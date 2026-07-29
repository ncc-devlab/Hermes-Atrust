//! Reusable WebDriver/BiDi support for complex interactive aTrust CAS flows.
//!
//! The browser owns all identity-provider and MFA interaction. This crate only
//! observes navigation and returns cookies scoped to the aTrust gateway after
//! the user closes the browser window.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atrust_auth::{CasChallenge, CasExchange, parse_portal_ticket};
use futures_util::{SinkExt as _, StreamExt as _};
use hermes_transport::GatewayCookie;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::{Instant, sleep, timeout_at};
use tokio_tungstenite::{connect_async, tungstenite};
use tracing::{info, warn};
use url::Url;

const WEBDRIVER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_WEBDRIVER_RESPONSE: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const TRACE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("invalid WebDriver endpoint")]
    InvalidEndpoint(#[source] url::ParseError),
    #[error("WebDriver request failed")]
    Request(#[source] reqwest::Error),
    #[error(
        "WebDriver is unavailable at {endpoint}; start ChromeDriver or use --webdriver-url with a running service"
    )]
    Unavailable { endpoint: Url },
    #[error("WebDriver returned HTTP {status}: {message}")]
    WebDriverStatus { status: StatusCode, message: String },
    #[error("WebDriver returned an invalid response")]
    InvalidResponse,
    #[error("WebDriver response exceeds the configured size limit")]
    ResponseTooLarge,
    #[error("browser returned an invalid URL")]
    InvalidBrowserUrl(#[source] url::ParseError),
    #[error("WebDriver did not provide a BiDi endpoint")]
    MissingBidiEndpoint,
    #[error("WebDriver BiDi communication failed")]
    Bidi(#[source] Box<tungstenite::Error>),
    #[error("WebDriver BiDi returned an invalid response")]
    InvalidBidiResponse,
    #[error("timed out waiting for aTrust multi-step login completion")]
    CallbackTimeout,
    #[error("browser returned invalid gateway cookies")]
    InvalidCookies,
    #[error("browser closed before any gateway cookies were observed")]
    BrowserClosedWithoutSession,
    #[error("failed to write browser trace")]
    Trace(#[source] std::io::Error),
    #[error("failed to serialize browser trace")]
    TraceJson(#[source] serde_json::Error),
}

/// Browser-produced materials after IDS + aTrust multi-step pages have finished.
#[derive(Debug)]
pub struct BrowserLoginResult {
    /// Optional portal ticket observed after multi-step. Cookie session is primary.
    pub exchange: Option<CasExchange>,
    pub gateway_cookies: Vec<GatewayCookie>,
    pub final_path: Option<String>,
    pub portal_hits: u32,
}

/// Redacted, append-only browser observability record. Values are deliberately
/// represented by lengths, hashes, or field names so the trace can be shared.
struct TraceWriter {
    file: BufWriter<File>,
    sequence: u64,
}

/// Adds a redacted control-plane lifecycle record to an existing browser trace.
pub fn append_trace_event(path: &Path, kind: &str, data: Value) -> Result<(), BrowserError> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(BrowserError::Trace)?;
    let mut file = BufWriter::new(file);
    let record = json!({
        "trace_version": TRACE_VERSION,
        "sequence": next_sequence(path)?,
        "timestamp_unix_ms": unix_millis(),
        "phase": "post_browser",
        "kind": kind,
        "data": data,
    });
    serde_json::to_writer(&mut file, &record).map_err(BrowserError::TraceJson)?;
    file.write_all(b"\n").map_err(BrowserError::Trace)?;
    file.flush().map_err(BrowserError::Trace)
}

/// Next 1-based sequence number for a record appended out-of-band (after the
/// browser `TraceWriter` was dropped). Each record is exactly one line, so the
/// existing line count equals the last sequence emitted; missing file means 1.
fn next_sequence(path: &Path) -> Result<u64, BrowserError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes.iter().filter(|&&byte| byte == b'\n').count() as u64 + 1),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(1),
        Err(error) => Err(BrowserError::Trace(error)),
    }
}

impl TraceWriter {
    fn open(path: &Path) -> Result<Self, BrowserError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(BrowserError::Trace)?;
        let mut writer = Self {
            file: BufWriter::new(file),
            sequence: 0,
        };
        writer.record(
            "trace_started",
            json!({
                "trace_version": TRACE_VERSION,
                "path": trace_path_label(path),
            }),
        )?;
        Ok(writer)
    }

    fn record(&mut self, kind: &str, data: Value) -> Result<(), BrowserError> {
        self.sequence = self.sequence.saturating_add(1);
        let record = json!({
            "trace_version": TRACE_VERSION,
            "sequence": self.sequence,
            "timestamp_unix_ms": unix_millis(),
            "kind": kind,
            "data": data,
        });
        serde_json::to_writer(&mut self.file, &record).map_err(BrowserError::TraceJson)?;
        self.file.write_all(b"\n").map_err(BrowserError::Trace)?;
        self.file.flush().map_err(BrowserError::Trace)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserKind {
    Firefox,
    Chrome,
}

#[derive(Debug)]
pub struct WebDriverBrowser {
    client: Client,
    endpoint: Url,
    session_id: String,
    bidi_endpoint: Url,
}

impl WebDriverBrowser {
    pub async fn connect(endpoint: &str, kind: BrowserKind) -> Result<Self, BrowserError> {
        let endpoint = normalized_endpoint(endpoint)?;
        let client = Client::builder()
            .timeout(WEBDRIVER_TIMEOUT)
            .build()
            .map_err(BrowserError::Request)?;
        let capabilities = match kind {
            BrowserKind::Firefox => json!({
                "alwaysMatch": {
                    "browserName": "firefox",
                    "webSocketUrl": true
                }
            }),
            BrowserKind::Chrome => chrome_capabilities(),
        };
        info!(
            event = "atrust_browser.webdriver_session_create",
            browser = ?kind,
            endpoint = %endpoint
        );
        let response = client
            .post(
                endpoint
                    .join("session")
                    .map_err(BrowserError::InvalidEndpoint)?,
            )
            .header("content-type", "application/json")
            .body(json!({ "capabilities": capabilities }).to_string())
            .send()
            .await
            .map_err(|error| {
                if error.is_connect() {
                    BrowserError::Unavailable {
                        endpoint: endpoint.clone(),
                    }
                } else {
                    BrowserError::Request(error)
                }
            })?;
        let value = response_value(response).await?;
        let session_id = value
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(BrowserError::InvalidResponse)?
            .to_owned();
        let bidi_endpoint = value
            .pointer("/capabilities/webSocketUrl")
            .and_then(Value::as_str)
            .ok_or(BrowserError::MissingBidiEndpoint)
            .and_then(|value| Url::parse(value).map_err(BrowserError::InvalidEndpoint));
        let bidi_endpoint = match bidi_endpoint {
            Ok(endpoint) => endpoint,
            Err(error) => {
                if let Ok(session_url) = endpoint.join(&format!("session/{session_id}")) {
                    let _ = client.delete(session_url).send().await;
                }
                return Err(error);
            }
        };

        Ok(Self {
            client,
            endpoint,
            session_id,
            bidi_endpoint,
        })
    }

    /// Runs full interactive login in the browser and only harvests after the window is closed.
    ///
    /// Intermediate IDS / aTrust MFA pages are observed (URL path + cookie names only) but never
    /// cause an early exit. Close the browser manually after finishing every step.
    pub async fn complete_cas(
        &self,
        challenge: CasChallenge,
        timeout: Duration,
        trace_path: Option<&Path>,
    ) -> Result<BrowserLoginResult, BrowserError> {
        let deadline = Instant::now() + timeout;
        let mut trace = trace_path.map(TraceWriter::open).transpose()?;
        trace_record(
            &mut trace,
            "browser_session_attached",
            json!({
                "session_id_sha256": sha256_hex(self.session_id.as_bytes()),
                "bidi_endpoint": safe_url(&self.bidi_endpoint),
            }),
        )?;
        let (mut events, _) = timeout_at(deadline, connect_async(self.bidi_endpoint.as_str()))
            .await
            .map_err(|_| BrowserError::CallbackTimeout)?
            .map_err(|error| BrowserError::Bidi(Box::new(error)))?;

        // Observe only — never intercept intermediate MFA navigations.
        events
            .send(tungstenite::Message::Text(
                json!({
                    "id": 1,
                    "method": "session.subscribe",
                    "params": {
                            "events": [
                                "network.beforeRequestSent",
                                "network.responseCompleted",
                                "network.fetchError",
                                "browsingContext.navigationStarted",
                            "browsingContext.load"
                        ]
                    }
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        wait_for_command(&mut events, 1, deadline).await?;
        trace_record(
            &mut trace,
            "bidi_subscribed",
            json!({
                "events": [
                    "network.beforeRequestSent",
                    "network.responseCompleted",
                    "network.fetchError",
                    "browsingContext.navigationStarted",
                    "browsingContext.load"
                ]
            }),
        )?;

        self.command(
            reqwest::Method::POST,
            "url",
            Some(json!({ "url": challenge.login_url.as_str() })),
        )
        .await?;

        let gateway_authority = challenge.callback_url().authority().to_owned();
        let mut last_portal: Option<Url> = None;
        let mut portal_hits: u32 = 0;
        let mut last_path = String::new();
        let mut last_cookie_names: Vec<String> = Vec::new();
        let mut latest_cookies: Vec<GatewayCookie> = Vec::new();
        let mut latest_path: Option<String> = None;
        let mut sid_seen = false;

        info!(
            event = "atrust_browser.waiting_manual_close",
            note = "finish IDS + aTrust MFA fully, then close this browser window to harvest"
        );

        loop {
            while let Ok(Some(message)) =
                timeout_at(Instant::now() + Duration::from_millis(250), events.next()).await
            {
                let Ok(message) = message else {
                    // BiDi stream errors often mean the browser/session is going away.
                    break;
                };
                let tungstenite::Message::Text(message) = message else {
                    continue;
                };
                let Ok(event) = serde_json::from_str::<Value>(&message) else {
                    continue;
                };
                trace_bidi_event(&mut trace, &event)?;
                let Some(url) = event
                    .pointer("/params/request/url")
                    .or_else(|| event.pointer("/params/response/url"))
                    .or_else(|| event.pointer("/params/url"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                let Ok(parsed) = Url::parse(url) else {
                    continue;
                };
                let path = safe_path(&parsed);
                if challenge.is_callback_target(&parsed) {
                    info!(
                        event = "atrust_browser.intermediate_cas",
                        path,
                        note = "CAS callback observed; still waiting for full MFA and manual close"
                    );
                    continue;
                }
                if challenge.is_completion_target(&parsed) {
                    portal_hits = portal_hits.saturating_add(1);
                    info!(
                        event = "atrust_browser.portal_navigation",
                        portal_hits,
                        path,
                        note = if portal_hits == 1 {
                            "first portal hit often starts aTrust two-step; not harvesting"
                        } else {
                            "later portal navigation after multi-step input"
                        }
                    );
                    last_portal = Some(parsed);
                    continue;
                }
                if parsed.authority() == gateway_authority && path != last_path {
                    info!(event = "atrust_browser.url_change", path);
                    last_path = path;
                }
            }

            if Instant::now() >= deadline {
                return Err(BrowserError::CallbackTimeout);
            }

            match self.current_url().await {
                Ok(url) => {
                    let path = safe_path(&url);
                    if path != last_path {
                        info!(event = "atrust_browser.url_change", path = %path);
                        last_path = path.clone();
                    }
                    latest_path = Some(path);
                }
                Err(_) => {
                    // Session/browser is gone: harvest whatever we last observed.
                    info!(
                        event = "atrust_browser.closed",
                        portal_hits,
                        gateway_cookie_count = latest_cookies.len(),
                        sid_seen
                    );
                    trace_record(
                        &mut trace,
                        "browser_session_closed",
                        json!({
                            "portal_hits": portal_hits,
                            "gateway_cookie_count": latest_cookies.len(),
                            "sid_seen": sid_seen,
                            "final_path": latest_path,
                        }),
                    )?;
                    if latest_cookies.is_empty() {
                        return Err(BrowserError::BrowserClosedWithoutSession);
                    }
                    let exchange = last_portal.as_ref().and_then(|url| {
                        if portal_ticket_harvest_allowed(portal_hits, sid_seen) {
                            parse_portal_ticket(url, &gateway_authority)
                                .ok()
                                .map(|portal_ticket| CasExchange { portal_ticket })
                        } else {
                            None
                        }
                    });
                    drop(challenge);
                    return Ok(BrowserLoginResult {
                        exchange,
                        gateway_cookies: latest_cookies,
                        final_path: latest_path,
                        portal_hits,
                    });
                }
            }

            match self.gateway_cookies_for_authority(&gateway_authority).await {
                Ok(cookies) => {
                    let mut names = cookies
                        .iter()
                        .map(|cookie| cookie.name.clone())
                        .collect::<Vec<_>>();
                    names.sort();
                    if names != last_cookie_names {
                        info!(
                            event = "atrust_browser.cookie_names",
                            cookie_names = ?names,
                            sid_present = names.iter().any(|name| name.eq_ignore_ascii_case("sid"))
                        );
                        trace_record(&mut trace, "cookie_snapshot", cookie_trace(&cookies))?;
                        last_cookie_names = names;
                    }
                    sid_seen = cookies
                        .iter()
                        .any(|cookie| cookie.name.eq_ignore_ascii_case("sid"));
                    latest_cookies = cookies;
                }
                Err(_) => {
                    info!(
                        event = "atrust_browser.closed",
                        portal_hits,
                        gateway_cookie_count = latest_cookies.len(),
                        sid_seen
                    );
                    trace_record(
                        &mut trace,
                        "browser_session_closed",
                        json!({
                            "portal_hits": portal_hits,
                            "gateway_cookie_count": latest_cookies.len(),
                            "sid_seen": sid_seen,
                            "final_path": latest_path,
                        }),
                    )?;
                    if latest_cookies.is_empty() {
                        return Err(BrowserError::BrowserClosedWithoutSession);
                    }
                    let exchange = last_portal.as_ref().and_then(|url| {
                        if portal_ticket_harvest_allowed(portal_hits, sid_seen) {
                            parse_portal_ticket(url, &gateway_authority)
                                .ok()
                                .map(|portal_ticket| CasExchange { portal_ticket })
                        } else {
                            None
                        }
                    });
                    drop(challenge);
                    return Ok(BrowserLoginResult {
                        exchange,
                        gateway_cookies: latest_cookies,
                        final_path: latest_path,
                        portal_hits,
                    });
                }
            }

            sleep(POLL_INTERVAL).await;
        }
    }

    async fn current_url(&self) -> Result<Url, BrowserError> {
        let value = self.command(reqwest::Method::GET, "url", None).await?;
        let raw = value.as_str().ok_or(BrowserError::InvalidResponse)?;
        Url::parse(raw).map_err(BrowserError::InvalidBrowserUrl)
    }

    async fn gateway_cookies_for_authority(
        &self,
        authority: &str,
    ) -> Result<Vec<GatewayCookie>, BrowserError> {
        let host = authority
            .split(':')
            .next()
            .unwrap_or(authority)
            .trim_matches(|ch| ch == '[' || ch == ']')
            .to_ascii_lowercase();
        let value = self.command(reqwest::Method::GET, "cookie", None).await?;
        let cookies = value
            .as_array()
            .ok_or(BrowserError::InvalidCookies)?
            .iter()
            .filter_map(|cookie| {
                let name = cookie.get("name")?.as_str()?;
                let value = cookie.get("value")?.as_str()?;
                let domain_raw = cookie.get("domain").and_then(Value::as_str).unwrap_or("");
                let domain = domain_raw.trim_start_matches('.').to_ascii_lowercase();
                let domain_ok =
                    domain.is_empty() || domain == host || host.ends_with(&format!(".{domain}"));
                if !domain_ok {
                    return None;
                }
                Some(GatewayCookie {
                    name: name.to_owned(),
                    value: value.to_owned(),
                    domain: if domain.is_empty() {
                        Some(host.clone())
                    } else {
                        Some(domain)
                    },
                    path: cookie
                        .get("path")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    secure: cookie
                        .get("secure")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
                    http_only: cookie
                        .get("httpOnly")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
            })
            .collect::<Vec<_>>();
        Ok(cookies)
    }

    pub async fn close(self) -> Result<(), BrowserError> {
        let response = self
            .client
            .delete(self.session_url("")?)
            .send()
            .await
            .map_err(BrowserError::Request)?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        let status = response.status();
        let message = response_error_message(response).await;
        Err(BrowserError::WebDriverStatus { status, message })
    }

    async fn command(
        &self,
        method: reqwest::Method,
        command: &str,
        body: Option<Value>,
    ) -> Result<Value, BrowserError> {
        let mut request = self.client.request(method, self.session_url(command)?);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.map_err(BrowserError::Request)?;
        response_value(response).await
    }

    fn session_url(&self, command: &str) -> Result<Url, BrowserError> {
        self.endpoint
            .join(&format!("session/{}/{command}", self.session_id))
            .map_err(BrowserError::InvalidEndpoint)
    }
}

async fn wait_for_command<S>(
    events: &mut S,
    command_id: u64,
    deadline: Instant,
) -> Result<(), BrowserError>
where
    S: futures_util::Stream<Item = Result<tungstenite::Message, tungstenite::Error>> + Unpin,
{
    loop {
        let message = timeout_at(deadline, events.next())
            .await
            .map_err(|_| BrowserError::CallbackTimeout)?
            .ok_or(BrowserError::InvalidBidiResponse)?;
        let message = message.map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        let tungstenite::Message::Text(message) = message else {
            continue;
        };
        let response: Value =
            serde_json::from_str(&message).map_err(|_| BrowserError::InvalidBidiResponse)?;
        if response.get("id").and_then(Value::as_u64) == Some(command_id) {
            return if response.get("type").and_then(Value::as_str) == Some("success") {
                Ok(())
            } else {
                Err(BrowserError::InvalidBidiResponse)
            };
        }
    }
}

fn normalized_endpoint(endpoint: &str) -> Result<Url, BrowserError> {
    let mut endpoint = Url::parse(endpoint).map_err(BrowserError::InvalidEndpoint)?;
    if !endpoint.path().ends_with('/') {
        endpoint.set_path(&format!("{}/", endpoint.path()));
    }
    Ok(endpoint)
}

fn trace_record(
    trace: &mut Option<TraceWriter>,
    kind: &str,
    data: Value,
) -> Result<(), BrowserError> {
    if let Some(trace) = trace {
        trace.record(kind, data)?;
    }
    Ok(())
}

fn trace_bidi_event(trace: &mut Option<TraceWriter>, event: &Value) -> Result<(), BrowserError> {
    let Some(method) = event.get("method").and_then(Value::as_str) else {
        return Ok(());
    };
    let params = event.get("params").unwrap_or(&Value::Null);
    let Some(data) = redact_bidi_event(method, params) else {
        return Ok(());
    };
    trace_record(trace, method, data)
}

/// Pure redaction of a subscribed BiDi network/navigation event into a record
/// that carries only lengths, hashes, header/query names, and the opaque
/// request-id string. Returns `None` for events that are not traced.
///
/// Kept side-effect free so tests can assert no raw request/response object,
/// cookie value, ticket, or callback URL survives.
fn redact_bidi_event(method: &str, params: &Value) -> Option<Value> {
    let data = match method {
        "network.beforeRequestSent" => {
            let request = params.get("request").unwrap_or(&Value::Null);
            json!({
                "request_id": request_id_field(params.get("request")),
                "method": request.get("method").and_then(Value::as_str),
                "url": request.get("url").and_then(Value::as_str).and_then(|url| Url::parse(url).ok()).map(|url| safe_url_with_query_names(&url)),
                "headers": header_names(request.get("headers")),
                "body": payload_summary(request.get("postData").or_else(|| request.get("body"))),
            })
        }
        "network.responseCompleted" => {
            let response = params.get("response").unwrap_or(&Value::Null);
            json!({
                "request_id": request_id_field(params.get("request")),
                "url": response.get("url").and_then(Value::as_str).and_then(|url| Url::parse(url).ok()).map(|url| safe_url_with_query_names(&url)),
                "status": response.get("status"),
                "status_text_present": response.get("statusText").and_then(Value::as_str).is_some_and(|value| !value.is_empty()),
                "headers": header_names(response.get("headers")),
                "mime_type": response.get("content").and_then(|content| content.get("mimeType")).and_then(Value::as_str),
            })
        }
        "network.fetchError" => json!({
            "request_id": request_id_field(params.get("request")),
            "url": params.get("url").and_then(Value::as_str).and_then(|url| Url::parse(url).ok()).map(|url| safe_url_with_query_names(&url)),
            "error_present": params.get("errorText").and_then(Value::as_str).is_some_and(|value| !value.is_empty()),
        }),
        "browsingContext.navigationStarted" | "browsingContext.load" => json!({
            "url": params.get("url").and_then(Value::as_str).and_then(|url| Url::parse(url).ok()).map(|url| safe_url_with_query_names(&url)),
        }),
        _ => return None,
    };
    Some(data)
}

fn cookie_trace(cookies: &[GatewayCookie]) -> Value {
    Value::Array(
        cookies
            .iter()
            .map(|cookie| {
                json!({
                    "name": cookie.name,
                    "value_len": cookie.value.len(),
                    "value_sha256": sha256_hex(cookie.value.as_bytes()),
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "http_only": cookie.http_only,
                })
            })
            .collect(),
    )
}

fn header_names(headers: Option<&Value>) -> Vec<String> {
    let mut names = headers
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|header| header.get("name").and_then(Value::as_str))
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn payload_summary(payload: Option<&Value>) -> Value {
    let Some(payload) = payload else {
        return Value::Null;
    };
    let bytes = payload
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| payload.as_str())
        .map(str::as_bytes);
    if let Some(bytes) = bytes {
        return json!({
            "length": bytes.len(),
            "sha256": sha256_hex(bytes),
            "json_keys": serde_json::from_slice::<Value>(bytes).ok().map(|value| json_keys(&value)),
            "correlation_fingerprints": serde_json::from_slice::<Value>(bytes)
                .ok()
                .map(|value| correlation_fingerprints(&value)),
        });
    }
    json!({ "present": true, "shape": json_shape(payload) })
}

fn json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            Value::Array(map.keys().map(|key| Value::String(key.clone())).collect())
        }
        Value::Array(values) => Value::Array(values.iter().map(json_keys).collect()),
        _ => Value::Null,
    }
}

fn json_shape(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "bool",
        Value::Null => "null",
    }
}

fn correlation_fingerprints(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut fields = serde_json::Map::new();
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "sid" | "signKey" | "deviceId" | "connectionId"
                ) {
                    if let Some(value) = value.as_str() {
                        fields.insert(
                            key.clone(),
                            json!({
                                "length": value.len(),
                                "sha256": sha256_hex(value.as_bytes()),
                            }),
                        );
                    }
                }
                let nested = correlation_fingerprints(value);
                if nested != Value::Null {
                    fields.insert(format!("{key}.*"), nested);
                }
            }
            if fields.is_empty() {
                Value::Null
            } else {
                Value::Object(fields)
            }
        }
        Value::Array(values) => {
            let values = values
                .iter()
                .map(correlation_fingerprints)
                .filter(|value| *value != Value::Null)
                .collect::<Vec<_>>();
            if values.is_empty() {
                Value::Null
            } else {
                Value::Array(values)
            }
        }
        _ => Value::Null,
    }
}

/// Extracts only the opaque request-id string from a BiDi `RequestData`.
///
/// Never returns the surrounding object: `RequestData` also carries the full
/// URL, request/response headers, cookies, and POST body, none of which may
/// enter the redacted trace. Anything that is not a plain string id is dropped.
fn request_id_field(request_data: Option<&Value>) -> Value {
    match request_data
        .and_then(|data| data.get("request"))
        .and_then(Value::as_str)
    {
        Some(id) => Value::String(id.to_owned()),
        None => Value::Null,
    }
}

fn safe_url(url: &Url) -> String {
    safe_url_with_query_names(url)
}

fn safe_url_with_query_names(url: &Url) -> String {
    let mut value = safe_path(url);
    let names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<Vec<_>>();
    if !names.is_empty() {
        value.push('?');
        value.push_str(&names.join("&"));
    }
    value
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

pub fn sha256_fingerprint(value: &[u8]) -> String {
    sha256_hex(value)
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn trace_path_label(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("browser-trace.jsonl")
        .to_owned()
}

fn safe_path(url: &Url) -> String {
    format!("{}://{}{}", url.scheme(), url.authority(), url.path())
}

/// Optional portal ticket may be kept only after multi-step progress, never on first portal alone.
fn portal_ticket_harvest_allowed(portal_hits: u32, sid_seen: bool) -> bool {
    portal_hits >= 2 || sid_seen
}

fn chrome_capabilities() -> Value {
    // Fresh profile each session avoids SingletonLock conflicts with a previous
    // Chrome/Chromium instance that left /tmp/hermes-chrome-profile locked.
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let profile = format!(
        "/tmp/hermes-chrome-profile-{}-{}",
        std::process::id(),
        stamp
    );
    let mut options = json!({
        "args": [
            format!("--user-data-dir={profile}"),
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-sync",
            "--disable-background-networking",
            "--disable-dev-shm-usage"
        ]
    });
    if let Some(binary) = resolve_chrome_binary() {
        info!(event = "atrust_browser.chrome_binary", path = %binary);
        options["binary"] = Value::String(binary);
    }
    json!({
        "alwaysMatch": {
            "browserName": "chrome",
            "webSocketUrl": true,
            "goog:chromeOptions": options
        }
    })
}

fn resolve_chrome_binary() -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "/opt/google/chrome/chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ];
    CANDIDATES
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_owned())
}

async fn read_limited_body(response: reqwest::Response) -> Result<Vec<u8>, BrowserError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_WEBDRIVER_RESPONSE as u64)
    {
        return Err(BrowserError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BrowserError::Request)?;
        if body.len().saturating_add(chunk.len()) > MAX_WEBDRIVER_RESPONSE {
            return Err(BrowserError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn response_error_message(response: reqwest::Response) -> String {
    match read_limited_body(response).await {
        Ok(body) => {
            if let Ok(envelope) = serde_json::from_slice::<Value>(&body) {
                if let Some(message) = envelope
                    .pointer("/value/message")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                {
                    return message.lines().next().unwrap_or(message).to_owned();
                }
            }
            String::from_utf8_lossy(&body).chars().take(500).collect()
        }
        Err(_) => "unable to read WebDriver error body".to_owned(),
    }
}

async fn response_value(response: reqwest::Response) -> Result<Value, BrowserError> {
    let status = response.status();
    if !status.is_success() {
        let message = response_error_message(response).await;
        warn!(
            event = "atrust_browser.webdriver_http_error",
            status = %status,
            message = %message
        );
        return Err(BrowserError::WebDriverStatus { status, message });
    }
    let body = read_limited_body(response).await?;
    let envelope: Value =
        serde_json::from_slice(&body).map_err(|_| BrowserError::InvalidResponse)?;
    envelope
        .get("value")
        .cloned()
        .ok_or(BrowserError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        normalized_endpoint, payload_summary, portal_ticket_harvest_allowed, redact_bidi_event,
        request_id_field, safe_url_with_query_names,
    };
    use url::Url;

    #[test]
    fn normalizes_webdriver_endpoint_path() {
        assert_eq!(
            normalized_endpoint("http://127.0.0.1:4444")
                .expect("valid endpoint")
                .as_str(),
            "http://127.0.0.1:4444/"
        );
        assert_eq!(
            normalized_endpoint("http://127.0.0.1:4444/wd/hub")
                .expect("valid endpoint")
                .as_str(),
            "http://127.0.0.1:4444/wd/hub/"
        );
    }

    #[test]
    fn does_not_harvest_portal_ticket_on_first_portal_without_sid() {
        assert!(!portal_ticket_harvest_allowed(0, false));
        assert!(!portal_ticket_harvest_allowed(1, false));
    }

    #[test]
    fn harvests_portal_ticket_after_second_portal_or_sid() {
        assert!(portal_ticket_harvest_allowed(2, false));
        assert!(portal_ticket_harvest_allowed(1, true));
        assert!(portal_ticket_harvest_allowed(0, true));
    }

    #[test]
    fn trace_url_keeps_path_and_query_names_only() {
        let url = Url::parse("https://gateway.test/passport/v1/auth?sid=secret&code=123").unwrap();
        assert_eq!(
            safe_url_with_query_names(&url),
            "https://gateway.test/passport/v1/auth?sid&code"
        );
    }

    #[test]
    fn response_completed_emits_request_id_string_not_raw_object() {
        // Realistic BiDi params whose `request` RequestData carries secrets that
        // must never reach the trace (student id, ticket, cookie header values).
        let params = json!({
            "request": {
                "request": "REQ-ID-1234",
                "url": "https://gw/portal/shortcut.html?username=student-secret-id&ticket=abc-secret",
                "headers": [{"name": "Cookie", "value": {"type": "string", "value": "sid=cookiesecret"}}],
                "cookies": [{"name": "sid", "value": {"type": "string", "value": "cookiesecret"}}],
            },
            "response": {
                "url": "https://gw/passport/v1/auth?sid=urlsecret&code=123",
                "status": 200,
                "headers": [{"name": "Set-Cookie", "value": {"type": "string", "value": "sid=cookiesecret"}}],
            }
        });
        let data = redact_bidi_event("network.responseCompleted", &params).unwrap();
        assert_eq!(
            data.get("request_id").and_then(Value::as_str),
            Some("REQ-ID-1234")
        );
        let text = data.to_string();
        for secret in [
            "student-secret-id",
            "cookiesecret",
            "urlsecret",
            "abc-secret",
            "ticket=",
        ] {
            assert!(!text.contains(secret), "leaked {secret:?} in {text}");
        }
        // Response header names survive as observability, values do not.
        assert!(text.contains("set-cookie"));
        assert_eq!(data.get("status").and_then(Value::as_i64), Some(200));
    }

    #[test]
    fn fetch_error_does_not_leak_request_object() {
        let params = json!({
            "request": {
                "request": "REQ-ID-9",
                "goog:postData": "{\"token\":\"t\"}",
                "headers": [{"name": "Referer", "value": {"type": "string", "value": "https://gw/x?username=student-secret-id"}}],
            },
            "url": "https://127.0.0.1:54630/v1/detect",
            "errorText": "net::ERR_CONNECTION_REFUSED",
        });
        let data = redact_bidi_event("network.fetchError", &params).unwrap();
        assert_eq!(
            data.get("request_id").and_then(Value::as_str),
            Some("REQ-ID-9")
        );
        assert_eq!(
            data.get("error_present").and_then(Value::as_bool),
            Some(true)
        );
        let text = data.to_string();
        for secret in ["student-secret-id", "postData", "token", "errorText"] {
            assert!(!text.contains(secret), "leaked {secret:?} in {text}");
        }
    }

    #[test]
    fn request_id_field_rejects_non_string_and_missing() {
        // An object (the leak shape) or a missing field collapses to null,
        // never the surrounding RequestData.
        assert_eq!(
            request_id_field(Some(&json!({"request": {"url": "https://gw/x"}}))),
            Value::Null
        );
        assert_eq!(request_id_field(None), Value::Null);
        assert_eq!(
            request_id_field(Some(&json!({"request": "REQ-1"}))),
            Value::String("REQ-1".to_owned())
        );
    }

    #[test]
    fn trace_payload_keeps_shape_and_fingerprint_but_not_values() {
        let payload = json!({"sid": "secret-sid", "signKey": "secret-key"});
        let summary = payload_summary(Some(&json!({
            "value": payload.to_string()
        })));
        let text = summary.to_string();
        assert!(!text.contains("secret-sid"));
        assert!(!text.contains("secret-key"));
        assert!(text.contains("sid"));
        assert!(text.contains("signKey"));
        assert!(text.contains("correlation_fingerprints"));
        assert!(summary.get("sha256").is_some());
    }
}
