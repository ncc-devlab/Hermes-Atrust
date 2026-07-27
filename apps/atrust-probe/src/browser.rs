use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atrust_auth::{CasChallenge, CasExchange, parse_portal_ticket};
use futures_util::{SinkExt as _, StreamExt as _};
use hermes_transport::GatewayCookie;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::time::{Instant, sleep, timeout_at};
use tokio_tungstenite::{connect_async, tungstenite};
use tracing::{info, warn};
use url::Url;

const WEBDRIVER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_WEBDRIVER_RESPONSE: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("invalid WebDriver endpoint")]
    InvalidEndpoint(#[source] url::ParseError),
    #[error("WebDriver request failed")]
    Request(#[source] reqwest::Error),
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
            event = "probe.webdriver_session_create",
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
            .map_err(BrowserError::Request)?;
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
    ) -> Result<BrowserLoginResult, BrowserError> {
        let deadline = Instant::now() + timeout;
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
            event = "probe.browser_waiting_manual_close",
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
                let Some(url) = event
                    .pointer("/params/request/url")
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
                        event = "probe.browser_intermediate_cas",
                        path,
                        note = "CAS callback observed; still waiting for full MFA and manual close"
                    );
                    continue;
                }
                if challenge.is_completion_target(&parsed) {
                    portal_hits = portal_hits.saturating_add(1);
                    info!(
                        event = "probe.browser_portal_navigation",
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
                    info!(event = "probe.browser_url_change", path);
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
                        info!(event = "probe.browser_url_change", path = %path);
                        last_path = path.clone();
                    }
                    latest_path = Some(path);
                }
                Err(_) => {
                    // Session/browser is gone: harvest whatever we last observed.
                    info!(
                        event = "probe.browser_closed",
                        portal_hits,
                        gateway_cookie_count = latest_cookies.len(),
                        sid_seen
                    );
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
                            event = "probe.browser_cookie_names",
                            cookie_names = ?names,
                            sid_present = names.iter().any(|name| name.eq_ignore_ascii_case("sid"))
                        );
                        last_cookie_names = names;
                    }
                    sid_seen = cookies
                        .iter()
                        .any(|cookie| cookie.name.eq_ignore_ascii_case("sid"));
                    latest_cookies = cookies;
                }
                Err(_) => {
                    info!(
                        event = "probe.browser_closed",
                        portal_hits,
                        gateway_cookie_count = latest_cookies.len(),
                        sid_seen
                    );
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
        info!(event = "probe.chrome_binary", path = %binary);
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
            event = "probe.webdriver_http_error",
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
    use super::{normalized_endpoint, portal_ticket_harvest_allowed};

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
}
