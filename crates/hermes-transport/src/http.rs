use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::cookie::Jar;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use thiserror::Error;
use tracing::{debug, warn};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Transport-neutral HTTP request. Its debug representation never exposes headers or body.
#[derive(Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("scheme", &self.url.scheme())
            .field("authority", &self.url.authority())
            .field("path", &self.url.path())
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl HttpRequest {
    pub fn get(url: Url) -> Self {
        Self {
            method: HttpMethod::Get,
            url,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    /// Redirect target retained because aTrust CAS carries a portal ticket in `Location`.
    pub location: Option<String>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("location_present", &self.location.is_some())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl HttpResponse {
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// Cookie imported from a trusted gateway origin only.
#[derive(Clone)]
pub struct GatewayCookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
}

impl std::fmt::Debug for GatewayCookie {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayCookie")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .finish()
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError>;

    /// Imports cookies for an already-validated gateway origin.
    ///
    /// Implementations must not accept arbitrary third-party origins; callers validate host.
    fn import_gateway_cookies(
        &self,
        _origin: &Url,
        _cookies: &[GatewayCookie],
    ) -> Result<(), HttpTransportError> {
        Err(HttpTransportError::CookieImportUnsupported)
    }

    /// Returns cookie names currently stored for `origin` without exposing values.
    fn gateway_cookie_names(&self, _origin: &Url) -> Vec<String> {
        Vec::new()
    }

    /// Returns a single cookie value previously imported for `origin` (never log the result).
    fn gateway_cookie_value(&self, _origin: &Url, _name: &str) -> Option<String> {
        None
    }

    /// Returns a cookie value the server itself set on `origin` (Set-Cookie jar), if any.
    ///
    /// Unlike `gateway_cookie_value`, this reads the live cookie jar rather than the
    /// trusted-import map, so it can export a SID established by a non-browser login
    /// (e.g. password auth). Never log the result.
    fn session_cookie_value(&self, _origin: &Url, _name: &str) -> Option<String> {
        None
    }

    /// Returns every cookie the jar would send to `origin`, shaped for re-import.
    ///
    /// Used to persist a live session across processes. Cookie attributes are
    /// not recoverable from a jar that only exposes the outgoing `Cookie:`
    /// header, so implementations fill in the origin host, `/`, `Secure`, and
    /// `HttpOnly`; only the names and values are authoritative.
    fn session_cookies(&self, _origin: &Url) -> Vec<GatewayCookie> {
        Vec::new()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TlsPolicy {
    /// Verify the peer using configured system/web roots.
    #[default]
    Verify,
    /// Compatibility mode for private gateways. This permits active interception.
    DangerousAcceptInvalidCertificates,
}

#[derive(Clone, Debug)]
pub struct ReqwestTransportConfig {
    pub timeout: Duration,
    pub max_response_body: usize,
    pub tls_policy: TlsPolicy,
}

impl Default for ReqwestTransportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            max_response_body: 2 * 1024 * 1024,
            tls_policy: TlsPolicy::Verify,
        }
    }
}

pub struct ReqwestTransport {
    client: reqwest::Client,
    jar: Arc<Jar>,
    max_response_body: usize,
    /// Cookie names observed via trusted gateway import only.
    imported_cookie_names: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Cookie values from trusted imports only; used for SID export. Never log values.
    imported_cookie_values: Arc<Mutex<HashMap<String, HashMap<String, String>>>>,
}

impl std::fmt::Debug for ReqwestTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name_hosts = self
            .imported_cookie_names
            .lock()
            .map(|map| map.len())
            .unwrap_or(0);
        formatter
            .debug_struct("ReqwestTransport")
            .field("max_response_body", &self.max_response_body)
            .field("imported_cookie_host_count", &name_hosts)
            .field("cookie_values", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ReqwestTransport {
    pub fn new(config: &ReqwestTransportConfig) -> Result<Self, HttpTransportError> {
        if config.max_response_body == 0 {
            return Err(HttpTransportError::InvalidConfiguration(
                "max_response_body must be greater than zero",
            ));
        }

        let dangerous_tls = config.tls_policy == TlsPolicy::DangerousAcceptInvalidCertificates;
        if dangerous_tls {
            warn!(event = "transport.insecure_tls_enabled");
        }

        let jar = Arc::new(Jar::default());
        let client = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            .redirect(Policy::none())
            .timeout(config.timeout)
            .danger_accept_invalid_certs(dangerous_tls)
            .build()
            .map_err(HttpTransportError::BuildClient)?;

        Ok(Self {
            client,
            jar,
            max_response_body: config.max_response_body,
            imported_cookie_names: Arc::new(Mutex::new(HashMap::new())),
            imported_cookie_values: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let started = Instant::now();
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
        };
        let method_name = method.as_str().to_owned();
        let host = request.url.host_str().unwrap_or("<unknown>").to_owned();
        let path = request.url.path().to_owned();
        let request_body_bytes = request.body.len();

        let mut builder = self.client.request(method, request.url);
        for (name, value) in request.headers {
            let name = HeaderName::try_from(name).map_err(HttpTransportError::InvalidHeaderName)?;
            let value =
                HeaderValue::try_from(value).map_err(HttpTransportError::InvalidHeaderValue)?;
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body);
        }

        debug!(
            event = "transport.http_begin",
            method = %method_name,
            host = %host,
            path = %path,
            request_body_bytes,
            max_response_body = self.max_response_body
        );

        let response = builder.send().await.map_err(|error| {
            warn!(
                event = "transport.http_send_failed",
                method = %method_name,
                host = %host,
                path = %path,
                elapsed_ms = started.elapsed().as_millis(),
                is_timeout = error.is_timeout(),
                is_connect = error.is_connect(),
                error = %error
            );
            map_reqwest_error(error, 0)
        })?;
        let status = response.status().as_u16();
        let content_length = response.content_length();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .map_err(HttpTransportError::InvalidResponseHeader)?;
        debug!(
            event = "transport.http_headers",
            method = %method_name,
            host = %host,
            path = %path,
            status,
            content_length,
            elapsed_ms = started.elapsed().as_millis()
        );
        if content_length.is_some_and(|length| length > self.max_response_body as u64) {
            warn!(
                event = "transport.http_response_too_large",
                method = %method_name,
                host = %host,
                path = %path,
                status,
                limit = self.max_response_body,
                content_length,
                bytes_read = 0u64
            );
            return Err(HttpTransportError::ResponseTooLarge {
                limit: self.max_response_body,
                bytes_read: 0,
                content_length,
            });
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                warn!(
                    event = "transport.http_body_failed",
                    method = %method_name,
                    host = %host,
                    path = %path,
                    status,
                    bytes_read = body.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    is_timeout = error.is_timeout(),
                    error = %error
                );
                map_reqwest_error(error, body.len())
            })?;
            if body.len().saturating_add(chunk.len()) > self.max_response_body {
                warn!(
                    event = "transport.http_response_too_large",
                    method = %method_name,
                    host = %host,
                    path = %path,
                    status,
                    limit = self.max_response_body,
                    content_length,
                    bytes_read = body.len()
                );
                return Err(HttpTransportError::ResponseTooLarge {
                    limit: self.max_response_body,
                    bytes_read: body.len(),
                    content_length,
                });
            }
            body.extend_from_slice(&chunk);
        }

        debug!(
            event = "transport.http_complete",
            method = %method_name,
            host = %host,
            path = %path,
            status,
            elapsed_ms = started.elapsed().as_millis(),
            response_bytes = body.len(),
            content_length
        );
        Ok(HttpResponse {
            status,
            location,
            body,
        })
    }

    fn import_gateway_cookies(
        &self,
        origin: &Url,
        cookies: &[GatewayCookie],
    ) -> Result<(), HttpTransportError> {
        if origin.scheme() != "https" {
            return Err(HttpTransportError::InvalidCookieOrigin);
        }
        let origin_host = origin
            .host_str()
            .ok_or(HttpTransportError::InvalidCookieOrigin)?;
        for cookie in cookies {
            validate_cookie_token(&cookie.name)
                .map_err(|_| HttpTransportError::InvalidCookieName)?;
            if cookie.value.is_empty()
                || cookie
                    .value
                    .chars()
                    .any(|ch| ch.is_control() || ch == ';' || ch == ',')
            {
                return Err(HttpTransportError::InvalidCookieValue);
            }
            let mut set_cookie = format!("{}={}", cookie.name, cookie.value);
            let domain = cookie
                .domain
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(origin_host)
                .trim_start_matches('.');
            if !domain.eq_ignore_ascii_case(origin_host)
                && !origin_host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", domain.to_ascii_lowercase()))
            {
                return Err(HttpTransportError::InvalidCookieOrigin);
            }
            set_cookie.push_str(&format!("; Domain={domain}"));
            let path = cookie
                .path
                .as_deref()
                .filter(|value| value.starts_with('/'))
                .unwrap_or("/");
            set_cookie.push_str(&format!("; Path={path}"));
            if cookie.secure || origin.scheme() == "https" {
                set_cookie.push_str("; Secure");
            }
            if cookie.http_only {
                set_cookie.push_str("; HttpOnly");
            }
            self.jar.add_cookie_str(&set_cookie, origin);
        }
        let host_key = origin_host.to_ascii_lowercase();
        let mut names = cookies
            .iter()
            .map(|cookie| cookie.name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        if let Ok(mut map) = self.imported_cookie_names.lock() {
            map.entry(host_key.clone())
                .and_modify(|existing| {
                    existing.extend(names.iter().cloned());
                    existing.sort();
                    existing.dedup();
                })
                .or_insert(names.clone());
        }
        if let Ok(mut map) = self.imported_cookie_values.lock() {
            let entry = map.entry(host_key).or_default();
            for cookie in cookies {
                entry.insert(cookie.name.to_ascii_lowercase(), cookie.value.clone());
            }
        }
        debug!(
            event = "transport.cookie_import",
            host = origin.host_str().unwrap_or("<unknown>"),
            cookie_count = cookies.len(),
            cookie_names = ?names
        );
        Ok(())
    }

    fn gateway_cookie_names(&self, origin: &Url) -> Vec<String> {
        // reqwest::Jar does not expose enumeration; track names from trusted imports only.
        let Some(host) = origin.host_str() else {
            return Vec::new();
        };
        self.imported_cookie_names
            .lock()
            .map(|map| {
                map.get(&host.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    fn gateway_cookie_value(&self, origin: &Url, name: &str) -> Option<String> {
        let host = origin.host_str()?;
        let map = self.imported_cookie_values.lock().ok()?;
        map.get(&host.to_ascii_lowercase())?
            .get(&name.to_ascii_lowercase())
            .cloned()
    }

    fn session_cookie_value(&self, origin: &Url, name: &str) -> Option<String> {
        use reqwest::cookie::CookieStore as _;
        let header = self.jar.cookies(origin)?;
        let raw = header.to_str().ok()?;
        // The jar returns a `Cookie:` header value: `a=1; b=2`.
        for pair in raw.split(';') {
            if let Some((cookie_name, value)) = pair.trim().split_once('=')
                && cookie_name.trim().eq_ignore_ascii_case(name)
            {
                return Some(value.trim().to_owned());
            }
        }
        None
    }

    fn session_cookies(&self, origin: &Url) -> Vec<GatewayCookie> {
        use reqwest::cookie::CookieStore as _;
        let Some(host) = origin.host_str() else {
            return Vec::new();
        };
        let Some(header) = self.jar.cookies(origin) else {
            return Vec::new();
        };
        let Ok(raw) = header.to_str() else {
            return Vec::new();
        };
        raw.split(';')
            .filter_map(|pair| pair.trim().split_once('='))
            .filter_map(|(name, value)| {
                let name = name.trim();
                let value = value.trim();
                if name.is_empty() || value.is_empty() {
                    return None;
                }
                Some(GatewayCookie {
                    name: name.to_owned(),
                    value: value.to_owned(),
                    domain: Some(host.to_owned()),
                    path: Some("/".to_owned()),
                    secure: true,
                    http_only: true,
                })
            })
            .collect()
    }
}

fn validate_cookie_token(value: &str) -> Result<(), ()> {
    if value.is_empty() {
        return Err(());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'!'))
    {
        return Err(());
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum HttpTransportError {
    #[error("invalid transport configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("failed to build HTTP client: {0}")]
    BuildClient(#[source] reqwest::Error),
    #[error("invalid HTTP header name: {0}")]
    InvalidHeaderName(#[source] reqwest::header::InvalidHeaderName),
    #[error("invalid HTTP header value: {0}")]
    InvalidHeaderValue(#[source] reqwest::header::InvalidHeaderValue),
    #[error("invalid HTTP response header value: {0}")]
    InvalidResponseHeader(#[source] reqwest::header::ToStrError),
    #[error("HTTP request failed: {0}")]
    Request(#[source] reqwest::Error),
    #[error(
        "HTTP request timed out after reading {bytes_read} response bytes (is_timeout={is_timeout})"
    )]
    Timeout {
        bytes_read: usize,
        is_timeout: bool,
        #[source]
        source: reqwest::Error,
    },
    #[error(
        "HTTP response exceeds the configured {limit} byte limit (read {bytes_read} bytes, content_length={content_length:?})"
    )]
    ResponseTooLarge {
        limit: usize,
        bytes_read: usize,
        content_length: Option<u64>,
    },
    #[error("cookie import is not supported by this transport")]
    CookieImportUnsupported,
    #[error("cookie origin must be an HTTPS gateway URL")]
    InvalidCookieOrigin,
    #[error("cookie name is invalid")]
    InvalidCookieName,
    #[error("cookie value is invalid")]
    InvalidCookieValue,
    #[error("mock transport failure: {0}")]
    Mock(String),
}

fn map_reqwest_error(error: reqwest::Error, bytes_read: usize) -> HttpTransportError {
    // reqwest often surfaces total-request timeouts as body/decode failures mid-stream
    // (e.g. "error decoding response body: operation timed out").
    let message = error.to_string().to_ascii_lowercase();
    if error.is_timeout() || message.contains("timed out") || message.contains("timeout") {
        return HttpTransportError::Timeout {
            bytes_read,
            is_timeout: error.is_timeout(),
            source: error,
        };
    }
    HttpTransportError::Request(error)
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn verified_tls_is_the_default() {
        assert_eq!(
            ReqwestTransportConfig::default().tls_policy,
            TlsPolicy::Verify
        );
    }

    #[test]
    fn zero_body_limit_is_rejected() {
        let config = ReqwestTransportConfig {
            max_response_body: 0,
            ..ReqwestTransportConfig::default()
        };
        assert!(matches!(
            ReqwestTransport::new(&config),
            Err(HttpTransportError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn request_and_response_debug_are_redacted() {
        let mut request =
            HttpRequest::get(Url::parse("https://example.test/path?ticket=secret").unwrap());
        request
            .headers
            .push(("x-csrf-token".to_owned(), "csrf-secret".to_owned()));
        request.body = b"password-secret".to_vec();
        let response = HttpResponse {
            status: 302,
            location: Some("https://example.test/?data=portal-secret".to_owned()),
            body: b"response-secret".to_vec(),
        };

        let debug = format!("{request:?} {response:?}");
        for secret in [
            "secret",
            "csrf-secret",
            "password-secret",
            "portal-secret",
            "response-secret",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[tokio::test]
    async fn redirects_are_returned_without_being_followed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = connection.read(&mut request).unwrap();
            connection
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: https://example.test/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();

        let response = transport
            .execute(HttpRequest::get(
                Url::parse(&format!("http://{address}/start")).unwrap(),
            ))
            .await
            .unwrap();

        server.join().unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            response.location.as_deref(),
            Some("https://example.test/next")
        );
    }

    fn sample_cookie(name: &str, value: &str, domain: Option<&str>) -> GatewayCookie {
        GatewayCookie {
            name: name.to_owned(),
            value: value.to_owned(),
            domain: domain.map(str::to_owned),
            path: Some("/".to_owned()),
            secure: true,
            http_only: true,
        }
    }

    #[test]
    fn imports_gateway_cookies_and_exposes_names_only() {
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let origin = Url::parse("https://atrust.example.edu/").unwrap();
        let cookies = [
            sample_cookie("sid", "session-value", Some("atrust.example.edu")),
            sample_cookie("sid.sig", "sig-value", None),
        ];

        transport.import_gateway_cookies(&origin, &cookies).unwrap();

        let mut names = transport.gateway_cookie_names(&origin);
        names.sort();
        assert_eq!(names, vec!["sid".to_owned(), "sid.sig".to_owned()]);
        assert!(!format!("{cookies:?}").contains("session-value"));
        assert_eq!(
            transport.gateway_cookie_names(&Url::parse("https://other.example.edu/").unwrap()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn rejects_http_origin_and_cross_domain_cookie_import() {
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let https = Url::parse("https://atrust.example.edu/").unwrap();
        let http = Url::parse("http://atrust.example.edu/").unwrap();

        assert!(matches!(
            transport.import_gateway_cookies(&http, &[sample_cookie("sid", "value", None)]),
            Err(HttpTransportError::InvalidCookieOrigin)
        ));
        assert!(matches!(
            transport.import_gateway_cookies(
                &https,
                &[sample_cookie("sid", "value", Some("evil.example"))]
            ),
            Err(HttpTransportError::InvalidCookieOrigin)
        ));
    }

    #[test]
    fn rejects_invalid_cookie_name_and_value() {
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let origin = Url::parse("https://atrust.example.edu/").unwrap();

        assert!(matches!(
            transport.import_gateway_cookies(&origin, &[sample_cookie("sid;evil", "value", None)]),
            Err(HttpTransportError::InvalidCookieName)
        ));
        assert!(matches!(
            transport.import_gateway_cookies(&origin, &[sample_cookie("sid", "", None)]),
            Err(HttpTransportError::InvalidCookieValue)
        ));
        assert!(matches!(
            transport.import_gateway_cookies(&origin, &[sample_cookie("sid", "a;b", None)]),
            Err(HttpTransportError::InvalidCookieValue)
        ));
    }

    #[test]
    fn merges_imported_cookie_names_per_origin() {
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let origin = Url::parse("https://atrust.example.edu/").unwrap();
        transport
            .import_gateway_cookies(&origin, &[sample_cookie("sid", "session-value", None)])
            .unwrap();
        transport
            .import_gateway_cookies(&origin, &[sample_cookie("lang", "zh-CN", None)])
            .unwrap();
        let mut names = transport.gateway_cookie_names(&origin);
        names.sort();
        assert_eq!(names, vec!["lang".to_owned(), "sid".to_owned()]);
    }

    #[test]
    fn exports_imported_cookie_value_by_name_without_logging_it() {
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let origin = Url::parse("https://atrust.example.edu/").unwrap();
        transport
            .import_gateway_cookies(
                &origin,
                &[sample_cookie("sid", "session-secret-value", None)],
            )
            .unwrap();
        assert_eq!(
            transport.gateway_cookie_value(&origin, "SID").as_deref(),
            Some("session-secret-value")
        );
        assert_eq!(transport.gateway_cookie_value(&origin, "missing"), None);
        assert!(!format!("{transport:?}").contains("session-secret-value"));
    }

    #[test]
    fn session_cookie_value_reads_the_live_jar_case_insensitively() {
        // `import_gateway_cookies` also writes the jar, so the SID is readable back through
        // the jar path used to export a session established by a non-browser (password) login.
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let origin = Url::parse("https://atrust.example.edu/").unwrap();
        transport
            .import_gateway_cookies(&origin, &[sample_cookie("sid", "SID-from-jar", None)])
            .unwrap();
        assert_eq!(
            transport.session_cookie_value(&origin, "sid").as_deref(),
            Some("SID-from-jar")
        );
        assert_eq!(
            transport.session_cookie_value(&origin, "SID").as_deref(),
            Some("SID-from-jar")
        );
        assert_eq!(transport.session_cookie_value(&origin, "absent"), None);
    }

    #[test]
    fn session_cookies_export_every_jar_entry_for_reimport() {
        // Persisting a session must capture the whole jar, not just the SID, and
        // the exported shape must round-trip back through `import_gateway_cookies`.
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let origin = Url::parse("https://atrust.example.edu/").unwrap();
        transport
            .import_gateway_cookies(
                &origin,
                &[
                    sample_cookie("sid", "sid-value", None),
                    sample_cookie("lang", "zh-CN", None),
                ],
            )
            .unwrap();

        let exported = transport.session_cookies(&origin);
        let mut pairs = exported
            .iter()
            .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
            .collect::<Vec<_>>();
        pairs.sort();
        assert_eq!(pairs, vec![("lang", "zh-CN"), ("sid", "sid-value")]);
        assert!(exported.iter().all(|cookie| cookie.domain.as_deref()
            == Some("atrust.example.edu")
            && cookie.path.as_deref() == Some("/")));

        let restored = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        restored.import_gateway_cookies(&origin, &exported).unwrap();
        assert_eq!(
            restored.session_cookie_value(&origin, "sid").as_deref(),
            Some("sid-value")
        );
    }

    #[test]
    fn session_cookies_are_empty_without_a_jar_entry() {
        let transport = ReqwestTransport::new(&ReqwestTransportConfig::default()).unwrap();
        let origin = Url::parse("https://atrust.example.edu/").unwrap();
        assert!(transport.session_cookies(&origin).is_empty());
    }
}
