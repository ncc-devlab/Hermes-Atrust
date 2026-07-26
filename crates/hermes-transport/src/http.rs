use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt as _;
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

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError>;
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

#[derive(Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    max_response_body: usize,
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

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .timeout(config.timeout)
            .danger_accept_invalid_certs(dangerous_tls)
            .build()
            .map_err(HttpTransportError::BuildClient)?;

        Ok(Self {
            client,
            max_response_body: config.max_response_body,
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

        let response = builder.send().await.map_err(HttpTransportError::Request)?;
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .map_err(HttpTransportError::InvalidResponseHeader)?;
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_body as u64)
        {
            return Err(HttpTransportError::ResponseTooLarge {
                limit: self.max_response_body,
            });
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(HttpTransportError::Request)?;
            if body.len().saturating_add(chunk.len()) > self.max_response_body {
                return Err(HttpTransportError::ResponseTooLarge {
                    limit: self.max_response_body,
                });
            }
            body.extend_from_slice(&chunk);
        }

        debug!(
            event = "transport.http_complete",
            method = method_name,
            host,
            status,
            elapsed_ms = started.elapsed().as_millis(),
            response_bytes = body.len()
        );
        Ok(HttpResponse {
            status,
            location,
            body,
        })
    }
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
    #[error("HTTP response exceeds the configured {limit} byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("mock transport failure: {0}")]
    Mock(String),
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
}
