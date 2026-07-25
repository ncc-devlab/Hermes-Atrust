use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::header::{HeaderName, HeaderValue};
use thiserror::Error;
use tracing::{debug, warn};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Transport-neutral HTTP request. Headers must already be free of secrets before logging.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
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
        Ok(HttpResponse { status, body })
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
    #[error("HTTP request failed: {0}")]
    Request(#[source] reqwest::Error),
    #[error("HTTP response exceeds the configured {limit} byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("mock transport failure: {0}")]
    Mock(String),
}

#[cfg(test)]
mod tests {
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
}
