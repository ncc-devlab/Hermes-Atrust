use std::time::Duration;

use atrust_auth::{CasChallenge, CasExchange};
use futures_util::{SinkExt as _, StreamExt as _};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use tokio_tungstenite::{connect_async, tungstenite};
use url::Url;

const WEBDRIVER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_WEBDRIVER_RESPONSE: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("invalid WebDriver endpoint")]
    InvalidEndpoint(#[source] url::ParseError),
    #[error("WebDriver request failed")]
    Request(#[source] reqwest::Error),
    #[error("WebDriver returned HTTP {0}")]
    WebDriverStatus(StatusCode),
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
    #[error("timed out waiting for the aTrust login completion")]
    CallbackTimeout,
    #[error("browser returned an invalid aTrust completion URL")]
    InvalidCompletion(#[source] atrust_auth::CasError),
    #[error("browser did not block the aTrust completion page before loading it")]
    CompletionNotIntercepted,
}

#[derive(Debug)]
pub struct WebDriverBrowser {
    client: Client,
    endpoint: Url,
    session_id: String,
    bidi_endpoint: Url,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserKind {
    Firefox,
    Chrome,
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
            BrowserKind::Chrome => json!({
                "alwaysMatch": {
                    "browserName": "chrome",
                    "webSocketUrl": true,
                    "goog:chromeOptions": {
                        // Isolated process/profile; does not touch the user's default Chrome profile.
                        "args": [
                            "--user-data-dir=/tmp/hermes-chrome-profile",
                            "--no-first-run",
                            "--no-default-browser-check",
                            "--disable-sync",
                            "--disable-background-networking"
                        ]
                    }
                }
            }),
        };
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

    /// Lets IDS and intermediate aTrust multi-factor pages run in the browser, then harvests
    /// credentials only after the final same-gateway portal entry is reached.
    pub async fn complete_cas(
        &self,
        challenge: CasChallenge,
        timeout: Duration,
    ) -> Result<CasExchange, BrowserError> {
        let deadline = Instant::now() + timeout;
        let (mut events, _) = timeout_at(deadline, connect_async(self.bidi_endpoint.as_str()))
            .await
            .map_err(|_| BrowserError::CallbackTimeout)?
            .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        let portal = challenge.portal_url();
        let mut pattern = json!({
            "type": "pattern",
            "protocol": portal.scheme(),
            "hostname": portal.host_str(),
            "pathname": portal.path()
        });
        if let Some(port) = portal.port_or_known_default() {
            pattern["port"] = json!(port.to_string());
        }
        let mut next_command_id = 1_u64;
        events
            .send(tungstenite::Message::Text(
                json!({
                    "id": next_command_id,
                    "method": "network.addIntercept",
                    "params": {
                        "phases": ["beforeRequestSent"],
                        "urlPatterns": [pattern]
                    }
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        wait_for_command(&mut events, next_command_id, deadline).await?;
        next_command_id += 1;
        events
            .send(tungstenite::Message::Text(
                json!({
                    "id": next_command_id,
                    "method": "session.subscribe",
                    "params": { "events": ["network.beforeRequestSent"] }
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        wait_for_command(&mut events, next_command_id, deadline).await?;
        next_command_id += 1;

        self.command(
            reqwest::Method::POST,
            "url",
            Some(json!({ "url": challenge.login_url.as_str() })),
        )
        .await?;

        loop {
            let message = timeout_at(deadline, events.next())
                .await
                .map_err(|_| BrowserError::CallbackTimeout)?
                .ok_or(BrowserError::InvalidBidiResponse)?
                .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
            let tungstenite::Message::Text(message) = message else {
                continue;
            };
            let event: Value =
                serde_json::from_str(&message).map_err(|_| BrowserError::InvalidBidiResponse)?;
            if event.get("method").and_then(Value::as_str) != Some("network.beforeRequestSent") {
                continue;
            }
            let Some(current) = event.pointer("/params/request/url").and_then(Value::as_str) else {
                continue;
            };
            let current = Url::parse(current).map_err(BrowserError::InvalidBrowserUrl)?;
            if !challenge.is_completion_target(&current) {
                continue;
            }
            if event.pointer("/params/isBlocked").and_then(Value::as_bool) != Some(true) {
                return Err(BrowserError::CompletionNotIntercepted);
            }
            let request = event
                .pointer("/params/request/request")
                .and_then(Value::as_str)
                .ok_or(BrowserError::InvalidBidiResponse)?;
            events
                .send(tungstenite::Message::Text(
                    json!({
                        "id": next_command_id,
                        "method": "network.failRequest",
                        "params": { "request": request }
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
            wait_for_command(&mut events, next_command_id, deadline).await?;
            return challenge
                .finish_completion(&current)
                .map_err(BrowserError::InvalidCompletion);
        }
    }

    pub async fn close(self) -> Result<(), BrowserError> {
        let response = self
            .client
            .delete(self.session_url("")?)
            .send()
            .await
            .map_err(BrowserError::Request)?;
        // Session may already be gone after failRequest/navigation teardown.
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(BrowserError::WebDriverStatus(response.status()))
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

async fn response_value(response: reqwest::Response) -> Result<Value, BrowserError> {
    if !response.status().is_success() {
        return Err(BrowserError::WebDriverStatus(response.status()));
    }
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
    let envelope: Value =
        serde_json::from_slice(&body).map_err(|_| BrowserError::InvalidResponse)?;
    envelope
        .get("value")
        .cloned()
        .ok_or(BrowserError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::normalized_endpoint;

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
}
