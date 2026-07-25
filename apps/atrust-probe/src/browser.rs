use std::time::Duration;

use atrust_auth::CasChallenge;
use futures_util::{SinkExt as _, StreamExt as _};
use hermes_model::SecretString;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use tokio_tungstenite::{connect_async, tungstenite};
use url::Url;

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
    #[error("browser returned an invalid URL")]
    InvalidBrowserUrl(#[source] url::ParseError),
    #[error("WebDriver did not provide a BiDi endpoint")]
    MissingBidiEndpoint,
    #[error("WebDriver BiDi communication failed")]
    Bidi(#[source] Box<tungstenite::Error>),
    #[error("WebDriver BiDi returned an invalid response")]
    InvalidBidiResponse,
    #[error("timed out waiting for the aTrust callback")]
    CallbackTimeout,
}

#[derive(Debug)]
pub struct WebDriverBrowser {
    client: Client,
    endpoint: Url,
    session_id: String,
    bidi_endpoint: Url,
}

impl WebDriverBrowser {
    pub async fn connect(endpoint: &str) -> Result<Self, BrowserError> {
        let endpoint = normalized_endpoint(endpoint)?;
        let client = Client::new();
        let response = client
            .post(
                endpoint
                    .join("session")
                    .map_err(BrowserError::InvalidEndpoint)?,
            )
            .header("content-type", "application/json")
            .body(
                json!({
                    "capabilities": {
                        "alwaysMatch": {
                            "browserName": "firefox",
                            "webSocketUrl": true
                        }
                    }
                })
                .to_string(),
            )
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
            .and_then(|value| Url::parse(value).map_err(BrowserError::InvalidEndpoint))?;

        Ok(Self {
            client,
            endpoint,
            session_id,
            bidi_endpoint,
        })
    }

    pub async fn complete_cas(
        &self,
        challenge: &CasChallenge,
        timeout: Duration,
    ) -> Result<SecretString, BrowserError> {
        let (mut events, _) = connect_async(self.bidi_endpoint.as_str())
            .await
            .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        events
            .send(tungstenite::Message::Text(
                json!({
                    "id": 1,
                    "method": "session.subscribe",
                    "params": { "events": ["network.beforeRequestSent"] }
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        wait_for_subscription(&mut events).await?;

        self.command(
            reqwest::Method::POST,
            "url",
            Some(json!({ "url": challenge.login_url.as_str() })),
        )
        .await?;

        let deadline = Instant::now() + timeout;
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
            if let Ok(ticket) = challenge.validate_callback(&current) {
                return Ok(ticket);
            }
        }
    }

    pub async fn close(self) -> Result<(), BrowserError> {
        let response = self
            .client
            .delete(self.session_url("")?)
            .send()
            .await
            .map_err(BrowserError::Request)?;
        if !response.status().is_success() {
            return Err(BrowserError::WebDriverStatus(response.status()));
        }
        Ok(())
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

async fn wait_for_subscription<S>(events: &mut S) -> Result<(), BrowserError>
where
    S: futures_util::Stream<Item = Result<tungstenite::Message, tungstenite::Error>> + Unpin,
{
    while let Some(message) = events.next().await {
        let message = message.map_err(|error| BrowserError::Bidi(Box::new(error)))?;
        let tungstenite::Message::Text(message) = message else {
            continue;
        };
        let response: Value =
            serde_json::from_str(&message).map_err(|_| BrowserError::InvalidBidiResponse)?;
        if response.get("id").and_then(Value::as_u64) == Some(1) {
            return if response.get("type").and_then(Value::as_str) == Some("success") {
                Ok(())
            } else {
                Err(BrowserError::InvalidBidiResponse)
            };
        }
    }
    Err(BrowserError::InvalidBidiResponse)
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
    let body = response.text().await.map_err(BrowserError::Request)?;
    let envelope: Value = serde_json::from_str(&body).map_err(|_| BrowserError::InvalidResponse)?;
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
