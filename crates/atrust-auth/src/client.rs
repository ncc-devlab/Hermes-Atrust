use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hermes_model::GatewayEndpoint;
use hermes_transport::{HttpRequest, HttpTransport, HttpTransportError};
use rand::Rng as _;
use thiserror::Error;
use tracing::debug;
use url::Url;

use crate::auth_config::{AuthConfigEnvelope, AuthConfigOptions, AuthConfiguration};
use crate::profile::AuthProtocolProfile;

pub struct AuthClient {
    endpoint: GatewayEndpoint,
    profile: AuthProtocolProfile,
    transport: Arc<dyn HttpTransport>,
}

impl fmt::Debug for AuthClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthClient")
            .field("endpoint", &self.endpoint)
            .field("profile", &self.profile)
            .field("transport", &"dyn HttpTransport")
            .finish()
    }
}

impl AuthClient {
    pub fn new(endpoint: GatewayEndpoint, transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            endpoint,
            profile: AuthProtocolProfile::default(),
            transport,
        }
    }

    pub fn with_profile(
        endpoint: GatewayEndpoint,
        transport: Arc<dyn HttpTransport>,
        profile: AuthProtocolProfile,
    ) -> Self {
        Self {
            endpoint,
            profile,
            transport,
        }
    }

    pub async fn auth_config(
        &self,
        options: AuthConfigOptions,
    ) -> Result<AuthConfiguration, AuthError> {
        let mut url = self.auth_config_url()?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("clientType", self.profile.client_type);
            query.append_pair("platform", self.profile.platform);
            query.append_pair("lang", self.profile.language);
            if options.modified {
                query.append_pair("mod", "1");
            }
            if options.need_ticket {
                query.append_pair("needTicket", "1");
            }
        }

        let mut request = HttpRequest::get(url);
        request
            .headers
            .push(("user-agent".to_owned(), self.profile.user_agent.to_owned()));
        request
            .headers
            .push(("x-sdp-rid".to_owned(), BASE64.encode(self.auth_authority())));
        request
            .headers
            .push(("x-sdp-traceid".to_owned(), random_trace_id()));

        debug!(
            event = "atrust.auth_config.request",
            host = self.endpoint.host()
        );
        let response = self.transport.execute(request).await?;
        if !response.is_success() {
            return Err(AuthError::UnexpectedStatus(response.status));
        }
        let envelope: AuthConfigEnvelope =
            serde_json::from_slice(&response.body).map_err(AuthError::InvalidResponse)?;
        let configuration = AuthConfiguration::from(envelope.data);
        debug!(
            event = "atrust.auth_config.complete",
            host = self.endpoint.host(),
            auth_method_count = configuration.methods.len(),
            login_state = ?configuration.login_state
        );
        Ok(configuration)
    }

    fn auth_config_url(&self) -> Result<Url, AuthError> {
        Url::parse(&format!(
            "https://{}/passport/v1/public/authConfig",
            self.auth_authority()
        ))
        .map_err(AuthError::InvalidUrl)
    }

    fn auth_authority(&self) -> String {
        if self.endpoint.port() == 443 {
            let host = self.endpoint.host();
            if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host.to_owned()
            }
        } else {
            self.endpoint.to_string()
        }
    }
}

fn random_trace_id() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| HEX[rng.random_range(0..HEX.len())] as char)
        .collect()
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid aTrust URL: {0}")]
    InvalidUrl(#[source] url::ParseError),
    #[error("aTrust transport failed: {0}")]
    Transport(#[from] HttpTransportError),
    #[error("aTrust returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    #[error("aTrust returned an invalid authConfig response: {0}")]
    InvalidResponse(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hermes_transport::{HttpResponse, HttpTransportError};

    use super::*;
    use crate::{AuthConfigOptions, LoginState};

    #[derive(Debug)]
    struct MockTransport {
        response: HttpResponse,
        requests: Mutex<Vec<HttpRequest>>,
    }

    #[async_trait]
    impl HttpTransport for MockTransport {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            self.requests.lock().unwrap().push(request);
            Ok(self.response.clone())
        }
    }

    fn client_with_response(body: &'static [u8]) -> (AuthClient, Arc<MockTransport>) {
        let transport = Arc::new(MockTransport {
            response: HttpResponse {
                status: 200,
                body: body.to_vec(),
            },
            requests: Mutex::new(Vec::new()),
        });
        let endpoint = GatewayEndpoint::new("rvpn.example.edu", 443).unwrap();
        (AuthClient::new(endpoint, transport.clone()), transport)
    }

    #[tokio::test]
    async fn parses_auth_config_and_builds_expected_request() {
        let body = br#"{
            "data": {
                "authServerInfoList": [{
                    "loginDomain": "Radius",
                    "authType": "auth/psw",
                    "authName": "Account",
                    "loginUrl": ""
                }],
                "isLogin": 0,
                "security": {"csrfToken": "csrf-from-security"},
                "pubKey": "ABCDEF",
                "pubKeyExp": "65537",
                "antiReplayRand": "random"
            }
        }"#;
        let (client, transport) = client_with_response(body);

        let result = client
            .auth_config(AuthConfigOptions {
                modified: true,
                need_ticket: true,
            })
            .await
            .unwrap();

        assert_eq!(result.login_state, LoginState::LoggedOut);
        assert_eq!(result.csrf_token, "csrf-from-security");
        assert_eq!(result.methods.len(), 1);
        let requests = transport.requests.lock().unwrap();
        let request = &requests[0];
        assert_eq!(request.url.path(), "/passport/v1/public/authConfig");
        let query: std::collections::HashMap<_, _> = request.url.query_pairs().collect();
        assert_eq!(query.get("clientType").unwrap(), "SDPClient");
        assert_eq!(query.get("mod").unwrap(), "1");
        assert_eq!(query.get("needTicket").unwrap(), "1");
        assert!(request.headers.iter().any(|(name, value)| {
            name == "x-sdp-traceid"
                && value.len() == 8
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }));
        let rid = request
            .headers
            .iter()
            .find(|(name, _)| name == "x-sdp-rid")
            .map(|(_, value)| value)
            .unwrap();
        assert_eq!(BASE64.decode(rid).unwrap(), b"rvpn.example.edu");
    }

    #[tokio::test]
    async fn rejects_error_envelope_without_data() {
        let (client, _) = client_with_response(br#"{"code":500,"message":"failed"}"#);
        assert!(matches!(
            client.auth_config(AuthConfigOptions::default()).await,
            Err(AuthError::InvalidResponse(_))
        ));
    }
}
