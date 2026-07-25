use std::fmt;
use std::sync::Arc;

use atrust_protocol::to_wire_json;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hermes_model::{DeviceId, GatewayEndpoint, SecretString};
use hermes_transport::{HttpMethod, HttpRequest, HttpTransport, HttpTransportError};
use rand::Rng as _;
use serde::Serialize;
use thiserror::Error;
use tracing::debug;
use url::Url;

use crate::auth_config::{AuthConfigEnvelope, AuthConfigOptions, AuthConfiguration};
use crate::cas::{CasChallenge, CasError};
use crate::password::{
    PasswordAuthOutcome, PasswordCredentials, PasswordEnvelope, PasswordError, PasswordRequest,
};
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
        self.append_shared_query(&mut url);
        {
            let mut query = url.query_pairs_mut();
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

    /// Creates a CAS challenge without prescribing how a browser or UI obtains the callback.
    pub fn prepare_cas(
        &self,
        configuration: &AuthConfiguration,
        login_domain: &str,
    ) -> Result<CasChallenge, AuthError> {
        let method = configuration
            .methods
            .iter()
            .find(|method| method.auth_type == "auth/cas" && method.login_domain == login_domain)
            .ok_or(CasError::LoginDomainUnavailable)?;
        CasChallenge::new(
            &self.endpoint,
            method.login_domain.clone(),
            &method.login_url,
        )
        .map_err(AuthError::Cas)
    }

    /// Performs exactly one primary password attempt and never retries credentials or captchas.
    pub async fn authenticate_password(
        &self,
        configuration: &AuthConfiguration,
        credentials: &PasswordCredentials,
        device_id: &DeviceId,
        graph_check_code: Option<&str>,
    ) -> Result<PasswordAuthOutcome, AuthError> {
        if !configuration.methods.iter().any(|method| {
            method.auth_type == "auth/psw" && method.login_domain == credentials.login_domain
        }) {
            return Err(AuthError::PasswordLoginDomainUnavailable);
        }

        let mut url = self.endpoint_url("/passport/v1/auth/psw")?;
        self.append_shared_query(&mut url);
        let body = PasswordRequest::build(configuration, credentials, graph_check_code)?;
        let environment = to_wire_json(&DeviceEnvironment {
            device_id: device_id.as_str(),
        })?;
        let mut request = HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: Vec::new(),
            body,
        };
        request
            .headers
            .push(("user-agent".to_owned(), self.profile.user_agent.to_owned()));
        request.headers.push((
            "content-type".to_owned(),
            "application/json;charset=utf-8".to_owned(),
        ));
        request
            .headers
            .push(("x-csrf-token".to_owned(), configuration.csrf_token.clone()));
        request
            .headers
            .push(("x-sdp-env".to_owned(), BASE64.encode(environment)));
        request
            .headers
            .push(("x-sdp-traceid".to_owned(), random_trace_id()));

        debug!(
            event = "atrust.password.request",
            host = self.endpoint.host(),
            login_domain = credentials.login_domain
        );
        let response = self.transport.execute(request).await?;
        if !response.is_success() {
            return Err(AuthError::UnexpectedStatus(response.status));
        }
        let envelope: PasswordEnvelope =
            serde_json::from_slice(&response.body).map_err(AuthError::InvalidPasswordResponse)?;
        let captcha_required = envelope.data.graph_check_code_enable != 0;
        if envelope.code != 0 && !captcha_required {
            return Err(AuthError::AuthenticationRejected {
                code: envelope.code,
                message: envelope.message,
            });
        }

        let ticket = if envelope.data.ticket.is_empty() {
            None
        } else {
            Some(SecretString::new(envelope.data.ticket).expect("ticket was checked as non-empty"))
        };
        if ticket.is_none() && !captcha_required {
            return Err(AuthError::MissingTicket);
        }
        debug!(
            event = "atrust.password.complete",
            host = self.endpoint.host(),
            captcha_required,
            ticket_received = ticket.is_some()
        );
        Ok(PasswordAuthOutcome {
            ticket,
            captcha_required,
        })
    }

    fn auth_config_url(&self) -> Result<Url, AuthError> {
        self.endpoint_url("/passport/v1/public/authConfig")
    }

    fn endpoint_url(&self, path: &str) -> Result<Url, AuthError> {
        let mut url = Url::parse(&format!("https://{}/", self.auth_authority()))
            .map_err(AuthError::InvalidUrl)?;
        url.set_path(path);
        Ok(url)
    }

    fn append_shared_query(&self, url: &mut Url) {
        let mut query = url.query_pairs_mut();
        query.append_pair("clientType", self.profile.client_type);
        query.append_pair("platform", self.profile.platform);
        query.append_pair("lang", self.profile.language);
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceEnvironment<'a> {
    device_id: &'a str,
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
    #[error("failed to build password request: {0}")]
    Password(#[from] PasswordError),
    #[error("failed to build device environment: {0}")]
    ProtocolJson(#[from] atrust_protocol::ProtocolJsonError),
    #[error("password login domain is unavailable")]
    PasswordLoginDomainUnavailable,
    #[error("authentication rejected with code {code}: {message}")]
    AuthenticationRejected { code: i64, message: String },
    #[error("password authentication succeeded without returning a ticket")]
    MissingTicket,
    #[error("aTrust returned an invalid password response: {0}")]
    InvalidPasswordResponse(#[source] serde_json::Error),
    #[error("failed to prepare CAS authentication: {0}")]
    Cas(#[from] CasError),
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hermes_transport::{HttpResponse, HttpTransportError};
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

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

    #[tokio::test]
    async fn password_request_encrypts_expected_anti_replay_plaintext() {
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let transport = Arc::new(MockTransport {
            response: HttpResponse {
                status: 200,
                body: br#"{"code":0,"message":"","data":{"ticket":"ticket-value","graphCheckCodeEnable":0}}"#.to_vec(),
            },
            requests: Mutex::new(Vec::new()),
        });
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let client = AuthClient::new(endpoint, transport.clone());
        let configuration = AuthConfiguration {
            login_state: LoginState::LoggedOut,
            methods: vec![crate::AuthInfo {
                login_domain: "local".to_owned(),
                auth_type: "auth/psw".to_owned(),
                auth_name: "Local".to_owned(),
                login_url: String::new(),
            }],
            csrf_token: "csrf".to_owned(),
            public_key: format!("{:X}", public_key.n()),
            public_key_exponent: public_key.e().to_string(),
            anti_replay_random: "anti-replay".to_owned(),
        };
        let credentials =
            PasswordCredentials::new("account", SecretString::new("password").unwrap(), "local")
                .unwrap();
        let device_id = DeviceId::new("device-id").unwrap();

        let outcome = client
            .authenticate_password(&configuration, &credentials, &device_id, None)
            .await
            .unwrap();
        assert!(outcome.ticket.is_some());
        assert!(!outcome.captcha_required);

        let requests = transport.requests.lock().unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let query: std::collections::HashMap<_, _> = requests[0].url.query_pairs().collect();
        assert_eq!(query.get("clientType").unwrap(), "SDPClient");
        assert_eq!(query.get("platform").unwrap(), "Linux");
        assert_eq!(query.get("lang").unwrap(), "en-US");
        assert_eq!(body["username"], "account@local");
        assert_eq!(body["rememberPwd"], "0");
        let ciphertext = hex::decode(body["password"].as_str().unwrap()).unwrap();
        let plaintext = private_key.decrypt(Pkcs1v15Encrypt, &ciphertext).unwrap();
        assert_eq!(plaintext, b"password_anti-replay");
    }

    #[tokio::test]
    async fn password_response_can_request_captcha_with_nonzero_code() {
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let transport = Arc::new(MockTransport {
            response: HttpResponse {
                status: 200,
                body: br#"{"code":75500000,"message":"challenge required","data":{"ticket":"","graphCheckCodeEnable":1}}"#.to_vec(),
            },
            requests: Mutex::new(Vec::new()),
        });
        let client = AuthClient::new(
            GatewayEndpoint::new("atrust.example.edu", 443).unwrap(),
            transport,
        );
        let configuration = AuthConfiguration {
            login_state: LoginState::LoggedOut,
            methods: vec![crate::AuthInfo {
                login_domain: "local".to_owned(),
                auth_type: "auth/psw".to_owned(),
                auth_name: "Local".to_owned(),
                login_url: String::new(),
            }],
            csrf_token: "csrf".to_owned(),
            public_key: format!("{:X}", public_key.n()),
            public_key_exponent: public_key.e().to_string(),
            anti_replay_random: "anti-replay".to_owned(),
        };
        let credentials =
            PasswordCredentials::new("account", SecretString::new("password").unwrap(), "local")
                .unwrap();

        let outcome = client
            .authenticate_password(
                &configuration,
                &credentials,
                &DeviceId::new("device-id").unwrap(),
                None,
            )
            .await
            .unwrap();
        assert!(outcome.captcha_required);
        assert!(outcome.ticket.is_none());
    }
}
