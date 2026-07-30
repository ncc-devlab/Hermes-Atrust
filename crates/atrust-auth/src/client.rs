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
use tracing::{debug, info, warn};
use url::Url;

use crate::auth_config::{AuthConfigEnvelope, AuthConfigOptions, AuthConfiguration};
use crate::cas::{CasCallbackCredential, CasChallenge, CasError, CasExchange, parse_portal_ticket};
use crate::password::{
    PasswordAuthOutcome, PasswordCredentials, PasswordEnvelope, PasswordError, PasswordRequest,
};
use crate::profile::AuthProtocolProfile;
use crate::resource::{ClientResourceRequest, ClientResources, ResourceError};
use crate::session::{
    AuthStep, AuthStepData, BusinessEnvelope, OnlineInfoData, ReportEnvRequest, SessionProgress,
};

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

    /// Consumes a browser-produced CAS service ticket in the aTrust HTTP session.
    ///
    /// The expected portal redirect is inherited from the legacy client and remains a
    /// protocol-validation gate until confirmed against each supported gateway profile.
    pub async fn exchange_cas_credential(
        &self,
        configuration: &AuthConfiguration,
        credential: CasCallbackCredential,
    ) -> Result<CasExchange, AuthError> {
        if credential.callback_authority != self.auth_authority() {
            return Err(AuthError::CasCredentialGatewayMismatch);
        }
        let mut url = self.endpoint_url("/passport/v1/auth/cas")?;
        url.query_pairs_mut()
            .append_pair("sfDomain", &credential.login_domain)
            .append_pair("ticket", credential.service_ticket.expose());
        let mut request = HttpRequest::get(url);
        request
            .headers
            .push(("user-agent".to_owned(), self.profile.user_agent.to_owned()));
        request
            .headers
            .push(("x-csrf-token".to_owned(), configuration.csrf_token.clone()));
        request
            .headers
            .push(("x-sdp-traceid".to_owned(), random_trace_id()));

        let response = self.transport.execute(request).await?;
        if response.status != 302 {
            return Err(AuthError::UnexpectedCasStatus(response.status));
        }
        let location = response.location.ok_or(AuthError::MissingCasRedirect)?;
        let redirect = Url::parse(&location).map_err(AuthError::InvalidCasRedirect)?;
        let portal_ticket = parse_portal_ticket(&redirect, &self.auth_authority())
            .map_err(AuthError::from_portal_error)?;
        Ok(CasExchange { portal_ticket })
    }

    /// Continues after browser login has already entered the portal and produced a portal ticket.
    ///
    /// This intentionally does not auto-complete SMS/MFA; unsupported next services become
    /// `SessionProgress::InteractionRequired`.
    pub async fn establish_session_from_portal(
        &self,
        configuration: &AuthConfiguration,
        exchange: &CasExchange,
        device_id: &DeviceId,
    ) -> Result<SessionProgress, AuthError> {
        self.report_env(configuration, &exchange.portal_ticket, device_id)
            .await?;
        let step = self.auth_check(configuration).await?;
        if !step.is_complete() {
            if step.service == "auth/authCheck" {
                // Some gateways return authCheck as a no-op loop starter; query once more.
                let step = self.auth_check(configuration).await?;
                if !step.is_complete() {
                    return Ok(SessionProgress::InteractionRequired {
                        service: step.service,
                        auth_id: step.auth_id,
                    });
                }
            } else {
                return Ok(SessionProgress::InteractionRequired {
                    service: step.service,
                    auth_id: step.auth_id,
                });
            }
        }
        let username = self.online_info(configuration).await.ok();
        Ok(SessionProgress::Established {
            username,
            sid_present: false,
        })
    }

    pub async fn report_env(
        &self,
        configuration: &AuthConfiguration,
        portal_ticket: &SecretString,
        device_id: &DeviceId,
    ) -> Result<(), AuthError> {
        let mut url = self.endpoint_url("/controller/v1/public/reportEnv")?;
        self.append_shared_query(&mut url);
        let body = to_wire_json(&ReportEnvRequest::new(portal_ticket, device_id))?;
        let mut request = HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: Vec::new(),
            body,
        };
        self.append_auth_headers(&mut request, configuration, false);
        debug!(
            event = "atrust.report_env.request",
            host = self.endpoint.host()
        );
        let response = self.transport.execute(request).await?;
        if !response.is_success() {
            return Err(AuthError::UnexpectedStatus(response.status));
        }
        let envelope: BusinessEnvelope<serde_json::Value> =
            serde_json::from_slice(&response.body).map_err(AuthError::InvalidSessionResponse)?;
        if envelope.code != 0 {
            return Err(AuthError::AuthenticationRejected {
                code: envelope.code,
                message: envelope.message,
            });
        }
        debug!(
            event = "atrust.report_env.complete",
            host = self.endpoint.host()
        );
        Ok(())
    }

    pub async fn auth_check(
        &self,
        configuration: &AuthConfiguration,
    ) -> Result<AuthStep, AuthError> {
        let mut url = self.endpoint_url("/passport/v1/auth/authCheck")?;
        self.append_shared_query(&mut url);
        let mut request = HttpRequest::get(url);
        self.append_auth_headers(&mut request, configuration, false);
        debug!(
            event = "atrust.auth_check.request",
            host = self.endpoint.host()
        );
        let response = self.transport.execute(request).await?;
        if !response.is_success() {
            return Err(AuthError::UnexpectedStatus(response.status));
        }
        let envelope: BusinessEnvelope<AuthStepData> =
            serde_json::from_slice(&response.body).map_err(AuthError::InvalidSessionResponse)?;
        if envelope.code != 0 {
            return Err(AuthError::AuthenticationRejected {
                code: envelope.code,
                message: envelope.message,
            });
        }
        let step = AuthStep::from_data(envelope.data);
        debug!(
            event = "atrust.auth_check.complete",
            host = self.endpoint.host(),
            next_service = %step.service,
            auth_id_present = step.auth_id.is_some()
        );
        Ok(step)
    }

    pub async fn online_info(
        &self,
        configuration: &AuthConfiguration,
    ) -> Result<String, AuthError> {
        let mut url = self.endpoint_url("/passport/v1/user/onlineInfo")?;
        self.append_shared_query(&mut url);
        let mut request = HttpRequest::get(url);
        self.append_auth_headers(&mut request, configuration, false);
        debug!(
            event = "atrust.online_info.request",
            host = self.endpoint.host()
        );
        let response = self.transport.execute(request).await?;
        if !response.is_success() {
            return Err(AuthError::UnexpectedStatus(response.status));
        }
        let envelope: BusinessEnvelope<OnlineInfoData> =
            serde_json::from_slice(&response.body).map_err(AuthError::InvalidSessionResponse)?;
        if envelope.code != 0 {
            return Err(AuthError::AuthenticationRejected {
                code: envelope.code,
                message: envelope.message,
            });
        }
        if envelope.data.username.is_empty() {
            return Err(AuthError::MissingOnlineUsername);
        }
        debug!(
            event = "atrust.online_info.complete",
            host = self.endpoint.host(),
            username_present = true
        );
        Ok(envelope.data.username)
    }

    /// Fetches and strictly parses control-plane resources. Does not open tunnels.
    pub async fn client_resource(
        &self,
        configuration: &AuthConfiguration,
    ) -> Result<ClientResources, AuthError> {
        let body = self.client_resource_body(configuration).await?;
        let resources = match ClientResources::parse_bytes(&body) {
            Ok(resources) => resources,
            Err(error) => {
                warn!(
                    event = "atrust.client_resource.parse_failed",
                    host = self.endpoint.host(),
                    response_bytes = body.len(),
                    error = %error
                );
                return Err(error.into());
            }
        };
        debug!(
            event = "atrust.client_resource.complete",
            host = self.endpoint.host(),
            ip_resource_count = resources.ip_resources.len(),
            domain_resource_count = resources.domain_resources.len(),
            node_group_count = resources.node_groups.len(),
            major_node_group_present = resources.major_node_group_id.is_some(),
            dns_primary_present = resources.dns.primary.is_some()
        );
        Ok(resources)
    }

    /// Fetches the raw `clientResource` body without parsing it.
    ///
    /// Exposed so a diagnostic run can save the exact bytes once and then iterate
    /// on resource matching entirely offline. The body describes server policy
    /// (apps, address ranges, node groups), not session credentials.
    pub async fn client_resource_body(
        &self,
        configuration: &AuthConfiguration,
    ) -> Result<Vec<u8>, AuthError> {
        let mut url = self.endpoint_url("/controller/v1/user/clientResource")?;
        self.append_shared_query(&mut url);
        let body = ClientResourceRequest::default_request().to_bytes()?;
        let mut request = HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: Vec::new(),
            body,
        };
        self.append_auth_headers(&mut request, configuration, false);
        debug!(
            event = "atrust.client_resource.request",
            host = self.endpoint.host(),
            request_body_bytes = request.body.len()
        );
        let response = match self.transport.execute(request).await {
            Ok(response) => response,
            Err(error) => {
                warn!(
                    event = "atrust.client_resource.transport_failed",
                    host = self.endpoint.host(),
                    error = %error,
                    error_debug = ?error
                );
                return Err(error.into());
            }
        };
        if !response.is_success() {
            warn!(
                event = "atrust.client_resource.unexpected_status",
                host = self.endpoint.host(),
                status = response.status,
                response_bytes = response.body.len()
            );
            return Err(AuthError::UnexpectedStatus(response.status));
        }
        info!(
            event = "atrust.client_resource.response",
            host = self.endpoint.host(),
            status = response.status,
            response_bytes = response.body.len()
        );
        Ok(response.body)
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

    fn append_auth_headers(
        &self,
        request: &mut HttpRequest,
        configuration: &AuthConfiguration,
        include_rid: bool,
    ) {
        request
            .headers
            .push(("user-agent".to_owned(), self.profile.user_agent.to_owned()));
        if !request.body.is_empty() {
            request.headers.push((
                "content-type".to_owned(),
                "application/json;charset=utf-8".to_owned(),
            ));
        }
        if !configuration.csrf_token.is_empty() {
            request
                .headers
                .push(("x-csrf-token".to_owned(), configuration.csrf_token.clone()));
        }
        if include_rid {
            request
                .headers
                .push(("x-sdp-rid".to_owned(), BASE64.encode(self.auth_authority())));
        }
        request
            .headers
            .push(("x-sdp-traceid".to_owned(), random_trace_id()));
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

impl AuthError {
    fn from_portal_error(error: CasError) -> Self {
        match error {
            CasError::InvalidPortalScheme
            | CasError::InvalidPortalAuthority
            | CasError::InvalidPortalPath
            | CasError::InvalidPortalUrl
            | CasError::PortalUrlTooLong => Self::InvalidCasRedirectTarget,
            CasError::InvalidPortalData => Self::InvalidPortalData(error),
            CasError::MissingPortalTicket => Self::MissingPortalTicket,
            other => Self::Cas(other),
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
    #[error("CAS credential belongs to another aTrust gateway")]
    CasCredentialGatewayMismatch,
    #[error("aTrust CAS exchange returned unexpected HTTP status {0}")]
    UnexpectedCasStatus(u16),
    #[error("aTrust CAS exchange did not return a redirect")]
    MissingCasRedirect,
    #[error("aTrust CAS exchange returned an invalid redirect URL: {0}")]
    InvalidCasRedirect(#[source] url::ParseError),
    #[error("aTrust CAS exchange redirected outside the expected portal endpoint")]
    InvalidCasRedirectTarget,
    #[error("aTrust CAS redirect contains invalid portal data: {0}")]
    InvalidPortalData(#[source] CasError),
    #[error("aTrust CAS redirect does not contain exactly one non-empty portal ticket")]
    MissingPortalTicket,
    #[error("aTrust returned an invalid session response: {0}")]
    InvalidSessionResponse(#[source] serde_json::Error),
    #[error("aTrust onlineInfo did not return a username")]
    MissingOnlineUsername,
    #[error("failed to parse clientResource: {0}")]
    Resource(#[from] ResourceError),
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hermes_transport::{HttpMethod, HttpResponse, HttpTransportError};
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
                location: None,
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
                location: None,
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
                location: None,
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

    #[tokio::test]
    async fn exchanges_web_credential_for_strict_portal_ticket() {
        let location = "https://atrust.example.edu/portal/shortcut.html?data=%7B%22ticket%22%3A%22portal-secret%22%7D";
        let transport = Arc::new(MockTransport {
            response: HttpResponse {
                status: 302,
                location: Some(location.to_owned()),
                body: Vec::new(),
            },
            requests: Mutex::new(Vec::new()),
        });
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let client = AuthClient::new(endpoint.clone(), transport.clone());
        let challenge = CasChallenge::new(
            &endpoint,
            "cas-domain".to_owned(),
            "https://ids.example.edu/login",
        )
        .unwrap();
        let callback = Url::parse(
            "https://atrust.example.edu/passport/v1/auth/cas?sfDomain=cas-domain&ticket=service-secret",
        )
        .unwrap();
        let credential = challenge.finish(&callback).unwrap();
        let configuration = AuthConfiguration {
            login_state: LoginState::LoggedOut,
            methods: Vec::new(),
            csrf_token: "csrf-secret".to_owned(),
            public_key: String::new(),
            public_key_exponent: String::new(),
            anti_replay_random: String::new(),
        };

        let exchange = client
            .exchange_cas_credential(&configuration, credential)
            .await
            .unwrap();

        assert_eq!(exchange.portal_ticket.expose(), "portal-secret");
        let requests = transport.requests.lock().unwrap();
        let query: std::collections::HashMap<_, _> = requests[0].url.query_pairs().collect();
        assert_eq!(query.get("sfDomain").unwrap(), "cas-domain");
        assert_eq!(query.get("ticket").unwrap(), "service-secret");
        assert!(
            requests[0]
                .headers
                .iter()
                .any(|(name, value)| name == "x-csrf-token" && value == "csrf-secret")
        );
        assert!(!format!("{:?}", requests[0]).contains("service-secret"));
    }

    #[test]
    fn rejects_cross_origin_portal_redirect() {
        let redirect = Url::parse(
            "https://attacker.example/portal/shortcut.html?data=%7B%22ticket%22%3A%22secret%22%7D",
        )
        .unwrap();
        assert!(matches!(
            parse_portal_ticket(&redirect, "atrust.example.edu"),
            Err(CasError::InvalidPortalAuthority)
        ));
    }

    #[derive(Debug)]
    struct QueueTransport {
        responses: Mutex<std::collections::VecDeque<HttpResponse>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl QueueTransport {
        fn new(responses: Vec<HttpResponse>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl HttpTransport for QueueTransport {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| HttpTransportError::Mock("no queued response".to_owned()))
        }
    }

    fn session_configuration() -> AuthConfiguration {
        AuthConfiguration {
            login_state: LoginState::LoggedIn,
            methods: Vec::new(),
            csrf_token: "csrf-session".to_owned(),
            public_key: String::new(),
            public_key_exponent: String::new(),
            anti_replay_random: String::new(),
        }
    }

    fn ok_json(body: &'static str) -> HttpResponse {
        HttpResponse {
            status: 200,
            location: None,
            body: body.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn report_env_posts_ticket_and_rejects_nonzero_code() {
        let transport = QueueTransport::new(vec![ok_json(
            r#"{"code":1,"message":"ticket used","data":{}}"#,
        )]);
        let client = AuthClient::new(
            GatewayEndpoint::new("atrust.example.edu", 443).unwrap(),
            transport.clone(),
        );
        let ticket = SecretString::new("portal-ticket").unwrap();
        let err = client
            .report_env(
                &session_configuration(),
                &ticket,
                &DeviceId::new("device-id").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AuthError::AuthenticationRejected { code: 1, .. }
        ));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests[0].url.path(), "/controller/v1/public/reportEnv");
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert!(
            requests[0]
                .headers
                .iter()
                .any(|(name, value)| name == "x-csrf-token" && value == "csrf-session")
        );
        assert!(!format!("{:?}", requests[0]).contains("portal-ticket"));
    }

    #[tokio::test]
    async fn auth_check_maps_next_service_and_complete() {
        let transport = QueueTransport::new(vec![
            ok_json(
                r#"{"code":0,"message":"","data":{"nextService":"auth/sms","nextServiceList":[{"authId":"sms-1","authType":"auth/sms"}]}}"#,
            ),
            ok_json(r#"{"code":0,"message":"","data":{}}"#),
        ]);
        let client = AuthClient::new(
            GatewayEndpoint::new("atrust.example.edu", 443).unwrap(),
            transport.clone(),
        );
        let configuration = session_configuration();

        let sms = client.auth_check(&configuration).await.unwrap();
        assert_eq!(sms.service, "auth/sms");
        assert_eq!(sms.auth_id.as_deref(), Some("sms-1"));
        assert!(!sms.is_complete());

        let done = client.auth_check(&configuration).await.unwrap();
        assert!(done.is_complete());
        let paths: Vec<_> = transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(
            paths,
            vec![
                "/passport/v1/auth/authCheck".to_owned(),
                "/passport/v1/auth/authCheck".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn online_info_returns_username_and_rejects_empty() {
        let transport = QueueTransport::new(vec![
            ok_json(r#"{"code":0,"message":"","data":{"username":"student"}}"#),
            ok_json(r#"{"code":0,"message":"","data":{"username":""}}"#),
        ]);
        let client = AuthClient::new(
            GatewayEndpoint::new("atrust.example.edu", 443).unwrap(),
            transport.clone(),
        );
        let configuration = session_configuration();

        let username = client.online_info(&configuration).await.unwrap();
        assert_eq!(username, "student");
        assert!(!format!("{:?}", transport.requests.lock().unwrap()[0]).contains("student"));

        let err = client.online_info(&configuration).await.unwrap_err();
        assert!(matches!(err, AuthError::MissingOnlineUsername));
        let paths: Vec<_> = transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(
            paths,
            vec![
                "/passport/v1/user/onlineInfo".to_owned(),
                "/passport/v1/user/onlineInfo".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn establish_session_reports_interaction_for_sms() {
        let transport = QueueTransport::new(vec![
            ok_json(r#"{"code":0,"message":"","data":{}}"#),
            ok_json(
                r#"{"code":0,"message":"","data":{"nextService":"auth/sms","nextServiceList":[{"authId":"sms-9","authType":"auth/sms"}]}}"#,
            ),
        ]);
        let client = AuthClient::new(
            GatewayEndpoint::new("atrust.example.edu", 443).unwrap(),
            transport,
        );
        let exchange = CasExchange {
            portal_ticket: SecretString::new("portal-ticket").unwrap(),
        };
        let progress = client
            .establish_session_from_portal(
                &session_configuration(),
                &exchange,
                &DeviceId::new("device-id").unwrap(),
            )
            .await
            .unwrap();
        match progress {
            SessionProgress::InteractionRequired { service, auth_id } => {
                assert_eq!(service, "auth/sms");
                assert_eq!(auth_id.as_deref(), Some("sms-9"));
            }
            SessionProgress::Established { .. } => panic!("expected SMS interaction"),
        }
    }

    #[tokio::test]
    async fn client_resource_posts_expected_body_and_parses_summary() {
        let body = r#"{
            "code":0,
            "data":{
                "appList":{"data":{"appInfo":[{"apps":[{
                    "id":"app-1","nodeGroupId":"ng-1",
                    "addressList":[{"protocol":"tcp","port":"443","host":"10.0.0.1"}]
                }]}],
                "config":{"nodeGroupConf":{"majorNodeGroup":{"id":"ng-1"},"nodeGroupList":[
                    {"id":"ng-1","addressInfo":[{"address":"10.9.0.1:441","type":"ip"}]}
                ]}}}},
                "sdpPolicy":{"data":{"clientOption":{"dnsOptionV2":{"firstDNS":"10.8.8.8"}}}}
            }
        }"#;
        let transport = QueueTransport::new(vec![ok_json(body)]);
        let client = AuthClient::new(
            GatewayEndpoint::new("atrust.example.edu", 443).unwrap(),
            transport.clone(),
        );
        let resources = client
            .client_resource(&session_configuration())
            .await
            .unwrap();
        assert_eq!(resources.ip_resources.len(), 1);
        assert_eq!(resources.node_groups.len(), 1);
        assert_eq!(resources.dns.primary.as_deref(), Some("10.8.8.8"));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests[0].url.path(), "/controller/v1/user/clientResource");
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert_eq!(
            requests[0].body,
            br#"{"resourceType":{"sdpPolicy":{},"appList":{},"favoriteAppList":{},"featureCenter":{},"uemSpace":{"params":{"action":"login"}}}}"#
        );
        assert!(
            requests[0]
                .headers
                .iter()
                .any(|(name, value)| name == "x-csrf-token" && value == "csrf-session")
        );
        assert!(!format!("{resources:?}").contains("app-1"));
    }

    #[tokio::test]
    async fn establish_session_retries_auth_check_noop_then_establishes() {
        let transport = QueueTransport::new(vec![
            ok_json(r#"{"code":0,"message":"","data":{}}"#),
            ok_json(
                r#"{"code":0,"message":"","data":{"nextService":"auth/authCheck","nextServiceList":[{"authId":"","authType":"auth/authCheck"}]}}"#,
            ),
            ok_json(r#"{"code":0,"message":"","data":{}}"#),
            ok_json(r#"{"code":0,"message":"","data":{"username":"student"}}"#),
        ]);
        let client = AuthClient::new(
            GatewayEndpoint::new("atrust.example.edu", 443).unwrap(),
            transport.clone(),
        );
        let exchange = CasExchange {
            portal_ticket: SecretString::new("portal-ticket").unwrap(),
        };
        let progress = client
            .establish_session_from_portal(
                &session_configuration(),
                &exchange,
                &DeviceId::new("device-id").unwrap(),
            )
            .await
            .unwrap();
        match progress {
            SessionProgress::Established {
                username,
                sid_present,
            } => {
                assert_eq!(username.as_deref(), Some("student"));
                assert!(!sid_present);
            }
            SessionProgress::InteractionRequired { .. } => panic!("expected established"),
        }
        let paths: Vec<_> = transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(
            paths,
            vec![
                "/controller/v1/public/reportEnv".to_owned(),
                "/passport/v1/auth/authCheck".to_owned(),
                "/passport/v1/auth/authCheck".to_owned(),
                "/passport/v1/user/onlineInfo".to_owned(),
            ]
        );
    }
}
