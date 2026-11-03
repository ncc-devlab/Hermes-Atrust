use async_trait::async_trait;
use atrust_auth::{AuthClient, AuthConfiguration, LoginState, SessionMaterial};
use atrust_client::{AtrustClient, AtrustClientConfig};
use hermes_model::{DeviceId, GatewayEndpoint, SecretString};
use hermes_transport::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError, TlsPolicy};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct Resources(pub String);
#[async_trait]
impl HttpTransport for Resources {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        Ok(HttpResponse {
            status: 200,
            location: None,
            body: if request.url.path().contains("onlineInfo") {
                br#"{"code":0,"data":{"username":"test"}}"#.to_vec()
            } else {
                self.0.as_bytes().to_vec()
            },
        })
    }
}
pub(crate) fn config() -> AuthConfiguration {
    AuthConfiguration {
        login_state: LoginState::LoggedIn,
        methods: vec![],
        csrf_token: "test".into(),
        public_key: String::new(),
        public_key_exponent: String::new(),
        anti_replay_random: String::new(),
    }
}
pub(crate) fn material() -> SessionMaterial {
    SessionMaterial::from_cookie_sid(
        &SecretString::new("test-sid").unwrap(),
        "sid",
        true,
        DeviceId::new("test-device").unwrap(),
        None,
        None,
    )
    .unwrap()
}
pub(crate) fn auth(prefers_l3: bool) -> Arc<AuthClient> {
    let resource = format!(
        r#"{{"code":0,"data":{{"appList":{{"data":{{"appInfo":[{{"apps":[{{"id":"a","nodeGroupId":"g","enableTCPPrefL3":{prefers_l3},"addressList":[{{"protocol":"all","host":"10.0.0.0/8","port":"1-65535"}},{{"protocol":"all","host":"*.test","port":"1-65535"}}]}}]}}]}}}}}}}}"#
    );
    Arc::new(AuthClient::new(
        GatewayEndpoint::new("gateway.test", 443).unwrap(),
        Arc::new(Resources(resource)),
    ))
}
pub(crate) async fn client(prefers_l3: bool) -> Arc<AtrustClient> {
    AtrustClient::start(
        auth(prefers_l3),
        config(),
        material(),
        AtrustClientConfig::new(
            GatewayEndpoint::new("gateway.test", 443).unwrap(),
            TlsPolicy::Verify,
        )
        .with_node_refresh_interval(std::time::Duration::ZERO),
    )
    .await
    .unwrap()
}
