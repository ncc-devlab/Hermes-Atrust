use std::env;
use std::sync::Arc;

use atrust_auth::{AuthClient, AuthConfigOptions};
use hermes_model::GatewayEndpoint;
use hermes_transport::{ReqwestTransport, ReqwestTransportConfig, TlsPolicy};

#[tokio::test]
#[ignore = "requires explicit aTrust live-test environment"]
async fn fetches_live_auth_config() {
    if env::var("HERMES_LIVE_TEST").as_deref() != Ok("1") {
        return;
    }

    let host = env::var("HERMES_ATRUST_HOST").expect("HERMES_ATRUST_HOST is required");
    let port = env::var("HERMES_ATRUST_PORT")
        .map(|value| value.parse().expect("HERMES_ATRUST_PORT must be a u16"))
        .unwrap_or(443);
    let insecure_tls = env::var("HERMES_ATRUST_INSECURE_TLS").as_deref() == Ok("1");
    let endpoint = GatewayEndpoint::new(host, port).unwrap();
    let transport = Arc::new(
        ReqwestTransport::new(&ReqwestTransportConfig {
            tls_policy: if insecure_tls {
                TlsPolicy::DangerousAcceptInvalidCertificates
            } else {
                TlsPolicy::Verify
            },
            ..ReqwestTransportConfig::default()
        })
        .unwrap(),
    );

    let configuration = AuthClient::new(endpoint, transport)
        .auth_config(AuthConfigOptions::default())
        .await
        .unwrap();
    assert!(!configuration.methods.is_empty());
}
