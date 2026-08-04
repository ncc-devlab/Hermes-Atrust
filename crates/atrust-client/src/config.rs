use std::time::Duration;

use atrust_l3::{L3_HEARTBEAT_INTERVAL, L3NodeEndpoint};
use hermes_model::GatewayEndpoint;
use hermes_transport::TlsPolicy;

/// Everything the runtime needs that is a deployment choice rather than a
/// protocol constant.
///
/// Frame versions, command bytes and signing algorithms deliberately do **not**
/// appear here; see the enforced boundaries in `docs/rust-rewrite-architecture.md`.
#[derive(Clone, Debug)]
pub struct AtrustClientConfig {
    /// Control-plane gateway, used to resolve `{{sdpcHost}}` node addresses.
    pub gateway: GatewayEndpoint,
    /// Applies to data-plane node connections. Xidian's nodes present a
    /// self-signed `CN=sdp`, so live use there requires a relaxed policy.
    pub tls_policy: TlsPolicy,
    /// Budget for TCP + TLS + Get-IP on one node connection.
    pub connect_timeout: Duration,
    pub heartbeat_interval: Duration,
    /// Budget for the TCP tunnel handshake after TLS is up.
    ///
    /// Not the same quantity as `connect_timeout`: E9 measured the gateway
    /// taking ~15 s to report `0x03` when the target itself was unreachable, so
    /// a short budget here reports a timeout for what is really a destination
    /// failure and hides the server's actual verdict.
    pub tcp_handshake_timeout: Duration,
    /// How often a complete `clientResource` generation is fetched. A failure
    /// keeps the previous generation; see `ResourceCache`.
    pub resource_refresh_interval: Duration,
    /// Replaces the advertised endpoint list for every node group.
    ///
    /// Exists because advertised order is not preference order: Xidian lists
    /// the unreachable internal address first, so a caller that has already
    /// measured reachability must be able to supply its own ordering. Failover
    /// still applies *within* the supplied list; a single-element list is
    /// therefore also the fail-closed `--node` pin.
    pub endpoint_override: Option<Vec<L3NodeEndpoint>>,
    /// `lang` field carried in signed auth requests.
    pub lang: String,
}

impl AtrustClientConfig {
    /// Defaults chosen from measured live behaviour, not from round numbers:
    /// the 20s connect budget clears the ~6.3s TLS connect measured on the
    /// Xidian link with room to spare, and stays well above the 8s flow-auth
    /// timeout so a slow link cannot be misreported as an auth failure.
    #[must_use]
    pub fn new(gateway: GatewayEndpoint, tls_policy: TlsPolicy) -> Self {
        Self {
            gateway,
            tls_policy,
            connect_timeout: Duration::from_secs(20),
            heartbeat_interval: L3_HEARTBEAT_INTERVAL,
            tcp_handshake_timeout: Duration::from_secs(20),
            resource_refresh_interval: Duration::from_secs(300),
            endpoint_override: None,
            lang: "en-US".to_owned(),
        }
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    #[must_use]
    pub fn with_resource_refresh_interval(mut self, interval: Duration) -> Self {
        self.resource_refresh_interval = interval;
        self
    }

    #[must_use]
    pub fn with_tcp_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tcp_handshake_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_endpoint_override(mut self, endpoints: Option<Vec<L3NodeEndpoint>>) -> Self {
        self.endpoint_override = endpoints.filter(|endpoints| !endpoints.is_empty());
        self
    }
}
