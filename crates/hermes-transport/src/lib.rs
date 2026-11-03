//! Runtime transport abstractions shared by protocol clients.

mod http;
mod tls;
mod underlay;
pub use underlay::{SystemUnderlay, UnderlayDialer, UnderlayOptions};

pub use http::{
    GatewayCookie, HttpMethod, HttpRequest, HttpResponse, HttpTransport, HttpTransportError,
    ReqwestTransport, ReqwestTransportConfig, TlsPolicy,
};
pub use tls::{
    NodeTlsProbeOutcome, NodeTlsProbeResult, NodeTlsStream, TargetTlsProfile, TlsConnectError,
    TlsTransportError, connect_tls, connect_tls_over, connect_tls_over_with_profile,
    connect_tls_with_underlay, probe_node_tls, probe_node_tls_with_underlay,
};
