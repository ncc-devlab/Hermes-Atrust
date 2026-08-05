//! Runtime transport abstractions shared by protocol clients.

mod http;
mod tls;

pub use http::{
    GatewayCookie, HttpMethod, HttpRequest, HttpResponse, HttpTransport, HttpTransportError,
    ReqwestTransport, ReqwestTransportConfig, TlsPolicy,
};
pub use tls::{
    NodeTlsProbeOutcome, NodeTlsProbeResult, NodeTlsStream, TargetTlsProfile, TlsConnectError,
    TlsTransportError, connect_tls, connect_tls_over, connect_tls_over_with_profile,
    probe_node_tls,
};
