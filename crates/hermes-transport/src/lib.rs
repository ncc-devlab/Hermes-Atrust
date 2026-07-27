//! Runtime transport abstractions shared by protocol clients.

mod http;
mod tls;

pub use http::{
    GatewayCookie, HttpMethod, HttpRequest, HttpResponse, HttpTransport, HttpTransportError,
    ReqwestTransport, ReqwestTransportConfig, TlsPolicy,
};
pub use tls::{
    NodeTlsProbeOutcome, NodeTlsProbeResult, NodeTlsStream, TlsConnectError, TlsTransportError,
    connect_tls, probe_node_tls,
};
