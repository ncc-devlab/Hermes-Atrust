//! Runtime transport abstractions shared by protocol clients.

mod http;

pub use http::{
    GatewayCookie, HttpMethod, HttpRequest, HttpResponse, HttpTransport, HttpTransportError,
    ReqwestTransport, ReqwestTransportConfig, TlsPolicy,
};
