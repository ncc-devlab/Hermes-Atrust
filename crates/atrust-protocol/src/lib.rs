//! Pure aTrust wire-format primitives.
//!
//! This crate intentionally has no network, runtime, configuration, or logging dependencies.

mod json;
mod signing;
mod tcp_frame;
mod tcp_init;

pub use json::{ProtocolJsonError, to_wire_json};
pub use signing::{RequestSignature, calculate_request_signature};
pub use tcp_frame::{
    TCP_INIT_PREFIX, TcpFrameError, encode_tcp_app_data, encode_tcp_close, encode_tcp_init_frame,
    encode_tcp_probe, encode_tcp_target_domain, encode_tcp_target_ipv4, is_status_ok,
    parse_status_payload,
};
pub use tcp_init::{
    ProcessIdentity, TcpInitError, TcpInitParams, build_signed_tcp_init_json,
};
