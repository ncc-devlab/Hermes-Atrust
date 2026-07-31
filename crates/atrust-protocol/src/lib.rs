//! Pure aTrust wire-format primitives.
//!
//! This crate intentionally has no network, runtime, configuration, or logging dependencies.

mod json;
mod l3_auth;
mod l3_frame;
mod signing;
mod tcp_frame;
mod tcp_init;

pub use json::{ProtocolJsonError, to_wire_json};
pub use l3_auth::{
    L3AuthError, L3AuthFiveTuple, L3AuthParams, L3AuthResponse, L3IpProtocol,
    build_signed_l3_auth_json, parse_l3_auth_response,
};
pub use l3_frame::{
    DataRespLayout, DataRespPackets, L3FrameError, L3_HEARTBEAT_REQ, L3_HEARTBEAT_RESP_HEADER,
    L3_VERSION, MAX_LENGTH_PREFIXED_DATA_RESP, classify_data_resp_prefix, decode_l3_data_resp_body,
    decode_l3_data_resp_frame, encode_l3_auth_req, encode_l3_data_req,
    encode_l3_data_resp_length_prefixed, encode_l3_heartbeat_req, is_l3_heartbeat_resp, l3_cmd,
    parse_l3_token_data_body,
};
pub use signing::{RequestSignature, calculate_request_signature};
pub use tcp_frame::{
    TCP_INIT_PREFIX, TcpFrameError, encode_tcp_app_data, encode_tcp_close, encode_tcp_init_frame,
    encode_tcp_probe, encode_tcp_target_domain, encode_tcp_target_ipv4, is_status_ok,
    parse_status_payload,
};
pub use tcp_init::{ProcessIdentity, TcpInitError, TcpInitParams, build_signed_tcp_init_json};
