//! aTrust L3 data-plane building blocks.
//!
//! - SID-only Get-IP exchange (`get_ipv4` / `request_ipv4`)
//! - Per-flow conntrack + connectToken (`conntrack`, `auth`)
//! - Packet `0x14`/`0x94` framing lives in `atrust-protocol::l3_frame`
//!
//! Full multiplexed tunnel I/O (read loop, heartbeat task, TUN) is a later stage.

mod auth;
mod conntrack;
mod get_ip;

pub use auth::{
    FlowAuthError, L3AuthContext, apply_auth_response_json, apply_auth_wire_status,
    build_flow_auth_frame, ready_token,
};
pub use conntrack::{
    AuthOutcome, ConntrackEntry, ConntrackError, ConntrackTable, FlowKey, L3_AUTH_TIMEOUT,
};
pub use get_ip::{GetIpv4Error, GetIpv4Request, get_ipv4, request_ipv4};

// Re-export wire helpers used by L3 callers.
pub use atrust_protocol::{
    L3AuthFiveTuple, L3AuthParams, L3AuthResponse, L3IpProtocol, L3_HEARTBEAT_REQ, ProcessIdentity,
    build_signed_l3_auth_json, encode_l3_data_req, encode_l3_heartbeat_req, parse_l3_auth_response,
};
