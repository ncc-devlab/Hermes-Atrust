//! aTrust L3 data-plane building blocks.
//!
//! - SID-only Get-IP exchange (`get_ipv4` / `request_ipv4`)
//! - Per-flow conntrack + connectToken (`conntrack`, `auth`)
//! - IPv4 packet classification (`packet`)
//! - Full-duplex session driver: read loop + heartbeat + flow auth (`session`)
//! - Node-group session ownership, reconnect and bounded retries (`manager`)
//! - Packet `0x14`/`0x94` framing lives in `atrust-protocol::l3_frame`
//!
//! TUN, DNS and routing are deliberately out of scope: this crate stops at raw
//! IPv4 packets in and out of one selected node group.

mod auth;
mod conntrack;
mod get_ip;
mod manager;
mod packet;
mod session;

pub use auth::{
    FlowAuthError, L3AuthContext, apply_auth_response_json, apply_auth_wire_status,
    build_flow_auth_frame, ready_token,
};
pub use conntrack::{
    AuthOutcome, ConntrackEntry, ConntrackError, ConntrackTable, FlowKey, L3_AUTH_TIMEOUT,
    L3_CONNTRACK_CAPACITY, L3_CONNTRACK_IDLE_TTL, PruneOutcome,
};
pub use get_ip::{GetIpv4Error, GetIpv4Request, GetIpv4Response, get_ipv4, request_ipv4};
pub use manager::{
    AuthorizedL3Flow, L3NodeEndpoint, L3SessionManager, L3SessionManagerCache,
    L3SessionManagerConfig, L3SessionManagerError,
};
pub use packet::{FLOW_KEY_ATYPE_IPV4, Ipv4Flow, PacketError, parse_ipv4_flow};
pub use session::{L3_HEARTBEAT_INTERVAL, L3Session, L3SessionConfig, L3SessionError};

/// Match zju-connect's retry boundary: five reconnects after a closed L3
/// connection, and one fresh-connection retry after flow-auth timeout.
pub const L3_CLOSED_RETRIES: usize = 5;
pub const L3_AUTH_TIMEOUT_RETRIES: usize = 1;

// Re-export wire helpers used by L3 callers.
pub use atrust_protocol::{
    L3_HEARTBEAT_REQ, L3AuthFiveTuple, L3AuthParams, L3AuthResponse, L3IpProtocol, ProcessIdentity,
    build_signed_l3_auth_json, encode_l3_data_req, encode_l3_heartbeat_req, parse_l3_auth_response,
};
