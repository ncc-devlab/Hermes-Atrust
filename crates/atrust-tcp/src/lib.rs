//! aTrust TCP data-plane tunnel: dial, handshake, framed I/O.
//!
//! Does not dial live nodes by default. Real-peer use must be explicit and
//! gated (see `docs/tunnel-plan.md`).

mod dial;
mod stream;
mod target;

pub use dial::{DialTcpError, DialTcpRequest, complete_handshake, dial_tcp, ipv4_target};
pub use stream::{TcpTunnel, TunnelError};
pub use target::TunnelTarget;
