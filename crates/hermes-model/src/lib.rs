//! Shared domain types with no transport or wire-protocol dependencies.

mod endpoint;
mod identifier;
mod secret;

pub use endpoint::{GatewayEndpoint, TargetAddress};
pub use identifier::{ConnectionId, DeviceId, SessionId};
pub use secret::{SecretError, SignKey};
