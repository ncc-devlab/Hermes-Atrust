//! Shared domain types with no transport or wire-protocol dependencies.

mod endpoint;
mod identifier;
mod secret;

pub use endpoint::{EndpointError, GatewayEndpoint, TargetAddress};
pub use identifier::{ConnectionId, DeviceId, IdentifierError, SessionId};
pub use secret::{SecretError, SecretString, SignKey};
