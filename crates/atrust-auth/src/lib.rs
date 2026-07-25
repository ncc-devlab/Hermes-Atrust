//! aTrust authentication control-plane state and requests.

mod auth_config;
mod client;
mod profile;

pub use auth_config::{AuthConfigOptions, AuthConfiguration, AuthInfo, LoginState};
pub use client::{AuthClient, AuthError};
pub use profile::AuthProtocolProfile;
