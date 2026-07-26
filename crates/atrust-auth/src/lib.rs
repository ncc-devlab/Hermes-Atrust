//! aTrust authentication control-plane state and requests.

mod auth_config;
mod cas;
mod client;
mod password;
mod profile;

pub use auth_config::{AuthConfigOptions, AuthConfiguration, AuthInfo, LoginState};
pub use cas::{CasCallbackCredential, CasChallenge, CasError, CasExchange};
pub use client::{AuthClient, AuthError};
pub use password::{PasswordAuthOutcome, PasswordCredentials, PasswordError};
pub use profile::AuthProtocolProfile;
