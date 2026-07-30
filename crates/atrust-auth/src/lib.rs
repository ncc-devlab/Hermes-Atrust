//! aTrust authentication control-plane state and requests.

mod auth_config;
mod cas;
mod client;
mod material;
mod password;
mod profile;
mod resource;
mod session;
mod store;

pub use auth_config::{AuthConfigOptions, AuthConfiguration, AuthInfo, LoginState};
pub use cas::{CasCallbackCredential, CasChallenge, CasError, CasExchange, parse_portal_ticket};
pub use client::{AuthClient, AuthError};
pub use material::{
    MaterialError, SessionMaterial, SessionMaterialLog, SidCookieSource, extract_sid_from_cookies,
    generate_provisional_sign_key,
};
pub use password::{PasswordAuthOutcome, PasswordCredentials, PasswordError};
pub use profile::AuthProtocolProfile;
pub use resource::{
    ClientResources, DEFAULT_NODE_PORT, DnsServers, DomainResource, IpResource, NodeAddress,
    NodeGroup, ResolvedNodeEndpoint, ResolvedNodeGroup, ResourceError, ResourceProtocol,
};
pub use session::{AuthStep, SessionProgress};
pub use store::{
    LoginMethod, SESSION_STORE_VERSION, SessionStoreError, StoredCookie, StoredSession,
};
