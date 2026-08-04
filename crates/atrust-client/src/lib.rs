//! The assembled aTrust runtime: one object an application can hold.
//!
//! # Why this crate exists
//!
//! `atrust-auth` and `atrust-l3` are deliberately independent — neither may
//! depend on the other. That leaves the wiring between them (route a packet,
//! pick a node group, own the reconnect, keep the resource table fresh, keep
//! managers aligned with each generation) belonging to nobody, and until now it
//! lived inside a diagnostic CLI's argument handler, where no second consumer
//! could reach it and no test covered it.
//!
//! [`AtrustClient`] is that wiring, with three things a CLI arm cannot provide:
//!
//! - **observation** — one [`hermes_events`] stream carrying VIP changes,
//!   reconnects, protocol findings and control-plane escalations;
//! - **control** — refresh, reconnect and shutdown as ordinary method calls;
//! - **a packet entry point** — [`AtrustClient::send_ipv4`] takes a raw IPv4
//!   packet and does everything between it and the wire.
//!
//! # Scope
//!
//! Still no TUN, no DNS, no routes and no login. Authentication is the caller's
//! job: this type starts from an already-authenticated [`SessionMaterial`], so
//! the browser, the MFA boundary and session persistence stay outside the core.
//! Packets go in and out as raw IPv4 bytes.

mod client;
mod config;
mod stats;

pub use client::{AtrustClient, ClientError, DialedTunnel, SentFlow};
pub use config::AtrustClientConfig;
pub use stats::{ClientStats, NodeGroupStats};

// Re-exported so an application can consume the runtime without depending on
// the layered crates directly.
pub use atrust_auth::{
    AuthClient, AuthConfiguration, AuthError, MatchedResource, ResourceSnapshot, SessionMaterial,
};
pub use atrust_l3::{Ipv4Flow, L3NodeEndpoint, L3Session, parse_ipv4_flow};
pub use hermes_events::{EventBus, EventDelivery, EventStream, HermesEvent};
