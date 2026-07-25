//! Pure aTrust wire-format primitives.
//!
//! This crate intentionally has no network, runtime, configuration, or logging dependencies.

mod json;
mod signing;

pub use json::{ProtocolJsonError, to_wire_json};
pub use signing::{RequestSignature, calculate_request_signature};
