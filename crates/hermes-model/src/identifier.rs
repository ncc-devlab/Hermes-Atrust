use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use md5::{Digest as _, Md5};
use serde::Serialize;
use thiserror::Error;

macro_rules! identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(IdentifierError::Empty);
                }
                if value.chars().any(char::is_control) {
                    return Err(IdentifierError::ControlCharacter);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"[REDACTED]")
                    .finish()
            }
        }
    };
}

identifier!(SessionId, "Authenticated aTrust session identifier.");
identifier!(DeviceId, "Stable identifier assigned to the client device.");
identifier!(
    ConnectionId,
    "Identifier for one client connection lifecycle."
);

impl ConnectionId {
    /// Go-compatible form: `UPPER(MD5(deviceId)) + "-" + microsecond_unix_timestamp`.
    pub fn from_device(device_id: &DeviceId) -> Result<Self, IdentifierError> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdentifierError::Clock)?
            .as_micros();
        Self::from_device_at(device_id, micros)
    }

    /// Deterministic variant for tests and replay of a known timestamp.
    pub fn from_device_at(
        device_id: &DeviceId,
        unix_micros: u128,
    ) -> Result<Self, IdentifierError> {
        let digest = Md5::digest(device_id.as_str().as_bytes());
        let mut hex = String::with_capacity(32);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02X}");
        }
        Self::new(format!("{hex}-{unix_micros}"))
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentifierError {
    #[error("identifier must not be empty")]
    Empty,
    #[error("identifier must not contain control characters")]
    ControlCharacter,
    #[error("system clock is before the unix epoch")]
    Clock,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_identifier_debug_output_is_redacted() {
        let session = SessionId::new("secret-session").unwrap();
        let output = format!("{session:?}");
        assert!(!output.contains("secret-session"));
        assert!(output.contains("REDACTED"));
    }

    #[test]
    fn identifier_rejects_control_characters() {
        assert_eq!(
            DeviceId::new("device\nother"),
            Err(IdentifierError::ControlCharacter)
        );
    }

    #[test]
    fn connection_id_matches_go_shape() {
        let device = DeviceId::new("device-abc").unwrap();
        let connection = ConnectionId::from_device_at(&device, 1_700_000_000_000_000).unwrap();
        let value = connection.as_str();
        let (hash, stamp) = value.split_once('-').expect("hash-stamp");
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(hash.chars().all(|ch| !ch.is_ascii_lowercase()));
        assert_eq!(stamp, "1700000000000000");
        assert!(!format!("{connection:?}").contains(hash));
    }
}
