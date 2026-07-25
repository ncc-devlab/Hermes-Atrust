use std::fmt;

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

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentifierError {
    #[error("identifier must not be empty")]
    Empty,
    #[error("identifier must not contain control characters")]
    ControlCharacter,
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
}
