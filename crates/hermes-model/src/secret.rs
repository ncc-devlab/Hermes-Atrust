use std::fmt;

use thiserror::Error;
use zeroize::Zeroize;

/// UTF-8 secret that is redacted from debug output and zeroized on drop.
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Result<Self, SecretError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// HMAC key used by aTrust request authentication.
pub struct SignKey(Vec<u8>);

impl SignKey {
    /// Decodes the hexadecimal representation used by the original client.
    pub fn from_hex(value: &str) -> Result<Self, SecretError> {
        let bytes = hex::decode(value).map_err(SecretError::InvalidHex)?;
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(Self(bytes))
    }

    /// Exposes key bytes only to code that must perform cryptographic operations.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SignKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SignKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignKey([REDACTED])")
    }
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret must not be empty")]
    Empty,
    #[error("secret is not valid hexadecimal: {0}")]
    InvalidHex(hex::FromHexError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_key_decodes_hex_without_exposing_it_in_debug() {
        let key = SignKey::from_hex("001122AAbb").unwrap();
        assert_eq!(key.expose(), &[0x00, 0x11, 0x22, 0xAA, 0xBB]);
        assert_eq!(format!("{key:?}"), "SignKey([REDACTED])");
    }

    #[test]
    fn sign_key_rejects_empty_input() {
        assert!(matches!(SignKey::from_hex(""), Err(SecretError::Empty)));
    }

    #[test]
    fn secret_string_debug_output_is_redacted() {
        let secret = SecretString::new("do-not-log").unwrap();
        assert_eq!(secret.expose(), "do-not-log");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
    }
}
