use std::fmt;

use hermes_model::SignKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Uppercase hexadecimal HMAC expected in the `xRequestSig` field.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestSignature(String);

impl RequestSignature {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RequestSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestSignature([REDACTED])")
    }
}

/// Calculates the aTrust request signature over the exact unsigned JSON bytes.
pub fn calculate_request_signature(key: &SignKey, unsigned_json: &[u8]) -> RequestSignature {
    let mut mac = HmacSha256::new_from_slice(key.expose())
        .expect("HMAC-SHA256 accepts keys of every non-empty length");
    mac.update(unsigned_json);
    let digest = mac.finalize().into_bytes();
    RequestSignature(format!("{digest:X}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_standard_hmac_sha256_golden_vector() {
        let key = SignKey::from_hex("6B6579").unwrap(); // ASCII "key"
        let signature =
            calculate_request_signature(&key, b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            signature.as_str(),
            "F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8"
        );
    }

    #[test]
    fn signature_debug_output_is_redacted() {
        let key = SignKey::from_hex("00").unwrap();
        let signature = calculate_request_signature(&key, b"payload");
        let output = format!("{signature:?}");
        assert!(!output.contains(signature.as_str()));
        assert!(output.contains("REDACTED"));
    }
}
