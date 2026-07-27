use std::fmt;

use hermes_model::{
    ConnectionId, DeviceId, IdentifierError, SecretError, SecretString, SessionId, SignKey,
};
use hermes_transport::GatewayCookie;
use thiserror::Error;

/// Tunnel/control session material assembled after login.
///
/// Debug never prints SID, SignKey, or username values.
pub struct SessionMaterial {
    pub sid: SessionId,
    pub device_id: DeviceId,
    pub connection_id: ConnectionId,
    pub sign_key: SignKey,
    pub username: Option<String>,
    /// True when `sign_key` was generated client-side and may not be registered server-side yet.
    pub sign_key_provisional: bool,
    /// Cookie name that supplied the SID (`sid` preferred over `sid-legacy`).
    pub sid_cookie_name: String,
    /// Whether a matching `*.sig` cookie name was present (value not retained).
    pub sid_sig_present: bool,
}

impl fmt::Debug for SessionMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMaterial")
            .field("sid", &self.sid)
            .field("device_id", &self.device_id)
            .field("connection_id", &self.connection_id)
            .field("sign_key", &self.sign_key)
            .field("username_present", &self.username.is_some())
            .field("sign_key_provisional", &self.sign_key_provisional)
            .field("sid_cookie_name", &self.sid_cookie_name)
            .field("sid_sig_present", &self.sid_sig_present)
            .finish()
    }
}

impl SessionMaterial {
    /// Builds material from a harvested gateway cookie SID and client-generated peers.
    ///
    /// SignKey defaults to a 32-byte random key (64 hex chars), matching the Go client's
    /// common `randHex(64)` pattern. Server registration of that key remains unconfirmed.
    pub fn from_cookie_sid(
        sid_value: &SecretString,
        sid_cookie_name: impl Into<String>,
        sid_sig_present: bool,
        device_id: DeviceId,
        username: Option<String>,
        sign_key: Option<SignKey>,
    ) -> Result<Self, MaterialError> {
        let sid =
            SessionId::new(sid_value.expose().to_owned()).map_err(MaterialError::Identifier)?;
        let connection_id =
            ConnectionId::from_device(&device_id).map_err(MaterialError::Identifier)?;
        let (sign_key, sign_key_provisional) = match sign_key {
            Some(key) => (key, false),
            None => (generate_provisional_sign_key()?, true),
        };
        Ok(Self {
            sid,
            device_id,
            connection_id,
            sign_key,
            username,
            sign_key_provisional,
            sid_cookie_name: sid_cookie_name.into(),
            sid_sig_present,
        })
    }

    /// Presence-only summary safe for structured logs.
    pub fn log_fields(&self) -> SessionMaterialLog<'_> {
        SessionMaterialLog {
            sid_present: true,
            device_id_present: true,
            connection_id_present: true,
            sign_key_present: true,
            username_present: self.username.is_some(),
            sign_key_provisional: self.sign_key_provisional,
            sid_cookie_name: self.sid_cookie_name.as_str(),
            sid_sig_present: self.sid_sig_present,
        }
    }
}

/// Non-sensitive snapshot for tracing fields.
#[derive(Clone, Copy, Debug)]
pub struct SessionMaterialLog<'a> {
    pub sid_present: bool,
    pub device_id_present: bool,
    pub connection_id_present: bool,
    pub sign_key_present: bool,
    pub username_present: bool,
    pub sign_key_provisional: bool,
    pub sid_cookie_name: &'a str,
    pub sid_sig_present: bool,
}

/// Preference order when multiple session cookies exist.
const SID_COOKIE_CANDIDATES: &[&str] = &["sid", "sid-legacy"];

/// Extracts SID value from harvested gateway cookies without logging the value.
pub fn extract_sid_from_cookies(
    cookies: &[GatewayCookie],
) -> Result<SidCookieSource, MaterialError> {
    for name in SID_COOKIE_CANDIDATES {
        if let Some(cookie) = cookies
            .iter()
            .find(|cookie| cookie.name.eq_ignore_ascii_case(name))
        {
            let value = SecretString::new(cookie.value.clone()).map_err(MaterialError::Secret)?;
            let sig_name = format!("{}.sig", cookie.name);
            let sid_sig_present = cookies
                .iter()
                .any(|other| other.name.eq_ignore_ascii_case(&sig_name));
            return Ok(SidCookieSource {
                value,
                cookie_name: cookie.name.clone(),
                sid_sig_present,
            });
        }
    }
    Err(MaterialError::SidCookieMissing)
}

/// SID taken from a trusted gateway cookie jar import path.
pub struct SidCookieSource {
    pub value: SecretString,
    pub cookie_name: String,
    pub sid_sig_present: bool,
}

impl fmt::Debug for SidCookieSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SidCookieSource")
            .field("value", &self.value)
            .field("cookie_name", &self.cookie_name)
            .field("sid_sig_present", &self.sid_sig_present)
            .finish()
    }
}

/// Client-generated provisional SignKey: 32 random bytes → 64 hex characters as raw key bytes
/// of the decoded form used by `SignKey::from_hex` of a 64-char string.
pub fn generate_provisional_sign_key() -> Result<SignKey, MaterialError> {
    use rand::RngCore as _;
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    // Go stores randHex(64) as the key string and uses those hex digits as key material via
    // hex decode in some paths; Hermes models SignKey as raw bytes. Prefer 32 random bytes
    // (cryptographically equivalent entropy) for HMAC.
    SignKey::from_bytes(bytes.to_vec()).map_err(MaterialError::Secret)
}

#[derive(Debug, Error)]
pub enum MaterialError {
    #[error("gateway cookies do not include a sid or sid-legacy value")]
    SidCookieMissing,
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    #[error(transparent)]
    Secret(#[from] SecretError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(name: &str, value: &str) -> GatewayCookie {
        GatewayCookie {
            name: name.to_owned(),
            value: value.to_owned(),
            domain: None,
            path: Some("/".to_owned()),
            secure: true,
            http_only: true,
        }
    }

    #[test]
    fn prefers_sid_over_legacy_and_detects_sig() {
        let cookies = [
            cookie("sid-legacy", "legacy-value"),
            cookie("sid", "primary-value"),
            cookie("sid.sig", "sig"),
        ];
        let source = extract_sid_from_cookies(&cookies).unwrap();
        assert_eq!(source.cookie_name, "sid");
        assert_eq!(source.value.expose(), "primary-value");
        assert!(source.sid_sig_present);
        assert!(!format!("{source:?}").contains("primary-value"));
    }

    #[test]
    fn falls_back_to_sid_legacy() {
        let cookies = [cookie("sid-legacy", "legacy-only")];
        let source = extract_sid_from_cookies(&cookies).unwrap();
        assert_eq!(source.cookie_name, "sid-legacy");
        assert!(!source.sid_sig_present);
    }

    #[test]
    fn missing_sid_is_error() {
        let cookies = [cookie("lang", "zh-CN")];
        assert!(matches!(
            extract_sid_from_cookies(&cookies),
            Err(MaterialError::SidCookieMissing)
        ));
    }

    #[test]
    fn session_material_debug_redacts_secrets() {
        let sid = SecretString::new("sid-secret-value").unwrap();
        let device = DeviceId::new("device-1").unwrap();
        let material = SessionMaterial::from_cookie_sid(
            &sid,
            "sid",
            true,
            device,
            Some("student".to_owned()),
            Some(SignKey::from_hex("aabb").unwrap()),
        )
        .unwrap();
        let debug = format!("{material:?}");
        assert!(!debug.contains("sid-secret-value"));
        assert!(!debug.contains("student"));
        assert!(!debug.contains("aabb"));
        assert!(debug.contains("REDACTED") || debug.contains("username_present"));
        let log = material.log_fields();
        assert!(log.sid_present);
        assert!(log.username_present);
        assert!(!log.sign_key_provisional);
        assert_eq!(log.sid_cookie_name, "sid");
    }

    #[test]
    fn provisional_sign_key_flag_when_generated() {
        let sid = SecretString::new("sid-value").unwrap();
        let device = DeviceId::new("device-2").unwrap();
        let material =
            SessionMaterial::from_cookie_sid(&sid, "sid", false, device, None, None).unwrap();
        assert!(material.sign_key_provisional);
        assert!(!material.sign_key.expose().is_empty());
    }
}
