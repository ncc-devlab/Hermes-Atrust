//! Cross-process persistence for a harvested gateway session.
//!
//! Interactive CAS login costs a full IDS + slider + SMS round trip, and the
//! resulting cookie jar previously lived only inside the process that ran the
//! browser. That forced every data-plane experiment to be chained into the same
//! `cas-login` invocation. A stored session decouples "how the session was
//! established" from "which subcommand uses it", so `tcp-dial`, `node-probe`,
//! and `client-resource` consume a CAS session exactly like a password session.
//!
//! The file holds live gateway cookies, the SID, and the SignKey. It is created
//! `0600` and an existing file is tightened to `0600` on every write.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hermes_model::{ConnectionId, DeviceId, GatewayEndpoint, SecretString, SessionId, SignKey};
use hermes_transport::GatewayCookie;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::material::{MaterialError, SessionMaterial};

/// Bumped whenever the on-disk shape changes incompatibly.
pub const SESSION_STORE_VERSION: u32 = 1;

/// How the persisted session was originally established.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    /// Interactive CAS/IDS login completed in a browser, cookies harvested on close.
    Cas,
    /// Local password authentication against the gateway.
    Password,
}

impl LoginMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cas => "cas",
            Self::Password => "password",
        }
    }
}

/// One persisted gateway session: cookies plus the identifiers the data plane
/// must keep stable across processes.
///
/// `device_id`, `connection_id`, and `sign_key` are stored rather than
/// regenerated: `connection_id` is derived from `device_id`, and a gateway that
/// binds either to the session would reject a process that invented new ones.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredSession {
    pub version: u32,
    pub saved_unix_ms: u128,
    pub gateway_host: String,
    pub gateway_port: u16,
    pub login_method: LoginMethod,
    pub login_domain: Option<String>,
    pub cookies: Vec<StoredCookie>,
    pub sid: String,
    pub sid_cookie_name: String,
    pub sid_sig_present: bool,
    pub device_id: String,
    pub connection_id: String,
    pub sign_key_hex: String,
    pub sign_key_provisional: bool,
    pub username: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
}

impl From<&GatewayCookie> for StoredCookie {
    fn from(cookie: &GatewayCookie) -> Self {
        Self {
            name: cookie.name.clone(),
            value: cookie.value.clone(),
            domain: cookie.domain.clone(),
            path: cookie.path.clone(),
            secure: cookie.secure,
            http_only: cookie.http_only,
        }
    }
}

impl From<&StoredCookie> for GatewayCookie {
    fn from(cookie: &StoredCookie) -> Self {
        Self {
            name: cookie.name.clone(),
            value: cookie.value.clone(),
            domain: cookie.domain.clone(),
            path: cookie.path.clone(),
            secure: cookie.secure,
            http_only: cookie.http_only,
        }
    }
}

impl StoredSession {
    /// Captures a live session. `cookies` must be the gateway-scoped jar contents.
    pub fn capture(
        gateway: &GatewayEndpoint,
        login_method: LoginMethod,
        login_domain: Option<String>,
        cookies: &[GatewayCookie],
        material: &SessionMaterial,
    ) -> Self {
        Self {
            version: SESSION_STORE_VERSION,
            saved_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis())
                .unwrap_or(0),
            gateway_host: gateway.host().to_owned(),
            gateway_port: gateway.port(),
            login_method,
            login_domain,
            cookies: cookies.iter().map(StoredCookie::from).collect(),
            sid: material.sid.as_str().to_owned(),
            sid_cookie_name: material.sid_cookie_name.clone(),
            sid_sig_present: material.sid_sig_present,
            device_id: material.device_id.as_str().to_owned(),
            connection_id: material.connection_id.as_str().to_owned(),
            sign_key_hex: material.sign_key.to_hex_lower(),
            sign_key_provisional: material.sign_key_provisional,
            username: material.username.clone(),
        }
    }

    /// Writes the session as a single JSON document with owner-only permissions.
    pub fn save(&self, path: &Path) -> Result<(), SessionStoreError> {
        let file = open_private(path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, self).map_err(SessionStoreError::Encode)?;
        writer.write_all(b"\n").map_err(|error| io(path, error))?;
        writer.flush().map_err(|error| io(path, error))
    }

    pub fn load(path: &Path) -> Result<Self, SessionStoreError> {
        let bytes = std::fs::read(path).map_err(|error| io(path, error))?;
        let session: Self = serde_json::from_slice(&bytes).map_err(SessionStoreError::Decode)?;
        if session.version != SESSION_STORE_VERSION {
            return Err(SessionStoreError::UnsupportedVersion(session.version));
        }
        Ok(session)
    }

    /// Rejects a session saved for a different gateway, so a stale file cannot
    /// silently send one school's cookies to another host.
    pub fn ensure_gateway(&self, gateway: &GatewayEndpoint) -> Result<(), SessionStoreError> {
        if self.gateway_host.eq_ignore_ascii_case(gateway.host())
            && self.gateway_port == gateway.port()
        {
            return Ok(());
        }
        Err(SessionStoreError::GatewayMismatch {
            stored: format!("{}:{}", self.gateway_host, self.gateway_port),
            requested: format!("{}:{}", gateway.host(), gateway.port()),
        })
    }

    pub fn gateway_cookies(&self) -> Vec<GatewayCookie> {
        self.cookies.iter().map(GatewayCookie::from).collect()
    }

    /// Rebuilds session material with the persisted identifiers, never fresh ones.
    pub fn to_material(&self) -> Result<SessionMaterial, SessionStoreError> {
        let sid = SessionId::new(self.sid.clone()).map_err(MaterialError::Identifier)?;
        let device_id = DeviceId::new(self.device_id.clone()).map_err(MaterialError::Identifier)?;
        let connection_id =
            ConnectionId::new(self.connection_id.clone()).map_err(MaterialError::Identifier)?;
        let sign_key = SignKey::from_hex(&self.sign_key_hex).map_err(MaterialError::Secret)?;
        Ok(SessionMaterial::from_parts(
            sid,
            device_id,
            connection_id,
            sign_key,
            self.username.clone(),
            self.sign_key_provisional,
            self.sid_cookie_name.clone(),
            self.sid_sig_present,
        ))
    }

    /// SID as a secret, for callers that re-derive material themselves.
    pub fn sid_secret(&self) -> Result<SecretString, SessionStoreError> {
        SecretString::new(self.sid.clone())
            .map_err(MaterialError::Secret)
            .map_err(SessionStoreError::from)
    }
}

fn open_private(path: &Path) -> Result<File, SessionStoreError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| io(path, error))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| io(path, error))?;
    Ok(file)
}

fn io(path: &Path, source: std::io::Error) -> SessionStoreError {
    SessionStoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("session store I/O failed for {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to encode session store")]
    Encode(#[source] serde_json::Error),
    #[error("failed to decode session store")]
    Decode(#[source] serde_json::Error),
    #[error("unsupported session store version {0}")]
    UnsupportedVersion(u32),
    #[error("session store was saved for gateway {stored}, but {requested} was requested")]
    GatewayMismatch { stored: String, requested: String },
    #[error(transparent)]
    Material(#[from] MaterialError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(name: &str, value: &str) -> GatewayCookie {
        GatewayCookie {
            name: name.to_owned(),
            value: value.to_owned(),
            domain: Some("gateway.test".to_owned()),
            path: Some("/".to_owned()),
            secure: true,
            http_only: true,
        }
    }

    fn material() -> SessionMaterial {
        let sid = SecretString::new("sid-cookie-value").unwrap();
        let device = DeviceId::new("device-abc").unwrap();
        SessionMaterial::from_cookie_sid(
            &sid,
            "sid",
            true,
            device,
            Some("student".to_owned()),
            Some(SignKey::from_hex("aabbccdd").unwrap()),
        )
        .unwrap()
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hermes-session-store-{}-{}-{tag}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn round_trips_identifiers_without_regenerating_them() {
        let gateway = GatewayEndpoint::new("gateway.test", 443).unwrap();
        let material = material();
        let session = StoredSession::capture(
            &gateway,
            LoginMethod::Cas,
            Some("cas42187".to_owned()),
            &[cookie("sid", "sid-cookie-value")],
            &material,
        );
        let path = temp_path("roundtrip");
        session.save(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "session store must stay owner-only");

        let loaded = StoredSession::load(&path).unwrap();
        loaded.ensure_gateway(&gateway).unwrap();
        assert_eq!(loaded.login_method, LoginMethod::Cas);
        assert_eq!(loaded.login_domain.as_deref(), Some("cas42187"));

        let restored = loaded.to_material().unwrap();
        // The whole point of persisting: identifiers survive the process boundary.
        assert_eq!(restored.sid.as_str(), material.sid.as_str());
        assert_eq!(restored.device_id.as_str(), material.device_id.as_str());
        assert_eq!(
            restored.connection_id.as_str(),
            material.connection_id.as_str()
        );
        assert_eq!(restored.sign_key.expose(), material.sign_key.expose());
        assert!(!restored.sign_key_provisional);
        assert_eq!(restored.username.as_deref(), Some("student"));
        assert!(restored.sid_sig_present);

        assert_eq!(loaded.gateway_cookies().len(), 1);
        assert_eq!(loaded.gateway_cookies()[0].value, "sid-cookie-value");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_a_session_saved_for_another_gateway() {
        let stored_gateway = GatewayEndpoint::new("gateway.test", 443).unwrap();
        let session = StoredSession::capture(
            &stored_gateway,
            LoginMethod::Password,
            None,
            &[cookie("sid", "value")],
            &material(),
        );
        let other = GatewayEndpoint::new("other.test", 443).unwrap();
        assert!(matches!(
            session.ensure_gateway(&other),
            Err(SessionStoreError::GatewayMismatch { .. })
        ));
    }

    #[test]
    fn rejects_an_unknown_store_version() {
        let path = temp_path("version");
        std::fs::write(&path, br#"{"version":999}"#).unwrap();
        assert!(matches!(
            StoredSession::load(&path),
            Err(SessionStoreError::Decode(_)) | Err(SessionStoreError::UnsupportedVersion(999))
        ));
        std::fs::remove_file(path).unwrap();
    }
}
