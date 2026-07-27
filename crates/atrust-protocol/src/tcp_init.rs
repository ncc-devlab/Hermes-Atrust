use hermes_model::{ConnectionId, DeviceId, SessionId, SignKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::json::{ProtocolJsonError, to_wire_json};
use crate::signing::calculate_request_signature;

/// Client process identity embedded in TCP tunnel init JSON (Go DialTCP parity).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub name: String,
    pub path: String,
}

impl ProcessIdentity {
    /// Matches the Go client's hardcoded Linux process spoofing.
    pub fn default_for_port(port: u16) -> Self {
        if port == 22 {
            Self {
                name: "ssh".to_owned(),
                path: "/usr/bin/ssh".to_owned(),
            }
        } else {
            Self {
                name: "google-chrome-stable".to_owned(),
                path: "/usr/bin/google-chrome-stable".to_owned(),
            }
        }
    }

    /// Uppercase hex SHA-256 of the process path bytes (Go `fmt.Sprintf("%X", sha256(...))`).
    pub fn proc_hash(&self) -> String {
        let digest = Sha256::digest(self.path.as_bytes());
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02X}");
        }
        out
    }
}

/// Inputs required to build a signed TCP tunnel init JSON body.
#[derive(Clone, Debug)]
pub struct TcpInitParams<'a> {
    pub sid: &'a SessionId,
    pub app_id: &'a str,
    /// Host used in `url` / `destAddr` (IP or original domain), without brackets.
    pub dest_host: &'a str,
    pub dest_port: u16,
    pub device_id: &'a DeviceId,
    pub connection_id: &'a ConnectionId,
    pub username: &'a str,
    pub process: &'a ProcessIdentity,
    pub lang: &'a str,
}

/// Builds compact signed JSON bytes for the TCP init frame body.
///
/// Field order is fixed by the wire struct declaration and must match the Go client.
pub fn build_signed_tcp_init_json(
    params: &TcpInitParams<'_>,
    sign_key: &SignKey,
) -> Result<Vec<u8>, TcpInitError> {
    if params.app_id.is_empty() {
        return Err(TcpInitError::EmptyAppId);
    }
    if params.dest_host.is_empty() {
        return Err(TcpInitError::EmptyDestHost);
    }
    if params.dest_port == 0 {
        return Err(TcpInitError::InvalidPort);
    }

    let dest_addr = format!("{}:{}", params.dest_host, params.dest_port);
    let url = format!("tcp://{dest_addr}");
    let proc_hash = params.process.proc_hash();

    let unsigned = TcpInitWire {
        sid: params.sid.as_str(),
        app_id: params.app_id,
        url: &url,
        device_id: params.device_id.as_str(),
        connection_id: params.connection_id.as_str(),
        proc_hash: &proc_hash,
        user_name: params.username,
        rc_applied_info: 0,
        lang: params.lang,
        dest_addr: &dest_addr,
        env: TcpInitEnv {
            application: TcpInitApplication {
                runtime: TcpInitRuntime {
                    process: TcpInitProcess {
                        name: &params.process.name,
                        digital_signature: "TrustAppClosed",
                        platform: "Linux",
                        fingerprint: &proc_hash,
                        description: "TrustAppClosed",
                        path: &params.process.path,
                        version: "TrustAppClosed",
                        security_env: "normal",
                    },
                    process_trusted: "TRUSTED",
                },
            },
        },
        x_request_sig: "",
    };

    let unsigned_bytes = to_wire_json(&unsigned)?;
    let signature = calculate_request_signature(sign_key, &unsigned_bytes);
    let signed = TcpInitWire {
        x_request_sig: signature.as_str(),
        ..unsigned
    };
    Ok(to_wire_json(&signed)?)
}

/// Wire DTO matching Go DialTCP JSON layout exactly (mixed camelCase / snake_case).
#[derive(Serialize)]
struct TcpInitWire<'a> {
    sid: &'a str,
    #[serde(rename = "appId")]
    app_id: &'a str,
    url: &'a str,
    #[serde(rename = "deviceId")]
    device_id: &'a str,
    #[serde(rename = "connectionId")]
    connection_id: &'a str,
    #[serde(rename = "procHash")]
    proc_hash: &'a str,
    #[serde(rename = "userName")]
    user_name: &'a str,
    #[serde(rename = "rcAppliedInfo")]
    rc_applied_info: i32,
    lang: &'a str,
    #[serde(rename = "destAddr")]
    dest_addr: &'a str,
    env: TcpInitEnv<'a>,
    #[serde(rename = "xRequestSig")]
    x_request_sig: &'a str,
}

#[derive(Serialize)]
struct TcpInitEnv<'a> {
    application: TcpInitApplication<'a>,
}

#[derive(Serialize)]
struct TcpInitApplication<'a> {
    runtime: TcpInitRuntime<'a>,
}

#[derive(Serialize)]
struct TcpInitRuntime<'a> {
    process: TcpInitProcess<'a>,
    process_trusted: &'a str,
}

#[derive(Serialize)]
struct TcpInitProcess<'a> {
    name: &'a str,
    digital_signature: &'a str,
    platform: &'a str,
    fingerprint: &'a str,
    description: &'a str,
    path: &'a str,
    version: &'a str,
    security_env: &'a str,
}

#[derive(Debug, Error)]
pub enum TcpInitError {
    #[error("appId must not be empty")]
    EmptyAppId,
    #[error("dest host must not be empty")]
    EmptyDestHost,
    #[error("dest port must not be zero")]
    InvalidPort,
    #[error(transparent)]
    Json(#[from] ProtocolJsonError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_model::SignKey;

    #[test]
    fn process_hash_is_uppercase_sha256_of_path() {
        let process = ProcessIdentity {
            name: "ssh".to_owned(),
            path: "/usr/bin/ssh".to_owned(),
        };
        let expected = {
            let digest = Sha256::digest(b"/usr/bin/ssh");
            digest
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
        };
        assert_eq!(process.proc_hash(), expected);
        assert!(process.proc_hash().chars().all(|c| !c.is_ascii_lowercase()));
    }

    #[test]
    fn default_process_identity_matches_go() {
        assert_eq!(
            ProcessIdentity::default_for_port(443).name,
            "google-chrome-stable"
        );
        assert_eq!(ProcessIdentity::default_for_port(22).path, "/usr/bin/ssh");
    }

    #[test]
    fn signed_init_json_matches_go_layout() {
        let sid = SessionId::new("sid-value").unwrap();
        let device = DeviceId::new("device-1").unwrap();
        let connection = ConnectionId::from_device_at(&device, 1_700_000_000_000_000).unwrap();
        let process = ProcessIdentity {
            name: "google-chrome-stable".to_owned(),
            path: "/usr/bin/google-chrome-stable".to_owned(),
        };
        let proc_hash = process.proc_hash();
        let params = TcpInitParams {
            sid: &sid,
            app_id: "app-1",
            dest_host: "10.0.0.1",
            dest_port: 80,
            device_id: &device,
            connection_id: &connection,
            username: "alice",
            process: &process,
            lang: "en-US",
        };
        let key = SignKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let body = build_signed_tcp_init_json(&params, &key).unwrap();
        let text = String::from_utf8(body).unwrap();

        let prefix = format!(
            r#"{{"sid":"sid-value","appId":"app-1","url":"tcp://10.0.0.1:80","deviceId":"device-1","connectionId":"{}","procHash":"{}","userName":"alice","rcAppliedInfo":0,"lang":"en-US","destAddr":"10.0.0.1:80","env":{{"application":{{"runtime":{{"process":{{"name":"google-chrome-stable","digital_signature":"TrustAppClosed","platform":"Linux","fingerprint":"{}","description":"TrustAppClosed","path":"/usr/bin/google-chrome-stable","version":"TrustAppClosed","security_env":"normal"}},"process_trusted":"TRUSTED"}}}}}},"xRequestSig":""#,
            connection.as_str(),
            proc_hash,
            proc_hash
        );
        assert!(text.starts_with(&prefix), "unexpected wire JSON: {text}");
        assert!(!text.contains(r#""xRequestSig":"""#));

        // Go: sign JSON with empty xRequestSig, then splice signature into the last field.
        // `prefix` already ends with the opening quote of xRequestSig's value.
        let unsigned = format!(r#"{prefix}"}}"#);
        let expected = calculate_request_signature(&key, unsigned.as_bytes());
        let mut expected_signed = unsigned;
        assert!(expected_signed.ends_with(r#""}"#));
        expected_signed.truncate(expected_signed.len() - 2);
        expected_signed.push_str(expected.as_str());
        expected_signed.push('"');
        expected_signed.push('}');
        assert_eq!(text, expected_signed);
    }

    #[test]
    fn rejects_empty_app_id() {
        let sid = SessionId::new("sid").unwrap();
        let device = DeviceId::new("dev").unwrap();
        let connection = ConnectionId::new("conn").unwrap();
        let process = ProcessIdentity::default_for_port(80);
        let params = TcpInitParams {
            sid: &sid,
            app_id: "",
            dest_host: "1.1.1.1",
            dest_port: 80,
            device_id: &device,
            connection_id: &connection,
            username: "",
            process: &process,
            lang: "en-US",
        };
        assert!(matches!(
            build_signed_tcp_init_json(&params, &SignKey::from_hex("aa").unwrap()),
            Err(TcpInitError::EmptyAppId)
        ));
    }
}
