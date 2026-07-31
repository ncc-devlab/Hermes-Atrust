//! L3 per-flow authorization JSON (`0x13` request / `0x93` response body).
//!
//! Distinct from TCP init: `url` uses `tcp:` / `udp:` / `icmp:` (no `//`), and
//! the body carries a five-tuple under `ip` plus `conntrackHash`.

use hermes_model::{ConnectionId, DeviceId, SessionId, SignKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::json::{ProtocolJsonError, to_wire_json};
use crate::signing::calculate_request_signature;
use crate::tcp_init::ProcessIdentity;

/// IP protocol numbers used in L3 auth `ip.protocol` and `url` scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum L3IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl L3IpProtocol {
    /// Wire scheme prefix for `url` (`tcp` / `udp` / `icmp`).
    #[must_use]
    pub const fn scheme(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Maps known IANA protocol numbers; unknown values return `None`.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Icmp),
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Five-tuple fields embedded in L3 auth JSON (`ip` object).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L3AuthFiveTuple {
    /// Address family wire value: Go uses `0x0800` for IPv4, `0x86DD` for IPv6.
    pub atype: u32,
    pub protocol: L3IpProtocol,
    pub dest_addr: String,
    pub dest_port: u16,
    pub src_addr: String,
    pub src_port: u16,
}

impl L3AuthFiveTuple {
    /// IPv4 Ethernet type constant used by Go `authIPType` for non-IPv6.
    pub const ATYPE_IPV4: u32 = 0x0800;
    /// IPv6 Ethernet type constant used by Go for atype 6.
    pub const ATYPE_IPV6: u32 = 0x86DD;

    /// Builds an IPv4 five-tuple (`atype = 0x0800`).
    #[must_use]
    pub fn ipv4(
        protocol: L3IpProtocol,
        src_addr: impl Into<String>,
        src_port: u16,
        dest_addr: impl Into<String>,
        dest_port: u16,
    ) -> Self {
        Self {
            atype: Self::ATYPE_IPV4,
            protocol,
            dest_addr: dest_addr.into(),
            dest_port,
            src_addr: src_addr.into(),
            src_port,
        }
    }
}

/// Inputs for a signed L3 per-flow auth request JSON body.
#[derive(Clone, Debug)]
pub struct L3AuthParams<'a> {
    pub sid: &'a SessionId,
    pub app_id: &'a str,
    pub device_id: &'a DeviceId,
    pub connection_id: &'a ConnectionId,
    /// Client-assigned conntrack id (`conntrackHash` on the wire).
    pub conntrack_hash: u64,
    pub five_tuple: &'a L3AuthFiveTuple,
    pub process: &'a ProcessIdentity,
    pub lang: &'a str,
}

/// Builds compact signed JSON for an L3 `0x13` auth request.
///
/// Field order matches Go `authRequestIP`. `url` is `{scheme}:{dest}:{port}`
/// without `//` (unlike TCP init's `tcp://`).
pub fn build_signed_l3_auth_json(
    params: &L3AuthParams<'_>,
    sign_key: &SignKey,
) -> Result<Vec<u8>, L3AuthError> {
    if params.app_id.is_empty() {
        return Err(L3AuthError::EmptyAppId);
    }
    if params.five_tuple.dest_addr.is_empty() {
        return Err(L3AuthError::EmptyDestAddr);
    }
    if params.five_tuple.src_addr.is_empty() {
        return Err(L3AuthError::EmptySrcAddr);
    }

    let url = format!(
        "{}:{}:{}",
        params.five_tuple.protocol.scheme(),
        params.five_tuple.dest_addr,
        params.five_tuple.dest_port
    );
    let proc_hash = params.process.proc_hash();

    let unsigned = L3AuthWire {
        sid: params.sid.as_str(),
        app_id: params.app_id,
        url: &url,
        device_id: params.device_id.as_str(),
        connection_id: params.connection_id.as_str(),
        env: L3AuthEnv {
            application: L3AuthApplication {
                runtime: L3AuthRuntime {
                    process: L3AuthProcess {
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
        conntrack_hash: params.conntrack_hash,
        lang: params.lang,
        ip: L3AuthIpWire {
            atype: params.five_tuple.atype,
            protocol: u32::from(params.five_tuple.protocol.as_u8()),
            dest_addr: &params.five_tuple.dest_addr,
            dest_port: params.five_tuple.dest_port,
            src_addr: &params.five_tuple.src_addr,
            src_port: params.five_tuple.src_port,
        },
        proc_hash: &proc_hash,
        x_request_sig: "",
    };

    let unsigned_bytes = to_wire_json(&unsigned)?;
    let signature = calculate_request_signature(sign_key, &unsigned_bytes);
    let signed = L3AuthWire {
        x_request_sig: signature.as_str(),
        ..unsigned
    };
    Ok(to_wire_json(&signed)?)
}

/// Successful fields from a decoded `0x93` auth response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L3AuthResponse {
    pub code: i64,
    pub message: String,
    pub conntrack_hash: u64,
    /// Prefer `connectToken`; falls back to `token` (Go parity).
    pub connect_token: String,
}

/// Parses an L3 auth response JSON body (payload after `05 93 <status> <u16 len>`).
pub fn parse_l3_auth_response(json: &[u8]) -> Result<L3AuthResponse, L3AuthError> {
    let raw: L3AuthResponseWire =
        serde_json::from_slice(json).map_err(L3AuthError::ResponseJson)?;
    let connect_token = raw
        .data
        .connect_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            raw.data
                .token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("")
        .to_owned();
    Ok(L3AuthResponse {
        code: raw.code,
        message: raw.message.unwrap_or_default(),
        conntrack_hash: raw.data.conntrack_hash,
        connect_token,
    })
}

/// Wire DTO matching Go `authRequestIP` field order.
#[derive(Serialize)]
struct L3AuthWire<'a> {
    sid: &'a str,
    #[serde(rename = "appId")]
    app_id: &'a str,
    url: &'a str,
    #[serde(rename = "deviceId")]
    device_id: &'a str,
    #[serde(rename = "connectionId")]
    connection_id: &'a str,
    env: L3AuthEnv<'a>,
    #[serde(rename = "conntrackHash")]
    conntrack_hash: u64,
    lang: &'a str,
    ip: L3AuthIpWire<'a>,
    #[serde(rename = "procHash")]
    proc_hash: &'a str,
    #[serde(rename = "xRequestSig")]
    x_request_sig: &'a str,
}

#[derive(Serialize)]
struct L3AuthEnv<'a> {
    application: L3AuthApplication<'a>,
}

#[derive(Serialize)]
struct L3AuthApplication<'a> {
    runtime: L3AuthRuntime<'a>,
}

#[derive(Serialize)]
struct L3AuthRuntime<'a> {
    process: L3AuthProcess<'a>,
    process_trusted: &'a str,
}

#[derive(Serialize)]
struct L3AuthProcess<'a> {
    name: &'a str,
    digital_signature: &'a str,
    platform: &'a str,
    fingerprint: &'a str,
    description: &'a str,
    path: &'a str,
    version: &'a str,
    security_env: &'a str,
}

#[derive(Serialize)]
struct L3AuthIpWire<'a> {
    atype: u32,
    protocol: u32,
    #[serde(rename = "destAddr")]
    dest_addr: &'a str,
    #[serde(rename = "destPort")]
    dest_port: u16,
    #[serde(rename = "srcAddr")]
    src_addr: &'a str,
    #[serde(rename = "srcPort")]
    src_port: u16,
}

#[derive(Deserialize)]
struct L3AuthResponseWire {
    code: i64,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: L3AuthResponseDataWire,
}

#[derive(Default, Deserialize)]
struct L3AuthResponseDataWire {
    #[serde(default, rename = "conntrackHash")]
    conntrack_hash: u64,
    #[serde(default, rename = "connectToken")]
    connect_token: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Error)]
pub enum L3AuthError {
    #[error("appId must not be empty")]
    EmptyAppId,
    #[error("dest address must not be empty")]
    EmptyDestAddr,
    #[error("src address must not be empty")]
    EmptySrcAddr,
    #[error(transparent)]
    Json(#[from] ProtocolJsonError),
    #[error("failed to parse L3 auth response JSON: {0}")]
    ResponseJson(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_model::SignKey;

    fn sample_ids() -> (SessionId, DeviceId, ConnectionId, ProcessIdentity) {
        let sid = SessionId::new("sid-value").unwrap();
        let device = DeviceId::new("device-1").unwrap();
        let connection = ConnectionId::from_device_at(&device, 1_700_000_000_000_000).unwrap();
        let process = ProcessIdentity {
            name: "google-chrome-stable".to_owned(),
            path: "/usr/bin/google-chrome-stable".to_owned(),
        };
        (sid, device, connection, process)
    }

    #[test]
    fn url_uses_scheme_without_slashes() {
        let (sid, device, connection, process) = sample_ids();
        let five = L3AuthFiveTuple::ipv4(L3IpProtocol::Tcp, "10.8.0.2", 12345, "10.0.0.1", 443);
        let params = L3AuthParams {
            sid: &sid,
            app_id: "app-1",
            device_id: &device,
            connection_id: &connection,
            conntrack_hash: 7,
            five_tuple: &five,
            process: &process,
            lang: "en-US",
        };
        let key = SignKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let body = build_signed_l3_auth_json(&params, &key).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains(r#""url":"tcp:10.0.0.1:443""#));
        assert!(!text.contains("tcp://"));
        assert!(text.contains(r#""conntrackHash":7"#));
        assert!(text.contains(r#""destAddr":"10.0.0.1""#));
        assert!(text.contains(r#""srcPort":12345"#));
        assert!(text.contains(r#""atype":2048"#));
        assert!(!text.contains(r#""xRequestSig":"""#));
    }

    #[test]
    fn signed_json_hmac_covers_empty_sig_field() {
        let (sid, device, connection, process) = sample_ids();
        let five = L3AuthFiveTuple::ipv4(L3IpProtocol::Udp, "10.8.0.2", 53, "1.1.1.1", 53);
        let params = L3AuthParams {
            sid: &sid,
            app_id: "app-udp",
            device_id: &device,
            connection_id: &connection,
            conntrack_hash: 1,
            five_tuple: &five,
            process: &process,
            lang: "zh-CN",
        };
        let key = SignKey::from_hex("aabb").unwrap();
        let body = build_signed_l3_auth_json(&params, &key).unwrap();
        let text = String::from_utf8(body.clone()).unwrap();
        let sig_key = r#""xRequestSig":""#;
        let start = text.find(sig_key).expect("sig field");
        let sig_start = start + sig_key.len();
        let sig_end = text[sig_start..].find('"').expect("closing quote") + sig_start;
        let sig = &text[sig_start..sig_end];
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));

        let rebuild = build_signed_l3_auth_json(&params, &key).unwrap();
        assert_eq!(body, rebuild);
    }

    #[test]
    fn parse_auth_response_prefers_connect_token() {
        let json = br#"{"code":0,"message":"ok","data":{"conntrackHash":42,"connectToken":"tok-a","token":"tok-b"}}"#;
        let resp = parse_l3_auth_response(json).unwrap();
        assert_eq!(resp.code, 0);
        assert_eq!(resp.conntrack_hash, 42);
        assert_eq!(resp.connect_token, "tok-a");
    }

    #[test]
    fn parse_auth_response_falls_back_to_token() {
        let json = br#"{"code":0,"data":{"conntrackHash":9,"token":" legacy "}}"#;
        let resp = parse_l3_auth_response(json).unwrap();
        assert_eq!(resp.connect_token, "legacy");
        assert_eq!(resp.conntrack_hash, 9);
    }

    #[test]
    fn rejects_empty_app_id() {
        let (sid, device, connection, process) = sample_ids();
        let five = L3AuthFiveTuple::ipv4(L3IpProtocol::Tcp, "1.1.1.1", 1, "2.2.2.2", 80);
        let params = L3AuthParams {
            sid: &sid,
            app_id: "",
            device_id: &device,
            connection_id: &connection,
            conntrack_hash: 1,
            five_tuple: &five,
            process: &process,
            lang: "en-US",
        };
        assert!(matches!(
            build_signed_l3_auth_json(&params, &SignKey::from_hex("aa").unwrap()),
            Err(L3AuthError::EmptyAppId)
        ));
    }
}
