//! Build and apply L3 per-flow auth frames (`0x13` / `0x93`).

use atrust_protocol::{
    L3AuthError, L3AuthFiveTuple, L3AuthParams, L3AuthResponse, ProcessIdentity,
    build_signed_l3_auth_json, encode_l3_auth_req, parse_l3_auth_response,
};
use hermes_model::{ConnectionId, DeviceId, SessionId, SignKey};
use thiserror::Error;

use crate::conntrack::{AuthOutcome, ConntrackError, ConntrackTable};

/// Session material needed to sign an L3 flow auth request.
#[derive(Clone, Debug)]
pub struct L3AuthContext<'a> {
    pub sid: &'a SessionId,
    pub device_id: &'a DeviceId,
    pub connection_id: &'a ConnectionId,
    pub sign_key: &'a SignKey,
    pub process: &'a ProcessIdentity,
    pub lang: &'a str,
}

/// Builds a signed `0x13` frame for one conntrack entry.
pub fn build_flow_auth_frame(
    ctx: &L3AuthContext<'_>,
    app_id: &str,
    auth_id: u64,
    five_tuple: &L3AuthFiveTuple,
) -> Result<Vec<u8>, FlowAuthError> {
    let params = L3AuthParams {
        sid: ctx.sid,
        app_id,
        device_id: ctx.device_id,
        connection_id: ctx.connection_id,
        conntrack_hash: auth_id,
        five_tuple,
        process: ctx.process,
        lang: ctx.lang,
    };
    let json = build_signed_l3_auth_json(&params, ctx.sign_key)?;
    Ok(encode_l3_auth_req(&json)?)
}

/// Applies a successful status-0 `0x93` JSON body to the conntrack table.
///
/// Wire status byte must already be checked by the reader (`status == 0`).
pub fn apply_auth_response_json(
    table: &mut ConntrackTable,
    json: &[u8],
) -> Result<L3AuthResponse, FlowAuthError> {
    let resp = parse_l3_auth_response(json)?;
    if resp.conntrack_hash == 0 {
        return Err(FlowAuthError::MissingConntrackHash);
    }
    table.mark_auth(
        resp.conntrack_hash,
        resp.code,
        resp.message.clone(),
        resp.connect_token.clone(),
    )?;
    Ok(resp)
}

/// Applies a non-zero wire status from `05 93 <status> ...` when JSON may still
/// identify the flow via `conntrackHash`.
///
/// Returns the `conntrackHash` the response settled, so a read loop can wake the
/// waiter for that flow without parsing the body a second time.
pub fn apply_auth_wire_status(
    table: &mut ConntrackTable,
    status: u8,
    json: &[u8],
) -> Result<u64, FlowAuthError> {
    if status == 0 {
        let resp = apply_auth_response_json(table, json)?;
        return Ok(resp.conntrack_hash);
    }
    if let Ok(resp) = parse_l3_auth_response(json) {
        if resp.conntrack_hash != 0 {
            table.mark_auth_error(resp.conntrack_hash, format!("auth status {status:#04x}"))?;
            return Ok(resp.conntrack_hash);
        }
    }
    Err(FlowAuthError::WireStatus(status))
}

/// Whether a completed entry may send `0x14` data, and with which token.
pub fn ready_token(outcome: &AuthOutcome) -> Result<&str, FlowAuthError> {
    match outcome {
        AuthOutcome::Ready { connect_token } => Ok(connect_token.as_str()),
        AuthOutcome::Failed { message } => Err(FlowAuthError::AuthFailed(message.clone())),
    }
}

#[derive(Debug, Error)]
pub enum FlowAuthError {
    #[error(transparent)]
    Protocol(#[from] L3AuthError),
    #[error(transparent)]
    Frame(#[from] atrust_protocol::L3FrameError),
    #[error(transparent)]
    Conntrack(#[from] ConntrackError),
    #[error("auth response missing conntrack hash")]
    MissingConntrackHash,
    #[error("L3 auth wire status {0:#04x}")]
    WireStatus(u8),
    #[error("L3 flow auth failed: {0}")]
    AuthFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrust_protocol::{L3IpProtocol, l3_cmd};
    use hermes_model::SignKey;

    use crate::conntrack::{AuthOutcome, FlowKey};

    fn ctx_ids() -> (SessionId, DeviceId, ConnectionId, ProcessIdentity, SignKey) {
        let sid = SessionId::new("sid").unwrap();
        let device = DeviceId::new("dev").unwrap();
        let connection = ConnectionId::new("conn").unwrap();
        let process = ProcessIdentity::default_for_port(443);
        let key = SignKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        (sid, device, connection, process, key)
    }

    #[test]
    fn build_frame_starts_with_auth_req() {
        let (sid, device, connection, process, key) = ctx_ids();
        let ctx = L3AuthContext {
            sid: &sid,
            device_id: &device,
            connection_id: &connection,
            sign_key: &key,
            process: &process,
            lang: "en-US",
        };
        let five = L3AuthFiveTuple::ipv4(L3IpProtocol::Tcp, "10.8.0.1", 40000, "10.0.0.9", 443);
        let frame = build_flow_auth_frame(&ctx, "app-1", 3, &five).unwrap();
        assert_eq!(frame[0], 0x05);
        assert_eq!(frame[1], l3_cmd::AUTH_REQ);
        let json_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        assert_eq!(frame.len(), 4 + json_len);
        let json = std::str::from_utf8(&frame[4..]).unwrap();
        assert!(json.contains(r#""conntrackHash":3"#));
        assert!(json.contains(r#""url":"tcp:10.0.0.9:443""#));
    }

    #[test]
    fn wire_status_failure_still_reports_the_flow() {
        let mut table = ConntrackTable::new();
        let key = FlowKey::new(4, "10.8.0.1", 1, "10.0.0.9", 443);
        let id = table.get_or_create(key.clone(), "app", "g").auth_id;
        let json = format!(r#"{{"code":0,"data":{{"conntrackHash":{id}}}}}"#);

        let hash = apply_auth_wire_status(&mut table, 0x01, json.as_bytes()).unwrap();
        assert_eq!(hash, id);
        assert!(matches!(
            table.get_by_key(&key).unwrap().outcome(),
            Some(AuthOutcome::Failed { .. })
        ));
    }

    #[test]
    fn wire_status_failure_without_hash_is_unattributable() {
        let mut table = ConntrackTable::new();
        assert!(matches!(
            apply_auth_wire_status(&mut table, 0x02, b"not json"),
            Err(FlowAuthError::WireStatus(0x02))
        ));
    }

    #[test]
    fn apply_response_marks_ready() {
        let mut table = ConntrackTable::new();
        let key = FlowKey::new(4, "10.8.0.1", 1, "10.0.0.9", 443);
        let id = table.get_or_create(key.clone(), "app", "g").auth_id;
        let json = format!(
            r#"{{"code":0,"message":"ok","data":{{"conntrackHash":{id},"connectToken":"c-token"}}}}"#
        );
        let resp = apply_auth_response_json(&mut table, json.as_bytes()).unwrap();
        assert_eq!(resp.connect_token, "c-token");
        assert_eq!(
            table.get_by_key(&key).unwrap().outcome(),
            Some(&AuthOutcome::Ready {
                connect_token: "c-token".to_owned()
            })
        );
        assert_eq!(
            ready_token(table.get_by_key(&key).unwrap().outcome().unwrap()).unwrap(),
            "c-token"
        );
    }
}
