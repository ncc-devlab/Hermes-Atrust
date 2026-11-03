//! End-to-end L3 session tests against an in-memory mock peer.
//!
//! The peer speaks the same frames as the reference server
//! (`Hermes-aTrust-Server::hermes-tunnel::l3`): Get-IP handshake, `0x93` for
//! `0x13`, length-prefixed `0x94` echoes for `0x14`, and `05 95 00 00` for
//! heartbeats. No TLS and no gateway are involved.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use atrust_l3::{
    FlowAuthStats, Ipv4Flow, L3AuthContext, L3AuthRetryConfig, L3CloseReason, L3Session,
    L3SessionError, parse_ipv4_flow,
};
use atrust_protocol::ProcessIdentity;
use hermes_events::{EventBus, EventDelivery, HermesEvent};
use hermes_model::{ConnectionId, DeviceId, SessionId, SignKey};
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::task::JoinHandle;

const GET_IP_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_HEARTBEAT: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug)]
enum PeerWritePlan {
    Whole,
    OneByte,
    Cuts(Vec<usize>),
    Coalesced,
}

async fn write_planned(server: &mut DuplexStream, bytes: &[u8], plan: &PeerWritePlan) {
    match plan {
        PeerWritePlan::Whole | PeerWritePlan::Coalesced => server.write_all(bytes).await.unwrap(),
        PeerWritePlan::OneByte => {
            for byte in bytes {
                server.write_all(std::slice::from_ref(byte)).await.unwrap();
            }
        }
        PeerWritePlan::Cuts(cuts) => {
            let mut start = 0;
            for &end in cuts {
                if end > start && end < bytes.len() {
                    server.write_all(&bytes[start..end]).await.unwrap();
                    start = end;
                }
            }
            server.write_all(&bytes[start..]).await.unwrap();
        }
    }
}

fn v2_data_response(packet: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x05, 0x94];
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

async fn read_get_ip(server: &mut DuplexStream) {
    let mut prefix = [0u8; 7];
    server.read_exact(&mut prefix).await.unwrap();
    let json_len = u16::from_be_bytes([prefix[5], prefix[6]]) as usize;
    let mut request = vec![0; json_len + 10];
    server.read_exact(&mut request).await.unwrap();
}

fn spawn_v2_plan_peer(
    mut server: DuplexStream,
    plan: PeerWritePlan,
    frames: Vec<u8>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        read_get_ip(&mut server).await;
        write_planned(&mut server, &[0x05, 0xd0], &plan).await;
        write_planned(&mut server, &[0x53, 0, 0, 2, b'O', b'K'], &plan).await;
        write_planned(&mut server, &[0x05, 0, 0, 1, 10, 8, 0, 7, 0, 0], &plan).await;
        write_planned(&mut server, &frames, &plan).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
}

/// How the mock peer should answer a `0x13`.
#[derive(Clone, Debug)]
enum AuthBehaviour {
    Grant {
        token: String,
    },
    /// Hold responses until this many distinct wire requests arrive, proving
    /// the client can have several authorizations outstanding at once.
    BatchGrant {
        token: String,
        batch_size: usize,
    },
    Deny {
        code: i64,
        message: String,
    },
    /// Accept the request and never answer, to exercise the caller's timeout.
    Ignore,
    /// Drop the connection instead of answering.
    Disconnect,
    TransientThenGrant {
        status: u8,
        token: String,
    },
    TransientForever {
        status: u8,
    },
    OuterStatus {
        status: u8,
    },
    RawTransient {
        status: u8,
        body: Vec<u8>,
    },
    TransientThenVip {
        status: u8,
    },
    LateThenGrant {
        token: String,
    },
}

#[derive(Clone, Debug, Default)]
struct PeerStats {
    auth_requests: Arc<AtomicUsize>,
    data_frames: Arc<AtomicUsize>,
    heartbeats: Arc<AtomicUsize>,
}

impl PeerStats {
    fn auth_requests(&self) -> usize {
        self.auth_requests.load(Ordering::SeqCst)
    }
    fn data_frames(&self) -> usize {
        self.data_frames.load(Ordering::SeqCst)
    }
    fn heartbeats(&self) -> usize {
        self.heartbeats.load(Ordering::SeqCst)
    }
}

fn sid() -> SessionId {
    SessionId::new("s".repeat(73)).expect("valid SID")
}

fn auth_ids() -> (DeviceId, ConnectionId, SignKey, ProcessIdentity) {
    let device = DeviceId::new("device-1").expect("device id");
    let connection = ConnectionId::from_device_at(&device, 1_700_000_000_000_000).expect("conn id");
    let key = SignKey::from_hex("00112233445566778899aabbccddeeff").expect("sign key");
    let process = ProcessIdentity::default_for_port(443);
    (device, connection, key, process)
}

/// Builds a minimal IPv4 TCP packet carrying `payload`.
fn tcp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 8, 0, 7]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0u8; 16]);
    pkt.extend_from_slice(payload);
    pkt
}

fn flow_of(packet: &[u8]) -> Ipv4Flow {
    parse_ipv4_flow(packet).expect("parses as IPv4")
}

/// Serves the Get-IP handshake then dispatches client frames until EOF.
fn spawn_peer(
    mut server: DuplexStream,
    behaviour: AuthBehaviour,
    stats: PeerStats,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Get-IP: `05 01 d0 53 00 <u16 len> <json>` then `05 04 00 01 ...`.
        let mut prefix = [0u8; 7];
        if server.read_exact(&mut prefix).await.is_err() {
            return;
        }
        assert_eq!(&prefix[..5], &[0x05, 0x01, 0xd0, 0x53, 0x00]);
        let json_len = u16::from_be_bytes([prefix[5], prefix[6]]) as usize;
        let mut json = vec![0; json_len];
        server.read_exact(&mut json).await.expect("SID JSON");
        let mut address_request = [0u8; 10];
        server
            .read_exact(&mut address_request)
            .await
            .expect("address request");

        server.write_all(&[0x05, 0xd0]).await.expect("method ack");
        server
            .write_all(&[0x53, 0x00, 0x00, 0x02, b'O', b'K'])
            .await
            .expect("status frame");
        // Real VIP frame: `05 00 <reserved> <addrType=1>` then a SIX byte body
        // whose first four are the IPv4. The
        // two trailing bytes are what an 8-byte reader would leave on the wire.
        server
            .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 7, 0xde, 0xad])
            .await
            .expect("vip");

        let mut pending: Vec<u8> = Vec::new();
        let mut pending_auth = Vec::new();
        let mut chunk = vec![0u8; 8192];
        loop {
            // Consume every whole frame currently buffered.
            while let Some(frame) = parse_client_frame(&pending) {
                match &frame.kind {
                    ClientFrame::Auth { json } => {
                        stats.auth_requests.fetch_add(1, Ordering::SeqCst);
                        let request: Value = serde_json::from_slice(json).expect("auth JSON");
                        let hash = request
                            .get("conntrackHash")
                            .and_then(Value::as_u64)
                            .expect("conntrackHash");
                        match &behaviour {
                            AuthBehaviour::Grant { token } => {
                                let body = format!(
                                    r#"{{"code":0,"message":"OK","data":{{"conntrackHash":{hash},"connectToken":"{token}"}}}}"#
                                );
                                server
                                    .write_all(&encode_auth_resp(0, body.as_bytes()))
                                    .await
                                    .expect("auth grant");
                            }
                            AuthBehaviour::BatchGrant { token, batch_size } => {
                                pending_auth.push(hash);
                                if pending_auth.len() == *batch_size {
                                    for hash in pending_auth.drain(..).rev() {
                                        let body = format!(
                                            r#"{{"code":0,"message":"OK","data":{{"conntrackHash":{hash},"connectToken":"{token}"}}}}"#
                                        );
                                        server
                                            .write_all(&encode_auth_resp(0, body.as_bytes()))
                                            .await
                                            .expect("batched auth grant");
                                    }
                                }
                            }
                            AuthBehaviour::Deny { code, message } => {
                                let body = format!(
                                    r#"{{"code":{code},"message":"{message}","data":{{"conntrackHash":{hash}}}}}"#
                                );
                                server
                                    .write_all(&encode_auth_resp(0, body.as_bytes()))
                                    .await
                                    .expect("auth deny");
                            }
                            AuthBehaviour::Ignore => {}
                            AuthBehaviour::Disconnect => return,
                            AuthBehaviour::TransientThenGrant { status, token } => {
                                let body =
                                    format!(r#"{{"code":0,"data":{{"conntrackHash":{hash}}}}}"#);
                                if stats.auth_requests() == 1 {
                                    server
                                        .write_all(&encode_auth_resp(*status, body.as_bytes()))
                                        .await
                                        .expect("transient auth");
                                } else {
                                    let body = format!(
                                        r#"{{"code":0,"message":"OK","data":{{"conntrackHash":{hash},"connectToken":"{token}"}}}}"#
                                    );
                                    server
                                        .write_all(&encode_auth_resp(0, body.as_bytes()))
                                        .await
                                        .expect("auth grant");
                                }
                            }
                            AuthBehaviour::TransientForever { status } => {
                                let body =
                                    format!(r#"{{"code":0,"data":{{"conntrackHash":{hash}}}}}"#);
                                server
                                    .write_all(&encode_auth_resp(*status, body.as_bytes()))
                                    .await
                                    .expect("transient auth");
                            }
                            AuthBehaviour::OuterStatus { status } => {
                                let body =
                                    format!(r#"{{"code":0,"data":{{"conntrackHash":{hash}}}}}"#);
                                server
                                    .write_all(&encode_auth_resp(*status, body.as_bytes()))
                                    .await
                                    .expect("terminal auth");
                            }
                            AuthBehaviour::RawTransient { status, body } => {
                                server
                                    .write_all(&encode_auth_resp(*status, body))
                                    .await
                                    .expect("raw transient auth");
                            }
                            AuthBehaviour::TransientThenVip { status } => {
                                let body =
                                    format!(r#"{{"code":0,"data":{{"conntrackHash":{hash}}}}}"#);
                                server
                                    .write_all(&encode_auth_resp(*status, body.as_bytes()))
                                    .await
                                    .expect("transient auth");
                                let update = br#"{"vip":"10.8.0.9"}"#;
                                let mut frame = vec![0x05, 0x97, 0];
                                frame.extend_from_slice(&(update.len() as u16).to_be_bytes());
                                frame.extend_from_slice(update);
                                server.write_all(&frame).await.expect("VIP update");
                            }
                            AuthBehaviour::LateThenGrant { token } => {
                                let body = format!(
                                    r#"{{"code":0,"message":"OK","data":{{"conntrackHash":{hash},"connectToken":"{token}"}}}}"#
                                );
                                if stats.auth_requests() == 1 {
                                    tokio::time::sleep(Duration::from_secs(9)).await;
                                }
                                server
                                    .write_all(&encode_auth_resp(0, body.as_bytes()))
                                    .await
                                    .expect("late/granted auth");
                            }
                        }
                    }
                    ClientFrame::Data { packets } => {
                        stats.data_frames.fetch_add(1, Ordering::SeqCst);
                        for packet in packets {
                            let mut resp = vec![0x05, 0x94];
                            resp.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                            resp.extend_from_slice(packet);
                            server.write_all(&resp).await.expect("data echo");
                        }
                    }
                    ClientFrame::Heartbeat => {
                        stats.heartbeats.fetch_add(1, Ordering::SeqCst);
                        server
                            .write_all(&[0x05, 0x95, 0x00, 0x00])
                            .await
                            .expect("heartbeat ack");
                    }
                }
                pending.drain(..frame.consumed);
            }

            match server.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
            }
        }
    })
}

fn spawn_vip_update_peer(mut server: DuplexStream) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut prefix = [0u8; 7];
        server.read_exact(&mut prefix).await.expect("Get-IP prefix");
        let json_len = u16::from_be_bytes([prefix[5], prefix[6]]) as usize;
        let mut rest = vec![0; json_len + 10];
        server.read_exact(&mut rest).await.expect("Get-IP request");
        server.write_all(&[0x05, 0xd0]).await.expect("method ack");
        server
            .write_all(&[0x53, 0x00, 0x00, 0x02, b'O', b'K'])
            .await
            .expect("status frame");
        server
            .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 7, 0, 0])
            .await
            .expect("VIP frame");

        let json = br#"{"data":{"ipv4":"10.8.0.9"}}"#;
        let mut update = vec![0x05, 0x97, 0x00];
        update.extend_from_slice(&(json.len() as u16).to_be_bytes());
        update.extend_from_slice(json);
        server.write_all(&update).await.expect("VIP update");
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
}

enum ClientFrame {
    Auth { json: Vec<u8> },
    Data { packets: Vec<Vec<u8>> },
    Heartbeat,
}

struct ParsedFrame {
    kind: ClientFrame,
    consumed: usize,
}

fn parse_client_frame(buf: &[u8]) -> Option<ParsedFrame> {
    if buf.len() < 2 {
        return None;
    }
    assert_eq!(buf[0], 0x05, "client must speak L3 version 5");
    match buf[1] {
        0x13 => {
            if buf.len() < 4 {
                return None;
            }
            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if buf.len() < 4 + len {
                return None;
            }
            Some(ParsedFrame {
                kind: ClientFrame::Auth {
                    json: buf[4..4 + len].to_vec(),
                },
                consumed: 4 + len,
            })
        }
        0x14 => {
            if buf.len() < 3 {
                return None;
            }
            let token_len = buf[2] as usize;
            let mut idx = 3 + token_len;
            if buf.len() < idx + 3 {
                return None;
            }
            idx += 2; // reserved
            let count = buf[idx] as usize;
            idx += 1;
            let mut packets = Vec::with_capacity(count);
            for _ in 0..count {
                if buf.len() < idx + 2 {
                    return None;
                }
                let plen = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
                idx += 2;
                if buf.len() < idx + plen {
                    return None;
                }
                packets.push(buf[idx..idx + plen].to_vec());
                idx += plen;
            }
            Some(ParsedFrame {
                kind: ClientFrame::Data { packets },
                consumed: idx,
            })
        }
        0x15 => {
            if buf.len() < 4 {
                return None;
            }
            Some(ParsedFrame {
                kind: ClientFrame::Heartbeat,
                consumed: 4,
            })
        }
        other => panic!("unexpected client command {other:#04x}"),
    }
}

fn encode_auth_resp(status: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x05, 0x93, status];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Establishes a session against a peer with the given auth behaviour.
async fn session_with(
    behaviour: AuthBehaviour,
    heartbeat: Duration,
) -> (L3Session, PeerStats, JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let stats = PeerStats::default();
    let peer = spawn_peer(server, behaviour, stats.clone());
    let session = L3Session::start(client, &sid(), heartbeat, GET_IP_TIMEOUT, None, None)
        .await
        .expect("session establishes");
    (session, stats, peer)
}

async fn e12_session_with(
    behaviour: AuthBehaviour,
    delayed_retry_delay: Duration,
) -> (L3Session, PeerStats, JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let stats = PeerStats::default();
    let peer = spawn_peer(server, behaviour, stats.clone());
    let session = L3Session::start_with_config(
        client,
        &sid(),
        IDLE_HEARTBEAT,
        GET_IP_TIMEOUT,
        None,
        None,
        L3AuthRetryConfig {
            enabled: true,
            max_wire_retries_per_flow: 1,
            delayed_retry_delay,
            overall_auth_deadline: Duration::from_secs(8),
        },
    )
    .await
    .expect("session establishes");
    (session, stats, peer)
}

async fn e12_authorize(session: &L3Session) -> Result<String, L3SessionError> {
    let (device, connection, key, process) = auth_ids();
    let session_id = sid();
    let ctx = L3AuthContext {
        sid: &session_id,
        device_id: &device,
        connection_id: &connection,
        sign_key: &key,
        process: &process,
        lang: "en-US",
        domain: None,
    };
    session
        .authorize_flow(
            &ctx,
            "e12-m-app",
            "e12-m-group",
            &flow_of(&tcp_packet(41_000, 443, b"")),
        )
        .await
}

#[tokio::test]
async fn e12_m_default_start_keeps_transient_retry_disabled() {
    let (session, stats, peer) = session_with(
        AuthBehaviour::TransientForever { status: 0x84 },
        IDLE_HEARTBEAT,
    )
    .await;
    assert!(matches!(
        e12_authorize(&session).await,
        Err(L3SessionError::FlowAuth(_))
    ));
    assert_eq!(stats.auth_requests(), 1);
    let flow_stats = session.flow_auth_stats();
    assert_eq!(flow_stats.transient_statuses_received, 1);
    assert_eq!(flow_stats.wire_retries_scheduled, 0);
    session.close().await;
    peer.abort();
}

#[tokio::test]
async fn e12_m_s84_retries_immediately_and_settles() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::TransientThenGrant {
            status: 0x84,
            token: "fixture-token-with-at-least-32-bytes".to_owned(),
        },
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(
        e12_authorize(&session).await.unwrap(),
        "fixture-token-with-at-least-32-bytes"
    );
    assert_eq!(stats.auth_requests(), 2);
    assert_eq!(session.flow_auth_stats().wire_retries_sent, 1);
    session.close().await;
    peer.abort();
}

#[tokio::test(start_paused = true)]
async fn e12_m_s85_s86_s87_wait_for_the_configured_delay() {
    for status in 0x85..=0x87 {
        let (session, stats, peer) = e12_session_with(
            AuthBehaviour::TransientThenGrant {
                status,
                token: "fixture-token-with-at-least-32-bytes".to_owned(),
            },
            Duration::from_secs(1),
        )
        .await;
        let session = Arc::new(session);
        let task_session = Arc::clone(&session);
        let task = tokio::spawn(async move { e12_authorize(&task_session).await });
        while stats.auth_requests() == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(999)).await;
        tokio::task::yield_now().await;
        assert_eq!(stats.auth_requests(), 1, "status {status:#04x}");
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(task.await.unwrap().is_ok());
        assert_eq!(stats.auth_requests(), 2);
        let flow_stats = session.flow_auth_stats();
        assert_eq!(flow_stats.transient_statuses_received, 1);
        assert_eq!(flow_stats.wire_retries_scheduled, 1);
        assert_eq!(flow_stats.wire_retries_sent, 1);
        session.close().await;
        peer.abort();
    }
}

#[tokio::test]
async fn e12_m_immediate_budget_exhaustion_fails_after_two_requests() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::TransientForever { status: 0x84 },
        Duration::from_secs(1),
    )
    .await;
    assert!(matches!(
        e12_authorize(&session).await,
        Err(L3SessionError::FlowAuth(_))
    ));
    assert_eq!(stats.auth_requests(), 2);
    let flow_stats = session.flow_auth_stats();
    assert_eq!(flow_stats.wire_retries_exhausted, 1);
    assert_eq!(flow_stats.wire_retries_sent, 1);
    session.close().await;
    peer.abort();
}

#[tokio::test(start_paused = true)]
async fn e12_m_close_cancels_a_delayed_retry() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::TransientForever { status: 0x85 },
        Duration::from_secs(1),
    )
    .await;
    let session = Arc::new(session);
    let task_session = Arc::clone(&session);
    let task = tokio::spawn(async move { e12_authorize(&task_session).await });
    while stats.auth_requests() == 0 {
        tokio::task::yield_now().await;
    }
    session.close().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(stats.auth_requests(), 1);
    assert_eq!(session.flow_auth_stats().wire_retries_cancelled, 1);
    assert!(matches!(task.await.unwrap(), Err(L3SessionError::Closed)));
    peer.abort();
}

#[tokio::test(start_paused = true)]
async fn e12_m_delayed_budget_exhaustion_fails_after_two_requests() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::TransientForever { status: 0x85 },
        Duration::from_secs(1),
    )
    .await;
    let session = Arc::new(session);
    let task_session = Arc::clone(&session);
    let task = tokio::spawn(async move { e12_authorize(&task_session).await });
    while stats.auth_requests() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        task.await.unwrap(),
        Err(L3SessionError::FlowAuth(_))
    ));
    assert_eq!(stats.auth_requests(), 2);
    assert_eq!(session.flow_auth_stats().wire_retries_exhausted, 1);
    session.close().await;
    peer.abort();
}

#[tokio::test]
async fn e12_m_terminal_status_never_retries() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::OuterStatus { status: 0x82 },
        Duration::from_secs(1),
    )
    .await;
    assert!(matches!(
        e12_authorize(&session).await,
        Err(L3SessionError::FlowAuth(_))
    ));
    assert_eq!(stats.auth_requests(), 1);
    assert_eq!(session.flow_auth_stats().wire_retries_scheduled, 0);
    session.close().await;
    peer.abort();
}

#[tokio::test(start_paused = true)]
async fn e12_m_malformed_missing_and_unknown_hashes_are_unattributable() {
    let bodies = [
        b"not-json".to_vec(),
        br#"{"code":0,"data":{"conntrackHash":0}}"#.to_vec(),
        br#"{"code":0,"data":{"conntrackHash":18446744073709551615}}"#.to_vec(),
    ];
    for body in bodies {
        let (session, stats, peer) = e12_session_with(
            AuthBehaviour::RawTransient { status: 0x84, body },
            Duration::from_secs(1),
        )
        .await;
        let session = Arc::new(session);
        let task_session = Arc::clone(&session);
        let task = tokio::spawn(async move { e12_authorize(&task_session).await });
        while stats.auth_requests() == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(8)).await;
        assert!(matches!(
            task.await.unwrap(),
            Err(L3SessionError::AuthTimeout { .. })
        ));
        assert_eq!(stats.auth_requests(), 1);
        assert_eq!(session.flow_auth_stats().wire_retries_scheduled, 0);
        session.close().await;
        peer.abort();
    }
}

#[tokio::test]
async fn e12_m_32_concurrent_callers_share_each_wire_attempt() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::TransientThenGrant {
            status: 0x84,
            token: "fixture-token-with-at-least-32-bytes".to_owned(),
        },
        Duration::from_secs(1),
    )
    .await;
    let session = Arc::new(session);
    let barrier = Arc::new(tokio::sync::Barrier::new(33));
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let session = Arc::clone(&session);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            e12_authorize(&session).await
        }));
    }
    barrier.wait().await;
    for task in tasks {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(stats.auth_requests(), 2);
    assert_eq!(session.flow_auth_stats().wire_retries_sent, 1);
    session.close().await;
    peer.abort();
}

#[tokio::test(start_paused = true)]
async fn e12_m_vip_change_cancels_a_delayed_retry() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::TransientThenVip { status: 0x85 },
        Duration::from_secs(1),
    )
    .await;
    let session = Arc::new(session);
    let task_session = Arc::clone(&session);
    let task = tokio::spawn(async move { e12_authorize(&task_session).await });
    assert!(matches!(
        task.await.unwrap(),
        Err(L3SessionError::VipChanged { .. })
    ));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(stats.auth_requests(), 1);
    assert_eq!(session.flow_auth_stats().wire_retries_cancelled, 1);
    session.close().await;
    peer.abort();
}

#[tokio::test(start_paused = true)]
async fn e12_m_late_response_does_not_settle_a_new_flow_attempt() {
    let (session, stats, peer) = e12_session_with(
        AuthBehaviour::LateThenGrant {
            token: "fixture-token-with-at-least-32-bytes".to_owned(),
        },
        Duration::from_secs(1),
    )
    .await;
    let session = Arc::new(session);
    let first_session = Arc::clone(&session);
    let first = tokio::spawn(async move { e12_authorize(&first_session).await });
    while stats.auth_requests() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(8)).await;
    assert!(matches!(
        first.await.unwrap(),
        Err(L3SessionError::AuthTimeout { .. })
    ));

    let second_session = Arc::clone(&session);
    let second = tokio::spawn(async move { e12_authorize(&second_session).await });
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(second.await.unwrap().is_ok());
    assert_eq!(stats.auth_requests(), 2);
    session.close().await;
    peer.abort();
}

#[tokio::test]
async fn async_vip_update_reaches_session_state_and_event_bus_without_tun() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer = spawn_vip_update_peer(server);
    let events = EventBus::new(8);
    let mut subscriber = events.subscribe();
    let session = L3Session::start(
        client,
        &sid(),
        IDLE_HEARTBEAT,
        GET_IP_TIMEOUT,
        Some("group-1".to_owned()),
        Some(events),
    )
    .await
    .expect("session establishes");

    assert_eq!(session.get_ip().address, Ipv4Addr::new(10, 8, 0, 7));
    let delivery = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("VIP event arrives")
        .expect("event stream remains open");
    let EventDelivery::Event(event) = delivery else {
        panic!("expected event delivery");
    };
    assert!(matches!(
        event.as_ref(),
        HermesEvent::L3VipChanged { node_group_id, previous, current }
            if node_group_id == "group-1"
                && *previous == Ipv4Addr::new(10, 8, 0, 7)
                && *current == Ipv4Addr::new(10, 8, 0, 9)
    ));
    assert_eq!(session.vip(), Ipv4Addr::new(10, 8, 0, 9));

    session.close().await;
    peer.abort();
}

#[tokio::test]
async fn session_authorizes_a_flow_and_round_trips_a_packet() {
    let (session, stats, peer) = session_with(
        AuthBehaviour::Grant {
            token: "tok-1".to_owned(),
        },
        IDLE_HEARTBEAT,
    )
    .await;

    assert_eq!(session.vip().to_string(), "10.8.0.7");
    assert_eq!(session.get_ip().status_text(), "OK");

    let (device, connection, key, process) = auth_ids();
    let session_id = sid();
    let ctx = L3AuthContext {
        sid: &session_id,
        device_id: &device,
        connection_id: &connection,
        sign_key: &key,
        process: &process,
        lang: "en-US",
        domain: None,
    };

    let packet = tcp_packet(40000, 443, b"hello");
    let flow = flow_of(&packet);
    let token = session
        .authorize_flow(&ctx, "app-1", "group-1", &flow)
        .await
        .expect("flow is authorized");
    assert_eq!(token, "tok-1");

    session
        .send_packet(&token, &packet)
        .await
        .expect("packet is sent");
    let echoed = session.recv_packet().await.expect("echo arrives");
    assert_eq!(echoed, packet);

    assert_eq!(stats.auth_requests(), 1);
    assert_eq!(stats.data_frames(), 1);

    session.close().await;
    assert!(session.is_closed());
    let _ = peer.await;
}

#[tokio::test]
async fn authorized_flow_is_cached_and_never_reauthorized() {
    let (session, stats, _peer) = session_with(
        AuthBehaviour::Grant {
            token: "tok-cached".to_owned(),
        },
        IDLE_HEARTBEAT,
    )
    .await;

    let (device, connection, key, process) = auth_ids();
    let session_id = sid();
    let ctx = L3AuthContext {
        sid: &session_id,
        device_id: &device,
        connection_id: &connection,
        sign_key: &key,
        process: &process,
        lang: "en-US",
        domain: None,
    };
    let flow = flow_of(&tcp_packet(40000, 443, b""));

    for _ in 0..3 {
        let token = session
            .authorize_flow(&ctx, "app-1", "group-1", &flow)
            .await
            .expect("authorized");
        assert_eq!(token, "tok-cached");
    }
    assert_eq!(
        stats.auth_requests(),
        1,
        "cached flow must not hit the wire"
    );

    // A different source port is a different flow and must authorize again.
    let other = flow_of(&tcp_packet(40001, 443, b""));
    session
        .authorize_flow(&ctx, "app-1", "group-1", &other)
        .await
        .expect("authorized");
    assert_eq!(stats.auth_requests(), 2);
}

#[tokio::test]
async fn concurrent_callers_for_one_flow_send_a_single_auth() {
    let (session, stats, _peer) = session_with(
        AuthBehaviour::Grant {
            token: "tok-shared".to_owned(),
        },
        IDLE_HEARTBEAT,
    )
    .await;
    let session = Arc::new(session);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let session = Arc::clone(&session);
        handles.push(tokio::spawn(async move {
            let (device, connection, key, process) = auth_ids();
            let session_id = sid();
            let ctx = L3AuthContext {
                sid: &session_id,
                device_id: &device,
                connection_id: &connection,
                sign_key: &key,
                process: &process,
                lang: "en-US",
                domain: None,
            };
            let flow = flow_of(&tcp_packet(40000, 443, b""));
            session
                .authorize_flow(&ctx, "app-1", "group-1", &flow)
                .await
        }));
    }
    for handle in handles {
        let token = handle.await.expect("task").expect("authorized");
        assert_eq!(token, "tok-shared");
    }
    assert_eq!(stats.auth_requests(), 1, "one 0x13 for one racing flow");
    assert_eq!(
        session.flow_auth_stats(),
        FlowAuthStats {
            requests_sent: 1,
            outcomes_received: 1,
            timeouts: 0,
            in_flight: 0,
            peak_in_flight: 1,
            ..FlowAuthStats::default()
        }
    );
}

#[tokio::test]
async fn concurrent_distinct_flows_are_in_flight_and_each_deduplicated() {
    let (session, stats, _peer) = session_with(
        AuthBehaviour::BatchGrant {
            token: "tok-batch".to_owned(),
            batch_size: 2,
        },
        IDLE_HEARTBEAT,
    )
    .await;
    let session = Arc::new(session);
    let barrier = Arc::new(tokio::sync::Barrier::new(5));
    let mut handles = Vec::new();
    for src_port in [40_000, 40_001] {
        for _ in 0..2 {
            let session = Arc::clone(&session);
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                let (device, connection, key, process) = auth_ids();
                let session_id = sid();
                let ctx = L3AuthContext {
                    sid: &session_id,
                    device_id: &device,
                    connection_id: &connection,
                    sign_key: &key,
                    process: &process,
                    lang: "en-US",
                    domain: None,
                };
                let flow = flow_of(&tcp_packet(src_port, 443, b""));
                barrier.wait().await;
                session
                    .authorize_flow(&ctx, "app-1", "group-1", &flow)
                    .await
            }));
        }
    }
    barrier.wait().await;
    for handle in handles {
        assert_eq!(
            handle.await.expect("task").expect("authorized"),
            "tok-batch"
        );
    }
    assert_eq!(stats.auth_requests(), 2);
    assert_eq!(session.conntrack_len(), 2);
    assert_eq!(
        session.flow_auth_stats(),
        FlowAuthStats {
            requests_sent: 2,
            outcomes_received: 2,
            timeouts: 0,
            in_flight: 0,
            peak_in_flight: 2,
            ..FlowAuthStats::default()
        }
    );
}

#[tokio::test]
async fn denied_flow_reports_the_server_message() {
    let (session, _stats, _peer) = session_with(
        AuthBehaviour::Deny {
            code: 403,
            message: "resource not permitted".to_owned(),
        },
        IDLE_HEARTBEAT,
    )
    .await;

    let (device, connection, key, process) = auth_ids();
    let session_id = sid();
    let ctx = L3AuthContext {
        sid: &session_id,
        device_id: &device,
        connection_id: &connection,
        sign_key: &key,
        process: &process,
        lang: "en-US",
        domain: None,
    };
    let flow = flow_of(&tcp_packet(40000, 443, b""));

    let error = session
        .authorize_flow(&ctx, "app-1", "group-1", &flow)
        .await
        .expect_err("server denied the flow");
    let text = error.to_string();
    assert!(text.contains("403"), "{text}");
    assert!(text.contains("resource not permitted"), "{text}");
}

#[tokio::test]
async fn peer_disconnect_wakes_the_waiter_without_waiting_for_the_timeout() {
    let (session, _stats, _peer) = session_with(AuthBehaviour::Disconnect, IDLE_HEARTBEAT).await;

    let (device, connection, key, process) = auth_ids();
    let session_id = sid();
    let ctx = L3AuthContext {
        sid: &session_id,
        device_id: &device,
        connection_id: &connection,
        sign_key: &key,
        process: &process,
        lang: "en-US",
        domain: None,
    };
    let flow = flow_of(&tcp_packet(40000, 443, b""));

    // The 8s auth timeout must not be what ends this call.
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        session.authorize_flow(&ctx, "app-1", "group-1", &flow),
    )
    .await
    .expect("waiter is woken by the disconnect, not by its own timeout")
    .expect_err("no token on a dead connection");
    assert!(matches!(error, L3SessionError::Closed), "{error}");
    assert!(session.is_closed());
    let close = session.close_info().expect("peer closure is retained");
    assert_eq!(close.reason, L3CloseReason::PeerEof);
    assert!(close.detail.contains("closed by peer"));
}

/// A peer that accepts `0x13` and never answers must not wedge the flow: the
/// caller times out after 8s, the entry is evicted, and a retry re-sends.
#[tokio::test(start_paused = true)]
async fn unanswered_auth_times_out_and_frees_the_flow_for_one_retry() {
    let (session, stats, _peer) = session_with(AuthBehaviour::Ignore, IDLE_HEARTBEAT).await;

    let (device, connection, key, process) = auth_ids();
    let session_id = sid();
    let ctx = L3AuthContext {
        sid: &session_id,
        device_id: &device,
        connection_id: &connection,
        sign_key: &key,
        process: &process,
        lang: "en-US",
        domain: None,
    };
    let flow = flow_of(&tcp_packet(40000, 443, b""));

    let error = session
        .authorize_flow(&ctx, "app-1", "group-1", &flow)
        .await
        .expect_err("peer never answered");
    assert!(
        matches!(error, L3SessionError::AuthTimeout { .. }),
        "{error}"
    );
    assert_eq!(stats.auth_requests(), 1);
    assert!(!session.is_closed(), "a flow timeout is not a dead session");

    // Evicted, so the retry authorizes from scratch instead of returning the
    // cached failure or waiting on a waiter that no longer exists.
    let error = session
        .authorize_flow(&ctx, "app-1", "group-1", &flow)
        .await
        .expect_err("still unanswered");
    assert!(
        matches!(error, L3SessionError::AuthTimeout { .. }),
        "{error}"
    );
    assert_eq!(stats.auth_requests(), 2, "retry must reach the wire");
}

#[tokio::test]
async fn heartbeats_are_emitted_on_the_configured_interval() {
    let (session, stats, _peer) = session_with(
        AuthBehaviour::Grant {
            token: "tok".to_owned(),
        },
        Duration::from_millis(60),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(260)).await;
    let beats = stats.heartbeats();
    assert!(beats >= 2, "expected repeated heartbeats, saw {beats}");
    let heartbeat = session.heartbeat_stats();
    assert!(heartbeat.requests_sent >= 2, "{heartbeat:?}");
    assert!(heartbeat.acknowledgements_received >= 2, "{heartbeat:?}");
    assert!(
        heartbeat.requests_sent >= heartbeat.acknowledgements_received,
        "{heartbeat:?}"
    );
    assert!(heartbeat.last_ack_at.is_some(), "{heartbeat:?}");
    assert!(heartbeat.last_ack_age.is_some(), "{heartbeat:?}");
    assert!(!session.is_closed());
}

#[tokio::test]
async fn caller_close_records_the_first_close_reason() {
    let (session, _stats, peer) = session_with(
        AuthBehaviour::Grant {
            token: "tok".to_owned(),
        },
        IDLE_HEARTBEAT,
    )
    .await;

    session.close().await;
    let close = session.close_info().expect("caller closure is retained");
    assert_eq!(close.reason, L3CloseReason::Caller);
    assert!(close.detail.contains("caller"));
    let _ = peer.await;
}

#[tokio::test]
async fn token_framed_data_response_is_delivered() {
    // Exercises the 0x94 token branch, which the reference server does not emit
    // but the compatibility fixture accepts.
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(async move {
        let mut prefix = [0u8; 7];
        server.read_exact(&mut prefix).await.expect("init prefix");
        let json_len = u16::from_be_bytes([prefix[5], prefix[6]]) as usize;
        let mut json = vec![0; json_len];
        server.read_exact(&mut json).await.expect("SID JSON");
        let mut address_request = [0u8; 10];
        server
            .read_exact(&mut address_request)
            .await
            .expect("address request");
        // Real VIP frame: `05 00 <reserved> <addrType=1>` then a SIX byte body
        // whose first four are the IPv4. The
        // two trailing bytes are what an 8-byte reader would leave on the wire.
        server
            .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 7, 0xde, 0xad])
            .await
            .expect("vip");

        // tokenLen=0x20 makes the leading u16 exceed 4096 → token branch.
        let mut frame = vec![0x05, 0x94, 0x20];
        frame.extend(std::iter::repeat_n(b'x', 32));
        frame.extend_from_slice(&[0x00, 0x00, 2]);
        frame.extend_from_slice(&[0x00, 0x02, 0xaa, 0xbb]);
        frame.extend_from_slice(&[0x00, 0x03, 0x01, 0x02, 0x03]);
        server.write_all(&frame).await.expect("token-framed data");
        // Hold the connection open so EOF does not race the assertions.
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let session = L3Session::start(client, &sid(), IDLE_HEARTBEAT, GET_IP_TIMEOUT, None, None)
        .await
        .expect("session establishes");

    assert_eq!(
        session.recv_packet().await.expect("first"),
        vec![0xaa, 0xbb]
    );
    assert_eq!(
        session.recv_packet().await.expect("second"),
        vec![0x01, 0x02, 0x03]
    );
    peer.abort();
}

#[tokio::test]
async fn v2_peer_write_plans_keep_data_heartbeat_and_packet_order_aligned() {
    let packet_a = tcp_packet(40000, 443, b"a");
    let packet_b = tcp_packet(40001, 443, b"b");
    let mut frames = vec![0x05, 0x42, 0, 3, b'a', b'b', b'c'];
    frames.extend_from_slice(&[0x53, 0, 0, 2, b'O', b'K']);
    frames.extend_from_slice(&[0x05, 0x95, 0, 0]);
    frames.extend_from_slice(&v2_data_response(&packet_a));
    frames.extend_from_slice(&v2_data_response(&packet_b));

    for plan in [
        PeerWritePlan::Whole,
        PeerWritePlan::OneByte,
        PeerWritePlan::Cuts(vec![2, 7, 13]),
        PeerWritePlan::Coalesced,
    ] {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = spawn_v2_plan_peer(server, plan, frames.clone());
        let session = L3Session::start(client, &sid(), IDLE_HEARTBEAT, GET_IP_TIMEOUT, None, None)
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), session.recv_packet())
                .await
                .unwrap()
                .unwrap(),
            packet_a
        );
        assert_eq!(session.recv_packet().await.unwrap(), packet_b);
        let (protocols, bodies) = session.protocol_messages();
        assert_eq!(protocols, 1);
        assert_eq!(bodies, vec!["OK"]);
        assert_eq!(session.heartbeat_stats().acknowledgements_received, 1);
        session.close().await;
        peer.abort();
    }
}

#[tokio::test]
async fn v2_vip_update_clears_flow_state_and_unknown_protocol_do_not_desync() {
    let update = br#"{"vip":"10.0.0.2"}"#;
    let mut frames = vec![0x05, 0x97, 0, 0, update.len() as u8];
    frames.extend_from_slice(update);
    frames.extend_from_slice(&[0x05, 0x95, 0, 0]);
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer = spawn_v2_plan_peer(server, PeerWritePlan::Coalesced, frames);
    let session = L3Session::start(client, &sid(), IDLE_HEARTBEAT, GET_IP_TIMEOUT, None, None)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if session.vip() == Ipv4Addr::new(10, 0, 0, 2) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(session.conntrack_len(), 0);
    assert_eq!(session.heartbeat_stats().acknowledgements_received, 1);
    session.close().await;
    peer.abort();
}

#[tokio::test]
async fn v2_foreign_version_fails_closed_without_packets() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer = spawn_v2_plan_peer(server, PeerWritePlan::Whole, vec![0x06, 0x95, 0, 0]);
    let session = L3Session::start(client, &sid(), IDLE_HEARTBEAT, GET_IP_TIMEOUT, None, None)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !session.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        session.close_info().unwrap().reason,
        L3CloseReason::FramingError
    );
    assert!(session.recv_packet().await.is_none());
    peer.abort();
}

async fn stalled_write_session() -> (Arc<L3Session>, DuplexStream) {
    stalled_write_session_with_heartbeat(IDLE_HEARTBEAT).await
}

async fn stalled_write_session_with_heartbeat(
    heartbeat: Duration,
) -> (Arc<L3Session>, DuplexStream) {
    let (client, mut peer) = tokio::io::duplex(128);
    let handshake = tokio::spawn(async move {
        read_get_ip(&mut peer).await;
        peer.write_all(&[5, 0, 0, 1, 10, 8, 0, 7, 0, 0])
            .await
            .unwrap();
        peer
    });
    let session = L3Session::start(client, &sid(), heartbeat, GET_IP_TIMEOUT, None, None)
        .await
        .unwrap();
    (Arc::new(session), handshake.await.unwrap())
}

#[tokio::test]
async fn close_interrupts_a_blocked_write_and_wakes_senders() {
    let (session, _peer) = stalled_write_session().await;
    let sender_session = Arc::clone(&session);
    let sender = tokio::spawn(async move {
        sender_session
            .send_packet(&"t".repeat(32), &tcp_packet(40000, 443, &[0; 4000]))
            .await
    });
    tokio::task::yield_now().await;
    assert!(!sender.is_finished());
    tokio::time::timeout(Duration::from_millis(200), session.close())
        .await
        .unwrap();
    assert!(matches!(sender.await.unwrap(), Err(L3SessionError::Closed)));
    assert_eq!(session.close_info().unwrap().reason, L3CloseReason::Caller);
}

#[tokio::test(start_paused = true)]
async fn stalled_write_deadline_closes_the_session() {
    let (session, _peer) = stalled_write_session().await;
    let result = session
        .send_packet(&"t".repeat(32), &tcp_packet(40000, 443, &[0; 4000]))
        .await;
    assert!(matches!(result, Err(L3SessionError::Closed)));
    assert_eq!(
        session.close_info().unwrap().reason,
        L3CloseReason::WriteTimeout
    );
    session.close().await;
}

#[tokio::test(start_paused = true)]
async fn unanswered_heartbeats_close_the_session() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let drain = tokio::spawn(async move {
        read_get_ip(&mut peer).await;
        peer.write_all(&[5, 0, 0, 1, 10, 8, 0, 7, 0, 0])
            .await
            .unwrap();
        let mut heartbeat = [0; 4];
        while peer.read_exact(&mut heartbeat).await.is_ok() {}
    });
    let session = L3Session::start(
        client,
        &sid(),
        Duration::from_secs(25),
        GET_IP_TIMEOUT,
        None,
        None,
    )
    .await
    .unwrap();
    for _ in 0..5 {
        tokio::time::advance(Duration::from_secs(25)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }
    assert!(session.is_closed());
    assert_eq!(
        session.close_info().unwrap().reason,
        L3CloseReason::HeartbeatTimeout
    );
    assert_eq!(session.heartbeat_stats().acknowledgements_received, 0);
    session.close().await;
    drain.await.unwrap();
}

#[tokio::test]
async fn changed_app_for_the_same_flow_reauthorizes_on_the_wire() {
    let (session, stats, _peer) = session_with(
        AuthBehaviour::Grant {
            token: "t".repeat(32),
        },
        IDLE_HEARTBEAT,
    )
    .await;
    let (device, connection, key, process) = auth_ids();
    let session_id = sid();
    let ctx = L3AuthContext {
        sid: &session_id,
        device_id: &device,
        connection_id: &connection,
        sign_key: &key,
        process: &process,
        lang: "en-US",
        domain: None,
    };
    let flow = flow_of(&tcp_packet(40000, 443, b""));
    for app in ["old-app", "old-app", "new-app", "new-app"] {
        session
            .authorize_flow(&ctx, app, "group", &flow)
            .await
            .unwrap();
    }
    assert_eq!(stats.auth_requests(), 2);
    assert_eq!(session.conntrack_len(), 1);
    session.close().await;
}

#[tokio::test]
async fn flow_receivers_demultiplex_replies_and_close_with_the_session() {
    let (session, mut peer) = stalled_write_session().await;
    let packet = tcp_packet(40000, 443, b"");
    let flow = flow_of(&packet);
    let mut replies = session.subscribe_flow(&flow).unwrap();
    assert!(matches!(
        session.subscribe_flow(&flow),
        Err(L3SessionError::FlowAlreadySubscribed)
    ));
    let mut reply = packet.clone();
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    reply[20..22].copy_from_slice(&packet[22..24]);
    reply[22..24].copy_from_slice(&packet[20..22]);
    peer.write_all(&v2_data_response(&reply)).await.unwrap();
    assert_eq!(replies.recv().await.unwrap(), reply);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), session.recv_packet())
            .await
            .is_err()
    );
    drop(replies);
    let mut replies = session.subscribe_flow(&flow).unwrap();
    session.close().await;
    assert!(replies.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn queued_but_unwritten_probes_do_not_count_as_missed_acknowledgements() {
    let (session, _peer) = stalled_write_session_with_heartbeat(Duration::from_secs(1)).await;
    let sending = session.clone();
    let send = tokio::spawn(async move {
        sending
            .send_packet(&"t".repeat(32), &tcp_packet(40000, 443, &[0; 4000]))
            .await
    });
    tokio::task::yield_now().await;
    for _ in 0..5 {
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(session.heartbeat_stats().requests_sent, 0);
    assert!(!session.is_closed(), "probes have not reached the peer yet");
    session.close().await;
    assert!(matches!(send.await.unwrap(), Err(L3SessionError::Closed)));
}

#[tokio::test]
async fn resource_change_during_auth_does_not_look_like_a_disconnected_tunnel() {
    let (session, stats, _peer) = session_with(
        AuthBehaviour::BatchGrant {
            token: "t".repeat(32),
            batch_size: 2,
        },
        IDLE_HEARTBEAT,
    )
    .await;
    let session = Arc::new(session);
    let authorize = |session: Arc<L3Session>, app: &'static str| async move {
        let (device, connection, key, process) = auth_ids();
        let sid = sid();
        let ctx = L3AuthContext {
            sid: &sid,
            device_id: &device,
            connection_id: &connection,
            sign_key: &key,
            process: &process,
            lang: "en-US",
            domain: None,
        };
        session
            .authorize_flow(&ctx, app, "group", &flow_of(&tcp_packet(40000, 443, b"")))
            .await
    };
    let old = tokio::spawn(authorize(session.clone(), "old-app"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while stats.auth_requests() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    authorize(session.clone(), "new-app").await.unwrap();
    assert!(
        matches!(old.await.unwrap(),Err(L3SessionError::FlowAuth(atrust_l3::FlowAuthError::AuthFailed(message))) if message.contains("resource changed"))
    );
    assert!(!session.is_closed());
    authorize(session.clone(), "new-app").await.unwrap();
    assert_eq!(stats.auth_requests(), 2);
    session.close().await;
}
