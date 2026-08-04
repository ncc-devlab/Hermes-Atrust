//! End-to-end L3 session tests against an in-memory mock peer.
//!
//! The peer speaks the same frames as the reference server
//! (`Hermes-aTrust-Server::hermes-tunnel::l3`): Get-IP handshake, `0x93` for
//! `0x13`, length-prefixed `0x94` echoes for `0x14`, and `05 95 00 00` for
//! heartbeats. No TLS and no gateway are involved.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use atrust_l3::{Ipv4Flow, L3AuthContext, L3Session, L3SessionError, parse_ipv4_flow};
use atrust_protocol::ProcessIdentity;
use hermes_model::{ConnectionId, DeviceId, SessionId, SignKey};
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::task::JoinHandle;

const GET_IP_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_HEARTBEAT: Duration = Duration::from_secs(3600);

/// How the mock peer should answer a `0x13`.
#[derive(Clone, Debug)]
enum AuthBehaviour {
    Grant {
        token: String,
    },
    Deny {
        code: i64,
        message: String,
    },
    /// Accept the request and never answer, to exercise the caller's timeout.
    Ignore,
    /// Drop the connection instead of answering.
    Disconnect,
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
        // whose first four are the IPv4 (zju-connect `vipPayloadLength`). The
        // two trailing bytes are what an 8-byte reader would leave on the wire.
        server
            .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 7, 0xde, 0xad])
            .await
            .expect("vip");

        let mut pending: Vec<u8> = Vec::new();
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
    let session = L3Session::start(client, &sid(), heartbeat, GET_IP_TIMEOUT, None)
        .await
        .expect("session establishes");
    (session, stats, peer)
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
    assert!(!session.is_closed());
}

#[tokio::test]
async fn token_framed_data_response_is_delivered() {
    // Exercises the 0x94 token branch, which the reference server does not emit
    // but the Go client accepts.
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
        // whose first four are the IPv4 (zju-connect `vipPayloadLength`). The
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

    let session = L3Session::start(client, &sid(), IDLE_HEARTBEAT, GET_IP_TIMEOUT, None)
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
