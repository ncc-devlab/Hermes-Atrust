//! Full-duplex L3 session over one long-lived TLS connection.
//!
//! One session owns one node connection and drives three concurrent tasks:
//!
//! - a **writer** task serialising every outbound frame onto the TLS stream;
//! - a **reader** task splitting the inbound byte stream into frames and
//!   dispatching `0x93` (auth), `0x94` (data), `0x95` (heartbeat ack) and
//!   `0x96` (second VIP);
//! - a **heartbeat** task emitting `05 15 00 00` every 25 seconds.
//!
//! The session is established by the same SID-only exchange as a standalone
//! Get-IP (`05 01 D0` / `53 00` / `05 04 ...`), except the connection is kept
//! open afterwards and reused for auth and data.
//!
//! # Scope
//!
//! This is the protocol driver only. It does **not** own a TUN device, a DNS
//! resolver, routes, or a node-group connection cache; packets go in and out as
//! raw IPv4 bytes so a failure stays inside the protocol, not the kernel routing
//! table. Reconnect-on-drop also belongs to the (absent) node-group cache: when
//! this connection dies, the session reports closed and every waiter is woken.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atrust_protocol::{
    DataRespPackets, L3_VERSION, L3FrameError, decode_l3_data_resp_body, encode_l3_data_req,
    encode_l3_heartbeat_req, l3_cmd,
};
use hermes_model::SessionId;
use hermes_transport::{TlsConnectError, TlsPolicy, connect_tls};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::auth::{FlowAuthError, L3AuthContext, apply_auth_wire_status, build_flow_auth_frame};
use crate::conntrack::{AuthOutcome, ConntrackTable, FlowKey, L3_AUTH_TIMEOUT};
use crate::get_ip::{GetIpv4Error, GetIpv4Response, request_ipv4};
use crate::packet::Ipv4Flow;

/// Heartbeat cadence for one L3 connection (Go: every 25 seconds).
pub const L3_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);

/// Second-VIP response command (`05 96 <status> <u16 len> <json>`).
const L3_SECOND_VIP_RESP: u8 = 0x96;

/// Cap on unparsed inbound bytes. A peer that never completes a frame cannot
/// make the reader buffer without bound.
const MAX_PENDING_READ: usize = 1024 * 1024;

/// Shortest `connectToken` for which the `0x94` layout discriminant is safe.
///
/// A token-framed body opens with `tokenLen` followed by the token, so its
/// leading `u16-be` is `tokenLen * 256 + token[0]`. The length-prefixed branch
/// claims `(0, 4096]`, which a token of 15 bytes or fewer always lands inside.
/// The gateway never declares this invariant; see `docs/open-questions.md` A1.
const MIN_UNAMBIGUOUS_CONNECT_TOKEN: usize = 17;

const READ_CHUNK: usize = 16 * 1024;
const WRITE_QUEUE_DEPTH: usize = 64;
const PACKET_QUEUE_DEPTH: usize = 256;

/// Inputs for establishing one L3 session against a data-plane node.
#[derive(Clone, Debug)]
pub struct L3SessionConfig<'a> {
    pub node_host: &'a str,
    pub node_port: u16,
    pub tls_policy: TlsPolicy,
    pub sid: &'a SessionId,
    /// Budget for TCP + TLS + the Get-IP exchange.
    ///
    /// Live TLS connect alone has been measured at ~6.3s on the Xidian link, so
    /// a budget near the 8s auth timeout will misreport a slow link as an auth
    /// failure. Default to something comfortably above the measured connect.
    pub connect_timeout: Duration,
    pub heartbeat_interval: Duration,
}

/// State shared between the caller and the session tasks.
#[derive(Debug)]
struct SessionShared {
    conntrack: Mutex<ConntrackTable>,
    /// Callers awaiting a `0x93` for a given auth id. A flow can have more than
    /// one waiter when several packets race into the same unauthorized flow.
    waiters: Mutex<HashMap<u64, Vec<oneshot::Sender<AuthOutcome>>>>,
    closed: AtomicBool,
    /// Broadcast stop signal. Every task selects on it, so closing a session
    /// does not have to wait for a task's own timer to fire.
    stop_tx: watch::Sender<bool>,
}

impl SessionShared {
    fn new() -> Self {
        Self {
            conntrack: Mutex::new(ConntrackTable::new()),
            waiters: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            stop_tx: watch::channel(false).0,
        }
    }

    fn stop_signal(&self) -> watch::Receiver<bool> {
        self.stop_tx.subscribe()
    }

    fn notify(&self, auth_id: u64, outcome: &AuthOutcome) {
        let senders = self
            .waiters
            .lock()
            .expect("waiters mutex")
            .remove(&auth_id)
            .unwrap_or_default();
        for sender in senders {
            // A waiter that timed out and went away is not an error.
            let _ = sender.send(outcome.clone());
        }
    }

    /// Marks the session dead, stops every task, and wakes every waiter so no
    /// caller blocks for the full 8s auth timeout on a connection already gone.
    ///
    /// Waiters are woken by *dropping* their sender rather than by sending a
    /// synthetic `Failed`: "the connection died" and "the server denied this
    /// flow" are different outcomes, and only the latter should look like a
    /// policy decision to the caller.
    fn shutdown(&self, reason: &str) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.stop_tx.send(true);
        let drained: Vec<_> = self
            .waiters
            .lock()
            .expect("waiters mutex")
            .drain()
            .collect();
        drop(drained);
        debug!(event = "atrust_l3.session.shutdown", reason);
    }
}

/// A live L3 session: virtual IP assigned, read loop and heartbeat running.
///
/// Every method takes `&self`, so the session can sit in an `Arc` and be driven
/// from several tasks at once.
#[derive(Debug)]
pub struct L3Session {
    get_ip: GetIpv4Response,
    shared: Arc<SessionShared>,
    write_tx: mpsc::Sender<Vec<u8>>,
    packets: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl L3Session {
    /// Connects to a node, performs Get-IP, and starts the session on that
    /// same connection.
    pub async fn establish(config: L3SessionConfig<'_>) -> Result<Self, L3SessionError> {
        let stream = timeout(
            config.connect_timeout,
            connect_tls(config.node_host, config.node_port, config.tls_policy),
        )
        .await
        .map_err(|_| L3SessionError::ConnectTimeout)??;
        Self::start(
            stream,
            config.sid,
            config.heartbeat_interval,
            config.connect_timeout,
        )
        .await
    }

    /// Starts a session on an already-connected stream.
    ///
    /// Exposed so the whole driver can be exercised against an in-memory duplex
    /// peer with no TLS and no gateway.
    pub async fn start<S>(
        mut stream: S,
        sid: &SessionId,
        heartbeat_interval: Duration,
        get_ip_timeout: Duration,
    ) -> Result<Self, L3SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let get_ip = timeout(get_ip_timeout, request_ipv4(&mut stream, sid))
            .await
            .map_err(|_| GetIpv4Error::Timeout)??;
        debug!(
            event = "atrust_l3.session.get_ip",
            vip = %get_ip.address,
            status_bodies = get_ip.status_bodies.len()
        );

        let shared = Arc::new(SessionShared::new());
        let (read_half, mut write_half) = tokio::io::split(stream);
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE_DEPTH);
        let (packets_tx, packets_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_DEPTH);

        let writer_shared = Arc::clone(&shared);
        let mut writer_stop = shared.stop_signal();
        let writer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Biased so a pending close is honoured before more frames
                    // are pushed onto a stream the caller has finished with.
                    biased;
                    _ = writer_stop.changed() => break,
                    frame = write_rx.recv() => {
                        let Some(frame) = frame else { break };
                        if let Err(error) = write_half.write_all(&frame).await {
                            warn!(event = "atrust_l3.session.write_failed", %error);
                            writer_shared.shutdown("L3 connection write failed");
                            break;
                        }
                        if let Err(error) = write_half.flush().await {
                            warn!(event = "atrust_l3.session.flush_failed", %error);
                            writer_shared.shutdown("L3 connection flush failed");
                            break;
                        }
                    }
                }
            }
            let _ = write_half.shutdown().await;
            debug!(event = "atrust_l3.session.writer_stopped");
        });

        let reader_shared = Arc::clone(&shared);
        let mut reader_stop = shared.stop_signal();
        let reader = tokio::spawn(async move {
            let reason = tokio::select! {
                reason = read_loop(read_half, &reader_shared, &packets_tx) => reason,
                _ = reader_stop.changed() => "L3 session closed by caller".to_owned(),
            };
            reader_shared.shutdown(&reason);
            debug!(event = "atrust_l3.session.reader_stopped", reason = %reason);
        });

        let heartbeat_tx = write_tx.clone();
        let mut heartbeat_stop = shared.stop_signal();
        let heartbeat = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(heartbeat_interval);
            // The first tick fires immediately; skip it so establishing a
            // session does not put a heartbeat ahead of the caller's first auth.
            ticker.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = heartbeat_stop.changed() => break,
                    _ = ticker.tick() => {
                        if heartbeat_tx.send(encode_l3_heartbeat_req().to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
            debug!(event = "atrust_l3.session.heartbeat_stopped");
        });

        Ok(Self {
            get_ip,
            shared,
            write_tx,
            packets: AsyncMutex::new(packets_rx),
            tasks: Mutex::new(vec![writer, reader, heartbeat]),
        })
    }

    /// Virtual IPv4 assigned by Get-IP.
    #[must_use]
    pub fn vip(&self) -> Ipv4Addr {
        self.get_ip.address
    }

    /// The full Get-IP outcome, including the `53 00` status bodies.
    #[must_use]
    pub fn get_ip(&self) -> &GetIpv4Response {
        &self.get_ip
    }

    /// True once the connection has failed or been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Authorizes one flow and returns its connect token.
    ///
    /// Repeat calls for an already-authorized flow return the cached token
    /// without touching the wire. Concurrent callers for the same flow send one
    /// `0x13` and all wait on the same response.
    ///
    /// On timeout the flow is evicted, so a caller that wants Go's
    /// "retry once, then drop the packet" behaviour calls this a second time.
    pub async fn authorize_flow(
        &self,
        ctx: &L3AuthContext<'_>,
        app_id: &str,
        node_group_id: &str,
        flow: &Ipv4Flow,
    ) -> Result<String, L3SessionError> {
        if self.is_closed() {
            return Err(L3SessionError::Closed);
        }
        let key = flow.flow_key();

        // Phase 1: claim the flow and register a waiter, holding the lock only
        // for bookkeeping — never across an await.
        let (auth_id, must_send, receiver) = {
            let mut table = self.shared.conntrack.lock().expect("conntrack mutex");
            let entry = table.get_or_create(key.clone(), app_id, node_group_id);
            if let Some(outcome) = entry.outcome() {
                return match outcome {
                    AuthOutcome::Ready { connect_token } => Ok(connect_token.clone()),
                    AuthOutcome::Failed { message } => {
                        Err(FlowAuthError::AuthFailed(message.clone()).into())
                    }
                };
            }
            let auth_id = entry.auth_id;
            let must_send = entry.try_start_auth();
            let (sender, receiver) = oneshot::channel();
            self.shared
                .waiters
                .lock()
                .expect("waiters mutex")
                .entry(auth_id)
                .or_default()
                .push(sender);
            (auth_id, must_send, receiver)
        };

        // Phase 2: build and send outside the lock. A build failure must not
        // strand the flow in "auth started" with nothing in flight.
        if must_send {
            let frame = match build_flow_auth_frame(ctx, app_id, auth_id, &flow.to_five_tuple()) {
                Ok(frame) => frame,
                Err(error) => {
                    self.abandon_flow(&key, auth_id);
                    return Err(error.into());
                }
            };
            debug!(
                event = "atrust_l3.session.auth_sent",
                auth_id,
                flow = %key,
                app_id
            );
            if self.write_tx.send(frame).await.is_err() {
                self.abandon_flow(&key, auth_id);
                return Err(L3SessionError::Closed);
            }
        }

        match timeout(L3_AUTH_TIMEOUT, receiver).await {
            Ok(Ok(AuthOutcome::Ready { connect_token })) => Ok(connect_token),
            Ok(Ok(AuthOutcome::Failed { message })) => {
                Err(FlowAuthError::AuthFailed(message).into())
            }
            // The reader task dropped the sender without a verdict.
            Ok(Err(_)) => Err(L3SessionError::Closed),
            Err(_) => {
                self.abandon_flow(&key, auth_id);
                warn!(
                    event = "atrust_l3.session.auth_timeout",
                    auth_id,
                    flow = %key,
                    timeout_seconds = L3_AUTH_TIMEOUT.as_secs()
                );
                Err(L3SessionError::AuthTimeout {
                    flow: key.to_string(),
                })
            }
        }
    }

    /// Drops a flow and its waiters so the next attempt starts clean.
    fn abandon_flow(&self, key: &FlowKey, auth_id: u64) {
        self.shared
            .conntrack
            .lock()
            .expect("conntrack mutex")
            .evict(key);
        self.shared
            .waiters
            .lock()
            .expect("waiters mutex")
            .remove(&auth_id);
    }

    /// Sends one raw IPv4 packet under an authorized flow's connect token.
    pub async fn send_packet(
        &self,
        connect_token: &str,
        packet: &[u8],
    ) -> Result<(), L3SessionError> {
        self.send_packets(connect_token, &[packet]).await
    }

    /// Sends several packets in one `0x14` frame (they share one connect token).
    pub async fn send_packets(
        &self,
        connect_token: &str,
        packets: &[&[u8]],
    ) -> Result<(), L3SessionError> {
        if self.is_closed() {
            return Err(L3SessionError::Closed);
        }
        let frame = encode_l3_data_req(connect_token.as_bytes(), packets)?;
        self.write_tx
            .send(frame)
            .await
            .map_err(|_| L3SessionError::Closed)
    }

    /// Receives the next inbound IPv4 packet, or `None` once the session ends.
    pub async fn recv_packet(&self) -> Option<Vec<u8>> {
        self.packets.lock().await.recv().await
    }

    /// Closes the connection and stops the reader, writer and heartbeat tasks.
    pub async fn close(&self) {
        self.shared.shutdown("L3 session closed by caller");
        let handles: Vec<_> = std::mem::take(&mut *self.tasks.lock().expect("tasks mutex"));
        for handle in handles {
            let _ = handle.await;
        }
        debug!(event = "atrust_l3.session.closed");
    }
}

impl Drop for L3Session {
    fn drop(&mut self) {
        // A dropped session must not leave three tasks holding a live socket.
        self.shared.closed.store(true, Ordering::SeqCst);
        if let Ok(mut tasks) = self.tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
    }
}

/// One decoded downstream frame.
#[derive(Debug, Eq, PartialEq)]
enum Inbound<'a> {
    Auth {
        status: u8,
        json: &'a [u8],
    },
    Data(DataRespPackets<'a>),
    Heartbeat,
    SecondVip {
        status: u8,
        json: &'a [u8],
    },
    /// Nested `53 00` protocol message.
    Protocol,
    /// A known-shaped frame this client has no use for.
    Ignored {
        cmd: u8,
    },
}

/// Splits one frame off the front of `buf`.
///
/// `Ok(None)` means "need more bytes"; the caller must not consume anything.
///
/// Framing follows zju-connect `readFrame`, which is the client proven against
/// the real gateway:
///
/// - `05 93` / `05 96` carry a status byte *before* the length;
/// - `05 94` is the dual-format data body;
/// - every other `05 <cmd>` uses the generic `<u16 len> <payload>` layout;
/// - `53 00 <u16 len> <payload>` protocol messages can appear mid-session and
///   are skipped, not treated as a desync.
///
/// Unknown `05` commands are skipped rather than fatal. An earlier revision
/// errored on them to surface new frames during bring-up, but that trades a
/// logged surprise for a dead session — and the generic layout is exactly what
/// the proven client relies on to stay in sync.
fn next_frame(buf: &[u8]) -> Result<Option<(Inbound<'_>, usize)>, L3SessionError> {
    if buf.len() < 2 {
        return Ok(None);
    }

    /// `<hdr> <u16 len> <payload>` — the generic four-byte-header layout.
    fn length_prefixed(buf: &[u8]) -> Option<usize> {
        if buf.len() < 4 {
            return None;
        }
        let total = 4 + u16::from_be_bytes([buf[2], buf[3]]) as usize;
        (buf.len() >= total).then_some(total)
    }

    /// `05 <cmd> <status> <u16 len> <json>`
    fn status_and_json(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
        if buf.len() < 5 {
            return None;
        }
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total = 5 + len;
        if buf.len() < total {
            return None;
        }
        Some((buf[2], &buf[5..total], total))
    }

    // Nested `53 00` protocol messages are not L3 frames and carry no command.
    if buf[0] == 0x53 {
        if buf[1] != 0 {
            return Err(L3SessionError::ProtocolRejected { status: buf[1] });
        }
        return Ok(length_prefixed(buf).map(|total| (Inbound::Protocol, total)));
    }

    if buf[0] != L3_VERSION {
        return Err(L3SessionError::UnexpectedVersion { byte: buf[0] });
    }

    match buf[1] {
        l3_cmd::AUTH_RESP => Ok(status_and_json(buf)
            .map(|(status, json, total)| (Inbound::Auth { status, json }, total))),
        L3_SECOND_VIP_RESP => Ok(status_and_json(buf)
            .map(|(status, json, total)| (Inbound::SecondVip { status, json }, total))),
        l3_cmd::HEARTBEAT_RESP => Ok(length_prefixed(buf).map(|total| (Inbound::Heartbeat, total))),
        l3_cmd::DATA_RESP => match decode_l3_data_resp_body(&buf[2..]) {
            Ok((packets, body_len)) => Ok(Some((Inbound::Data(packets), 2 + body_len))),
            Err(L3FrameError::Truncated { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        },
        cmd => Ok(length_prefixed(buf).map(|total| (Inbound::Ignored { cmd }, total))),
    }
}

/// Reads and dispatches until the peer goes away. Returns the stop reason.
async fn read_loop<R>(
    mut read_half: R,
    shared: &Arc<SessionShared>,
    packets_tx: &mpsc::Sender<Vec<u8>>,
) -> String
where
    R: AsyncRead + Unpin,
{
    let mut pending: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let mut chunk = vec![0u8; READ_CHUNK];

    loop {
        // Drain every complete frame already buffered before reading again.
        loop {
            let (action, consumed) = match next_frame(&pending) {
                Ok(Some((frame, consumed))) => (dispatch(frame, shared, packets_tx), consumed),
                Ok(None) => break,
                Err(error) => return format!("L3 framing error: {error}"),
            };
            pending.drain(..consumed);
            match action {
                Dispatch::Continue => {}
                Dispatch::Send(packet) => {
                    if packets_tx.send(packet).await.is_err() {
                        return "L3 packet consumer dropped".to_owned();
                    }
                }
                Dispatch::SendMany(packets) => {
                    for packet in packets {
                        if packets_tx.send(packet).await.is_err() {
                            return "L3 packet consumer dropped".to_owned();
                        }
                    }
                }
            }
        }

        if pending.len() > MAX_PENDING_READ {
            return format!("L3 inbound buffer exceeded {MAX_PENDING_READ} bytes");
        }

        match read_half.read(&mut chunk).await {
            Ok(0) => return "L3 connection closed by peer".to_owned(),
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(error) => return format!("L3 connection read failed: {error}"),
        }
    }
}

/// What the read loop must do after a frame is decoded.
///
/// Packets are handed back rather than sent inline so the borrow on the read
/// buffer ends before the loop awaits on the packet channel.
enum Dispatch {
    Continue,
    Send(Vec<u8>),
    SendMany(Vec<Vec<u8>>),
}

fn dispatch(
    frame: Inbound<'_>,
    shared: &Arc<SessionShared>,
    _packets_tx: &mpsc::Sender<Vec<u8>>,
) -> Dispatch {
    match frame {
        Inbound::Auth { status, json } => {
            let mut table = shared.conntrack.lock().expect("conntrack mutex");
            match apply_auth_wire_status(&mut table, status, json) {
                Ok(auth_id) => {
                    let outcome = table
                        .get_by_auth_id(auth_id)
                        .and_then(|entry| entry.outcome())
                        .cloned();
                    drop(table);
                    if let Some(outcome) = outcome {
                        debug!(
                            event = "atrust_l3.session.auth_settled",
                            auth_id,
                            ready = outcome.connect_token().is_some(),
                            connect_token_len = outcome.connect_token().map_or(0, str::len)
                        );
                        // The `0x94` token-framed branch is only distinguishable
                        // from the length-prefixed one because `tokenLen` is large
                        // enough to push the leading u16 past 4096. A short token
                        // makes the discriminant misfire and desynchronizes the
                        // stream far from here, so it is reported at the one point
                        // where the length is known.
                        if let Some(token) = outcome.connect_token()
                            && token.len() < MIN_UNAMBIGUOUS_CONNECT_TOKEN
                        {
                            warn!(
                                event = "atrust_l3.session.connect_token_ambiguous",
                                connect_token_len = token.len(),
                                minimum = MIN_UNAMBIGUOUS_CONNECT_TOKEN
                            );
                        }
                        shared.notify(auth_id, &outcome);
                    }
                }
                Err(error) => {
                    // An unattributable response (bad JSON, unknown id, or a
                    // late reply for an evicted flow) cannot wake a waiter; the
                    // waiter falls through to its own timeout.
                    warn!(event = "atrust_l3.session.auth_unattributable", %error, status);
                }
            }
            Dispatch::Continue
        }
        // Which branch the gateway actually uses is unconfirmed against the real
        // gateway, and the two are told apart only by a numeric threshold, so the
        // choice is recorded on every frame rather than inferred after a failure.
        Inbound::Data(packets) => match packets {
            DataRespPackets::LengthPrefixed(packet) => {
                debug!(
                    event = "atrust_l3.session.data_resp",
                    layout = "length_prefixed",
                    packets = 1,
                    bytes = packet.len()
                );
                Dispatch::Send(packet.to_vec())
            }
            DataRespPackets::TokenFramed(packets) => {
                debug!(
                    event = "atrust_l3.session.data_resp",
                    layout = "token_framed",
                    packets = packets.len(),
                    bytes = packets.iter().map(|packet| packet.len()).sum::<usize>()
                );
                Dispatch::SendMany(packets.into_iter().map(<[u8]>::to_vec).collect())
            }
        },
        Inbound::Heartbeat => {
            debug!(event = "atrust_l3.session.heartbeat_ack");
            Dispatch::Continue
        }
        Inbound::SecondVip { status, json } => {
            // Not requested by this milestone; recorded because the body is one
            // of the few places a second VIP could be observed live.
            debug!(
                event = "atrust_l3.session.second_vip_resp",
                status,
                body = %String::from_utf8_lossy(json)
            );
            Dispatch::Continue
        }
        Inbound::Protocol => {
            debug!(event = "atrust_l3.session.protocol_message");
            Dispatch::Continue
        }
        Inbound::Ignored { cmd } => {
            // Warn, not debug: an unrecognised frame from the real gateway is a
            // finding, even though skipping it keeps the session alive.
            warn!(event = "atrust_l3.session.ignored_command", cmd);
            Dispatch::Continue
        }
    }
}

#[derive(Debug, Error)]
pub enum L3SessionError {
    #[error("TLS connection failed: {0}")]
    Tls(#[from] TlsConnectError),
    #[error("timed out connecting to the L3 node")]
    ConnectTimeout,
    #[error(transparent)]
    GetIp(#[from] GetIpv4Error),
    #[error(transparent)]
    Frame(#[from] L3FrameError),
    #[error(transparent)]
    FlowAuth(#[from] FlowAuthError),
    #[error("L3 flow auth timed out after {} seconds: {flow}", L3_AUTH_TIMEOUT.as_secs())]
    AuthTimeout { flow: String },
    #[error("L3 session is closed")]
    Closed,
    #[error("unexpected L3 version byte {byte:#04x}")]
    UnexpectedVersion { byte: u8 },
    #[error("L3 protocol message rejected with status {status:#04x}")]
    ProtocolRejected { status: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_frame_needs_a_complete_auth_response() {
        let json = br#"{"code":0}"#;
        let mut frame = vec![L3_VERSION, l3_cmd::AUTH_RESP, 0x00];
        frame.extend_from_slice(&(json.len() as u16).to_be_bytes());
        frame.extend_from_slice(json);

        for partial in 0..frame.len() {
            assert_eq!(next_frame(&frame[..partial]).unwrap(), None, "at {partial}");
        }
        let (decoded, consumed) = next_frame(&frame).unwrap().unwrap();
        assert_eq!(consumed, frame.len());
        assert_eq!(
            decoded,
            Inbound::Auth {
                status: 0,
                json: json.as_slice()
            }
        );
    }

    #[test]
    fn next_frame_reads_heartbeat_and_data_back_to_back() {
        // The 0x93 status byte sits where 0x95 keeps its length: decoding both
        // from one buffer proves the per-command headers do not desync.
        let mut buf = vec![L3_VERSION, l3_cmd::HEARTBEAT_RESP, 0x00, 0x00];
        buf.extend_from_slice(&[L3_VERSION, l3_cmd::DATA_RESP, 0x00, 0x03, 1, 2, 3]);

        let (first, consumed) = next_frame(&buf).unwrap().unwrap();
        assert_eq!(first, Inbound::Heartbeat);
        assert_eq!(consumed, 4);

        let (second, consumed) = next_frame(&buf[consumed..]).unwrap().unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(
            second,
            Inbound::Data(DataRespPackets::LengthPrefixed(&[1, 2, 3]))
        );
    }

    #[test]
    fn next_frame_rejects_a_foreign_version_byte() {
        assert!(matches!(
            next_frame(&[0x06, 0x94, 0x00, 0x01, 0xff]),
            Err(L3SessionError::UnexpectedVersion { byte: 0x06 })
        ));
    }

    /// zju-connect `readFrame` skips unknown `05` commands using the generic
    /// `<u16 len>` layout and keeps the session alive; so must Hermes.
    #[test]
    fn next_frame_skips_unknown_commands_generically() {
        let mut buf = vec![L3_VERSION, 0x42, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        buf.extend_from_slice(&[L3_VERSION, l3_cmd::HEARTBEAT_RESP, 0x00, 0x00]);

        let (decoded, consumed) = next_frame(&buf).unwrap().unwrap();
        assert_eq!(decoded, Inbound::Ignored { cmd: 0x42 });
        assert_eq!(consumed, 7);
        // The stream is still aligned for the next real frame.
        assert_eq!(
            next_frame(&buf[consumed..]).unwrap().unwrap().0,
            Inbound::Heartbeat
        );
    }

    /// `53 00` protocol messages appear mid-session, not only during Get-IP.
    /// Treating one as a version desync would kill an otherwise healthy tunnel.
    #[test]
    fn next_frame_skips_nested_protocol_messages() {
        let mut buf = vec![0x53, 0x00, 0x00, 0x02, b'O', b'K'];
        buf.extend_from_slice(&[L3_VERSION, l3_cmd::DATA_RESP, 0x00, 0x02, 0x01, 0x02]);

        let (decoded, consumed) = next_frame(&buf).unwrap().unwrap();
        assert_eq!(decoded, Inbound::Protocol);
        assert_eq!(consumed, 6);
        assert_eq!(
            next_frame(&buf[consumed..]).unwrap().unwrap().0,
            Inbound::Data(DataRespPackets::LengthPrefixed(&[0x01, 0x02]))
        );

        assert!(matches!(
            next_frame(&[0x53, 0x07, 0x00, 0x00]),
            Err(L3SessionError::ProtocolRejected { status: 0x07 })
        ));
    }

    #[test]
    fn next_frame_decodes_token_framed_data() {
        // tokenLen=0x20 forces the token branch (first u16 = 0x2078 > 4096).
        let mut body = vec![0x20];
        body.extend(std::iter::repeat_n(b'x', 32));
        body.extend_from_slice(&[0x00, 0x00, 1, 0x00, 0x02, 0xab, 0xcd]);
        let mut frame = vec![L3_VERSION, l3_cmd::DATA_RESP];
        frame.extend_from_slice(&body);

        let (decoded, consumed) = next_frame(&frame).unwrap().unwrap();
        assert_eq!(consumed, frame.len());
        assert_eq!(
            decoded,
            Inbound::Data(DataRespPackets::TokenFramed(vec![&[0xab, 0xcd][..]]))
        );
    }
}
