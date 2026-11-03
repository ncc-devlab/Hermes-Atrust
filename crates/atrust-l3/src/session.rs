//! Full-duplex L3 session over one long-lived TLS connection.
//!
//! One session owns one node connection and drives three concurrent tasks:
//!
//! - a **writer** task serialising every outbound frame onto the TLS stream;
//! - a **reader** task splitting the inbound byte stream into frames and
//!   dispatching `0x93` (auth), `0x94` (data), `0x95` (heartbeat ack) and
//!   `0x96` (second VIP) and `0x97` (asynchronous VIP update);
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
//! table. Reconnect-on-drop belongs to [`crate::L3SessionManager`]: when this
//! connection dies, the session reports closed and every waiter is woken.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use atrust_protocol::{
    DataRespPackets, L3_VERSION, L3FrameError, decode_l3_data_resp_body, encode_l3_data_req,
    encode_l3_heartbeat_req, l3_cmd,
};
use hermes_events::{EventBus, HermesEvent, L3DataLayout, OptionalEventBus as _};
use hermes_model::SessionId;
use hermes_transport::{
    SystemUnderlay, TlsConnectError, TlsPolicy, UnderlayDialer, connect_tls_with_underlay,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth::{
    AuthWireDisposition, FlowAuthError, L3AuthContext, apply_auth_wire_status,
    build_flow_auth_frame, classify_auth_wire_status,
};
use crate::conntrack::{
    AuthOutcome, ConntrackTable, FlowKey, L3_AUTH_TIMEOUT, L3_CONNTRACK_CAPACITY,
};
use crate::get_ip::{GetIpv4Error, GetIpv4Response, request_ipv4};
use crate::packet::{Ipv4Flow, PacketError, parse_ipv4_flow};

/// Heartbeat cadence validated for one L3 connection.
pub const L3_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);
/// Close after three unanswered probe intervals; cadence remains deployment-controlled.
pub const L3_HEARTBEAT_MISS_LIMIT: u64 = 3;

/// Monotonic flow-authorization counters for diagnostics and concurrency tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlowAuthStats {
    pub requests_sent: u64,
    pub outcomes_received: u64,
    pub timeouts: u64,
    pub in_flight: u64,
    pub peak_in_flight: u64,
    pub transient_statuses_received: u64,
    pub wire_retries_scheduled: u64,
    pub wire_retries_sent: u64,
    pub wire_retries_exhausted: u64,
    pub wire_retries_cancelled: u64,
}

/// Experimental auth retry policy. `L3Session::start` always uses the disabled
/// policy; this is explicit so production callers cannot opt in accidentally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L3AuthRetryConfig {
    pub enabled: bool,
    pub max_wire_retries_per_flow: usize,
    pub delayed_retry_delay: Duration,
    pub overall_auth_deadline: Duration,
}

impl L3AuthRetryConfig {
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            max_wire_retries_per_flow: 0,
            delayed_retry_delay: Duration::ZERO,
            overall_auth_deadline: L3_AUTH_TIMEOUT,
        }
    }
}

/// Monotonic heartbeat counters and the most recent gateway acknowledgement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeartbeatStats {
    /// Heartbeats successfully written and flushed to the connection.
    pub requests_sent: u64,
    pub acknowledgements_received: u64,
    pub last_ack_at: Option<SystemTime>,
    /// Monotonic age of `last_ack_at`, unaffected by wall-clock adjustments.
    pub last_ack_age: Option<Duration>,
}

/// Stable category for the first event that closed an L3 connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L3CloseReason {
    Caller,
    PeerEof,
    ReadError,
    WriteError,
    FlushError,
    WriteTimeout,
    HeartbeatTimeout,
    FramingError,
    InboundBufferLimit,
    PacketConsumerDropped,
    Dropped,
}

impl L3CloseReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::PeerEof => "peer_eof",
            Self::ReadError => "read_error",
            Self::WriteError => "write_error",
            Self::FlushError => "flush_error",
            Self::WriteTimeout => "write_timeout",
            Self::HeartbeatTimeout => "heartbeat_timeout",
            Self::FramingError => "framing_error",
            Self::InboundBufferLimit => "inbound_buffer_limit",
            Self::PacketConsumerDropped => "packet_consumer_dropped",
            Self::Dropped => "dropped",
        }
    }
}

/// First-wins closure diagnostic retained after the connection is gone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L3CloseInfo {
    pub reason: L3CloseReason,
    pub detail: String,
    pub closed_at: SystemTime,
}

/// Second-VIP response command (`05 96 <status> <u16 len> <json>`).
const L3_SECOND_VIP_RESP: u8 = 0x96;
/// Asynchronous VIP update (`05 97 <status> <u16 len> <json>`).
const L3_VIP_UPDATE_RESP: u8 = 0x97;

/// Cap on unparsed inbound bytes. A peer that never completes a frame cannot
/// make the reader buffer without bound.
const MAX_PENDING_READ: usize = 1024 * 1024;

/// A5: bound on retained `53 00` bodies. A run long enough to matter must not
/// be able to grow this without limit; the counter keeps the true total.
const MAX_STORED_PROTOCOL_MESSAGES: usize = 64;

/// Shortest `connectToken` for which the `0x94` layout discriminant is safe.
///
/// A token-framed body opens with `tokenLen` followed by the token, so its
/// leading `u16-be` is `tokenLen * 256 + token[0]`. The length-prefixed branch
/// claims `(0, 4096]`, which a token of 15 bytes or fewer always lands inside.
/// The gateway never declares this invariant; see `docs/open-questions.md` A1.
const MIN_UNAMBIGUOUS_CONNECT_TOKEN: usize = 17;

const READ_CHUNK: usize = 16 * 1024;
const WRITE_QUEUE_DEPTH: usize = 64;
const AUTH_RETRY_QUEUE_DEPTH: usize = 64;
const PACKET_QUEUE_DEPTH: usize = 256;
const WRITE_TIMEOUT: Duration = Duration::from_secs(20);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

struct OutboundFrame {
    bytes: Vec<u8>,
    written: Option<oneshot::Sender<Result<(), ()>>>,
    heartbeat: bool,
}

struct RetryJob {
    auth_id: u64,
    delay: Duration,
}

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
    /// Owning group, used to attribute asynchronous VIP changes.
    pub node_group_id: Option<&'a str>,
    /// Observation channel for protocol findings seen on this connection.
    pub events: Option<Arc<EventBus>>,
}

#[derive(Debug)]
struct PacketSubscription {
    id: u64,
    sender: mpsc::Sender<Vec<u8>>,
}

/// State shared between the caller and the session tasks.
#[derive(Debug)]
struct SessionShared {
    /// Effective source address. The initial Get-IP response remains immutable
    /// for diagnostics while `0x97` can replace this value at runtime.
    current_vip: Mutex<Ipv4Addr>,
    node_group_id: Option<String>,
    conntrack: Mutex<ConntrackTable>,
    /// Callers awaiting a `0x93` for a given auth id. A flow can have more than
    /// one waiter when several packets race into the same unauthorized flow.
    waiters: Mutex<HashMap<u64, Vec<oneshot::Sender<AuthOutcome>>>>,
    packet_subscribers: Mutex<HashMap<FlowKey, PacketSubscription>>,
    next_subscriber: AtomicU64,
    closed: AtomicBool,
    close_info: Mutex<Option<L3CloseInfo>>,
    /// Inbound packets discarded because the consumer was not keeping up.
    dropped_packets: AtomicU64,
    auth_requests_sent: AtomicU64,
    auth_outcomes_received: AtomicU64,
    auth_timeouts: AtomicU64,
    auth_in_flight: AtomicU64,
    auth_peak_in_flight: AtomicU64,
    auth_retry_config: L3AuthRetryConfig,
    retry_tx: Mutex<Option<mpsc::Sender<RetryJob>>>,
    transient_statuses_received: AtomicU64,
    wire_retries_scheduled: AtomicU64,
    wire_retries_sent: AtomicU64,
    wire_retries_exhausted: AtomicU64,
    wire_retries_cancelled: AtomicU64,
    heartbeat_requests_sent: AtomicU64,
    heartbeat_acks_received: AtomicU64,
    last_heartbeat_ack: Mutex<Option<(SystemTime, Instant)>>,
    last_heartbeat_ack_monotonic: Mutex<Option<tokio::time::Instant>>,
    first_heartbeat_written: Mutex<Option<tokio::time::Instant>>,
    /// Broadcast stop signal. Every task selects on it, so closing a session
    /// does not have to wait for a task's own timer to fire.
    stop_tx: watch::Sender<bool>,
    /// Optional observation channel. Publishing is non-blocking and lossy by
    /// contract, which is what makes it safe to call from the read loop.
    events: Option<Arc<EventBus>>,
    /// Which `0x94` branches have already been reported. The layout is a
    /// protocol finding (A1), so it is worth one event per branch — and only
    /// one, because a saturated tunnel would otherwise flood the stream.
    seen_length_prefixed: AtomicBool,
    seen_token_framed: AtomicBool,
    /// A5: every mid-session `53 00` body, bounded. Kept so a long run can be
    /// inspected after the fact instead of only while its log is being watched.
    protocol_messages: Mutex<Vec<String>>,
    protocol_messages_seen: AtomicU64,
}

impl SessionShared {
    fn new(
        initial_vip: Ipv4Addr,
        node_group_id: Option<String>,
        events: Option<Arc<EventBus>>,
        auth_retry_config: L3AuthRetryConfig,
    ) -> Self {
        Self {
            current_vip: Mutex::new(initial_vip),
            node_group_id,
            conntrack: Mutex::new(ConntrackTable::new()),
            waiters: Mutex::new(HashMap::new()),
            packet_subscribers: Mutex::new(HashMap::new()),
            next_subscriber: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            close_info: Mutex::new(None),
            dropped_packets: AtomicU64::new(0),
            auth_requests_sent: AtomicU64::new(0),
            auth_outcomes_received: AtomicU64::new(0),
            auth_timeouts: AtomicU64::new(0),
            auth_in_flight: AtomicU64::new(0),
            auth_peak_in_flight: AtomicU64::new(0),
            auth_retry_config,
            retry_tx: Mutex::new(None),
            transient_statuses_received: AtomicU64::new(0),
            wire_retries_scheduled: AtomicU64::new(0),
            wire_retries_sent: AtomicU64::new(0),
            wire_retries_exhausted: AtomicU64::new(0),
            wire_retries_cancelled: AtomicU64::new(0),
            heartbeat_requests_sent: AtomicU64::new(0),
            heartbeat_acks_received: AtomicU64::new(0),
            last_heartbeat_ack: Mutex::new(None),
            last_heartbeat_ack_monotonic: Mutex::new(None),
            first_heartbeat_written: Mutex::new(None),
            stop_tx: watch::channel(false).0,
            events,
            seen_length_prefixed: AtomicBool::new(false),
            seen_token_framed: AtomicBool::new(false),
            protocol_messages: Mutex::new(Vec::new()),
            protocol_messages_seen: AtomicU64::new(0),
        }
    }

    fn apply_vip_update(&self, current: Ipv4Addr) {
        let previous = {
            let mut vip = self.current_vip.lock().expect("current VIP mutex");
            if *vip == current {
                return;
            }
            std::mem::replace(&mut *vip, current)
        };

        let (retired_flows, cancelled) = {
            let mut table = self.conntrack.lock().expect("conntrack mutex");
            let cancelled = table.scheduled_retries();
            (table.clear(), cancelled)
        };
        self.wire_retries_cancelled
            .fetch_add(cancelled as u64, Ordering::Relaxed);
        let drained: Vec<_> = self
            .waiters
            .lock()
            .expect("waiters mutex")
            .drain()
            .collect();
        drop(drained);
        self.auth_in_flight.store(0, Ordering::Relaxed);
        self.packet_subscribers
            .lock()
            .expect("packet subscribers mutex")
            .clear();

        warn!(
            event = "atrust_l3.session.vip_changed",
            node_group_id = self.node_group_id.as_deref().unwrap_or("unknown"),
            %previous,
            %current,
            retired_flows
        );
        if let Some(node_group_id) = self.node_group_id.as_ref() {
            self.events.emit(|| HermesEvent::L3VipChanged {
                node_group_id: node_group_id.clone(),
                previous,
                current,
            });
        }
    }

    /// Reports a `0x94` branch the first time it is seen on this connection.
    fn record_data_layout(&self, layout: L3DataLayout, bytes: usize) {
        let first = match layout {
            L3DataLayout::LengthPrefixed => &self.seen_length_prefixed,
            L3DataLayout::TokenFramed => &self.seen_token_framed,
        };
        if !first.swap(true, Ordering::Relaxed) {
            self.events
                .emit(|| HermesEvent::L3DataLayoutObserved { layout, bytes });
        }
    }

    /// Records one discarded inbound packet and returns the running total.
    ///
    /// Logged at WARN for the first drop and then on a widening scale: a
    /// congested tunnel must not turn into a log flood, but the first drop is
    /// the moment the operator can still act on it.
    fn record_drop(&self) -> u64 {
        let total = self.dropped_packets.fetch_add(1, Ordering::Relaxed) + 1;
        if total == 1 || total.is_power_of_two() {
            warn!(
                event = "atrust_l3.session.packet_dropped",
                dropped_total = total,
                queue_depth = PACKET_QUEUE_DEPTH,
                note = "inbound packet discarded: consumer is slower than the tunnel"
            );
            self.events.emit(|| HermesEvent::L3PacketsDropped {
                dropped_total: total,
            });
        }
        total
    }

    fn stop_signal(&self) -> watch::Receiver<bool> {
        self.stop_tx.subscribe()
    }

    fn record_auth_sent(&self) {
        self.auth_requests_sent.fetch_add(1, Ordering::Relaxed);
        let in_flight = self.auth_in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        self.auth_peak_in_flight
            .fetch_max(in_flight, Ordering::Relaxed);
    }

    fn record_retry_sent(&self) {
        self.auth_requests_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn settle_auth(&self, timed_out: bool) {
        if timed_out {
            self.auth_timeouts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.auth_outcomes_received.fetch_add(1, Ordering::Relaxed);
        }
        let _ = self
            .auth_in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            });
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
    fn shutdown(&self, reason: L3CloseReason, detail: impl Into<String>) {
        let detail = detail.into();
        {
            let mut close_info = self.close_info.lock().expect("close info mutex");
            if close_info.is_some() {
                return;
            }
            *close_info = Some(L3CloseInfo {
                reason,
                detail: detail.clone(),
                closed_at: SystemTime::now(),
            });
            self.closed.store(true, Ordering::SeqCst);
        }
        let _ = self.stop_tx.send(true);
        self.packet_subscribers
            .lock()
            .expect("packet subscribers mutex")
            .clear();
        let cancelled = {
            let mut table = self.conntrack.lock().expect("conntrack mutex");
            let cancelled = table.scheduled_retries();
            table.clear();
            cancelled
        };
        self.wire_retries_cancelled
            .fetch_add(cancelled as u64, Ordering::Relaxed);
        let drained: Vec<_> = self
            .waiters
            .lock()
            .expect("waiters mutex")
            .drain()
            .collect();
        drop(drained);
        debug!(
            event = "atrust_l3.session.shutdown",
            reason = reason.as_str(),
            detail
        );
    }

    fn record_protocol_message(&self, body: &[u8]) {
        self.protocol_messages_seen.fetch_add(1, Ordering::Relaxed);
        let mut stored = self
            .protocol_messages
            .lock()
            .expect("protocol message mutex");
        if stored.len() < MAX_STORED_PROTOCOL_MESSAGES {
            stored.push(String::from_utf8_lossy(body).into_owned());
        }
    }

    fn record_heartbeat_ack(&self) {
        self.heartbeat_acks_received.fetch_add(1, Ordering::Relaxed);
        *self.last_heartbeat_ack.lock().expect("heartbeat ack mutex") =
            Some((SystemTime::now(), Instant::now()));
        *self
            .last_heartbeat_ack_monotonic
            .lock()
            .expect("heartbeat clock mutex") = Some(tokio::time::Instant::now());
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
    write_tx: mpsc::Sender<OutboundFrame>,
    packets: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    tasks: AsyncMutex<Vec<JoinHandle<()>>>,
}

/// Exclusive bounded reply queue for an outbound five-tuple. Matching packets
/// do not compete with the raw packet reader or another flow's receiver.
#[derive(Debug)]
pub struct FlowPackets {
    shared: Weak<SessionShared>,
    key: FlowKey,
    id: u64,
    receiver: mpsc::Receiver<Vec<u8>>,
}
impl FlowPackets {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.receiver.recv().await
    }
}
impl Drop for FlowPackets {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            let mut subscribers = shared
                .packet_subscribers
                .lock()
                .expect("packet subscribers mutex");
            if subscribers
                .get(&self.key)
                .is_some_and(|entry| entry.id == self.id)
            {
                subscribers.remove(&self.key);
            }
        }
    }
}

impl L3Session {
    pub fn subscribe_flow(&self, flow: &Ipv4Flow) -> Result<FlowPackets, L3SessionError> {
        let mut subscribers = self
            .shared
            .packet_subscribers
            .lock()
            .expect("packet subscribers mutex");
        if self.is_closed() {
            return Err(L3SessionError::Closed);
        }
        if flow.src_addr != self.vip() {
            return Err(L3SessionError::VipChanged {
                packet_source: flow.src_addr,
                session_vip: self.vip(),
            });
        }
        let key = flow.flow_key();
        if subscribers.contains_key(&key) {
            return Err(L3SessionError::FlowAlreadySubscribed);
        }
        let id = self.shared.next_subscriber.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(64);
        subscribers.insert(key.clone(), PacketSubscription { id, sender });
        Ok(FlowPackets {
            shared: Arc::downgrade(&self.shared),
            key,
            id,
            receiver,
        })
    }

    /// Connects to a node, performs Get-IP, and starts the session on that
    /// same connection.
    pub async fn establish(config: L3SessionConfig<'_>) -> Result<Self, L3SessionError> {
        Self::establish_with_underlay(config, &SystemUnderlay::default()).await
    }

    pub async fn establish_with_underlay(
        config: L3SessionConfig<'_>,
        underlay: &dyn UnderlayDialer,
    ) -> Result<Self, L3SessionError> {
        let stream = timeout(
            config.connect_timeout,
            connect_tls_with_underlay(
                config.node_host,
                config.node_port,
                config.tls_policy,
                underlay,
            ),
        )
        .await
        .map_err(|_| L3SessionError::ConnectTimeout)??;
        Self::start(
            stream,
            config.sid,
            config.heartbeat_interval,
            config.connect_timeout,
            config.node_group_id.map(str::to_owned),
            config.events,
        )
        .await
    }

    /// Starts a session on an already-connected stream.
    ///
    /// Exposed so the whole driver can be exercised against an in-memory duplex
    /// peer with no TLS and no gateway.
    pub async fn start<S>(
        stream: S,
        sid: &SessionId,
        heartbeat_interval: Duration,
        get_ip_timeout: Duration,
        node_group_id: Option<String>,
        events: Option<Arc<EventBus>>,
    ) -> Result<Self, L3SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::start_with_config(
            stream,
            sid,
            heartbeat_interval,
            get_ip_timeout,
            node_group_id,
            events,
            L3AuthRetryConfig::disabled(),
        )
        .await
    }

    /// Starts a session with the explicitly experimental auth retry policy.
    pub async fn start_with_config<S>(
        mut stream: S,
        sid: &SessionId,
        heartbeat_interval: Duration,
        get_ip_timeout: Duration,
        node_group_id: Option<String>,
        events: Option<Arc<EventBus>>,
        retry_config: L3AuthRetryConfig,
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

        let shared = Arc::new(SessionShared::new(
            get_ip.address,
            node_group_id,
            events,
            retry_config,
        ));
        let (read_half, mut write_half) = tokio::io::split(stream);
        let (write_tx, mut write_rx) = mpsc::channel::<OutboundFrame>(WRITE_QUEUE_DEPTH);
        let (retry_tx, mut retry_rx) = mpsc::channel::<RetryJob>(AUTH_RETRY_QUEUE_DEPTH);
        *shared.retry_tx.lock().expect("retry mutex") = Some(retry_tx);
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
                        let result = tokio::select! {
                            biased;
                            _ = writer_stop.changed() => break,
                            result = timeout(WRITE_TIMEOUT, async {
                                write_half.write_all(&frame.bytes).await
                                    .map_err(|error| (L3CloseReason::WriteError, error))?;
                                write_half.flush().await
                                    .map_err(|error| (L3CloseReason::FlushError, error))
                            }) => result,
                        };
                        if result.is_err() {
                            writer_shared.shutdown(L3CloseReason::WriteTimeout, "L3 write deadline exceeded");
                            break;
                        }
                        if let Err((reason, error)) = result.expect("write completed before deadline") {
                            if let Some(written) = frame.written {
                                let _ = written.send(Err(()));
                            }
                            warn!(event = "atrust_l3.session.write_failed", %error);
                            writer_shared.shutdown(
                                reason,
                                format!("L3 connection write failed: {error}"),
                            );
                            break;
                        }
                        if let Some(written) = frame.written {
                            let _ = written.send(Ok(()));
                        }
                        if frame.heartbeat {
                            writer_shared.first_heartbeat_written.lock().expect("heartbeat clock mutex")
                                .get_or_insert_with(tokio::time::Instant::now);
                            writer_shared
                                .heartbeat_requests_sent
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            let _ = timeout(CLOSE_TIMEOUT, write_half.shutdown()).await;
            debug!(event = "atrust_l3.session.writer_stopped");
        });

        let reader_shared = Arc::clone(&shared);
        let mut reader_stop = shared.stop_signal();
        let reader = tokio::spawn(async move {
            let reason = tokio::select! {
                reason = read_loop(read_half, &reader_shared, &packets_tx) => reason,
                _ = reader_stop.changed() => ShutdownReason::new(
                    L3CloseReason::Caller,
                    "L3 session closed by caller",
                ),
            };
            reader_shared.shutdown(reason.reason, reason.detail.clone());
            debug!(
                event = "atrust_l3.session.reader_stopped",
                reason = reason.reason.as_str(),
                detail = %reason.detail
            );
        });

        let heartbeat_tx = write_tx.clone();
        let heartbeat_shared = Arc::clone(&shared);
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
                        let now = tokio::time::Instant::now();
                        let last_ack = *heartbeat_shared.last_heartbeat_ack_monotonic
                            .lock().expect("heartbeat clock mutex");
                        let first_probe_at = *heartbeat_shared.first_heartbeat_written.lock().expect("heartbeat clock mutex");
                        let unanswered = heartbeat_shared.heartbeat_requests_sent.load(Ordering::Relaxed)
                            .saturating_sub(heartbeat_shared.heartbeat_acks_received.load(Ordering::Relaxed));
                        if unanswered >= L3_HEARTBEAT_MISS_LIMIT && first_probe_at.is_some_and(|first| {
                            now.saturating_duration_since(last_ack.unwrap_or(first))
                                >= heartbeat_interval.saturating_mul(L3_HEARTBEAT_MISS_LIMIT as u32)
                        }) {
                            heartbeat_shared.shutdown(L3CloseReason::HeartbeatTimeout,
                                "L3 peer did not acknowledge heartbeat probes");
                            break;
                        }
                        if heartbeat_tx.send(OutboundFrame {
                            bytes: encode_l3_heartbeat_req().to_vec(),
                            written: None,
                            heartbeat: true,
                        }).await.is_err() {
                            break;
                        }
                    }
                }
            }
            debug!(event = "atrust_l3.session.heartbeat_stopped");
        });

        let retry_shared = Arc::clone(&shared);
        let retry_write = write_tx.clone();
        let mut retry_stop = shared.stop_signal();
        let retry_scheduler = tokio::spawn(async move {
            while let Some(job) = tokio::select! {
                biased;
                _ = retry_stop.changed() => None,
                job = retry_rx.recv() => job,
            } {
                let sleep = tokio::time::sleep(job.delay);
                tokio::pin!(sleep);
                tokio::select! {
                    biased;
                    _ = retry_stop.changed() => break,
                    _ = &mut sleep => {}
                }
                let frame = {
                    let mut table = retry_shared.conntrack.lock().expect("conntrack mutex");
                    let Some(entry) = table.get_by_auth_id_mut(job.auth_id) else {
                        retry_shared
                            .wire_retries_cancelled
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if entry
                        .auth_deadline()
                        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
                    {
                        entry.complete(AuthOutcome::Failed {
                            message: "auth deadline exceeded".to_owned(),
                        });
                        retry_shared
                            .wire_retries_exhausted
                            .fetch_add(1, Ordering::Relaxed);
                        None
                    } else {
                        entry.take_retry()
                    }
                };
                let Some(bytes) = frame else {
                    if let Some(outcome) = retry_shared
                        .conntrack
                        .lock()
                        .expect("conntrack mutex")
                        .get_by_auth_id(job.auth_id)
                        .and_then(|e| e.outcome())
                        .cloned()
                    {
                        retry_shared.settle_auth(false);
                        retry_shared.notify(job.auth_id, &outcome);
                    }
                    continue;
                };
                let (written, done) = oneshot::channel();
                if retry_write
                    .send(OutboundFrame {
                        bytes,
                        written: Some(written),
                        heartbeat: false,
                    })
                    .await
                    .is_err()
                    || !matches!(done.await, Ok(Ok(())))
                {
                    retry_shared.shutdown(L3CloseReason::WriteError, "auth retry write failed");
                    break;
                }
                retry_shared
                    .wire_retries_sent
                    .fetch_add(1, Ordering::Relaxed);
                retry_shared.record_retry_sent();
            }
        });

        Ok(Self {
            get_ip,
            shared,
            write_tx,
            packets: AsyncMutex::new(packets_rx),
            tasks: AsyncMutex::new(vec![writer, reader, heartbeat, retry_scheduler]),
        })
    }

    /// Virtual IPv4 assigned by Get-IP.
    #[must_use]
    pub fn vip(&self) -> Ipv4Addr {
        *self.shared.current_vip.lock().expect("current VIP mutex")
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

    /// Flows currently tracked on this connection.
    ///
    /// Bounded by `L3_CONNTRACK_CAPACITY`; a value pinned at the cap means the
    /// table is thrashing rather than merely busy.
    #[must_use]
    pub fn conntrack_len(&self) -> usize {
        self.shared.conntrack.lock().expect("conntrack mutex").len()
    }

    /// Inbound packets discarded because the consumer fell behind.
    ///
    /// Non-zero means the tunnel outran whatever is draining [`Self::recv_packet`].
    /// The packets are gone — this is the counter a TUN layer should surface as
    /// interface drops rather than treating as a protocol error.
    #[must_use]
    pub fn dropped_packets(&self) -> u64 {
        self.shared.dropped_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn flow_auth_stats(&self) -> FlowAuthStats {
        FlowAuthStats {
            requests_sent: self.shared.auth_requests_sent.load(Ordering::Relaxed),
            outcomes_received: self.shared.auth_outcomes_received.load(Ordering::Relaxed),
            timeouts: self.shared.auth_timeouts.load(Ordering::Relaxed),
            in_flight: self.shared.auth_in_flight.load(Ordering::Relaxed),
            peak_in_flight: self.shared.auth_peak_in_flight.load(Ordering::Relaxed),
            transient_statuses_received: self
                .shared
                .transient_statuses_received
                .load(Ordering::Relaxed),
            wire_retries_scheduled: self.shared.wire_retries_scheduled.load(Ordering::Relaxed),
            wire_retries_sent: self.shared.wire_retries_sent.load(Ordering::Relaxed),
            wire_retries_exhausted: self.shared.wire_retries_exhausted.load(Ordering::Relaxed),
            wire_retries_cancelled: self.shared.wire_retries_cancelled.load(Ordering::Relaxed),
        }
    }

    /// A5: mid-session `53 00` bodies seen, and the retained sample of them.
    ///
    /// The count is the true total; the vector is capped at
    /// [`MAX_STORED_PROTOCOL_MESSAGES`].
    #[must_use]
    pub fn protocol_messages(&self) -> (u64, Vec<String>) {
        let stored = self
            .shared
            .protocol_messages
            .lock()
            .expect("protocol message mutex")
            .clone();
        (
            self.shared.protocol_messages_seen.load(Ordering::Relaxed),
            stored,
        )
    }

    /// Heartbeats flushed to the wire and acknowledgements received from the peer.
    #[must_use]
    pub fn heartbeat_stats(&self) -> HeartbeatStats {
        let last_ack = *self
            .shared
            .last_heartbeat_ack
            .lock()
            .expect("heartbeat ack mutex");
        HeartbeatStats {
            requests_sent: self.shared.heartbeat_requests_sent.load(Ordering::Relaxed),
            acknowledgements_received: self.shared.heartbeat_acks_received.load(Ordering::Relaxed),
            last_ack_at: last_ack.map(|(wall, _)| wall),
            last_ack_age: last_ack.map(|(_, monotonic)| monotonic.elapsed()),
        }
    }

    /// The first event that ended this connection, retained after shutdown.
    #[must_use]
    pub fn close_info(&self) -> Option<L3CloseInfo> {
        self.shared
            .close_info
            .lock()
            .expect("close info mutex")
            .clone()
    }

    /// Authorizes one flow and returns its connect token.
    ///
    /// Repeat calls for an already-authorized flow return the cached token
    /// without touching the wire. Concurrent callers for the same flow send one
    /// `0x13` and all wait on the same response.
    ///
    /// On timeout the flow is evicted, so a caller that wants the compatibility
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
        if flow.src_addr != self.vip() {
            return Err(L3SessionError::VipChanged {
                packet_source: flow.src_addr,
                session_vip: self.vip(),
            });
        }
        let key = flow.flow_key();

        // Phase 1: claim the flow and register a waiter, holding the lock only
        // for bookkeeping — never across an await.
        let (auth_id, must_send, receiver, prune) = {
            let mut table = self.shared.conntrack.lock().expect("conntrack mutex");
            // Retire idle flows on the same lock acquisition that adds one, so
            // the table stays bounded without a second task contending here.
            let prune = table.maintain_for_flow(&key);
            if let Some((old_id, in_flight)) = table
                .get_by_key(&key)
                .filter(|entry| entry.app_id != app_id || entry.node_group_id != node_group_id)
                .map(|entry| (entry.auth_id, entry.auth_in_flight()))
            {
                // Late replies and cancelled callers must not settle or remove
                // the replacement authorization for this same five-tuple.
                table.evict_by_auth_id(old_id);
                self.shared.notify(
                    old_id,
                    &AuthOutcome::Failed {
                        message: "flow resource changed during authorization".to_owned(),
                    },
                );
                if in_flight {
                    let _ = self.shared.auth_in_flight.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |n| Some(n.saturating_sub(1)),
                    );
                }
            }
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
            (auth_id, must_send, receiver, prune)
        };

        // Reported outside the lock. Idle expiry is routine and stays at debug;
        // a capacity eviction is not, because it means an authorized flow was
        // retired early and will pay another round trip.
        if prune.evicted_for_capacity > 0 {
            warn!(
                event = "atrust_l3.session.conntrack_pressure",
                entries = prune.entries,
                capacity = L3_CONNTRACK_CAPACITY,
                evicted = prune.evicted_for_capacity
            );
            self.shared
                .events
                .emit(|| HermesEvent::L3ConntrackPressure {
                    entries: prune.entries,
                    capacity: L3_CONNTRACK_CAPACITY,
                    evicted: prune.evicted_for_capacity,
                });
        } else if prune.expired > 0 {
            debug!(
                event = "atrust_l3.session.conntrack_expired",
                expired = prune.expired,
                entries = prune.entries
            );
        }

        // Phase 2: build and send outside the lock. A build failure must not
        // strand the flow in "auth started" with nothing in flight.
        if must_send {
            let frame = match build_flow_auth_frame(ctx, app_id, auth_id, &flow.to_five_tuple()) {
                Ok(frame) => frame,
                Err(error) => {
                    self.abandon_flow(auth_id);
                    return Err(error.into());
                }
            };
            if let Some(entry) = self
                .shared
                .conntrack
                .lock()
                .expect("conntrack mutex")
                .get_by_auth_id_mut(auth_id)
                .filter(|entry| entry.auth_in_flight())
            {
                entry.set_reusable_frame(
                    frame.clone(),
                    tokio::time::Instant::now()
                        + self.shared.auth_retry_config.overall_auth_deadline,
                );
            }
            debug!(
                event = "atrust_l3.session.auth_sent",
                auth_id,
                flow = %key,
                app_id
            );
            if self.write_frame(frame).await.is_err() {
                self.abandon_flow(auth_id);
                return Err(L3SessionError::Closed);
            }
            self.shared.record_auth_sent();
        }

        match timeout(
            self.shared.auth_retry_config.overall_auth_deadline,
            receiver,
        )
        .await
        {
            Ok(Ok(AuthOutcome::Ready { connect_token })) => {
                if flow.src_addr != self.vip() {
                    Err(L3SessionError::VipChanged {
                        packet_source: flow.src_addr,
                        session_vip: self.vip(),
                    })
                } else {
                    Ok(connect_token)
                }
            }
            Ok(Ok(AuthOutcome::Failed { message })) => {
                Err(FlowAuthError::AuthFailed(message).into())
            }
            // The reader task dropped the sender without a verdict.
            Ok(Err(_)) if flow.src_addr != self.vip() => Err(L3SessionError::VipChanged {
                packet_source: flow.src_addr,
                session_vip: self.vip(),
            }),
            Ok(Err(_)) => Err(L3SessionError::Closed),
            Err(_) => {
                self.abandon_flow(auth_id);
                if must_send {
                    self.shared.settle_auth(true);
                }
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
    fn abandon_flow(&self, auth_id: u64) {
        self.shared
            .conntrack
            .lock()
            .expect("conntrack mutex")
            .evict_by_auth_id(auth_id);
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
        for packet in packets {
            let flow = parse_ipv4_flow(packet)?;
            if flow.src_addr != self.vip() {
                return Err(L3SessionError::VipChanged {
                    packet_source: flow.src_addr,
                    session_vip: self.vip(),
                });
            }
        }
        let frame = encode_l3_data_req(connect_token.as_bytes(), packets)?;
        self.write_frame(frame).await
    }

    /// Queues a frame and waits until the writer has flushed it. Without this
    /// acknowledgement a dead socket looks successful to callers, preventing
    /// the connection owner from performing a safe L3 retry.
    async fn write_frame(&self, bytes: Vec<u8>) -> Result<(), L3SessionError> {
        let mut stop = self.shared.stop_signal();
        if self.is_closed() {
            return Err(L3SessionError::Closed);
        }
        let (written, receiver) = oneshot::channel();
        tokio::select! {
            biased;
            _ = stop.changed() => Err(L3SessionError::Closed),
            result = async {
                self.write_tx
            .send(OutboundFrame {
                bytes,
                written: Some(written),
                heartbeat: false,
            })
            .await
            .map_err(|_| L3SessionError::Closed)?;
                match receiver.await {
            Ok(Ok(())) => Ok(()),
            _ => Err(L3SessionError::Closed),
                }
            } => result,
        }
    }

    /// Receives the next inbound IPv4 packet, or `None` once the session ends.
    pub async fn recv_packet(&self) -> Option<Vec<u8>> {
        self.packets.lock().await.recv().await
    }

    /// Closes the connection and stops the reader, writer and heartbeat tasks.
    pub fn request_close(&self) {
        self.shared
            .shutdown(L3CloseReason::Caller, "L3 session closed by caller");
    }

    /// Requests closure and joins the owned tasks within their shutdown budget.
    pub async fn close(&self) {
        self.request_close();
        let mut handles = self.tasks.lock().await;
        while let Some(handle) = handles.last_mut() {
            if timeout(CLOSE_TIMEOUT, &mut *handle).await.is_err() {
                handle.abort();
                let _ = handle.await;
            }
            handles.pop();
        }
        debug!(event = "atrust_l3.session.closed");
    }
}

impl Drop for L3Session {
    fn drop(&mut self) {
        // A dropped session must not leave three tasks holding a live socket.
        self.shared
            .shutdown(L3CloseReason::Dropped, "L3 session object dropped");
        for handle in self.tasks.get_mut().drain(..) {
            handle.abort();
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
    VipUpdate {
        status: u8,
        json: &'a [u8],
    },
    /// Nested `53 00` protocol message.
    Protocol {
        body: &'a [u8],
    },
    /// A known-shaped frame this client has no use for.
    Ignored {
        cmd: u8,
    },
}

/// Splits one frame off the front of `buf`.
///
/// `Ok(None)` means "need more bytes"; the caller must not consume anything.
///
/// Framing follows behavior validated by gateway observations and local fixtures:
///
/// - `05 93` / `05 96` / `05 97` carry a status byte *before* the length;
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
        return Ok(length_prefixed(buf).map(|total| {
            (
                Inbound::Protocol {
                    body: &buf[4..total],
                },
                total,
            )
        }));
    }

    if buf[0] != L3_VERSION {
        return Err(L3SessionError::UnexpectedVersion { byte: buf[0] });
    }

    match buf[1] {
        l3_cmd::AUTH_RESP => Ok(status_and_json(buf)
            .map(|(status, json, total)| (Inbound::Auth { status, json }, total))),
        L3_SECOND_VIP_RESP => Ok(status_and_json(buf)
            .map(|(status, json, total)| (Inbound::SecondVip { status, json }, total))),
        L3_VIP_UPDATE_RESP => Ok(status_and_json(buf)
            .map(|(status, json, total)| (Inbound::VipUpdate { status, json }, total))),
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
#[derive(Debug)]
struct ShutdownReason {
    reason: L3CloseReason,
    detail: String,
}

impl ShutdownReason {
    fn new(reason: L3CloseReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

async fn read_loop<R>(
    mut read_half: R,
    shared: &Arc<SessionShared>,
    packets_tx: &mpsc::Sender<Vec<u8>>,
) -> ShutdownReason
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
                Err(error) => {
                    return ShutdownReason::new(
                        L3CloseReason::FramingError,
                        format!("L3 framing error: {error}"),
                    );
                }
            };
            pending.drain(..consumed);
            match action {
                Dispatch::Continue => {}
                Dispatch::Send(packet) => {
                    if let Some(reason) = deliver(packets_tx, shared, packet) {
                        return ShutdownReason::new(L3CloseReason::PacketConsumerDropped, reason);
                    }
                }
                Dispatch::SendMany(packets) => {
                    for packet in packets {
                        if let Some(reason) = deliver(packets_tx, shared, packet) {
                            return ShutdownReason::new(
                                L3CloseReason::PacketConsumerDropped,
                                reason,
                            );
                        }
                    }
                }
            }
        }

        if pending.len() > MAX_PENDING_READ {
            return ShutdownReason::new(
                L3CloseReason::InboundBufferLimit,
                format!("L3 inbound buffer exceeded {MAX_PENDING_READ} bytes"),
            );
        }

        match read_half.read(&mut chunk).await {
            Ok(0) => {
                return ShutdownReason::new(L3CloseReason::PeerEof, "L3 connection closed by peer");
            }
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(error) => {
                return ShutdownReason::new(
                    L3CloseReason::ReadError,
                    format!("L3 connection read failed: {error}"),
                );
            }
        }
    }
}

/// Hands one inbound packet to the consumer, dropping it if the queue is full.
///
/// Returns a shutdown reason only when the consumer is gone for good.
///
/// **Dropping, not awaiting, is the point.** This runs on the read loop, which
/// is also the only task that dispatches `0x93` auth responses and `0x95`
/// heartbeat acks. Blocking here on a full queue would stall the control path
/// behind a slow data consumer: every in-flight `authorize_flow` would run out
/// its 8s timeout while the tunnel still looked healthy, and the reader would
/// stop draining the socket. A tunnel that carries IP is lossy by contract, so
/// discarding a packet is a legal outcome; wedging flow authorization is not.
fn deliver(
    packets_tx: &mpsc::Sender<Vec<u8>>,
    shared: &Arc<SessionShared>,
    packet: Vec<u8>,
) -> Option<String> {
    let subscriber = parse_ipv4_flow(&packet).ok().and_then(|flow| {
        shared
            .packet_subscribers
            .lock()
            .expect("packet subscribers mutex")
            .get(&flow.reverse_flow_key())
            .map(|entry| entry.sender.clone())
    });
    if let Some(sender) = subscriber {
        if sender.try_send(packet).is_err() {
            shared.record_drop();
        }
        return None;
    }
    match packets_tx.try_send(packet) {
        Ok(()) => None,
        Err(mpsc::error::TrySendError::Full(_)) => {
            shared.record_drop();
            None
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Some("L3 packet consumer dropped".to_owned()),
    }
}

fn touch_inbound_flow(shared: &SessionShared, packet: &[u8]) {
    let Ok(flow) = parse_ipv4_flow(packet) else {
        return;
    };
    shared
        .conntrack
        .lock()
        .expect("conntrack mutex")
        .touch(&flow.reverse_flow_key());
}

fn first_ipv4_in_json(json: &[u8]) -> Option<Ipv4Addr> {
    fn visit(value: &serde_json::Value) -> Option<Ipv4Addr> {
        match value {
            serde_json::Value::String(value) => value.parse().ok(),
            serde_json::Value::Array(values) => values.iter().find_map(visit),
            serde_json::Value::Object(values) => values.values().find_map(visit),
            _ => None,
        }
    }

    serde_json::from_slice(json).ok().as_ref().and_then(visit)
}

/// What the read loop must do after a frame is decoded.
///
/// Packets are handed back rather than sent inline so the borrow on the read
/// buffer ends before the loop hands them to the packet channel.
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
            let disposition = classify_auth_wire_status(status);
            let transient = matches!(
                disposition,
                AuthWireDisposition::RetryImmediate | AuthWireDisposition::RetryDelayed { .. }
            );
            if transient {
                shared
                    .transient_statuses_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            if transient && shared.auth_retry_config.enabled {
                let hash = atrust_protocol::parse_l3_auth_response(json)
                    .ok()
                    .map(|response| response.conntrack_hash)
                    .filter(|hash| *hash != 0);
                let Some(auth_id) = hash else {
                    warn!(event = "atrust_l3.session.auth_unattributable", status);
                    return Dispatch::Continue;
                };
                let delay = match disposition {
                    AuthWireDisposition::RetryImmediate => Duration::ZERO,
                    AuthWireDisposition::RetryDelayed { .. } => {
                        shared.auth_retry_config.delayed_retry_delay
                    }
                    _ => unreachable!(),
                };
                let scheduled = {
                    let mut table = shared.conntrack.lock().expect("conntrack mutex");
                    let Some(entry) = table.get_by_auth_id_mut(auth_id) else {
                        return Dispatch::Continue;
                    };
                    if entry.outcome().is_some() || entry.retry_scheduled() {
                        return Dispatch::Continue;
                    } else if entry
                        .retry_exhausted(shared.auth_retry_config.max_wire_retries_per_flow)
                    {
                        entry.complete(AuthOutcome::Failed {
                            message: "auth retry budget exhausted".to_owned(),
                        });
                        shared
                            .wire_retries_exhausted
                            .fetch_add(1, Ordering::Relaxed);
                        let outcome = entry.outcome().cloned();
                        drop(table);
                        if let Some(outcome) = outcome {
                            shared.settle_auth(false);
                            shared.notify(auth_id, &outcome);
                        }
                        return Dispatch::Continue;
                    } else {
                        entry.schedule_retry(shared.auth_retry_config.max_wire_retries_per_flow)
                    }
                };
                if scheduled {
                    let sent = shared
                        .retry_tx
                        .lock()
                        .expect("retry mutex")
                        .as_ref()
                        .cloned();
                    if sent
                        .as_ref()
                        .is_some_and(|tx| tx.try_send(RetryJob { auth_id, delay }).is_ok())
                    {
                        shared
                            .wire_retries_scheduled
                            .fetch_add(1, Ordering::Relaxed);
                    } else {
                        shared
                            .wire_retries_cancelled
                            .fetch_add(1, Ordering::Relaxed);
                        let outcome = {
                            let mut table = shared.conntrack.lock().expect("conntrack mutex");
                            table.get_by_auth_id_mut(auth_id).map(|entry| {
                                entry.complete(AuthOutcome::Failed {
                                    message: "auth retry scheduler unavailable".to_owned(),
                                });
                                entry.outcome().cloned().expect("just completed")
                            })
                        };
                        if let Some(outcome) = outcome {
                            shared.settle_auth(false);
                            shared.notify(auth_id, &outcome);
                        }
                    }
                }
                return Dispatch::Continue;
            }
            let mut table = shared.conntrack.lock().expect("conntrack mutex");
            match apply_auth_wire_status(&mut table, status, json) {
                Ok(auth_id) => {
                    let outcome = table
                        .get_by_auth_id(auth_id)
                        .and_then(|entry| entry.outcome())
                        .cloned();
                    drop(table);
                    if let Some(outcome) = outcome {
                        shared.settle_auth(false);
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
                            shared.events.emit(|| HermesEvent::L3ConnectTokenAmbiguous {
                                connect_token_len: token.len(),
                                minimum: MIN_UNAMBIGUOUS_CONNECT_TOKEN,
                            });
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
                touch_inbound_flow(shared, packet);
                debug!(
                    event = "atrust_l3.session.data_resp",
                    layout = "length_prefixed",
                    packets = 1,
                    bytes = packet.len()
                );
                shared.record_data_layout(L3DataLayout::LengthPrefixed, packet.len());
                Dispatch::Send(packet.to_vec())
            }
            DataRespPackets::TokenFramed(packets) => {
                for packet in &packets {
                    touch_inbound_flow(shared, packet);
                }
                let bytes = packets.iter().map(|packet| packet.len()).sum::<usize>();
                debug!(
                    event = "atrust_l3.session.data_resp",
                    layout = "token_framed",
                    packets = packets.len(),
                    bytes
                );
                shared.record_data_layout(L3DataLayout::TokenFramed, bytes);
                Dispatch::SendMany(packets.into_iter().map(<[u8]>::to_vec).collect())
            }
        },
        Inbound::Heartbeat => {
            shared.record_heartbeat_ack();
            debug!(
                event = "atrust_l3.session.heartbeat_ack",
                acknowledgements_received = shared.heartbeat_acks_received.load(Ordering::Relaxed)
            );
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
        Inbound::VipUpdate { status, json } => {
            if status != 0 {
                warn!(
                    event = "atrust_l3.session.vip_update_rejected",
                    status,
                    body_len = json.len()
                );
            } else if let Some(vip) = first_ipv4_in_json(json) {
                shared.apply_vip_update(vip);
            } else {
                warn!(
                    event = "atrust_l3.session.vip_update_invalid",
                    body_len = json.len(),
                    note = "successful VIP update contained no IPv4 address"
                );
            }
            Dispatch::Continue
        }
        Inbound::Protocol { body } => {
            // A5: the body is logged rather than merely counted. If one of these
            // ever carries actionable state (session revoked, policy changed,
            // re-auth required), discarding it shows up as "tunnel healthy but
            // every flow silently stops working" — with nothing in the log.
            shared.record_protocol_message(body);
            info!(
                event = "atrust_l3.session.protocol_message",
                len = body.len(),
                body = %String::from_utf8_lossy(body)
            );
            Dispatch::Continue
        }
        Inbound::Ignored { cmd } => {
            // Warn, not debug: an unrecognised frame from the real gateway is a
            // finding, even though skipping it keeps the session alive.
            warn!(event = "atrust_l3.session.ignored_command", cmd);
            shared.events.emit(|| HermesEvent::L3UnknownCommand { cmd });
            Dispatch::Continue
        }
    }
}

#[derive(Debug, Error)]
pub enum L3SessionError {
    #[error("flow already has an exclusive packet subscriber")]
    FlowAlreadySubscribed,
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
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error("L3 flow auth timed out after {} seconds: {flow}", L3_AUTH_TIMEOUT.as_secs())]
    AuthTimeout { flow: String },
    #[error("L3 session is closed")]
    Closed,
    #[error("packet source {packet_source} no longer matches current L3 VIP {session_vip}")]
    VipChanged {
        packet_source: Ipv4Addr,
        session_vip: Ipv4Addr,
    },
    #[error("unexpected L3 version byte {byte:#04x}")]
    UnexpectedVersion { byte: u8 },
    #[error("L3 protocol message rejected with status {status:#04x}")]
    ProtocolRejected { status: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full packet queue must cost packets, never the read loop. If `deliver`
    /// ever goes back to awaiting, this test deadlocks instead of failing — which
    /// is exactly the production symptom it guards against.
    #[tokio::test]
    async fn a_full_packet_queue_drops_instead_of_stalling_the_reader() {
        let shared = Arc::new(SessionShared::new(
            Ipv4Addr::UNSPECIFIED,
            None,
            None,
            L3AuthRetryConfig::disabled(),
        ));
        let (packets_tx, _packets_rx) = mpsc::channel::<Vec<u8>>(2);

        assert_eq!(deliver(&packets_tx, &shared, vec![1]), None);
        assert_eq!(deliver(&packets_tx, &shared, vec![2]), None);
        assert_eq!(shared.dropped_packets.load(Ordering::Relaxed), 0);

        // Third packet has nowhere to go.
        assert_eq!(deliver(&packets_tx, &shared, vec![3]), None);
        assert_eq!(deliver(&packets_tx, &shared, vec![4]), None);
        assert_eq!(shared.dropped_packets.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn a_gone_consumer_still_ends_the_session() {
        let shared = Arc::new(SessionShared::new(
            Ipv4Addr::UNSPECIFIED,
            None,
            None,
            L3AuthRetryConfig::disabled(),
        ));
        let (packets_tx, packets_rx) = mpsc::channel::<Vec<u8>>(2);
        drop(packets_rx);

        let reason = deliver(&packets_tx, &shared, vec![1]).expect("closed consumer ends the loop");
        assert!(reason.contains("consumer"));
        // A closed channel is not congestion, so it must not inflate the counter.
        assert_eq!(shared.dropped_packets.load(Ordering::Relaxed), 0);
    }

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
    fn next_frame_keeps_alignment_after_async_vip_update() {
        let json = br#"{"ip":"10.0.0.2"}"#;
        let mut buf = vec![L3_VERSION, L3_VIP_UPDATE_RESP, 0x00];
        buf.extend_from_slice(&(json.len() as u16).to_be_bytes());
        buf.extend_from_slice(json);
        buf.extend_from_slice(&[L3_VERSION, l3_cmd::HEARTBEAT_RESP, 0x00, 0x00]);

        let (first, consumed) = next_frame(&buf).unwrap().unwrap();
        assert_eq!(
            first,
            Inbound::VipUpdate {
                status: 0,
                json: json.as_slice()
            }
        );
        assert_eq!(
            next_frame(&buf[consumed..]).unwrap().unwrap().0,
            Inbound::Heartbeat
        );
    }

    #[test]
    fn vip_update_extracts_nested_ipv4_and_ignores_ipv6() {
        let json = br#"{"data":{"addresses":["2001:db8::1","10.0.0.2"]}}"#;
        assert_eq!(first_ipv4_in_json(json), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(first_ipv4_in_json(br#"{"ip":"2001:db8::1"}"#), None);
        assert_eq!(first_ipv4_in_json(b"not-json"), None);
    }

    #[tokio::test]
    async fn vip_update_replaces_state_clears_flows_and_emits_event() {
        let events = EventBus::new(8);
        let mut subscriber = events.subscribe();
        let shared = Arc::new(SessionShared::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Some("group-1".to_owned()),
            Some(events),
            L3AuthRetryConfig::disabled(),
        ));
        let flow = crate::FlowKey::new(1, 6, "10.0.0.1", 1234, "192.0.2.1", 443);
        shared
            .conntrack
            .lock()
            .expect("conntrack mutex")
            .get_or_create(flow, "app", "group-1");

        shared.apply_vip_update(Ipv4Addr::new(10, 0, 0, 2));

        assert_eq!(
            *shared.current_vip.lock().expect("current VIP mutex"),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(shared.conntrack.lock().expect("conntrack mutex").len(), 0);
        let event = subscriber.recv().await;
        let Some(hermes_events::EventDelivery::Event(event)) = event else {
            panic!("expected VIP change event");
        };
        assert!(matches!(
            event.as_ref(),
            HermesEvent::L3VipChanged {
                node_group_id,
                previous,
                current,
            } if node_group_id == "group-1"
                && *previous == Ipv4Addr::new(10, 0, 0, 1)
                && *current == Ipv4Addr::new(10, 0, 0, 2)
        ));
    }

    #[test]
    fn next_frame_rejects_a_foreign_version_byte() {
        assert!(matches!(
            next_frame(&[0x06, 0x94, 0x00, 0x01, 0xff]),
            Err(L3SessionError::UnexpectedVersion { byte: 0x06 })
        ));
    }

    /// Unknown `05` commands use the generic `<u16 len>` layout and do not end
    /// an otherwise healthy session.
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
        // The body is carried, not just counted: A5 needs its contents.
        assert_eq!(decoded, Inbound::Protocol { body: b"OK" });
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

    fn v2_auth() -> Vec<u8> {
        let json = br#"{}"#;
        let mut frame = vec![L3_VERSION, l3_cmd::AUTH_RESP, 0];
        frame.extend_from_slice(&(json.len() as u16).to_be_bytes());
        frame.extend_from_slice(json);
        frame
    }

    fn v2_status(cmd: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = vec![L3_VERSION, cmd, 0];
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    fn v2_generic(cmd: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = vec![L3_VERSION, cmd];
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    fn v2_data(packet: &[u8]) -> Vec<u8> {
        let mut frame = vec![L3_VERSION, l3_cmd::DATA_RESP];
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);
        frame
    }

    #[test]
    fn v2_prefixes_consumed_lengths_and_sentinels() {
        let fixtures = [
            v2_auth(),
            v2_status(L3_SECOND_VIP_RESP, br#"{}"#),
            v2_status(L3_VIP_UPDATE_RESP, br#"{"vip":"10.0.0.2"}"#),
            vec![L3_VERSION, l3_cmd::HEARTBEAT_RESP, 0, 0],
            v2_generic(0x42, b"abc"),
            vec![0x53, 0, 0, 2, b'O', b'K'],
            v2_data(&[1, 2, 3]),
        ];
        for fixture in fixtures {
            for end in 0..fixture.len() {
                assert_eq!(next_frame(&fixture[..end]).unwrap(), None, "prefix {end}");
            }
            let mut joined = fixture.clone();
            joined.extend_from_slice(&[L3_VERSION, l3_cmd::HEARTBEAT_RESP, 0, 0]);
            let (_, consumed) = next_frame(&joined).unwrap().unwrap();
            assert_eq!(consumed, fixture.len());
            assert_eq!(next_frame(&joined[consumed..]).unwrap().unwrap().1, 4);
        }
    }

    #[test]
    fn v2_pairwise_known_frames_preserve_dispatch_alignment() {
        let frames = [
            v2_auth(),
            v2_status(L3_SECOND_VIP_RESP, b"{}"),
            v2_status(L3_VIP_UPDATE_RESP, br#"{"vip":"10.0.0.2"}"#),
            vec![L3_VERSION, l3_cmd::HEARTBEAT_RESP, 0, 0],
            v2_generic(0x42, b"abc"),
            vec![0x53, 0, 0, 2, b'O', b'K'],
            v2_data(&[1, 2, 3]),
        ];
        for left in &frames {
            for right in &frames {
                let mut joined = left.clone();
                joined.extend_from_slice(right);
                let (_, first) = next_frame(&joined).unwrap().unwrap();
                let (_, second) = next_frame(&joined[first..]).unwrap().unwrap();
                assert_eq!(first, left.len());
                assert_eq!(second, right.len());
            }
        }
    }

    #[test]
    fn v2_ambiguous_and_malformed_frames_are_explicitly_not_accepted() {
        assert!(matches!(
            next_frame(&[0x06, 0x94, 0, 1, 0xff]),
            Err(L3SessionError::UnexpectedVersion { .. })
        ));
        assert!(matches!(
            next_frame(&[0x53, 7, 0, 0]),
            Err(L3SessionError::ProtocolRejected { status: 7 })
        ));
        assert_eq!(
            next_frame(&[L3_VERSION, 0x97, 0, 0, 4, b'{']).unwrap(),
            None
        );
        assert_eq!(next_frame(&[L3_VERSION, 0x42, 0, 5, 1, 2]).unwrap(), None);
        // A token length of 15 or a zero-leading length-16 token is ambiguous
        // with the length-prefixed branch and must not be guessed here.
    }
}
