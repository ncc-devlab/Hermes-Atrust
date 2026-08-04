//! One event stream for every runtime state change worth acting on.
//!
//! # Why this exists
//!
//! Structured `tracing` events are the right tool for *what happened*, but they
//! are a one-way, human-readable, after-the-fact record. Two consumers need
//! something else:
//!
//! - **A TUN layer needs to act on state changes.** When a reconnect assigns a
//!   new virtual IP, the interface address, the conntrack table and the routes
//!   are all stale. That fact currently exists only as an error return value on
//!   whichever call happened to be in flight, which is not something a device
//!   owner can subscribe to.
//! - **Protocol bring-up needs the surprises, not the log volume.** Unknown
//!   commands, an ambiguous `connectToken` length, and which `0x94` branch the
//!   gateway actually used are exactly the open questions in
//!   `docs/open-questions.md`; they must be observable without setting the whole
//!   process to `debug`.
//!
//! # Contract
//!
//! Publishing is **non-blocking, infallible and lossy**. It happens on the L3
//! read loop, so it must never be able to stall the protocol: a bus with no
//! subscribers discards, and a subscriber that falls behind is told how many
//! events it missed rather than silently seeing a gap. Events carry no
//! credentials — no SID, SignKey, cookie or `connectToken` value; token
//! *lengths* are reported because [`docs/open-questions.md`] A1 turns on them.
//!
//! [`docs/open-questions.md`]: ../../../docs/open-questions.md

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::broadcast;

/// Buffered events per subscriber before the slowest one starts losing them.
pub const DEFAULT_EVENT_CAPACITY: usize = 256;

/// Which `0x94` body layout the gateway used.
///
/// The two are told apart only by a numeric threshold on the leading `u16`
/// (see `atrust-protocol::l3_frame`), so the branch actually taken is a
/// protocol finding rather than a routine detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L3DataLayout {
    LengthPrefixed,
    TokenFramed,
}

impl L3DataLayout {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LengthPrefixed => "length_prefixed",
            Self::TokenFramed => "token_framed",
        }
    }
}

impl fmt::Display for L3DataLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How much attention an event deserves from a consumer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EventSeverity {
    /// Normal lifecycle progress.
    Info,
    /// Degraded but handled; the runtime is still trying.
    Warning,
    /// An observation that answers, or contradicts, a documented open question.
    /// These are the events worth keeping even when logs are discarded.
    Finding,
}

/// Every runtime state change a consumer can subscribe to.
///
/// Variants are additive: a consumer must tolerate unknown ones, so match with
/// a catch-all rather than exhaustively.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum HermesEvent {
    // ---- L3 connection lifecycle -------------------------------------------
    /// A node connection completed Get-IP and is carrying traffic.
    L3SessionEstablished {
        node_group_id: String,
        node_host: String,
        node_port: u16,
        vip: Ipv4Addr,
    },
    /// **The event a TUN device must handle.** A reconnect assigned a different
    /// virtual IP, so the interface address, every cached flow and any route
    /// pinned to the old address are now wrong.
    L3VipChanged {
        node_group_id: String,
        previous: Ipv4Addr,
        current: Ipv4Addr,
    },
    /// The connection for a node group ended. `reason` is a human string, not a
    /// stable discriminant.
    L3SessionClosed {
        node_group_id: String,
        reason: String,
    },
    /// A bounded reconnect is about to be attempted.
    L3Reconnecting {
        node_group_id: String,
        reason: &'static str,
        remaining_retries: usize,
    },
    /// One candidate endpoint failed; the manager will try the next.
    L3EndpointFailed {
        node_group_id: String,
        node_host: String,
        node_port: u16,
        error: String,
    },

    // ---- Flow authorization -------------------------------------------------
    L3FlowAuthorized {
        node_group_id: String,
        flow: String,
        app_id: String,
        connect_token_len: usize,
    },
    L3FlowRejected {
        node_group_id: String,
        flow: String,
        app_id: String,
        reason: String,
    },

    // ---- Protocol findings (docs/open-questions.md) -------------------------
    /// A1: the `0x94` discriminant is only safe for tokens long enough to push
    /// the leading `u16` past 4096. A shorter one will desynchronise the stream.
    L3ConnectTokenAmbiguous {
        connect_token_len: usize,
        minimum: usize,
    },
    /// A3/A4: an `05 <cmd>` this client has no handler for. Skipped generically,
    /// but a first-hand finding about the real gateway.
    L3UnknownCommand {
        cmd: u8,
    },
    /// A1: emitted the first time each `0x94` branch is observed, not per frame,
    /// so a saturated tunnel cannot turn a finding into a flood.
    L3DataLayoutObserved {
        layout: L3DataLayout,
        bytes: usize,
    },
    /// Inbound packets discarded because the consumer fell behind. Reported on a
    /// widening scale, carrying the running total.
    L3PacketsDropped {
        dropped_total: u64,
    },
    /// The conntrack table hit its cap and retired flows that had not yet gone
    /// idle. Flows are being opened faster than the idle TTL retires them, so
    /// the affected flows will pay one extra authorization round trip.
    L3ConntrackPressure {
        entries: usize,
        capacity: usize,
        evicted: usize,
    },

    // ---- TCP tunnel ---------------------------------------------------------
    /// One TCP tunnel completed its handshake against a node.
    TcpTunnelOpened {
        node_group_id: String,
        node_host: String,
        node_port: u16,
        app_id: String,
        target: String,
    },
    /// One candidate endpoint failed to produce a tunnel; another may be tried.
    TcpDialFailed {
        node_group_id: String,
        node_host: String,
        node_port: u16,
        target: String,
        error: String,
    },

    // ---- Control plane ------------------------------------------------------
    /// A complete `clientResource` generation was published atomically.
    ResourcePublished {
        generation: u64,
        ip_resources: usize,
        domain_resources: usize,
        node_groups: usize,
    },
    /// A refresh failed; the previous generation is still in use. Consecutive
    /// failures are counted so a consumer can escalate rather than watch warnings.
    ResourceRefreshFailed {
        generation_in_use: u64,
        consecutive_failures: u32,
        error: String,
    },
    /// The gateway rejected the stored session. Nothing downstream can recover
    /// from this without a fresh login, so it is a distinct event rather than
    /// another refresh failure.
    SessionInvalidated {
        reason: String,
    },

    // ---- Node group reconciliation -----------------------------------------
    NodeEndpointsUpdated {
        node_group_id: String,
        endpoint_count: usize,
    },
    NodeGroupRetired {
        node_group_id: String,
    },
}

impl HermesEvent {
    /// Stable slug for filtering and for log correlation. Kept in sync with the
    /// `event =` names used by `tracing` in the emitting crate.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::L3SessionEstablished { .. } => "l3.session_established",
            Self::L3VipChanged { .. } => "l3.vip_changed",
            Self::L3SessionClosed { .. } => "l3.session_closed",
            Self::L3Reconnecting { .. } => "l3.reconnecting",
            Self::L3EndpointFailed { .. } => "l3.endpoint_failed",
            Self::L3FlowAuthorized { .. } => "l3.flow_authorized",
            Self::L3FlowRejected { .. } => "l3.flow_rejected",
            Self::L3ConnectTokenAmbiguous { .. } => "l3.connect_token_ambiguous",
            Self::L3UnknownCommand { .. } => "l3.unknown_command",
            Self::L3DataLayoutObserved { .. } => "l3.data_layout_observed",
            Self::L3PacketsDropped { .. } => "l3.packets_dropped",
            Self::L3ConntrackPressure { .. } => "l3.conntrack_pressure",
            Self::TcpTunnelOpened { .. } => "tcp.tunnel_opened",
            Self::TcpDialFailed { .. } => "tcp.dial_failed",
            Self::ResourcePublished { .. } => "resource.published",
            Self::ResourceRefreshFailed { .. } => "resource.refresh_failed",
            Self::SessionInvalidated { .. } => "session.invalidated",
            Self::NodeEndpointsUpdated { .. } => "node.endpoints_updated",
            Self::NodeGroupRetired { .. } => "node.group_retired",
        }
    }

    #[must_use]
    pub fn severity(&self) -> EventSeverity {
        match self {
            Self::L3ConnectTokenAmbiguous { .. }
            | Self::L3UnknownCommand { .. }
            | Self::L3DataLayoutObserved { .. } => EventSeverity::Finding,
            Self::L3VipChanged { .. }
            | Self::L3SessionClosed { .. }
            | Self::L3Reconnecting { .. }
            | Self::L3EndpointFailed { .. }
            | Self::L3FlowRejected { .. }
            | Self::L3PacketsDropped { .. }
            | Self::L3ConntrackPressure { .. }
            | Self::TcpDialFailed { .. }
            | Self::ResourceRefreshFailed { .. }
            | Self::SessionInvalidated { .. }
            | Self::NodeGroupRetired { .. } => EventSeverity::Warning,
            Self::L3SessionEstablished { .. }
            | Self::L3FlowAuthorized { .. }
            | Self::TcpTunnelOpened { .. }
            | Self::ResourcePublished { .. }
            | Self::NodeEndpointsUpdated { .. } => EventSeverity::Info,
        }
    }
}

/// What a subscriber receives.
///
/// `Lagged` is a delivered value rather than an error because a consumer that
/// missed events needs to *know* it missed them — a TUN layer that skipped an
/// [`HermesEvent::L3VipChanged`] must resynchronise, not carry on.
#[derive(Clone, Debug)]
pub enum EventDelivery {
    Event(Arc<HermesEvent>),
    Lagged { skipped: u64 },
}

/// Fan-out point for runtime events.
///
/// Cheap to clone behind an [`Arc`]; publishing with no subscribers costs one
/// atomic and drops the event.
#[derive(Debug)]
pub struct EventBus {
    sender: broadcast::Sender<Arc<HermesEvent>>,
    published: AtomicU64,
}

impl EventBus {
    #[must_use]
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            sender: broadcast::channel(capacity.max(1)).0,
            published: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn with_default_capacity() -> Arc<Self> {
        Self::new(DEFAULT_EVENT_CAPACITY)
    }

    /// Publishes one event. Never blocks, never fails, never panics.
    ///
    /// A send error means "nobody is listening", which is not a runtime problem
    /// and must not surface to the protocol path that emitted it.
    pub fn publish(&self, event: HermesEvent) {
        self.published.fetch_add(1, Ordering::Relaxed);
        let _ = self.sender.send(Arc::new(event));
    }

    #[must_use]
    pub fn subscribe(&self) -> EventStream {
        EventStream {
            receiver: self.sender.subscribe(),
        }
    }

    /// Total events published, including those nobody was listening for.
    #[must_use]
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

/// One subscriber's view of the bus.
#[derive(Debug)]
pub struct EventStream {
    receiver: broadcast::Receiver<Arc<HermesEvent>>,
}

impl EventStream {
    /// Waits for the next delivery, or `None` once every publisher is gone.
    pub async fn recv(&mut self) -> Option<EventDelivery> {
        match self.receiver.recv().await {
            Ok(event) => Some(EventDelivery::Event(event)),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                Some(EventDelivery::Lagged { skipped })
            }
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }

    /// Takes an event only if one is already buffered.
    pub fn try_recv(&mut self) -> Option<EventDelivery> {
        match self.receiver.try_recv() {
            Ok(event) => Some(EventDelivery::Event(event)),
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                Some(EventDelivery::Lagged { skipped })
            }
            Err(_) => None,
        }
    }
}

/// Emits into an optional bus without building the event when nobody wants it.
///
/// Every protocol crate holds its bus as `Option<Arc<EventBus>>` so that the
/// event stream stays an opt-in observation channel rather than a construction
/// requirement for tests and offline use.
pub trait OptionalEventBus {
    fn emit(&self, event: impl FnOnce() -> HermesEvent);
}

impl OptionalEventBus for Option<Arc<EventBus>> {
    fn emit(&self, event: impl FnOnce() -> HermesEvent) {
        if let Some(bus) = self {
            bus.publish(event());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vip_changed() -> HermesEvent {
        HermesEvent::L3VipChanged {
            node_group_id: "group".to_owned(),
            previous: Ipv4Addr::new(10, 0, 0, 1),
            current: Ipv4Addr::new(10, 0, 0, 2),
        }
    }

    #[tokio::test]
    async fn a_subscriber_receives_published_events_in_order() {
        let bus = EventBus::with_default_capacity();
        let mut stream = bus.subscribe();

        bus.publish(vip_changed());
        bus.publish(HermesEvent::L3UnknownCommand { cmd: 0x42 });

        let first = stream.recv().await.expect("first event");
        let second = stream.recv().await.expect("second event");
        assert!(matches!(first, EventDelivery::Event(event) if event.kind() == "l3.vip_changed"));
        assert!(
            matches!(second, EventDelivery::Event(event) if event.kind() == "l3.unknown_command")
        );
        assert_eq!(bus.published(), 2);
    }

    /// Publishing must be free of back-pressure: the protocol path emits from
    /// the L3 read loop, where blocking would stall flow authorization.
    #[tokio::test]
    async fn publishing_without_subscribers_is_dropped_not_buffered() {
        let bus = EventBus::new(1);
        for _ in 0..1000 {
            bus.publish(HermesEvent::L3PacketsDropped { dropped_total: 1 });
        }
        assert_eq!(bus.published(), 1000);
        assert_eq!(bus.subscriber_count(), 0);
    }

    /// A slow consumer must be told it missed events rather than silently
    /// resuming — a skipped VIP change would leave a TUN device misconfigured.
    #[tokio::test]
    async fn a_lagging_subscriber_is_told_how_many_it_missed() {
        let bus = EventBus::new(2);
        let mut stream = bus.subscribe();

        for cmd in 0..6u8 {
            bus.publish(HermesEvent::L3UnknownCommand { cmd });
        }

        let delivery = stream.recv().await.expect("lag notice");
        let EventDelivery::Lagged { skipped } = delivery else {
            panic!("expected a lag notice, got {delivery:?}");
        };
        assert_eq!(skipped, 4);
        // The stream stays usable afterwards.
        assert!(matches!(stream.recv().await, Some(EventDelivery::Event(_))));
    }

    #[tokio::test]
    async fn a_closed_bus_ends_the_stream() {
        let bus = EventBus::with_default_capacity();
        let mut stream = bus.subscribe();
        bus.publish(vip_changed());
        drop(bus);

        assert!(matches!(stream.recv().await, Some(EventDelivery::Event(_))));
        assert!(stream.recv().await.is_none());
    }

    #[test]
    fn findings_outrank_warnings_so_consumers_can_filter_on_severity() {
        assert!(EventSeverity::Finding > EventSeverity::Warning);
        assert!(EventSeverity::Warning > EventSeverity::Info);
        assert_eq!(
            HermesEvent::L3UnknownCommand { cmd: 1 }.severity(),
            EventSeverity::Finding
        );
        assert_eq!(vip_changed().severity(), EventSeverity::Warning);
    }

    #[test]
    fn an_absent_bus_never_builds_the_event() {
        let bus: Option<Arc<EventBus>> = None;
        bus.emit(|| panic!("the event must not be constructed without a bus"));
    }
}
