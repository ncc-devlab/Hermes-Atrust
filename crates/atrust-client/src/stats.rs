use std::net::Ipv4Addr;

/// A point-in-time view of the runtime.
///
/// Every field here is state the runtime already computed and previously threw
/// away — packet drops, the resource generation in use, consecutive refresh
/// failures. A log line cannot answer "what is true right now", which is
/// exactly what a diagnostic run and a future control UI both need.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientStats {
    pub resource_generation: u64,
    pub consecutive_refresh_failures: u32,
    pub ip_resources: usize,
    pub domain_resources: usize,
    pub node_groups_advertised: usize,
    /// Node groups with a manager, i.e. those routing has actually selected.
    pub node_groups_active: usize,
    pub events_published: u64,
    pub groups: Vec<NodeGroupStats>,
}

/// Per-node-group connection state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGroupStats {
    pub node_group_id: String,
    /// `None` when no connection has been established yet.
    pub vip: Option<Ipv4Addr>,
    /// False when the manager holds no live connection; the next packet will
    /// establish one.
    pub connected: bool,
    /// Inbound packets discarded because the consumer fell behind. Non-zero
    /// means the tunnel outran whoever is draining it.
    pub dropped_packets: u64,
    /// Flows currently tracked on this connection. Bounded by
    /// `atrust_l3::L3_CONNTRACK_CAPACITY`; a value pinned at the cap means the
    /// table is thrashing rather than merely busy.
    pub tracked_flows: usize,
}
