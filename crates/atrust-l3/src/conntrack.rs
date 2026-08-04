//! Per-flow conntrack and connectToken state (Go `conntrackMgr` parity).
//!
//! Auth wait is 8 seconds. One outstanding auth attempt per flow key.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default wait for a per-flow `0x93` response (Go `ensureAuth`).
pub const L3_AUTH_TIMEOUT: Duration = Duration::from_secs(8);

/// How long an authorized flow survives without carrying a packet.
///
/// **This is a deliberate divergence from zju-connect, which never expires a
/// conntrack entry.** That is survivable for a short-lived process and a memory
/// leak for a long-lived tunnel: every short connection burns a fresh source
/// port, so an hour of ordinary browsing produces tens of thousands of distinct
/// five-tuples that would otherwise be retained until the connection dies.
///
/// 5 minutes is chosen against two measured quantities rather than as a round
/// number: re-authorization costs one round trip (~30 ms on the Xidian link,
/// 2026-08-04), and common HTTP keep-alive idles are 60–120 s. The TTL sits
/// above the latter so interactive flows are not churned, and the penalty when
/// it does fire is one extra round trip on the next packet.
pub const L3_CONNTRACK_IDLE_TTL: Duration = Duration::from_secs(300);

/// Hard cap on tracked flows per connection.
///
/// Roughly 250 bytes per entry (flow key, two UUIDs, a 32-byte token, and two
/// hash map slots), so the cap bounds the table near 2 MB. Reaching it means
/// the client is opening flows faster than [`L3_CONNTRACK_IDLE_TTL`] retires
/// them, which is a condition worth surfacing rather than absorbing silently.
pub const L3_CONNTRACK_CAPACITY: usize = 8192;

/// Stable key for one L3 flow (Go `connTrackKey`).
///
/// Format: `{atype}:{src}:{srcPort}-{dst}:{dstPort}`. Protocol is not included
/// until live capture confirms server requirements.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey(String);

impl FlowKey {
    /// Builds the Go-compatible flow key string.
    #[must_use]
    pub fn new(atype: u8, src: &str, src_port: u16, dst: &str, dst_port: u16) -> Self {
        Self(format!("{atype}:{src}:{src_port}-{dst}:{dst_port}"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Outcome after auth completes (or fails).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthOutcome {
    /// Server returned a non-empty connect token.
    Ready { connect_token: String },
    /// Auth failed; flow must not send `0x14` data.
    Failed { message: String },
}

impl AuthOutcome {
    #[must_use]
    pub fn connect_token(&self) -> Option<&str> {
        match self {
            Self::Ready { connect_token } => Some(connect_token.as_str()),
            Self::Failed { .. } => None,
        }
    }
}

/// Mutable per-flow entry.
#[derive(Debug)]
pub struct ConntrackEntry {
    pub key: FlowKey,
    /// Client-generated id sent as `conntrackHash` (Go `authID`).
    pub auth_id: u64,
    pub app_id: String,
    pub node_group_id: String,
    auth_started: bool,
    outcome: Option<AuthOutcome>,
    /// Last time a packet touched this flow. Drives idle expiry.
    last_used: Instant,
}

impl ConntrackEntry {
    #[must_use]
    pub fn auth_started(&self) -> bool {
        self.auth_started
    }

    #[must_use]
    pub fn last_used(&self) -> Instant {
        self.last_used
    }

    /// True while a `0x13` is outstanding and no verdict has arrived.
    ///
    /// Such an entry must never be pruned: a caller is blocked on its waiter,
    /// and removing it would strand that caller for the full auth timeout even
    /// though the answer was still coming.
    #[must_use]
    pub fn auth_in_flight(&self) -> bool {
        self.auth_started && self.outcome.is_none()
    }

    #[must_use]
    pub fn outcome(&self) -> Option<&AuthOutcome> {
        self.outcome.as_ref()
    }

    /// Marks that an auth request has been (or is about to be) sent.
    ///
    /// Returns `true` if this call won the race and the caller should send `0x13`.
    pub fn try_start_auth(&mut self) -> bool {
        if self.auth_started {
            return false;
        }
        self.auth_started = true;
        true
    }

    /// Completes auth (success or failure). Idempotent after first completion.
    pub fn complete(&mut self, outcome: AuthOutcome) {
        if self.outcome.is_none() {
            self.outcome = Some(outcome);
        }
    }
}

/// Conntrack table keyed by flow and by auth id (Go `conntrackMgr`).
#[derive(Debug)]
pub struct ConntrackTable {
    next_auth_id: AtomicU64,
    by_key: HashMap<FlowKey, ConntrackEntry>,
    by_id: HashMap<u64, FlowKey>,
    idle_ttl: Duration,
    capacity: usize,
}

impl Default for ConntrackTable {
    fn default() -> Self {
        Self::with_limits(L3_CONNTRACK_IDLE_TTL, L3_CONNTRACK_CAPACITY)
    }
}

/// What one prune pass removed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PruneOutcome {
    /// Entries retired for exceeding the idle TTL. Routine.
    pub expired: usize,
    /// Entries retired early because the table was full. Not routine: it means
    /// flows are being created faster than the TTL retires them.
    pub evicted_for_capacity: usize,
    /// Entries remaining afterwards.
    pub entries: usize,
}

impl PruneOutcome {
    #[must_use]
    pub fn removed_any(&self) -> bool {
        self.expired > 0 || self.evicted_for_capacity > 0
    }
}

impl ConntrackTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_limits(idle_ttl: Duration, capacity: usize) -> Self {
        Self {
            next_auth_id: AtomicU64::new(0),
            by_key: HashMap::new(),
            by_id: HashMap::new(),
            idle_ttl,
            capacity: capacity.max(1),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Retires idle flows, then trims to capacity by least-recently-used.
    ///
    /// Call this before creating an entry rather than on a timer: it keeps the
    /// table bounded without a second task contending for the same lock, and
    /// the only moment the bound can be exceeded is the moment a flow is added.
    pub fn prune(&mut self) -> PruneOutcome {
        self.prune_at(Instant::now())
    }

    /// [`Self::prune`] against a caller-supplied clock.
    pub fn prune_at(&mut self, now: Instant) -> PruneOutcome {
        let mut outcome = PruneOutcome::default();

        let expired: Vec<FlowKey> = self
            .by_key
            .values()
            .filter(|entry| {
                !entry.auth_in_flight()
                    && now.saturating_duration_since(entry.last_used) >= self.idle_ttl
            })
            .map(|entry| entry.key.clone())
            .collect();
        for key in expired {
            self.evict(&key);
            outcome.expired += 1;
        }

        // Capacity is enforced only against settled entries. An in-flight auth
        // clears itself within the 8s timeout, so a table that is briefly all
        // in-flight is self-limiting; refusing to track a new flow there would
        // turn a transient burst into dropped traffic.
        while self.by_key.len() >= self.capacity {
            let Some(victim) = self
                .by_key
                .values()
                .filter(|entry| !entry.auth_in_flight())
                .min_by_key(|entry| entry.last_used)
                .map(|entry| entry.key.clone())
            else {
                break;
            };
            self.evict(&victim);
            outcome.evicted_for_capacity += 1;
        }

        outcome.entries = self.by_key.len();
        outcome
    }

    /// Returns existing entry or creates one with a fresh `auth_id`.
    ///
    /// Touching an existing flow refreshes its idle clock, so an active flow is
    /// never retired underneath a caller that is still sending on it.
    pub fn get_or_create(
        &mut self,
        key: FlowKey,
        app_id: impl Into<String>,
        node_group_id: impl Into<String>,
    ) -> &mut ConntrackEntry {
        self.get_or_create_at(key, app_id, node_group_id, Instant::now())
    }

    /// [`Self::get_or_create`] against a caller-supplied clock.
    pub fn get_or_create_at(
        &mut self,
        key: FlowKey,
        app_id: impl Into<String>,
        node_group_id: impl Into<String>,
        now: Instant,
    ) -> &mut ConntrackEntry {
        if let Some(entry) = self.by_key.get_mut(&key) {
            entry.last_used = now;
            return self.by_key.get_mut(&key).expect("key present");
        }
        let auth_id = self.next_auth_id.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = ConntrackEntry {
            key: key.clone(),
            auth_id,
            app_id: app_id.into(),
            node_group_id: node_group_id.into(),
            auth_started: false,
            outcome: None,
            last_used: now,
        };
        self.by_id.insert(auth_id, key.clone());
        self.by_key.insert(key.clone(), entry);
        self.by_key.get_mut(&key).expect("just inserted")
    }

    #[must_use]
    pub fn get_by_key(&self, key: &FlowKey) -> Option<&ConntrackEntry> {
        self.by_key.get(key)
    }

    pub fn get_by_key_mut(&mut self, key: &FlowKey) -> Option<&mut ConntrackEntry> {
        self.by_key.get_mut(key)
    }

    #[must_use]
    pub fn get_by_auth_id(&self, auth_id: u64) -> Option<&ConntrackEntry> {
        let key = self.by_id.get(&auth_id)?;
        self.by_key.get(key)
    }

    pub fn get_by_auth_id_mut(&mut self, auth_id: u64) -> Option<&mut ConntrackEntry> {
        let key = self.by_id.get(&auth_id)?.clone();
        self.by_key.get_mut(&key)
    }

    /// Completes auth for `auth_id` from a parsed `0x93` body.
    ///
    /// Empty tokens on success become a failure (Go requires connect token).
    pub fn mark_auth(
        &mut self,
        auth_id: u64,
        code: i64,
        message: impl Into<String>,
        connect_token: impl Into<String>,
    ) -> Result<(), ConntrackError> {
        let entry = self
            .get_by_auth_id_mut(auth_id)
            .ok_or(ConntrackError::UnknownAuthId(auth_id))?;
        let token = connect_token.into();
        let message = message.into();
        let outcome = if code != 0 {
            AuthOutcome::Failed {
                message: if message.is_empty() {
                    format!("auth failed: {code}")
                } else {
                    format!("auth failed: {code} {message}")
                },
            }
        } else if token.is_empty() {
            AuthOutcome::Failed {
                message: "missing connect token".to_owned(),
            }
        } else {
            AuthOutcome::Ready {
                connect_token: token,
            }
        };
        entry.complete(outcome);
        Ok(())
    }

    /// Drops one flow so the next packet re-authorizes from scratch.
    ///
    /// This is the "retry once" path: an auth timeout evicts the entry, and the
    /// caller may attempt a single fresh auth. The `auth_id` is not reused, so a
    /// late `0x93` for the evicted attempt lands on an unknown id and is dropped
    /// rather than reviving a flow the caller has given up on.
    pub fn evict(&mut self, key: &FlowKey) -> Option<ConntrackEntry> {
        let entry = self.by_key.remove(key)?;
        self.by_id.remove(&entry.auth_id);
        Some(entry)
    }

    /// Drops one flow addressed by its auth id.
    pub fn evict_by_auth_id(&mut self, auth_id: u64) -> Option<ConntrackEntry> {
        let key = self.by_id.get(&auth_id)?.clone();
        self.evict(&key)
    }

    /// Records a local error (send failure) without a server body.
    pub fn mark_auth_error(
        &mut self,
        auth_id: u64,
        message: impl Into<String>,
    ) -> Result<(), ConntrackError> {
        let entry = self
            .get_by_auth_id_mut(auth_id)
            .ok_or(ConntrackError::UnknownAuthId(auth_id))?;
        entry.complete(AuthOutcome::Failed {
            message: message.into(),
        });
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConntrackError {
    #[error("unknown conntrack auth id {0}")]
    UnknownAuthId(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_create_assigns_monotonic_auth_ids() {
        let mut table = ConntrackTable::new();
        let k1 = FlowKey::new(4, "10.0.0.1", 1, "10.0.0.2", 80);
        let k2 = FlowKey::new(4, "10.0.0.1", 2, "10.0.0.2", 80);
        let a1 = table.get_or_create(k1.clone(), "app", "g").auth_id;
        let a2 = table.get_or_create(k2, "app", "g").auth_id;
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(table.get_or_create(k1, "app", "g").auth_id, a1);
    }

    #[test]
    fn try_start_auth_only_once() {
        let mut table = ConntrackTable::new();
        let key = FlowKey::new(4, "1.1.1.1", 9, "2.2.2.2", 443);
        let entry = table.get_or_create(key, "a", "g");
        assert!(entry.try_start_auth());
        assert!(!entry.try_start_auth());
    }

    #[test]
    fn mark_auth_ready_and_failed() {
        let mut table = ConntrackTable::new();
        let key = FlowKey::new(4, "1.1.1.1", 1, "2.2.2.2", 80);
        let id = table.get_or_create(key.clone(), "a", "g").auth_id;
        table.mark_auth(id, 0, "", "tok-1").unwrap();
        assert_eq!(
            table.get_by_key(&key).unwrap().outcome(),
            Some(&AuthOutcome::Ready {
                connect_token: "tok-1".to_owned()
            })
        );

        let key2 = FlowKey::new(4, "1.1.1.1", 2, "2.2.2.2", 80);
        let id2 = table.get_or_create(key2.clone(), "a", "g").auth_id;
        table.mark_auth(id2, 1, "denied", "ignored").unwrap();
        assert!(matches!(
            table.get_by_key(&key2).unwrap().outcome(),
            Some(AuthOutcome::Failed { .. })
        ));
    }

    fn table(capacity: usize) -> ConntrackTable {
        ConntrackTable::with_limits(Duration::from_secs(300), capacity)
    }

    fn flow(port: u16) -> FlowKey {
        FlowKey::new(4, "10.0.0.1", port, "10.9.0.1", 80)
    }

    /// The leak this replaces: before idle expiry, every successful flow stayed
    /// until the connection died, and a browsing session burns a fresh source
    /// port per connection.
    #[test]
    fn an_idle_settled_flow_is_retired_but_an_active_one_is_not() {
        let mut table = table(64);
        let start = Instant::now();

        for port in [1000, 1001] {
            let entry = table.get_or_create_at(flow(port), "app", "group", start);
            entry.try_start_auth();
        }
        table
            .mark_auth(1, 0, "OK", "token-1")
            .expect("settle first flow");
        table
            .mark_auth(2, 0, "OK", "token-2")
            .expect("settle second flow");

        // One flow keeps carrying packets; the other goes quiet.
        let later = start + Duration::from_secs(299);
        table.get_or_create_at(flow(1000), "app", "group", later);

        let outcome = table.prune_at(start + Duration::from_secs(301));
        assert_eq!(outcome.expired, 1);
        assert_eq!(outcome.evicted_for_capacity, 0);
        assert_eq!(outcome.entries, 1);
        assert!(table.get_by_key(&flow(1000)).is_some(), "active flow kept");
        assert!(table.get_by_key(&flow(1001)).is_none(), "idle flow retired");
        // The retired flow's auth id must go with it, or a late 0x93 could
        // revive an entry the caller has forgotten.
        assert!(table.get_by_auth_id(2).is_none());
    }

    /// Pruning must never take an entry whose caller is still blocked on it:
    /// that would strand the waiter for the full auth timeout with the verdict
    /// already on its way.
    #[test]
    fn an_in_flight_auth_survives_both_expiry_and_capacity_pressure() {
        let mut table = table(1);
        let start = Instant::now();
        table
            .get_or_create_at(flow(1000), "app", "group", start)
            .try_start_auth();

        let outcome = table.prune_at(start + Duration::from_secs(3600));
        assert_eq!(outcome.expired, 0);
        assert_eq!(outcome.evicted_for_capacity, 0);
        assert_eq!(outcome.entries, 1, "the entry is still there");
        assert!(!outcome.removed_any());
        assert!(table.get_by_key(&flow(1000)).is_some());
        assert!(
            table
                .get_by_key(&flow(1000))
                .expect("entry")
                .auth_in_flight(),
            "the entry is exactly the one prune must refuse to take"
        );
    }

    #[test]
    fn capacity_pressure_evicts_the_least_recently_used_settled_flow() {
        let mut table = table(3);
        let start = Instant::now();

        for (index, port) in [1000u16, 1001, 1002].into_iter().enumerate() {
            let at = start + Duration::from_secs(index as u64);
            table
                .get_or_create_at(flow(port), "app", "group", at)
                .try_start_auth();
            table
                .mark_auth(index as u64 + 1, 0, "OK", "token")
                .expect("settle");
        }
        // 1000 is the oldest; touching it makes 1001 the least recent.
        table.get_or_create_at(flow(1000), "app", "group", start + Duration::from_secs(10));

        let outcome = table.prune_at(start + Duration::from_secs(11));
        assert_eq!(outcome.expired, 0);
        assert_eq!(outcome.evicted_for_capacity, 1);
        assert!(table.get_by_key(&flow(1001)).is_none(), "LRU evicted");
        assert!(table.get_by_key(&flow(1000)).is_some());
        assert!(table.get_by_key(&flow(1002)).is_some());
    }

    /// The bound is the point: a client that never stops opening flows must not
    /// be able to grow the table without limit.
    #[test]
    fn a_flood_of_settled_flows_stays_under_the_cap() {
        let mut table = table(16);
        let start = Instant::now();

        for index in 0..500u64 {
            let at = start + Duration::from_millis(index);
            let port = 10_000 + u16::try_from(index % 5000).expect("port fits");
            table.prune_at(at);
            let entry = table.get_or_create_at(flow(port), "app", "group", at);
            let auth_id = entry.auth_id;
            if entry.try_start_auth() {
                table.mark_auth(auth_id, 0, "OK", "token").expect("settle");
            }
            assert!(table.len() <= 16, "table exceeded the cap at {index}");
        }
    }

    #[test]
    fn evict_frees_the_flow_and_retires_the_auth_id() {
        let mut table = ConntrackTable::new();
        let key = FlowKey::new(4, "10.8.0.1", 5, "10.0.0.2", 80);
        let id = table.get_or_create(key.clone(), "app", "g").auth_id;

        assert!(table.evict(&key).is_some());
        assert!(table.get_by_key(&key).is_none());
        // A late response for the retired attempt must not resurrect the flow.
        assert_eq!(
            table.mark_auth(id, 0, "", "late-token"),
            Err(ConntrackError::UnknownAuthId(id))
        );

        // Re-creating the flow issues a fresh id and a clean auth state.
        let entry = table.get_or_create(key, "app", "g");
        assert_ne!(entry.auth_id, id);
        assert!(entry.outcome().is_none());
        assert!(entry.try_start_auth());
    }

    #[test]
    fn evict_by_auth_id_matches_evict_by_key() {
        let mut table = ConntrackTable::new();
        let key = FlowKey::new(4, "10.8.0.1", 6, "10.0.0.2", 443);
        let id = table.get_or_create(key.clone(), "app", "g").auth_id;
        assert!(table.evict_by_auth_id(id).is_some());
        assert!(table.get_by_key(&key).is_none());
        assert!(table.evict_by_auth_id(id).is_none());
    }

    #[test]
    fn empty_token_is_failure() {
        let mut table = ConntrackTable::new();
        let key = FlowKey::new(4, "a", 1, "b", 2);
        let id = table.get_or_create(key, "a", "g").auth_id;
        table.mark_auth(id, 0, "ok", "").unwrap();
        assert!(matches!(
            table.get_by_auth_id(id).unwrap().outcome(),
            Some(AuthOutcome::Failed { message }) if message.contains("missing connect token")
        ));
    }
}
