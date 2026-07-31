//! Per-flow conntrack and connectToken state (Go `conntrackMgr` parity).
//!
//! Auth wait is 8 seconds. One outstanding auth attempt per flow key.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;

/// Default wait for a per-flow `0x93` response (Go `ensureAuth`).
pub const L3_AUTH_TIMEOUT: Duration = Duration::from_secs(8);

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
}

impl ConntrackEntry {
    #[must_use]
    pub fn auth_started(&self) -> bool {
        self.auth_started
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
#[derive(Debug, Default)]
pub struct ConntrackTable {
    next_auth_id: AtomicU64,
    by_key: HashMap<FlowKey, ConntrackEntry>,
    by_id: HashMap<u64, FlowKey>,
}

impl ConntrackTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns existing entry or creates one with a fresh `auth_id`.
    pub fn get_or_create(
        &mut self,
        key: FlowKey,
        app_id: impl Into<String>,
        node_group_id: impl Into<String>,
    ) -> &mut ConntrackEntry {
        if self.by_key.contains_key(&key) {
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
