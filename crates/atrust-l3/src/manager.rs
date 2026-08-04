use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;

use hermes_events::{EventBus, HermesEvent, OptionalEventBus as _};
use hermes_model::SessionId;
use hermes_transport::TlsPolicy;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;

use crate::{
    Ipv4Flow, L3_AUTH_TIMEOUT_RETRIES, L3_CLOSED_RETRIES, L3_HEARTBEAT_INTERVAL, L3AuthContext,
    L3Session, L3SessionConfig, L3SessionError,
};

/// Owned inputs for a reconnectable L3 connection to one selected node group.
#[derive(Clone, Debug)]
pub struct L3SessionManagerConfig {
    pub endpoints: Vec<L3NodeEndpoint>,
    pub node_group_id: String,
    pub tls_policy: TlsPolicy,
    pub sid: SessionId,
    pub connect_timeout: Duration,
    pub heartbeat_interval: Duration,
    /// Observation channel for connection lifecycle and VIP changes.
    pub events: Option<Arc<EventBus>>,
}

impl L3SessionManagerConfig {
    pub fn with_default_heartbeat(
        endpoints: Vec<L3NodeEndpoint>,
        node_group_id: String,
        tls_policy: TlsPolicy,
        sid: SessionId,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            endpoints,
            node_group_id,
            tls_policy,
            sid,
            connect_timeout,
            heartbeat_interval: L3_HEARTBEAT_INTERVAL,
            events: None,
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Option<Arc<EventBus>>) -> Self {
        self.events = events;
        self
    }
}

/// One data-plane endpoint advertised for a node group.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct L3NodeEndpoint {
    pub host: String,
    pub port: u16,
}

impl L3NodeEndpoint {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

/// Authorization result tied to the exact session that issued the token.
#[derive(Debug)]
pub struct AuthorizedL3Flow {
    session: Arc<L3Session>,
    connect_token: String,
}

impl AuthorizedL3Flow {
    pub fn session(&self) -> &Arc<L3Session> {
        &self.session
    }

    pub fn connect_token(&self) -> &str {
        &self.connect_token
    }
}

/// Reconnect owner for one selected node group. It operates on raw IPv4 flows
/// and deliberately has no dependency on TUN, DNS, or system routes.
#[derive(Debug)]
pub struct L3SessionManager {
    config: L3SessionManagerConfig,
    endpoints: RwLock<Vec<L3NodeEndpoint>>,
    current: Mutex<SessionState>,
}

#[derive(Debug, Default)]
struct SessionState {
    session: Option<Arc<L3Session>>,
    next_endpoint: usize,
    /// VIP of the last established connection, kept across reconnects so a
    /// change can be reported. A new VIP invalidates every cached flow and any
    /// interface or route configured for the old one.
    last_vip: Option<Ipv4Addr>,
}

impl L3SessionManager {
    pub fn new(config: L3SessionManagerConfig) -> Self {
        let endpoints = deduplicate_endpoints(config.endpoints.clone());
        Self {
            config,
            endpoints: RwLock::new(endpoints),
            current: Mutex::new(SessionState::default()),
        }
    }

    /// Replaces the candidates used on the next connection attempt. A healthy
    /// session is not interrupted merely because a refresh reordered nodes.
    pub fn update_endpoints(&self, endpoints: Vec<L3NodeEndpoint>) {
        *self.endpoints.write().expect("L3 endpoint lock poisoned") =
            deduplicate_endpoints(endpoints);
    }

    #[must_use]
    pub fn node_group_id(&self) -> &str {
        &self.config.node_group_id
    }

    /// The current connection if one is live, without establishing a new one.
    ///
    /// Observation only: unlike [`Self::session`] this never dials, so polling
    /// it for statistics cannot trigger a reconnect.
    pub async fn current_session(&self) -> Option<Arc<L3Session>> {
        self.current
            .lock()
            .await
            .session
            .as_ref()
            .filter(|session| !session.is_closed())
            .map(Arc::clone)
    }

    /// VIP of the last established connection, whether or not it is still live.
    pub async fn last_vip(&self) -> Option<Ipv4Addr> {
        self.current.lock().await.last_vip
    }

    /// Returns the live session, establishing Get-IP lazily when absent/closed.
    pub async fn session(&self) -> Result<Arc<L3Session>, L3SessionManagerError> {
        let mut state = self.current.lock().await;
        if let Some(session) = state.session.as_ref()
            && !session.is_closed()
        {
            return Ok(Arc::clone(session));
        }
        if let Some(closed) = state.session.take() {
            closed.close().await;
        }
        let endpoints = self
            .endpoints
            .read()
            .expect("L3 endpoint lock poisoned")
            .clone();
        if endpoints.is_empty() {
            return Err(L3SessionManagerError::NoEndpoints {
                node_group_id: self.config.node_group_id.clone(),
            });
        }

        let start = state.next_endpoint % endpoints.len();
        let mut last_error = None;
        for offset in 0..endpoints.len() {
            let index = (start + offset) % endpoints.len();
            let endpoint = &endpoints[index];
            let result = L3Session::establish(L3SessionConfig {
                node_host: &endpoint.host,
                node_port: endpoint.port,
                tls_policy: self.config.tls_policy,
                sid: &self.config.sid,
                connect_timeout: self.config.connect_timeout,
                heartbeat_interval: self.config.heartbeat_interval,
                events: self.config.events.clone(),
            })
            .await;
            match result {
                Ok(session) => {
                    let session = Arc::new(session);
                    state.next_endpoint = (index + 1) % endpoints.len();
                    state.session = Some(Arc::clone(&session));
                    self.report_established(&mut state, endpoint, session.vip());
                    return Ok(session);
                }
                Err(error) if establishment_is_retryable(&error) => {
                    warn!(
                        event = "atrust_l3.manager.endpoint_failed",
                        node_group_id = %self.config.node_group_id,
                        node_host = %endpoint.host,
                        node_port = endpoint.port,
                        error = %error
                    );
                    self.config.events.emit(|| HermesEvent::L3EndpointFailed {
                        node_group_id: self.config.node_group_id.clone(),
                        node_host: endpoint.host.clone(),
                        node_port: endpoint.port,
                        error: error.to_string(),
                    });
                    last_error = Some(error);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(last_error
            .expect("non-empty endpoint list produced an error")
            .into())
    }

    /// Announces a fresh connection, and separately announces a VIP change.
    ///
    /// The two are distinct events on purpose. Establishment is routine; a VIP
    /// that differs from the previous one means every authorized flow, every
    /// interface address and every route pinned to the old VIP is now wrong,
    /// and a consumer must be able to react to that alone.
    fn report_established(
        &self,
        state: &mut SessionState,
        endpoint: &L3NodeEndpoint,
        vip: Ipv4Addr,
    ) {
        let previous = state.last_vip.replace(vip);
        self.config
            .events
            .emit(|| HermesEvent::L3SessionEstablished {
                node_group_id: self.config.node_group_id.clone(),
                node_host: endpoint.host.clone(),
                node_port: endpoint.port,
                vip,
            });
        if let Some(previous) = previous
            && previous != vip
        {
            warn!(
                event = "atrust_l3.manager.vip_changed",
                node_group_id = %self.config.node_group_id,
                previous = %previous,
                current = %vip
            );
            self.config.events.emit(|| HermesEvent::L3VipChanged {
                node_group_id: self.config.node_group_id.clone(),
                previous,
                current: vip,
            });
        }
    }

    /// Authorizes a flow, reconnecting on closed sessions and once after auth
    /// timeout. Explicit server policy failures are returned without retry.
    pub async fn authorize_flow(
        &self,
        ctx: &L3AuthContext<'_>,
        app_id: &str,
        flow: &Ipv4Flow,
    ) -> Result<AuthorizedL3Flow, L3SessionManagerError> {
        let mut budget = RetryBudget::default();
        self.authorize_with_budget(ctx, app_id, flow, &mut budget)
            .await
    }

    /// Authorizes and flushes one packet. A write-side disconnect reconnects,
    /// reauthorizes, and retries under the same bounded policy.
    pub async fn authorize_and_send(
        &self,
        ctx: &L3AuthContext<'_>,
        app_id: &str,
        flow: &Ipv4Flow,
        packet: &[u8],
    ) -> Result<AuthorizedL3Flow, L3SessionManagerError> {
        let mut budget = RetryBudget::default();
        loop {
            let authorized = self
                .authorize_with_budget(ctx, app_id, flow, &mut budget)
                .await?;
            match authorized
                .session
                .send_packet(&authorized.connect_token, packet)
                .await
            {
                Ok(()) => return Ok(authorized),
                Err(error) => match budget.consume(&error) {
                    Some(retry) => {
                        self.report_retry(&retry);
                        self.invalidate(&authorized.session).await;
                    }
                    None => return Err(error.into()),
                },
            }
        }
    }

    async fn authorize_with_budget(
        &self,
        ctx: &L3AuthContext<'_>,
        app_id: &str,
        flow: &Ipv4Flow,
        budget: &mut RetryBudget,
    ) -> Result<AuthorizedL3Flow, L3SessionManagerError> {
        loop {
            let session = self.session().await?;
            if session.vip() != flow.src_addr {
                return Err(L3SessionManagerError::VipChanged {
                    packet_source: flow.src_addr,
                    session_vip: session.vip(),
                });
            }
            match session
                .authorize_flow(ctx, app_id, &self.config.node_group_id, flow)
                .await
            {
                Ok(connect_token) => {
                    self.config.events.emit(|| HermesEvent::L3FlowAuthorized {
                        node_group_id: self.config.node_group_id.clone(),
                        flow: flow.flow_key().to_string(),
                        app_id: app_id.to_owned(),
                        connect_token_len: connect_token.len(),
                    });
                    return Ok(AuthorizedL3Flow {
                        session,
                        connect_token,
                    });
                }
                Err(error) => match budget.consume(&error) {
                    Some(retry) => {
                        self.report_retry(&retry);
                        self.invalidate(&session).await;
                    }
                    None => {
                        self.config.events.emit(|| HermesEvent::L3FlowRejected {
                            node_group_id: self.config.node_group_id.clone(),
                            flow: flow.flow_key().to_string(),
                            app_id: app_id.to_owned(),
                            reason: error.to_string(),
                        });
                        return Err(error.into());
                    }
                },
            }
        }
    }

    fn report_retry(&self, retry: &RetryDecision) {
        warn!(
            event = "atrust_l3.manager.reconnect",
            reason = retry.reason,
            remaining_retries = retry.remaining
        );
        self.config.events.emit(|| HermesEvent::L3Reconnecting {
            node_group_id: self.config.node_group_id.clone(),
            reason: retry.reason,
            remaining_retries: retry.remaining,
        });
    }

    async fn invalidate(&self, failed: &Arc<L3Session>) {
        let removed = {
            let mut state = self.current.lock().await;
            if state
                .session
                .as_ref()
                .is_some_and(|session| Arc::ptr_eq(session, failed))
            {
                state.session.take()
            } else {
                None
            }
        };
        if let Some(session) = removed {
            session.close().await;
            self.report_closed("session invalidated after a failed operation");
        }
    }

    pub async fn close(&self) {
        if let Some(session) = self.current.lock().await.session.take() {
            session.close().await;
            self.report_closed("closed by caller");
        }
    }

    fn report_closed(&self, reason: &str) {
        self.config.events.emit(|| HermesEvent::L3SessionClosed {
            node_group_id: self.config.node_group_id.clone(),
            reason: reason.to_owned(),
        });
    }
}

fn deduplicate_endpoints(endpoints: Vec<L3NodeEndpoint>) -> Vec<L3NodeEndpoint> {
    let mut seen = HashSet::new();
    endpoints
        .into_iter()
        .filter(|endpoint| seen.insert(endpoint.clone()))
        .collect()
}

fn establishment_is_retryable(error: &L3SessionError) -> bool {
    use crate::GetIpv4Error;

    matches!(
        error,
        L3SessionError::Tls(_)
            | L3SessionError::ConnectTimeout
            | L3SessionError::GetIp(
                GetIpv4Error::Timeout | GetIpv4Error::Tls(_) | GetIpv4Error::Io(_)
            )
    )
}

/// Authenticated-session-scoped cache of reconnect owners, keyed by node group.
#[derive(Debug)]
pub struct L3SessionManagerCache {
    tls_policy: TlsPolicy,
    sid: SessionId,
    connect_timeout: Duration,
    heartbeat_interval: Duration,
    events: Option<Arc<EventBus>>,
    managers: StdMutex<HashMap<String, CachedManager>>,
}

#[derive(Debug)]
struct CachedManager {
    manager: Arc<L3SessionManager>,
    resource_generation: u64,
}

impl L3SessionManagerCache {
    pub fn with_default_heartbeat(
        tls_policy: TlsPolicy,
        sid: SessionId,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            tls_policy,
            sid,
            connect_timeout,
            heartbeat_interval: L3_HEARTBEAT_INTERVAL,
            events: None,
            managers: StdMutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn with_heartbeat_interval(mut self, heartbeat_interval: Duration) -> Self {
        self.heartbeat_interval = heartbeat_interval;
        self
    }

    /// Attaches an observation channel inherited by every manager this cache
    /// creates from here on.
    #[must_use]
    pub fn with_events(mut self, events: Option<Arc<EventBus>>) -> Self {
        self.events = events;
        self
    }

    /// Returns the stable manager for a group and refreshes its future failover
    /// candidates without holding the cache lock during network operations.
    pub fn manager(
        &self,
        node_group_id: &str,
        endpoints: Vec<L3NodeEndpoint>,
    ) -> Arc<L3SessionManager> {
        self.manager_for_generation(node_group_id, endpoints, 0)
    }

    /// Generation-aware lookup used with `ResourceSnapshot`. An older flow
    /// snapshot cannot overwrite endpoint candidates published by a refresh.
    pub fn manager_for_generation(
        &self,
        node_group_id: &str,
        endpoints: Vec<L3NodeEndpoint>,
        resource_generation: u64,
    ) -> Arc<L3SessionManager> {
        let mut managers = self.managers.lock().expect("L3 manager cache poisoned");
        let cached = managers
            .entry(node_group_id.to_owned())
            .or_insert_with(|| CachedManager {
                manager: Arc::new(L3SessionManager::new(L3SessionManagerConfig {
                    endpoints: endpoints.clone(),
                    node_group_id: node_group_id.to_owned(),
                    tls_policy: self.tls_policy,
                    sid: self.sid.clone(),
                    connect_timeout: self.connect_timeout,
                    heartbeat_interval: self.heartbeat_interval,
                    events: self.events.clone(),
                })),
                resource_generation,
            });
        if resource_generation >= cached.resource_generation {
            cached.manager.update_endpoints(endpoints);
            cached.resource_generation = resource_generation;
        }
        Arc::clone(&cached.manager)
    }

    pub fn len(&self) -> usize {
        self.managers
            .lock()
            .expect("L3 manager cache poisoned")
            .len()
    }

    /// Every manager currently cached, for observation and control.
    #[must_use]
    pub fn managers(&self) -> Vec<Arc<L3SessionManager>> {
        self.managers
            .lock()
            .expect("L3 manager cache poisoned")
            .values()
            .map(|cached| Arc::clone(&cached.manager))
            .collect()
    }

    /// Looks up an existing manager without creating one.
    #[must_use]
    pub fn get(&self, node_group_id: &str) -> Option<Arc<L3SessionManager>> {
        self.managers
            .lock()
            .expect("L3 manager cache poisoned")
            .get(node_group_id)
            .map(|cached| Arc::clone(&cached.manager))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Applies one complete resource generation to managers already in use.
    /// New groups remain lazy; removed groups are closed and evicted.
    pub async fn reconcile(
        &self,
        resource_generation: u64,
        groups: &HashMap<String, Vec<L3NodeEndpoint>>,
    ) {
        let (updated, removed) = {
            let mut managers = self.managers.lock().expect("L3 manager cache poisoned");
            let removed_ids = managers
                .iter()
                .filter(|(group_id, cached)| {
                    resource_generation >= cached.resource_generation
                        && !groups.contains_key(*group_id)
                })
                .map(|(group_id, _)| group_id.clone())
                .collect::<Vec<_>>();
            let removed = removed_ids
                .into_iter()
                .filter_map(|group_id| managers.remove(&group_id).map(|cached| cached.manager))
                .collect::<Vec<_>>();
            let updated = managers
                .iter_mut()
                .filter_map(|(group_id, cached)| {
                    if resource_generation < cached.resource_generation {
                        return None;
                    }
                    cached.resource_generation = resource_generation;
                    Some((Arc::clone(&cached.manager), groups.get(group_id)?.clone()))
                })
                .collect::<Vec<_>>();
            (updated, removed)
        };
        for (manager, endpoints) in updated {
            let endpoint_count = endpoints.len();
            manager.update_endpoints(endpoints);
            self.events.emit(|| HermesEvent::NodeEndpointsUpdated {
                node_group_id: manager.config.node_group_id.clone(),
                endpoint_count,
            });
        }
        for manager in removed {
            manager.close().await;
            self.events.emit(|| HermesEvent::NodeGroupRetired {
                node_group_id: manager.config.node_group_id.clone(),
            });
        }
    }

    pub async fn close(&self) {
        let managers = {
            let mut cache = self.managers.lock().expect("L3 manager cache poisoned");
            cache
                .drain()
                .map(|(_, cached)| cached.manager)
                .collect::<Vec<_>>()
        };
        for manager in managers {
            manager.close().await;
        }
    }
}

#[derive(Debug)]
struct RetryBudget {
    closed: usize,
    auth_timeout: usize,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self {
            closed: L3_CLOSED_RETRIES,
            auth_timeout: L3_AUTH_TIMEOUT_RETRIES,
        }
    }
}

/// A granted retry. Returned rather than logged inside the budget so the
/// caller, which knows the node group, owns both the log line and the event.
#[derive(Debug, Eq, PartialEq)]
struct RetryDecision {
    reason: &'static str,
    remaining: usize,
}

impl RetryBudget {
    fn consume(&mut self, error: &L3SessionError) -> Option<RetryDecision> {
        let (remaining, reason) = match error {
            L3SessionError::Closed if self.closed > 0 => (&mut self.closed, "closed"),
            L3SessionError::AuthTimeout { .. } if self.auth_timeout > 0 => {
                (&mut self.auth_timeout, "auth_timeout")
            }
            _ => return None,
        };
        *remaining -= 1;
        Some(RetryDecision {
            reason,
            remaining: *remaining,
        })
    }
}

#[derive(Debug, Error)]
pub enum L3SessionManagerError {
    #[error(transparent)]
    Session(#[from] L3SessionError),
    #[error("node group {node_group_id} has no data-plane endpoints")]
    NoEndpoints { node_group_id: String },
    #[error("L3 reconnect changed VIP from packet source {packet_source} to {session_vip}")]
    VipChanged {
        packet_source: std::net::Ipv4Addr,
        session_vip: std::net::Ipv4Addr,
    },
}

#[cfg(test)]
mod tests {
    use hermes_events::EventDelivery;

    use super::*;
    use crate::FlowAuthError;

    fn endpoint(host: &str) -> L3NodeEndpoint {
        L3NodeEndpoint::new(host.to_owned(), 441)
    }

    fn manager_cache() -> L3SessionManagerCache {
        L3SessionManagerCache::with_default_heartbeat(
            TlsPolicy::Verify,
            SessionId::new("s".repeat(73)).expect("valid SID"),
            Duration::from_secs(1),
        )
    }

    #[test]
    fn retry_budget_matches_zju_connect_boundaries() {
        let mut budget = RetryBudget::default();
        for remaining in (0..L3_CLOSED_RETRIES).rev() {
            assert_eq!(
                budget.consume(&L3SessionError::Closed),
                Some(RetryDecision {
                    reason: "closed",
                    remaining
                })
            );
        }
        assert_eq!(budget.consume(&L3SessionError::Closed), None);

        assert_eq!(
            budget.consume(&L3SessionError::AuthTimeout {
                flow: "flow".to_owned(),
            }),
            Some(RetryDecision {
                reason: "auth_timeout",
                remaining: 0
            })
        );
        assert_eq!(
            budget.consume(&L3SessionError::AuthTimeout {
                flow: "flow".to_owned(),
            }),
            None
        );
    }

    #[test]
    fn policy_rejection_is_never_retried() {
        let mut budget = RetryBudget::default();
        assert_eq!(
            budget.consume(&L3SessionError::FlowAuth(FlowAuthError::AuthFailed(
                "denied".to_owned()
            ))),
            None
        );
    }

    /// The event a TUN layer depends on. Establishing is routine and must not
    /// masquerade as a change; only a *different* VIP invalidates the world.
    #[tokio::test]
    async fn a_reconnect_onto_a_different_vip_is_announced_once() {
        let bus = EventBus::with_default_capacity();
        let mut stream = bus.subscribe();
        let manager = L3SessionManagerCache::with_default_heartbeat(
            TlsPolicy::Verify,
            SessionId::new("s".repeat(73)).expect("valid SID"),
            Duration::from_secs(1),
        )
        .with_events(Some(Arc::clone(&bus)))
        .manager("group-a", vec![endpoint("node.example")]);

        let mut state = SessionState::default();
        let node = endpoint("node.example");
        let first = Ipv4Addr::new(10, 210, 29, 48);
        let second = Ipv4Addr::new(10, 210, 29, 99);

        manager.report_established(&mut state, &node, first);
        manager.report_established(&mut state, &node, first);
        manager.report_established(&mut state, &node, second);

        let kinds = std::iter::from_fn(|| stream.try_recv())
            .map(|delivery| match delivery {
                EventDelivery::Event(event) => event.kind().to_owned(),
                EventDelivery::Lagged { skipped } => panic!("unexpected lag of {skipped}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                "l3.session_established",
                "l3.session_established",
                "l3.session_established",
                "l3.vip_changed",
            ],
            "only the third establish changed the VIP"
        );
        assert_eq!(state.last_vip, Some(second));
    }

    /// A retry must be observable as an event, not only as a log line: a
    /// consumer deciding whether to tear down a TUN device cannot grep stderr.
    #[tokio::test]
    async fn a_granted_retry_is_published_with_its_remaining_budget() {
        let bus = EventBus::with_default_capacity();
        let mut stream = bus.subscribe();
        let manager = L3SessionManagerCache::with_default_heartbeat(
            TlsPolicy::Verify,
            SessionId::new("s".repeat(73)).expect("valid SID"),
            Duration::from_secs(1),
        )
        .with_events(Some(Arc::clone(&bus)))
        .manager("group-a", vec![endpoint("node.example")]);

        let mut budget = RetryBudget::default();
        let decision = budget
            .consume(&L3SessionError::Closed)
            .expect("first close is retryable");
        manager.report_retry(&decision);

        let Some(EventDelivery::Event(event)) = stream.try_recv() else {
            panic!("a granted retry must publish an event");
        };
        assert!(matches!(
            event.as_ref(),
            HermesEvent::L3Reconnecting {
                reason: "closed",
                remaining_retries,
                ..
            } if *remaining_retries == L3_CLOSED_RETRIES - 1
        ));
    }

    #[test]
    fn manager_cache_is_stable_per_group_and_distinct_across_groups() {
        let cache = manager_cache();
        let first = cache.manager_for_generation("group-a", vec![endpoint("first.example")], 1);
        let refreshed =
            cache.manager_for_generation("group-a", vec![endpoint("second.example")], 2);
        cache.manager_for_generation("group-a", vec![endpoint("stale.example")], 1);
        let other = cache.manager("group-b", vec![endpoint("other.example")]);

        assert!(Arc::ptr_eq(&first, &refreshed));
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(cache.len(), 2);
        assert_eq!(
            *first.endpoints.read().expect("endpoint lock"),
            vec![endpoint("second.example")]
        );
    }

    #[tokio::test]
    async fn cache_retires_groups_removed_by_a_resource_refresh() {
        let cache = manager_cache();
        let keep = cache.manager("keep", vec![endpoint("old.example")]);
        cache.manager("remove", vec![endpoint("remove.example")]);

        cache
            .reconcile(
                1,
                &HashMap::from([("keep".to_owned(), vec![endpoint("new.example")])]),
            )
            .await;

        assert_eq!(cache.len(), 1);
        assert_eq!(keep.config.node_group_id, "keep");
        assert_eq!(
            *keep.endpoints.read().expect("endpoint lock"),
            vec![endpoint("new.example")]
        );
    }

    #[tokio::test]
    async fn an_empty_group_fails_closed_without_dialling() {
        let manager = manager_cache().manager("empty", Vec::new());
        assert!(matches!(
            manager.session().await,
            Err(L3SessionManagerError::NoEndpoints { node_group_id }) if node_group_id == "empty"
        ));
    }
}
