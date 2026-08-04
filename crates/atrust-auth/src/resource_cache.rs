use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use hermes_events::{EventBus, HermesEvent, OptionalEventBus as _};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::{AuthClient, AuthConfiguration, AuthError, ClientResources, ResourceIndex};

/// One atomically published resource generation. Routing and node endpoints
/// always come from the same `ClientResources` response.
#[derive(Clone, Debug)]
pub struct ResourceSnapshot {
    generation: u64,
    resources: Arc<ClientResources>,
    routing: Arc<ResourceIndex>,
}

impl ResourceSnapshot {
    fn new(generation: u64, resources: ClientResources) -> Self {
        let routing = Arc::new(resources.routing_index());
        Self {
            generation,
            resources: Arc::new(resources),
            routing,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn resources(&self) -> &Arc<ClientResources> {
        &self.resources
    }

    pub fn routing(&self) -> &Arc<ResourceIndex> {
        &self.routing
    }
}

/// Last-known-good clientResource cache with atomic snapshot replacement.
#[derive(Debug)]
pub struct ResourceCache {
    current: RwLock<Arc<ResourceSnapshot>>,
    updates: watch::Sender<Arc<ResourceSnapshot>>,
    events: Option<Arc<EventBus>>,
    /// Refreshes that have failed back-to-back. Reset by any success, so a
    /// consumer can tell "one flaky request" from "this session is finished".
    consecutive_failures: AtomicU32,
}

impl ResourceCache {
    pub fn new(resources: ClientResources) -> Self {
        let snapshot = Arc::new(ResourceSnapshot::new(1, resources));
        let (updates, _) = watch::channel(Arc::clone(&snapshot));
        Self {
            current: RwLock::new(snapshot),
            updates,
            events: None,
            consecutive_failures: AtomicU32::new(0),
        }
    }

    /// Attaches an observation channel for generation publishes and failures.
    #[must_use]
    pub fn with_events(mut self, events: Option<Arc<EventBus>>) -> Self {
        self.events = events;
        self
    }

    /// Refreshes that have failed since the last success.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    pub async fn load(
        client: &AuthClient,
        configuration: &AuthConfiguration,
    ) -> Result<Self, AuthError> {
        Ok(Self::new(client.client_resource(configuration).await?))
    }

    pub async fn snapshot(&self) -> Arc<ResourceSnapshot> {
        Arc::clone(&*self.current.read().await)
    }

    /// Subscribes to complete generations for data-plane reconciliation.
    pub fn subscribe(&self) -> watch::Receiver<Arc<ResourceSnapshot>> {
        self.updates.subscribe()
    }

    /// Fetches and fully indexes a replacement before publishing it. Errors
    /// leave the previous generation untouched.
    pub async fn refresh(
        &self,
        client: &AuthClient,
        configuration: &AuthConfiguration,
    ) -> Result<Arc<ResourceSnapshot>, AuthError> {
        let resources = match client.client_resource(configuration).await {
            Ok(resources) => resources,
            Err(error) => {
                self.report_failure(&error).await;
                return Err(error);
            }
        };
        let mut current = self.current.write().await;
        let next = Arc::new(ResourceSnapshot::new(
            current.generation().saturating_add(1),
            resources,
        ));
        *current = Arc::clone(&next);
        self.updates.send_replace(Arc::clone(&next));
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.events.emit(|| HermesEvent::ResourcePublished {
            generation: next.generation(),
            ip_resources: next.resources().ip_resources.len(),
            domain_resources: next.resources().domain_resources.len(),
            node_groups: next.resources().node_groups.len(),
        });
        Ok(next)
    }

    /// Classifies one failed refresh.
    ///
    /// An invalid session is escalated rather than counted: no number of
    /// retries will fix it, and everything downstream is now running on a
    /// resource table that can only get staler.
    async fn report_failure(&self, error: &AuthError) {
        if error.is_session_invalid() {
            error!(
                event = "atrust_auth.session_invalidated",
                error = %error,
                note = "the gateway rejected the stored session; a fresh login is required"
            );
            self.events.emit(|| HermesEvent::SessionInvalidated {
                reason: error.to_string(),
            });
            return;
        }
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_in_use = self.current.read().await.generation();
        warn!(
            event = "atrust_auth.resource_refresh_failed",
            generation_in_use,
            consecutive_failures = consecutive,
            error = %error
        );
        self.events.emit(|| HermesEvent::ResourceRefreshFailed {
            generation_in_use,
            consecutive_failures: consecutive,
            error: error.to_string(),
        });
    }

    /// Starts non-overlapping full refreshes. A failed refresh is logged and
    /// retried at the next interval while readers retain the last good snapshot.
    pub fn spawn_periodic_refresh(
        self: &Arc<Self>,
        client: Arc<AuthClient>,
        configuration: Arc<AuthConfiguration>,
        interval: Duration,
    ) -> ResourceRefreshTask {
        let interval = interval.max(Duration::from_secs(1));
        let cache = Arc::clone(self);
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = async {
                        tokio::time::sleep(interval).await;
                        cache.refresh(&client, &configuration).await
                    } => {
                        // Failures are classified and reported inside `refresh`,
                        // which is the only place that can tell an expired
                        // session apart from a transient one.
                        match result {
                            Ok(snapshot) => info!(
                                    event = "atrust_auth.resource_refreshed",
                                    generation = snapshot.generation()
                                ),
                            Err(error) if error.is_session_invalid() => break,
                            Err(_) => {}
                        }
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        ResourceRefreshTask {
            stop: stop_tx,
            task,
        }
    }
}

/// Cancellation owner for a periodic resource refresh loop.
#[derive(Debug)]
pub struct ResourceRefreshTask {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ResourceRefreshTask {
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.task).await;
    }
}

impl Drop for ResourceRefreshTask {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hermes_model::GatewayEndpoint;
    use hermes_transport::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};

    use super::*;
    use crate::LoginState;

    #[derive(Debug)]
    struct QueueTransport {
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    #[async_trait]
    impl HttpTransport for QueueTransport {
        async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            Ok(self
                .responses
                .lock()
                .expect("response queue")
                .pop_front()
                .expect("queued response"))
        }
    }

    fn response(app_id: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            location: None,
            body: format!(
                r#"{{"code":0,"data":{{"appList":{{"data":{{"appInfo":[{{"apps":[{{"id":"{app_id}","nodeGroupId":"group","addressList":[{{"protocol":"tcp","port":"443","host":"10.0.0.1"}}]}}]}}],"config":{{"nodeGroupConf":{{"nodeGroupList":[]}}}}}}}},"sdpPolicy":{{"data":{{}}}}}}}}"#
            )
            .into_bytes(),
        }
    }

    fn configuration() -> AuthConfiguration {
        AuthConfiguration {
            login_state: LoginState::LoggedIn,
            methods: Vec::new(),
            csrf_token: "csrf".to_owned(),
            public_key: String::new(),
            public_key_exponent: String::new(),
            anti_replay_random: String::new(),
        }
    }

    #[tokio::test]
    async fn refresh_atomically_replaces_a_complete_snapshot_and_keeps_last_good() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::from([
                response("app-1"),
                response("app-2"),
                HttpResponse {
                    status: 500,
                    location: None,
                    body: Vec::new(),
                },
            ])),
        });
        let client = AuthClient::new(
            GatewayEndpoint::new("gateway.test", 443).expect("gateway"),
            transport,
        );
        let cache = ResourceCache::load(&client, &configuration())
            .await
            .expect("initial resource");
        let first = cache.snapshot().await;
        let mut updates = cache.subscribe();

        let second = cache
            .refresh(&client, &configuration())
            .await
            .expect("refresh");
        assert_eq!(first.generation(), 1);
        assert_eq!(second.generation(), 2);
        assert_eq!(first.resources().ip_resources[0].app_id, "app-1");
        assert_eq!(second.resources().ip_resources[0].app_id, "app-2");
        updates.changed().await.expect("refresh notification");
        assert_eq!(updates.borrow_and_update().generation(), 2);

        assert!(cache.refresh(&client, &configuration()).await.is_err());
        assert_eq!(cache.snapshot().await.generation(), 2);
    }

    fn session_invalid_response() -> HttpResponse {
        HttpResponse {
            status: 200,
            location: None,
            body: br#"{"code":75500002,"message":"The session is invalid"}"#.to_vec(),
        }
    }

    /// An expired session must escalate, not blend into the retry noise. A
    /// refresh loop that keeps warning forever leaves the whole runtime on a
    /// resource table that can only get staler.
    #[tokio::test]
    async fn an_invalid_session_escalates_instead_of_counting_as_a_retryable_failure() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::from([
                response("app-1"),
                HttpResponse {
                    status: 500,
                    location: None,
                    body: Vec::new(),
                },
                session_invalid_response(),
            ])),
        });
        let client = AuthClient::new(
            GatewayEndpoint::new("gateway.test", 443).expect("gateway"),
            transport,
        );
        let bus = hermes_events::EventBus::with_default_capacity();
        let mut stream = bus.subscribe();
        let cache = ResourceCache::load(&client, &configuration())
            .await
            .expect("initial resource")
            .with_events(Some(Arc::clone(&bus)));

        // A transport-level failure is retryable and increments the counter.
        assert!(cache.refresh(&client, &configuration()).await.is_err());
        assert_eq!(cache.consecutive_failures(), 1);

        // An invalid session is a different class of failure entirely.
        let error = cache
            .refresh(&client, &configuration())
            .await
            .expect_err("session invalid");
        assert!(error.is_session_invalid(), "got {error}");
        assert_eq!(
            cache.consecutive_failures(),
            1,
            "an unrecoverable session must not inflate the retry counter"
        );

        let kinds = std::iter::from_fn(|| stream.try_recv())
            .map(|delivery| match delivery {
                hermes_events::EventDelivery::Event(event) => event.kind().to_owned(),
                hermes_events::EventDelivery::Lagged { skipped } => {
                    panic!("unexpected lag of {skipped}")
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(kinds, ["resource.refresh_failed", "session.invalidated"]);
    }

    #[tokio::test]
    async fn a_successful_refresh_publishes_a_generation_and_clears_the_failure_count() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::from([
                response("app-1"),
                HttpResponse {
                    status: 500,
                    location: None,
                    body: Vec::new(),
                },
                response("app-2"),
            ])),
        });
        let client = AuthClient::new(
            GatewayEndpoint::new("gateway.test", 443).expect("gateway"),
            transport,
        );
        let bus = hermes_events::EventBus::with_default_capacity();
        let mut stream = bus.subscribe();
        let cache = ResourceCache::load(&client, &configuration())
            .await
            .expect("initial resource")
            .with_events(Some(Arc::clone(&bus)));

        assert!(cache.refresh(&client, &configuration()).await.is_err());
        assert_eq!(cache.consecutive_failures(), 1);
        cache
            .refresh(&client, &configuration())
            .await
            .expect("recovery");
        assert_eq!(cache.consecutive_failures(), 0);

        let kinds = std::iter::from_fn(|| stream.try_recv())
            .map(|delivery| match delivery {
                hermes_events::EventDelivery::Event(event) => event.kind().to_owned(),
                hermes_events::EventDelivery::Lagged { skipped } => {
                    panic!("unexpected lag of {skipped}")
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(kinds, ["resource.refresh_failed", "resource.published"]);
    }
}
