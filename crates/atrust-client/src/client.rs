use std::collections::HashMap;
use std::sync::Arc;

use atrust_auth::{
    AuthClient, AuthConfiguration, AuthError, FlowProtocol, MatchedResource, ResourceCache,
    ResourceRefreshTask, ResourceSnapshot, SessionMaterial,
};
use atrust_l3::{
    Ipv4Flow, L3AuthContext, L3IpProtocol, L3NodeEndpoint, L3Session, L3SessionManager,
    L3SessionManagerCache, L3SessionManagerError, PacketError, ProcessIdentity, parse_ipv4_flow,
};
use atrust_tcp::{
    DialTcpError, DialTcpRequest, TCP_DIAL_RETRIES, TcpTunnel, TunnelTarget, dial_tcp_with_retry,
};
use hermes_events::{EventBus, EventStream, HermesEvent};
use thiserror::Error;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::AtrustClientConfig;
use crate::stats::{ClientStats, NodeGroupStats};

/// The assembled runtime: authenticated session, live resource table, node
/// group connections, one event stream.
#[derive(Debug)]
pub struct AtrustClient {
    config: AtrustClientConfig,
    auth: Arc<AuthClient>,
    auth_config: Arc<AuthConfiguration>,
    material: SessionMaterial,
    resources: Arc<ResourceCache>,
    managers: Arc<L3SessionManagerCache>,
    events: Arc<EventBus>,
    background: Mutex<Option<Background>>,
}

/// Owned background work, kept together so shutdown cannot forget one of them.
#[derive(Debug)]
struct Background {
    refresh: ResourceRefreshTask,
    reconciler: Reconciler,
}

/// One opened TCP tunnel plus the routing decision that produced it.
#[derive(Debug)]
pub struct DialedTunnel {
    pub tunnel: TcpTunnel,
    pub app_id: String,
    pub node_group_id: String,
    pub node_host: String,
    pub node_port: u16,
}

/// The outcome of authorizing (and optionally sending) one packet.
#[derive(Debug)]
pub struct SentFlow {
    pub flow: Ipv4Flow,
    pub app_id: String,
    pub node_group_id: String,
    /// Length only. The token is a credential and never leaves the runtime.
    pub connect_token_len: usize,
    pub session: Arc<L3Session>,
}

impl AtrustClient {
    /// Starts the runtime from an already-authenticated session.
    ///
    /// Fetches the first resource generation, then starts the refresh loop and
    /// the reconciler that keeps node-group managers aligned with it. No node
    /// connection is opened here: connections stay lazy until routing selects a
    /// group, so starting the runtime costs one control-plane request.
    pub async fn start(
        auth: Arc<AuthClient>,
        auth_config: AuthConfiguration,
        material: SessionMaterial,
        config: AtrustClientConfig,
    ) -> Result<Arc<Self>, ClientError> {
        let events = EventBus::with_default_capacity();
        let resources = Arc::new(
            ResourceCache::load(&auth, &auth_config)
                .await?
                .with_events(Some(Arc::clone(&events))),
        );
        let managers = Arc::new(
            L3SessionManagerCache::with_default_heartbeat(
                config.tls_policy,
                material.sid.clone(),
                config.connect_timeout,
            )
            .with_heartbeat_interval(config.heartbeat_interval)
            .with_events(Some(Arc::clone(&events))),
        );

        let auth_config = Arc::new(auth_config);
        let refresh = resources.spawn_periodic_refresh(
            Arc::clone(&auth),
            Arc::clone(&auth_config),
            config.resource_refresh_interval,
        );
        let reconciler = Reconciler::spawn(
            resources.subscribe(),
            Arc::clone(&managers),
            config.gateway.clone(),
            config.endpoint_override.clone(),
        );

        let snapshot = resources.snapshot().await;
        info!(
            event = "atrust_client.started",
            resource_generation = snapshot.generation(),
            ip_resources = snapshot.resources().ip_resources.len(),
            domain_resources = snapshot.resources().domain_resources.len(),
            node_groups = snapshot.resources().node_groups.len(),
            refresh_interval_seconds = config.resource_refresh_interval.as_secs()
        );

        Ok(Arc::new(Self {
            config,
            auth,
            auth_config,
            material,
            resources,
            managers,
            events,
            background: Mutex::new(Some(Background {
                refresh,
                reconciler,
            })),
        }))
    }

    // ---- Observation --------------------------------------------------------

    /// Subscribes to the runtime event stream.
    ///
    /// Subscribe **before** the first packet: the stream carries only events
    /// published after this call, and the first
    /// [`HermesEvent::L3SessionEstablished`](hermes_events::HermesEvent) arrives
    /// during the first send.
    #[must_use]
    pub fn events(&self) -> EventStream {
        self.events.subscribe()
    }

    #[must_use]
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.events
    }

    pub async fn resources(&self) -> Arc<ResourceSnapshot> {
        self.resources.snapshot().await
    }

    /// Resolves a destination to its app and node group without dialling.
    pub async fn route(
        &self,
        host: &str,
        port: u16,
        protocol: FlowProtocol,
    ) -> Option<MatchedResource> {
        self.resources
            .snapshot()
            .await
            .routing()
            .match_destination(host, port, protocol)
            .map(|destination| destination.to_matched_resource())
    }

    pub async fn stats(&self) -> ClientStats {
        let snapshot = self.resources.snapshot().await;
        let mut groups = Vec::new();
        for manager in self.managers.managers() {
            let session = manager.current_session().await;
            groups.push(NodeGroupStats {
                node_group_id: manager.node_group_id().to_owned(),
                vip: manager.last_vip().await,
                connected: session.is_some(),
                dropped_packets: session.as_ref().map_or(0, |s| s.dropped_packets()),
                tracked_flows: session.as_ref().map_or(0, |s| s.conntrack_len()),
            });
        }
        groups.sort_by(|left, right| left.node_group_id.cmp(&right.node_group_id));
        ClientStats {
            resource_generation: snapshot.generation(),
            consecutive_refresh_failures: self.resources.consecutive_failures(),
            ip_resources: snapshot.resources().ip_resources.len(),
            domain_resources: snapshot.resources().domain_resources.len(),
            node_groups_advertised: snapshot.resources().node_groups.len(),
            node_groups_active: groups.len(),
            events_published: self.events.published(),
            groups,
        }
    }

    // ---- Data plane ---------------------------------------------------------

    /// Authorizes and sends one raw IPv4 packet.
    ///
    /// This is the entry point a TUN device drives: parse, route, connect,
    /// authorize, send — with reconnect and bounded retries underneath. It is
    /// **fail-closed**: a packet the resource table does not cover is rejected
    /// rather than sent to a default node group.
    pub async fn send_ipv4(&self, packet: &[u8]) -> Result<SentFlow, ClientError> {
        self.dispatch(packet, true).await
    }

    /// Authorizes the packet's flow without sending it.
    ///
    /// Splits "the gateway refused this flow" from "the data path is broken"
    /// into two separately readable outcomes, which is what makes a live
    /// bring-up failure diagnosable.
    pub async fn authorize_ipv4(&self, packet: &[u8]) -> Result<SentFlow, ClientError> {
        self.dispatch(packet, false).await
    }

    async fn dispatch(&self, packet: &[u8], send: bool) -> Result<SentFlow, ClientError> {
        let flow = parse_ipv4_flow(packet)?;
        let snapshot = self.resources.snapshot().await;
        let route = snapshot
            .routing()
            .match_destination(
                &flow.dst_addr.to_string(),
                flow.dst_port,
                flow_protocol(flow.protocol),
            )
            .map(|destination| destination.to_matched_resource())
            .ok_or_else(|| ClientError::Unauthorized {
                destination: format!("{}:{}", flow.dst_addr, flow.dst_port),
                protocol: flow.protocol.scheme(),
            })?;
        let manager = self.manager_for_snapshot(&snapshot, &route.node_group_id)?;

        let process = ProcessIdentity::default_for_port(flow.dst_port);
        let ctx = L3AuthContext {
            sid: &self.material.sid,
            device_id: &self.material.device_id,
            connection_id: &self.material.connection_id,
            sign_key: &self.material.sign_key,
            process: &process,
            lang: &self.config.lang,
        };

        let authorized = if send {
            manager
                .authorize_and_send(&ctx, &route.app_id, &flow, packet)
                .await?
        } else {
            manager.authorize_flow(&ctx, &route.app_id, &flow).await?
        };

        Ok(SentFlow {
            flow,
            app_id: route.app_id,
            node_group_id: route.node_group_id,
            connect_token_len: authorized.connect_token().len(),
            session: Arc::clone(authorized.session()),
        })
    }

    /// Returns the reconnect owner for a node group, creating it on first use.
    ///
    /// Endpoints come from the same generation that produced the route, so a
    /// refresh landing mid-dispatch cannot pair one generation's `appId` with
    /// another's node addresses.
    async fn manager_for(&self, node_group_id: &str) -> Result<Arc<L3SessionManager>, ClientError> {
        let snapshot = self.resources.snapshot().await;
        self.manager_for_snapshot(&snapshot, node_group_id)
    }

    fn manager_for_snapshot(
        &self,
        snapshot: &ResourceSnapshot,
        node_group_id: &str,
    ) -> Result<Arc<L3SessionManager>, ClientError> {
        let endpoints = self.endpoints_for(snapshot, node_group_id);
        if endpoints.is_empty() {
            return Err(ClientError::NoEndpoints {
                node_group_id: node_group_id.to_owned(),
            });
        }
        Ok(self
            .managers
            .manager_for_generation(node_group_id, endpoints, snapshot.generation()))
    }

    fn endpoints_for(
        &self,
        snapshot: &ResourceSnapshot,
        node_group_id: &str,
    ) -> Vec<L3NodeEndpoint> {
        if let Some(override_endpoints) = &self.config.endpoint_override {
            return override_endpoints.clone();
        }
        snapshot
            .resources()
            .resolve_node_groups(&self.config.gateway)
            .into_iter()
            .find(|group| group.id == node_group_id)
            .map(|group| {
                group
                    .endpoints
                    .into_iter()
                    .map(|endpoint| L3NodeEndpoint::new(endpoint.host, endpoint.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Establishes (or reuses) a node group's connection and returns it.
    ///
    /// This is how a device layer learns its virtual IP: the VIP is assigned by
    /// Get-IP during establishment, and an interface has to be configured with
    /// it *before* any packet can legitimately carry it as a source address.
    /// Afterwards, [`HermesEvent::L3VipChanged`](hermes_events::HermesEvent) is
    /// the only thing that can invalidate it.
    pub async fn connect_node_group(
        &self,
        node_group_id: &str,
    ) -> Result<Arc<L3Session>, ClientError> {
        Ok(self.manager_for(node_group_id).await?.session().await?)
    }

    /// Waits for the next inbound packet on a node group's connection.
    ///
    /// Returns `None` when the group has no live connection, rather than
    /// establishing one: receiving must never be the thing that dials.
    pub async fn recv_ipv4(&self, node_group_id: &str) -> Option<Vec<u8>> {
        let session = self.managers.get(node_group_id)?.current_session().await?;
        session.recv_packet().await
    }

    // ---- TCP tunnel ---------------------------------------------------------

    /// Opens one aTrust TCP tunnel to a destination the resource table covers.
    ///
    /// Same fail-closed contract as [`Self::send_ipv4`]: an uncovered
    /// destination is refused before anything dials. Unlike L3 there is no
    /// long-lived session to reconnect — each tunnel is its own connection — so
    /// the only recovery here is trying the next candidate endpoint.
    ///
    /// Domains are passed through as domains: the handshake carries the name, so
    /// resolving locally would present the node with a destination the server's
    /// domain resource never authorized.
    pub async fn dial_tcp(&self, host: &str, port: u16) -> Result<DialedTunnel, ClientError> {
        let snapshot = self.resources.snapshot().await;
        let route = snapshot
            .routing()
            .match_destination(host, port, FlowProtocol::Tcp)
            .map(|destination| destination.to_matched_resource())
            .ok_or_else(|| ClientError::Unauthorized {
                destination: format!("{host}:{port}"),
                protocol: "tcp",
            })?;
        let target = tunnel_target(host, port, &route.app_id);

        let endpoints = self.endpoints_for(&snapshot, &route.node_group_id);
        if endpoints.is_empty() {
            return Err(ClientError::NoEndpoints {
                node_group_id: route.node_group_id,
            });
        }

        let username = self.material.username.as_deref().unwrap_or_default();
        let mut last_error = None;
        for endpoint in &endpoints {
            let request = DialTcpRequest {
                node_host: &endpoint.host,
                node_port: endpoint.port,
                tls_policy: self.config.tls_policy,
                sid: &self.material.sid,
                device_id: &self.material.device_id,
                connection_id: &self.material.connection_id,
                sign_key: &self.material.sign_key,
                username,
                target: target.clone(),
                process: None,
                lang: &self.config.lang,
                connect_timeout: self.config.connect_timeout,
                handshake_timeout: self.config.tcp_handshake_timeout,
            };
            match dial_tcp_with_retry(request, TCP_DIAL_RETRIES).await {
                Ok(tunnel) => {
                    info!(
                        event = "atrust_client.tcp_tunnel_opened",
                        node_group_id = %route.node_group_id,
                        node_port = endpoint.port,
                        target_port = port
                    );
                    self.events.publish(HermesEvent::TcpTunnelOpened {
                        node_group_id: route.node_group_id.clone(),
                        node_host: endpoint.host.clone(),
                        node_port: endpoint.port,
                        app_id: route.app_id.clone(),
                        target: target.dest_addr_string(),
                    });
                    return Ok(DialedTunnel {
                        tunnel,
                        app_id: route.app_id,
                        node_group_id: route.node_group_id,
                        node_host: endpoint.host.clone(),
                        node_port: endpoint.port,
                    });
                }
                Err(error) => {
                    warn!(
                        event = "atrust_client.tcp_dial_failed",
                        node_group_id = %route.node_group_id,
                        node_port = endpoint.port,
                        error = %error
                    );
                    self.events.publish(HermesEvent::TcpDialFailed {
                        node_group_id: route.node_group_id.clone(),
                        node_host: endpoint.host.clone(),
                        node_port: endpoint.port,
                        target: target.dest_addr_string(),
                        error: error.to_string(),
                    });
                    // A server-side refusal is about the destination, not the
                    // path to it, so trying another node would only repeat it.
                    if !error.is_retryable() {
                        return Err(error.into());
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error
            .expect("a non-empty endpoint list produced an error")
            .into())
    }

    // ---- Control ------------------------------------------------------------

    /// Fetches and publishes a resource generation immediately.
    pub async fn refresh_resources(&self) -> Result<Arc<ResourceSnapshot>, ClientError> {
        Ok(self
            .resources
            .refresh(&self.auth, &self.auth_config)
            .await?)
    }

    /// Drops a node group's connection. The next packet re-establishes it,
    /// which may land on a different endpoint and a different VIP.
    pub async fn reconnect(&self, node_group_id: &str) {
        if let Some(manager) = self.managers.get(node_group_id) {
            debug!(event = "atrust_client.reconnect_requested", node_group_id);
            manager.close().await;
        }
    }

    /// Stops background work and closes every connection.
    ///
    /// Idempotent, and safe to call from a signal handler: without it the
    /// process exits with node connections still open, leaving a session the
    /// gateway has to time out on its own.
    pub async fn shutdown(&self) {
        if let Some(background) = self.background.lock().await.take() {
            background.reconciler.shutdown().await;
            background.refresh.shutdown().await;
        }
        self.managers.close().await;
        info!(event = "atrust_client.shutdown");
    }
}

/// Maps an IPv4 protocol number onto the resource matcher's protocol.
fn flow_protocol(protocol: L3IpProtocol) -> FlowProtocol {
    match protocol {
        L3IpProtocol::Tcp => FlowProtocol::Tcp,
        L3IpProtocol::Udp => FlowProtocol::Udp,
        L3IpProtocol::Icmp => FlowProtocol::Icmp,
    }
}

/// Keeps managers already in use aligned with each complete resource
/// generation. Manager creation stays lazy until routing selects a group.
#[derive(Debug)]
struct Reconciler {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Reconciler {
    fn spawn(
        mut updates: watch::Receiver<Arc<ResourceSnapshot>>,
        managers: Arc<L3SessionManagerCache>,
        gateway: hermes_model::GatewayEndpoint,
        endpoint_override: Option<Vec<L3NodeEndpoint>>,
    ) -> Self {
        let (stop, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = updates.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let snapshot = Arc::clone(&updates.borrow_and_update());
                        let groups = snapshot
                            .resources()
                            .resolve_node_groups(&gateway)
                            .into_iter()
                            .map(|group| {
                                let endpoints = match &endpoint_override {
                                    Some(endpoints) => endpoints.clone(),
                                    None => group
                                        .endpoints
                                        .into_iter()
                                        .map(|endpoint| {
                                            L3NodeEndpoint::new(endpoint.host, endpoint.port)
                                        })
                                        .collect(),
                                };
                                (group.id, endpoints)
                            })
                            .collect::<HashMap<_, _>>();
                        managers.reconcile(snapshot.generation(), &groups).await;
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        Self { stop, task }
    }

    async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.task).await;
    }
}

impl Drop for Reconciler {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

/// Builds the handshake destination, keeping domains as domains.
fn tunnel_target(host: &str, port: u16, app_id: &str) -> TunnelTarget {
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => TunnelTarget::Ipv4 {
            ip,
            port,
            app_id: app_id.to_owned(),
        },
        Err(_) => TunnelTarget::Domain {
            host: host.to_owned(),
            port,
            app_id: app_id.to_owned(),
            resolved: None,
        },
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Tcp(#[from] DialTcpError),
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error(transparent)]
    Session(#[from] L3SessionManagerError),
    #[error("the resource table does not authorize {protocol} destination {destination}")]
    Unauthorized {
        destination: String,
        protocol: &'static str,
    },
    #[error("node group {node_group_id} has no resolvable data-plane endpoint")]
    NoEndpoints { node_group_id: String },
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use async_trait::async_trait;
    use hermes_events::{EventDelivery, HermesEvent};
    use hermes_model::{ConnectionId, DeviceId, GatewayEndpoint, SessionId, SignKey};
    use hermes_transport::{
        HttpRequest, HttpResponse, HttpTransport, HttpTransportError, TlsPolicy,
    };

    use super::*;

    #[derive(Debug)]
    struct QueueTransport {
        responses: StdMutex<VecDeque<HttpResponse>>,
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

    /// One IP resource for `10.9.0.0/24` on TCP 80, in a group with one node.
    fn resource_response() -> HttpResponse {
        HttpResponse {
            status: 200,
            location: None,
            body: br#"{"code":0,"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"app-1","nodeGroupId":"group-1","addressList":[{"protocol":"tcp","port":"80","host":"10.9.0.0/24"}]}]}],"config":{"nodeGroupConf":{"nodeGroupList":[{"id":"group-1","addressInfo":[{"address":"node.example","port":"441","addressType":"domain"}]}]}}}},"sdpPolicy":{"data":{}}}}"#
                .to_vec(),
        }
    }

    fn configuration() -> AuthConfiguration {
        AuthConfiguration {
            login_state: atrust_auth::LoginState::LoggedIn,
            methods: Vec::new(),
            csrf_token: "csrf".to_owned(),
            public_key: String::new(),
            public_key_exponent: String::new(),
            anti_replay_random: String::new(),
        }
    }

    fn material() -> SessionMaterial {
        let device_id = DeviceId::new("d".repeat(32)).expect("device id");
        SessionMaterial {
            connection_id: ConnectionId::from_device(&device_id).expect("connection id"),
            sid: SessionId::new("s".repeat(73)).expect("sid"),
            device_id,
            sign_key: SignKey::from_hex(&"ab".repeat(32)).expect("sign key"),
            username: Some("tester".to_owned()),
            sign_key_provisional: true,
            sid_cookie_name: "sid".to_owned(),
            sid_sig_present: true,
        }
    }

    /// A TCP SYN from `vip` to `dst:port`, hand-built so routing can be
    /// exercised without a live session assigning a real VIP.
    fn tcp_syn(dst: [u8; 4], port: u16) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 6, 0x00, 0x00, 10, 210, 29, 48,
        ];
        packet.extend_from_slice(&dst);
        packet.extend_from_slice(&40000u16.to_be_bytes());
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
        packet
    }

    async fn client_with(responses: Vec<HttpResponse>) -> Arc<AtrustClient> {
        let transport = Arc::new(QueueTransport {
            responses: StdMutex::new(VecDeque::from(responses)),
        });
        let gateway = GatewayEndpoint::new("gateway.test", 443).expect("gateway");
        let auth = Arc::new(AuthClient::new(gateway.clone(), transport));
        let config = AtrustClientConfig::new(gateway, TlsPolicy::Verify)
            // Long enough that the refresh loop never fires during a test.
            .with_resource_refresh_interval(Duration::from_secs(3600));
        AtrustClient::start(auth, configuration(), material(), config)
            .await
            .expect("client starts")
    }

    #[tokio::test]
    async fn starting_loads_one_generation_and_opens_no_connection() {
        let client = client_with(vec![resource_response()]).await;
        let stats = client.stats().await;

        assert_eq!(stats.resource_generation, 1);
        assert_eq!(stats.ip_resources, 1);
        assert_eq!(stats.node_groups_advertised, 1);
        assert_eq!(
            stats.node_groups_active, 0,
            "connections must stay lazy until routing selects a group"
        );
        assert_eq!(stats.consecutive_refresh_failures, 0);
        client.shutdown().await;
    }

    #[tokio::test]
    async fn routing_resolves_a_covered_destination_and_rejects_an_uncovered_one() {
        let client = client_with(vec![resource_response()]).await;

        let matched = client
            .route("10.9.0.7", 80, FlowProtocol::Tcp)
            .await
            .expect("covered destination");
        assert_eq!(matched.app_id, "app-1");
        assert_eq!(matched.node_group_id, "group-1");

        assert!(
            client
                .route("10.9.0.7", 443, FlowProtocol::Tcp)
                .await
                .is_none()
        );
        assert!(
            client
                .route("8.8.8.8", 80, FlowProtocol::Tcp)
                .await
                .is_none()
        );
        client.shutdown().await;
    }

    /// The fail-closed guarantee, and the reason this test needs no network:
    /// an unauthorized packet must be rejected *before* anything dials. If this
    /// ever regresses it will hang on a connect timeout instead of failing.
    #[tokio::test]
    async fn an_unauthorized_packet_is_rejected_without_dialling() {
        let client = client_with(vec![resource_response()]).await;

        let error = client
            .send_ipv4(&tcp_syn([8, 8, 8, 8], 80))
            .await
            .expect_err("uncovered destination must be refused");
        assert!(
            matches!(&error, ClientError::Unauthorized { destination, protocol }
                if destination == "8.8.8.8:80" && *protocol == "tcp"),
            "got {error}"
        );
        assert_eq!(client.stats().await.node_groups_active, 0);
        client.shutdown().await;
    }

    /// Same fail-closed contract as the packet path, and the same reason this
    /// needs no network: an uncovered destination must be refused before any
    /// dial. A regression here shows up as a connect timeout, not a failure.
    #[tokio::test]
    async fn an_uncovered_tcp_destination_is_refused_before_dialling() {
        let client = client_with(vec![resource_response()]).await;

        let error = client
            .dial_tcp("8.8.8.8", 80)
            .await
            .expect_err("uncovered destination must be refused");
        assert!(
            matches!(&error, ClientError::Unauthorized { destination, protocol }
                if destination == "8.8.8.8:80" && *protocol == "tcp"),
            "got {error}"
        );

        // A covered destination on an unauthorized port is equally refused.
        assert!(matches!(
            client.dial_tcp("10.9.0.7", 443).await,
            Err(ClientError::Unauthorized { .. })
        ));
        client.shutdown().await;
    }

    /// Domains must reach the handshake as domains: resolving locally would
    /// present the node a destination its domain resource never authorized.
    #[test]
    fn a_domain_target_is_not_resolved_into_an_address() {
        let target = tunnel_target("portal.example.edu", 443, "app-1");
        assert!(matches!(
            &target,
            TunnelTarget::Domain { host, resolved: None, .. } if host == "portal.example.edu"
        ));
        assert!(matches!(
            tunnel_target("10.9.0.7", 80, "app-1"),
            TunnelTarget::Ipv4 { .. }
        ));
    }

    #[tokio::test]
    async fn a_malformed_packet_never_reaches_routing() {
        let client = client_with(vec![resource_response()]).await;
        let error = client
            .send_ipv4(&[0x45, 0x00])
            .await
            .expect_err("a truncated packet is not a flow");
        assert!(matches!(error, ClientError::Packet(_)), "got {error}");
        client.shutdown().await;
    }

    #[tokio::test]
    async fn a_manual_refresh_publishes_a_generation_on_the_event_stream() {
        let client = client_with(vec![resource_response(), resource_response()]).await;
        let mut events = client.events();

        let snapshot = client.refresh_resources().await.expect("refresh");
        assert_eq!(snapshot.generation(), 2);
        assert_eq!(client.stats().await.resource_generation, 2);

        let Some(EventDelivery::Event(event)) = events.try_recv() else {
            panic!("a published generation must reach subscribers");
        };
        assert!(matches!(
            event.as_ref(),
            HermesEvent::ResourcePublished { generation: 2, .. }
        ));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let client = client_with(vec![resource_response()]).await;
        client.shutdown().await;
        client.shutdown().await;
    }
}
