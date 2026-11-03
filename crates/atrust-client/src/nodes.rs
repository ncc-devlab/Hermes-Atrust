use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use atrust_auth::ResourceSnapshot;
use atrust_l3::L3NodeEndpoint;
use futures_util::{StreamExt, stream};
use hermes_transport::{NodeTlsProbeResult, probe_node_tls_with_underlay};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::AtrustClientConfig;

#[derive(Clone, Debug)]
pub struct NodeHealth {
    pub node_group_id: String,
    pub resource_generation: u64,
    pub measurements: Vec<NodeTlsProbeResult>,
}

#[derive(Debug)]
struct Ranked {
    at: Instant,
    health: NodeHealth,
    endpoints: Vec<L3NodeEndpoint>,
}

/// Serializes each refresh pass so first-use traffic and the background timer
/// cannot launch duplicate probe batches. Each batch has bounded concurrency.
#[derive(Debug)]
pub(crate) struct NodeSelector {
    config: AtrustClientConfig,
    rankings: Mutex<HashMap<String, Ranked>>,
}

impl NodeSelector {
    pub fn new(config: AtrustClientConfig) -> Self {
        Self {
            config,
            rankings: Mutex::new(HashMap::new()),
        }
    }

    pub async fn health(&self) -> Vec<NodeHealth> {
        self.rankings
            .lock()
            .await
            .values()
            .map(|r| r.health.clone())
            .collect()
    }

    pub async fn endpoints(&self, snapshot: &ResourceSnapshot, group: &str) -> Vec<L3NodeEndpoint> {
        let endpoints = configured_endpoints(&self.config, snapshot, group);
        if self.config.node_refresh_interval.is_zero()
            || override_matches(&self.config, snapshot, group)
        {
            return endpoints;
        }
        let mut rankings = self.rankings.lock().await;
        if let Some(ranked) = rankings.get(group)
            && ranked.health.resource_generation == snapshot.generation()
            && ranked.at.elapsed() < self.config.node_refresh_interval
        {
            return ranked.endpoints.clone();
        }
        let underlay = Arc::clone(&self.config.underlay);
        let policy = self.config.tls_policy;
        let timeout = self.config.node_probe_timeout;
        let mut measurements = stream::iter(endpoints.iter().cloned())
            .map(|endpoint| {
                let underlay = Arc::clone(&underlay);
                async move {
                    probe_node_tls_with_underlay(
                        &endpoint.host,
                        endpoint.port,
                        policy,
                        timeout,
                        underlay.as_ref(),
                    )
                    .await
                }
            })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        rank(&mut measurements);
        // Keep failed candidates as recovery fallbacks. A stale probe must not
        // permanently remove a node that has just become reachable again.
        let ordered = measurements
            .iter()
            .map(|m| L3NodeEndpoint::new(m.host.clone(), m.port))
            .collect::<Vec<_>>();
        rankings.insert(
            group.to_owned(),
            Ranked {
                at: Instant::now(),
                health: NodeHealth {
                    node_group_id: group.to_owned(),
                    resource_generation: snapshot.generation(),
                    measurements,
                },
                endpoints: ordered.clone(),
            },
        );
        ordered
    }
}

fn rank(measurements: &mut [NodeTlsProbeResult]) {
    measurements.sort_by_key(|m| (!m.success(), m.elapsed, m.host.clone(), m.port));
}

fn override_matches(config: &AtrustClientConfig, snapshot: &ResourceSnapshot, group: &str) -> bool {
    config.endpoint_override.is_some()
        && (config.endpoint_override_node_group_id.as_deref() == Some(group)
            || (config.endpoint_override_node_group_id.is_none()
                && snapshot.resources().node_groups.len() == 1
                && snapshot.resources().node_groups[0].id == group))
}

pub(crate) fn configured_endpoints(
    config: &AtrustClientConfig,
    snapshot: &ResourceSnapshot,
    group: &str,
) -> Vec<L3NodeEndpoint> {
    if override_matches(config, snapshot, group) {
        return config.endpoint_override.clone().unwrap_or_default();
    }
    snapshot
        .resources()
        .resolve_node_groups(&config.gateway)
        .into_iter()
        .find(|g| g.id == group)
        .map(|g| {
            g.endpoints
                .into_iter()
                .map(|e| L3NodeEndpoint::new(e.host, e.port))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn refresh_interval(interval: Duration) -> Duration {
    interval.max(Duration::from_secs(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_transport::NodeTlsProbeOutcome;
    #[test]
    fn fast_failures_never_beat_reachable_nodes() {
        let mut measurements = vec![
            NodeTlsProbeResult {
                host: "failed".into(),
                port: 441,
                outcome: NodeTlsProbeOutcome::TcpConnectFailed,
                elapsed: Duration::from_millis(1),
            },
            NodeTlsProbeResult {
                host: "slow".into(),
                port: 441,
                outcome: NodeTlsProbeOutcome::Ok,
                elapsed: Duration::from_millis(50),
            },
            NodeTlsProbeResult {
                host: "fast".into(),
                port: 441,
                outcome: NodeTlsProbeOutcome::Ok,
                elapsed: Duration::from_millis(5),
            },
        ];
        rank(&mut measurements);
        assert_eq!(
            measurements
                .iter()
                .map(|m| m.host.as_str())
                .collect::<Vec<_>>(),
            ["fast", "slow", "failed"]
        );
    }
}
