//! Data-plane endpoint selection: probe every advertised endpoint, rank by
//! measured latency, and honour an explicit override fail-closed.
//!
//! The previous behaviour was `primary_nodes()` — the first endpoint of the
//! first group, with no reachability check at all. That is wrong in exactly the
//! configuration Xidian ships: a node group advertising both an internal-only
//! address and a public one, in server order. Picking the first meant every
//! command hung against an address that cannot be reached from where the client
//! runs, and the failure looked like a protocol timeout.

use std::collections::BTreeSet;
use std::time::Duration;

use futures_util::future::join_all;
use hermes_transport::{NodeTlsProbeOutcome, TlsPolicy, probe_node_tls};
use thiserror::Error;
use tracing::{debug, warn};

use crate::resource::{DEFAULT_NODE_PORT, ResolvedNodeEndpoint};

/// One endpoint's measured reachability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeMeasurement {
    pub group_id: String,
    pub endpoint: ResolvedNodeEndpoint,
    pub outcome: NodeTlsProbeOutcome,
    pub elapsed: Duration,
}

impl NodeMeasurement {
    #[must_use]
    pub fn reachable(&self) -> bool {
        self.outcome == NodeTlsProbeOutcome::Ok
    }

    #[must_use]
    pub fn address(&self) -> String {
        self.endpoint.socket_display()
    }
}

/// Why the chosen endpoint won.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionSource {
    /// The caller named this endpoint and it is advertised and reachable.
    Requested,
    /// The caller named an endpoint the gateway never advertised, and
    /// [`UnadvertisedNode::Allow`] permitted it anyway.
    RequestedUnadvertised,
    /// Lowest measured TLS handshake latency among the reachable endpoints.
    LowestLatency,
}

impl SelectionSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::RequestedUnadvertised => "requested_unadvertised",
            Self::LowestLatency => "lowest_latency",
        }
    }
}

/// What to do when the caller names an endpoint the gateway never advertised.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UnadvertisedNode {
    /// Refuse. An address the server did not offer is either a stale note or a
    /// misdirection, and dialling it puts session material somewhere the gateway
    /// never pointed us.
    #[default]
    Reject,
    /// Permit with a warning. Needed while the advertised list itself is under
    /// investigation and a known-good address has to be forced.
    Allow,
}

/// Outcome of one selection pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSelection {
    pub chosen: NodeMeasurement,
    /// Every candidate: reachable first by ascending latency, then the rest.
    pub ranked: Vec<NodeMeasurement>,
    pub source: SelectionSource,
}

impl NodeSelection {
    #[must_use]
    pub fn host_port(&self) -> (String, u16) {
        (self.chosen.endpoint.host.clone(), self.chosen.endpoint.port)
    }
}

#[derive(Debug, Error)]
pub enum NodeSelectError {
    #[error("no data-plane endpoint was advertised")]
    NoCandidates,
    #[error("node address {0:?} is not a valid host:port")]
    MalformedAddress(String),
    #[error("requested node {requested} is not advertised by the gateway (advertised: {})",
        if advertised.is_empty() { "<none>".to_owned() } else { advertised.join(", ") })]
    NotAdvertised {
        requested: String,
        advertised: Vec<String>,
    },
    #[error("requested node {requested} is advertised but unreachable ({outcome})")]
    RequestedUnreachable {
        requested: String,
        outcome: NodeTlsProbeOutcome,
    },
    #[error("all {} advertised endpoints are unreachable", ranked.len())]
    AllUnreachable { ranked: Vec<NodeMeasurement> },
}

/// Probes every candidate concurrently and picks one.
///
/// `requested` is an operator-supplied `host:port`. When present it wins over
/// latency, but it must still be advertised (unless `unadvertised` allows it)
/// and must still answer — a silent fallback to a different node would make
/// every measurement taken afterwards unattributable.
pub async fn select_node(
    candidates: &[(String, ResolvedNodeEndpoint)],
    requested: Option<&str>,
    unadvertised: UnadvertisedNode,
    tls_policy: TlsPolicy,
    connect_timeout: Duration,
) -> Result<NodeSelection, NodeSelectError> {
    select_node_with(
        candidates,
        requested,
        unadvertised,
        |host: String, port: u16| async move {
            let result = probe_node_tls(&host, port, tls_policy, connect_timeout).await;
            (result.outcome, result.elapsed)
        },
    )
    .await
}

/// [`select_node`] with the probe injected, so the ranking and fail-closed rules
/// can be tested without a network.
pub async fn select_node_with<F, Fut>(
    candidates: &[(String, ResolvedNodeEndpoint)],
    requested: Option<&str>,
    unadvertised: UnadvertisedNode,
    probe: F,
) -> Result<NodeSelection, NodeSelectError>
where
    F: Fn(String, u16) -> Fut,
    Fut: Future<Output = (NodeTlsProbeOutcome, Duration)>,
{
    let requested = requested
        .map(|value| {
            parse_host_port(value)
                .ok_or_else(|| NodeSelectError::MalformedAddress(value.to_owned()))
        })
        .transpose()?;

    // An unadvertised override is refused before any probe: the point of
    // fail-closed is not to touch it at all.
    if let Some((host, port)) = requested.as_ref()
        && !is_advertised(candidates, host, *port)
    {
        let advertised = advertised_addresses(candidates);
        let requested = format_host_port(host, *port);
        match unadvertised {
            UnadvertisedNode::Reject => {
                return Err(NodeSelectError::NotAdvertised {
                    requested,
                    advertised,
                });
            }
            UnadvertisedNode::Allow => {
                warn!(
                    event = "atrust_auth.node_select.unadvertised_allowed",
                    requested = %requested,
                    advertised = %advertised.join(",")
                );
                let endpoint = ResolvedNodeEndpoint {
                    host: host.clone(),
                    port: *port,
                    address_type: "override".to_owned(),
                    from_sdpc_placeholder: false,
                };
                let (outcome, elapsed) = probe(host.clone(), *port).await;
                let measurement = NodeMeasurement {
                    group_id: String::new(),
                    endpoint,
                    outcome,
                    elapsed,
                };
                if !measurement.reachable() {
                    return Err(NodeSelectError::RequestedUnreachable {
                        requested,
                        outcome: measurement.outcome,
                    });
                }
                return Ok(NodeSelection {
                    ranked: vec![measurement.clone()],
                    chosen: measurement,
                    source: SelectionSource::RequestedUnadvertised,
                });
            }
        }
    }

    if candidates.is_empty() {
        return Err(NodeSelectError::NoCandidates);
    }

    // Every candidate is probed even when one was requested: the ranking is the
    // record of what the alternatives cost, which is the whole point of E1.
    let probes = candidates
        .iter()
        .map(|(group_id, endpoint)| {
            let future = probe(endpoint.host.clone(), endpoint.port);
            async move {
                let (outcome, elapsed) = future.await;
                NodeMeasurement {
                    group_id: group_id.clone(),
                    endpoint: endpoint.clone(),
                    outcome,
                    elapsed,
                }
            }
        })
        .collect::<Vec<_>>();
    let mut ranked = join_all(probes).await;

    // Reachable first, then ascending latency. A failed probe's elapsed time is
    // the timeout, which says nothing about the endpoint, so it never competes.
    ranked.sort_by(|left, right| {
        right
            .reachable()
            .cmp(&left.reachable())
            .then(left.elapsed.cmp(&right.elapsed))
    });

    for measurement in &ranked {
        debug!(
            event = "atrust_auth.node_select.measured",
            group_id = %measurement.group_id,
            address = %measurement.address(),
            outcome = %measurement.outcome,
            reachable = measurement.reachable(),
            elapsed_ms = measurement.elapsed.as_millis()
        );
    }

    let chosen = match requested {
        Some((host, port)) => {
            let requested = format_host_port(&host, port);
            let measurement = ranked
                .iter()
                .find(|measurement| matches_endpoint(&measurement.endpoint, &host, port))
                .cloned()
                .ok_or_else(|| NodeSelectError::NotAdvertised {
                    requested: requested.clone(),
                    advertised: advertised_addresses(candidates),
                })?;
            if !measurement.reachable() {
                return Err(NodeSelectError::RequestedUnreachable {
                    requested,
                    outcome: measurement.outcome,
                });
            }
            return Ok(NodeSelection {
                chosen: measurement,
                ranked,
                source: SelectionSource::Requested,
            });
        }
        None => ranked.iter().find(|measurement| measurement.reachable()),
    };

    let Some(chosen) = chosen.cloned() else {
        return Err(NodeSelectError::AllUnreachable { ranked });
    };
    Ok(NodeSelection {
        chosen,
        ranked,
        source: SelectionSource::LowestLatency,
    })
}

fn is_advertised(candidates: &[(String, ResolvedNodeEndpoint)], host: &str, port: u16) -> bool {
    candidates
        .iter()
        .any(|(_, endpoint)| matches_endpoint(endpoint, host, port))
}

/// Hosts compare case-insensitively; no DNS resolution happens here. An address
/// that resolves to an advertised IP is still a different address, and treating
/// it as the same one would reintroduce exactly the ambiguity fail-closed exists
/// to remove.
fn matches_endpoint(endpoint: &ResolvedNodeEndpoint, host: &str, port: u16) -> bool {
    endpoint.port == port && endpoint.host.eq_ignore_ascii_case(host)
}

fn advertised_addresses(candidates: &[(String, ResolvedNodeEndpoint)]) -> Vec<String> {
    candidates
        .iter()
        .map(|(_, endpoint)| endpoint.socket_display())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn parse_host_port(value: &str) -> Option<(String, u16)> {
    crate::resource::split_host_port(value, DEFAULT_NODE_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(host: &str, port: u16) -> (String, ResolvedNodeEndpoint) {
        (
            "group-1".to_owned(),
            ResolvedNodeEndpoint {
                host: host.to_owned(),
                port,
                address_type: "host".to_owned(),
                from_sdpc_placeholder: false,
            },
        )
    }

    /// Probe stub: reachable hosts map to a latency, everything else times out.
    fn prober<'a>(
        table: &'a [(&'static str, u64)],
    ) -> impl Fn(String, u16) -> std::future::Ready<(NodeTlsProbeOutcome, Duration)> + use<'a> {
        move |host: String, _port: u16| {
            let hit = table.iter().find(|(name, _)| *name == host);
            std::future::ready(match hit {
                Some((_, ms)) => (NodeTlsProbeOutcome::Ok, Duration::from_millis(*ms)),
                None => (NodeTlsProbeOutcome::Timeout, Duration::from_secs(5)),
            })
        }
    }

    #[tokio::test]
    async fn picks_the_lowest_latency_reachable_endpoint() {
        let candidates = vec![
            endpoint("10.255.57.11", 441),
            endpoint("slow.example.edu", 441),
            endpoint("61.150.43.94", 441),
        ];
        let selection = select_node_with(
            &candidates,
            None,
            UnadvertisedNode::Reject,
            prober(&[("61.150.43.94", 81), ("slow.example.edu", 400)]),
        )
        .await
        .expect("selection");

        assert_eq!(selection.chosen.endpoint.host, "61.150.43.94");
        assert_eq!(selection.source, SelectionSource::LowestLatency);
        // Server order put the unreachable internal address first; ranking must
        // not preserve it.
        assert_eq!(selection.ranked[0].endpoint.host, "61.150.43.94");
        assert_eq!(selection.ranked[1].endpoint.host, "slow.example.edu");
        assert!(!selection.ranked[2].reachable());
    }

    #[tokio::test]
    async fn unreachable_endpoints_never_win_on_a_fast_failure() {
        // A refused TCP connect returns in microseconds. Sorting on latency
        // alone would rank it first.
        let candidates = vec![
            endpoint("dead.example.edu", 441),
            endpoint("live.example.edu", 441),
        ];
        let selection = select_node_with(
            &candidates,
            None,
            UnadvertisedNode::Reject,
            |host: String, _port: u16| {
                std::future::ready(if host == "live.example.edu" {
                    (NodeTlsProbeOutcome::Ok, Duration::from_millis(300))
                } else {
                    (
                        NodeTlsProbeOutcome::TcpConnectFailed,
                        Duration::from_micros(50),
                    )
                })
            },
        )
        .await
        .expect("selection");

        assert_eq!(selection.chosen.endpoint.host, "live.example.edu");
    }

    #[tokio::test]
    async fn requested_endpoint_wins_over_a_faster_one() {
        let candidates = vec![
            endpoint("61.150.43.94", 441),
            endpoint("fast.example.edu", 441),
        ];
        let selection = select_node_with(
            &candidates,
            Some("61.150.43.94:441"),
            UnadvertisedNode::Reject,
            prober(&[("61.150.43.94", 200), ("fast.example.edu", 10)]),
        )
        .await
        .expect("selection");

        assert_eq!(selection.chosen.endpoint.host, "61.150.43.94");
        assert_eq!(selection.source, SelectionSource::Requested);
        // The alternatives were still measured, so the cost of the override is
        // visible in the log rather than inferred.
        assert_eq!(selection.ranked.len(), 2);
    }

    #[tokio::test]
    async fn unadvertised_request_is_refused_without_probing() {
        let candidates = vec![endpoint("10.255.57.11", 441)];
        let probes = std::cell::Cell::new(0u32);
        let error = select_node_with(
            &candidates,
            Some("61.150.43.94:441"),
            UnadvertisedNode::Reject,
            |_host: String, _port: u16| {
                probes.set(probes.get() + 1);
                std::future::ready((NodeTlsProbeOutcome::Ok, Duration::from_millis(1)))
            },
        )
        .await
        .expect_err("unadvertised must fail closed");

        assert!(matches!(error, NodeSelectError::NotAdvertised { .. }));
        assert_eq!(probes.get(), 0, "fail-closed must not dial the address");
        assert!(error.to_string().contains("10.255.57.11:441"));
    }

    #[tokio::test]
    async fn unadvertised_request_is_allowed_under_the_escape_hatch() {
        let candidates = vec![endpoint("10.255.57.11", 441)];
        let selection = select_node_with(
            &candidates,
            Some("61.150.43.94:441"),
            UnadvertisedNode::Allow,
            prober(&[("61.150.43.94", 81)]),
        )
        .await
        .expect("selection");

        assert_eq!(selection.chosen.endpoint.host, "61.150.43.94");
        assert_eq!(selection.source, SelectionSource::RequestedUnadvertised);
    }

    #[tokio::test]
    async fn requested_but_unreachable_never_falls_back() {
        let candidates = vec![endpoint("10.255.57.11", 441), endpoint("61.150.43.94", 441)];
        let error = select_node_with(
            &candidates,
            Some("10.255.57.11:441"),
            UnadvertisedNode::Reject,
            prober(&[("61.150.43.94", 81)]),
        )
        .await
        .expect_err("a pinned dead node must not silently become another node");

        assert!(matches!(
            error,
            NodeSelectError::RequestedUnreachable { .. }
        ));
    }

    #[tokio::test]
    async fn all_unreachable_reports_every_measurement() {
        let candidates = vec![endpoint("10.255.57.11", 441), endpoint("61.150.43.99", 441)];
        let error = select_node_with(&candidates, None, UnadvertisedNode::Reject, prober(&[]))
            .await
            .expect_err("no reachable endpoint");

        match error {
            NodeSelectError::AllUnreachable { ranked } => assert_eq!(ranked.len(), 2),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn empty_candidate_list_is_an_error_not_a_default() {
        let error = select_node_with(&[], None, UnadvertisedNode::Reject, prober(&[]))
            .await
            .expect_err("no candidates");
        assert!(matches!(error, NodeSelectError::NoCandidates));
    }

    #[tokio::test]
    async fn request_defaults_to_the_node_port_and_ignores_host_case() {
        let candidates = vec![endpoint("Node.Example.Edu", 441)];
        let selection = select_node_with(
            &candidates,
            Some("node.example.edu"),
            UnadvertisedNode::Reject,
            prober(&[("Node.Example.Edu", 12)]),
        )
        .await
        .expect("selection");

        assert_eq!(selection.chosen.endpoint.port, DEFAULT_NODE_PORT);
        assert_eq!(selection.source, SelectionSource::Requested);
    }

    #[tokio::test]
    async fn malformed_request_is_rejected() {
        let candidates = vec![endpoint("61.150.43.94", 441)];
        let error = select_node_with(
            &candidates,
            Some("61.150.43.94:not-a-port"),
            UnadvertisedNode::Reject,
            prober(&[]),
        )
        .await
        .expect_err("malformed");
        assert!(matches!(error, NodeSelectError::MalformedAddress(_)));
    }
}
