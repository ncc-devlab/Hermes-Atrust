//! Resource matching: does a flow belong in the tunnel, and under which
//! `appId` / `nodeGroupId`?
//!
//! Both data-plane paths need this before they may send anything. The L3 path
//! extracts `(dstIP, protocol, dstPort)` from an IPv4 packet and must hit a
//! server-published IP resource — an unmatched packet is not sent to the VPN at
//! all (`docs/atrust-protocol-analysis.md` §3.4, §6.4). The TCP tunnel path
//! resolves a `host:port` destination the same way, except a domain target is
//! matched against domain resources rather than resolved locally first, because
//! domain and IP resources may carry different `appId` and node groups.
//!
//! Matching is pure and offline: no network, no session, no tunnel. Build the
//! index once per `clientResource` fetch and query it per flow — the conntrack
//! layer above only asks on the first packet of a five-tuple.
//!
//! ## Ambiguity
//!
//! Real resource tables overlap (a `/16` and a `/32` inside it, a port range and
//! an exact port). The gateway's own precedence rule is **not confirmed**, so
//! this module ranks candidates by specificity — narrowest address range first,
//! then narrowest port range, then an exact protocol ahead of `all`, with the
//! server's original order breaking remaining ties — and exposes every candidate
//! through [`ResourceIndex::match_ip_all`] / [`ResourceIndex::match_domain_all`]
//! so a live capture can confirm or refute the ranking. If the gateway turns out
//! to be plain first-match-wins, only [`ResourceIndex::build`]'s sort changes.

use std::net::Ipv4Addr;

use hermes_model::GatewayEndpoint;

use crate::resource::{
    ClientResources, DomainResource, IpResource, ResolvedNodeEndpoint, ResourceProtocol,
};

/// IP-layer protocol of a flow, as read from an IPv4 packet header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowProtocol {
    Tcp,
    Udp,
    Icmp,
}

impl FlowProtocol {
    /// IANA protocol number carried in the IPv4 header.
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
        }
    }

    pub const fn from_number(value: u8) -> Option<Self> {
        match value {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            1 => Some(Self::Icmp),
            _ => None,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "icmp" => Some(Self::Icmp),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }

    /// ICMP carries no ports, so a port range cannot gate it.
    pub const fn has_ports(self) -> bool {
        !matches!(self, Self::Icmp)
    }
}

/// Destination of one flow to authorize. `port` is ignored for ICMP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowKey {
    pub destination: Ipv4Addr,
    pub port: u16,
    pub protocol: FlowProtocol,
}

impl FlowKey {
    pub const fn tcp(destination: Ipv4Addr, port: u16) -> Self {
        Self {
            destination,
            port,
            protocol: FlowProtocol::Tcp,
        }
    }

    pub const fn udp(destination: Ipv4Addr, port: u16) -> Self {
        Self {
            destination,
            port,
            protocol: FlowProtocol::Udp,
        }
    }

    /// ICMP has no port; the port field is set to zero and never compared.
    pub const fn icmp(destination: Ipv4Addr) -> Self {
        Self {
            destination,
            port: 0,
            protocol: FlowProtocol::Icmp,
        }
    }
}

/// Destination of one flow whose target is still a name (TCP tunnel path).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainFlow<'a> {
    pub host: &'a str,
    pub port: u16,
    pub protocol: FlowProtocol,
}

/// Which resource table authorized a destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination<'a> {
    Ip(&'a IpResource),
    Domain(&'a DomainResource),
}

impl Destination<'_> {
    pub fn app_id(&self) -> &str {
        match self {
            Self::Ip(resource) => &resource.app_id,
            Self::Domain(resource) => &resource.app_id,
        }
    }

    pub fn node_group_id(&self) -> &str {
        match self {
            Self::Ip(resource) => &resource.node_group_id,
            Self::Domain(resource) => &resource.node_group_id,
        }
    }

    pub fn protocol(&self) -> ResourceProtocol {
        match self {
            Self::Ip(resource) => resource.protocol,
            Self::Domain(resource) => resource.protocol,
        }
    }

    pub fn port_range(&self) -> (u16, u16) {
        match self {
            Self::Ip(resource) => (resource.port_min, resource.port_max),
            Self::Domain(resource) => (resource.port_min, resource.port_max),
        }
    }

    /// Stable label for logs and traces. Never includes credentials.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ip(_) => "ip",
            Self::Domain(_) => "domain",
        }
    }
}

/// Resource tables pre-sorted so the first hit is the most specific one.
#[derive(Clone, Debug)]
pub struct ResourceIndex {
    ip: Vec<IpResource>,
    domain: Vec<IndexedDomain>,
}

#[derive(Clone, Debug)]
struct IndexedDomain {
    pattern: DomainPattern,
    resource: DomainResource,
}

impl ResourceIndex {
    /// Builds the index once per `clientResource` fetch.
    ///
    /// Sorting is stable, so resources of equal specificity keep the order the
    /// gateway sent them in.
    pub fn build(resources: &ClientResources) -> Self {
        let mut ip = resources.ip_resources.clone();
        ip.sort_by_key(ip_specificity);

        let mut domain = resources
            .domain_resources
            .iter()
            .filter_map(|resource| {
                Some(IndexedDomain {
                    pattern: DomainPattern::parse(&resource.host)?,
                    resource: resource.clone(),
                })
            })
            .collect::<Vec<_>>();
        domain.sort_by_key(domain_specificity);

        Self { ip, domain }
    }

    pub fn ip_len(&self) -> usize {
        self.ip.len()
    }

    pub fn domain_len(&self) -> usize {
        self.domain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ip.is_empty() && self.domain.is_empty()
    }

    /// Most specific IP resource authorizing `flow`, or `None` when the flow is
    /// out of scope and must not be sent to the VPN.
    pub fn match_ip(&self, flow: FlowKey) -> Option<&IpResource> {
        self.ip
            .iter()
            .find(|resource| ip_resource_matches(resource, flow))
    }

    /// Every IP resource authorizing `flow`, most specific first. Use this to
    /// inspect an ambiguous table against a live capture.
    pub fn match_ip_all(&self, flow: FlowKey) -> Vec<&IpResource> {
        self.ip
            .iter()
            .filter(|resource| ip_resource_matches(resource, flow))
            .collect()
    }

    /// Most specific domain resource authorizing `flow`. An exact host beats a
    /// wildcard, and a longer wildcard suffix beats a shorter one.
    pub fn match_domain(&self, flow: DomainFlow<'_>) -> Option<&DomainResource> {
        let host = normalize_host(flow.host)?;
        self.domain
            .iter()
            .find(|entry| domain_entry_matches(entry, &host, flow))
            .map(|entry| &entry.resource)
    }

    pub fn match_domain_all(&self, flow: DomainFlow<'_>) -> Vec<&DomainResource> {
        let Some(host) = normalize_host(flow.host) else {
            return Vec::new();
        };
        self.domain
            .iter()
            .filter(|entry| domain_entry_matches(entry, &host, flow))
            .map(|entry| &entry.resource)
            .collect()
    }

    /// Matches a `host:port` destination the way the TCP tunnel path needs it:
    /// an IPv4 literal goes to the IP table, anything else to the domain table.
    ///
    /// A domain is deliberately not resolved locally first — domain and IP
    /// resources may carry different `appId` and node groups, so resolving early
    /// would lose the domain resource's semantics (§6.4).
    pub fn match_destination(
        &self,
        host: &str,
        port: u16,
        protocol: FlowProtocol,
    ) -> Option<Destination<'_>> {
        match host.trim().parse::<Ipv4Addr>() {
            Ok(destination) => self
                .match_ip(FlowKey {
                    destination,
                    port,
                    protocol,
                })
                .map(Destination::Ip),
            Err(_) => self
                .match_domain(DomainFlow {
                    host,
                    port,
                    protocol,
                })
                .map(Destination::Domain),
        }
    }
}

impl ClientResources {
    /// Builds the routing index for these resources.
    pub fn routing_index(&self) -> ResourceIndex {
        ResourceIndex::build(self)
    }

    /// Resolved endpoints of one node group, for a match's `node_group_id`.
    pub fn node_group_endpoints(
        &self,
        node_group_id: &str,
        gateway: &GatewayEndpoint,
    ) -> Vec<ResolvedNodeEndpoint> {
        self.resolve_node_groups(gateway)
            .into_iter()
            .find(|group| group.id == node_group_id)
            .map(|group| group.endpoints)
            .unwrap_or_default()
    }
}

/// Ranking key: narrowest address range, then narrowest port range, then an
/// exact protocol ahead of `all`. Lower sorts first.
fn ip_specificity(resource: &IpResource) -> (u32, u32, u8) {
    let address_span = u32::from(resource.ip_max).saturating_sub(u32::from(resource.ip_min));
    (
        address_span,
        port_span(resource.port_min, resource.port_max),
        protocol_rank(resource.protocol),
    )
}

/// Ranking key: exact host ahead of wildcard, then more suffix labels, then the
/// same port/protocol tiebreak as IP resources.
fn domain_specificity(entry: &IndexedDomain) -> (u8, i32, u32, u8) {
    let wildcard = u8::from(entry.pattern.wildcard);
    // Negated so that more labels (more specific) sorts first.
    let labels = -(entry.pattern.label_count() as i32);
    (
        wildcard,
        labels,
        port_span(entry.resource.port_min, entry.resource.port_max),
        protocol_rank(entry.resource.protocol),
    )
}

fn port_span(min: u16, max: u16) -> u32 {
    u32::from(max).saturating_sub(u32::from(min))
}

fn protocol_rank(protocol: ResourceProtocol) -> u8 {
    match protocol {
        ResourceProtocol::Tcp | ResourceProtocol::Udp | ResourceProtocol::Icmp => 0,
        ResourceProtocol::All => 1,
    }
}

fn ip_resource_matches(resource: &IpResource, flow: FlowKey) -> bool {
    let destination = u32::from(flow.destination);
    destination >= u32::from(resource.ip_min)
        && destination <= u32::from(resource.ip_max)
        && protocol_matches(resource.protocol, flow.protocol)
        && port_matches(
            resource.port_min,
            resource.port_max,
            flow.port,
            flow.protocol,
        )
}

fn domain_entry_matches(entry: &IndexedDomain, host: &str, flow: DomainFlow<'_>) -> bool {
    entry.pattern.matches(host)
        && protocol_matches(entry.resource.protocol, flow.protocol)
        && port_matches(
            entry.resource.port_min,
            entry.resource.port_max,
            flow.port,
            flow.protocol,
        )
}

/// A `tcp`/`udp` resource only carries its own protocol; `all` carries any.
///
/// ICMP therefore requires an `all` resource. This mirrors the resource table
/// having no ICMP protocol value of its own, and is **unconfirmed against a live
/// gateway** — verify before relying on ping through the tunnel.
fn protocol_matches(resource: ResourceProtocol, flow: FlowProtocol) -> bool {
    matches!(
        (resource, flow),
        (ResourceProtocol::All, _)
            | (ResourceProtocol::Tcp, FlowProtocol::Tcp)
            | (ResourceProtocol::Udp, FlowProtocol::Udp)
            | (ResourceProtocol::Icmp, FlowProtocol::Icmp)
    )
}

/// ICMP has no port, so a port range cannot exclude it; every other protocol
/// must fall inside the published range.
fn port_matches(min: u16, max: u16, port: u16, protocol: FlowProtocol) -> bool {
    if !protocol.has_ports() {
        return true;
    }
    port >= min && port <= max
}

/// Host pattern from a domain resource: either an exact name or a `*.` suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainPattern {
    /// Lowercase, trailing-dot-free. Empty only for the bare `*` pattern.
    suffix: String,
    wildcard: bool,
}

impl DomainPattern {
    fn parse(host: &str) -> Option<Self> {
        let host = host.trim().to_ascii_lowercase();
        if host == "*" {
            return Some(Self {
                suffix: String::new(),
                wildcard: true,
            });
        }
        let (wildcard, rest) = match host.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, host.as_str()),
        };
        // Strip the FQDN root dot only after the wildcard prefix is removed, so
        // a malformed `*.` cannot collapse into the match-everything pattern.
        let suffix = rest.trim_end_matches('.');
        if suffix.is_empty() {
            return None;
        }
        Some(Self {
            suffix: suffix.to_owned(),
            wildcard,
        })
    }

    /// `host` must already be normalized by [`normalize_host`].
    fn matches(&self, host: &str) -> bool {
        if !self.wildcard {
            return host == self.suffix;
        }
        if self.suffix.is_empty() {
            return true;
        }
        // `*.example.edu` covers any subdomain but not the apex itself.
        host.len() > self.suffix.len() + 1
            && host.ends_with(&self.suffix)
            && host.as_bytes()[host.len() - self.suffix.len() - 1] == b'.'
    }

    fn label_count(&self) -> usize {
        if self.suffix.is_empty() {
            0
        } else {
            self.suffix.split('.').count()
        }
    }
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{DnsServers, NodeAddress, NodeGroup};

    fn ip_resource(
        range: (&str, &str),
        ports: (u16, u16),
        protocol: ResourceProtocol,
        app_id: &str,
    ) -> IpResource {
        IpResource {
            ip_min: range.0.parse().unwrap(),
            ip_max: range.1.parse().unwrap(),
            port_min: ports.0,
            port_max: ports.1,
            protocol,
            app_id: app_id.to_owned(),
            node_group_id: format!("ng-{app_id}"),
        }
    }

    fn domain_resource(
        host: &str,
        ports: (u16, u16),
        protocol: ResourceProtocol,
        app_id: &str,
    ) -> DomainResource {
        DomainResource {
            host: host.to_owned(),
            port_min: ports.0,
            port_max: ports.1,
            protocol,
            app_id: app_id.to_owned(),
            node_group_id: format!("ng-{app_id}"),
            resolved_ips: Vec::new(),
        }
    }

    fn resources(ip: Vec<IpResource>, domain: Vec<DomainResource>) -> ClientResources {
        ClientResources {
            ip_resources: ip,
            domain_resources: domain,
            node_groups: Vec::new(),
            major_node_group_id: None,
            dns: DnsServers {
                primary: None,
                secondary: None,
            },
        }
    }

    #[test]
    fn unmatched_flow_is_out_of_scope() {
        // The contract that matters most: no resource means the packet must not
        // be sent to the VPN at all.
        let index = resources(
            vec![ip_resource(
                ("10.0.0.0", "10.0.255.255"),
                (443, 443),
                ResourceProtocol::Tcp,
                "a",
            )],
            Vec::new(),
        )
        .routing_index();

        assert!(
            index
                .match_ip(FlowKey::tcp("8.8.8.8".parse().unwrap(), 443))
                .is_none()
        );
        // In range, wrong port.
        assert!(
            index
                .match_ip(FlowKey::tcp("10.0.0.5".parse().unwrap(), 80))
                .is_none()
        );
        // In range and port, wrong protocol.
        assert!(
            index
                .match_ip(FlowKey::udp("10.0.0.5".parse().unwrap(), 443))
                .is_none()
        );
        assert!(
            index
                .match_ip(FlowKey::tcp("10.0.0.5".parse().unwrap(), 443))
                .is_some()
        );
    }

    #[test]
    fn narrowest_address_range_wins_over_a_broader_one() {
        // A /32 inside a /16 must win, otherwise a catch-all resource would
        // capture every flow and pick the wrong appId / node group.
        let index = resources(
            vec![
                ip_resource(
                    ("10.1.0.0", "10.1.255.255"),
                    (1, 65535),
                    ResourceProtocol::All,
                    "broad",
                ),
                ip_resource(
                    ("10.1.2.3", "10.1.2.3"),
                    (443, 443),
                    ResourceProtocol::Tcp,
                    "exact",
                ),
            ],
            Vec::new(),
        )
        .routing_index();

        let flow = FlowKey::tcp("10.1.2.3".parse().unwrap(), 443);
        let best = index.match_ip(flow).unwrap();
        assert_eq!(best.app_id, "exact");
        assert_eq!(best.node_group_id, "ng-exact");

        // Both remain visible, most specific first, for live comparison.
        let all = index.match_ip_all(flow);
        assert_eq!(
            all.iter().map(|r| r.app_id.as_str()).collect::<Vec<_>>(),
            vec!["exact", "broad"]
        );

        // A different address in the /16 still falls back to the broad resource.
        let other = index
            .match_ip(FlowKey::tcp("10.1.9.9".parse().unwrap(), 8080))
            .unwrap();
        assert_eq!(other.app_id, "broad");
    }

    #[test]
    fn equal_address_range_prefers_narrower_ports_then_exact_protocol() {
        let index = resources(
            vec![
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (1, 65535),
                    ResourceProtocol::All,
                    "any",
                ),
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (80, 443),
                    ResourceProtocol::All,
                    "band",
                ),
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (443, 443),
                    ResourceProtocol::All,
                    "all443",
                ),
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (443, 443),
                    ResourceProtocol::Tcp,
                    "tcp443",
                ),
            ],
            Vec::new(),
        )
        .routing_index();

        let all = index.match_ip_all(FlowKey::tcp("10.0.0.1".parse().unwrap(), 443));
        assert_eq!(
            all.iter().map(|r| r.app_id.as_str()).collect::<Vec<_>>(),
            vec!["tcp443", "all443", "band", "any"]
        );
    }

    #[test]
    fn equal_specificity_keeps_the_server_order() {
        let index = resources(
            vec![
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (443, 443),
                    ResourceProtocol::Tcp,
                    "first",
                ),
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (443, 443),
                    ResourceProtocol::Tcp,
                    "second",
                ),
            ],
            Vec::new(),
        )
        .routing_index();

        let best = index
            .match_ip(FlowKey::tcp("10.0.0.1".parse().unwrap(), 443))
            .unwrap();
        assert_eq!(best.app_id, "first");
    }

    #[test]
    fn icmp_needs_an_all_resource_and_ignores_ports() {
        let index = resources(
            vec![
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (443, 443),
                    ResourceProtocol::Tcp,
                    "tcp",
                ),
                ip_resource(
                    ("10.0.0.2", "10.0.0.2"),
                    (443, 443),
                    ResourceProtocol::All,
                    "all",
                ),
            ],
            Vec::new(),
        )
        .routing_index();

        // A tcp-only resource never authorizes ICMP.
        assert!(
            index
                .match_ip(FlowKey::icmp("10.0.0.1".parse().unwrap()))
                .is_none()
        );
        // An `all` resource does, and its port range cannot gate a portless protocol.
        let matched = index
            .match_ip(FlowKey::icmp("10.0.0.2".parse().unwrap()))
            .unwrap();
        assert_eq!(matched.app_id, "all");
    }

    #[test]
    fn udp_flow_matches_udp_and_all_but_not_tcp() {
        let index = resources(
            vec![
                ip_resource(
                    ("10.0.0.1", "10.0.0.1"),
                    (53, 53),
                    ResourceProtocol::Tcp,
                    "tcp",
                ),
                ip_resource(
                    ("10.0.0.2", "10.0.0.2"),
                    (53, 53),
                    ResourceProtocol::Udp,
                    "udp",
                ),
                ip_resource(
                    ("10.0.0.3", "10.0.0.3"),
                    (53, 53),
                    ResourceProtocol::All,
                    "all",
                ),
            ],
            Vec::new(),
        )
        .routing_index();

        assert!(
            index
                .match_ip(FlowKey::udp("10.0.0.1".parse().unwrap(), 53))
                .is_none()
        );
        assert_eq!(
            index
                .match_ip(FlowKey::udp("10.0.0.2".parse().unwrap(), 53))
                .unwrap()
                .app_id,
            "udp"
        );
        assert_eq!(
            index
                .match_ip(FlowKey::udp("10.0.0.3".parse().unwrap(), 53))
                .unwrap()
                .app_id,
            "all"
        );
    }

    #[test]
    fn port_range_boundaries_are_inclusive() {
        let index = resources(
            vec![ip_resource(
                ("10.0.0.1", "10.0.0.1"),
                (80, 443),
                ResourceProtocol::Tcp,
                "range",
            )],
            Vec::new(),
        )
        .routing_index();

        let address: Ipv4Addr = "10.0.0.1".parse().unwrap();
        assert!(index.match_ip(FlowKey::tcp(address, 79)).is_none());
        assert!(index.match_ip(FlowKey::tcp(address, 80)).is_some());
        assert!(index.match_ip(FlowKey::tcp(address, 443)).is_some());
        assert!(index.match_ip(FlowKey::tcp(address, 444)).is_none());
    }

    #[test]
    fn cidr_boundaries_are_inclusive() {
        let index = resources(
            vec![ip_resource(
                ("10.1.0.0", "10.1.255.255"),
                (443, 443),
                ResourceProtocol::Tcp,
                "cidr",
            )],
            Vec::new(),
        )
        .routing_index();

        assert!(
            index
                .match_ip(FlowKey::tcp("10.0.255.255".parse().unwrap(), 443))
                .is_none()
        );
        assert!(
            index
                .match_ip(FlowKey::tcp("10.1.0.0".parse().unwrap(), 443))
                .is_some()
        );
        assert!(
            index
                .match_ip(FlowKey::tcp("10.1.255.255".parse().unwrap(), 443))
                .is_some()
        );
        assert!(
            index
                .match_ip(FlowKey::tcp("10.2.0.0".parse().unwrap(), 443))
                .is_none()
        );
    }

    #[test]
    fn wildcard_domain_covers_subdomains_but_not_the_apex() {
        let index = resources(
            Vec::new(),
            vec![domain_resource(
                "*.example.edu",
                (443, 443),
                ResourceProtocol::Tcp,
                "wild",
            )],
        )
        .routing_index();

        let flow = |host| DomainFlow {
            host,
            port: 443,
            protocol: FlowProtocol::Tcp,
        };
        assert!(index.match_domain(flow("lib.example.edu")).is_some());
        assert!(index.match_domain(flow("a.b.example.edu")).is_some());
        assert!(index.match_domain(flow("example.edu")).is_none());
        assert!(index.match_domain(flow("notexample.edu")).is_none());
        assert!(index.match_domain(flow("example.edu.evil.com")).is_none());
    }

    #[test]
    fn exact_domain_beats_wildcard_and_longer_suffix_beats_shorter() {
        let index = resources(
            Vec::new(),
            vec![
                domain_resource("*.edu", (443, 443), ResourceProtocol::Tcp, "tld"),
                domain_resource("*.example.edu", (443, 443), ResourceProtocol::Tcp, "wild"),
                domain_resource(
                    "lib.example.edu",
                    (443, 443),
                    ResourceProtocol::Tcp,
                    "exact",
                ),
            ],
        )
        .routing_index();

        let flow = DomainFlow {
            host: "lib.example.edu",
            port: 443,
            protocol: FlowProtocol::Tcp,
        };
        assert_eq!(index.match_domain(flow).unwrap().app_id, "exact");
        assert_eq!(
            index
                .match_domain_all(flow)
                .iter()
                .map(|r| r.app_id.as_str())
                .collect::<Vec<_>>(),
            vec!["exact", "wild", "tld"]
        );
    }

    #[test]
    fn domain_match_is_case_and_trailing_dot_insensitive() {
        let index = resources(
            Vec::new(),
            vec![domain_resource(
                "Lib.Example.EDU.",
                (443, 443),
                ResourceProtocol::Tcp,
                "exact",
            )],
        )
        .routing_index();

        assert!(
            index
                .match_domain(DomainFlow {
                    host: "LIB.example.edu.",
                    port: 443,
                    protocol: FlowProtocol::Tcp,
                })
                .is_some()
        );
    }

    #[test]
    fn bare_star_matches_any_host_and_ranks_last() {
        let index = resources(
            Vec::new(),
            vec![
                domain_resource("*", (1, 65535), ResourceProtocol::All, "catchall"),
                domain_resource("*.example.edu", (443, 443), ResourceProtocol::Tcp, "wild"),
            ],
        )
        .routing_index();

        let inside = DomainFlow {
            host: "lib.example.edu",
            port: 443,
            protocol: FlowProtocol::Tcp,
        };
        assert_eq!(index.match_domain(inside).unwrap().app_id, "wild");
        assert_eq!(
            index
                .match_domain(DomainFlow {
                    host: "anything.test",
                    port: 8080,
                    protocol: FlowProtocol::Tcp,
                })
                .unwrap()
                .app_id,
            "catchall"
        );
    }

    #[test]
    fn destination_routes_literals_to_ip_and_names_to_domain() {
        let index = resources(
            vec![ip_resource(
                ("10.0.0.1", "10.0.0.1"),
                (443, 443),
                ResourceProtocol::Tcp,
                "byip",
            )],
            vec![domain_resource(
                "*.example.edu",
                (443, 443),
                ResourceProtocol::Tcp,
                "byname",
            )],
        )
        .routing_index();

        let literal = index
            .match_destination("10.0.0.1", 443, FlowProtocol::Tcp)
            .unwrap();
        assert_eq!(literal.kind(), "ip");
        assert_eq!(literal.app_id(), "byip");
        assert_eq!(literal.node_group_id(), "ng-byip");

        let name = index
            .match_destination("lib.example.edu", 443, FlowProtocol::Tcp)
            .unwrap();
        assert_eq!(name.kind(), "domain");
        assert_eq!(name.app_id(), "byname");

        // A name that resolves to an authorized IP is still not authorized by
        // the IP table: resolving early would lose the domain resource.
        assert!(
            index
                .match_destination("unknown.test", 443, FlowProtocol::Tcp)
                .is_none()
        );
    }

    #[test]
    fn invalid_domain_patterns_are_dropped_at_build_time() {
        let index = resources(
            Vec::new(),
            vec![
                domain_resource("", (443, 443), ResourceProtocol::Tcp, "empty"),
                domain_resource("*.", (443, 443), ResourceProtocol::Tcp, "danglingstar"),
                domain_resource("ok.test", (443, 443), ResourceProtocol::Tcp, "ok"),
            ],
        )
        .routing_index();

        assert_eq!(index.domain_len(), 1);
        assert!(
            index
                .match_domain(DomainFlow {
                    host: "",
                    port: 443,
                    protocol: FlowProtocol::Tcp,
                })
                .is_none()
        );
    }

    #[test]
    fn node_group_endpoints_resolve_for_a_match() {
        let mut resources = resources(
            vec![ip_resource(
                ("10.0.0.1", "10.0.0.1"),
                (443, 443),
                ResourceProtocol::Tcp,
                "a",
            )],
            Vec::new(),
        );
        resources.node_groups = vec![NodeGroup {
            id: "ng-a".to_owned(),
            addresses: vec![NodeAddress {
                address: "10.9.0.1:442".to_owned(),
                address_type: "ip".to_owned(),
            }],
        }];

        let gateway = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let index = resources.routing_index();
        let matched = index
            .match_ip(FlowKey::tcp("10.0.0.1".parse().unwrap(), 443))
            .unwrap();
        let endpoints = resources.node_group_endpoints(&matched.node_group_id, &gateway);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].socket_display(), "10.9.0.1:442");
        assert!(
            resources
                .node_group_endpoints("ng-missing", &gateway)
                .is_empty()
        );
    }

    #[test]
    fn matches_against_a_parsed_client_resource_body() {
        // End-to-end over the real parse path: a gateway body with a CIDR, an
        // exact host, a port range, and a wildcard domain, all under different
        // apps and node groups.
        let body = br#"{
            "code": 0,
            "data": {
                "appList": {
                    "data": {
                        "appInfo": [{
                            "apps": [
                                {
                                    "id": "app-web",
                                    "nodeGroupId": "ng-main",
                                    "addressList": [
                                        {"protocol":"tcp","port":"443","host":"10.1.2.3"},
                                        {"protocol":"tcp","port":"80-443","host":"*.lib.example.edu"}
                                    ]
                                },
                                {
                                    "id": "app-lan",
                                    "nodeGroupId": "ng-backup",
                                    "addressList": [
                                        {"protocol":"all","port":"1-65535","host":"10.1.0.0/16"}
                                    ]
                                }
                            ]
                        }],
                        "config": {
                            "nodeGroupConf": {
                                "majorNodeGroup": {"id": "ng-main"},
                                "nodeGroupList": [
                                    {"id":"ng-main","addressInfo":[{"address":"node-a.example.edu:441","type":"host"}]},
                                    {"id":"ng-backup","addressInfo":[{"address":"10.9.0.2","type":"ip"}]}
                                ]
                            }
                        }
                    }
                }
            }
        }"#;
        let resources = ClientResources::parse_bytes(body).unwrap();
        let index = resources.routing_index();
        assert_eq!(index.ip_len(), 2);
        assert_eq!(index.domain_len(), 1);
        assert!(!index.is_empty());

        let gateway = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();

        // The /32 beats the enclosing /16 and selects the other node group.
        let exact = index
            .match_destination("10.1.2.3", 443, FlowProtocol::Tcp)
            .unwrap();
        assert_eq!(exact.app_id(), "app-web");
        assert_eq!(exact.node_group_id(), "ng-main");
        assert_eq!(
            resources.node_group_endpoints(exact.node_group_id(), &gateway)[0].socket_display(),
            "node-a.example.edu:441"
        );

        // Same address, port outside the /32 resource, falls back to the /16.
        let fallback = index
            .match_destination("10.1.2.3", 8080, FlowProtocol::Tcp)
            .unwrap();
        assert_eq!(fallback.app_id(), "app-lan");
        assert_eq!(
            resources.node_group_endpoints(fallback.node_group_id(), &gateway)[0].socket_display(),
            "10.9.0.2:441"
        );

        // UDP is only carried by the `all` resource.
        assert_eq!(
            index
                .match_destination("10.1.2.3", 53, FlowProtocol::Udp)
                .unwrap()
                .app_id(),
            "app-lan"
        );

        // Domain target keeps its own app, and is not authorized by the IP table.
        let domain = index
            .match_destination("opac.lib.example.edu", 80, FlowProtocol::Tcp)
            .unwrap();
        assert_eq!(domain.kind(), "domain");
        assert_eq!(domain.app_id(), "app-web");
        assert!(
            index
                .match_destination("opac.lib.example.edu", 8080, FlowProtocol::Tcp)
                .is_none()
        );

        // Anything outside every resource stays out of the tunnel.
        assert!(
            index
                .match_destination("8.8.8.8", 443, FlowProtocol::Tcp)
                .is_none()
        );
    }

    #[test]
    fn flow_protocol_maps_ipv4_header_numbers() {
        assert_eq!(FlowProtocol::from_number(6), Some(FlowProtocol::Tcp));
        assert_eq!(FlowProtocol::from_number(17), Some(FlowProtocol::Udp));
        assert_eq!(FlowProtocol::from_number(1), Some(FlowProtocol::Icmp));
        assert_eq!(FlowProtocol::from_number(58), None);
        assert_eq!(FlowProtocol::Tcp.number(), 6);
        assert_eq!(FlowProtocol::parse("UDP"), Some(FlowProtocol::Udp));
        assert_eq!(FlowProtocol::parse("icmp6"), None);
        assert!(!FlowProtocol::Icmp.has_ports());
        assert!(FlowProtocol::Tcp.has_ports());
    }
    /// An `icmp` resource must authorize ICMP flows and nothing else, matching
    /// zju-connect's `resource.Protocol == protocol || == "all"` check.
    #[test]
    fn icmp_resource_authorizes_only_icmp() {
        let resource = IpResource {
            ip_min: Ipv4Addr::new(10, 0, 0, 1),
            ip_max: Ipv4Addr::new(10, 0, 0, 1),
            port_min: 0,
            port_max: 65535,
            protocol: ResourceProtocol::Icmp,
            app_id: "app-icmp".to_owned(),
            node_group_id: "ng".to_owned(),
        };
        let target = Ipv4Addr::new(10, 0, 0, 1);
        assert!(ip_resource_matches(&resource, FlowKey::icmp(target)));
        assert!(!ip_resource_matches(&resource, FlowKey::tcp(target, 80)));
        assert!(!ip_resource_matches(&resource, FlowKey::udp(target, 80)));
    }
}
