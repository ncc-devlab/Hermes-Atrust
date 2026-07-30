use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use atrust_protocol::to_wire_json;
use hermes_model::GatewayEndpoint;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default aTrust data-plane node port when the resource omits an explicit port.
pub const DEFAULT_NODE_PORT: u16 = 441;
const SDPC_HOST_PLACEHOLDER: &str = "{{sdpcHost}}";

/// Deterministic clientResource request body (field order is part of the wire profile).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientResourceRequest {
    resource_type: ClientResourceTypeRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientResourceTypeRequest {
    sdp_policy: EmptyObject,
    app_list: EmptyObject,
    favorite_app_list: EmptyObject,
    feature_center: EmptyObject,
    uem_space: UemSpaceRequest,
}

#[derive(Serialize)]
struct EmptyObject {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UemSpaceRequest {
    params: UemSpaceParams,
}

#[derive(Serialize)]
struct UemSpaceParams {
    action: &'static str,
}

impl ClientResourceRequest {
    pub(crate) fn default_request() -> Self {
        Self {
            resource_type: ClientResourceTypeRequest {
                sdp_policy: EmptyObject {},
                app_list: EmptyObject {},
                favorite_app_list: EmptyObject {},
                feature_center: EmptyObject {},
                uem_space: UemSpaceRequest {
                    params: UemSpaceParams { action: "login" },
                },
            },
        }
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, atrust_protocol::ProtocolJsonError> {
        to_wire_json(self)
    }
}

/// Strict, tunnel-free view of resources returned by clientResource.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientResources {
    pub ip_resources: Vec<IpResource>,
    pub domain_resources: Vec<DomainResource>,
    pub node_groups: Vec<NodeGroup>,
    pub major_node_group_id: Option<String>,
    pub dns: DnsServers,
}

impl fmt::Debug for ClientResources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientResources")
            .field("ip_resource_count", &self.ip_resources.len())
            .field("domain_resource_count", &self.domain_resources.len())
            .field("node_group_count", &self.node_groups.len())
            .field(
                "major_node_group_present",
                &self.major_node_group_id.is_some(),
            )
            .field("dns", &self.dns)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServers {
    pub primary: Option<String>,
    pub secondary: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGroup {
    pub id: String,
    pub addresses: Vec<NodeAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAddress {
    pub address: String,
    pub address_type: String,
}

/// Resolved data-plane endpoint for a node group member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedNodeEndpoint {
    pub host: String,
    pub port: u16,
    pub address_type: String,
    /// True when `{{sdpcHost}}` was substituted with the control-plane gateway host.
    pub from_sdpc_placeholder: bool,
}

impl ResolvedNodeEndpoint {
    pub fn socket_display(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        self.socket_display().parse().ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedNodeGroup {
    pub id: String,
    pub endpoints: Vec<ResolvedNodeEndpoint>,
}

impl ClientResources {
    /// Resolves node group addresses without probing reachability or opening tunnels.
    pub fn resolve_node_groups(&self, gateway: &GatewayEndpoint) -> Vec<ResolvedNodeGroup> {
        self.node_groups
            .iter()
            .map(|group| ResolvedNodeGroup {
                id: group.id.clone(),
                endpoints: group
                    .addresses
                    .iter()
                    .filter_map(|address| resolve_node_address(address, gateway))
                    .collect(),
            })
            .collect()
    }

    /// Returns every resolved endpoint from every node group without probing or scoring.
    pub fn all_nodes(&self, gateway: &GatewayEndpoint) -> Vec<(String, ResolvedNodeEndpoint)> {
        self.resolve_node_groups(gateway)
            .into_iter()
            .flat_map(|group| {
                let id = group.id;
                group
                    .endpoints
                    .into_iter()
                    .map(move |endpoint| (id.clone(), endpoint))
            })
            .collect()
    }

    /// Picks the first resolved endpoint for each group (no latency scoring yet).
    pub fn primary_nodes(&self, gateway: &GatewayEndpoint) -> Vec<(String, ResolvedNodeEndpoint)> {
        self.resolve_node_groups(gateway)
            .into_iter()
            .filter_map(|group| {
                let endpoint = group.endpoints.into_iter().next()?;
                Some((group.id, endpoint))
            })
            .collect()
    }
}

fn resolve_node_address(
    address: &NodeAddress,
    gateway: &GatewayEndpoint,
) -> Option<ResolvedNodeEndpoint> {
    let raw = address.address.trim();
    if raw.is_empty() {
        return None;
    }
    let from_sdpc_placeholder = raw.contains(SDPC_HOST_PLACEHOLDER);
    let substituted = if from_sdpc_placeholder {
        raw.replace(SDPC_HOST_PLACEHOLDER, gateway.host())
    } else {
        raw.to_owned()
    };
    let (host, port) = split_host_port(&substituted, DEFAULT_NODE_PORT)?;
    if host.is_empty() {
        return None;
    }
    Some(ResolvedNodeEndpoint {
        host,
        port,
        address_type: address.address_type.clone(),
        from_sdpc_placeholder,
    })
}

fn split_host_port(value: &str, default_port: u16) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if after.is_empty() {
            return Some((host.to_owned(), default_port));
        }
        let port = after.strip_prefix(':')?.parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some((host.to_owned(), port));
    }
    // Bare IPv6 without brackets is not accepted as host:port.
    if value.matches(':').count() > 1 {
        return Some((value.to_owned(), default_port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.is_empty() {
            return None;
        }
        let port = port.parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some((host.to_owned(), port));
    }
    Some((value.to_owned(), default_port))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpResource {
    pub ip_min: Ipv4Addr,
    pub ip_max: Ipv4Addr,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: ResourceProtocol,
    pub app_id: String,
    pub node_group_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainResource {
    pub host: String,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: ResourceProtocol,
    pub app_id: String,
    pub node_group_id: String,
    pub resolved_ips: Vec<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceProtocol {
    Tcp,
    Udp,
    All,
}

impl ResourceProtocol {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ResourceError {
    #[error("clientResource response is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("clientResource rejected with code {code}: {message}")]
    Rejected { code: i64, message: String },
    #[error("clientResource response is missing data")]
    MissingData,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ClientResourceEnvelope {
    #[serde(default)]
    pub code: Option<i64>,
    #[serde(default)]
    pub message: String,
    #[serde(default, alias = "Data")]
    pub data: Option<ClientResourceData>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientResourceData {
    #[serde(default, alias = "AppList")]
    app_list: NestedSection<AppListData>,
    #[serde(default, alias = "SDPPolicy", alias = "SdpPolicy")]
    sdp_policy: NestedSection<SdpPolicyData>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NestedSection<T> {
    #[serde(default, alias = "Data")]
    data: T,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppListData {
    #[serde(default, alias = "AppInfo")]
    app_info: Vec<AppInfoGroup>,
    #[serde(default, alias = "Config")]
    config: AppListConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppInfoGroup {
    #[serde(default, alias = "Apps")]
    apps: Vec<AppItem>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppItem {
    #[serde(default, alias = "ID", alias = "Id")]
    id: String,
    #[serde(default, alias = "NodeGroupID", alias = "NodeGroupId")]
    node_group_id: String,
    #[serde(default, alias = "AddressList")]
    address_list: Vec<AddressItem>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressItem {
    #[serde(default, alias = "Protocol")]
    protocol: String,
    #[serde(default, alias = "Port")]
    port: String,
    #[serde(default, alias = "Host")]
    host: String,
    #[serde(default, alias = "IP")]
    ip: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppListConfig {
    #[serde(default, alias = "NodeGroupConf")]
    node_group_conf: NodeGroupConf,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeGroupConf {
    #[serde(default, alias = "MajorNodeGroup")]
    major_node_group: MajorNodeGroup,
    #[serde(default, alias = "NodeGroupList")]
    node_group_list: Vec<NodeGroupItem>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MajorNodeGroup {
    #[serde(default, alias = "ID", alias = "Id")]
    id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeGroupItem {
    #[serde(default, alias = "ID", alias = "Id")]
    id: String,
    #[serde(default, alias = "AddressInfo")]
    address_info: Vec<NodeAddressItem>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeAddressItem {
    #[serde(default, alias = "Address")]
    address: String,
    #[serde(default, rename = "type", alias = "Type")]
    address_type: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SdpPolicyData {
    #[serde(default, alias = "ClientOption")]
    client_option: ClientOptionData,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientOptionData {
    #[serde(default, alias = "DNSOption")]
    dns_option: DnsOptionData,
    #[serde(default, alias = "DNSOptionV2")]
    dns_option_v2: DnsOptionData,
}

#[derive(Debug, Default, Deserialize)]
struct DnsOptionData {
    // Service uses firstDNS (DNS fully capitalized), not serde camelCase firstDns.
    #[serde(default, rename = "firstDNS", alias = "FirstDNS")]
    first_dns: String,
    #[serde(default, rename = "secondDNS", alias = "SecondDNS")]
    second_dns: String,
}

impl ClientResources {
    pub(crate) fn from_envelope(envelope: ClientResourceEnvelope) -> Result<Self, ResourceError> {
        if let Some(code) = envelope.code
            && code != 0
        {
            return Err(ResourceError::Rejected {
                code,
                message: envelope.message,
            });
        }
        let data = envelope.data.ok_or(ResourceError::MissingData)?;
        Ok(Self::from_data(data))
    }

    /// Parses a `clientResource` response body captured earlier.
    ///
    /// Lets resource matching be developed and replayed offline against a real
    /// gateway body, with no session and no network.
    pub fn from_json_bytes(body: &[u8]) -> Result<Self, ResourceError> {
        Self::parse_bytes(body)
    }

    pub(crate) fn parse_bytes(body: &[u8]) -> Result<Self, ResourceError> {
        let envelope: ClientResourceEnvelope = serde_json::from_slice(body)
            .map_err(|error| ResourceError::InvalidJson(error.to_string()))?;
        Self::from_envelope(envelope)
    }

    fn from_data(data: ClientResourceData) -> Self {
        let mut ip_resources = Vec::new();
        let mut domain_resources = Vec::new();

        for group in data.app_list.data.app_info {
            for app in group.apps {
                if app.id.is_empty() || app.node_group_id.is_empty() {
                    continue;
                }
                for address in app.address_list {
                    let Some(protocol) = ResourceProtocol::parse(&address.protocol) else {
                        continue;
                    };
                    let Some((port_min, port_max)) = parse_port_range(&address.port) else {
                        continue;
                    };
                    let host = address.host.trim();
                    if host.is_empty() {
                        continue;
                    }
                    match classify_host(host) {
                        HostKind::Ip(ip) => ip_resources.push(IpResource {
                            ip_min: ip,
                            ip_max: ip,
                            port_min,
                            port_max,
                            protocol,
                            app_id: app.id.clone(),
                            node_group_id: app.node_group_id.clone(),
                        }),
                        HostKind::Cidr { min, max } => ip_resources.push(IpResource {
                            ip_min: min,
                            ip_max: max,
                            port_min,
                            port_max,
                            protocol,
                            app_id: app.id.clone(),
                            node_group_id: app.node_group_id.clone(),
                        }),
                        HostKind::Range { min, max } => ip_resources.push(IpResource {
                            ip_min: min,
                            ip_max: max,
                            port_min,
                            port_max,
                            protocol,
                            app_id: app.id.clone(),
                            node_group_id: app.node_group_id.clone(),
                        }),
                        HostKind::Domain => {
                            let mut resolved_ips = Vec::new();
                            for ip in &address.ip {
                                if let Ok(parsed) = Ipv4Addr::from_str(ip.trim()) {
                                    resolved_ips.push(parsed);
                                }
                            }
                            domain_resources.push(DomainResource {
                                host: host.to_owned(),
                                port_min,
                                port_max,
                                protocol,
                                app_id: app.id.clone(),
                                node_group_id: app.node_group_id.clone(),
                                resolved_ips,
                            });
                        }
                    }
                }
            }
        }

        let major = data
            .app_list
            .data
            .config
            .node_group_conf
            .major_node_group
            .id;
        let major_node_group_id = if major.is_empty() { None } else { Some(major) };

        let mut node_groups = Vec::new();
        for group in data.app_list.data.config.node_group_conf.node_group_list {
            if group.id.is_empty() {
                continue;
            }
            let addresses = group
                .address_info
                .into_iter()
                .filter(|item| !item.address.is_empty())
                .map(|item| NodeAddress {
                    address: item.address,
                    address_type: item.address_type,
                })
                .collect();
            node_groups.push(NodeGroup {
                id: group.id,
                addresses,
            });
        }

        let dns = {
            let v1 = &data.sdp_policy.data.client_option.dns_option;
            let v2 = &data.sdp_policy.data.client_option.dns_option_v2;
            let primary = first_non_empty([&v1.first_dns, &v2.first_dns]);
            let secondary = first_non_empty([&v1.second_dns, &v2.second_dns]);
            DnsServers { primary, secondary }
        };

        Self {
            ip_resources,
            domain_resources,
            node_groups,
            major_node_group_id,
            dns,
        }
    }
}

fn first_non_empty(values: [&str; 2]) -> Option<String> {
    values
        .into_iter()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_port_range(value: &str) -> Option<(u16, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some((left, right)) = value.split_once('-') {
        let min = left.trim().parse::<u16>().ok()?;
        let max = right.trim().parse::<u16>().ok()?;
        if min == 0 || max == 0 || min > max {
            return None;
        }
        return Some((min, max));
    }
    let port = value.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some((port, port))
}

enum HostKind {
    Ip(Ipv4Addr),
    Cidr { min: Ipv4Addr, max: Ipv4Addr },
    Range { min: Ipv4Addr, max: Ipv4Addr },
    Domain,
}

fn classify_host(host: &str) -> HostKind {
    if let Ok(ip) = Ipv4Addr::from_str(host) {
        return HostKind::Ip(ip);
    }
    if let Some((network, prefix)) = host.split_once('/')
        && let (Ok(base), Ok(bits)) = (Ipv4Addr::from_str(network.trim()), prefix.parse::<u8>())
        && bits <= 32
    {
        let base_u = u32::from(base);
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        let min = Ipv4Addr::from(base_u & mask);
        let max = Ipv4Addr::from((base_u & mask) | !mask);
        return HostKind::Cidr { min, max };
    }
    if let Some((left, right)) = host.split_once('-')
        && let (Ok(min), Ok(max)) = (
            Ipv4Addr::from_str(left.trim()),
            Ipv4Addr::from_str(right.trim()),
        )
        && u32::from(min) <= u32::from(max)
    {
        return HostKind::Range { min, max };
    }
    HostKind::Domain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_is_compact_and_ordered() {
        let bytes = ClientResourceRequest::default_request().to_bytes().unwrap();
        assert_eq!(
            bytes,
            br#"{"resourceType":{"sdpPolicy":{},"appList":{},"favoriteAppList":{},"featureCenter":{},"uemSpace":{"params":{"action":"login"}}}}"#
        );
    }

    #[test]
    fn rejects_nonzero_business_code() {
        let body = br#"{"code":500,"message":"denied","data":{}}"#;
        assert_eq!(
            ClientResources::parse_bytes(body),
            Err(ResourceError::Rejected {
                code: 500,
                message: "denied".to_owned()
            })
        );
    }

    #[test]
    fn parses_ip_cidr_domain_nodes_and_dns() {
        let body = br#"{
            "code": 0,
            "message": "ok",
            "data": {
                "appList": {
                    "data": {
                        "appInfo": [{
                            "apps": [{
                                "id": "app-1",
                                "nodeGroupId": "ng-1",
                                "addressList": [
                                    {"protocol":"tcp","port":"443","host":"10.0.0.1"},
                                    {"protocol":"all","port":"1-1024","host":"10.1.0.0/16"},
                                    {"protocol":"udp","port":"53","host":"*.example.edu","ip":["10.2.0.9","bad"]}
                                ]
                            }]
                        }],
                        "config": {
                            "nodeGroupConf": {
                                "majorNodeGroup": {"id": "ng-major"},
                                "nodeGroupList": [{
                                    "id": "ng-1",
                                    "addressInfo": [
                                        {"address":"{{sdpcHost}}","type":"host"},
                                        {"address":"10.9.0.1:441","type":"ip"}
                                    ]
                                }]
                            }
                        }
                    }
                },
                "sdpPolicy": {
                    "data": {
                        "clientOption": {
                            "dnsOption": {"firstDNS":"","secondDNS":""},
                            "dnsOptionV2": {"firstDNS":"10.8.8.8","secondDNS":"10.8.4.4"}
                        }
                    }
                }
            }
        }"#;
        let resources = ClientResources::parse_bytes(body).unwrap();
        assert_eq!(resources.ip_resources.len(), 2);
        assert_eq!(resources.ip_resources[0].ip_min, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(resources.ip_resources[0].port_min, 443);
        assert_eq!(resources.ip_resources[0].protocol, ResourceProtocol::Tcp);
        assert_eq!(resources.ip_resources[1].ip_min, Ipv4Addr::new(10, 1, 0, 0));
        assert_eq!(
            resources.ip_resources[1].ip_max,
            Ipv4Addr::new(10, 1, 255, 255)
        );
        assert_eq!(resources.domain_resources.len(), 1);
        assert_eq!(resources.domain_resources[0].host, "*.example.edu");
        assert_eq!(
            resources.domain_resources[0].resolved_ips,
            vec![Ipv4Addr::new(10, 2, 0, 9)]
        );
        assert_eq!(resources.major_node_group_id.as_deref(), Some("ng-major"));
        assert_eq!(resources.node_groups.len(), 1);
        assert_eq!(resources.node_groups[0].addresses.len(), 2);
        assert_eq!(resources.dns.primary.as_deref(), Some("10.8.8.8"));
        assert_eq!(resources.dns.secondary.as_deref(), Some("10.8.4.4"));
        assert!(!format!("{resources:?}").contains("app-1"));
    }

    #[test]
    fn skips_invalid_ports_protocols_and_empty_app_ids() {
        let body = br#"{
            "code":0,
            "data":{
                "appList":{"data":{"appInfo":[{"apps":[
                    {"id":"","nodeGroupId":"ng","addressList":[{"protocol":"tcp","port":"80","host":"1.1.1.1"}]},
                    {"id":"app","nodeGroupId":"ng","addressList":[
                        {"protocol":"icmp","port":"80","host":"1.1.1.1"},
                        {"protocol":"tcp","port":"0","host":"1.1.1.1"},
                        {"protocol":"tcp","port":"90-80","host":"1.1.1.1"}
                    ]}
                ]}]}}
            }
        }"#;
        let resources = ClientResources::parse_bytes(body).unwrap();
        assert!(resources.ip_resources.is_empty());
        assert!(resources.domain_resources.is_empty());
    }

    #[test]
    fn accepts_go_style_pascal_case_fields() {
        let body = br#"{
            "code":0,
            "Data":{
                "AppList":{"Data":{
                    "AppInfo":[{"Apps":[{
                        "ID":"app-x",
                        "NodeGroupID":"ng-x",
                        "AddressList":[{"Protocol":"tcp","Port":"22","Host":"192.168.1.1"}]
                    }]}],
                    "Config":{"NodeGroupConf":{"MajorNodeGroup":{"ID":"major-x"},"NodeGroupList":[]}}
                }}
            }
        }"#;
        let resources = ClientResources::parse_bytes(body).unwrap();
        assert_eq!(resources.ip_resources.len(), 1);
        assert_eq!(resources.ip_resources[0].app_id, "app-x");
        assert_eq!(resources.ip_resources[0].node_group_id, "ng-x");
        assert_eq!(resources.major_node_group_id.as_deref(), Some("major-x"));
    }

    #[test]
    fn empty_data_object_yields_empty_resources() {
        let resources = ClientResources::parse_bytes(br#"{"code":0,"data":{}}"#).unwrap();
        assert!(resources.ip_resources.is_empty());
        assert!(resources.domain_resources.is_empty());
        assert!(resources.node_groups.is_empty());
        assert!(resources.major_node_group_id.is_none());
        assert!(resources.dns.primary.is_none());
    }

    #[test]
    fn resolves_sdpc_placeholder_and_default_node_port() {
        use hermes_model::GatewayEndpoint;

        let resources = ClientResources {
            ip_resources: Vec::new(),
            domain_resources: Vec::new(),
            node_groups: vec![NodeGroup {
                id: "ng-1".to_owned(),
                addresses: vec![
                    NodeAddress {
                        address: "{{sdpcHost}}".to_owned(),
                        address_type: "host".to_owned(),
                    },
                    NodeAddress {
                        address: "10.9.0.1:442".to_owned(),
                        address_type: "ip".to_owned(),
                    },
                    NodeAddress {
                        address: "10.9.0.2".to_owned(),
                        address_type: "ip".to_owned(),
                    },
                ],
            }],
            major_node_group_id: Some("ng-1".to_owned()),
            dns: DnsServers {
                primary: None,
                secondary: None,
            },
        };
        let gateway = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let resolved = resources.resolve_node_groups(&gateway);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].endpoints.len(), 3);
        assert_eq!(resolved[0].endpoints[0].host, "atrust.example.edu");
        assert_eq!(resolved[0].endpoints[0].port, DEFAULT_NODE_PORT);
        assert!(resolved[0].endpoints[0].from_sdpc_placeholder);
        assert_eq!(resolved[0].endpoints[1].port, 442);
        assert!(!resolved[0].endpoints[1].from_sdpc_placeholder);
        assert_eq!(resolved[0].endpoints[2].port, DEFAULT_NODE_PORT);
        let all = resources.all_nodes(&gateway);
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|(group_id, _)| group_id == "ng-1"));
        assert_eq!(all[1].1.socket_display(), "10.9.0.1:442");
        let primaries = resources.primary_nodes(&gateway);
        assert_eq!(primaries.len(), 1);
        assert_eq!(primaries[0].1.socket_display(), "atrust.example.edu:441");
    }

    #[test]
    fn split_host_port_supports_ipv6_brackets() {
        let (host, port) = split_host_port("[2001:db8::1]:441", DEFAULT_NODE_PORT).unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 441);
        let (host, port) = split_host_port("[2001:db8::2]", DEFAULT_NODE_PORT).unwrap();
        assert_eq!(host, "2001:db8::2");
        assert_eq!(port, DEFAULT_NODE_PORT);
    }
}
