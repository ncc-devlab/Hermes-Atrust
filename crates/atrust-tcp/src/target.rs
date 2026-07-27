use std::fmt;
use std::net::Ipv4Addr;

/// Destination presented to the data-plane node during TCP handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelTarget {
    /// Raw IPv4 (type 0x01 destination block).
    Ipv4 {
        ip: Ipv4Addr,
        port: u16,
        app_id: String,
    },
    /// Domain name (type 0x03 destination block); `url`/`destAddr` use the domain.
    Domain {
        host: String,
        port: u16,
        app_id: String,
        /// Optional resolved IPv4 for logging; handshake uses domain bytes only.
        resolved: Option<Ipv4Addr>,
    },
}

impl TunnelTarget {
    pub fn app_id(&self) -> &str {
        match self {
            Self::Ipv4 { app_id, .. } | Self::Domain { app_id, .. } => app_id.as_str(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4 { port, .. } | Self::Domain { port, .. } => *port,
        }
    }

    pub fn dest_addr_string(&self) -> String {
        match self {
            Self::Ipv4 { ip, port, .. } => format!("{ip}:{port}"),
            Self::Domain { host, port, .. } => format!("{host}:{port}"),
        }
    }

    /// Host component for init JSON `url` / `destAddr`.
    pub fn json_dest_host(&self) -> String {
        match self {
            Self::Ipv4 { ip, .. } => ip.to_string(),
            Self::Domain { host, .. } => host.clone(),
        }
    }
}

impl fmt::Display for TunnelTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.dest_addr_string())
    }
}
