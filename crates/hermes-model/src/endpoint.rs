use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::Serialize;
use thiserror::Error;

/// Network location of an aTrust gateway.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GatewayEndpoint {
    host: String,
    port: u16,
}

impl GatewayEndpoint {
    /// Creates an endpoint after validating the host and port.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, EndpointError> {
        let host = host.into();
        validate_host(&host)?;
        if host.contains("://") {
            return Err(EndpointError::HostContainsScheme);
        }
        if port == 0 {
            return Err(EndpointError::ZeroPort);
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for GatewayEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') && !self.host.starts_with('[') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

/// Destination requested through a tunnel, preserving whether the caller used a domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum TargetAddress {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl TargetAddress {
    pub const fn ip(ip: IpAddr, port: u16) -> Self {
        Self::Ip(SocketAddr::new(ip, port))
    }

    pub fn domain(host: impl Into<String>, port: u16) -> Result<Self, EndpointError> {
        let host = host.into();
        validate_host(&host)?;
        if port == 0 {
            return Err(EndpointError::ZeroPort);
        }
        Ok(Self::Domain { host, port })
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }
}

fn validate_host(host: &str) -> Result<(), EndpointError> {
    if host.is_empty() {
        return Err(EndpointError::EmptyHost);
    }
    if host.chars().any(char::is_whitespace) {
        return Err(EndpointError::WhitespaceInHost);
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EndpointError {
    #[error("host must not be empty")]
    EmptyHost,
    #[error("host must not include a URL scheme")]
    HostContainsScheme,
    #[error("host must not contain whitespace")]
    WhitespaceInHost,
    #[error("port must not be zero")]
    ZeroPort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_rejects_url_instead_of_silently_normalizing_it() {
        assert_eq!(
            GatewayEndpoint::new("https://vpn.example.edu", 443),
            Err(EndpointError::HostContainsScheme)
        );
    }

    #[test]
    fn gateway_formats_ipv6_with_brackets() {
        let endpoint = GatewayEndpoint::new("2001:db8::1", 441).unwrap();
        assert_eq!(endpoint.to_string(), "[2001:db8::1]:441");
    }

    #[test]
    fn gateway_rejects_whitespace_without_silently_trimming_it() {
        assert_eq!(
            GatewayEndpoint::new(" vpn.example.edu", 443),
            Err(EndpointError::WhitespaceInHost)
        );
    }

    #[test]
    fn target_preserves_domain_name() {
        let target = TargetAddress::domain("service.internal", 443).unwrap();
        assert_eq!(target.port(), 443);
        assert!(matches!(target, TargetAddress::Domain { .. }));
    }
}
