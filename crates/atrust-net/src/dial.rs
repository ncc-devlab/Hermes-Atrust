use async_trait::async_trait;
use atrust_auth::FlowProtocol;
use atrust_client::AtrustClient;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::{
    Datagram, Destination, FakeIpPool, NetworkStack, Resolver, ResolverConfig, TcpStream, dns_wire,
};

/// Address-oriented contract shared by SOCKS, HTTP and port-forwarding services.
#[async_trait]
pub trait ProxyConnector: std::fmt::Debug + Send + Sync {
    async fn dial_tcp(&self, host: &str, port: u16) -> io::Result<TcpStream>;
    async fn dial_udp(&self, host: &str, port: u16) -> io::Result<Arc<dyn Datagram>>;
}

#[derive(Debug)]
pub struct ProxyDialer {
    client: Arc<AtrustClient>,
    stack: Arc<dyn NetworkStack>,
    resolver: Arc<Resolver>,
    pool: Mutex<FakeIpPool>,
}
impl ProxyDialer {
    pub fn new(
        client: Arc<AtrustClient>,
        stack: Arc<dyn NetworkStack>,
        config: ResolverConfig,
    ) -> Self {
        let resolver = Arc::new(Resolver::new(client.clone(), stack.clone(), config));
        Self::with_resolver(client, stack, resolver)
    }
    pub fn with_resolver(
        client: Arc<AtrustClient>,
        stack: Arc<dyn NetworkStack>,
        resolver: Arc<Resolver>,
    ) -> Self {
        Self {
            client,
            stack,
            resolver,
            pool: Mutex::new(FakeIpPool::new(8192)),
        }
    }

    async fn original_host(
        &self,
        host: &str,
        port: u16,
        protocol: FlowProtocol,
    ) -> io::Result<String> {
        let Ok(ip) = host.parse::<Ipv4Addr>() else {
            return dns_wire::normalize(host);
        };
        let epoch = self.client.session_epoch();
        let snapshot = self.client.resources().await;
        let mut pool = self.pool.lock().await;
        if FakeIpPool::is_fake(ip) {
            return pool
                .lookup(ip, epoch, snapshot.generation())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::PermissionDenied, "unknown or stale Fake IP")
                });
        }
        let names = pool.real_hosts(ip, epoch, snapshot.generation());
        drop(pool);
        let mut covered = Vec::new();
        for name in names {
            if self.client.route(&name, port, protocol).await.is_some() {
                covered.push(name);
            }
        }
        if covered.len() == 1 {
            return Ok(covered.remove(0));
        }
        if covered.len() > 1 && self.client.route(host, port, protocol).await.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "shared address has ambiguous domain policy; use a hostname or Fake IP",
            ));
        }
        Ok(host.to_owned())
    }

    /// DNS adapter entry point. AddrPretend=false returns a real IP and retains
    /// its hostname association; permitted fake addresses avoid shared-IP loss.
    pub async fn dns_ipv4(&self, host: &str, ttl: Duration) -> io::Result<Ipv4Addr> {
        Ok(self.dns_record(host, ttl).await?.0)
    }

    pub async fn dns_record(
        &self,
        host: &str,
        max_ttl: Duration,
    ) -> io::Result<(Ipv4Addr, Duration)> {
        let host = dns_wire::normalize(host)?;
        let epoch = self.client.session_epoch();
        let snapshot = self.client.resources().await;
        let policies = snapshot.routing().domain_resources_for_host(&host);
        if policies
            .first()
            .is_some_and(|resource| resource.addr_pretend)
        {
            let ip = self
                .pool
                .lock()
                .await
                .assign(&host, epoch, snapshot.generation(), max_ttl)?;
            return Ok((ip, max_ttl));
        }
        let (ips, ttl) = self.resolver.lookup_with_ttl(&host).await?;
        let ttl = ttl.min(max_ttl);
        let ip = *ips.first().ok_or(io::ErrorKind::AddrNotAvailable)?;
        if !policies.is_empty() {
            if self.client.session_epoch() != epoch
                || self.client.resources().await.generation() != snapshot.generation()
            {
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.pool
                .lock()
                .await
                .remember_real(ip, &host, epoch, snapshot.generation(), ttl)?;
        }
        Ok((ip, ttl))
    }
}

#[async_trait]
impl ProxyConnector for ProxyDialer {
    async fn dial_tcp(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let host = self.original_host(host, port, FlowProtocol::Tcp).await?;
        // The aTrust native TCP handshake carries the hostname directly; it
        // needs no preliminary DNS lookup, which might itself require L3.
        if host.parse::<Ipv4Addr>().is_err()
            && let Some(resource) = self.client.route(&host, port, FlowProtocol::Tcp).await
            && !resource.tcp_prefers_l3
        {
            return self
                .stack
                .dial_tcp(Destination {
                    host,
                    address: Ipv4Addr::UNSPECIFIED,
                    port,
                    domain_resource: true,
                    resource,
                })
                .await;
        }
        self.stack
            .dial_tcp(
                self.resolver
                    .resolve(&host, port, FlowProtocol::Tcp)
                    .await?,
            )
            .await
    }
    async fn dial_udp(&self, host: &str, port: u16) -> io::Result<Arc<dyn Datagram>> {
        let host = self.original_host(host, port, FlowProtocol::Udp).await?;
        self.stack
            .dial_udp(
                self.resolver
                    .resolve(&host, port, FlowProtocol::Udp)
                    .await?,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Default)]
    struct Stack(std::sync::Mutex<Vec<String>>);
    #[async_trait]
    impl NetworkStack for Stack {
        async fn dial_tcp(&self, target: Destination) -> io::Result<TcpStream> {
            self.0.lock().unwrap().push(target.host);
            Ok(Box::new(tokio::io::duplex(64).0))
        }
        async fn dial_udp(&self, _target: Destination) -> io::Result<Arc<dyn Datagram>> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    #[tokio::test]
    async fn fake_ip_restores_domain_without_dns_and_expires_with_policy() {
        let client = crate::test_support::client(false).await;
        let stack = Arc::new(Stack::default());
        let dialer = ProxyDialer::new(client.clone(), stack.clone(), ResolverConfig::default());
        let fake = dialer
            .dns_ipv4("portal.test", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(FakeIpPool::is_fake(fake));
        dialer.dial_tcp(&fake.to_string(), 443).await.unwrap();
        assert_eq!(*stack.0.lock().unwrap(), ["portal.test"]);
        client.refresh_resources().await.unwrap();
        assert_eq!(
            dialer
                .dial_tcp(&fake.to_string(), 443)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_ne!(
            dialer
                .dns_ipv4("portal.test", Duration::from_secs(60))
                .await
                .unwrap(),
            fake
        );
        client.shutdown().await;
    }
}
