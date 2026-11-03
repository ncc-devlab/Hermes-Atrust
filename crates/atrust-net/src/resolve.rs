use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use atrust_auth::FlowProtocol;
use atrust_client::AtrustClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout};

use crate::dns_wire::{self, Answer};
use crate::{Destination, NetworkStack};

#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// Empty uses the current resource table's primary and secondary DNS.
    pub servers: Vec<SocketAddrV4>,
    pub udp_timeout: Duration,
    pub lookup_timeout: Duration,
    pub max_ttl: Duration,
    pub capacity: usize,
}
impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            udp_timeout: Duration::from_millis(300),
            lookup_timeout: Duration::from_secs(10),
            max_ttl: Duration::from_secs(3600),
            capacity: 1024,
        }
    }
}

#[async_trait]
pub trait DnsExchange: std::fmt::Debug + Send + Sync {
    async fn query(&self, server: SocketAddrV4, request: &[u8], tcp: bool) -> io::Result<Vec<u8>>;
}

#[derive(Debug)]
struct StackDns {
    client: Arc<AtrustClient>,
    stack: Arc<dyn NetworkStack>,
}
#[async_trait]
impl DnsExchange for StackDns {
    async fn query(&self, server: SocketAddrV4, request: &[u8], tcp: bool) -> io::Result<Vec<u8>> {
        let resource = self
            .client
            .route(
                &server.ip().to_string(),
                server.port(),
                if tcp {
                    FlowProtocol::Tcp
                } else {
                    FlowProtocol::Udp
                },
            )
            .await
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "DNS server is not authorized",
                )
            })?;
        let target = Destination {
            host: server.ip().to_string(),
            address: *server.ip(),
            port: server.port(),
            domain_resource: false,
            resource,
        };
        if !tcp {
            let conn = self.stack.dial_udp(target).await?;
            conn.send(request).await?;
            return conn.recv().await;
        }
        let mut conn = self.stack.dial_tcp(target).await?;
        let length = u16::try_from(request.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        conn.write_all(&length.to_be_bytes()).await?;
        conn.write_all(request).await?;
        conn.flush().await?;
        let length = conn.read_u16().await?;
        let mut response = vec![0; length as usize];
        conn.read_exact(&mut response).await?;
        Ok(response)
    }
}

type CacheKey = (u64, u64, String);
#[derive(Debug)]
struct Cached {
    addresses: Vec<Ipv4Addr>,
    until: Instant,
}

#[derive(Debug)]
pub struct Resolver {
    client: Arc<AtrustClient>,
    exchange: Arc<dyn DnsExchange>,
    config: ResolverConfig,
    cache: Mutex<HashMap<CacheKey, Cached>>,
    flights: Mutex<HashMap<CacheKey, Weak<Mutex<()>>>>,
    ids: AtomicU16,
}

impl Resolver {
    pub fn new(
        client: Arc<AtrustClient>,
        stack: Arc<dyn NetworkStack>,
        config: ResolverConfig,
    ) -> Self {
        Self::with_exchange(client.clone(), Arc::new(StackDns { client, stack }), config)
    }
    pub fn with_exchange(
        client: Arc<AtrustClient>,
        exchange: Arc<dyn DnsExchange>,
        config: ResolverConfig,
    ) -> Self {
        Self {
            client,
            exchange,
            config,
            cache: Mutex::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            ids: AtomicU16::new(1),
        }
    }

    pub async fn lookup(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        Ok(self.lookup_with_ttl(host).await?.0)
    }

    pub async fn lookup_with_ttl(&self, host: &str) -> io::Result<(Vec<Ipv4Addr>, Duration)> {
        self.client.check_session().await.map_err(crate::io_error)?;
        if let Ok(ip) = host.parse() {
            return Ok((vec![ip], Duration::ZERO));
        }
        let host = dns_wire::normalize(host)?;
        let epoch = self.client.session_epoch();
        let snapshot = self.client.resources().await;
        let key = (epoch, snapshot.generation(), host.clone());
        let gate = {
            let mut flights = self.flights.lock().await;
            flights.retain(|_, gate| gate.strong_count() != 0);
            if let Some(gate) = flights.get(&key).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(Mutex::new(()));
                flights.insert(key.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        let _guard = gate.lock().await;
        if let Some(cached) = self.cache.lock().await.get(&key)
            && cached.until > Instant::now()
            && self.client.session_epoch() == epoch
        {
            return Ok((
                cached.addresses.clone(),
                cached.until.saturating_duration_since(Instant::now()),
            ));
        }
        let static_ips = snapshot
            .routing()
            .domain_resources_for_host(&host)
            .into_iter()
            .flat_map(|resource| resource.resolved_ips.iter().copied())
            .collect::<Vec<_>>();
        let (addresses, ttl) = if !static_ips.is_empty() {
            (static_ips, self.config.max_ttl)
        } else {
            let servers = if self.config.servers.is_empty() {
                [
                    &snapshot.resources().dns.primary,
                    &snapshot.resources().dns.secondary,
                ]
                .into_iter()
                .filter_map(|value| value.as_deref())
                .filter_map(|value| {
                    value
                        .parse::<SocketAddrV4>()
                        .ok()
                        .or_else(|| value.parse().ok().map(|ip| SocketAddrV4::new(ip, 53)))
                })
                .collect::<Vec<_>>()
            } else {
                self.config.servers.clone()
            };
            timeout(
                self.config.lookup_timeout,
                self.lookup_remote(&host, &servers),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS lookup deadline exceeded")
            })??
        };
        if self.client.session_epoch() != epoch
            || self.client.resources().await.generation() != key.1
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "DNS policy changed during lookup",
            ));
        }
        let ttl = ttl.min(self.config.max_ttl);
        if !ttl.is_zero() && self.config.capacity != 0 {
            let mut cache = self.cache.lock().await;
            cache.retain(|entry, value| {
                entry.0 == epoch && entry.1 == key.1 && value.until > Instant::now()
            });
            if cache.len() >= self.config.capacity
                && let Some(victim) = cache
                    .iter()
                    .min_by_key(|(_, v)| v.until)
                    .map(|(k, _)| k.clone())
            {
                cache.remove(&victim);
            }
            cache.insert(
                key,
                Cached {
                    addresses: addresses.clone(),
                    until: Instant::now() + ttl,
                },
            );
        }
        Ok((addresses, ttl))
    }

    async fn lookup_remote(
        &self,
        host: &str,
        servers: &[SocketAddrV4],
    ) -> io::Result<(Vec<Ipv4Addr>, Duration)> {
        let mut error = io::Error::new(
            io::ErrorKind::NotConnected,
            "no advertised DNS server; configure a resolver",
        );
        for &server in servers {
            let id = self.ids.fetch_add(1, Ordering::Relaxed);
            let query = dns_wire::query(host, id)?;
            let udp = timeout(
                self.config.udp_timeout,
                self.exchange.query(server, &query, false),
            )
            .await;
            if let Ok(Ok(bytes)) = udp
                && let Ok(Answer::Addresses(ips, ttl)) = dns_wire::parse(&bytes, host, id)
            {
                return Ok((ips, ttl));
            }
            match self
                .exchange
                .query(server, &query, true)
                .await
                .and_then(|bytes| dns_wire::parse(&bytes, host, id))
            {
                Ok(Answer::Addresses(ips, ttl)) => return Ok((ips, ttl)),
                Ok(Answer::Truncated) => {
                    error = io::Error::new(io::ErrorKind::InvalidData, "DNS over TCP was truncated")
                }
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }

    pub async fn resolve(
        &self,
        host: &str,
        port: u16,
        protocol: FlowProtocol,
    ) -> io::Result<Destination> {
        let domain = if host.parse::<Ipv4Addr>().is_err() {
            self.client.route(host, port, protocol).await
        } else {
            None
        };
        for address in self.lookup(host).await? {
            if let Some(resource) = domain.clone() {
                return Ok(Destination {
                    host: dns_wire::normalize(host)?,
                    address,
                    port,
                    domain_resource: true,
                    resource,
                });
            }
            if let Some(resource) = self
                .client
                .route(&address.to_string(), port, protocol)
                .await
            {
                return Ok(Destination {
                    host: host.to_owned(),
                    address,
                    port,
                    domain_resource: false,
                    resource,
                });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination is outside authorized resources",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    #[derive(Debug, Default)]
    struct Exchange(std::sync::atomic::AtomicUsize);
    #[async_trait]
    impl DnsExchange for Exchange {
        async fn query(
            &self,
            _server: SocketAddrV4,
            request: &[u8],
            tcp: bool,
        ) -> io::Result<Vec<u8>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok(dns_wire::test_answer(request, !tcp))
        }
    }
    #[tokio::test(start_paused = true)]
    async fn coalesces_queries_falls_back_to_tcp_and_invalidates_on_ttl_policy_and_session() {
        let client = test_support::client(false).await;
        let exchange = Arc::new(Exchange::default());
        let resolver = Arc::new(Resolver::with_exchange(
            client.clone(),
            exchange.clone(),
            ResolverConfig {
                servers: vec!["10.0.0.53:53".parse().unwrap()],
                ..ResolverConfig::default()
            },
        ));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let resolver = resolver.clone();
            tasks.push(tokio::spawn(async move {
                resolver.lookup("Portal.Test.").await.unwrap()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), [Ipv4Addr::new(10, 0, 0, 7)]);
        }
        assert_eq!(exchange.0.load(Ordering::Relaxed), 2);
        tokio::time::advance(Duration::from_secs(3)).await;
        resolver.lookup("portal.test").await.unwrap();
        assert_eq!(exchange.0.load(Ordering::Relaxed), 4);
        client.refresh_resources().await.unwrap();
        resolver.lookup("portal.test").await.unwrap();
        assert_eq!(exchange.0.load(Ordering::Relaxed), 6);
        client
            .replace_session(
                test_support::auth(false),
                test_support::config(),
                test_support::material(),
            )
            .await
            .unwrap();
        resolver.lookup("portal.test").await.unwrap();
        assert_eq!(exchange.0.load(Ordering::Relaxed), 8);
        client.shutdown().await;
    }
}
