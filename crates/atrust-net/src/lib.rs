//! Connection adapters between aTrust and proxy/TUN applications. Authentication
//! and operating-system route changes remain the host application's concern.
use std::fmt::Debug;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use atrust_auth::MatchedResource;
use atrust_client::AtrustClient;
use tokio::io::{AsyncRead, AsyncWrite};

mod dial;
mod dns_wire;
mod fake_ip;
mod resolve;
#[cfg(test)]
mod test_support;
mod udp;
pub use dial::{ProxyConnector, ProxyDialer};
pub use fake_ip::FakeIpPool;
pub use resolve::{DnsExchange, Resolver, ResolverConfig};
pub use udp::AtrustUdp;

pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send + Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> ByteStream for T {}
pub type TcpStream = Box<dyn ByteStream>;

#[async_trait]
pub trait Datagram: Debug + Send + Sync {
    async fn send(&self, payload: &[u8]) -> io::Result<()>;
    async fn recv(&self) -> io::Result<Vec<u8>>;
}

/// A destination retains both the original hostname and the selected real IP.
#[derive(Clone, Debug)]
pub struct Destination {
    pub host: String,
    pub address: Ipv4Addr,
    pub port: u16,
    pub domain_resource: bool,
    pub resource: MatchedResource,
}

#[async_trait]
pub trait NetworkStack: Debug + Send + Sync {
    async fn dial_tcp(&self, target: Destination) -> io::Result<TcpStream>;
    async fn dial_udp(&self, target: Destination) -> io::Result<Arc<dyn Datagram>>;
}

/// Native aTrust TCP plus connected UDP over the shared L3 session. A host with
/// a userspace TCP/IP stack can supply it for resources requiring TCP over L3.
#[derive(Debug)]
pub struct AtrustStack {
    client: Arc<AtrustClient>,
    l3_tcp: Option<Arc<dyn NetworkStack>>,
}

impl AtrustStack {
    pub fn new(client: Arc<AtrustClient>) -> Self {
        Self {
            client,
            l3_tcp: None,
        }
    }
    pub fn with_l3_tcp(mut self, stack: Arc<dyn NetworkStack>) -> Self {
        self.l3_tcp = Some(stack);
        self
    }
}

#[async_trait]
impl NetworkStack for AtrustStack {
    async fn dial_tcp(&self, target: Destination) -> io::Result<TcpStream> {
        self.client.check_session().await.map_err(io_error)?;
        // Recheck policy at the point of use. A resolved destination is a hint,
        // never an authority to override the latest server resource table.
        let host = if target.domain_resource {
            target.host.clone()
        } else {
            target.address.to_string()
        };
        let route = self
            .client
            .route(&host, target.port, atrust_auth::FlowProtocol::Tcp)
            .await
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCP destination is no longer authorized",
                )
            })?;
        if route.tcp_prefers_l3 {
            let stack = self.l3_tcp.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "resource requires a host-provided L3 TCP/IP stack",
                )
            })?;
            return stack
                .dial_tcp(Destination {
                    resource: route,
                    ..target
                })
                .await;
        }
        Ok(Box::new(
            self.client
                .dial_tcp(&host, target.port)
                .await
                .map_err(io_error)?
                .tunnel,
        ))
    }

    async fn dial_udp(&self, target: Destination) -> io::Result<Arc<dyn Datagram>> {
        self.client.check_session().await.map_err(io_error)?;
        Ok(Arc::new(
            AtrustUdp::connect(Arc::clone(&self.client), target).await?,
        ))
    }
}

pub(crate) fn io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    let kind = match (&error as &dyn std::error::Error).downcast_ref::<atrust_client::ClientError>()
    {
        Some(
            atrust_client::ClientError::Unauthorized { .. }
            | atrust_client::ClientError::AuthenticationRequired,
        ) => io::ErrorKind::PermissionDenied,
        Some(atrust_client::ClientError::Closed) => io::ErrorKind::ConnectionReset,
        Some(atrust_client::ClientError::L3StackRequired) => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Default)]
    struct RecordingStack(std::sync::atomic::AtomicUsize);
    #[async_trait]
    impl NetworkStack for RecordingStack {
        async fn dial_tcp(&self, target: Destination) -> io::Result<TcpStream> {
            assert!(target.resource.tcp_prefers_l3);
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Box::new(tokio::io::duplex(64).0))
        }
        async fn dial_udp(&self, _target: Destination) -> io::Result<Arc<dyn Datagram>> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    #[tokio::test]
    async fn current_policy_selects_the_supplied_l3_stack() {
        let client = test_support::client(true).await;
        let target = Destination {
            host: "portal.test".into(),
            address: "10.0.0.7".parse().unwrap(),
            port: 443,
            domain_resource: true,
            resource: client
                .route("portal.test", 443, atrust_auth::FlowProtocol::Tcp)
                .await
                .unwrap(),
        };
        assert_eq!(
            AtrustStack::new(client.clone())
                .dial_tcp(target.clone())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let l3 = Arc::new(RecordingStack::default());
        AtrustStack::new(client.clone())
            .with_l3_tcp(l3.clone())
            .dial_tcp(target)
            .await
            .unwrap();
        assert_eq!(l3.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        client.shutdown().await;
    }
}
