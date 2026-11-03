//! Bounded local proxy listeners sharing one address-oriented dialer.
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use atrust_net::ProxyConnector;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};

mod dns;
mod http;
mod socks;
pub use dns::{DnsResponder, DnsServer, PolicyDns};

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials([REDACTED])")
    }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    pub credentials: Option<Credentials>,
}
impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(45),
            credentials: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Socks5,
    Http,
}

#[derive(Debug)]
pub struct ProxyServer {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<io::Result<()>>,
}

impl ProxyServer {
    pub async fn bind(
        address: SocketAddr,
        protocol: Protocol,
        connector: Arc<dyn ProxyConnector>,
        config: ProxyConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let (stop, mut stopping) = watch::channel(false);
        let permits = Arc::new(Semaphore::new(config.max_connections.max(1)));
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    _ = clients.join_next(), if !clients.is_empty() => {},
                    accepted = listener.accept() => {
                        let (stream, peer) = accepted?;
                        let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                        let connector = connector.clone(); let config = config.clone();
                        clients.spawn(async move {
                            let _permit = permit;
                            let _ = match protocol {
                                Protocol::Http => http::serve(stream,connector,config).await,
                                Protocol::Socks5 => socks::serve(stream,peer,connector,config).await,
                            };
                        });
                    }
                }
            }
            clients.shutdown().await;
            Ok(())
        });
        Ok(Self {
            address,
            stop,
            task,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
        (&mut self.task).await.map_err(io::Error::other)?
    }
}
impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.task.abort();
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
async fn connect(
    connector: &dyn ProxyConnector,
    host: &str,
    port: u16,
    budget: Duration,
) -> io::Result<atrust_net::TcpStream> {
    tokio::time::timeout(budget, connector.dial_tcp(host, port))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy connection deadline exceeded",
            )
        })?
}
