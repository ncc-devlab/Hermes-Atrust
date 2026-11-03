use async_trait::async_trait;
use atrust_net::ProxyDialer;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

#[async_trait]
pub trait DnsResponder: std::fmt::Debug + Send + Sync {
    async fn respond(&self, request: &[u8]) -> io::Result<Vec<u8>>;
}
#[derive(Debug)]
pub struct PolicyDns {
    pub dialer: Arc<ProxyDialer>,
    pub max_ttl: Duration,
}
#[async_trait]
impl DnsResponder for PolicyDns {
    async fn respond(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        self.dialer.answer_dns(request, self.max_ttl).await
    }
}

#[derive(Debug)]
pub struct DnsServer {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<io::Result<()>>,
}
impl DnsServer {
    /// Binds UDP and TCP to the same address. Both listeners and all in-flight
    /// requests are owned by this handle and cancelled on shutdown or drop.
    pub async fn bind(address: SocketAddr, responder: Arc<dyn DnsResponder>) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(address).await?);
        let address = socket.local_addr()?;
        let tcp = TcpListener::bind(address).await?;
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut requests = JoinSet::new();
            let mut buffer = vec![0; 4096];
            loop {
                tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    _ = requests.join_next(), if !requests.is_empty() => {},
                    packet = socket.recv_from(&mut buffer), if requests.len() < 128 => {
                        let (n,peer) = packet?; let query = buffer[..n].to_vec();
                        let socket = socket.clone(); let responder = responder.clone();
                        requests.spawn(async move {
                            if let Ok(Ok(reply)) = tokio::time::timeout(Duration::from_secs(15),responder.respond(&query)).await
                                && reply.len() <= 4096 { let _ = socket.send_to(&reply,peer).await; }
                        });
                    }
                    accepted = tcp.accept(), if requests.len() < 128 => {
                        let (mut stream,_) = accepted?; let responder = responder.clone();
                        requests.spawn(async move {
                            let work = async {
                                loop {
                                    let length = stream.read_u16().await? as usize;
                                    if !(12..=4096).contains(&length) { return Err(io::Error::from(io::ErrorKind::InvalidData)); }
                                    let mut query = vec![0;length]; stream.read_exact(&mut query).await?;
                                    let reply = responder.respond(&query).await?;
                                    if reply.len() > 4096 { return Err(io::Error::from(io::ErrorKind::InvalidData)); }
                                    stream.write_all(&(reply.len() as u16).to_be_bytes()).await?;
                                    stream.write_all(&reply).await?;
                                }
                            };
                            let _: Result<io::Result<()>,_> = tokio::time::timeout(Duration::from_secs(30),work).await;
                        });
                    }
                }
            }
            requests.shutdown().await;
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
impl Drop for DnsServer {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.task.abort();
    }
}
