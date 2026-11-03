use async_trait::async_trait;
use atrust_net::{Datagram, ProxyConnector, TcpStream as ProxyStream};
use hermes_proxy::{Credentials, DnsResponder, DnsServer, Protocol, ProxyConfig, ProxyServer};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Default)]
struct Echo {
    calls: Mutex<Vec<String>>,
}
#[derive(Debug)]
struct EchoDatagram {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    receiver: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}
#[async_trait]
impl Datagram for EchoDatagram {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        self.sender
            .send(data.to_vec())
            .await
            .map_err(io::Error::other)
    }
    async fn recv(&self) -> io::Result<Vec<u8>> {
        self.receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof.into())
    }
}
#[async_trait]
impl ProxyConnector for Echo {
    async fn dial_tcp(&self, host: &str, port: u16) -> io::Result<ProxyStream> {
        self.calls.lock().unwrap().push(format!("{host}:{port}"));
        let (stream, peer) = tokio::io::duplex(16384);
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(peer);
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });
        Ok(Box::new(stream))
    }
    async fn dial_udp(&self, host: &str, port: u16) -> io::Result<Arc<dyn Datagram>> {
        self.calls.lock().unwrap().push(format!("{host}:{port}"));
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        Ok(Arc::new(EchoDatagram {
            sender,
            receiver: tokio::sync::Mutex::new(receiver),
        }))
    }
}
async fn header(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let mut byte = [0];
    while !data.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        data.push(byte[0]);
    }
    data
}
async fn socks_client(server: &ProxyServer) -> TcpStream {
    let mut client = TcpStream::connect(server.local_addr()).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    client
}
#[tokio::test]
async fn socks_tcp_preserves_half_close_and_shutdown_closes_clients() {
    let connector = Arc::new(Echo::default());
    let server = ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Protocol::Socks5,
        connector.clone(),
        ProxyConfig::default(),
    )
    .await
    .unwrap();
    let mut client = socks_client(&server).await;
    client
        .write_all(&[5, 1, 0, 1, 10, 0, 0, 7, 0, 80])
        .await
        .unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    client.write_all(b"hello").await.unwrap();
    client.shutdown().await.unwrap();
    let mut data = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"hello");
    let mut pending = socks_client(&server).await;
    server.shutdown().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), pending.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(*connector.calls.lock().unwrap(), ["10.0.0.7:80"]);
}
#[tokio::test]
async fn socks_udp_association_reuses_the_destination_and_rejects_fragments() {
    let connector = Arc::new(Echo::default());
    let server = ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Protocol::Socks5,
        connector.clone(),
        ProxyConfig::default(),
    )
    .await
    .unwrap();
    let mut control = socks_client(&server).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let relay = std::net::SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = [0, 0, 0, 1, 10, 0, 0, 7, 0, 53, b'x'];
    let mut buffer = [0; 128];
    for _ in 0..2 {
        udp.send_to(&packet, relay).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(1), udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], &packet);
    }
    assert_eq!(connector.calls.lock().unwrap().len(), 1);
    let mut fragmented = packet;
    fragmented[2] = 1;
    udp.send_to(&fragmented, relay).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), udp.recv(&mut buffer))
            .await
            .is_err()
    );
    server.shutdown().await.unwrap();
}
#[tokio::test]
async fn http_connect_keeps_coalesced_payload_and_accepts_port_80() {
    let connector = Arc::new(Echo::default());
    let server = ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Protocol::Http,
        connector.clone(),
        ProxyConfig::default(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(server.local_addr()).await.unwrap();
    client
        .write_all(b"CONNECT portal.test:80 HTTP/1.1\r\nHost: portal.test\r\n\r\nhello")
        .await
        .unwrap();
    assert!(header(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let mut payload = [0; 5];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"hello");
    assert_eq!(*connector.calls.lock().unwrap(), ["portal.test:80"]);
    server.shutdown().await.unwrap();
}
#[tokio::test]
async fn authentication_rejection_never_dials() {
    let connector = Arc::new(Echo::default());
    let config = ProxyConfig {
        credentials: Some(Credentials {
            username: "user".into(),
            password: "secret".into(),
        }),
        ..ProxyConfig::default()
    };
    let server = ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Protocol::Http,
        connector.clone(),
        config.clone(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(server.local_addr()).await.unwrap();
    client
        .write_all(b"CONNECT portal.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(header(&mut client).await.starts_with(b"HTTP/1.1 407"));
    server.shutdown().await.unwrap();
    let server = ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Protocol::Socks5,
        connector.clone(),
        config,
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(server.local_addr()).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    client.write_all(&[1, 1, b'x', 1, b'y']).await.unwrap();
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [1, 1]);
    assert!(connector.calls.lock().unwrap().is_empty());
    server.shutdown().await.unwrap();
}
#[derive(Debug)]
struct DnsEcho;
#[async_trait]
impl DnsResponder for DnsEcho {
    async fn respond(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        Ok(request.to_vec())
    }
}
#[tokio::test]
async fn dns_binds_udp_and_tcp_to_the_same_port() {
    let server = DnsServer::bind("127.0.0.1:0".parse().unwrap(), Arc::new(DnsEcho))
        .await
        .unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = [0; 12];
    udp.send_to(&query, server.local_addr()).await.unwrap();
    let mut data = [0; 12];
    udp.recv(&mut data).await.unwrap();
    assert_eq!(data, query);
    let mut tcp = TcpStream::connect(server.local_addr()).await.unwrap();
    tcp.write_u16(12).await.unwrap();
    tcp.write_all(&query).await.unwrap();
    assert_eq!(tcp.read_u16().await.unwrap(), 12);
    tcp.read_exact(&mut data).await.unwrap();
    assert_eq!(data, query);
    server.shutdown().await.unwrap();
    assert_eq!(tcp.read(&mut data).await.unwrap(), 0);
}

#[tokio::test]
async fn ordinary_http_rewrites_authority_and_removes_proxy_headers() {
    let connector = Arc::new(Echo::default());
    let server = ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Protocol::Http,
        connector.clone(),
        ProxyConfig::default(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(server.local_addr()).await.unwrap();
    client.write_all(b"GET http://portal.test:8080/path?x=1 HTTP/1.1\r\nHost: wrong.test\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic ignored\r\n\r\n").await.unwrap();
    let forwarded = String::from_utf8(header(&mut client).await).unwrap();
    assert!(
        forwarded.starts_with(
            "GET /path?x=1 HTTP/1.1\r\nHost: portal.test:8080\r\nConnection: close\r\n"
        )
    );
    assert!(!forwarded.to_ascii_lowercase().contains("proxy-"));
    assert_eq!(*connector.calls.lock().unwrap(), ["portal.test:8080"]);
    server.shutdown().await.unwrap();
}
