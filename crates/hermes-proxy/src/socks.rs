use atrust_net::{Datagram, ProxyConnector};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::{ProxyConfig, connect, invalid};

async fn address(stream: &mut TcpStream) -> io::Result<(String, u16)> {
    let host = match stream.read_u8().await? {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let n = stream.read_u8().await? as usize;
            if n == 0 {
                return Err(invalid("empty SOCKS domain"));
            }
            let mut host = vec![0; n];
            stream.read_exact(&mut host).await?;
            String::from_utf8(host).map_err(|_| invalid("invalid SOCKS domain"))?
        }
        _ => return Err(invalid("unsupported SOCKS address type")),
    };
    Ok((host, stream.read_u16().await?))
}

async fn handshake(stream: &mut TcpStream, config: &ProxyConfig) -> io::Result<(u8, String, u16)> {
    if stream.read_u8().await? != 5 {
        return Err(invalid("unsupported SOCKS version"));
    }
    let count = stream.read_u8().await? as usize;
    let mut methods = vec![0; count];
    stream.read_exact(&mut methods).await?;
    let method = if config.credentials.is_some() { 2 } else { 0 };
    if !methods.contains(&method) {
        stream.write_all(&[5, 255]).await?;
        return Err(invalid("no supported SOCKS authentication method"));
    }
    stream.write_all(&[5, method]).await?;
    if let Some(credentials) = &config.credentials {
        if stream.read_u8().await? != 1 {
            return Err(invalid("invalid SOCKS authentication version"));
        }
        let length = stream.read_u8().await? as usize;
        let mut user = vec![0; length];
        stream.read_exact(&mut user).await?;
        let length = stream.read_u8().await? as usize;
        let mut password = vec![0; length];
        stream.read_exact(&mut password).await?;
        let valid =
            user == credentials.username.as_bytes() && password == credentials.password.as_bytes();
        stream.write_all(&[1, u8::from(!valid)]).await?;
        if !valid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let mut header = [0; 3];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        return Err(invalid("invalid SOCKS request"));
    }
    let (host, port) = address(stream).await?;
    Ok((header[1], host, port))
}

fn encode_address(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let length = u8::try_from(host.len()).map_err(|_| invalid("SOCKS domain too long"))?;
            if length == 0 {
                return Err(invalid("empty SOCKS domain"));
            }
            bytes.extend_from_slice(&[3, length]);
            bytes.extend_from_slice(host.as_bytes());
        }
    }
    bytes.extend_from_slice(&port.to_be_bytes());
    Ok(bytes)
}

async fn reply(stream: &mut TcpStream, status: u8, bound: SocketAddr) -> io::Result<()> {
    let mut packet = vec![5, status, 0];
    packet.extend_from_slice(&encode_address(&bound.ip().to_string(), bound.port())?);
    stream.write_all(&packet).await
}

pub(super) async fn serve(
    mut stream: TcpStream,
    peer: SocketAddr,
    connector: Arc<dyn ProxyConnector>,
    config: ProxyConfig,
) -> io::Result<()> {
    let (command, host, port) = timeout(config.handshake_timeout, handshake(&mut stream, &config))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let bound = stream.local_addr()?;
    match command {
        1 => match connect(connector.as_ref(), &host, port, config.connect_timeout).await {
            Ok(mut target) => {
                reply(&mut stream, 0, bound).await?;
                tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
            }
            Err(error) => {
                reply(
                    &mut stream,
                    if error.kind() == io::ErrorKind::PermissionDenied {
                        2
                    } else {
                        5
                    },
                    bound,
                )
                .await?;
            }
        },
        3 => associate(stream, peer, host, port, connector, config).await?,
        _ => reply(&mut stream, 7, bound).await?,
    }
    Ok(())
}

struct Peer {
    connection: Arc<dyn Datagram>,
    last_used: Instant,
    receiver: JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.receiver.abort();
    }
}

fn datagram(packet: &[u8]) -> io::Result<(String, u16, usize)> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return Err(invalid("fragmented or invalid SOCKS datagram"));
    }
    let (host, end) = match packet[3] {
        1 => {
            let ip = packet
                .get(4..8)
                .ok_or_else(|| invalid("truncated SOCKS datagram"))?;
            (Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(), 8)
        }
        3 => {
            let n = *packet
                .get(4)
                .ok_or_else(|| invalid("truncated SOCKS domain"))? as usize;
            if n == 0 {
                return Err(invalid("empty SOCKS domain"));
            }
            let host = packet
                .get(5..5 + n)
                .ok_or_else(|| invalid("truncated SOCKS domain"))?;
            (
                std::str::from_utf8(host)
                    .map_err(|_| invalid("invalid SOCKS domain"))?
                    .to_owned(),
                5 + n,
            )
        }
        _ => return Err(invalid("unsupported SOCKS UDP address")),
    };
    let port = packet
        .get(end..end + 2)
        .ok_or_else(|| invalid("missing SOCKS UDP port"))?;
    Ok((host, u16::from_be_bytes([port[0], port[1]]), end + 2))
}

async fn associate(
    mut control: TcpStream,
    peer: SocketAddr,
    requested_host: String,
    requested_port: u16,
    connector: Arc<dyn ProxyConnector>,
    config: ProxyConfig,
) -> io::Result<()> {
    if requested_host
        .parse::<IpAddr>()
        .is_ok_and(|ip| !ip.is_unspecified() && ip != peer.ip())
    {
        let bound = control.local_addr()?;
        reply(&mut control, 2, bound).await?;
        return Ok(());
    }
    let socket = Arc::new(UdpSocket::bind(SocketAddr::new(control.local_addr()?.ip(), 0)).await?);
    reply(&mut control, 0, socket.local_addr()?).await?;
    let mut client = if requested_port == 0 {
        None
    } else {
        Some(SocketAddr::new(peer.ip(), requested_port))
    };
    let mut peers: HashMap<(String, u16), Peer> = HashMap::new();
    let mut buffer = vec![0; 65535];
    let mut byte = [0];
    loop {
        tokio::select! {
            closed = control.read(&mut byte) => { if closed? == 0 { break; } },
            packet = socket.recv_from(&mut buffer) => {
                let (n,source) = packet?;
                if source.ip() != peer.ip() || client.is_some_and(|client| client != source) { continue; }
                let Ok((host,port,start)) = datagram(&buffer[..n]) else { continue };
                client.get_or_insert(source);
                peers.retain(|_,peer| peer.last_used.elapsed() < Duration::from_secs(120) && !peer.receiver.is_finished());
                let key = (host.clone(),port);
                if !peers.contains_key(&key) {
                    if peers.len() >= 64 { continue; }
                    let Ok(Ok(connection)) = timeout(config.connect_timeout,connector.dial_udp(&host,port)).await else { continue };
                    let mut prefix = vec![0,0,0]; prefix.extend_from_slice(&encode_address(&host,port)?);
                    let returning = connection.clone(); let socket = socket.clone();
                    let receiver = tokio::spawn(async move {
                        while let Ok(payload) = returning.recv().await {
                            let mut reply = prefix.clone(); reply.extend_from_slice(&payload);
                            if socket.send_to(&reply,source).await.is_err() { break; }
                        }
                    });
                    peers.insert(key.clone(),Peer { connection, last_used: Instant::now(), receiver });
                }
                let target = peers.get_mut(&key).expect("inserted UDP peer"); target.last_used = Instant::now();
                if target.connection.send(&buffer[start..n]).await.is_err() { peers.remove(&key); }
            }
        }
    }
    Ok(())
}
