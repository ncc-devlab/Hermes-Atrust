use std::collections::HashSet;
use std::io;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use async_trait::async_trait;
use atrust_auth::FlowProtocol;
use atrust_client::AtrustClient;
use atrust_l3::{FlowPackets, L3Session, parse_ipv4_flow};
use tokio::sync::Mutex;

use crate::{Datagram, Destination, io_error};

fn ports() -> &'static StdMutex<HashSet<u16>> {
    static PORTS: OnceLock<StdMutex<HashSet<u16>>> = OnceLock::new();
    PORTS.get_or_init(StdMutex::default)
}

#[derive(Debug)]
struct Port(u16);
impl Port {
    fn allocate() -> io::Result<Self> {
        let mut used = ports().lock().expect("UDP port pool mutex");
        for port in 49152..=65535 {
            if used.insert(port) {
                return Ok(Self(port));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "UDP port pool is exhausted",
        ))
    }
}
impl Drop for Port {
    fn drop(&mut self) {
        ports().lock().expect("UDP port pool mutex").remove(&self.0);
    }
}

#[derive(Debug)]
pub struct AtrustUdp {
    client: Arc<AtrustClient>,
    target: Destination,
    session: Arc<L3Session>,
    receiver: Mutex<FlowPackets>,
    source: SocketAddrV4,
    _port: Port,
}

impl AtrustUdp {
    pub async fn connect(client: Arc<AtrustClient>, target: Destination) -> io::Result<Self> {
        let host = if target.domain_resource {
            target.host.clone()
        } else {
            target.address.to_string()
        };
        let resource = client
            .route(&host, target.port, FlowProtocol::Udp)
            .await
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "UDP destination is not authorized",
                )
            })?;
        let session = client
            .connect_node_group(&resource.node_group_id)
            .await
            .map_err(io_error)?;
        let port = Port::allocate()?;
        let source = SocketAddrV4::new(session.vip(), port.0);
        let packet = encode(source, SocketAddrV4::new(target.address, target.port), &[])?;
        let receiver = session
            .subscribe_flow(&parse_ipv4_flow(&packet).map_err(io_error)?)
            .map_err(io_error)?;
        Ok(Self {
            client,
            target,
            session,
            receiver: Mutex::new(receiver),
            source,
            _port: port,
        })
    }
}

#[async_trait]
impl Datagram for AtrustUdp {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        // Avoid producing fragments until the core has a fragment reassembler.
        if payload.len() > 1372 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds the 1400-byte tunnel MTU",
            ));
        }
        if self.session.is_closed() || self.session.vip() != *self.source.ip() {
            return Err(reset());
        }
        let packet = encode(
            self.source,
            SocketAddrV4::new(self.target.address, self.target.port),
            payload,
        )?;
        let sent = if self.target.domain_resource {
            self.client
                .send_ipv4_for_domain(&packet, &self.target.host)
                .await
        } else {
            self.client.send_ipv4(&packet).await
        }
        .map_err(io_error)?;
        if !Arc::ptr_eq(&sent.session, &self.session) {
            return Err(reset());
        }
        Ok(())
    }

    async fn recv(&self) -> io::Result<Vec<u8>> {
        let mut receiver = self.receiver.lock().await;
        if self.session.is_closed() || self.session.vip() != *self.source.ip() {
            return Err(reset());
        }
        let packet = receiver.recv().await.ok_or_else(reset)?;
        decode(
            &packet,
            SocketAddrV4::new(self.target.address, self.target.port),
            self.source,
        )
    }
}

fn reset() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "UDP session changed; redial the datagram connection",
    )
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(source: SocketAddrV4, dest: SocketAddrV4, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&source.ip().octets());
    pseudo.extend_from_slice(&dest.ip().octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    checksum(&pseudo)
}

fn encode(source: SocketAddrV4, dest: SocketAddrV4, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > 65507 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut packet = vec![0; 28 + payload.len()];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&dest.ip().octets());
    let ip_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source.port().to_be_bytes());
    packet[22..24].copy_from_slice(&dest.port().to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let sum = udp_checksum(source, dest, &packet[20..]);
    packet[26..28].copy_from_slice(&(if sum == 0 { 65535 } else { sum }).to_be_bytes());
    Ok(packet)
}

fn decode(packet: &[u8], source: SocketAddrV4, dest: SocketAddrV4) -> io::Result<Vec<u8>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid UDP reply");
    let flow = parse_ipv4_flow(packet).map_err(io_error)?;
    let ihl = ((packet[0] & 15) as usize) * 4;
    if packet.len() < ihl + 8
        || packet[9] != 17
        || flow.src_addr != *source.ip()
        || flow.dst_addr != *dest.ip()
        || flow.src_port != source.port()
        || flow.dst_port != dest.port()
        || u16::from_be_bytes([packet[2], packet[3]]) as usize != packet.len()
        || checksum(&packet[..ihl]) != 0
    {
        return Err(bad());
    }
    let udp = &packet[ihl..];
    if u16::from_be_bytes([udp[4], udp[5]]) as usize != udp.len()
        || (udp[6..8] != [0, 0] && udp_checksum(source, dest, udp) != 0)
    {
        return Err(bad());
    }
    Ok(udp[8..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_roundtrip_checks_lengths_addresses_and_checksums() {
        let src = "10.0.0.1:10000".parse().unwrap();
        let dst = "10.0.0.2:53".parse().unwrap();
        for size in [0, 1, 1372] {
            let data = vec![123; size];
            let mut packet = encode(src, dst, &data).unwrap();
            assert_eq!(decode(&packet, src, dst).unwrap(), data);
            packet[24] ^= 1;
            assert!(decode(&packet, src, dst).is_err());
        }
        assert!(decode(&encode(src, dst, b"a").unwrap(), dst, src).is_err());
    }
    #[test]
    fn live_port_leases_never_overlap() {
        let a = Port::allocate().unwrap();
        let b = Port::allocate().unwrap();
        assert_ne!(a.0, b.0);
    }
}
