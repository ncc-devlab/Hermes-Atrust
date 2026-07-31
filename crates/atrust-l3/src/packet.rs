//! IPv4 packet inspection for L3 flow classification (Go `processIPV4` parity).
//!
//! Only IPv4 is parsed. IPv6 packets are rejected rather than silently treated
//! as IPv4: the auth five-tuple and the resource matcher are both IPv4-shaped,
//! and a misparsed header would produce a wrong `appId`.
//!
//! Ports are read only for TCP and UDP. ICMP carries no ports, so both are 0 —
//! this matches the resource matcher, which does not compare ports for ICMP.

use std::net::Ipv4Addr;

use atrust_protocol::{L3AuthFiveTuple, L3IpProtocol};
use thiserror::Error;

use crate::conntrack::FlowKey;

/// Address-type value used in the conntrack flow key (Go `connTrackKey`).
///
/// Distinct from the auth JSON's `atype`, which is the EtherType `0x0800`
/// (`L3AuthFiveTuple::ATYPE_IPV4`). Both are correct in their own place.
pub const FLOW_KEY_ATYPE_IPV4: u8 = 4;

/// Minimum bytes needed before the version / IHL nibble is meaningful.
const MIN_IPV4_HEADER: usize = 20;

/// Five-tuple extracted from one IPv4 packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Flow {
    pub protocol: L3IpProtocol,
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
}

impl Ipv4Flow {
    /// Builds the signed-auth five-tuple (`atype = 0x0800`).
    #[must_use]
    pub fn to_five_tuple(&self) -> L3AuthFiveTuple {
        L3AuthFiveTuple::ipv4(
            self.protocol,
            self.src_addr.to_string(),
            self.src_port,
            self.dst_addr.to_string(),
            self.dst_port,
        )
    }

    /// Builds the conntrack key (`atype = 4`).
    ///
    /// The protocol number is deliberately absent: Go's key omits it, and
    /// whether the server requires it is still unconfirmed (architecture doc
    /// open item 5). Two flows differing only in protocol therefore collide;
    /// that is Go-compatible, not an oversight.
    #[must_use]
    pub fn flow_key(&self) -> FlowKey {
        FlowKey::new(
            FLOW_KEY_ATYPE_IPV4,
            &self.src_addr.to_string(),
            self.src_port,
            &self.dst_addr.to_string(),
            self.dst_port,
        )
    }
}

/// Parses the IPv4 header and transport ports of one raw packet.
pub fn parse_ipv4_flow(packet: &[u8]) -> Result<Ipv4Flow, PacketError> {
    if packet.len() < MIN_IPV4_HEADER {
        return Err(PacketError::Truncated {
            needed: MIN_IPV4_HEADER,
            got: packet.len(),
        });
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(PacketError::NotIpv4 { version });
    }
    // IHL counts 32-bit words; the minimum legal value is 5 (20 bytes).
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < MIN_IPV4_HEADER {
        return Err(PacketError::BadHeaderLength { ihl });
    }
    if packet.len() < ihl {
        return Err(PacketError::Truncated {
            needed: ihl,
            got: packet.len(),
        });
    }

    let protocol_number = packet[9];
    let protocol =
        L3IpProtocol::from_u8(protocol_number).ok_or(PacketError::UnsupportedProtocol {
            protocol: protocol_number,
        })?;
    let src_addr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let (src_port, dst_port) = match protocol {
        // Both TCP and UDP put the port pair in the first four payload bytes.
        L3IpProtocol::Tcp | L3IpProtocol::Udp => {
            let payload = &packet[ihl..];
            if payload.len() < 4 {
                return Err(PacketError::Truncated {
                    needed: ihl + 4,
                    got: packet.len(),
                });
            }
            (
                u16::from_be_bytes([payload[0], payload[1]]),
                u16::from_be_bytes([payload[2], payload[3]]),
            )
        }
        L3IpProtocol::Icmp => (0, 0),
    };

    Ok(Ipv4Flow {
        protocol,
        src_addr,
        src_port,
        dst_addr,
        dst_port,
    })
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PacketError {
    #[error("IPv4 packet truncated: need {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },
    #[error("not an IPv4 packet: version {version}")]
    NotIpv4 { version: u8 },
    #[error("illegal IPv4 header length {ihl}")]
    BadHeaderLength { ihl: usize },
    #[error("unsupported IP protocol {protocol}")]
    UnsupportedProtocol { protocol: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an IPv4 packet with `options_words` extra header words.
    fn ipv4_packet(protocol: u8, payload: &[u8], options_words: usize) -> Vec<u8> {
        let ihl_words = 5 + options_words;
        let mut pkt = vec![0u8; ihl_words * 4];
        pkt[0] = 0x40 | (ihl_words as u8);
        pkt[9] = protocol;
        pkt[12..16].copy_from_slice(&[10, 8, 0, 7]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(payload);
        pkt
    }

    fn tcp_payload(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&src_port.to_be_bytes());
        payload.extend_from_slice(&dst_port.to_be_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload
    }

    #[test]
    fn parses_tcp_five_tuple() {
        let pkt = ipv4_packet(6, &tcp_payload(40000, 443), 0);
        let flow = parse_ipv4_flow(&pkt).unwrap();
        assert_eq!(flow.protocol, L3IpProtocol::Tcp);
        assert_eq!(flow.src_addr, Ipv4Addr::new(10, 8, 0, 7));
        assert_eq!(flow.src_port, 40000);
        assert_eq!(flow.dst_addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(flow.dst_port, 443);
    }

    #[test]
    fn parses_udp_five_tuple() {
        let pkt = ipv4_packet(17, &tcp_payload(53000, 53), 0);
        let flow = parse_ipv4_flow(&pkt).unwrap();
        assert_eq!(flow.protocol, L3IpProtocol::Udp);
        assert_eq!(flow.src_port, 53000);
        assert_eq!(flow.dst_port, 53);
    }

    #[test]
    fn honours_ihl_options_when_reading_ports() {
        // Two option words shift the transport header by 8 bytes; reading at a
        // fixed offset of 20 would silently return option bytes as ports.
        let pkt = ipv4_packet(6, &tcp_payload(1234, 8080), 2);
        let flow = parse_ipv4_flow(&pkt).unwrap();
        assert_eq!(flow.src_port, 1234);
        assert_eq!(flow.dst_port, 8080);
    }

    #[test]
    fn icmp_has_no_ports() {
        let pkt = ipv4_packet(1, &[8, 0, 0, 0, 0, 1, 0, 1], 0);
        let flow = parse_ipv4_flow(&pkt).unwrap();
        assert_eq!(flow.protocol, L3IpProtocol::Icmp);
        assert_eq!(flow.src_port, 0);
        assert_eq!(flow.dst_port, 0);
    }

    #[test]
    fn rejects_ipv6_and_unknown_protocol() {
        let mut v6 = ipv4_packet(6, &tcp_payload(1, 2), 0);
        v6[0] = 0x60 | 0x05;
        assert_eq!(
            parse_ipv4_flow(&v6),
            Err(PacketError::NotIpv4 { version: 6 })
        );

        let gre = ipv4_packet(47, &tcp_payload(1, 2), 0);
        assert_eq!(
            parse_ipv4_flow(&gre),
            Err(PacketError::UnsupportedProtocol { protocol: 47 })
        );
    }

    #[test]
    fn rejects_truncated_header_and_transport() {
        assert!(matches!(
            parse_ipv4_flow(&[0x45, 0x00]),
            Err(PacketError::Truncated { .. })
        ));
        // Full 20-byte header, but only 2 bytes of TCP header: no port pair.
        let short = ipv4_packet(6, &[0x00, 0x50], 0);
        assert!(matches!(
            parse_ipv4_flow(&short),
            Err(PacketError::Truncated {
                needed: 24,
                got: 22
            })
        ));
    }

    #[test]
    fn rejects_header_length_below_minimum() {
        let mut pkt = ipv4_packet(6, &tcp_payload(1, 2), 0);
        pkt[0] = 0x44; // IHL = 4 words = 16 bytes
        assert_eq!(
            parse_ipv4_flow(&pkt),
            Err(PacketError::BadHeaderLength { ihl: 16 })
        );
    }

    #[test]
    fn five_tuple_and_flow_key_use_their_own_atype() {
        let pkt = ipv4_packet(6, &tcp_payload(40000, 443), 0);
        let flow = parse_ipv4_flow(&pkt).unwrap();
        let five = flow.to_five_tuple();
        assert_eq!(five.atype, L3AuthFiveTuple::ATYPE_IPV4);
        assert_eq!(five.dest_addr, "10.0.0.1");
        assert_eq!(flow.flow_key().as_str(), "4:10.8.0.7:40000-10.0.0.1:443");
    }
}
