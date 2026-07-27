use std::net::Ipv4Addr;

use thiserror::Error;

/// Prefix for TCP tunnel init before nested length + signed JSON.
///
/// Wire: `05 01 81 53 03 <u16-be len> <json>`
pub const TCP_INIT_PREFIX: &[u8] = &[0x05, 0x01, 0x81, 0x53, 0x03];

/// Builds the TCP tunnel init frame around already-signed JSON bytes.
pub fn encode_tcp_init_frame(signed_json: &[u8]) -> Result<Vec<u8>, TcpFrameError> {
    let len = u16::try_from(signed_json.len()).map_err(|_| TcpFrameError::PayloadTooLarge {
        length: signed_json.len(),
        max: u16::MAX as usize,
    })?;
    let mut out = Vec::with_capacity(TCP_INIT_PREFIX.len() + 2 + signed_json.len());
    out.extend_from_slice(TCP_INIT_PREFIX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(signed_json);
    Ok(out)
}

/// IPv4 target address frame after init: `05 01 01 01 <4 bytes IP> <u16-be port>`.
pub fn encode_tcp_target_ipv4(ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 + 2);
    out.extend_from_slice(&[0x05, 0x01, 0x01, 0x01]);
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Domain target address frame: `05 01 01 03 <u8 domain len> <domain> <u16-be port>`.
pub fn encode_tcp_target_domain(host: &str, port: u16) -> Result<Vec<u8>, TcpFrameError> {
    if host.is_empty() {
        return Err(TcpFrameError::EmptyDomain);
    }
    let host_bytes = host.as_bytes();
    let len = u8::try_from(host_bytes.len()).map_err(|_| TcpFrameError::DomainTooLong {
        length: host_bytes.len(),
    })?;
    let mut out = Vec::with_capacity(4 + 1 + host_bytes.len() + 2);
    out.extend_from_slice(&[0x05, 0x01, 0x01, 0x03]);
    out.push(len);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Application data write frame: `01 00 <u16-be len> <payload>`.
pub fn encode_tcp_app_data(payload: &[u8]) -> Result<Vec<u8>, TcpFrameError> {
    let len = u16::try_from(payload.len()).map_err(|_| TcpFrameError::PayloadTooLarge {
        length: payload.len(),
        max: u16::MAX as usize,
    })?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Application close frame: `01 01 00 00`.
pub fn encode_tcp_close() -> [u8; 4] {
    [0x01, 0x01, 0x00, 0x00]
}

/// Connection probe after address OK: `01 00 00 00`.
pub fn encode_tcp_probe() -> [u8; 4] {
    [0x01, 0x00, 0x00, 0x00]
}

/// Parses a nested `53 00 <u16-be len> <payload>` success marker commonly used after init.
pub fn parse_status_payload(input: &[u8]) -> Result<&[u8], TcpFrameError> {
    if input.len() < 4 {
        return Err(TcpFrameError::Truncated {
            needed: 4,
            got: input.len(),
        });
    }
    if input[0] != 0x53 || input[1] != 0x00 {
        return Err(TcpFrameError::UnexpectedStatusHeader {
            got: [input[0], input[1]],
        });
    }
    let len = u16::from_be_bytes([input[2], input[3]]) as usize;
    let end = 4usize.saturating_add(len);
    if input.len() < end {
        return Err(TcpFrameError::Truncated {
            needed: end,
            got: input.len(),
        });
    }
    Ok(&input[4..end])
}

/// True when payload is the ASCII `OK` success body (any surrounding whitespace rejected).
pub fn is_status_ok(payload: &[u8]) -> bool {
    payload == b"OK"
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TcpFrameError {
    #[error("payload length {length} exceeds max {max}")]
    PayloadTooLarge { length: usize, max: usize },
    #[error("domain name is empty")]
    EmptyDomain,
    #[error("domain name length {length} exceeds 255 bytes")]
    DomainTooLong { length: usize },
    #[error("frame truncated: need {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },
    #[error("unexpected status header {got:02x?}, expected 53 00")]
    UnexpectedStatusHeader { got: [u8; 2] },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_frame_matches_documented_prefix_and_length() {
        let json = br#"{"sid":"x"}"#;
        let frame = encode_tcp_init_frame(json).unwrap();
        assert_eq!(&frame[..5], TCP_INIT_PREFIX);
        assert_eq!(&frame[5..7], &(json.len() as u16).to_be_bytes());
        assert_eq!(&frame[7..], json);
    }

    #[test]
    fn ipv4_target_frame_is_fixed_layout() {
        let frame = encode_tcp_target_ipv4(Ipv4Addr::new(10, 0, 0, 1), 443);
        assert_eq!(frame, vec![0x05, 0x01, 0x01, 0x01, 10, 0, 0, 1, 0x01, 0xbb]);
    }

    #[test]
    fn domain_target_frame_includes_length_byte() {
        let frame = encode_tcp_target_domain("svc.internal", 80).unwrap();
        assert_eq!(&frame[..4], &[0x05, 0x01, 0x01, 0x03]);
        assert_eq!(frame[4], 12);
        assert_eq!(&frame[5..17], b"svc.internal");
        assert_eq!(&frame[17..], &80u16.to_be_bytes());
    }

    #[test]
    fn app_data_and_close_and_probe() {
        let data = encode_tcp_app_data(b"hi").unwrap();
        assert_eq!(data, vec![0x01, 0x00, 0x00, 0x02, b'h', b'i']);
        assert_eq!(encode_tcp_close(), [0x01, 0x01, 0x00, 0x00]);
        assert_eq!(encode_tcp_probe(), [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn status_ok_parser() {
        let mut buf = vec![0x53, 0x00, 0x00, 0x02];
        buf.extend_from_slice(b"OK");
        assert!(is_status_ok(parse_status_payload(&buf).unwrap()));
        assert_eq!(
            parse_status_payload(&[0x05, 0x00, 0x00, 0x00]),
            Err(TcpFrameError::UnexpectedStatusHeader { got: [0x05, 0x00] })
        );
        assert!(matches!(
            parse_status_payload(&[0x53, 0x00]),
            Err(TcpFrameError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_oversized_init_payload() {
        let huge = vec![0u8; usize::from(u16::MAX) + 1];
        assert!(matches!(
            encode_tcp_init_frame(&huge),
            Err(TcpFrameError::PayloadTooLarge { .. })
        ));
    }
}
