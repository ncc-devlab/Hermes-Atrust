//! L3 tunnel binary frames.
//!
//! # `0x94` body framing
//!
//! After the command header `05 94`, the body uses a fixed two-branch layout
//! shared with zju-connect `readDataRespPayload`:
//!
//! - Let `n = u16::from_be_bytes(body[0..2])`.
//! - If `0 < n <= MAX_LENGTH_PREFIXED_DATA_RESP` (4096): **length-prefixed** —
//!   the following `n` bytes are one raw IP packet.
//! - Otherwise: **token-framed** — same layout as the `0x14` request body
//!   (`tokenLen`, token, reserved, packetCount, length-prefixed packets).
//!
//! This threshold is the wire discriminant, not a content scan of IP packets.
//!
//! # Auth / heartbeat
//!
//! - Per-flow auth request: `05 13 <u16-be jsonLen> <json>`
//! - Heartbeat request: `05 15 00 00` (`L3_HEARTBEAT_REQ`)
//! - Heartbeat response header: `05 95` (payload length follows on the wire)

use thiserror::Error;

/// L3 frame version byte.
pub const L3_VERSION: u8 = 0x05;

/// L3 command codes used on the data plane.
pub mod l3_cmd {
    pub const AUTH_REQ: u8 = 0x13;
    pub const AUTH_RESP: u8 = 0x93;
    pub const DATA_REQ: u8 = 0x14;
    pub const DATA_RESP: u8 = 0x94;
    pub const HEARTBEAT_REQ: u8 = 0x15;
    pub const HEARTBEAT_RESP: u8 = 0x95;
}

/// Maximum payload size for the length-prefixed `0x94` branch.
///
/// Values in `(0, MAX]` select that branch; everything else is token-framed.
pub const MAX_LENGTH_PREFIXED_DATA_RESP: u16 = 4096;

/// Fixed heartbeat request: `05 15 00 00`.
pub const L3_HEARTBEAT_REQ: [u8; 4] = [
    L3_VERSION,
    l3_cmd::HEARTBEAT_REQ,
    0x00,
    0x00,
];

/// Heartbeat response command header (`05 95`); length-prefixed body follows.
pub const L3_HEARTBEAT_RESP_HEADER: [u8; 2] = [L3_VERSION, l3_cmd::HEARTBEAT_RESP];

/// Which body layout follows `05 94`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataRespLayout {
    /// `u16-be(n)` then `n` bytes of one IP packet, with `0 < n <= 4096`.
    LengthPrefixed { packet_len: u16 },
    /// Body starts with `tokenLen` (same structure as `0x14` payload after version/cmd).
    TokenFramed,
}

/// Decoded IP packets from one `0x94` body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataRespPackets<'a> {
    /// Single packet from the length-prefixed branch.
    LengthPrefixed(&'a [u8]),
    /// Zero or more packets from the token-framed branch.
    TokenFramed(Vec<&'a [u8]>),
}

/// Classifies the body that follows `05 94` from its first two bytes.
pub fn classify_data_resp_prefix(prefix: [u8; 2]) -> DataRespLayout {
    let n = u16::from_be_bytes(prefix);
    if n > 0 && n <= MAX_LENGTH_PREFIXED_DATA_RESP {
        DataRespLayout::LengthPrefixed { packet_len: n }
    } else {
        DataRespLayout::TokenFramed
    }
}

/// Encodes one per-flow auth request frame (`0x13`).
///
/// Wire: `05 13 <u16-be jsonLen> <json>`
pub fn encode_l3_auth_req(json: &[u8]) -> Result<Vec<u8>, L3FrameError> {
    if json.len() > u16::MAX as usize {
        return Err(L3FrameError::JsonTooLarge {
            length: json.len(),
        });
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.push(L3_VERSION);
    out.push(l3_cmd::AUTH_REQ);
    out.extend_from_slice(&(json.len() as u16).to_be_bytes());
    out.extend_from_slice(json);
    Ok(out)
}

/// Returns the fixed heartbeat request bytes (`05 15 00 00`).
#[must_use]
pub fn encode_l3_heartbeat_req() -> [u8; 4] {
    L3_HEARTBEAT_REQ
}

/// True when `header` is a heartbeat response command (`05 95`).
#[must_use]
pub fn is_l3_heartbeat_resp(header: [u8; 2]) -> bool {
    header == L3_HEARTBEAT_RESP_HEADER
}

/// Encodes one `0x14` data request frame.
///
/// Wire: `05 14 <tokenLen> <token> 00 00 <count> [u16-be len][pkt]...`
pub fn encode_l3_data_req(token: &[u8], packets: &[&[u8]]) -> Result<Vec<u8>, L3FrameError> {
    if token.len() > u8::MAX as usize {
        return Err(L3FrameError::TokenTooLong {
            length: token.len(),
        });
    }
    if packets.len() > u8::MAX as usize {
        return Err(L3FrameError::TooManyPackets {
            count: packets.len(),
        });
    }
    let mut body_len = 1 + token.len() + 2 + 1;
    for pkt in packets {
        if pkt.len() > u16::MAX as usize {
            return Err(L3FrameError::PacketTooLarge {
                length: pkt.len(),
            });
        }
        body_len += 2 + pkt.len();
    }
    let mut out = Vec::with_capacity(2 + body_len);
    out.push(L3_VERSION);
    out.push(l3_cmd::DATA_REQ);
    out.push(token.len() as u8);
    out.extend_from_slice(token);
    out.extend_from_slice(&[0x00, 0x00]);
    out.push(packets.len() as u8);
    for pkt in packets {
        out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        out.extend_from_slice(pkt);
    }
    Ok(out)
}

/// Encodes one length-prefixed `0x94` response (Hermes reference server / Go `"len"` mode).
///
/// Wire: `05 94 <u16-be n> <n bytes IP packet>`, requiring `0 < n <= 4096`.
pub fn encode_l3_data_resp_length_prefixed(packet: &[u8]) -> Result<Vec<u8>, L3FrameError> {
    if packet.is_empty() {
        return Err(L3FrameError::EmptyLengthPrefixedPacket);
    }
    if packet.len() > MAX_LENGTH_PREFIXED_DATA_RESP as usize {
        return Err(L3FrameError::PacketTooLarge {
            length: packet.len(),
        });
    }
    let mut out = Vec::with_capacity(4 + packet.len());
    out.push(L3_VERSION);
    out.push(l3_cmd::DATA_RESP);
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    Ok(out)
}

/// Parses the token-framed data body (no version/cmd):  
/// `tokenLen | token | reserved(2) | count | [u16 len][pkt]...`
pub fn parse_l3_token_data_body(body: &[u8]) -> Result<Vec<&[u8]>, L3FrameError> {
    if body.len() < 4 {
        return Err(L3FrameError::Truncated {
            needed: 4,
            got: body.len(),
        });
    }
    let token_len = body[0] as usize;
    let mut idx = 1 + token_len;
    if body.len() < idx + 3 {
        return Err(L3FrameError::Truncated {
            needed: idx + 3,
            got: body.len(),
        });
    }
    idx += 2; // reserved
    let count = body[idx] as usize;
    idx += 1;

    let mut packets = Vec::with_capacity(count);
    for _ in 0..count {
        if idx + 2 > body.len() {
            return Err(L3FrameError::Truncated {
                needed: idx + 2,
                got: body.len(),
            });
        }
        let plen = u16::from_be_bytes([body[idx], body[idx + 1]]) as usize;
        idx += 2;
        if idx + plen > body.len() {
            return Err(L3FrameError::Truncated {
                needed: idx + plen,
                got: body.len(),
            });
        }
        packets.push(&body[idx..idx + plen]);
        idx += plen;
    }
    Ok(packets)
}

/// Bytes consumed while parsing a token-framed body from a prefix of a stream buffer.
fn token_body_len(body: &[u8]) -> Result<usize, L3FrameError> {
    if body.is_empty() {
        return Err(L3FrameError::Truncated {
            needed: 1,
            got: 0,
        });
    }
    let token_len = body[0] as usize;
    let mut idx = 1 + token_len;
    if body.len() < idx + 3 {
        return Err(L3FrameError::Truncated {
            needed: idx + 3,
            got: body.len(),
        });
    }
    idx += 2;
    let count = body[idx] as usize;
    idx += 1;
    for _ in 0..count {
        if idx + 2 > body.len() {
            return Err(L3FrameError::Truncated {
                needed: idx + 2,
                got: body.len(),
            });
        }
        let plen = u16::from_be_bytes([body[idx], body[idx + 1]]) as usize;
        idx += 2 + plen;
        if idx > body.len() {
            return Err(L3FrameError::Truncated {
                needed: idx,
                got: body.len(),
            });
        }
    }
    Ok(idx)
}

/// Decodes the body after `05 94`.
///
/// Returns the packets and the number of body bytes consumed (for stream buffers).
pub fn decode_l3_data_resp_body(
    body: &[u8],
) -> Result<(DataRespPackets<'_>, usize), L3FrameError> {
    if body.len() < 2 {
        return Err(L3FrameError::Truncated {
            needed: 2,
            got: body.len(),
        });
    }
    match classify_data_resp_prefix([body[0], body[1]]) {
        DataRespLayout::LengthPrefixed { packet_len } => {
            let n = packet_len as usize;
            let need = 2 + n;
            if body.len() < need {
                return Err(L3FrameError::Truncated {
                    needed: need,
                    got: body.len(),
                });
            }
            Ok((DataRespPackets::LengthPrefixed(&body[2..need]), need))
        }
        DataRespLayout::TokenFramed => {
            let consumed = token_body_len(body)?;
            let packets = parse_l3_token_data_body(&body[..consumed])?;
            Ok((DataRespPackets::TokenFramed(packets), consumed))
        }
    }
}

/// Decodes a full `05 94 ...` frame starting at the version byte.
pub fn decode_l3_data_resp_frame(
    frame: &[u8],
) -> Result<(DataRespPackets<'_>, usize), L3FrameError> {
    if frame.len() < 2 {
        return Err(L3FrameError::Truncated {
            needed: 2,
            got: frame.len(),
        });
    }
    if frame[0] != L3_VERSION || frame[1] != l3_cmd::DATA_RESP {
        return Err(L3FrameError::UnexpectedHeader {
            got: [frame[0], frame[1]],
        });
    }
    let (packets, body_len) = decode_l3_data_resp_body(&frame[2..])?;
    Ok((packets, 2 + body_len))
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum L3FrameError {
    #[error("token length {length} exceeds 255")]
    TokenTooLong { length: usize },
    #[error("packet count {count} exceeds 255")]
    TooManyPackets { count: usize },
    #[error("packet length {length} exceeds framing limit")]
    PacketTooLarge { length: usize },
    #[error("auth JSON length {length} exceeds u16")]
    JsonTooLarge { length: usize },
    #[error("length-prefixed 0x94 packet must be non-empty")]
    EmptyLengthPrefixedPacket,
    #[error("frame truncated: need {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },
    #[error("unexpected L3 header {got:02x?}")]
    UnexpectedHeader { got: [u8; 2] },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_go_threshold() {
        assert_eq!(
            classify_data_resp_prefix(1u16.to_be_bytes()),
            DataRespLayout::LengthPrefixed { packet_len: 1 }
        );
        assert_eq!(
            classify_data_resp_prefix(4096u16.to_be_bytes()),
            DataRespLayout::LengthPrefixed { packet_len: 4096 }
        );
        assert_eq!(
            classify_data_resp_prefix(0u16.to_be_bytes()),
            DataRespLayout::TokenFramed
        );
        assert_eq!(
            classify_data_resp_prefix(4097u16.to_be_bytes()),
            DataRespLayout::TokenFramed
        );
    }

    #[test]
    fn encode_data_req_matches_documented_layout() {
        let frame = encode_l3_data_req(b"tok", &[b"AB", b"C"]).unwrap();
        assert_eq!(
            frame,
            vec![
                0x05, 0x14, 3, b't', b'o', b'k', 0x00, 0x00, 2, 0x00, 0x02, b'A', b'B', 0x00,
                0x01, b'C',
            ]
        );
    }

    #[test]
    fn length_prefixed_resp_roundtrip() {
        let pkt = b"\x45\x00fake-ip";
        let frame = encode_l3_data_resp_length_prefixed(pkt).unwrap();
        assert_eq!(&frame[..2], &[0x05, 0x94]);
        let (decoded, consumed) = decode_l3_data_resp_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        match decoded {
            DataRespPackets::LengthPrefixed(p) => assert_eq!(p, pkt.as_slice()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn token_framed_resp_parses_like_data_req_body() {
        // tokenLen=0, reserved, count=1, one 2-byte packet
        let body = [0u8, 0x00, 0x00, 1, 0x00, 0x02, 0xde, 0xad];
        // first two bytes 0x0000 → token branch
        assert_eq!(
            classify_data_resp_prefix([body[0], body[1]]),
            DataRespLayout::TokenFramed
        );
        let mut frame = vec![0x05, 0x94];
        frame.extend_from_slice(&body);
        let (decoded, consumed) = decode_l3_data_resp_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        match decoded {
            DataRespPackets::TokenFramed(pkts) => {
                assert_eq!(pkts, vec![&[0xde, 0xad][..]]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn token_framed_with_token_bytes() {
        // token "ab" (len 2) → first u16 is 0x0261 = 609 ≤ 4096 → length-prefixed!
        // Use token that forces token branch: tokenLen=0 already covered.
        // tokenLen=0x20 (32), next byte 0x10 → n=0x2010 = 8208 > 4096 → token
        let mut body = vec![0x20];
        body.extend(std::iter::repeat_n(b'x', 32));
        body.extend_from_slice(&[0x00, 0x00, 1, 0x00, 0x03, b'p', b'k', b't']);
        assert_eq!(
            classify_data_resp_prefix([body[0], body[1]]),
            DataRespLayout::TokenFramed
        );
        let (packets, n) = decode_l3_data_resp_body(&body).unwrap();
        assert_eq!(n, body.len());
        match packets {
            DataRespPackets::TokenFramed(pkts) => assert_eq!(pkts, vec![b"pkt".as_slice()]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn heartbeat_constant() {
        assert_eq!(L3_HEARTBEAT_REQ, [0x05, 0x15, 0x00, 0x00]);
        assert_eq!(encode_l3_heartbeat_req(), L3_HEARTBEAT_REQ);
        assert!(is_l3_heartbeat_resp([0x05, 0x95]));
        assert!(!is_l3_heartbeat_resp([0x05, 0x15]));
    }

    #[test]
    fn encode_auth_req_matches_documented_layout() {
        let json = br#"{"sid":"x"}"#;
        let frame = encode_l3_auth_req(json).unwrap();
        assert_eq!(&frame[..2], &[0x05, 0x13]);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), json.len() as u16);
        assert_eq!(&frame[4..], json);
    }

    #[test]
    fn rejects_oversized_length_prefixed_encode() {
        let huge = vec![0u8; 4097];
        assert!(matches!(
            encode_l3_data_resp_length_prefixed(&huge),
            Err(L3FrameError::PacketTooLarge { .. })
        ));
    }
}
