//! SID-only Get-IP exchange (virtual IPv4 assignment).

use std::net::Ipv4Addr;
use std::time::Duration;

use hermes_model::SessionId;
use hermes_transport::{TlsConnectError, TlsPolicy, connect_tls};
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const MAX_PROTOCOL_RESPONSE: usize = 64 * 1024;
/// Bound response framing so a hostile peer cannot keep the reader busy forever.
const MAX_RESPONSE_FRAMES: usize = 8;

#[derive(Clone, Debug)]
pub struct GetIpv4Request<'a> {
    pub node_host: &'a str,
    pub node_port: u16,
    pub tls_policy: TlsPolicy,
    pub sid: &'a SessionId,
    pub timeout: Duration,
}

/// Outcome of one Get-IP exchange.
///
/// `status_bodies` holds every `53 00 <len> <body>` payload seen before the
/// address reply, in wire order. Xidian sends a bare `OK`, but the envelope is
/// the only place a mask / second-VIP hint could appear, so it is surfaced for
/// tracing rather than discarded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetIpv4Response {
    pub address: Ipv4Addr,
    /// Wire `addrType` from the VIP reply (1 = IPv4, 4 = IPv6, 5 = both).
    pub address_type: u8,
    /// Raw VIP body. For `addrType = 5` this also carries the IPv6 VIP, and for
    /// `addrType = 1` the two bytes trailing the IPv4 — kept because second-VIP
    /// semantics are still unconfirmed and this is where the evidence would be.
    pub vip_data: Vec<u8>,
    pub status_bodies: Vec<Vec<u8>>,
}

impl GetIpv4Response {
    /// Status bodies rendered as UTF-8 for logs, lossy on non-text payloads.
    #[must_use]
    pub fn status_text(&self) -> String {
        self.status_bodies
            .iter()
            .map(|body| String::from_utf8_lossy(body).into_owned())
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

/// Opens one TLS connection, performs the SID-only Get-IP exchange, and closes it.
pub async fn get_ipv4(request: GetIpv4Request<'_>) -> Result<GetIpv4Response, GetIpv4Error> {
    timeout(request.timeout, async {
        let mut stream =
            connect_tls(request.node_host, request.node_port, request.tls_policy).await?;
        request_ipv4(&mut stream, request.sid).await
    })
    .await
    .map_err(|_| GetIpv4Error::Timeout)?
}

/// Runs the wire exchange over an established stream. Exposed for deterministic
/// mock-server tests without requiring a live gateway, and reused by the L3
/// session driver, which keeps the same connection open afterwards.
pub async fn request_ipv4<S>(
    stream: &mut S,
    sid: &SessionId,
) -> Result<GetIpv4Response, GetIpv4Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[derive(Serialize)]
    struct SidRequest<'a> {
        sid: &'a str,
    }

    let json = serde_json::to_vec(&SidRequest { sid: sid.as_str() })?;
    let json_len = u16::try_from(json.len()).map_err(|_| GetIpv4Error::RequestTooLarge)?;

    let mut init = Vec::with_capacity(7 + json.len());
    init.extend_from_slice(&[0x05, 0x01, 0xd0, 0x53, 0x00]);
    init.extend_from_slice(&json_len.to_be_bytes());
    init.extend_from_slice(&json);
    stream.write_all(&init).await?;
    stream
        .write_all(&[0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;
    stream.flush().await?;

    let mut status_bodies = Vec::new();

    // Xidian (and zju-connect L3 auth) may first emit method ack `05 d0`, then
    // optional `53 00 <len> <body>` ("OK"), then address `05 00 00 01 <ipv4>`.
    // Match Go getIP: keep reading 2-byte headers until the address reply.
    for _ in 0..MAX_RESPONSE_FRAMES {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;

        if header == [0x05, 0xd0] {
            // Method selection ack: two bytes, no payload.
            continue;
        }

        if header[0] == 0x53 {
            if header[1] != 0 {
                return Err(GetIpv4Error::ProtocolRejected(header[1]));
            }
            let response_len = read_u16(stream).await? as usize;
            if response_len > MAX_PROTOCOL_RESPONSE {
                return Err(GetIpv4Error::ResponseTooLarge(response_len));
            }
            let mut response = vec![0; response_len];
            stream.read_exact(&mut response).await?;
            status_bodies.push(response);
            continue;
        }

        if header == [0x05, 0x00] {
            // VIP reply: `05 <status> <reserved> <addrType>` then an
            // address-type-sized body. The body length is NOT four — for
            // `addrType = 1` it is six, of which only the first four are the
            // IPv4 (zju-connect `vipPayloadLength` / `parseVirtualIPData`).
            // Consuming only four leaves two bytes on the wire, which is
            // invisible when the connection is closed straight after but
            // desynchronizes every later frame on a session that stays open.
            let mut tail = [0u8; 2];
            stream.read_exact(&mut tail).await?;
            let status = tail[0];
            let address_type = tail[1];
            if status != 0 {
                return Err(GetIpv4Error::AddressRejected(status));
            }
            let mut vip_data = vec![0; vip_payload_length(address_type)];
            stream.read_exact(&mut vip_data).await?;
            // Read the body before rejecting an unsupported type: the caller may
            // keep using this connection, and a half-consumed frame poisons it.
            let Some(address) = ipv4_from_vip_data(address_type, &vip_data) else {
                return Err(GetIpv4Error::UnsupportedAddressType(address_type));
            };
            return Ok(GetIpv4Response {
                address,
                address_type,
                vip_data,
                status_bodies,
            });
        }

        return Err(GetIpv4Error::UnexpectedHeader(header));
    }

    Err(GetIpv4Error::TooManyResponseFrames)
}

async fn read_u16<S>(stream: &mut S) -> Result<u16, std::io::Error>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    stream.read_exact(&mut bytes).await?;
    Ok(u16::from_be_bytes(bytes))
}

/// Body length that follows `05 <status> <reserved> <addrType>`.
///
/// Mirrors zju-connect `vipPayloadLength`: 1 = IPv4, 4 = IPv6, 5 = both. The
/// unknown-type fallback of four bytes is what keeps the stream in sync when the
/// server answers with a type this client did not ask for.
#[must_use]
pub const fn vip_payload_length(address_type: u8) -> usize {
    match address_type {
        1 => 6,
        4 => 18,
        5 => 22,
        _ => 4,
    }
}

/// Extracts the IPv4 VIP from a VIP body, if that type carries one.
///
/// Mirrors zju-connect `parseVirtualIPData`, which keys off the body length:
/// 6 = IPv4 (plus two trailing bytes), 18 = IPv6 only, 22 = IPv4 then IPv6.
fn ipv4_from_vip_data(address_type: u8, vip_data: &[u8]) -> Option<Ipv4Addr> {
    match address_type {
        1 | 5 if vip_data.len() >= 4 => Some(Ipv4Addr::new(
            vip_data[0],
            vip_data[1],
            vip_data[2],
            vip_data[3],
        )),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum GetIpv4Error {
    #[error("Get-IP operation timed out")]
    Timeout,
    #[error("TLS connection failed: {0}")]
    Tls(#[from] TlsConnectError),
    #[error("Get-IP I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to encode SID request: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SID request exceeds the protocol length limit")]
    RequestTooLarge,
    #[error("protocol response exceeded limit: {0} bytes")]
    ResponseTooLarge(usize),
    #[error("Get-IP protocol response rejected with status {0:#04x}")]
    ProtocolRejected(u8),
    #[error("unexpected Get-IP response header {0:02x?}")]
    UnexpectedHeader([u8; 2]),
    #[error("Get-IP response exceeded frame budget without an address")]
    TooManyResponseFrames,
    #[error("Get-IP address request rejected with status {0:#04x}")]
    AddressRejected(u8),
    #[error("Get-IP returned unsupported address type {0:#04x}")]
    UnsupportedAddressType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> SessionId {
        SessionId::new("s".repeat(73)).expect("valid SID")
    }

    async fn drain_request(server: &mut (impl AsyncRead + Unpin)) {
        let mut prefix = [0u8; 7];
        server.read_exact(&mut prefix).await.expect("init prefix");
        assert_eq!(&prefix[..5], &[0x05, 0x01, 0xd0, 0x53, 0x00]);
        let json_len = u16::from_be_bytes([prefix[5], prefix[6]]) as usize;
        let mut json = vec![0; json_len];
        server.read_exact(&mut json).await.expect("SID JSON");
        let mut address_request = [0u8; 10];
        server
            .read_exact(&mut address_request)
            .await
            .expect("address request");
        assert_eq!(address_request, [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn get_ip_uses_dynamic_json_length_and_parses_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server.read_exact(&mut prefix).await.expect("init prefix");
            assert_eq!(&prefix[..5], &[0x05, 0x01, 0xd0, 0x53, 0x00]);
            let json_len = u16::from_be_bytes([prefix[5], prefix[6]]) as usize;
            assert_eq!(json_len, 83);
            let mut json = vec![0; json_len];
            server.read_exact(&mut json).await.expect("SID JSON");
            assert_eq!(
                json,
                format!(r#"{{"sid":"{}"}}"#, "s".repeat(73)).as_bytes()
            );

            let mut address_request = [0u8; 10];
            server
                .read_exact(&mut address_request)
                .await
                .expect("address request");
            assert_eq!(address_request, [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            server
                .write_all(&[0x53, 0x00, 0x00, 0x02, b'O', b'K'])
                .await
                .expect("protocol response");
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 7, 0xde, 0xad])
                .await
                .expect("address response");
        });

        let response = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds");
        assert_eq!(response.address, Ipv4Addr::new(10, 8, 0, 7));
        assert_eq!(response.status_bodies, vec![b"OK".to_vec()]);
        assert_eq!(response.status_text(), "OK");
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_accepts_direct_address_response() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0; 7 + 83 + 10];
            server.read_exact(&mut request).await.expect("request");
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0xde, 0xad])
                .await
                .expect("address response");
        });

        let response = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds");
        assert_eq!(response.address, Ipv4Addr::new(10, 0, 0, 1));
        assert!(response.status_bodies.is_empty());
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_accepts_method_ack_then_ok_then_address() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            drain_request(&mut server).await;
            // Xidian live order observed: 05 d0, then 53 00 OK, then 05 00 IPv4.
            server.write_all(&[0x05, 0xd0]).await.expect("method ack");
            server
                .write_all(&[0x53, 0x00, 0x00, 0x02, b'O', b'K'])
                .await
                .expect("protocol response");
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 42, 0xde, 0xad])
                .await
                .expect("address response");
        });

        let response = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds after method ack");
        assert_eq!(response.address, Ipv4Addr::new(10, 8, 0, 42));
        assert_eq!(response.status_text(), "OK");
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_accepts_method_ack_before_direct_address() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            drain_request(&mut server).await;
            server
                .write_all(&[0x05, 0xd0, 0x05, 0x00, 0x00, 0x01, 10, 0, 0, 9, 0xde, 0xad])
                .await
                .expect("method ack + address");
        });

        let response = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds");
        assert_eq!(response.address, Ipv4Addr::new(10, 0, 0, 9));
        server_task.await.expect("mock server task");
    }

    /// The VIP body is six bytes for `addrType = 1`, not four. Under-reading it
    /// is invisible when the caller closes the connection, but leaves two bytes
    /// that desynchronize every later frame on a session that stays open — which
    /// is exactly how the L3 session driver uses this function.
    #[tokio::test]
    async fn get_ip_consumes_the_whole_vip_frame() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            drain_request(&mut server).await;
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 7, 0xde, 0xad])
                .await
                .expect("vip");
            // The next frame on the wire, which must survive intact.
            server
                .write_all(&[0x05, 0x95, 0x00, 0x00])
                .await
                .expect("heartbeat");
        });

        let response = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds");
        assert_eq!(response.address, Ipv4Addr::new(10, 8, 0, 7));
        assert_eq!(response.address_type, 1);
        assert_eq!(response.vip_data, vec![10, 8, 0, 7, 0xde, 0xad]);

        let mut next = [0u8; 4];
        client.read_exact(&mut next).await.expect("next frame");
        assert_eq!(
            next,
            [0x05, 0x95, 0x00, 0x00],
            "the VIP frame must be fully consumed, leaving the stream aligned"
        );
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_rejects_non_ipv4_response() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0; 7 + 83 + 10];
            server.read_exact(&mut request).await.expect("request");
            server
                .write_all(&[
                    0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ])
                .await
                .expect("address response");
        });

        let error = request_ipv4(&mut client, &sid())
            .await
            .expect_err("IPv6 response is unsupported");
        assert!(matches!(error, GetIpv4Error::UnsupportedAddressType(4)));
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_rejects_unknown_header_after_method_ack() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            drain_request(&mut server).await;
            server
                .write_all(&[0x05, 0xd0, 0x05, 0xff])
                .await
                .expect("method ack + unknown");
        });

        let error = request_ipv4(&mut client, &sid())
            .await
            .expect_err("unknown header after method ack");
        assert!(matches!(
            error,
            GetIpv4Error::UnexpectedHeader([0x05, 0xff])
        ));
        server_task.await.expect("mock server task");
    }
}
