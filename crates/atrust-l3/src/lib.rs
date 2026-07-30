//! Minimal aTrust L3 data-plane experiments.
//!
//! This crate intentionally starts with the SID-only Get-IP exchange. Per-flow
//! authorization and packet forwarding remain separate, later protocol stages.

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

/// Opens one TLS connection, performs the SID-only Get-IP exchange, and closes it.
pub async fn get_ipv4(request: GetIpv4Request<'_>) -> Result<Ipv4Addr, GetIpv4Error> {
    timeout(request.timeout, async {
        let mut stream =
            connect_tls(request.node_host, request.node_port, request.tls_policy).await?;
        request_ipv4(&mut stream, request.sid).await
    })
    .await
    .map_err(|_| GetIpv4Error::Timeout)?
}

/// Runs the wire exchange over an established stream. Exposed for deterministic
/// mock-server tests without requiring a live gateway.
pub async fn request_ipv4<S>(stream: &mut S, sid: &SessionId) -> Result<Ipv4Addr, GetIpv4Error>
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
            continue;
        }

        if header == [0x05, 0x00] {
            let mut address = [0u8; 6];
            stream.read_exact(&mut address).await?;
            if address[0] != 0 {
                return Err(GetIpv4Error::AddressRejected(address[0]));
            }
            if address[1] != 1 {
                return Err(GetIpv4Error::UnsupportedAddressType(address[1]));
            }
            return Ok(Ipv4Addr::new(
                address[2], address[3], address[4], address[5],
            ));
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
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 7])
                .await
                .expect("address response");
        });

        let address = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds");
        assert_eq!(address, Ipv4Addr::new(10, 8, 0, 7));
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_accepts_direct_address_response() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0; 7 + 83 + 10];
            server.read_exact(&mut request).await.expect("request");
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1])
                .await
                .expect("address response");
        });

        let address = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds");
        assert_eq!(address, Ipv4Addr::new(10, 0, 0, 1));
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
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 8, 0, 42])
                .await
                .expect("address response");
        });

        let address = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds after method ack");
        assert_eq!(address, Ipv4Addr::new(10, 8, 0, 42));
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_accepts_method_ack_before_direct_address() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            drain_request(&mut server).await;
            server
                .write_all(&[0x05, 0xd0, 0x05, 0x00, 0x00, 0x01, 10, 0, 0, 9])
                .await
                .expect("method ack + address");
        });

        let address = request_ipv4(&mut client, &sid())
            .await
            .expect("Get-IP succeeds");
        assert_eq!(address, Ipv4Addr::new(10, 0, 0, 9));
        server_task.await.expect("mock server task");
    }

    #[tokio::test]
    async fn get_ip_rejects_non_ipv4_response() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0; 7 + 83 + 10];
            server.read_exact(&mut request).await.expect("request");
            server
                .write_all(&[0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0])
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
