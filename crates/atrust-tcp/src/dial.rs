use std::net::Ipv4Addr;
use std::time::Duration;

use atrust_protocol::{
    ProcessIdentity, TcpInitParams, build_signed_tcp_init_json, encode_tcp_init_frame,
    encode_tcp_probe, encode_tcp_target_domain, encode_tcp_target_ipv4, is_status_ok,
    parse_status_payload,
};
use hermes_model::{ConnectionId, DeviceId, SessionId, SignKey};
use hermes_transport::{TlsConnectError, TlsPolicy, connect_tls};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::stream::TcpTunnel;
use crate::target::TunnelTarget;

/// Session + node parameters for one TCP tunnel dial.
/// Default budget for TCP/TLS establishment and for the aTrust handshake.
pub const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// zju-connect may repeat one failed underlay dial after refreshing the network
/// interface. Hermes has no interface owner, but makes the same single retry for
/// transient failures before any application bytes can have been sent.
pub const TCP_DIAL_RETRIES: usize = 1;

#[derive(Clone, Debug)]
pub struct DialTcpRequest<'a> {
    pub node_host: &'a str,
    pub node_port: u16,
    pub tls_policy: TlsPolicy,
    pub sid: &'a SessionId,
    pub device_id: &'a DeviceId,
    pub connection_id: &'a ConnectionId,
    pub sign_key: &'a SignKey,
    pub username: &'a str,
    pub target: TunnelTarget,
    pub process: Option<ProcessIdentity>,
    pub lang: &'a str,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
}

/// Opens TLS to the node, completes aTrust TCP handshake, returns a framed tunnel.
pub async fn dial_tcp(request: DialTcpRequest<'_>) -> Result<TcpTunnel, DialTcpError> {
    validate_request(&request)?;

    let process = request
        .process
        .clone()
        .unwrap_or_else(|| ProcessIdentity::default_for_port(request.target.port()));
    let (init_frame, dest_frame) = build_handshake_frames(&request, &process)?;

    debug!(
        event = "atrust_tcp.dial.begin",
        node_port = request.node_port,
        target_port = request.target.port(),
        app_id_present = !request.target.app_id().is_empty(),
        init_len = init_frame.len(),
        dest_len = dest_frame.len()
    );

    let stream = timeout(
        request.connect_timeout,
        connect_tls(request.node_host, request.node_port, request.tls_policy),
    )
    .await
    .map_err(|_| DialTcpError::ConnectTimeout)?
    .map_err(DialTcpError::Tls)?;

    let stream = timeout(
        request.handshake_timeout,
        complete_handshake(stream, &init_frame, &dest_frame),
    )
    .await
    .map_err(|_| DialTcpError::HandshakeTimeout)??;

    info!(
        event = "atrust_tcp.dial.established",
        node_port = request.node_port,
        target_port = request.target.port()
    );

    Ok(TcpTunnel::from_stream(stream))
}

/// Dials a TCP tunnel and retries transient establishment failures.
///
/// This never retries a server rejection or malformed protocol response, and it
/// stops once a [`TcpTunnel`] is returned. Replaying application bytes after a
/// later disconnect would be unsafe for non-idempotent protocols.
pub async fn dial_tcp_with_retry(
    request: DialTcpRequest<'_>,
    max_retries: usize,
) -> Result<TcpTunnel, DialTcpError> {
    let mut retries = 0_usize;
    loop {
        match dial_tcp(request.clone()).await {
            Ok(tunnel) => return Ok(tunnel),
            Err(error) if retries < max_retries && error.is_retryable() => {
                retries += 1;
                warn!(
                    event = "atrust_tcp.dial.retry",
                    attempt = retries + 1,
                    max_attempts = max_retries + 1,
                    error = %error
                );
            }
            Err(error) => return Err(error),
        }
    }
}

/// Runs the aTrust TCP handshake on an already-connected stream (tests / injection).
pub async fn complete_handshake<S>(
    mut stream: S,
    init_frame: &[u8],
    dest_frame: &[u8],
) -> Result<S, DialTcpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(init_frame).await?;
    stream.write_all(dest_frame).await?;
    stream.flush().await?;
    wait_for_address_ok(&mut stream).await?;
    stream.write_all(&encode_tcp_probe()).await?;
    stream.flush().await?;
    wait_for_connect_status(&mut stream).await?;
    Ok(stream)
}

fn validate_request(request: &DialTcpRequest<'_>) -> Result<(), DialTcpError> {
    if request.node_host.is_empty() {
        return Err(DialTcpError::EmptyNodeHost);
    }
    if request.node_port == 0 {
        return Err(DialTcpError::InvalidNodePort);
    }
    if request.target.app_id().is_empty() {
        return Err(DialTcpError::EmptyAppId);
    }
    if request.target.port() == 0 {
        return Err(DialTcpError::InvalidTargetPort);
    }
    Ok(())
}

fn build_handshake_frames(
    request: &DialTcpRequest<'_>,
    process: &ProcessIdentity,
) -> Result<(Vec<u8>, Vec<u8>), DialTcpError> {
    let dest_host = request.target.json_dest_host();
    let params = TcpInitParams {
        sid: request.sid,
        app_id: request.target.app_id(),
        dest_host: dest_host.as_str(),
        dest_port: request.target.port(),
        device_id: request.device_id,
        connection_id: request.connection_id,
        username: request.username,
        process,
        lang: request.lang,
    };
    let init_json = build_signed_tcp_init_json(&params, request.sign_key)?;
    let init_frame = encode_tcp_init_frame(&init_json)?;
    let dest_frame = encode_dest_frame(&request.target)?;
    Ok((init_frame, dest_frame))
}

fn encode_dest_frame(target: &TunnelTarget) -> Result<Vec<u8>, DialTcpError> {
    match target {
        TunnelTarget::Ipv4 { ip, port, .. } => Ok(encode_tcp_target_ipv4(*ip, *port)),
        TunnelTarget::Domain { host, port, .. } => {
            encode_tcp_target_domain(host, *port).map_err(DialTcpError::from)
        }
    }
}

/// After init+dest: skip `05 81` noise, require `53 00 <len> <payload containing OK>`.
async fn wait_for_address_ok<S>(stream: &mut S) -> Result<(), DialTcpError>
where
    S: AsyncRead + Unpin,
{
    loop {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await?;
        debug!(
            event = "atrust_tcp.dial.header",
            h0 = header[0],
            h1 = header[1]
        );
        if header[0] == 0x05 && header[1] == 0x81 {
            continue;
        }
        if header[0] != 0x53 || header[1] != 0x00 {
            return Err(DialTcpError::UnexpectedStatusHeader {
                bytes: header.to_vec(),
            });
        }
        let mut len_bytes = [0_u8; 2];
        stream.read_exact(&mut len_bytes).await?;
        let len = u16::from_be_bytes(len_bytes) as usize;
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).await?;
        // Full nested form also accepted via parse_status_payload for 53 00 bodies.
        let body = if payload.starts_with(&[0x53, 0x00]) {
            parse_status_payload(&payload)?.to_vec()
        } else {
            payload
        };
        debug!(
            event = "atrust_tcp.dial.address_response",
            payload_len = body.len()
        );
        if body.windows(2).any(|w| w == b"OK") || is_status_ok(&body) {
            return Ok(());
        }
        return Err(DialTcpError::AddressRejected {
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
}

/// After probe: `05 <status>` where `00` is success (Go waitForTCPConnect).
async fn wait_for_connect_status<S>(stream: &mut S) -> Result<(), DialTcpError>
where
    S: AsyncRead + Unpin,
{
    let mut status = [0_u8; 2];
    stream.read_exact(&mut status).await?;
    debug!(
        event = "atrust_tcp.dial.connect_status",
        s0 = status[0],
        s1 = status[1]
    );
    if status[0] != 0x05 {
        return Err(DialTcpError::UnexpectedStatusHeader {
            bytes: status.to_vec(),
        });
    }
    match status[1] {
        0x00 => Ok(()),
        code => Err(DialTcpError::ConnectRejected { status: code }),
    }
}

/// Builds destination for tests / helpers from an IPv4.
pub fn ipv4_target(ip: Ipv4Addr, port: u16, app_id: impl Into<String>) -> TunnelTarget {
    TunnelTarget::Ipv4 {
        ip,
        port,
        app_id: app_id.into(),
    }
}

#[derive(Debug, Error)]
pub enum DialTcpError {
    #[error("node host must not be empty")]
    EmptyNodeHost,
    #[error("node port must not be zero")]
    InvalidNodePort,
    #[error("appId must not be empty")]
    EmptyAppId,
    #[error("target port must not be zero")]
    InvalidTargetPort,
    #[error("TLS connect timed out")]
    ConnectTimeout,
    #[error("TCP handshake timed out")]
    HandshakeTimeout,
    #[error(transparent)]
    Tls(#[from] TlsConnectError),
    #[error(transparent)]
    InitJson(#[from] atrust_protocol::TcpInitError),
    #[error(transparent)]
    Frame(#[from] atrust_protocol::TcpFrameError),
    #[error("I/O error during handshake: {0}")]
    Io(#[from] std::io::Error),
    #[error("unexpected status header: {bytes:?}")]
    UnexpectedStatusHeader { bytes: Vec<u8> },
    #[error("node rejected tunnel address: {body}")]
    AddressRejected { body: String },
    #[error("node rejected TCP connect with status 0x{status:02x}")]
    ConnectRejected { status: u8 },
}

impl DialTcpError {
    /// Whether a fresh connection can safely retry this failure before the
    /// caller has received a tunnel and sent application data.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConnectTimeout | Self::HandshakeTimeout => true,
            Self::Tls(error) => !matches!(error, TlsConnectError::InvalidServerName),
            Self::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::UnexpectedEof
            ),
            Self::EmptyNodeHost
            | Self::InvalidNodePort
            | Self::EmptyAppId
            | Self::InvalidTargetPort
            | Self::InitJson(_)
            | Self::Frame(_)
            | Self::UnexpectedStatusHeader { .. }
            | Self::AddressRejected { .. }
            | Self::ConnectRejected { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrust_protocol::{TCP_INIT_PREFIX, encode_tcp_init_frame};
    use hermes_model::SignKey;
    use tokio::io::duplex;

    #[test]
    fn dest_ipv4_frame_matches_codec() {
        let target = TunnelTarget::Ipv4 {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            port: 443,
            app_id: "app".into(),
        };
        let frame = encode_dest_frame(&target).unwrap();
        assert_eq!(
            frame,
            encode_tcp_target_ipv4(Ipv4Addr::new(10, 0, 0, 1), 443)
        );
    }

    #[test]
    fn retry_policy_only_accepts_transient_establishment_failures() {
        assert!(DialTcpError::ConnectTimeout.is_retryable());
        assert!(DialTcpError::HandshakeTimeout.is_retryable());
        assert!(
            DialTcpError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
                .is_retryable()
        );
        assert!(!DialTcpError::InvalidTargetPort.is_retryable());
        assert!(!DialTcpError::ConnectRejected { status: 2 }.is_retryable());
        assert!(!DialTcpError::UnexpectedStatusHeader { bytes: vec![5, 9] }.is_retryable());
    }

    #[test]
    fn init_frame_prefix_on_signed_json() {
        let sid = SessionId::new("sid").unwrap();
        let device = DeviceId::new("dev").unwrap();
        let connection = ConnectionId::new("conn-1").unwrap();
        let process = ProcessIdentity::default_for_port(80);
        let params = TcpInitParams {
            sid: &sid,
            app_id: "app",
            dest_host: "1.2.3.4",
            dest_port: 80,
            device_id: &device,
            connection_id: &connection,
            username: "u",
            process: &process,
            lang: "en-US",
        };
        let key = SignKey::from_hex("aabb").unwrap();
        let json = build_signed_tcp_init_json(&params, &key).unwrap();
        let frame = encode_tcp_init_frame(&json).unwrap();
        assert_eq!(&frame[..TCP_INIT_PREFIX.len()], TCP_INIT_PREFIX);
        assert_eq!(
            u16::from_be_bytes([frame[5], frame[6]]) as usize,
            json.len()
        );
    }

    #[tokio::test]
    async fn mock_peer_handshake_and_echo() {
        let (client, mut server) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            // Read init: prefix 5 + u16 + json
            let mut prefix = [0_u8; 5];
            server.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, [0x05, 0x01, 0x81, 0x53, 0x03]);
            let mut len_bytes = [0_u8; 2];
            server.read_exact(&mut len_bytes).await.unwrap();
            let len = u16::from_be_bytes(len_bytes) as usize;
            let mut json = vec![0_u8; len];
            server.read_exact(&mut json).await.unwrap();
            assert!(json.windows(7).any(|w| w == br#""appId""#));

            // Dest IPv4: 10 bytes
            let mut dest = [0_u8; 10];
            server.read_exact(&mut dest).await.unwrap();
            assert_eq!(&dest[..4], &[0x05, 0x01, 0x01, 0x01]);

            // Address OK
            let mut ok = vec![0x53, 0x00, 0x00, 0x02];
            ok.extend_from_slice(b"OK");
            server.write_all(&ok).await.unwrap();

            // Probe
            let mut probe = [0_u8; 4];
            server.read_exact(&mut probe).await.unwrap();
            assert_eq!(probe, [0x01, 0x00, 0x00, 0x00]);

            // Connect success
            server.write_all(&[0x05, 0x00]).await.unwrap();
            server.flush().await.unwrap();

            // Echo one app frame
            let mut app_hdr = [0_u8; 4];
            server.read_exact(&mut app_hdr).await.unwrap();
            assert_eq!(&app_hdr[..2], &[0x01, 0x00]);
            let app_len = u16::from_be_bytes([app_hdr[2], app_hdr[3]]) as usize;
            let mut app = vec![0_u8; app_len];
            server.read_exact(&mut app).await.unwrap();
            let mut reply = vec![0x01, 0x00];
            reply.extend_from_slice(&(app_len as u16).to_be_bytes());
            reply.extend_from_slice(&app);
            server.write_all(&reply).await.unwrap();
            server.flush().await.unwrap();
        });

        let sid = SessionId::new("sid").unwrap();
        let device = DeviceId::new("dev").unwrap();
        let connection = ConnectionId::new("conn-1").unwrap();
        let key = SignKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let process = ProcessIdentity::default_for_port(80);
        let request = DialTcpRequest {
            node_host: "unused",
            node_port: 443,
            tls_policy: TlsPolicy::Verify,
            sid: &sid,
            device_id: &device,
            connection_id: &connection,
            sign_key: &key,
            username: "alice",
            target: TunnelTarget::Ipv4 {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 80,
                app_id: "app-1".into(),
            },
            process: Some(process),
            lang: "en-US",
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        };
        let process = request.process.clone().unwrap();
        let (init_frame, dest_frame) = build_handshake_frames(&request, &process).unwrap();
        let stream = complete_handshake(client, &init_frame, &dest_frame)
            .await
            .unwrap();
        let mut tunnel = TcpTunnel::from_stream(stream);
        tunnel.write_app(b"ping").await.unwrap();
        let echo = tunnel.read_app().await.unwrap().unwrap();
        assert_eq!(echo, b"ping");
        server_task.await.unwrap();
    }
}
