use std::pin::Pin;
use std::task::{Context, Poll};

use atrust_protocol::{encode_tcp_app_data, encode_tcp_close, encode_tcp_probe, is_status_ok};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tracing::debug;

/// Trailer that makes an `01 01` frame the server closing the tunnel, as
/// distinct from the `01 01 00 00` this side sends. Matches Go `tcpTunnelConn`.
const SERVER_CLOSE_TRAILER: [u8; 2] = [0x30, 0x30];

/// Framed TCP tunnel after a successful handshake.
///
/// Application frames match Go `tcpTunnelConn`:
/// - data: `01 00 <u16-be len> <payload>`
/// - close sent by this side: `01 01 00 00`
/// - close sent by the server: `01 01 30 30`; any other `01 01` trailer is a
///   marker the stream continues past
pub struct TcpTunnel<S = hermes_transport::NodeTlsStream> {
    stream: S,
    read_buf: Vec<u8>,
    app_pending: Vec<u8>,
    write_pending: Vec<u8>,
    write_offset: usize,
    closed: bool,
}

impl<S> TcpTunnel<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn from_stream(stream: S) -> Self {
        Self {
            stream,
            read_buf: Vec::with_capacity(8 * 1024),
            app_pending: Vec::new(),
            write_pending: Vec::new(),
            write_offset: 0,
            closed: false,
        }
    }

    /// Sends keepalive probe (`01 00 00 00`).
    pub async fn send_probe(&mut self) -> Result<(), TunnelError> {
        if self.closed {
            return Err(TunnelError::Closed);
        }
        self.stream.write_all(&encode_tcp_probe()).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Sends close frame and shuts down the write half.
    pub async fn close(&mut self) -> Result<(), TunnelError> {
        if self.closed {
            return Ok(());
        }
        let _ = self.stream.write_all(&encode_tcp_close()).await;
        let _ = self.stream.flush().await;
        let _ = self.stream.shutdown().await;
        self.closed = true;
        debug!(event = "atrust_tcp.tunnel.closed");
        Ok(())
    }

    /// Writes one application-data frame.
    pub async fn write_app(&mut self, payload: &[u8]) -> Result<(), TunnelError> {
        if self.closed {
            return Err(TunnelError::Closed);
        }
        let frame = encode_tcp_app_data(payload)?;
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads the next complete application-data frame payload.
    pub async fn read_app(&mut self) -> Result<Option<Vec<u8>>, TunnelError> {
        if self.closed {
            return Ok(None);
        }
        loop {
            match try_decode_app(&mut self.read_buf)? {
                Decode::App(payload) => return Ok(Some(payload)),
                Decode::Closed => {
                    self.closed = true;
                    return Ok(None);
                }
                Decode::NeedMore => {}
            }
            let mut tmp = [0_u8; 8192];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                self.closed = true;
                return Ok(None);
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
}

#[derive(Debug)]
enum Decode {
    App(Vec<u8>),
    Closed,
    NeedMore,
}

fn try_decode_app(read_buf: &mut Vec<u8>) -> Result<Decode, TunnelError> {
    let mut skipped = 0_usize;
    loop {
        if read_buf.len() < 2 {
            return Ok(Decode::NeedMore);
        }
        let h0 = read_buf[0];
        let h1 = read_buf[1];

        // Application data: 01 00 | u16be | payload
        if h0 == 0x01 && h1 == 0x00 {
            if read_buf.len() < 4 {
                return Ok(Decode::NeedMore);
            }
            let len = u16::from_be_bytes([read_buf[2], read_buf[3]]) as usize;
            if read_buf.len() < 4 + len {
                return Ok(Decode::NeedMore);
            }
            let payload = read_buf[4..4 + len].to_vec();
            read_buf.drain(..4 + len);
            return Ok(Decode::App(payload));
        }

        // `01 01` carries a two-byte trailer, and only the ASCII "00" trailer is
        // the server closing the tunnel. Go `tcpTunnelConn::Read` consumes every
        // other trailer and keeps reading, and the node does send `01 01 00 00`
        // ahead of the first response: treating that as EOF ends the stream just
        // before the target's data arrives.
        if h0 == 0x01 && h1 == 0x01 {
            if read_buf.len() < 4 {
                return Ok(Decode::NeedMore);
            }
            let trailer = [read_buf[2], read_buf[3]];
            read_buf.drain(..4);
            if trailer == SERVER_CLOSE_TRAILER {
                debug!(
                    event = "atrust_tcp.tunnel.close_frame",
                    trailer0 = trailer[0],
                    trailer1 = trailer[1]
                );
                return Ok(Decode::Closed);
            }
            debug!(
                event = "atrust_tcp.tunnel.marker_frame",
                trailer0 = trailer[0],
                trailer1 = trailer[1]
            );
            continue;
        }

        // `05 81` is node chatter with no body. The handshake already skips it;
        // it can also appear once the data phase has started.
        if h0 == 0x05 && h1 == 0x81 {
            debug!(event = "atrust_tcp.tunnel.node_chatter");
            read_buf.drain(..2);
            continue;
        }

        // Protocol chatter during data phase: 53 00 | len | body
        if h0 == 0x53 && h1 == 0x00 {
            if read_buf.len() < 4 {
                return Ok(Decode::NeedMore);
            }
            let len = u16::from_be_bytes([read_buf[2], read_buf[3]]) as usize;
            if read_buf.len() < 4 + len {
                return Ok(Decode::NeedMore);
            }
            let body = read_buf[4..4 + len].to_vec();
            read_buf.drain(..4 + len);
            if !is_status_ok(&body) {
                return Err(TunnelError::ProtocolError {
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
            }
            continue;
        }

        // The node emits a run of padding after the connect status, and Go
        // `tcpTunnelConn::Read` walks past it: its branch chain has no final
        // `else`, so an unrecognised two-byte header is consumed and the loop
        // continues. Rejecting it here ended the tunnel on the node's very first
        // response. The bound is ours, not Go's — it keeps a genuine
        // desynchronisation from spinning forever on buffered garbage.
        skipped += 2;
        if skipped > MAX_SKIPPED_CHATTER_BYTES {
            debug!(
                event = "atrust_tcp.tunnel.unexpected_frame",
                h0,
                h1,
                skipped,
                buffered = read_buf.len(),
                head = %hex_head(read_buf)
            );
            return Err(TunnelError::UnexpectedFrame { header: [h0, h1] });
        }
        debug!(event = "atrust_tcp.tunnel.skipped_chatter", h0, h1, skipped);
        read_buf.drain(..2);
    }
}

/// Consecutive unrecognised bytes tolerated before the stream is declared
/// desynchronised rather than merely padded.
const MAX_SKIPPED_CHATTER_BYTES: usize = 1024;

fn hex_head(read_buf: &[u8]) -> String {
    read_buf
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

impl<S> AsyncWrite for TcpTunnel<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tunnel closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.write_pending.is_empty() {
            let chunk_len = buf.len().min(u16::MAX as usize);
            debug!(
                event = "atrust_tcp.tunnel.app_frame_write",
                payload_len = chunk_len
            );
            let frame = encode_tcp_app_data(&buf[..chunk_len])
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            self.write_pending = frame;
            self.write_offset = 0;
        }

        let user_len = if self.write_pending.len() >= 4 {
            u16::from_be_bytes([self.write_pending[2], self.write_pending[3]]) as usize
        } else {
            0
        };

        loop {
            if self.write_offset >= self.write_pending.len() {
                break;
            }
            let offset = self.write_offset;
            let to_write = self.write_pending[offset..].to_vec();
            match Pin::new(&mut self.stream).poll_write(cx, &to_write) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.write_pending.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(user_len))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.closed && self.write_pending.is_empty() {
            self.write_pending = encode_tcp_close().to_vec();
            self.write_offset = 0;
        }
        loop {
            if self.write_offset >= self.write_pending.len() {
                break;
            }
            let offset = self.write_offset;
            let to_write = self.write_pending[offset..].to_vec();
            match Pin::new(&mut self.stream).poll_write(cx, &to_write) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(n)) => self.write_offset += n,
                Poll::Ready(Err(_)) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_pending.clear();
        self.closed = true;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<S> AsyncRead for TcpTunnel<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.app_pending.is_empty() {
            let n = buf.remaining().min(self.app_pending.len());
            buf.put_slice(&self.app_pending[..n]);
            self.app_pending.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        loop {
            match try_decode_app(&mut self.read_buf) {
                Ok(Decode::App(payload)) => {
                    // A zero-length application frame is a tunnel probe, not
                    // stream EOF. Returning an unchanged ReadBuf would make
                    // Tokio/rustls terminate the inner TLS handshake.
                    if payload.is_empty() {
                        continue;
                    }
                    self.app_pending.extend_from_slice(&payload);
                    let n = buf.remaining().min(self.app_pending.len());
                    buf.put_slice(&self.app_pending[..n]);
                    self.app_pending.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Decode::Closed) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Ok(Decode::NeedMore) => {}
                Err(error) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error,
                    )));
                }
            }

            let mut tmp = [0_u8; 8192];
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        self.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.read_buf.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> std::fmt::Debug for TcpTunnel<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTunnel")
            .field("closed", &self.closed)
            .field("read_buf_len", &self.read_buf.len())
            .field("app_pending_len", &self.app_pending.len())
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("tunnel is closed")]
    Closed,
    #[error(transparent)]
    Frame(#[from] atrust_protocol::TcpFrameError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unexpected tunnel frame header {header:02x?}")]
    UnexpectedFrame { header: [u8; 2] },
    #[error("protocol error during data phase: {body}")]
    ProtocolError { body: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrust_protocol::encode_tcp_app_data;
    use tokio::time::{Duration, timeout};

    #[test]
    fn decode_app_frame_from_buffer() {
        let mut frame = encode_tcp_app_data(b"hello").unwrap();
        match try_decode_app(&mut frame).unwrap() {
            Decode::App(payload) => assert_eq!(payload, b"hello"),
            other => panic!("expected app, got {other:?}"),
        }
    }

    #[test]
    fn server_close_frame_ends_the_stream() {
        let mut frame = vec![0x01, 0x01, SERVER_CLOSE_TRAILER[0], SERVER_CLOSE_TRAILER[1]];
        assert!(matches!(
            try_decode_app(&mut frame).unwrap(),
            Decode::Closed
        ));
    }

    /// The node sends this ahead of the first target response. Reading it as EOF
    /// ended the tunnel exactly one frame before the data the caller wanted.
    #[test]
    fn zero_trailer_marker_is_not_end_of_stream() {
        let mut wire = encode_tcp_close().to_vec();
        wire.extend_from_slice(&encode_tcp_app_data(b"hello").unwrap());
        match try_decode_app(&mut wire).unwrap() {
            Decode::App(payload) => assert_eq!(payload, b"hello"),
            other => panic!("expected app after marker, got {other:?}"),
        }
    }

    /// What the node actually sends after `05 00`: the marker, then a run of
    /// padding, then the target's first response.
    #[test]
    fn padding_run_after_connect_status_is_walked_past() {
        let mut wire = vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        wire.extend_from_slice(&encode_tcp_app_data(b"hello").unwrap());
        match try_decode_app(&mut wire).unwrap() {
            Decode::App(payload) => assert_eq!(payload, b"hello"),
            other => panic!("expected app after padding, got {other:?}"),
        }
    }

    #[test]
    fn unbounded_garbage_is_still_reported_as_desync() {
        let mut wire = vec![0xab; MAX_SKIPPED_CHATTER_BYTES * 2];
        assert!(matches!(
            try_decode_app(&mut wire),
            Err(TunnelError::UnexpectedFrame { .. })
        ));
    }

    #[test]
    fn node_chatter_is_skipped_during_data_phase() {
        let mut wire = vec![0x05, 0x81];
        wire.extend_from_slice(&encode_tcp_app_data(b"hello").unwrap());
        match try_decode_app(&mut wire).unwrap() {
            Decode::App(payload) => assert_eq!(payload, b"hello"),
            other => panic!("expected app after chatter, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn async_read_continues_past_zero_trailer_marker() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let mut tunnel = TcpTunnel::from_stream(stream);
        let mut wire = encode_tcp_close().to_vec();
        wire.extend_from_slice(&encode_tcp_app_data(b"hello").unwrap());
        peer.write_all(&wire).await.unwrap();

        let mut payload = [0_u8; 5];
        tunnel.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
    }

    #[test]
    fn data_phase_status_rejects_non_success_body() {
        for body in [b"NOT OK".as_slice(), b"OKAY".as_slice()] {
            let mut frame = vec![0x53, 0x00];
            frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
            frame.extend_from_slice(body);

            assert!(matches!(
                try_decode_app(&mut frame),
                Err(TunnelError::ProtocolError { .. })
            ));
        }

        let body = br#"{"code":0,"message":"OK"}"#;
        let mut frame = vec![0x53, 0x00];
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(body);
        assert!(matches!(try_decode_app(&mut frame), Ok(Decode::NeedMore)));
    }

    #[tokio::test]
    async fn async_write_of_empty_buffer_emits_nothing() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let mut tunnel = TcpTunnel::from_stream(stream);

        assert_eq!(tunnel.write(&[]).await.unwrap(), 0);
        let mut byte = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(20), peer.read(&mut byte))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn async_read_skips_zero_length_probe_before_data() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let mut tunnel = TcpTunnel::from_stream(stream);
        let mut wire = encode_tcp_app_data(b"").unwrap();
        wire.extend_from_slice(&encode_tcp_app_data(b"hello").unwrap());
        peer.write_all(&wire).await.unwrap();

        let mut payload = [0_u8; 5];
        tunnel.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
    }

    #[tokio::test]
    async fn async_read_walks_past_padding_run() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let mut tunnel = TcpTunnel::from_stream(stream);
        let mut wire = vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        wire.extend_from_slice(&encode_tcp_app_data(b"hello").unwrap());
        peer.write_all(&wire).await.unwrap();

        let mut payload = [0_u8; 5];
        tunnel.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
    }
}
