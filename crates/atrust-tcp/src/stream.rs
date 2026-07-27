use std::pin::Pin;
use std::task::{Context, Poll};

use atrust_protocol::{encode_tcp_app_data, encode_tcp_close, encode_tcp_probe};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tracing::debug;

/// Framed TCP tunnel after a successful handshake.
///
/// Application frames match Go `tcpTunnelConn`:
/// - data: `01 00 <u16-be len> <payload>`
/// - close: `01 01 00 00`
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

        // Close: 01 01 ....
        if h0 == 0x01 && h1 == 0x01 {
            if read_buf.len() < 4 {
                return Ok(Decode::NeedMore);
            }
            read_buf.drain(..4);
            return Ok(Decode::Closed);
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
            if !body.windows(2).any(|w| w == b"OK") && body.as_slice() != b"OK" {
                return Err(TunnelError::ProtocolError {
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
            }
            continue;
        }

        return Err(TunnelError::UnexpectedFrame { header: [h0, h1] });
    }
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

        if self.write_pending.is_empty() {
            let chunk_len = buf.len().min(u16::MAX as usize);
            let frame = encode_tcp_app_data(&buf[..chunk_len]).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
            })?;
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

    #[test]
    fn decode_app_frame_from_buffer() {
        let mut frame = encode_tcp_app_data(b"hello").unwrap();
        match try_decode_app(&mut frame).unwrap() {
            Decode::App(payload) => assert_eq!(payload, b"hello"),
            other => panic!("expected app, got {other:?}"),
        }
    }

    #[test]
    fn decode_close_frame() {
        let mut frame = encode_tcp_close().to_vec();
        assert!(matches!(try_decode_app(&mut frame).unwrap(), Decode::Closed));
    }
}
