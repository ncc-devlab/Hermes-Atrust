use std::pin::Pin;
use std::task::{Context, Poll};

use atrust_protocol::{encode_tcp_app_data, encode_tcp_close, encode_tcp_probe, is_status_ok};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tracing::debug;

/// Trailer that makes an `01 01` frame the server closing the tunnel, as
/// distinct from the `01 01 00 00` this side sends.
const SERVER_CLOSE_TRAILER: [u8; 2] = [0x30, 0x30];

/// Framed TCP tunnel after a successful handshake.
///
/// Application frames validated by the interoperability fixtures:
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
        self.closed = true;
        let mut first_error = self.stream.write_all(&encode_tcp_close()).await.err();
        if let Err(error) = self.stream.flush().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.stream.shutdown().await {
            first_error.get_or_insert(error);
        }
        debug!(event = "atrust_tcp.tunnel.closed");
        first_error.map_or(Ok(()), |error| Err(error.into()))
    }

    /// Writes application data, splitting it into complete wire frames as needed.
    pub async fn write_app(&mut self, payload: &[u8]) -> Result<(), TunnelError> {
        if self.closed {
            return Err(TunnelError::Closed);
        }
        self.write_all(payload).await?;
        self.flush().await?;
        Ok(())
    }

    /// Reads the next complete application-data frame payload.
    pub async fn read_app(&mut self) -> Result<Option<Vec<u8>>, TunnelError> {
        if self.closed {
            return Ok(None);
        }
        loop {
            match try_decode_app(&mut self.read_buf)? {
                Decode::App(payload) if payload.is_empty() => continue,
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
        if read_buf.len().saturating_sub(skipped) < 2 {
            return Ok(Decode::NeedMore);
        }
        let h0 = read_buf[skipped];
        let h1 = read_buf[skipped + 1];

        // Application data: 01 00 | u16be | payload
        if h0 == 0x01 && h1 == 0x00 {
            if read_buf.len() < skipped + 4 {
                return Ok(Decode::NeedMore);
            }
            let len = u16::from_be_bytes([read_buf[skipped + 2], read_buf[skipped + 3]]) as usize;
            if read_buf.len() < skipped + 4 + len {
                return Ok(Decode::NeedMore);
            }
            let payload = read_buf[skipped + 4..skipped + 4 + len].to_vec();
            read_buf.drain(..skipped + 4 + len);
            return Ok(Decode::App(payload));
        }

        // `01 01` carries a two-byte trailer, and only the ASCII "00" trailer is
        // the server closing the tunnel. Other trailers are consumed while the
        // stream keeps reading, and the node does send `01 01 00 00`
        // ahead of the first response: treating that as EOF ends the stream just
        // before the target's data arrives.
        if h0 == 0x01 && h1 == 0x01 {
            if read_buf.len() < skipped + 4 {
                return Ok(Decode::NeedMore);
            }
            let trailer = [read_buf[skipped + 2], read_buf[skipped + 3]];
            read_buf.drain(..skipped + 4);
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
            skipped = 0;
            continue;
        }

        // `05 81` is node chatter with no body. The handshake already skips it;
        // it can also appear once the data phase has started.
        if h0 == 0x05 && h1 == 0x81 {
            debug!(event = "atrust_tcp.tunnel.node_chatter");
            read_buf.drain(..skipped + 2);
            skipped = 0;
            continue;
        }

        // Protocol chatter during data phase: 53 00 | len | body
        if h0 == 0x53 && h1 == 0x00 {
            if read_buf.len() < skipped + 4 {
                return Ok(Decode::NeedMore);
            }
            let len = u16::from_be_bytes([read_buf[skipped + 2], read_buf[skipped + 3]]) as usize;
            if read_buf.len() < skipped + 4 + len {
                return Ok(Decode::NeedMore);
            }
            let body = read_buf[skipped + 4..skipped + 4 + len].to_vec();
            read_buf.drain(..skipped + 4 + len);
            if !is_status_ok(&body) {
                return Err(TunnelError::ProtocolError {
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
            }
            skipped = 0;
            continue;
        }

        // The node emits a run of padding after the connect status. An
        // unrecognised two-byte header is consumed and the loop continues;
        // rejecting it ended the tunnel on the node's first response. The bound
        // keeps a genuine
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
                Poll::Ready(Ok(0)) => {
                    self.write_pending.clear();
                    self.closed = true;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_offset += n,
                Poll::Ready(Err(error)) => {
                    self.write_pending.clear();
                    self.closed = true;
                    return Poll::Ready(Err(error));
                }
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
    use std::collections::VecDeque;
    use std::io;
    use tokio::time::{Duration, timeout};

    #[derive(Default)]
    struct ScriptedIo {
        read_chunks: VecDeque<Vec<u8>>,
        max_write: usize,
        pending_every: Option<usize>,
        read_polls: usize,
        write_polls: usize,
        read_pending: bool,
        write_pending: bool,
        fail_write_after: Option<usize>,
        fail_flush: bool,
        fail_shutdown: bool,
        written: Vec<u8>,
    }

    impl ScriptedIo {
        fn with_reads(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                read_chunks: chunks.into_iter().collect(),
                max_write: usize::MAX,
                ..Self::default()
            }
        }

        fn writer(max_write: usize, pending_every: Option<usize>) -> Self {
            Self {
                max_write,
                pending_every,
                ..Self::default()
            }
        }
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.read_polls += 1;
            if self
                .pending_every
                .is_some_and(|every| self.read_polls % every == 0)
                && !self.read_pending
            {
                self.read_pending = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.read_pending = false;
            let Some(mut chunk) = self.read_chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            let n = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..n]);
            if n < chunk.len() {
                chunk.drain(..n);
                self.read_chunks.push_front(chunk);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_polls += 1;
            if self
                .pending_every
                .is_some_and(|every| self.write_polls % every == 0)
                && !self.write_pending
            {
                self.write_pending = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.write_pending = false;
            if self
                .fail_write_after
                .is_some_and(|limit| self.written.len() >= limit)
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "injected write failure",
                )));
            }
            let before_failure = self
                .fail_write_after
                .map_or(usize::MAX, |limit| limit - self.written.len());
            let n = buf.len().min(self.max_write).min(before_failure);
            if n == 0 && !buf.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "injected write failure",
                )));
            }
            self.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.fail_flush {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected flush failure",
                )))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.fail_shutdown {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "injected shutdown failure",
                )))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    fn decode_written_frames(wire: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < wire.len() {
            assert_eq!(&wire[offset..offset + 2], &[0x01, 0x00]);
            let len = u16::from_be_bytes([wire[offset + 2], wire[offset + 3]]) as usize;
            let end = offset + 4 + len;
            assert!(end <= wire.len(), "incomplete frame at {offset}");
            frames.push(wire[offset + 4..end].to_vec());
            offset = end;
        }
        frames
    }

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

    #[test]
    fn v1_a_decoder_exhaustive_single_splits_and_sentinel() {
        let sentinel = encode_tcp_app_data(b"end").unwrap();
        let fixtures = [
            (
                "app0",
                vec![0x01, 0x00, 0x00, 0x00],
                Some(Vec::new()),
                false,
            ),
            (
                "app1",
                vec![0x01, 0x00, 0x00, 0x01, b'A'],
                Some(b"A".to_vec()),
                false,
            ),
            (
                "control-payload",
                vec![
                    0x01, 0x00, 0x00, 0x08, 0x01, 0x01, 0x01, 0x00, 0x05, 0x81, 0x53, 0x00,
                ],
                Some(vec![0x01, 0x01, 0x01, 0x00, 0x05, 0x81, 0x53, 0x00]),
                false,
            ),
            ("marker", vec![0x01, 0x01, 0x00, 0x00], None, false),
            ("close", vec![0x01, 0x01, 0x30, 0x30], None, true),
            ("chatter", vec![0x05, 0x81], None, false),
            (
                "status",
                vec![0x53, 0x00, 0x00, 0x02, b'O', b'K'],
                None,
                false,
            ),
        ];

        for (name, fixture, expected, closes) in fixtures {
            for cut in 0..=fixture.len() {
                let mut buffered = fixture[..cut].to_vec();
                let first = try_decode_app(&mut buffered).unwrap();
                if cut < fixture.len() {
                    assert!(matches!(first, Decode::NeedMore), "{name} cut {cut}");
                }
                buffered.extend_from_slice(&fixture[cut..]);
                buffered.extend_from_slice(&sentinel);

                let candidate = if cut == fixture.len() {
                    first
                } else {
                    try_decode_app(&mut buffered).unwrap()
                };
                if closes {
                    assert!(matches!(candidate, Decode::Closed), "{name} cut {cut}");
                    continue;
                }
                if let Some(expected) = &expected {
                    assert!(
                        matches!(candidate, Decode::App(ref payload) if payload == expected),
                        "{name} cut {cut}: {candidate:?}"
                    );
                    match try_decode_app(&mut buffered).unwrap() {
                        Decode::App(payload) => assert_eq!(payload, b"end", "{name} cut {cut}"),
                        other => panic!("{name} cut {cut}: expected sentinel, got {other:?}"),
                    }
                } else {
                    match candidate {
                        Decode::App(payload) => assert_eq!(payload, b"end", "{name} cut {cut}"),
                        Decode::NeedMore => match try_decode_app(&mut buffered).unwrap() {
                            Decode::App(payload) => assert_eq!(payload, b"end", "{name} cut {cut}"),
                            other => panic!("{name} cut {cut}: expected sentinel, got {other:?}"),
                        },
                        other => panic!("{name} cut {cut}: expected sentinel, got {other:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn v1_a_decoder_exhaustive_double_splits() {
        let fixtures = [
            vec![
                0x01, 0x00, 0x00, 0x08, 0x01, 0x01, 0x01, 0x00, 0x05, 0x81, 0x53, 0x00,
            ],
            vec![0x53, 0x00, 0x00, 0x02, b'O', b'K'],
        ];
        let sentinel = encode_tcp_app_data(b"end").unwrap();
        for fixture in fixtures {
            for first in 0..fixture.len() {
                for second in first..=fixture.len() {
                    let mut buffered = fixture[..first].to_vec();
                    assert!(matches!(
                        try_decode_app(&mut buffered).unwrap(),
                        Decode::NeedMore
                    ));
                    buffered.extend_from_slice(&fixture[first..second]);
                    let middle = try_decode_app(&mut buffered).unwrap();
                    if second < fixture.len() {
                        assert!(matches!(middle, Decode::NeedMore));
                    }
                    buffered.extend_from_slice(&fixture[second..]);
                    buffered.extend_from_slice(&sentinel);
                    let mut payloads = Vec::new();
                    if let Decode::App(payload) = middle {
                        payloads.push(payload);
                    }
                    loop {
                        match try_decode_app(&mut buffered).unwrap() {
                            Decode::App(payload) => {
                                let done = payload == b"end";
                                payloads.push(payload);
                                if done {
                                    break;
                                }
                            }
                            Decode::NeedMore => panic!("missing sentinel at cuts {first}/{second}"),
                            Decode::Closed => panic!("unexpected close at cuts {first}/{second}"),
                        }
                    }
                    assert_eq!(payloads.last().unwrap(), b"end");
                }
            }
        }
    }

    #[test]
    fn v1_a_chatter_limit_is_preserved_across_reads() {
        let sentinel = encode_tcp_app_data(b"end").unwrap();
        let mut at_limit = vec![0xab; MAX_SKIPPED_CHATTER_BYTES];
        assert!(matches!(
            try_decode_app(&mut at_limit).unwrap(),
            Decode::NeedMore
        ));
        at_limit.extend_from_slice(&sentinel);
        assert!(matches!(
            try_decode_app(&mut at_limit).unwrap(),
            Decode::App(payload) if payload == b"end"
        ));

        for excess in [1, 2] {
            let mut wire = vec![0xab; MAX_SKIPPED_CHATTER_BYTES + excess];
            wire.extend_from_slice(&sentinel);
            assert!(matches!(
                try_decode_app(&mut wire),
                Err(TunnelError::UnexpectedFrame { .. })
            ));
        }
    }

    #[tokio::test]
    async fn v1_b_async_read_schedules_preserve_application_bytes() {
        let app1 = encode_tcp_app_data(b"A").unwrap();
        let end = encode_tcp_app_data(b"end").unwrap();
        let mut baseline = app1.clone();
        baseline.extend_from_slice(&end);
        let one_byte = baseline.iter().map(|byte| vec![*byte]).collect::<Vec<_>>();

        for chunks in [vec![baseline.clone()], one_byte] {
            let mut tunnel = TcpTunnel::from_stream(ScriptedIo::with_reads(chunks));
            let mut output = Vec::new();
            timeout(Duration::from_secs(2), tunnel.read_to_end(&mut output))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(output, b"Aend");
        }

        let mut pending_io =
            ScriptedIo::with_reads(baseline.iter().map(|byte| vec![*byte]).collect::<Vec<_>>());
        pending_io.pending_every = Some(2);
        let mut tunnel = TcpTunnel::from_stream(pending_io);
        let mut output = Vec::new();
        timeout(Duration::from_secs(2), tunnel.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output, b"Aend");

        let mut tunnel = TcpTunnel::from_stream(ScriptedIo::with_reads([baseline.clone()]));
        let mut output = [0_u8; 4];
        for byte in &mut output {
            tunnel.read_exact(std::slice::from_mut(byte)).await.unwrap();
        }
        assert_eq!(&output, b"Aend");

        for prefix in [
            vec![0x01, 0x01, 0x00, 0x00],
            vec![0x01, 0x00, 0x00, 0x00],
            vec![0x05, 0x81, 0x53, 0x00, 0x00, 0x02, b'O', b'K'],
        ] {
            let mut wire = prefix;
            wire.extend_from_slice(&app1);
            let mut tunnel = TcpTunnel::from_stream(ScriptedIo::with_reads([wire]));
            let mut output = [0_u8; 1];
            tunnel.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"A");
        }

        let mut closed_wire = vec![0x01, 0x01, 0x30, 0x30];
        closed_wire.extend_from_slice(&app1);
        let mut tunnel = TcpTunnel::from_stream(ScriptedIo::with_reads([closed_wire]));
        let mut output = Vec::new();
        tunnel.read_to_end(&mut output).await.unwrap();
        assert!(output.is_empty());

        let mut tunnel = TcpTunnel::from_stream(ScriptedIo::with_reads([baseline]));
        let mut output = Vec::new();
        tunnel.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"Aend");
    }

    #[tokio::test]
    async fn v1_b_read_app_skips_control_frames_and_probe() {
        let mut wire = vec![0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        wire.extend_from_slice(&[0x05, 0x81, 0x53, 0x00, 0x00, 0x02, b'O', b'K']);
        wire.extend_from_slice(&encode_tcp_app_data(b"A").unwrap());
        wire.extend_from_slice(&encode_tcp_app_data(b"end").unwrap());
        let mut tunnel = TcpTunnel::from_stream(ScriptedIo::with_reads(
            wire.into_iter().map(|byte| vec![byte]),
        ));
        assert_eq!(tunnel.read_app().await.unwrap().unwrap(), b"A");
        assert_eq!(tunnel.read_app().await.unwrap().unwrap(), b"end");
        assert!(tunnel.read_app().await.unwrap().is_none());

        let mut wire = vec![0x01, 0x01, 0x30, 0x30];
        wire.extend_from_slice(&encode_tcp_app_data(b"hidden").unwrap());
        let mut tunnel = TcpTunnel::from_stream(ScriptedIo::with_reads([wire]));
        assert!(tunnel.read_app().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn v1_c_async_write_splits_large_payloads_under_short_writes_and_pending() {
        for len in [0, 1, 65_535, 65_536, 131_071] {
            let payload = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            for max_write in [1, 2, 3, 4096] {
                for pending_every in [None, Some(2)] {
                    let mut tunnel =
                        TcpTunnel::from_stream(ScriptedIo::writer(max_write, pending_every));
                    timeout(Duration::from_secs(2), tunnel.write_all(&payload))
                        .await
                        .unwrap()
                        .unwrap();
                    let frames = decode_written_frames(&tunnel.stream.written);
                    let lengths = frames.iter().map(Vec::len).collect::<Vec<_>>();
                    let expected_lengths = match len {
                        0 => vec![],
                        1 => vec![1],
                        65_535 => vec![65_535],
                        65_536 => vec![65_535, 1],
                        131_071 => vec![65_535, 65_535, 1],
                        _ => unreachable!(),
                    };
                    assert_eq!(lengths, expected_lengths);
                    assert_eq!(frames.concat(), payload);
                }
            }
        }
    }

    #[tokio::test]
    async fn v1_c_poll_write_accepts_at_most_one_frame() {
        let payload = vec![0x5a; 65_536];
        let mut tunnel = TcpTunnel::from_stream(ScriptedIo::writer(2, Some(2)));
        let accepted = timeout(Duration::from_secs(2), tunnel.write(&payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted, 65_535);
        assert_eq!(
            decode_written_frames(&tunnel.stream.written),
            [payload[..accepted].to_vec()]
        );
        assert_eq!(tunnel.write(&payload[accepted..]).await.unwrap(), 1);
        assert_eq!(
            decode_written_frames(&tunnel.stream.written).concat(),
            payload
        );
    }

    #[tokio::test]
    async fn v1_c_write_app_automatically_fragments() {
        let payload = (0..131_071).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let mut tunnel = TcpTunnel::from_stream(ScriptedIo::writer(3, Some(2)));
        timeout(Duration::from_secs(2), tunnel.write_app(&payload))
            .await
            .unwrap()
            .unwrap();
        let frames = decode_written_frames(&tunnel.stream.written);
        assert_eq!(
            frames.iter().map(Vec::len).collect::<Vec<_>>(),
            [65_535, 65_535, 1]
        );
        assert_eq!(frames.concat(), payload);
    }

    #[tokio::test]
    async fn v1_e_close_returns_first_error_and_is_idempotent() {
        for limit in [0, 1, 3] {
            let mut io = ScriptedIo::writer(usize::MAX, None);
            io.fail_write_after = Some(limit);
            let mut tunnel = TcpTunnel::from_stream(io);
            assert!(matches!(
                tunnel.close().await,
                Err(TunnelError::Io(ref error)) if error.kind() == io::ErrorKind::ConnectionReset
            ));
            assert_eq!(tunnel.stream.written.len(), limit);
            tunnel.close().await.unwrap();
            assert_eq!(tunnel.stream.written.len(), limit);
        }

        let mut io = ScriptedIo::writer(usize::MAX, None);
        io.fail_flush = true;
        io.fail_shutdown = true;
        let mut tunnel = TcpTunnel::from_stream(io);
        assert!(matches!(
            tunnel.close().await,
            Err(TunnelError::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
        assert_eq!(tunnel.stream.written, encode_tcp_close());
        tunnel.close().await.unwrap();

        let mut io = ScriptedIo::writer(usize::MAX, None);
        io.fail_shutdown = true;
        let mut tunnel = TcpTunnel::from_stream(io);
        assert!(matches!(
            tunnel.close().await,
            Err(TunnelError::Io(ref error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        tunnel.close().await.unwrap();
    }

    #[tokio::test]
    async fn v1_e_poll_shutdown_propagates_write_and_shutdown_errors() {
        let mut io = ScriptedIo::writer(usize::MAX, None);
        io.fail_write_after = Some(1);
        let mut tunnel = TcpTunnel::from_stream(io);
        let error = tunnel.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(tunnel.stream.written.len(), 1);

        let mut io = ScriptedIo::writer(usize::MAX, None);
        io.fail_shutdown = true;
        let mut tunnel = TcpTunnel::from_stream(io);
        let error = tunnel.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(tunnel.stream.written, encode_tcp_close());
    }
}
