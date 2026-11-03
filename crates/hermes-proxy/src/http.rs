use atrust_net::ProxyConnector;
use base64::Engine;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use url::Url;

use crate::{ProxyConfig, connect, invalid};

async fn header(stream: &mut BufReader<TcpStream>) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0];
    while bytes.len() < 32768 {
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|_| invalid("HTTP header is not UTF-8"));
        }
    }
    Err(invalid("HTTP header exceeds 32 KiB"))
}

pub(super) async fn serve(
    stream: TcpStream,
    connector: Arc<dyn ProxyConnector>,
    config: ProxyConfig,
) -> io::Result<()> {
    let mut stream = BufReader::new(stream);
    let header = tokio::time::timeout(config.handshake_timeout, header(&mut stream))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let mut lines = header.split("\r\n");
    let request = lines
        .next()
        .ok_or_else(|| invalid("missing HTTP request line"))?
        .split(' ')
        .collect::<Vec<_>>();
    if request.len() != 3
        || !["HTTP/1.0", "HTTP/1.1"].contains(&request[2])
        || request[0].is_empty()
        || !request[0]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'-')
    {
        return Err(invalid("invalid HTTP request line"));
    }
    let mut headers = Vec::new();
    let mut authorization = None;
    let mut length = None;
    let mut chunked = false;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid HTTP header"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127)
        {
            return Err(invalid("invalid HTTP header"));
        }
        if name.eq_ignore_ascii_case("proxy-authorization") {
            if authorization.replace(value.trim()).is_some() {
                return Err(invalid("duplicate proxy authorization"));
            }
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length
                .replace(
                    value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| invalid("invalid content length"))?,
                )
                .is_some()
            {
                return Err(invalid("duplicate content length"));
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = true;
        }
        headers.push((name, value));
    }
    if chunked && length.is_some() {
        return Err(invalid("ambiguous HTTP body framing"));
    }
    if let Some(credentials) = config.credentials {
        let expected = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", credentials.username, credentials.password));
        if authorization != Some(format!("Basic {expected}").as_str()) {
            stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Hermes\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(());
        }
    }
    let tunnel = request[0] == "CONNECT";
    let url = Url::parse(&if tunnel {
        format!("http://{}", request[1])
    } else {
        request[1].to_owned()
    })
    .map_err(|_| invalid("invalid HTTP target"))?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (tunnel && (url.path() != "/" || url.query().is_some()))
    {
        return Err(invalid("unsupported HTTP target"));
    }
    let host = url.host_str().ok_or_else(|| invalid("missing HTTP host"))?;
    let port = if tunnel {
        request[1]
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
    } else {
        url.port_or_known_default()
    }
    .filter(|port| *port != 0)
    .ok_or_else(|| invalid("missing HTTP port"))?;
    let mut target = match connect(connector.as_ref(), host, port, config.connect_timeout).await {
        Ok(target) => target,
        Err(error) => {
            let status = if error.kind() == io::ErrorKind::PermissionDenied {
                "403 Forbidden"
            } else {
                "502 Bad Gateway"
            };
            stream
                .write_all(
                    format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            return Ok(());
        }
    };
    if tunnel {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        let path = format!(
            "{}{}",
            url.path(),
            url.query().map(|q| format!("?{q}")).unwrap_or_default()
        );
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        let mut rewritten = format!(
            "{} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n",
            request[0]
        );
        for (name, value) in headers {
            if ![
                "host",
                "connection",
                "proxy-connection",
                "proxy-authorization",
            ]
            .iter()
            .any(|ignored| name.eq_ignore_ascii_case(ignored))
            {
                rewritten.push_str(name);
                rewritten.push(':');
                rewritten.push_str(value);
                rewritten.push_str("\r\n");
            }
        }
        rewritten.push_str("\r\n");
        target.write_all(rewritten.as_bytes()).await?;
    }
    tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
    Ok(())
}
