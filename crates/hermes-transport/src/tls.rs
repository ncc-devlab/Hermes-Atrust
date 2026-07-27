use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::http::TlsPolicy;

/// Outcome of a TLS-only node smoke probe (no application bytes written).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeTlsProbeResult {
    pub host: String,
    pub port: u16,
    pub outcome: NodeTlsProbeOutcome,
    pub elapsed: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeTlsProbeOutcome {
    Ok,
    TcpConnectFailed,
    TlsHandshakeFailed,
    Timeout,
    InvalidServerName,
}

impl NodeTlsProbeResult {
    pub fn success(&self) -> bool {
        self.outcome == NodeTlsProbeOutcome::Ok
    }
}

/// Probes `host:port` with TCP + TLS only. Never sends aTrust init frames.
pub async fn probe_node_tls(
    host: &str,
    port: u16,
    tls_policy: TlsPolicy,
    connect_timeout: Duration,
) -> NodeTlsProbeResult {
    let started = Instant::now();
    let server_name = match ServerName::try_from(host.to_owned()) {
        Ok(name) => name,
        Err(_) => {
            return NodeTlsProbeResult {
                host: host.to_owned(),
                port,
                outcome: NodeTlsProbeOutcome::InvalidServerName,
                elapsed: started.elapsed(),
            };
        }
    };

    let outcome = match timeout(
        connect_timeout,
        probe_once(host, port, tls_policy, server_name),
    )
    .await
    {
        Ok(Ok(())) => NodeTlsProbeOutcome::Ok,
        Ok(Err(ProbeStepError::Tcp)) => NodeTlsProbeOutcome::TcpConnectFailed,
        Ok(Err(ProbeStepError::Tls)) => NodeTlsProbeOutcome::TlsHandshakeFailed,
        Err(_) => NodeTlsProbeOutcome::Timeout,
    };

    let result = NodeTlsProbeResult {
        host: host.to_owned(),
        port,
        outcome,
        elapsed: started.elapsed(),
    };
    debug!(
        event = "transport.node_tls_probe",
        host = %result.host,
        port = result.port,
        outcome = ?result.outcome,
        elapsed_ms = result.elapsed.as_millis()
    );
    result
}

enum ProbeStepError {
    Tcp,
    Tls,
}

async fn probe_once(
    host: &str,
    port: u16,
    tls_policy: TlsPolicy,
    server_name: ServerName<'static>,
) -> Result<(), ProbeStepError> {
    let addr = resolve_first(host, port)
        .await
        .map_err(|_| ProbeStepError::Tcp)?;
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|_| ProbeStepError::Tcp)?;
    let connector = TlsConnector::from(Arc::new(client_config(tls_policy)));
    let _tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|_| ProbeStepError::Tls)?;
    // Drop immediately: smoke only, no application data.
    Ok(())
}

async fn resolve_first(host: &str, port: u16) -> Result<SocketAddr, std::io::Error> {
    if let Ok(ip) = host.parse() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses"))
}

fn client_config(policy: TlsPolicy) -> ClientConfig {
    match policy {
        TlsPolicy::Verify => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        TlsPolicy::DangerousAcceptInvalidCertificates => ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth(),
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug, Error)]
pub enum TlsTransportError {
    #[error("invalid TLS probe configuration: {0}")]
    InvalidConfiguration(&'static str),
}

impl fmt::Display for NodeTlsProbeOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => formatter.write_str("ok"),
            Self::TcpConnectFailed => formatter.write_str("tcp_connect_failed"),
            Self::TlsHandshakeFailed => formatter.write_str("tls_handshake_failed"),
            Self::Timeout => formatter.write_str("timeout"),
            Self::InvalidServerName => formatter.write_str("invalid_server_name"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn localhost_closed_port_is_tcp_failure_or_timeout() {
        let result = probe_node_tls(
            "127.0.0.1",
            1,
            TlsPolicy::Verify,
            Duration::from_millis(300),
        )
        .await;
        assert!(!result.success());
        assert!(matches!(
            result.outcome,
            NodeTlsProbeOutcome::TcpConnectFailed | NodeTlsProbeOutcome::Timeout
        ));
    }

    #[tokio::test]
    async fn invalid_server_name_is_reported() {
        let result = probe_node_tls("", 441, TlsPolicy::Verify, Duration::from_millis(100)).await;
        assert_eq!(result.outcome, NodeTlsProbeOutcome::InvalidServerName);
    }
}
