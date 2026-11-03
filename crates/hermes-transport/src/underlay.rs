//! Physical-network dialing, independent of tunnel routes. Hosts may inject
//! their own resolver/interface selection by implementing `UnderlayDialer`.
use std::fmt::Debug;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::{TcpSocket, TcpStream};

#[async_trait]
pub trait UnderlayDialer: Debug + Send + Sync {
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnderlayOptions {
    pub local_address: Option<IpAddr>,
    /// Native interface binding is currently available on Linux/Android.
    /// Unsupported platforms return an error rather than ignoring the binding.
    pub interface: Option<String>,
}

#[derive(Debug, Default)]
pub struct SystemUnderlay {
    options: RwLock<UnderlayOptions>,
}

impl SystemUnderlay {
    pub fn new(options: UnderlayOptions) -> Self {
        Self {
            options: RwLock::new(options),
        }
    }

    /// Hosts call this after an egress change; the next connection takes one
    /// consistent snapshot. Existing sockets retain their original binding.
    pub fn update(&self, options: UnderlayOptions) {
        *self.options.write().expect("underlay options lock") = options;
    }
}

#[async_trait]
impl UnderlayDialer for SystemUnderlay {
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let options = self.options.read().expect("underlay options lock").clone();
        let addresses: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
        let mut error = io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no matching underlay address",
        );
        for address in addresses {
            if options
                .local_address
                .is_some_and(|ip| ip.is_ipv4() != address.is_ipv4())
            {
                continue;
            }
            let socket = if address.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            if let Some(interface) = &options.interface {
                #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
                socket.bind_device(Some(interface.as_bytes()))?;
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "fuchsia"
                )))]
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("native underlay interface binding unavailable: {interface}"),
                ));
            }
            if let Some(ip) = options.local_address {
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            match tokio::time::timeout(Duration::from_secs(3), socket.connect(address)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(failure)) => error = failure,
                Err(_) => {
                    error = io::Error::new(io::ErrorKind::TimedOut, "underlay address timed out")
                }
            }
        }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn binding_and_updates_apply_to_the_next_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dialer = SystemUnderlay::new(UnderlayOptions {
            local_address: Some("127.0.0.1".parse().unwrap()),
            interface: None,
        });
        let stream = dialer.connect("127.0.0.1", port).await.unwrap();
        assert_eq!(stream.local_addr().unwrap().ip().to_string(), "127.0.0.1");
        dialer.update(UnderlayOptions {
            local_address: Some("::1".parse().unwrap()),
            interface: None,
        });
        assert_eq!(
            dialer.connect("127.0.0.1", port).await.unwrap_err().kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }
}
