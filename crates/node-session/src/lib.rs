//! Protocol-independent authenticated payload boundary.
//! Host implementations own policy, routing and durable accounting; codecs own framing.
use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

#[derive(Clone, PartialEq, Eq)]
pub struct User {
    pub name: Arc<str>,
    pub uuid: Option<[u8; 16]>,
    pub password: Option<Arc<str>>,
}
// Authentication material is deliberately not Debug.

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}
impl Destination {
    pub fn new(host: impl Into<String>, port: u16) -> io::Result<Self> {
        let host = host.into();
        if host.is_empty() || host.len() > 253 || host.chars().any(char::is_control) || port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid destination",
            ));
        }
        Ok(Self { host, port })
    }
}

#[async_trait]
pub trait Datagram: Send + Sync {
    /// Sends payload only; the host applies the current route and shared user budget.
    async fn send(&self, payload: &[u8], target: &Destination) -> io::Result<usize>;
    /// Receives only from previously admitted targets, preserving message boundaries.
    async fn receive(&self, buffer: &mut [u8]) -> io::Result<(usize, Destination)>;
}

#[async_trait]
pub trait Host: Send + Sync {
    /// An immutable snapshot. Codecs authenticate against it, then the host
    /// rechecks exact identity at admission to reject revoked delayed handshakes.
    fn users(&self) -> Arc<[User]>;
    /// Returned stream holds the source-IP lease and accounts/rate-limits payload.
    async fn connect(
        &self,
        user: &User,
        peer: SocketAddr,
        target: &Destination,
    ) -> io::Result<BoxStream>;
    /// Returned channel holds the source-IP lease and bounded association/peer state.
    async fn datagram(&self, user: &User, peer: SocketAddr) -> io::Result<Arc<dyn Datagram>>;
}

pub async fn relay(mut client: BoxStream, mut remote: BoxStream) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let result = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    let _ = client.shutdown().await;
    let _ = remote.shutdown().await;
    result.map(|_| ())
}
