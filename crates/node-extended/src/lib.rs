//! Authenticated protocol codecs. Policy and payload accounting belong to `Host`.
//! TLS/REALITY is supplied by the caller; this crate does not create listeners.
mod address;
pub mod anytls;
#[allow(dead_code)]
mod async_stream;
mod auth;
mod budget;
mod channel;
pub mod grpc;
pub mod http2;
pub mod httpupgrade;
mod io_adapter;
pub mod mux;
pub mod sip003;
mod util;
pub mod vmess;
pub mod websocket;

pub use auth::{AuthenticationCache, MAX_ANYTLS_USERS, MAX_VMESS_USERS};
pub use budget::SharedBudget;
use node_session::{BoxStream, Host};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Vmess,
    AnyTls,
}

#[derive(Clone)]
pub struct Config {
    pub handshake_timeout: Duration,
    pub max_frame: usize,
    pub max_sessions: usize,
    pub max_queued_bytes: usize,
    /// Controls optional Sing/XUDP/plugin multiplex carriers; ordinary TCP/UDP
    /// protocol handshakes remain available when this is false.
    pub multiplex_enabled: bool,
    pub vmess_security: vmess::Security,
    pub anytls_padding: Arc<anytls::anytls_padding::PaddingFactory>,
    /// Clone one listener's config for all admissions so replay protection is shared.
    pub vmess_replay: Arc<vmess::ReplayCache>,
    /// Retains only the current Host snapshot; cloned listener configs share derived keys.
    pub authentication: Arc<AuthenticationCache>,
    /// Listener-wide payload queue and logical-session permits. Clone this config
    /// for every connection, including VLESS carriers handled outside this crate.
    pub shared_budget: Arc<SharedBudget>,
    pub xudp_sessions: Arc<mux::xudp::GlobalSessions>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            max_frame: 65535,
            max_sessions: 1024,
            max_queued_bytes: 8 * 1024 * 1024,
            multiplex_enabled: true,
            vmess_security: vmess::Security::Any,
            anytls_padding: anytls::anytls_padding::PaddingFactory::default_factory(),
            vmess_replay: Arc::new(vmess::ReplayCache::default()),
            authentication: Arc::new(AuthenticationCache::default()),
            shared_budget: Arc::new(SharedBudget::default()),
            xudp_sessions: Arc::new(mux::xudp::GlobalSessions::default()),
        }
    }
}
impl Config {
    pub(crate) fn require_multiplex(&self) -> io::Result<()> {
        if self.multiplex_enabled {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "multiplexing is disabled for this listener",
            ))
        }
    }
    /// Validate the node's user snapshot before starting a listener. Admissions repeat
    /// this check when Host supplies a different Arc after a hot update.
    pub fn validate_users(
        &self,
        protocol: Protocol,
        users: &[node_session::User],
    ) -> io::Result<()> {
        auth::validate_users(protocol, users)
    }
    /// Optionally derive the current Host snapshot during listener construction
    /// or a hot update instead of making the first handshake perform that work.
    pub fn prepare_users(
        &self,
        protocol: Protocol,
        users: Arc<[node_session::User]>,
    ) -> io::Result<()> {
        match protocol {
            Protocol::Vmess => {
                self.authentication.vmess(users)?;
            }
            Protocol::AnyTls => {
                self.authentication.anytls(users)?;
            }
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.handshake_timeout.is_zero()
            || self.handshake_timeout > Duration::from_secs(10)
            || self.max_frame == 0
            || self.max_frame > 65535
            || self.max_sessions == 0
            || self.max_sessions > 1024
            || self.max_queued_bytes < self.max_frame
            || self.max_queued_bytes > 8 * 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protocol limits exceed supported bounds",
            ));
        }
        self.shared_budget
            .bind(self.max_queued_bytes, self.max_sessions)?;
        Ok(())
    }
}

pub async fn serve(
    protocol: Protocol,
    config: Config,
    stream: BoxStream,
    peer: SocketAddr,
    host: Arc<dyn Host>,
    cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    config.validate()?;
    match protocol {
        Protocol::Vmess => vmess::serve(stream, peer, host, config, cancel).await,
        Protocol::AnyTls => anytls::serve(stream, peer, host, config, cancel).await,
    }
}

pub(crate) async fn cancelled(cancel: &mut Option<watch::Receiver<bool>>) {
    match cancel {
        None => std::future::pending::<()>().await,
        Some(rx) => loop {
            if *rx.borrow() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        },
    }
}
pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(crate) struct SessionContext {
    pub user: node_session::User,
    pub peer: SocketAddr,
    pub host: Arc<dyn Host>,
    pub config: Config,
}
