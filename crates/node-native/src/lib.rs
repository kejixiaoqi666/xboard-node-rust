//! Rust-native TCP data plane, embedded in the controller's own executable.
pub mod auth;
pub mod config;
#[cfg(unix)]
mod control;
pub mod limits;
#[cfg(any(unix, test))]
mod network;
pub mod protocol;
#[cfg(any(unix, test))]
mod traffic;
#[cfg(any(unix, test))]
mod traffic_store;
#[cfg(any(unix, test))]
mod udp;

#[cfg(unix)]
use arc_swap::ArcSwap;
use std::path::PathBuf;
#[cfg(any(unix, test))]
use std::sync::Arc;
#[cfg(any(unix, test))]
use std::{net::SocketAddr, time::Duration};
use thiserror::Error;
#[cfg(any(unix, test))]
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::{net::TcpListener, task::JoinSet};
#[cfg(unix)]
use tokio_rustls::TlsAcceptor;
#[cfg(test)]
mod network_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_backpressure;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid Rust kernel configuration")]
    Config,
    #[error("unsupported Rust kernel feature")]
    Unsupported,
    #[error("user device limit reached")]
    Limited,
    #[error("destination blocked by routing policy")]
    Blocked,
    #[error("DNS resolution failed")]
    Dns,
    #[error("invalid or duplicate authentication data")]
    Auth,
    #[error("invalid TCP protocol request")]
    Protocol,
    #[error("invalid TLS certificate/key")]
    Tls,
    #[error("Rust kernel I/O failed")]
    Io(#[from] std::io::Error),
    #[error("Rust kernel task failed")]
    Task,
}

pub async fn run_cli(args: &[String]) -> Result<(), Error> {
    let check = args.first().is_some_and(|arg| arg == "check");
    if !check && args.first().is_none_or(|arg| arg != "run") {
        return Err(Error::Config);
    }
    let mut path = None;
    let mut socket = None;
    let mut traffic_enabled = None;
    let mut traffic_state = None;
    let mut traffic_destination = None;
    let mut checkpoint_ms = None;
    let (pairs, remainder) = args[1..].as_chunks::<2>();
    for pair in pairs {
        match pair[0].as_str() {
            "-c" if path.is_none() => path = Some(PathBuf::from(&pair[1])),
            "--control-socket" if socket.is_none() => socket = Some(PathBuf::from(&pair[1])),
            "--traffic-enabled" if traffic_enabled.is_none() => {
                traffic_enabled = Some(pair[1].parse::<bool>().map_err(|_| Error::Config)?)
            }
            "--traffic-state" if traffic_state.is_none() => {
                traffic_state = Some(PathBuf::from(&pair[1]))
            }
            "--traffic-destination" if traffic_destination.is_none() => {
                traffic_destination = Some(pair[1].clone())
            }
            "--traffic-checkpoint-ms" if checkpoint_ms.is_none() => {
                checkpoint_ms = Some(pair[1].parse::<u64>().map_err(|_| Error::Config)?)
            }
            _ => return Err(Error::Config),
        }
    }
    if !remainder.is_empty() {
        return Err(Error::Config);
    }
    let path = path.ok_or(Error::Config)?;
    let checkpoint_ms = checkpoint_ms.unwrap_or(1000);
    if !(50..=60000).contains(&checkpoint_ms)
        || traffic_state.is_some() != traffic_destination.is_some()
        || traffic_state
            .as_ref()
            .is_some_and(|s| Some(s.as_path()) != path.parent())
        || traffic_destination
            .as_ref()
            .is_some_and(|d| d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()))
        || traffic_state.is_some() && traffic_enabled == Some(false)
    {
        return Err(Error::Config);
    }
    let initial = config::read_candidate(&path)?;
    let tls = config::tls_config(initial.base.tls.as_ref())?;
    if check {
        return Ok(());
    }
    #[cfg(unix)]
    {
        serve(
            initial,
            tls,
            path,
            socket.ok_or(Error::Config)?,
            traffic_enabled.unwrap_or(true),
            traffic_state.zip(traffic_destination),
            Duration::from_millis(checkpoint_ms),
        )
        .await
    }
    #[cfg(not(unix))]
    {
        let _ = (
            initial,
            tls,
            path,
            socket,
            traffic_state,
            traffic_destination,
        );
        Err(Error::Unsupported)
    }
}

#[cfg(unix)]
async fn serve(
    initial: config::Candidate,
    tls: Option<Arc<rustls::ServerConfig>>,
    path: PathBuf,
    socket: PathBuf,
    traffic_enabled: bool,
    persistent: Option<(PathBuf, String)>,
    checkpoint_period: Duration,
) -> Result<(), Error> {
    let control = control::bind(&path, &socket)?;
    let network = Arc::new(network::Network::new(
        &initial.base.route,
        &initial.base.outbounds,
        initial.base.dns.as_ref(),
    )?);
    let mut listener =
        Some(TcpListener::bind(SocketAddr::new(initial.base.listen, initial.base.port)).await?);
    let protocol = initial.base.protocol;
    let users: auth::Users = Arc::new(ArcSwap::from(initial.auth.clone()));
    let control_users = Arc::clone(&users);
    let directory = path.parent().ok_or(Error::Config)?.to_path_buf();
    let durable = persistent.is_some();
    let traffic = Arc::new(match persistent {
        Some((directory, destination)) => traffic::Traffic::open(&directory, destination)?,
        None => traffic::Traffic::random(traffic_enabled)?,
    });
    let (quiesce_tx, mut quiesce_rx) = tokio::sync::watch::channel(false);
    let (quiesced_tx, quiesced_rx) = tokio::sync::watch::channel(0_u8);
    let mut checkpoint = tokio::time::interval(checkpoint_period);
    checkpoint.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut controller = tokio::spawn(control::serve(
        control,
        initial,
        control_users,
        directory,
        Arc::clone(&traffic),
        control::Quiesce {
            request: quiesce_tx,
            done: quiesced_rx,
        },
    ));
    let tls = tls.map(TlsAcceptor::from);
    let limits = Arc::new(limits::Registry::new(Arc::clone(&users)));
    let udp_slots = Arc::new(tokio::sync::Semaphore::new(1024));
    const MAX_CONNECTIONS: usize = 16384;
    let mut connections = JoinSet::new();
    let mut accept_after = tokio::time::Instant::now();
    let shutdown = shutdown();
    tokio::pin!(shutdown);
    let mut control_finished = false;
    let result = loop {
        // Finished tasks still occupy JoinSet entries until reaped. Bound both
        // active connections and those entries, with a bounded reap batch.
        for _ in 0..64 {
            if connections.try_join_next().is_none() {
                break;
            }
        }
        tokio::select! {
            _=&mut shutdown => break Ok(()),
            _=&mut controller => { control_finished=true; break Err(Error::Task); },
            changed=quiesce_rx.changed(), if listener.is_some() => {
                if changed.is_err() { break Err(Error::Task); }
                listener.take();
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                let persisted=match traffic.blocking(|t|t.checkpoint(true)).await { Ok(result)=>result,Err(_)=>break Err(Error::Task) };
                let _=quiesced_tx.send(if persisted.is_ok() {1} else {2});
                if let Err(error)=persisted { break Err(Error::Io(error)); }
            },
            _=checkpoint.tick(), if durable => {
                match traffic.blocking(|t|t.checkpoint(false)).await {
                    Ok(Ok(()))=>{}, Ok(Err(error))=>break Err(Error::Io(error)), Err(_)=>break Err(Error::Task),
                }
            },
            Some(_)=connections.join_next(),if !connections.is_empty() => {},
            accepted=async {
                tokio::time::sleep_until(accept_after).await;
                listener.as_ref().expect("enabled listener").accept().await
            }, if listener.is_some() && connections.len() < MAX_CONNECTIONS => {
                let (stream,source)=match accepted {
                    Ok(pair)=>pair,
                    Err(error)=> {
                        if let Some(delay)=accept_retry_delay(&error) {
                            accept_after=tokio::time::Instant::now()+delay;
                            continue;
                        }
                        break Err(Error::Io(error));
                    }
                };
                let users=Arc::clone(&users);
                let tls=tls.clone();
                let traffic=Arc::clone(&traffic);
                let limits=Arc::clone(&limits);
                let udp_slots=Arc::clone(&udp_slots);
                let network=Arc::clone(&network);
                connections.spawn(async move {
                    let _=stream.set_nodelay(true);
                    let context=ConnectionContext { users: &users, traffic: &traffic, source, limits: &limits, udp_slots: &udp_slots, network: &network };
                    if let Some(tls)=tls {
                        if let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(10),tls.accept(stream)).await {
                            let _=connection_routed(stream,protocol,context).await;
                        }
                    } else { let _=connection_routed(stream,protocol,context).await; }
                });
            }
        }
    };
    // Reap every copy before the final checkpoint; the successful barrier has
    // no remaining payload writer. Control is then stopped before process exit.
    listener.take();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let final_save = traffic.blocking(|t| t.checkpoint(true)).await;
    if !control_finished {
        controller.abort();
        let _ = controller.await;
    }
    final_save.map_err(|_| Error::Task)??;
    result
}

/// Bind a native checkpoint to the credential-free panel/node destination.
pub fn traffic_destination(identity: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(identity.as_bytes()))
}

#[cfg(any(unix, test))]
fn accept_retry_delay(error: &std::io::Error) -> Option<Duration> {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock
        | ErrorKind::TimedOut => return Some(Duration::from_millis(10)),
        ErrorKind::OutOfMemory => return Some(Duration::from_millis(100)),
        _ => {}
    }
    #[cfg(target_os = "linux")]
    if matches!(
        error.raw_os_error(),
        // ENFILE, EMFILE, ENONET, EPROTO, ENOPROTOOPT, EOPNOTSUPP,
        // ENETDOWN, ENETUNREACH, ENOBUFS, EHOSTDOWN, EHOSTUNREACH.
        Some(23 | 24 | 64 | 71 | 92 | 95 | 100 | 101 | 105 | 112 | 113)
    ) {
        return Some(Duration::from_millis(100));
    }
    None
}

#[cfg(test)]
async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    inbound: S,
    protocol: config::Protocol,
    users: &auth::Users,
    traffic: &Arc<traffic::Traffic>,
    source: std::net::IpAddr,
    limits: &Arc<limits::Registry>,
    udp_slots: &Arc<tokio::sync::Semaphore>,
) -> Result<(), Error> {
    let network = network::Network::direct();
    connection_routed(
        inbound,
        protocol,
        ConnectionContext {
            users,
            traffic,
            source: SocketAddr::new(source, 12345),
            limits,
            udp_slots,
            network: &network,
        },
    )
    .await
}

#[cfg(any(unix, test))]
struct ConnectionContext<'a> {
    users: &'a auth::Users,
    traffic: &'a Arc<traffic::Traffic>,
    source: SocketAddr,
    limits: &'a Arc<limits::Registry>,
    udp_slots: &'a Arc<tokio::sync::Semaphore>,
    network: &'a network::Network,
}

#[cfg(any(unix, test))]
async fn connection_routed<S: AsyncRead + AsyncWrite + Unpin>(
    mut inbound: S,
    protocol: config::Protocol,
    context: ConnectionContext<'_>,
) -> Result<(), Error> {
    let ConnectionContext {
        users,
        traffic,
        source,
        limits,
        udp_slots,
        network,
    } = context;
    let (request, outbound, counter, lease, _udp_slot) =
        tokio::time::timeout(Duration::from_secs(10), async {
            let request = protocol::handshake(&mut inbound, protocol, users).await?;
            let current_policy = users.load().policy(&request.user).unwrap_or(request.policy);
            let lease = limits.acquire(Arc::clone(&request.user), source.ip(), current_policy)?;
            let udp_slot = if request.command == protocol::Command::Udp {
                Some(
                    Arc::clone(udp_slots)
                        .try_acquire_owned()
                        .map_err(|_| Error::Limited)?,
                )
            } else {
                None
            };
            let outbound = if request.command == protocol::Command::Tcp {
                Some(
                    network
                        .connect(&request.address, request.port, source)
                        .await?,
                )
            } else {
                None
            };
            // The registry lock can be held by a durable fsync. Never take it on
            // the single-thread async executor: cancellation, signals and other
            // payload connections must keep making progress while storage waits.
            let counter = if traffic.enabled() {
                let user = Arc::clone(&request.user);
                Some(
                    traffic
                        .blocking(move |t| t.user(user))
                        .await
                        .map_err(|_| Error::Task)??,
                )
            } else {
                None
            };
            Ok::<_, Error>((request, outbound, counter, lease, udp_slot))
        })
        .await
        .map_err(|_| Error::Protocol)??;
    if protocol == config::Protocol::Vless {
        inbound.write_all(&[0, 0]).await?;
        inbound.flush().await?;
    }
    if request.command == protocol::Command::Udp {
        return udp::relay(
            inbound,
            request,
            protocol,
            &lease,
            users,
            counter,
            udp::RouteContext { network, source },
        )
        .await;
    }
    let outbound = outbound.ok_or(Error::Config)?;
    let _ = outbound.set_nodelay(true);
    let Some(counter) = counter else {
        relay(inbound, outbound, &lease, users).await?;
        return Ok(());
    };
    // Tokio propagates each half-close while continuing the opposite direction.
    let inbound = traffic::Counted::new(inbound, Arc::clone(&counter), 1);
    let outbound = traffic::Counted::new(outbound, counter, 0);
    relay(inbound, outbound, &lease, users).await?;
    Ok(())
}

#[cfg(any(unix, test))]
async fn relay<A, B>(
    inbound: A,
    outbound: B,
    lease: &limits::Lease,
    users: &auth::Users,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (ir, iw) = tokio::io::split(inbound);
    let (or, ow) = tokio::io::split(outbound);
    async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        mut reader: R,
        mut writer: W,
        lease: &limits::Lease,
        users: &auth::Users,
    ) -> std::io::Result<()> {
        use tokio::io::AsyncReadExt;
        let mut buffer = [0_u8; 8192];
        loop {
            let size = reader.read(&mut buffer).await?;
            if size == 0 {
                return writer.shutdown().await;
            }
            lease.charge(size, users).await;
            writer.write_all(&buffer[..size]).await?;
            // TLS may accept plaintext while ciphertext still waits for the
            // socket. Flush before waiting for the next read, so a request/
            // response protocol cannot strand the last chunk under backpressure.
            writer.flush().await?;
        }
    }
    tokio::try_join!(copy(ir, ow, lease, users), copy(or, iw, lease, users))?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    if let Ok(mut term) = signal(SignalKind::terminate()) {
        tokio::select! { _=tokio::signal::ctrl_c()=>{},_=term.recv()=>{} }
    } else {
        let _ = tokio::signal::ctrl_c().await;
    }
}
