//! Rust-native TCP data plane, embedded in the controller's own executable.
pub mod auth;
pub mod config;
#[cfg(unix)]
mod control;
pub mod limits;
#[cfg(any(unix, test))]
mod network;
#[cfg(any(unix, test))]
mod os_dns;
#[cfg(unix)]
mod plugin;
pub mod protocol;
#[cfg(any(unix, test))]
mod reality;
#[cfg(any(unix, test))]
mod session;
mod shadowsocks;

pub fn reality_config(
    s: &node_core::reality::Settings,
) -> Result<node_reality::RealityServerConfig, Error> {
    s.validate().map_err(|_| Error::Config)?;
    let private = node_reality::decode_private_key(&s.private_key).map_err(|_| Error::Config)?;
    if let Some(public) = &s.public_key
        && node_reality::decode_public_key(public).map_err(|_| Error::Config)?
            != node_reality::public_key_from_private(private)
    {
        return Err(Error::Config);
    }
    Ok(node_reality::RealityServerConfig {
        private_key: private,
        short_ids: s
            .short_id
            .values()
            .iter()
            .map(|v| node_reality::decode_short_id(v).map_err(|_| Error::Config))
            .collect::<Result<_, _>>()?,
        server_name: s.server_name.clone(),
        max_time_diff: (s.max_time_diff != 0).then_some(s.max_time_diff),
        min_client_version: s.min_client_version,
        max_client_version: s.max_client_version,
        cipher_suites: Vec::new(),
        key_update_after_records: s.key_update_after_records,
    })
}
pub fn generate_reality_keypair() -> std::io::Result<(String, String)> {
    node_reality::generate_keypair()
}
pub fn generate_reality_mldsa65_keypair() -> std::io::Result<(String, String)> {
    node_reality::generate_mldsa65_keypair()
}
#[cfg(any(unix, test))]
mod traffic;
#[cfg(any(unix, test))]
mod traffic_store;
#[cfg(any(unix, test))]
mod udp;
#[cfg(any(unix, test))]
mod vision;

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
    run_cli_with_shutdown(args, None).await
}
/// Runtime-owned listener; it reacts only to its node's cancellation channel.
/// The controller owns OS signals, so a fleet has a single signal handler.
pub async fn run_embedded(
    args: &[String],
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error> {
    run_cli_with_shutdown(args, Some(stop)).await
}
async fn run_cli_with_shutdown(
    args: &[String],
    external_stop: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(), Error> {
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
            ServerOptions {
                path,
                socket: socket.ok_or(Error::Config)?,
                traffic_enabled: traffic_enabled.unwrap_or(true),
                persistent: traffic_state.zip(traffic_destination),
                checkpoint_period: Duration::from_millis(checkpoint_ms),
                external_stop,
            },
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
            external_stop,
        );
        Err(Error::Unsupported)
    }
}

#[cfg(unix)]
struct ServerOptions {
    path: PathBuf,
    socket: PathBuf,
    traffic_enabled: bool,
    persistent: Option<(PathBuf, String)>,
    checkpoint_period: Duration,
    external_stop: Option<tokio::sync::watch::Receiver<bool>>,
}
#[cfg(unix)]
async fn serve(
    initial: config::Candidate,
    tls: Option<Arc<rustls::ServerConfig>>,
    options: ServerOptions,
) -> Result<(), Error> {
    let ServerOptions {
        path,
        socket,
        traffic_enabled,
        persistent,
        checkpoint_period,
        external_stop,
    } = options;
    let control = control::bind(&path, &socket)?;
    let network = Arc::new(network::Network::new(
        &initial.base.route,
        &initial.base.outbounds,
        initial.base.dns.as_ref(),
    )?);
    let quic_protocol = matches!(
        initial.base.protocol,
        config::Protocol::Hysteria2 | config::Protocol::Tuic
    );
    let public = SocketAddr::new(initial.base.listen, initial.base.port);
    let plugin_config = initial.base.plugin.clone();
    let mut listener = if quic_protocol {
        None
    } else {
        Some(
            TcpListener::bind(if plugin_config.is_some() {
                SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0)
            } else {
                public
            })
            .await?,
        )
    };
    let initial_reality = initial
        .base
        .tls
        .as_ref()
        .and_then(|t| t.reality.clone())
        .map(Arc::new);
    let protocol = initial.base.protocol;
    let tag: Arc<str> = Arc::from(initial.base.tag.as_str());
    let transport = initial.base.transport.clone();
    let extended_config = initial
        .base
        .extended
        .as_ref()
        .map(config::Extended::config)
        .transpose()?
        .unwrap_or_default();
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
    let reality = initial_reality;
    let quic_tls = tls.clone();
    let tls = tls.map(|mut tls| {
        if let Some(transport) = &transport {
            Arc::make_mut(&mut tls).alpn_protocols =
                vec![if matches!(transport.kind.as_str(), "http2" | "grpc") {
                    b"h2".to_vec()
                } else {
                    b"http/1.1".to_vec()
                }];
        }
        TlsAcceptor::from(tls)
    });
    let limits = Arc::new(limits::Registry::new(Arc::clone(&users)));
    let udp_slots = Arc::new(tokio::sync::Semaphore::new(1024));
    let host: Arc<dyn node_session::Host> = Arc::new(session::SessionHost::new(
        users.clone(),
        limits.clone(),
        traffic.clone(),
        network.clone(),
        udp_slots.clone(),
        tag.clone(),
    ));
    let (protocol_stop_tx, protocol_stop_rx) = tokio::sync::watch::channel(false);
    let shutdown = async {
        match external_stop {
            Some(mut stop) => loop {
                if *stop.borrow() {
                    break;
                }
                if stop.changed().await.is_err() {
                    break;
                }
            },
            None => shutdown().await,
        }
    };
    tokio::pin!(shutdown);
    let mut quic = if quic_protocol {
        let settings = initial.base.quic.as_ref().ok_or(Error::Config)?;
        let kind = if protocol == config::Protocol::Hysteria2 {
            node_quic::ProtocolKind::Hysteria2
        } else {
            node_quic::ProtocolKind::Tuic
        };
        let mut config = node_quic::Config::new(
            kind,
            SocketAddr::new(initial.base.listen, initial.base.port),
            quic_tls.ok_or(Error::Tls)?,
        );
        config.allow_0rtt = settings.allow_0rtt;
        config.enable_udp = settings.enable_udp;
        config.congestion_control = match settings.congestion_control.as_str() {
            "cubic" => node_quic::CongestionControl::Cubic,
            "new_reno" => node_quic::CongestionControl::NewReno,
            "bbr" => node_quic::CongestionControl::Bbr,
            _ => return Err(Error::Config),
        };
        config.obfs =
            settings
                .obfs_password
                .as_deref()
                .map(|password| node_quic::SalamanderConfig {
                    password: Arc::from(password),
                });
        let handle = node_quic::bind(config, host.clone(), protocol_stop_rx.clone()).await?;
        Some(QuicTask {
            task: OwnedTask::new(handle.task),
        })
    } else {
        None
    };
    let ss_service = Arc::new(shadowsocks::Service::new());
    // Do not expose authenticated UDP while an external transport is still
    // starting: startup cancellation/failure has no payload writers to drain.
    let mut plugin = if let Some(config) = &plugin_config {
        let started = plugin::Process::start(
            config,
            public,
            listener.as_ref().ok_or(Error::Config)?.local_addr()?,
            &mut shutdown,
        )
        .await?;
        if started.is_none() {
            traffic
                .blocking(|t| t.checkpoint(true))
                .await
                .map_err(|_| Error::Task)??;
            return Ok(());
        }
        started
    } else {
        None
    };
    let mut ss_udp: Option<shadowsocks::UdpHandle> = if protocol == config::Protocol::Shadowsocks {
        let bound = shadowsocks::serve_udp(
            if plugin_config.is_some() {
                public
            } else {
                listener.as_ref().unwrap().local_addr()?
            },
            shadowsocks::UdpContext {
                users: users.clone(),
                traffic: traffic.clone(),
                limits: limits.clone(),
                network: network.clone(),
                tag: tag.clone(),
            },
            ss_service.clone(),
        )
        .await;
        match bound {
            Ok(handle) => Some(handle),
            Err(error) => {
                if let Some(mut process) = plugin.take() {
                    let _ = process.stop().await;
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    let mut controller = OwnedTask::new(tokio::spawn(control::serve(
        control,
        initial,
        control_users,
        directory,
        Arc::clone(&traffic),
        control::Quiesce {
            request: quiesce_tx,
            done: quiesced_rx,
            limits: Arc::clone(&limits),
            extended: extended_config.clone(),
        },
    )));
    const MAX_CONNECTIONS: usize = 16384;
    let mut connections = JoinSet::new();
    let mut accept_after = tokio::time::Instant::now();
    let mut control_finished = false;
    let mut accepting = true;
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
            result=async {(&mut quic.as_mut().expect("enabled QUIC listener").task).await},if quic.is_some()=> {
                quic.take();
                break match result {Ok(Err(error))=>Err(Error::Io(error)),_=>Err(Error::Task)};
            },
            result=async {ss_udp.as_mut().expect("enabled Shadowsocks UDP").finished().await},if ss_udp.is_some()=> {
                break result.and(Err(Error::Task));
            },
            changed=quiesce_rx.changed(), if accepting => {
                if changed.is_err() { break Err(Error::Task); }
                accepting=false;
                listener.take();
                let _=protocol_stop_tx.send(true);
                drain_connections(&mut connections).await;
                extended_config.xudp_sessions.clear_idle();
                if let Some(mut process)=plugin.take() && let Err(error)=process.stop().await {break Err(error);}
                if let Some(handle)=quic.take() {
                    match handle.task.await {Ok(Ok(()))=>{},Ok(Err(error))=>break Err(Error::Io(error)),Err(_)=>break Err(Error::Task)}
                }
                if let Some(udp)=ss_udp.take() && let Err(error)=udp.shutdown().await {break Err(error);}
                if let Err(error)=payload_barrier(&limits,&extended_config).await {break Err(error);}
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
            result=async{plugin.as_mut().expect("enabled plugin").wait().await},if plugin.is_some()=>{break result;},
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
                let reality=reality.clone();
                let traffic=Arc::clone(&traffic);
                let limits=Arc::clone(&limits);
                let udp_slots=Arc::clone(&udp_slots);
                let network=Arc::clone(&network);
                let ss_service=ss_service.clone();
                let host=host.clone();
                let tag=tag.clone();
                let extended_config=extended_config.clone();
                let transport=transport.clone();
                let stop=protocol_stop_rx.clone();
                connections.spawn(async move {
                    let _=stream.set_nodelay(true);
                    let context=ConnectionContext { users: &users, traffic: &traffic, source, limits: &limits, udp_slots: &udp_slots, network: &network, extended: extended_config.clone(), stop: Some(stop.clone()), tag };
                    if protocol==config::Protocol::Shadowsocks && transport.is_none() && tls.is_none() {let _=shadowsocks::connection(stream,&ss_service,context).await;} else if let Some(reality)=reality {let _=reality::connection(stream,&reality,context).await;} else if let Some(tls)=tls {
                        if let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(10),tls.accept(vision::RecordIo::new(stream))).await {
                            if let Some(transport)=transport {
                                let _=connection_transport(Box::new(stream),transport,protocol,context,host,ss_service).await;
                            } else if matches!(protocol,config::Protocol::Vmess|config::Protocol::AnyTls) {
                                let kind=if protocol==config::Protocol::Vmess {node_extended::Protocol::Vmess} else {node_extended::Protocol::AnyTls};
                                let _=node_extended::serve(kind,extended_config,Box::new(stream),source,host,Some(stop)).await;
                            } else {let _=connection_tls(stream,protocol,context).await;}
                        }
                    } else if let Some(transport)=transport {
                        let _=connection_transport(Box::new(stream),transport,protocol,context,host,ss_service).await;
                    } else if matches!(protocol,config::Protocol::Vmess|config::Protocol::AnyTls) {
                        let kind=if protocol==config::Protocol::Vmess {node_extended::Protocol::Vmess} else {node_extended::Protocol::AnyTls};
                        let _=node_extended::serve(kind,extended_config,Box::new(stream),source,host,Some(stop)).await;
                    } else { let _=connection_routed(stream,protocol,context).await; }
                });
            }
        }
    };
    // Reap every copy before the final checkpoint; the successful barrier has
    // no remaining payload writer. Control is then stopped before process exit.
    listener.take();
    let _ = protocol_stop_tx.send(true);
    drain_connections(&mut connections).await;
    extended_config.xudp_sessions.clear_idle();
    let plugin_stop = match plugin.take() {
        Some(mut process) => process.stop().await,
        None => Ok(()),
    };
    let quic_stop = match quic.take() {
        Some(handle) => match handle.task.await {
            Ok(result) => result.map_err(Error::Io),
            Err(_) => Err(Error::Task),
        },
        None => Ok(()),
    };
    let udp_stop = match ss_udp.take() {
        Some(udp) => udp.shutdown().await,
        None => Ok(()),
    };
    let barrier = payload_barrier(&limits, &extended_config).await;
    let final_save = if barrier.is_ok() {
        Some(traffic.blocking(|t| t.checkpoint(true)).await)
    } else {
        None
    };
    if !control_finished {
        controller.abort();
        let _ = controller.await;
    }
    barrier?;
    final_save.ok_or(Error::Task)?.map_err(|_| Error::Task)??;
    udp_stop?;
    quic_stop?;
    plugin_stop?;
    result
}

#[cfg(unix)]
async fn drain_connections(connections: &mut JoinSet<()>) {
    // Let structured protocol cancellation join nested mux/HTTP2/AnyTLS jobs.
    // Residual unauthenticated handshakes/direct copies have a bounded fallback.
    if tokio::time::timeout(Duration::from_secs(1), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}
#[cfg(unix)]
async fn payload_barrier(
    limits: &limits::Registry,
    config: &node_extended::Config,
) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let bytes = config.shared_budget.available_bytes();
            let sessions = config.shared_budget.available_sessions();
            if limits.activity().sessions == 0
                && bytes.is_none_or(|n| n == config.max_queued_bytes)
                && sessions.is_none_or(|n| n == config.max_sessions)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| Error::Task)
}

/// Bind a native checkpoint to the credential-free panel/node destination.
#[cfg(unix)]
struct QuicTask {
    task: OwnedTask<std::io::Result<()>>,
}
#[cfg(any(unix, test))]
struct OwnedTask<T>(tokio::task::JoinHandle<T>);
#[cfg(any(unix, test))]
impl<T> OwnedTask<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self(task)
    }
    fn abort(&self) {
        self.0.abort();
    }
}
#[cfg(any(unix, test))]
impl<T> std::future::Future for OwnedTask<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.get_mut().0).poll(cx)
    }
}
#[cfg(any(unix, test))]
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
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
async fn connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    inbound: S,
    protocol: config::Protocol,
    users: &auth::Users,
    traffic: &Arc<traffic::Traffic>,
    source: std::net::IpAddr,
    limits: &Arc<limits::Registry>,
    udp_slots: &Arc<tokio::sync::Semaphore>,
) -> Result<(), Error> {
    let network = Arc::new(network::Network::direct());
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
            extended: node_extended::Config::default(),
            stop: None,
            tag: Arc::from("vless-in"),
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
    network: &'a Arc<network::Network>,
    extended: node_extended::Config,
    stop: Option<tokio::sync::watch::Receiver<bool>>,
    tag: Arc<str>,
}

#[cfg(unix)]
async fn connection_transport(
    stream: node_session::BoxStream,
    transport: config::Transport,
    protocol: config::Protocol,
    context: ConnectionContext<'_>,
    host: Arc<dyn node_session::Host>,
    ss_service: Arc<shadowsocks::Service>,
) -> Result<(), Error> {
    match transport.kind.as_str() {
        "ws" | "httpupgrade" => {
            let plugin_mux = transport.plugin_mux;
            let stream = if transport.kind == "ws" {
                node_extended::websocket::accept(stream, transport.websocket()).await?
            } else {
                node_extended::httpupgrade::accept(
                    stream,
                    node_extended::httpupgrade::HttpUpgradeConfig {
                        path: transport.path,
                        host: transport.host,
                        ..Default::default()
                    },
                )
                .await?
            };
            if plugin_mux {
                let config = context.extended.clone();
                let stop = context.stop.clone();
                let handler = Arc::new(TransportHandler::new(protocol, context, host, ss_service));
                node_extended::mux::serve_plugin_mux(stream, handler, config, stop).await?;
                Ok(())
            } else if protocol == config::Protocol::Shadowsocks {
                shadowsocks::connection(stream, &ss_service, context).await
            } else {
                connection_extended(stream, protocol, context, host).await
            }
        }
        "http2" | "grpc" => {
            let config = context.extended.clone();
            let stop = context.stop.clone();
            let handler = Arc::new(TransportHandler::new(protocol, context, host, ss_service));
            if transport.kind == "http2" {
                node_extended::http2::serve(
                    stream,
                    node_extended::http2::Http2Config {
                        path: transport.path,
                        hosts: transport.hosts,
                        method: transport.method,
                    },
                    handler,
                    config,
                    stop,
                )
                .await?;
            } else {
                node_extended::grpc::serve(
                    stream,
                    node_extended::grpc::GrpcConfig {
                        service_name: transport.service_name.ok_or(Error::Config)?,
                    },
                    handler,
                    config,
                    stop,
                )
                .await?;
            }
            Ok(())
        }
        _ => Err(Error::Unsupported),
    }
}
#[cfg(unix)]
struct TransportHandler {
    protocol: config::Protocol,
    users: auth::Users,
    traffic: Arc<traffic::Traffic>,
    source: SocketAddr,
    limits: Arc<limits::Registry>,
    udp_slots: Arc<tokio::sync::Semaphore>,
    network: Arc<network::Network>,
    extended: node_extended::Config,
    stop: Option<tokio::sync::watch::Receiver<bool>>,
    tag: Arc<str>,
    host: Arc<dyn node_session::Host>,
    ss_service: Arc<shadowsocks::Service>,
}
#[cfg(unix)]
impl TransportHandler {
    fn new(
        protocol: config::Protocol,
        context: ConnectionContext<'_>,
        host: Arc<dyn node_session::Host>,
        ss_service: Arc<shadowsocks::Service>,
    ) -> Self {
        Self {
            protocol,
            users: context.users.clone(),
            traffic: context.traffic.clone(),
            source: context.source,
            limits: context.limits.clone(),
            udp_slots: context.udp_slots.clone(),
            network: context.network.clone(),
            extended: context.extended,
            stop: context.stop,
            tag: context.tag,
            host,
            ss_service,
        }
    }
}
#[cfg(unix)]
#[async_trait::async_trait]
impl node_extended::http2::StreamHandler for TransportHandler {
    async fn serve(&self, stream: node_session::BoxStream) -> std::io::Result<()> {
        let context = ConnectionContext {
            users: &self.users,
            traffic: &self.traffic,
            source: self.source,
            limits: &self.limits,
            udp_slots: &self.udp_slots,
            network: &self.network,
            extended: self.extended.clone(),
            stop: self.stop.clone(),
            tag: self.tag.clone(),
        };
        let result = if self.protocol == config::Protocol::Shadowsocks {
            shadowsocks::connection(stream, &self.ss_service, context).await
        } else {
            connection_extended(stream, self.protocol, context, self.host.clone()).await
        };
        result.map_err(std::io::Error::other)
    }
}

#[cfg(unix)]
async fn connection_extended(
    stream: node_session::BoxStream,
    protocol: config::Protocol,
    context: ConnectionContext<'_>,
    host: Arc<dyn node_session::Host>,
) -> Result<(), Error> {
    match protocol {
        config::Protocol::Vmess | config::Protocol::AnyTls => {
            let kind = if protocol == config::Protocol::Vmess {
                node_extended::Protocol::Vmess
            } else {
                node_extended::Protocol::AnyTls
            };
            node_extended::serve(
                kind,
                context.extended,
                stream,
                context.source,
                host,
                context.stop,
            )
            .await?;
            Ok(())
        }
        _ => connection_routed(stream, protocol, context).await,
    }
}

#[cfg(any(unix, test))]
async fn connection_routed<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut inbound: S,
    protocol: config::Protocol,
    context: ConnectionContext<'_>,
) -> Result<(), Error> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let request = tokio::time::timeout_at(
        deadline,
        protocol::handshake(&mut inbound, protocol, context.users),
    )
    .await
    .map_err(|_| Error::Protocol)??;
    if request.vision_uuid.is_some() {
        return Err(Error::Unsupported);
    }
    connection_authenticated(inbound, protocol, request, false, deadline, context).await
}

#[cfg(any(unix, test))]
async fn connection_tls<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut inbound: tokio_rustls::server::TlsStream<vision::RecordIo<S>>,
    protocol: config::Protocol,
    context: ConnectionContext<'_>,
) -> Result<(), Error> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let request = tokio::time::timeout_at(
        deadline,
        protocol::handshake(&mut inbound, protocol, context.users),
    )
    .await
    .map_err(|_| Error::Protocol)??;
    if let Some(uuid) = request.vision_uuid {
        if inbound.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(Error::Unsupported);
        }
        tokio::time::timeout_at(deadline, inbound.flush())
            .await
            .map_err(|_| Error::Protocol)??;
        let (transport, session) = inbound.into_inner();
        let stream = node_vision::VisionStream::new_server(
            transport.into_inner()?,
            rustls::Connection::Server(session),
            uuid,
            &[],
        )?;
        connection_authenticated(stream, protocol, request, true, deadline, context).await
    } else {
        connection_authenticated(inbound, protocol, request, false, deadline, context).await
    }
}

#[cfg(any(unix, test))]
async fn connection_authenticated<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    inbound: S,
    protocol: config::Protocol,
    request: protocol::Request,
    vision: bool,
    deadline: tokio::time::Instant,
    mut context: ConnectionContext<'_>,
) -> Result<(), Error> {
    let profile = request.profile.clone().ok_or(Error::Auth)?;
    let changes = context.limits.subscribe_auth();
    let mux = request.command == protocol::Command::Mux
        || request.command == protocol::Command::Tcp
            && request.port == node_extended::mux::MUX_PORT
            && matches!(&request.address,protocol::Address::Domain(name) if name==node_extended::mux::MUX_HOST);
    let mut stop = context.stop.clone();
    if mux {
        // Revoke the carrier through its cancellation API so it can join its
        // own workers, rather than dropping a future with a nested JoinSet.
        let users = context.users.clone();
        let (signal, receiver) = tokio::sync::watch::channel(false);
        let mut watcher = OwnedTask::new(tokio::spawn(async move {
            tokio::select! {biased;_=session::revoked(&users,&profile,changes)=>(),_=protocol_cancelled(&mut stop)=>()}
            let _ = signal.send(true);
        }));
        context.stop = Some(receiver);
        let result =
            connection_authenticated_live(inbound, protocol, request, vision, deadline, context)
                .await;
        watcher.abort();
        let _ = (&mut watcher).await;
        result
    } else {
        tokio::select! {biased;_=protocol_cancelled(&mut stop)=>Ok(()),_=session::revoked(context.users,&profile,changes)=>Err(Error::Auth),result=connection_authenticated_live(inbound,protocol,request,vision,deadline,context)=>result}
    }
}
#[cfg(any(unix, test))]
async fn protocol_cancelled(stop: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match stop {
        None => std::future::pending::<()>().await,
        Some(stop) => loop {
            if *stop.borrow() || stop.changed().await.is_err() {
                return;
            }
        },
    }
}
#[cfg(any(unix, test))]
async fn connection_authenticated_live<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut inbound: S,
    protocol: config::Protocol,
    request: protocol::Request,
    vision: bool,
    deadline: tokio::time::Instant,
    context: ConnectionContext<'_>,
) -> Result<(), Error> {
    let ConnectionContext {
        users,
        traffic,
        source,
        limits,
        udp_slots,
        network,
        extended,
        stop,
        tag,
    } = context;
    let h2mux = request.command == protocol::Command::Tcp
        && request.port == node_extended::mux::MUX_PORT
        && matches!(&request.address,protocol::Address::Domain(name) if name==node_extended::mux::MUX_HOST);
    if request.command == protocol::Command::Mux || h2mux {
        if !extended.multiplex_enabled {
            return Err(Error::Unsupported);
        }
        let user = request.profile.ok_or(Error::Auth)?;
        let host: Arc<dyn node_session::Host> = Arc::new(session::SessionHost::new(
            users.clone(),
            limits.clone(),
            traffic.clone(),
            network.clone(),
            udp_slots.clone(),
            tag.clone(),
        ));
        if protocol == config::Protocol::Vless && !vision {
            inbound.write_all(&[0, 0]).await?;
            inbound.flush().await?;
        }
        if h2mux {
            node_extended::mux::serve_h2mux(Box::new(inbound), user, source, host, extended, stop)
                .await?;
        } else {
            node_extended::mux::serve_xudp(Box::new(inbound), user, source, host, extended, stop)
                .await?;
        }
        return Ok(());
    }
    let (request, outbound, counter, lease, _udp_slot) = tokio::time::timeout_at(deadline, async {
        let current_policy = users.load().policy(&request.user).unwrap_or(request.policy);
        let lease =
            Arc::new(limits.acquire(Arc::clone(&request.user), source.ip(), current_policy)?);
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
                    .connect_for(&request.address, request.port, source, &request.user, &tag)
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
    if protocol == config::Protocol::Vless && !vision {
        inbound.write_all(&[0, 0]).await?;
        inbound.flush().await?;
    }
    if request.command == protocol::Command::Udp {
        let datagram = session::routed_datagram(session::DatagramContext {
            peer: source,
            lease,
            users: users.clone(),
            network: network.clone(),
            tag,
            user: request.user.clone(),
            profile: request.profile.clone().ok_or(Error::Auth)?,
            changes: limits.subscribe_auth(),
            counter: counter.clone(),
            slot: _udp_slot,
            count_down: false,
        });
        return udp::relay(inbound, request, protocol, datagram, counter).await;
    }
    let outbound = outbound.ok_or(Error::Config)?;
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
