//! Native Hysteria 2 and TUIC v5 listeners.
//!
//! Authentication, protocol frames and padding never cross the node-session
//! payload boundary. A listener owns every application task and joins those
//! tasks on shutdown. New admissions use the host's live identity snapshot.
mod obfs;
mod udp;
mod wire;

use bytes::Bytes;
use node_session::{Host, User};
pub use obfs::{SalamanderConfig, wrap_salamander};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use wire::{Mode, Packet};

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_LIMIT: usize = 128;
const STREAM_LIMIT: usize = 64;
const CLOSE_CODE: u32 = 0x100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolKind {
    Hysteria2,
    Tuic,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CongestionControl {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Clone)]
pub struct Config {
    pub kind: ProtocolKind,
    pub addr: SocketAddr,
    pub tls: Arc<rustls::ServerConfig>,
    pub obfs: Option<SalamanderConfig>,
    pub congestion_control: CongestionControl,
    pub enable_udp: bool,
    /// TUIC may negotiate early data, but the server never admits payload
    /// until the complete TLS handshake and exporter authentication finish.
    /// Hysteria's password authentication always disables early data.
    pub allow_0rtt: bool,
}
impl Config {
    pub fn new(kind: ProtocolKind, addr: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Self {
        Self {
            kind,
            addr,
            tls,
            obfs: None,
            congestion_control: CongestionControl::Cubic,
            enable_udp: true,
            allow_0rtt: false,
        }
    }
}

pub struct Handle {
    pub local_addr: SocketAddr,
    pub task: JoinHandle<io::Result<()>>,
}

/// The socket and endpoint are bound before returning, so callers can announce
/// readiness using local_addr without racing a detached setup task.
pub async fn bind(
    config: Config,
    host: Arc<dyn Host>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<Handle> {
    if config.obfs.is_some() && config.kind != ProtocolKind::Hysteria2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Salamander is only available for Hysteria2",
        ));
    }
    let mut tls = (*config.tls).clone();
    if config.kind == ProtocolKind::Hysteria2 || tls.alpn_protocols.is_empty() {
        tls.alpn_protocols = vec![b"h3".to_vec()];
    }
    tls.max_early_data_size = if config.kind == ProtocolKind::Tuic && config.allow_0rtt {
        u32::MAX
    } else {
        0
    };
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server
        .max_incoming(CONNECTION_LIMIT)
        .incoming_buffer_size(64 * 1024)
        .incoming_buffer_size_total(8 * 1024 * 1024);
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams((STREAM_LIMIT as u32).into())
        .max_concurrent_uni_streams((STREAM_LIMIT as u32).into())
        .max_idle_timeout(Some(
            Duration::from_secs(60)
                .try_into()
                .map_err(io::Error::other)?,
        ))
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .stream_receive_window((256u32 * 1024).into())
        .receive_window((8u32 * 1024 * 1024).into())
        .send_window(8 * 1024 * 1024)
        .datagram_receive_buffer_size(if config.enable_udp || config.kind == ProtocolKind::Tuic {
            Some(64 * 1024)
        } else {
            None
        })
        .datagram_send_buffer_size(64 * 1024)
        .initial_mtu(1200)
        .min_mtu(1200)
        .enable_segmentation_offload(config.obfs.is_none());
    let congestion: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        match config.congestion_control {
            CongestionControl::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            CongestionControl::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
            CongestionControl::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
        };
    transport.congestion_controller_factory(congestion);
    server.transport_config(Arc::new(transport));
    let socket = std::net::UdpSocket::bind(config.addr)?;
    socket.set_nonblocking(true)?;
    let endpoint = if let Some(obfs) = &config.obfs {
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            wrap_salamander(socket, obfs.password.clone())?,
            Arc::new(quinn::TokioRuntime),
        )?
    } else {
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?
    };
    let local_addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        let cancel = CancellationToken::new();
        let budget = udp::Budget::new();
        let mut tasks = JoinSet::new();
        let mut result = Ok(());
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                update=stop.changed()=>{if update.is_err() || *stop.borrow(){break;}},
                incoming=endpoint.accept()=>{
                    let Some(incoming)=incoming else{break;};
                    if tasks.len()>=CONNECTION_LIMIT {incoming.refuse();continue;}
                    let host=host.clone();let config=config.clone();let child=cancel.child_token();let budget=budget.clone();
                    tasks.spawn(budget.tracker.clone().track_future(async move {
                        let result=process_connection(incoming,config,host,budget,child.clone()).await;
                        child.cancel();
                        if let Err(e)=result {tracing::debug!(error=%e,"QUIC connection ended");}
                    }));
                },
                completed=tasks.join_next(),if !tasks.is_empty()=>{
                    if let Some(Err(e))=completed {result=Err(io::Error::other(e));break;}
                },
            }
        }
        cancel.cancel();
        endpoint.close(CLOSE_CODE.into(), b"listener stopped");
        // Cancellation drops pending Host futures. A bounded grace period also
        // prevents a non-cooperative Host implementation from blocking stop.
        if timeout(Duration::from_secs(5), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        budget.tracker.close();
        budget.tracker.wait().await;
        let _ = timeout(Duration::from_secs(5), endpoint.wait_idle()).await;
        result
    });
    Ok(Handle { local_addr, task })
}

type H3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;

async fn process_connection(
    incoming: quinn::Incoming,
    config: Config,
    host: Arc<dyn Host>,
    budget: Arc<udp::Budget>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let deadline = Instant::now() + AUTH_TIMEOUT;
    let connection = tokio::select! {
        _=cancel.cancelled()=>return Ok(()),
        result=timeout_at(deadline,incoming)=>result.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"QUIC handshake timed out"))?.map_err(io::Error::other)?,
    };
    // Even with allow_0rtt, incoming.await waits for TLS handshake completion.
    // Exporter tokens are bound to this connection, so replayed TUIC auth from
    // another connection cannot authorize buffered early payload.
    let authentication = async {
        match config.kind {
            ProtocolKind::Hysteria2 => {
                let (user, h3) =
                    authenticate_hysteria(&connection, host.as_ref(), config.enable_udp).await?;
                Ok((user, Some(h3), Vec::new()))
            }
            ProtocolKind::Tuic => {
                let (user, pending) = authenticate_tuic(&connection, host.as_ref()).await?;
                Ok((user, None, pending))
            }
        }
    };
    let auth: io::Result<_> = tokio::select! {
        _=cancel.cancelled()=>Err(io::Error::new(io::ErrorKind::Interrupted,"listener stopped")),
        result=timeout_at(deadline,authentication)=>result.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"QUIC authentication timed out")).and_then(|r|r),
    };
    let (user, h3, pending) = match auth {
        Ok(value) => value,
        Err(error) => {
            connection.close(CLOSE_CODE.into(), b"authentication failed");
            return Err(error);
        }
    };
    if !host.users().iter().any(|current| current == &user) {
        connection.close(CLOSE_CODE.into(), b"identity revoked");
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity revoked",
        ));
    }
    let peer = connection.remote_address();
    let result = serve_connection(
        connection.clone(),
        config,
        host,
        user,
        peer,
        budget,
        cancel.clone(),
        h3,
        pending,
    )
    .await;
    cancel.cancel();
    connection.close(CLOSE_CODE.into(), b"connection stopped");
    result
}

fn password_matches(user: &User, provided: &str) -> bool {
    if let Some(password) = &user.password {
        return password.as_bytes().ct_eq(provided.as_bytes()).into();
    }
    let Some(uuid) = user.uuid else {
        return false;
    };
    let mut value = String::with_capacity(36);
    use std::fmt::Write;
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        let _ = write!(&mut value, "{b:02x}");
    }
    value.as_bytes().ct_eq(provided.as_bytes()).into()
}

async fn authenticate_hysteria(
    connection: &quinn::Connection,
    host: &dyn Host,
    udp: bool,
) -> io::Result<(User, H3Connection)> {
    let mut h3: H3Connection = h3::server::builder()
        .max_field_section_size(16 * 1024)
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(io::Error::other)?;
    for _ in 0..32 {
        let Some(request) = h3.accept().await.map_err(io::Error::other)? else {
            return Err(wire::invalid(
                "HTTP/3 connection ended before authentication",
            ));
        };
        let (request, mut stream) = request.resolve_request().await.map_err(io::Error::other)?;
        let user = if request.method() == http::Method::POST
            && request.uri().host() == Some("hysteria")
            && request.uri().path() == "/auth"
        {
            request
                .headers()
                .get("hysteria-auth")
                .and_then(|h| h.to_str().ok())
                .and_then(|provided| {
                    host.users()
                        .iter()
                        .find(|u| password_matches(u, provided))
                        .cloned()
                })
        } else {
            None
        };
        let response = if user.is_some() {
            http::Response::builder()
                .status(233)
                .header("Hysteria-UDP", if udp { "true" } else { "false" })
                .header("Hysteria-CC-RX", "auto")
                .header("Hysteria-Padding", hysteria_padding())
                .body(())
        } else {
            http::Response::builder()
                .status(404)
                .header("content-length", "0")
                .body(())
        }
        .map_err(io::Error::other)?;
        stream
            .send_response(response)
            .await
            .map_err(io::Error::other)?;
        stream.finish().await.map_err(io::Error::other)?;
        if let Some(user) = user {
            return Ok((user, h3));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "too many unauthenticated HTTP/3 requests",
    ))
}

fn hysteria_padding() -> String {
    use rand::{Rng, RngCore};
    let mut rng = rand::rngs::OsRng;
    let len = 32 + (rng.next_u32() % 64) as usize;
    rng.sample_iter(rand::distributions::Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

type PendingUni = Vec<(u8, quinn::RecvStream)>;
async fn authenticate_tuic(
    connection: &quinn::Connection,
    host: &dyn Host,
) -> io::Result<(User, PendingUni)> {
    let mut pending = Vec::new();
    loop {
        let mut stream = connection.accept_uni().await.map_err(io::Error::other)?;
        let version = stream.read_u8().await?;
        let command = stream.read_u8().await?;
        if version != 5 {
            return Err(wire::invalid("invalid TUIC version"));
        }
        if command != 0 {
            if !matches!(command, 2 | 3) || pending.len() >= STREAM_LIMIT {
                return Err(wire::invalid(
                    "too many or invalid pre-authentication streams",
                ));
            }
            pending.push((command, stream));
            continue;
        }
        let mut uuid = [0; 16];
        let mut token = [0; 32];
        stream
            .read_exact(&mut uuid)
            .await
            .map_err(io::Error::other)?;
        stream
            .read_exact(&mut token)
            .await
            .map_err(io::Error::other)?;
        for user in host.users().iter().filter(|u| u.uuid == Some(uuid)) {
            let Some(password) = &user.password else {
                continue;
            };
            let mut expected = [0; 32];
            connection
                .export_keying_material(&mut expected, &uuid, password.as_bytes())
                .map_err(|_| io::Error::other("TLS exporter failed"))?;
            if bool::from(token.ct_eq(&expected)) {
                let _ = stream.stop(0u32.into());
                return Ok((user.clone(), pending));
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TUIC authentication failed",
        ));
    }
}

enum Event {
    Done,
    Packet(Packet, OwnedSemaphorePermit),
    Dissociate(u32),
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    connection: quinn::Connection,
    config: Config,
    host: Arc<dyn Host>,
    user: User,
    peer: SocketAddr,
    budget: Arc<udp::Budget>,
    cancel: CancellationToken,
    _h3: Option<H3Connection>,
    pending: PendingUni,
) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    let mut udp = udp::Manager::new(
        connection.clone(),
        host.clone(),
        user.clone(),
        peer,
        budget.clone(),
        cancel.clone(),
    );
    for (command, stream) in pending {
        spawn_uni(
            &mut tasks,
            stream,
            Some(command),
            budget.clone(),
            config.enable_udp,
        );
    }
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.tick().await;
    let result = loop {
        tokio::select! {
            _=cancel.cancelled()=>break Ok(()),
            _=connection.closed()=>break Ok(()),
            _=interval.tick()=>{
                udp.purge();
                if !host.users().iter().any(|current|current==&user) {break Err(io::Error::new(io::ErrorKind::PermissionDenied,"identity revoked"));}
                if config.kind==ProtocolKind::Tuic {let _=connection.send_datagram(Bytes::from_static(&[5,4]));}
            },
            bi=connection.accept_bi(),if tasks.len()<STREAM_LIMIT=>{
                match bi {
                    Ok((send,recv))=>{
                        let host=host.clone();let user=user.clone();let kind=config.kind;
                        tasks.spawn(budget.tracker.track_future(async move {proxy_stream(kind,send,recv,host,user,peer).await.map(|_|Event::Done)}));
                    },
                    Err(_)=>break Ok(()),
                }
            },
            uni=connection.accept_uni(),if config.kind==ProtocolKind::Tuic && tasks.len()<STREAM_LIMIT=>{
                match uni {Ok(stream)=>spawn_uni(&mut tasks,stream,None,budget.clone(),config.enable_udp),Err(_)=>break Ok(())}
            },
            datagram=connection.read_datagram(),if config.enable_udp || config.kind==ProtocolKind::Tuic=>{
                let data=match datagram {Ok(data)=>data,Err(_)=>break Ok(())};
                if config.kind==ProtocolKind::Tuic && data.as_ref()==[5,4] {continue;}
                if !config.enable_udp {continue;}
                let parsed=match config.kind {ProtocolKind::Hysteria2=>wire::hysteria_packet(data),ProtocolKind::Tuic=>wire::tuic_packet(data,Mode::TuicNative)};
                match parsed {
                    Ok(packet)=>{
                        let route=tokio::select! {_=cancel.cancelled()=>break Ok(()),_=connection.closed()=>break Ok(()),result=udp.route(packet,None)=>result};
                        if let Err(error)=route && error.kind()==io::ErrorKind::PermissionDenied {break Err(error);}
                    },
                    Err(error) if config.kind==ProtocolKind::Tuic=>break Err(error),
                    Err(_)=>{}, // Hysteria unreliable malformed fragments are discarded.
                }
            },
            finished=tasks.join_next(),if !tasks.is_empty()=>{
                match finished {
                    Some(Ok(Ok(Event::Packet(packet,permit))))=>{
                        let route=tokio::select! {_=cancel.cancelled()=>break Ok(()),_=connection.closed()=>break Ok(()),result=udp.route(packet,Some(permit))=>result};
                        if let Err(error)=route && error.kind()==io::ErrorKind::PermissionDenied {break Err(error);}
                    },
                    Some(Ok(Ok(Event::Dissociate(id))))=>udp.dissociate(id),
                    Some(Ok(Err(error))) if error.kind()==io::ErrorKind::InvalidData && config.kind==ProtocolKind::Tuic=>break Err(error),
                    Some(Err(error))=>break Err(io::Error::other(error)),
                    _=>{},
                }
            },
            finished=udp.tasks.join_next(),if !udp.tasks.is_empty()=>{
                if let Some(Ok((id,generation)))=finished {udp.finished(id,generation);}
            },
        }
    };
    cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    udp.shutdown().await;
    result
}

fn spawn_uni(
    tasks: &mut JoinSet<io::Result<Event>>,
    mut stream: quinn::RecvStream,
    command: Option<u8>,
    budget: Arc<udp::Budget>,
    enabled: bool,
) {
    tasks.spawn(budget.tracker.clone().track_future(async move {
        timeout(AUTH_TIMEOUT, async {
            let command = if let Some(command) = command {
                command
            } else {
                if stream.read_u8().await? != 5 {
                    return Err(wire::invalid("invalid TUIC version"));
                }
                stream.read_u8().await?
            };
            match command {
                2 if enabled => {
                    let permit = budget
                        .queue
                        .clone()
                        .try_acquire_many_owned(wire::MAX_PAYLOAD as u32)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::WouldBlock, "UDP stream budget exhausted")
                        })?;
                    let packet = wire::tuic_stream_packet(&mut stream).await?;
                    let _ = stream.stop(0u32.into());
                    Ok(Event::Packet(packet, permit))
                }
                2 => {
                    let _ = stream.stop(0u32.into());
                    Ok(Event::Done)
                }
                3 => Ok(Event::Dissociate(stream.read_u16().await? as u32)),
                _ => Err(wire::invalid("invalid TUIC unidirectional command")),
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUIC command timed out"))?
    }));
}

async fn proxy_stream(
    kind: ProtocolKind,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    host: Arc<dyn Host>,
    user: User,
    peer: SocketAddr,
) -> io::Result<()> {
    let target = timeout(AUTH_TIMEOUT, async {
        match kind {
            ProtocolKind::Hysteria2 => wire::hysteria_tcp(&mut recv).await,
            ProtocolKind::Tuic => {
                if recv.read_u8().await? != 5 || recv.read_u8().await? != 1 {
                    return Err(wire::invalid("invalid TUIC TCP command"));
                }
                wire::tuic_address(&mut recv)
                    .await?
                    .ok_or_else(|| wire::invalid("TCP target required"))
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP command timed out"))??;
    let remote = timeout(AUTH_TIMEOUT, host.connect(&user, peer, &target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP admission timed out"))?;
    let remote = match remote {
        Ok(remote) => remote,
        Err(error) => {
            if kind == ProtocolKind::Hysteria2 {
                let _ = send
                    .write_all(&[1, 6, b'd', b'e', b'n', b'i', b'e', b'd', 0])
                    .await;
                let _ = send.finish();
            }
            return Err(error);
        }
    };
    if kind == ProtocolKind::Hysteria2 {
        send.write_all(&[0, 0, 0]).await.map_err(io::Error::other)?;
    }
    node_session::relay(Box::new(QuicStream { send, recv }), remote).await
}

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}
impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}
impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
