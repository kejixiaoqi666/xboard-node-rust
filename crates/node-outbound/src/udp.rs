use crate::{
    BoxStream, Datagram, Packet, context, invalid,
    stream::{address, parse_address},
};
use async_trait::async_trait;
use bytes::BytesMut;
use shadowsocks::{
    config::ServerConfig,
    relay::{
        socks5::Address,
        udprelay::{crypto_io, options::UdpSocketControlData},
    },
};
use std::{
    collections::{BTreeMap, HashSet},
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::UdpSocket,
    sync::Mutex,
};
const PAYLOAD: usize = 65507;
const TARGETS: usize = 64;
type Targets = Mutex<HashSet<SocketAddr>>;
pub(crate) struct Bounded {
    pub inner: Arc<dyn Datagram>,
    pub _slot: tokio::sync::OwnedSemaphorePermit,
    pub framing: Arc<tokio::sync::Semaphore>,
    pub sends: Arc<tokio::sync::Semaphore>,
}
#[async_trait]
impl Datagram for Bounded {
    async fn send(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        check(payload, target)?;
        let _send = self.sends.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP send concurrency limit reached",
            )
        })?;
        // Reserve for all eight possible nested frame copies before the first
        // allocation; internal layers do not recursively acquire this budget.
        let _bytes = self
            .framing
            .clone()
            .try_acquire_many_owned(((payload.len() + 1024) * 8) as u32)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDP framing allocation limit reached",
                )
            })?;
        self.inner.send(payload, target).await
    }
    async fn receive_packet(&self) -> io::Result<Packet> {
        self.inner.receive_packet().await
    }
}
fn check(payload: &[u8], target: SocketAddr) -> io::Result<()> {
    if payload.len() > PAYLOAD
        || target.port() == 0
        || target.ip().is_unspecified()
        || target.ip().is_multicast()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid UDP payload or target",
        ));
    }
    Ok(())
}
fn admit(targets: &HashSet<SocketAddr>, target: SocketAddr) -> io::Result<()> {
    if targets.len() >= TARGETS && !targets.contains(&target) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "UDP target limit reached",
        ));
    }
    Ok(())
}
pub(crate) struct Direct {
    socket: UdpSocket,
    targets: Targets,
    framing: Arc<tokio::sync::Semaphore>,
}
impl Direct {
    pub async fn bind(
        target: SocketAddr,
        framing: Arc<tokio::sync::Semaphore>,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(if target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?,
            targets: Mutex::new(HashSet::new()),
            framing,
        })
    }
}
#[async_trait]
impl Datagram for Direct {
    async fn send(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        check(payload, target)?;
        let target = SocketAddr::new(node_core::routing::canonical(target.ip()), target.port());
        let mut targets = self.targets.lock().await;
        admit(&targets, target)?;
        if self.socket.send_to(payload, target).await? != payload.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        targets.insert(target);
        Ok(())
    }
    async fn receive_packet(&self) -> io::Result<Packet> {
        loop {
            self.socket.readable().await?;
            let permit = self
                .framing
                .clone()
                .try_acquire_many_owned(65535)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "UDP receive allocation limit reached",
                    )
                })?;
            let mut payload = vec![0; 65535];
            let (n, source) = match self.socket.try_recv_from(&mut payload) {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            };
            let source = SocketAddr::new(node_core::routing::canonical(source.ip()), source.port());
            if self.targets.lock().await.contains(&source) {
                payload.truncate(n);
                return Ok(Packet {
                    payload,
                    source,
                    _permit: permit,
                });
            }
        }
    }
}
pub(crate) struct Socks {
    control: Mutex<BoxStream>,
    lower: Arc<dyn Datagram>,
    relay: SocketAddr,
    targets: Targets,
}
impl Socks {
    pub fn new(control: BoxStream, lower: Arc<dyn Datagram>, relay: SocketAddr) -> Self {
        Self {
            control: Mutex::new(control),
            lower,
            relay,
            targets: Mutex::new(HashSet::new()),
        }
    }
}
#[async_trait]
impl Datagram for Socks {
    async fn send(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        check(payload, target)?;
        let mut targets = self.targets.lock().await;
        admit(&targets, target)?;
        let mut packet = vec![0; 3];
        packet.extend(address(target));
        packet.extend(payload);
        self.lower.send(&packet, self.relay).await?;
        targets.insert(target);
        Ok(())
    }
    async fn receive_packet(&self) -> io::Result<Packet> {
        let mut control = self.control.lock().await;
        loop {
            let mut packet = tokio::select! {value=control.read_u8()=>{let _=value?;return Err(invalid("SOCKS UDP control stream closed or sent unexpected data"))},value=self.lower.receive_packet()=>value?};
            let n = packet.payload.len();
            let bytes = &mut packet.payload;
            if packet.source != self.relay || n < 4 || bytes[..3] != [0, 0, 0] {
                continue;
            }
            let Ok((target, header)) = parse_address(&bytes[3..n]) else {
                continue;
            };
            let header = 3 + header;
            if self.targets.lock().await.contains(&target) {
                bytes.copy_within(header..n, 0);
                bytes.truncate(n - header);
                packet.source = target;
                return Ok(packet);
            }
        }
    }
}
struct StreamReader {
    stream: ReadHalf<BoxStream>,
    header: [u8; 23],
    read: usize,
    need: usize,
    payload: Vec<u8>,
    filled: usize,
    source: Option<SocketAddr>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
pub(crate) struct Stream {
    reader: Mutex<StreamReader>,
    writer: Mutex<WriteHalf<BoxStream>>,
    vless: bool,
    fixed: SocketAddr,
    targets: Targets,
    framing: Arc<tokio::sync::Semaphore>,
    poisoned: AtomicBool,
}
impl Stream {
    pub fn new(
        stream: BoxStream,
        vless: bool,
        fixed: SocketAddr,
        framing: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(StreamReader {
                stream: reader,
                header: [0; 23],
                read: 0,
                need: if vless { 2 } else { 1 },
                payload: Vec::new(),
                filled: 0,
                source: None,
                permit: None,
            }),
            writer: Mutex::new(writer),
            vless,
            fixed,
            targets: Mutex::new(HashSet::new()),
            framing,
            poisoned: AtomicBool::new(false),
        }
    }
}
struct WriteGuard<'a> {
    flag: &'a AtomicBool,
    armed: bool,
}
impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.flag.store(true, Ordering::Release);
        }
    }
}
#[async_trait]
impl Datagram for Stream {
    async fn send(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        check(payload, target)?;
        if self.vless && target != self.fixed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS UDP stream is bound to one target",
            ));
        }
        let mut targets = self.targets.lock().await;
        admit(&targets, target)?;
        let mut writer = self.writer.lock().await;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "previous UDP stream write was cancelled",
            ));
        }
        let mut guard = WriteGuard {
            flag: &self.poisoned,
            armed: true,
        };
        let mut packet = if self.vless {
            Vec::with_capacity(payload.len() + 2)
        } else {
            address(target)
        };
        packet.extend((payload.len() as u16).to_be_bytes());
        if !self.vless {
            packet.extend(b"\r\n");
        }
        packet.extend(payload);
        writer.write_all(&packet).await?;
        writer.flush().await?;
        targets.insert(target);
        guard.armed = false;
        Ok(())
    }
    async fn receive_packet(&self) -> io::Result<Packet> {
        let mut reader = self.reader.lock().await;
        loop {
            if self.poisoned.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "UDP stream was cancelled during a write",
                ));
            }
            while reader.read < reader.need {
                let StreamReader {
                    stream,
                    header,
                    read,
                    need,
                    ..
                } = &mut *reader;
                let n = stream.read(&mut header[*read..*need]).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                *read += n;
                if !self.vless && *read == 1 && *need == 1 {
                    *need = match header[0] {
                        1 => 11,
                        4 => 23,
                        3 => {
                            return Err(crate::unsupported(
                                "Trojan UDP response must preserve the pinned IP",
                            ));
                        }
                        _ => return Err(invalid("invalid Trojan UDP address type")),
                    };
                }
            }
            if reader.source.is_none() {
                let (target, offset) = if self.vless {
                    (self.fixed, 0)
                } else {
                    parse_address(&reader.header[..reader.need])?
                };
                let n =
                    u16::from_be_bytes([reader.header[offset], reader.header[offset + 1]]) as usize;
                if n > PAYLOAD {
                    return Err(invalid("proxy UDP frame exceeds limit"));
                }
                if !self.vless && reader.header[offset + 2..offset + 4] != *b"\r\n" {
                    return Err(invalid("invalid Trojan UDP separator"));
                }
                let permit = self
                    .framing
                    .clone()
                    .try_acquire_many_owned(n as u32)
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "UDP partial frame allocation limit reached",
                        )
                    })?;
                reader.payload = vec![0; n];
                reader.permit = Some(permit);
                reader.source = Some(target);
            }
            while reader.filled < reader.payload.len() {
                let StreamReader {
                    stream,
                    payload,
                    filled,
                    ..
                } = &mut *reader;
                let n = stream.read(&mut payload[*filled..]).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                *filled += n;
            }
            let source = reader.source.unwrap();
            let accepted = self.targets.lock().await.contains(&source);
            let payload = std::mem::take(&mut reader.payload);
            let permit = reader.permit.take().unwrap();
            reader.read = 0;
            reader.need = if self.vless { 2 } else { 1 };
            reader.filled = 0;
            reader.source = None;
            if accepted {
                return Ok(Packet {
                    payload,
                    source,
                    _permit: permit,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };
    #[tokio::test]
    async fn real_tcp_partial_header_and_payload_survive_cancelled_receive() {
        for vless in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let target = "127.0.0.1:53".parse().unwrap();
            let budget = Arc::new(tokio::sync::Semaphore::new(8 * 1024 * 1024));
            let channel = Stream::new(Box::new(client), vless, target, budget.clone());
            channel.send(b"request", target).await.unwrap();
            let mut request = vec![0; if vless { 9 } else { 18 }];
            peer.read_exact(&mut request).await.unwrap();
            let payload = b"complete-response";
            let mut packet = if vless { vec![] } else { address(target) };
            packet.extend((payload.len() as u16).to_be_bytes());
            if !vless {
                packet.extend(b"\r\n")
            }
            let header = packet.len();
            packet.extend(payload);
            peer.write_all(&packet[..1]).await.unwrap();
            assert!(
                timeout(Duration::from_millis(20), channel.receive_packet())
                    .await
                    .is_err()
            );
            peer.write_all(&packet[1..header + 3]).await.unwrap();
            assert!(
                timeout(Duration::from_millis(20), channel.receive_packet())
                    .await
                    .is_err()
            );
            assert_eq!(budget.available_permits(), 8 * 1024 * 1024 - payload.len());
            peer.write_all(&packet[header + 3..]).await.unwrap();
            let response = timeout(Duration::from_secs(1), channel.receive_packet())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.payload, payload);
            assert_eq!(response.source, target);
            assert_eq!(budget.available_permits(), 8 * 1024 * 1024 - payload.len());
            drop(response);
            assert_eq!(budget.available_permits(), 8 * 1024 * 1024);
            peer.write_all(&packet).await.unwrap();
            let response = channel.receive_packet().await.unwrap();
            assert_eq!(response.payload, payload);
            drop(response);
            assert_eq!(budget.available_permits(), 8 * 1024 * 1024);
        }
    }
    #[tokio::test]
    async fn waiting_many_native_udp_receives_allocate_no_packet_buffers() {
        let graph =
            crate::Graph::new(&[node_core::routing::Outbound::plain("direct", "direct")]).unwrap();
        let mut channels = vec![];
        for _ in 0..64 {
            channels.push(
                graph
                    .udp_open("direct", "127.0.0.1:53".parse().unwrap())
                    .await
                    .unwrap(),
            );
        }
        let mut futures: Vec<_> = channels
            .iter()
            .map(|channel| channel.receive_packet())
            .collect();
        std::future::poll_fn(|cx| {
            for future in &mut futures {
                assert!(future.as_mut().poll(cx).is_pending());
            }
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(graph.framing.available_permits(), 8 * 1024 * 1024);
        drop(futures);
        drop(channels);
        assert_eq!(graph.associations.available_permits(), 1024);
    }
}
#[derive(Default)]
struct Replay {
    highest: u64,
    bits: u128,
}
impl Replay {
    fn admit(&mut self, id: u64) -> bool {
        if self.bits == 0 {
            self.highest = id;
            self.bits = 1;
            return true;
        }
        if id > self.highest {
            self.bits = self
                .bits
                .checked_shl((id - self.highest).min(128) as u32)
                .unwrap_or(0)
                | 1;
            self.highest = id;
            return true;
        }
        let distance = self.highest - id;
        if distance >= 128 {
            return false;
        }
        let bit = 1u128 << distance;
        if self.bits & bit != 0 {
            return false;
        }
        self.bits |= bit;
        true
    }
}
struct SsState {
    targets: HashSet<SocketAddr>,
    client_session: u64,
    packet: u64,
    server_sessions: BTreeMap<u64, Replay>,
}
pub(crate) struct Shadowsocks {
    lower: Arc<dyn Datagram>,
    proxy: SocketAddr,
    config: ServerConfig,
    context: shadowsocks::context::SharedContext,
    state: Mutex<SsState>,
}
impl Shadowsocks {
    pub fn new(
        lower: Arc<dyn Datagram>,
        proxy: SocketAddr,
        config: ServerConfig,
    ) -> io::Result<Self> {
        let mut random = [0; 8];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut random)
            .map_err(|_| io::Error::other("UDP random source failed"))?;
        Ok(Self {
            lower,
            proxy,
            config,
            context: context(),
            state: Mutex::new(SsState {
                targets: HashSet::new(),
                client_session: u64::from_be_bytes(random),
                packet: 0,
                server_sessions: BTreeMap::new(),
            }),
        })
    }
}
#[async_trait]
impl Datagram for Shadowsocks {
    async fn send(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        check(payload, target)?;
        let mut state = self.state.lock().await;
        admit(&state.targets, target)?;
        state.packet = state
            .packet
            .checked_add(1)
            .ok_or_else(|| invalid("Shadowsocks UDP packet counter exhausted"))?;
        let mut control = UdpSocketControlData::default();
        control.client_session_id = state.client_session;
        control.packet_id = state.packet;
        let mut encrypted = BytesMut::new();
        crypto_io::encrypt_client_payload(
            &self.context,
            self.config.method(),
            self.config.key(),
            &Address::SocketAddress(target),
            &control,
            self.config.identity_keys(),
            payload,
            &mut encrypted,
        );
        self.lower.send(&encrypted, self.proxy).await?;
        state.targets.insert(target);
        Ok(())
    }
    async fn receive_packet(&self) -> io::Result<Packet> {
        loop {
            let mut packet = self.lower.receive_packet().await?;
            if packet.source != self.proxy {
                continue;
            }
            let Ok((n, target, control)) = crypto_io::decrypt_server_payload(
                &self.context,
                self.config.method(),
                self.config.key(),
                &mut packet.payload,
            ) else {
                continue;
            };
            let Address::SocketAddress(target) = target else {
                continue;
            };
            let target = SocketAddr::new(node_core::routing::canonical(target.ip()), target.port());
            let mut state = self.state.lock().await;
            if !state.targets.contains(&target) {
                continue;
            }
            if let Some(control) = control {
                if control.client_session_id != state.client_session {
                    continue;
                }
                if !state
                    .server_sessions
                    .contains_key(&control.server_session_id)
                    && state.server_sessions.len() >= 8
                {
                    continue;
                }
                if !state
                    .server_sessions
                    .entry(control.server_session_id)
                    .or_default()
                    .admit(control.packet_id)
                {
                    continue;
                }
            }
            packet.payload.truncate(n);
            packet.source = target;
            return Ok(packet);
        }
    }
}
