//! Bounded, authenticated native Shadowsocks UDP associations.
use super::{Credential, Credentials, Replay, Service, address, context};
use crate::{Error, auth::Users, limits, network::Network, traffic::Traffic};
use bytes::BytesMut;
use shadowsocks::relay::{
    socks5::Address,
    udprelay::{crypto_io, options::UdpSocketControlData},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};

const MAX_PACKET: usize = 65507;
const MAX_ASSOCIATIONS: usize = 1024;
const MAX_SESSIONS: usize = 4096;
const QUEUED_BYTES: u32 = 8 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(60);
const SESSION_TTL: Duration = Duration::from_secs(120);

/// 1024-packet reordering window; session records survive association closure.
struct Window {
    highest: u64,
    bits: [u64; 16],
    last: Instant,
}
impl Window {
    fn new(packet: u64, now: Instant) -> Self {
        let mut bits = [0; 16];
        bits[0] = 1;
        Self {
            highest: packet,
            bits,
            last: now,
        }
    }
    fn claim(&mut self, packet: u64, now: Instant) -> Result<(), Error> {
        if packet > self.highest {
            let shift = packet - self.highest;
            if shift >= 1024 {
                self.bits.fill(0);
            } else {
                let words = (shift / 64) as usize;
                let bits = (shift % 64) as u32;
                for i in (0..16).rev() {
                    self.bits[i] = if i < words {
                        0
                    } else {
                        (self.bits[i - words] << bits)
                            | if bits > 0 && i > words {
                                self.bits[i - words - 1] >> (64 - bits)
                            } else {
                                0
                            }
                    };
                }
            }
            self.highest = packet;
        }
        let behind = self.highest - packet;
        if behind >= 1024 {
            return Err(Error::Auth);
        }
        let index = (behind / 64) as usize;
        let bit = 1u64 << (behind % 64);
        if self.bits[index] & bit != 0 {
            return Err(Error::Auth);
        }
        self.bits[index] |= bit;
        self.last = now;
        Ok(())
    }
}
#[derive(Default)]
struct PacketReplay {
    classic: Replay,
    sessions: HashMap<([u8; 32], u64), Window>,
    cleaned: Option<Instant>,
}
impl PacketReplay {
    fn claim(
        &mut self,
        user: &Credential,
        salt: &[u8],
        control: Option<&UdpSocketControlData>,
    ) -> Result<(), Error> {
        let now = Instant::now();
        if let Some(control) = control {
            if self
                .cleaned
                .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(1))
            {
                self.sessions
                    .retain(|_, window| now.saturating_duration_since(window.last) < SESSION_TTL);
                self.cleaned = Some(now);
            }
            let key = (
                *blake3::hash(&user.key).as_bytes(),
                control.client_session_id,
            );
            if let Some(window) = self.sessions.get_mut(&key) {
                return window.claim(control.packet_id, now);
            }
            if self.sessions.len() >= MAX_SESSIONS {
                return Err(Error::Limited);
            }
            self.sessions
                .insert(key, Window::new(control.packet_id, now));
            Ok(())
        } else {
            self.classic.claim_with_window(&user.key, salt, now, IDLE)
        }
    }
}

struct Packet {
    address: crate::protocol::Address,
    port: u16,
    payload: Vec<u8>,
    _budget: Option<OwnedSemaphorePermit>,
}
struct Decoded {
    user: Arc<Credential>,
    packet: Packet,
    session: u64,
}
fn decrypt(
    credentials: &Credentials,
    body: &[u8],
    replay: &mut PacketReplay,
) -> Result<Decoded, Error> {
    if body.len() > MAX_PACKET {
        return Err(Error::Protocol);
    }
    let ctx = context();
    let (user, mut bytes, size, destination, control) = if credentials.method.is_aead_2022() {
        let mut bytes = body.to_vec();
        let (size, destination, control) = crypto_io::decrypt_client_payload(
            &ctx,
            credentials.method,
            &credentials.server_key,
            &mut bytes,
            Some(&credentials.manager),
        )
        .map_err(|_| Error::Auth)?;
        let user = control
            .as_ref()
            .and_then(|c| c.user.as_ref())
            .and_then(|u| credentials.identities.get(u.identity_hash()))
            .cloned()
            .ok_or(Error::Auth)?;
        (user, bytes, size, destination, control)
    } else {
        let mut found = None;
        for user in &credentials.users {
            let mut bytes = body.to_vec();
            if let Ok((size, destination, control)) = crypto_io::decrypt_client_payload(
                &ctx,
                credentials.method,
                &user.key,
                &mut bytes,
                None,
            ) {
                found = Some((user.clone(), bytes, size, destination, control));
                break;
            }
        }
        found.ok_or(Error::Auth)?
    };
    let (address, port) = address(destination)?;
    let salt = body
        .get(..credentials.method.salt_len())
        .ok_or(Error::Protocol)?;
    replay.claim(&user, salt, control.as_ref())?;
    bytes.truncate(size);
    Ok(Decoded {
        user,
        packet: Packet {
            address,
            port,
            payload: bytes,
            _budget: None,
        },
        session: control.map_or(0, |c| c.client_session_id),
    })
}
fn canonical(source: SocketAddr) -> SocketAddr {
    if let IpAddr::V6(ip) = source.ip()
        && let Some(ip) = ip.to_ipv4_mapped()
    {
        return SocketAddr::new(ip.into(), source.port());
    }
    source
}
// Credentials can be reassigned to a different panel account by a hot update.
// Keep that authenticated identity in the association/counter ownership key.
type Key = (SocketAddr, [u8; 32], u64, Arc<str>);
struct Association {
    generation: u64,
    sender: mpsc::Sender<Packet>,
}
#[derive(Clone)]
pub(crate) struct Context {
    pub users: Users,
    pub limits: Arc<limits::Registry>,
    pub traffic: Arc<Traffic>,
    pub network: Arc<Network>,
}

/// Graceful stop joins all payload writers before the controller's checkpoint.
pub(crate) struct Handle {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), Error>>>,
}
impl Handle {
    #[cfg(unix)]
    pub async fn finished(&mut self) -> Result<(), Error> {
        let result = self.task.as_mut().ok_or(Error::Task)?.await;
        self.task.take();
        result.map_err(|_| Error::Task)?
    }
    pub async fn shutdown(mut self) -> Result<(), Error> {
        let _ = self.stop.send(true);
        match self.task.take() {
            Some(task) => task.await.map_err(|_| Error::Task)?,
            None => Ok(()),
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
pub(crate) async fn serve(
    bind: SocketAddr,
    context: Context,
    _service: Arc<Service>,
) -> Result<Handle, Error> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    let (stop, mut stopped) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut associations = HashMap::<Key, Association>::new();
        let mut workers = JoinSet::new();
        let budget = Arc::new(Semaphore::new(QUEUED_BYTES as usize));
        let mut replay = PacketReplay::default();
        let mut generation = 0u64;
        let mut buffer = vec![0; 65536];
        let result = loop {
            tokio::select! {
                _=stopped.changed()=>break Ok(()),
                Some(done)=workers.join_next(),if !workers.is_empty()=> {
                    if let Ok((key,generation))=done && associations.get(&key).is_some_and(|a|a.generation==generation) {associations.remove(&key);}
                },
                packet=socket.recv_from(&mut buffer)=> {
                    let (size,source)=match packet {Ok(pair)=>pair,Err(error)=>break Err(Error::Io(error))};
                    let snapshot=context.users.load_full();
                    let Some(credentials)=snapshot.shadowsocks.as_ref() else {continue;};
                    let Ok(mut decoded)=decrypt(credentials,&buffer[..size],&mut replay) else {continue;};
                    let key=(canonical(source),*blake3::hash(&decoded.user.key).as_bytes(),decoded.session,decoded.user.name.clone());
                    // Decrypted padding can leave retained Vec capacity much
                    // larger than the payload. Bound allocation, not just len.
                    let Ok(permit)=budget.clone().try_acquire_many_owned(decoded.packet.payload.capacity().max(1) as u32) else {continue;};
                    decoded.packet._budget=Some(permit);
                    if associations.get(&key).is_some_and(|a|a.sender.is_closed()) {associations.remove(&key);}
                    if let Some(association)=associations.get(&key) {let _=association.sender.try_send(decoded.packet);continue;}
                    if associations.len()>=MAX_ASSOCIATIONS || workers.len()>=MAX_ASSOCIATIONS {continue;}
                    let Some(policy)=snapshot.policy(&decoded.user.name) else {continue;};
                    let method=credentials.method;drop(snapshot);
                    let Ok(lease)=context.limits.acquire(decoded.user.name.clone(),source.ip(),policy) else {continue;};
                    let (sender,receiver)=mpsc::channel(8);
                    let _=sender.try_send(decoded.packet);
                    generation=generation.checked_add(1).ok_or(Error::Task)?;
                    associations.insert(key.clone(),Association{generation,sender});
                    let socket=socket.clone();let context=context.clone();let user=decoded.user;
                    workers.spawn(async move {let _=relay(socket,source,user,method,key.2,receiver,lease,context).await;(key,generation)});
                }
            }
        };
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        result
    });
    Ok(Handle {
        stop,
        task: Some(task),
    })
}

#[allow(clippy::too_many_arguments)]
async fn relay(
    inbound: Arc<UdpSocket>,
    source: SocketAddr,
    user: Arc<Credential>,
    method: shadowsocks::crypto::CipherKind,
    session: u64,
    mut packets: mpsc::Receiver<Packet>,
    lease: limits::Lease,
    context: Context,
) -> Result<(), Error> {
    let socket4 = UdpSocket::bind("0.0.0.0:0").await?;
    let socket6 = UdpSocket::bind("[::]:0").await.ok();
    let mut peers = HashSet::new();
    let counter = if context.traffic.enabled() {
        let name = user.name.clone();
        Some(
            context
                .traffic
                .blocking(move |t| t.user(name))
                .await
                .map_err(|_| Error::Task)??,
        )
    } else {
        None
    };
    let ctx = self::context();
    let mut random = [0u8; 8];
    ctx.generate_nonce(method, &mut random, false);
    let server_session = u64::from_ne_bytes(random);
    let mut packet_id = 0u64;
    let mut buffer = vec![0; 65536];
    let mut encrypted = BytesMut::new();
    let mut last = tokio::time::Instant::now();
    loop {
        let receive = tokio::select! {
            packet=packets.recv()=> {
                let Some(packet)=packet else {return Ok(());};
                let destination=match context.network.udp_destination(&packet.address,packet.port,source).await {Ok(value)=>value,Err(Error::Blocked|Error::Unsupported|Error::Dns)=>continue,Err(error)=>return Err(error)};
                if !peers.contains(&destination) && peers.len()>=64 {continue;}
                let socket=if destination.is_ipv4(){&socket4}else{socket6.as_ref().ok_or(Error::Unsupported)?};
                lease.charge(packet.payload.len(),&context.users).await;
                let size=socket.send_to(&packet.payload,destination).await?;
                if size!=packet.payload.len(){return Err(Error::Protocol);}
                peers.insert(destination);
                if let Some(counter)=&counter {counter.add(0,size);}
                last=tokio::time::Instant::now();continue;
            },
            ready=socket4.readable()=> {ready?;&socket4},
            ready=async {socket6.as_ref().expect("enabled IPv6 socket").readable().await},if socket6.is_some()=> {ready?;socket6.as_ref().unwrap()},
            _=tokio::time::sleep_until(last+IDLE)=>return Ok(()),
        };
        let (size, peer) = match receive.try_recv_from(&mut buffer) {
            Ok(pair) => pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error.into()),
        };
        let peer = canonical(peer);
        if !peers.contains(&peer) || size > MAX_PACKET {
            continue;
        }
        let mut control = UdpSocketControlData::default();
        control.client_session_id = session;
        control.server_session_id = server_session;
        control.packet_id = packet_id;
        packet_id = packet_id.checked_add(1).ok_or(Error::Protocol)?;
        encrypted.clear();
        crypto_io::encrypt_server_payload(
            &ctx,
            method,
            &user.key,
            &Address::SocketAddress(peer),
            &control,
            &buffer[..size],
            &mut encrypted,
        );
        if encrypted.len() > MAX_PACKET {
            continue;
        }
        lease.charge(size, &context.users).await;
        let sent = inbound.send_to(&encrypted, source).await?;
        if sent != encrypted.len() {
            return Err(Error::Protocol);
        }
        if let Some(counter) = &counter {
            counter.add(1, size);
        }
        last = tokio::time::Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::candidate;
    use super::*;
    use arc_swap::ArcSwap;
    use node_core::shadowsocks::{Cipher, user_password};
    use shadowsocks::config::{ServerConfig, ServerType};

    fn encrypted(method: Cipher, password: &str, target: Address, packet_id: u64) -> BytesMut {
        encrypted_payload(method, password, target, packet_id, b"datagram-roundtrip")
    }
    fn encrypted_payload(
        method: Cipher,
        password: &str,
        target: Address,
        packet_id: u64,
        payload: &[u8],
    ) -> BytesMut {
        let user = ServerConfig::new(
            ("127.0.0.1", 1),
            user_password(method, password).into_owned(),
            method.name().parse().unwrap(),
        )
        .unwrap();
        let server = ServerConfig::new(
            ("127.0.0.1", 1),
            user_password(method, "server-unique-key").into_owned(),
            method.name().parse().unwrap(),
        )
        .unwrap();
        let ctx = shadowsocks::context::Context::new(ServerType::Local);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 777;
        control.packet_id = packet_id;
        let keys = if method.is_v2() {
            vec![bytes::Bytes::copy_from_slice(server.key())]
        } else {
            vec![]
        };
        let mut encrypted = BytesMut::new();
        crypto_io::encrypt_client_payload(
            &ctx,
            user.method(),
            user.key(),
            &target,
            &control,
            &keys,
            payload,
            &mut encrypted,
        );
        encrypted
    }
    #[test]
    fn session_window_reorders_rejects_replay_and_ancient_packets() {
        let now = Instant::now();
        let mut window = Window::new(100, now);
        for packet in [99, 102, 101, 1200, 1198, 1199, 2170, 2168] {
            window.claim(packet, now).unwrap();
        }
        for packet in [100, 102, 1199, 1200, 2170, 2168, 0] {
            assert!(window.claim(packet, now).is_err());
        }
        window.claim(u64::MAX, now).unwrap();
        assert!(window.claim(u64::MAX, now).is_err());
    }
    #[test]
    fn vendored_udp_cache_uses_key_contents_even_when_storage_address_is_reused() {
        for name in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"] {
            let method: shadowsocks::crypto::CipherKind = name.parse().unwrap();
            let mut reused = vec![1; method.key_len()];
            let pointer = reused.as_ptr();
            let mut control = UdpSocketControlData::default();
            control.server_session_id = 987;
            control.client_session_id = 777;
            for marker in [1, 2, 3, 1] {
                reused.fill(marker);
                assert_eq!(pointer, reused.as_ptr());
                let mut body = BytesMut::new();
                crypto_io::encrypt_server_payload(
                    &context(),
                    method,
                    &reused,
                    &Address::SocketAddress("127.0.0.1:53".parse().unwrap()),
                    &control,
                    b"changed-secret",
                    &mut body,
                );
                let independent = reused.clone();
                let (size, _, _) =
                    crypto_io::decrypt_server_payload(&context(), method, &independent, &mut body)
                        .unwrap();
                assert_eq!(&body[..size], b"changed-secret");
            }
        }
    }
    #[test]
    fn empty_udp_response_padding_never_exposes_reused_buffer_contents() {
        use aes::{
            Aes128, Aes256,
            cipher::{BlockDecrypt, KeyInit},
        };
        use shadowsocks::crypto::v2::udp::UdpCipher;
        for name in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"] {
            let method: shadowsocks::crypto::CipherKind = name.parse().unwrap();
            let key = vec![42; method.key_len()];
            let mut control = UdpSocketControlData::default();
            control.server_session_id = 987;
            control.client_session_id = 777;
            for packet in 0..20 {
                control.packet_id = packet;
                let mut wire = BytesMut::from(vec![0xa5; 2048].as_slice());
                wire.clear();
                crypto_io::encrypt_server_payload(
                    &context(),
                    method,
                    &key,
                    &Address::SocketAddress("127.0.0.1:53".parse().unwrap()),
                    &control,
                    b"",
                    &mut wire,
                );
                let (header, body) = wire.split_at_mut(16);
                let mut block = aes::Block::default();
                block.copy_from_slice(header);
                if name.contains("aes-128") {
                    Aes128::new_from_slice(&key)
                        .unwrap()
                        .decrypt_block(&mut block);
                } else {
                    Aes256::new_from_slice(&key)
                        .unwrap()
                        .decrypt_block(&mut block);
                }
                header.copy_from_slice(&block);
                assert!(UdpCipher::new(method, &key, 987).decrypt_packet(&header[4..16], body));
                let padding = u16::from_be_bytes([body[17], body[18]]) as usize;
                assert!(body[19..19 + padding].iter().all(|byte| *byte == 0));
            }
        }
    }
    #[test]
    fn all_methods_udp_auth_replay_and_identity_survive_cache_key_reuse() {
        for method in [
            Cipher::Aes128,
            Cipher::Aes256,
            Cipher::Chacha20,
            Cipher::Aes128V2,
            Cipher::Aes256V2,
        ] {
            let snapshot =
                candidate(method, &[("7", "user-first-key"), ("8", "user-second-key")]).auth;
            let credentials = snapshot.shadowsocks.as_ref().unwrap();
            let target = Address::SocketAddress("127.0.0.1:53".parse().unwrap());
            let body = encrypted(method, "user-second-key", target.clone(), 10);
            let mut replay = PacketReplay::default();
            let result = decrypt(credentials, &body, &mut replay).unwrap();
            assert_eq!(&*result.user.name, "8");
            assert_eq!(result.packet.payload, b"datagram-roundtrip");
            assert!(decrypt(credentials, &body, &mut replay).is_err());
            let mut tampered = body.to_vec();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(decrypt(credentials, &tampered, &mut PacketReplay::default()).is_err());
            assert!(
                decrypt(
                    credentials,
                    &encrypted(method, "wrong-user", target.clone(), 11),
                    &mut replay
                )
                .is_err()
            );
            let replaced = candidate(method, &[("7", "replacement-key")]).auth;
            assert!(
                decrypt(
                    replaced.shadowsocks.as_ref().unwrap(),
                    &body,
                    &mut PacketReplay::default()
                )
                .is_err()
            );
            assert_eq!(
                &*decrypt(
                    replaced.shadowsocks.as_ref().unwrap(),
                    &encrypted(method, "replacement-key", target, 10),
                    &mut PacketReplay::default()
                )
                .unwrap()
                .user
                .name,
                "7"
            );
        }
    }
    #[tokio::test]
    async fn all_methods_datagram_relay_accounting_and_graceful_stop() {
        for method in [
            Cipher::Aes128,
            Cipher::Aes256,
            Cipher::Chacha20,
            Cipher::Aes128V2,
            Cipher::Aes256V2,
        ] {
            let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = origin.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut buffer = [0; 8192];
                for _ in 0..3 {
                    let (size, peer) = origin.recv_from(&mut buffer).await.unwrap();
                    origin.send_to(&buffer[..size], peer).await.unwrap();
                }
            });
            let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let bind = listener.local_addr().unwrap();
            drop(listener);
            let users: Users = Arc::new(ArcSwap::from(
                candidate(method, &[("7", "user-first-key")]).auth,
            ));
            let traffic = Arc::new(Traffic::new("ss-udp-test".into()));
            let handle = serve(
                bind,
                Context {
                    limits: Arc::new(limits::Registry::new(users.clone())),
                    users,
                    traffic: traffic.clone(),
                    network: Arc::new(Network::direct()),
                },
                Arc::new(Service::new()),
            )
            .await
            .unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for (index, payload) in [vec![], b"datagram-roundtrip".to_vec(), vec![42; 8000]]
                .iter()
                .enumerate()
            {
                let body = encrypted_payload(
                    method,
                    "user-first-key",
                    Address::SocketAddress(target),
                    index as u64 + 1,
                    payload,
                );
                client.send_to(&body, bind).await.unwrap();
                let mut response = vec![0; 65536];
                let (size, _) =
                    tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut response))
                        .await
                        .unwrap()
                        .unwrap();
                let key = ServerConfig::new(
                    ("127.0.0.1", 1),
                    user_password(method, "user-first-key").into_owned(),
                    method.name().parse().unwrap(),
                )
                .unwrap();
                let (size, from, _) = crypto_io::decrypt_server_payload(
                    &context(),
                    key.method(),
                    key.key(),
                    &mut response[..size],
                )
                .unwrap();
                assert_eq!(from, Address::SocketAddress(target));
                assert_eq!(&response[..size], payload);
            }
            echo.await.unwrap();
            handle.shutdown().await.unwrap();
            assert!(UdpSocket::bind(bind).await.is_ok());
            assert_eq!(
                traffic.snapshot().unwrap().unwrap().traffic["7"],
                [8018, 8018]
            );
        }
    }
    #[tokio::test]
    async fn hot_reassigned_key_on_same_source_uses_new_user_counter() {
        for method in [Cipher::Aes128, Cipher::Aes128V2] {
            let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = origin.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut buffer = [0; 4096];
                for _ in 0..2 {
                    let (size, peer) = origin.recv_from(&mut buffer).await.unwrap();
                    origin.send_to(&buffer[..size], peer).await.unwrap();
                }
            });
            let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let bind = listener.local_addr().unwrap();
            drop(listener);
            let users: Users = Arc::new(ArcSwap::from(
                candidate(method, &[("7", "shared-key")]).auth,
            ));
            let traffic = Arc::new(Traffic::new("ss-reassign-test".into()));
            let handle = serve(
                bind,
                Context {
                    limits: Arc::new(limits::Registry::new(users.clone())),
                    users: users.clone(),
                    traffic: traffic.clone(),
                    network: Arc::new(Network::direct()),
                },
                Arc::new(Service::new()),
            )
            .await
            .unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut buffer = [0; 4096];
            for packet_id in [1, 2] {
                if packet_id == 2 {
                    users.store(candidate(method, &[("8", "shared-key")]).auth);
                }
                let packet = encrypted(
                    method,
                    "shared-key",
                    Address::SocketAddress(target),
                    packet_id,
                );
                client.send_to(&packet, bind).await.unwrap();
                tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            }
            handle.shutdown().await.unwrap();
            echo.await.unwrap();
            let counters = traffic.snapshot().unwrap().unwrap().traffic;
            assert_eq!(counters["7"], [18, 18]);
            assert_eq!(counters["8"], [18, 18]);
        }
    }
}
