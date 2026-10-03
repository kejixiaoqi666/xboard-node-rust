//! Native integration of pinned MIT shadowsocks-rust framing/crypto.
//! Multi-user identification and bounded replay storage are owned here.
#![cfg_attr(not(any(unix, test)), allow(dead_code, unused_imports))]
use crate::Error;
use node_core::shadowsocks::Settings;
use shadowsocks::{
    config::{ServerConfig, ServerType, ServerUser, ServerUserManager},
    crypto::CipherKind,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(crate) struct Credential {
    pub name: Arc<str>,
    pub key: Vec<u8>,
}
pub(crate) struct Credentials {
    pub method: CipherKind,
    pub server_key: Vec<u8>,
    pub users: Vec<Arc<Credential>>,
    pub identities: HashMap<[u8; 16], Arc<Credential>>,
    pub manager: Arc<ServerUserManager>,
}
impl Credentials {
    pub fn new(settings: &Settings, users: Vec<(Arc<str>, String)>) -> Result<Self, Error> {
        settings.validate().map_err(|_| Error::Config)?;
        if users.len() > settings.method.max_users() {
            return Err(Error::Auth);
        }
        let method = settings
            .method
            .name()
            .parse::<CipherKind>()
            .map_err(|_| Error::Config)?;
        let mut out = Self {
            method,
            server_key: Vec::new(),
            users: Vec::with_capacity(users.len()),
            identities: HashMap::new(),
            manager: Arc::new(ServerUserManager::new()),
        };
        if settings.method.is_v2() {
            out.server_key = ServerConfig::new(
                ("127.0.0.1", 1),
                settings.password.as_deref().ok_or(Error::Config)?,
                method,
            )
            .map_err(|_| Error::Config)?
            .key()
            .to_vec();
        }
        let mut seen = HashSet::with_capacity(users.len());
        for (name, password) in users {
            if settings.method.is_v2() {
                Settings {
                    method: settings.method,
                    password: Some(password.clone()),
                }
                .validate()
                .map_err(|_| Error::Auth)?;
            }
            let key = ServerConfig::new(("127.0.0.1", 1), password, method)
                .map_err(|_| Error::Auth)?
                .key()
                .to_vec();
            if !seen.insert(key.clone()) {
                return Err(Error::Auth);
            }
            let credential = Arc::new(Credential {
                name: name.clone(),
                key: key.clone(),
            });
            if settings.method.is_v2() {
                let user = ServerUser::new(name.to_string(), key);
                let hash: [u8; 16] = user.identity_hash().try_into().map_err(|_| Error::Auth)?;
                if out.identities.insert(hash, credential.clone()).is_some() {
                    return Err(Error::Auth);
                }
                Arc::get_mut(&mut out.manager)
                    .expect("unshared manager")
                    .add_user(user);
            }
            out.users.push(credential);
        }
        Ok(out)
    }
}

const MAX_REPLAY: usize = 65536;
const REPLAY_WINDOW: Duration = Duration::from_secs(120);
/// TCP replay scope is one process and 120 seconds, surviving user updates.
/// Never evict unexpired entries to admit new traffic: at capacity, fail closed.
#[derive(Default)]
pub(crate) struct Replay {
    set: HashSet<[u8; 32]>,
    order: VecDeque<(Instant, [u8; 32])>,
}
impl Replay {
    fn claim(&mut self, key: &[u8], salt: &[u8], now: Instant) -> Result<(), Error> {
        self.claim_with_window(key, salt, now, REPLAY_WINDOW)
    }
    fn claim_with_window(
        &mut self,
        key: &[u8],
        salt: &[u8],
        now: Instant,
        window: Duration,
    ) -> Result<(), Error> {
        while self
            .order
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= window)
        {
            let (_, hash) = self.order.pop_front().unwrap();
            self.set.remove(&hash);
        }
        let hash = *blake3::hash(&[key, salt].concat()).as_bytes();
        if self.set.contains(&hash) {
            return Err(Error::Auth);
        }
        if self.set.len() >= MAX_REPLAY {
            return Err(Error::Limited);
        }
        self.set.insert(hash);
        self.order.push_back((now, hash));
        Ok(())
    }
}

pub(crate) struct Service {
    pub replay: Mutex<Replay>,
    pub handshakes: Arc<tokio::sync::Semaphore>,
}
impl Service {
    pub fn new() -> Self {
        Self {
            replay: Mutex::new(Replay::default()),
            handshakes: Arc::new(tokio::sync::Semaphore::new(64)),
        }
    }
    fn claim(&self, key: &[u8], salt: &[u8]) -> Result<(), Error> {
        self.replay
            .lock()
            .map_err(|_| Error::Task)?
            .claim(key, salt, Instant::now())
    }
}

#[cfg(any(unix, test))]
pub(crate) fn context() -> Arc<shadowsocks::context::Context> {
    // Per TCP connection: the library's AEAD2022 nonce cache cannot grow
    // unbounded across connections; our process replay gate is shared.
    Arc::new(shadowsocks::context::Context::new(ServerType::Server))
}

#[cfg(any(unix, test))]
pub(crate) fn address(
    value: shadowsocks::relay::socks5::Address,
) -> Result<(crate::protocol::Address, u16), Error> {
    use shadowsocks::relay::socks5::Address;
    let (address, port) = match value {
        Address::SocketAddress(a) => (crate::protocol::Address::Ip(a.ip()), a.port()),
        Address::DomainNameAddress(name, port) => {
            if !node_core::routing::valid_domain(&name) {
                return Err(Error::Protocol);
            }
            (crate::protocol::Address::Domain(name), port)
        }
    };
    if port == 0 {
        return Err(Error::Protocol);
    }
    Ok((address, port))
}

#[cfg(any(unix, test))]
fn identity(credentials: &Credentials, prefix: &[u8]) -> Result<Arc<Credential>, Error> {
    use aes::{
        Aes128, Aes256,
        cipher::{BlockDecrypt, KeyInit},
    };
    let n = credentials.method.key_len();
    let subkey = blake3::derive_key(
        "shadowsocks 2022 identity subkey",
        &[credentials.server_key.as_slice(), &prefix[..n]].concat(),
    );
    let mut block = aes::Block::default();
    block.copy_from_slice(&prefix[n..n + 16]);
    match credentials.method {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM => Aes128::new_from_slice(&subkey[..16])
            .map_err(|_| Error::Auth)?
            .decrypt_block(&mut block),
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM => Aes256::new_from_slice(&subkey)
            .map_err(|_| Error::Auth)?
            .decrypt_block(&mut block),
        _ => return Err(Error::Unsupported),
    }
    credentials
        .identities
        .get(&block[..])
        .cloned()
        .ok_or(Error::Auth)
}

#[cfg(any(unix, test))]
struct Prefix<S> {
    prefix: bytes::Bytes,
    stream: S,
}
#[cfg(any(unix, test))]
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Prefix<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use bytes::Buf;
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
#[cfg(any(unix, test))]
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Prefix<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(any(unix, test))]
pub(crate) async fn connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    service: &Service,
    context: crate::ConnectionContext<'_>,
) -> Result<(), Error> {
    use shadowsocks::relay::tcprelay::proxy_stream::ProxyServerStream;
    use tokio::io::AsyncReadExt;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let slot = service
        .handshakes
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Limited)?;
    let (stream, request) = tokio::time::timeout_at(deadline, async {
        let snapshot = context.users.load_full();
        let credentials = snapshot.shadowsocks.as_ref().ok_or(Error::Config)?;
        let method = credentials.method;
        let n = method.key_len();
        // Upstream's 2022 reader requires its entire fixed header in one read.
        // Buffer salt + EIH + type + timestamp + length + tag, so TCP packet
        // fragmentation and our credential pre-read cannot shorten that read.
        let mut prefix = vec![0; n + if method.is_aead_2022() { 43 } else { 18 }];
        stream.read_exact(&mut prefix).await?;
        let selected = if method.is_aead_2022() {
            identity(credentials, &prefix)?
        } else {
            credentials
                .users
                .iter()
                .find(|user| {
                    let mut header = prefix[n..].to_vec();
                    let mut cipher =
                        shadowsocks::crypto::v1::Cipher::new(method, &user.key, &prefix[..n]);
                    cipher.decrypt_packet(&mut header)
                        && (1..=0x3fff).contains(&u16::from_be_bytes([header[0], header[1]]))
                })
                .cloned()
                .ok_or(Error::Auth)?
        };
        let policy = snapshot.policy(&selected.name).ok_or(Error::Auth)?;
        let mut manager = ServerUserManager::new();
        if method.is_aead_2022() {
            manager.add_user(ServerUser::new(
                selected.name.to_string(),
                selected.key.clone(),
            ));
        }
        let key = if method.is_aead_2022() {
            &credentials.server_key
        } else {
            &selected.key
        };
        let salt = prefix[..n].to_vec();
        let mut encrypted = ProxyServerStream::from_stream_with_user_manager(
            self::context(),
            Prefix {
                prefix: prefix.into(),
                stream,
            },
            method,
            key,
            method.is_aead_2022().then(|| Arc::new(manager)),
        );
        drop(snapshot);
        let (address, port) = address(encrypted.handshake().await?)?;
        service.claim(&selected.key, &salt)?;
        let request = crate::protocol::Request {
            user: selected.name.clone(),
            policy,
            address,
            port,
            command: crate::protocol::Command::Tcp,
            vision_uuid: None,
        };
        Ok::<_, Error>((encrypted, request))
    })
    .await
    .map_err(|_| Error::Protocol)??;
    drop(slot);
    crate::connection_authenticated(
        stream,
        crate::config::Protocol::Shadowsocks,
        request,
        false,
        deadline,
        context,
    )
    .await
}

#[cfg(any(unix, test))]
mod udp;
#[cfg(unix)]
pub(crate) use udp::serve as serve_udp;
#[cfg(unix)]
pub(crate) use udp::{Context as UdpContext, Handle as UdpHandle};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{auth, config, limits, network, traffic};
    use arc_swap::ArcSwap;
    use node_core::shadowsocks::{Cipher, user_password};
    use shadowsocks::relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const METHODS: [Cipher; 5] = [
        Cipher::Aes128,
        Cipher::Aes256,
        Cipher::Chacha20,
        Cipher::Aes128V2,
        Cipher::Aes256V2,
    ];
    pub(super) fn candidate(method: Cipher, passwords: &[(&str, &str)]) -> config::Candidate {
        let mut value = crate::tests::config(serde_json::json!([]));
        let inbound = &mut value["inbounds"][0];
        inbound["type"] = serde_json::json!("shadowsocks");
        inbound["method"] = serde_json::json!(method);
        if method.is_v2() {
            inbound["password"] = serde_json::json!(user_password(method, "server-unique-key"));
        }
        inbound["users"]=serde_json::json!(passwords.iter().map(|(name,key)|serde_json::json!({"name":name,"password":user_password(method,key)})).collect::<Vec<_>>());
        config::decode(value.to_string().as_bytes()).unwrap()
    }
    fn client_config(method: Cipher, user: &str) -> ServerConfig {
        let password = if method.is_v2() {
            format!(
                "{}:{}",
                user_password(method, "server-unique-key"),
                user_password(method, user)
            )
        } else {
            user.into()
        };
        ServerConfig::new(("127.0.0.1", 1), password, method.name().parse().unwrap()).unwrap()
    }
    #[test]
    fn derived_keys_collision_and_hot_base_boundaries() {
        for method in METHODS {
            let a = candidate(method, &[("7", "user-first-key"), ("8", "user-second-key")]);
            let b = candidate(method, &[("8", "user-second-key")]);
            assert_eq!(a.base, b.base);
            assert!(b.auth.policy("7").is_none());
            assert_eq!(b.auth.shadowsocks.as_ref().unwrap().users.len(), 1);
            let duplicate = Settings {
                method,
                password: a.base.shadowsocks.unwrap().password,
            };
            assert!(
                Credentials::new(
                    &duplicate,
                    vec![
                        (
                            Arc::from("7"),
                            user_password(method, "identical").into_owned()
                        ),
                        (
                            Arc::from("8"),
                            user_password(method, "identical").into_owned()
                        )
                    ]
                )
                .is_err()
            );
        }
    }
    #[test]
    fn replay_capacity_expiry_and_credentials_are_isolated() {
        let now = Instant::now();
        let mut replay = Replay::default();
        replay.claim(b"key", b"nonce", now).unwrap();
        assert!(replay.claim(b"key", b"nonce", now).is_err());
        replay.claim(b"other", b"nonce", now).unwrap();
        for n in 2..MAX_REPLAY {
            replay
                .claim(b"key", &(n as u64).to_le_bytes(), now)
                .unwrap();
        }
        assert!(matches!(
            replay.claim(b"key", b"full", now),
            Err(Error::Limited)
        ));
        assert!(replay.claim(b"key", b"nonce", now + REPLAY_WINDOW).is_ok());
        assert_eq!(replay.set.len(), 1);
    }
    #[tokio::test]
    async fn all_methods_tcp_multichunk_half_close_and_exact_payload_accounting() {
        for method in METHODS {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = origin.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut socket, _) = origin.accept().await.unwrap();
                let mut data = Vec::new();
                socket.read_to_end(&mut data).await.unwrap();
                assert_eq!(data.len(), 131072);
                socket.write_all(&data).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let users: auth::Users = Arc::new(ArcSwap::from(
                candidate(method, &[("7", "user-first-key"), ("8", "user-second-key")]).auth,
            ));
            let counters = Arc::new(traffic::Traffic::new("ss-tcp-test".into()));
            let copy = counters.clone();
            let (server, client) = tokio::io::duplex(2048);
            let task = tokio::spawn(async move {
                let limits = Arc::new(limits::Registry::new(users.clone()));
                let slots = Arc::new(tokio::sync::Semaphore::new(1024));
                let network = network::Network::direct();
                let result = connection(
                    server,
                    &Service::new(),
                    crate::ConnectionContext {
                        users: &users,
                        traffic: &copy,
                        limits: &limits,
                        udp_slots: &slots,
                        network: &network,
                        source: "127.0.0.1:12345".parse().unwrap(),
                    },
                )
                .await;
                assert!(result.is_ok(), "{method:?}: {result:?}");
                result
            });
            let client_context = Arc::new(shadowsocks::context::Context::new(ServerType::Local));
            let mut client = ProxyClientStream::from_stream(
                client_context,
                client,
                &client_config(method, "user-second-key"),
                Address::SocketAddress(target),
            );
            let payload = (0..131072).map(|n| (n % 251) as u8).collect::<Vec<_>>();
            // The upstream test client expects its first address-bearing write
            // to fit one AEAD frame; the remaining application data spans many.
            client.write_all(&payload[..1024]).await.unwrap();
            client.flush().await.unwrap();
            client.write_all(&payload[1024..]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut returned = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut returned))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(returned, payload);
            task.await.unwrap().unwrap();
            echo.await.unwrap();
            assert_eq!(
                counters.snapshot().unwrap().unwrap().traffic["8"],
                [131072, 131072]
            );
        }
    }
}
