//! Business acceptance at the real native Host boundary. Every payload crosses
//! a local socket; the SOCKS fixture is an independent wire-level UDP relay.
use super::*;
use arc_swap::ArcSwap;
use node_core::routing::{Outbound, Route, Rule};
use std::{
    future::poll_fn,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const UUID: &str = "00000000-0000-4000-8000-000000000007";
const OTHER_UUID: &str = "00000000-0000-4000-8000-000000000008";
const PASSWORD: &str = "session-fixture-password";
const TAG: &str = "session-integration-node";

fn configured_user(
    name: &str,
    uuid: &str,
    password: &str,
    speed: i64,
    devices: i64,
) -> crate::config::User {
    crate::config::User {
        name: name.into(),
        uuid: Some(uuid.into()),
        password: Some(password.into()),
        flow: None,
        speed_limit: speed,
        device_limit: devices,
    }
}

struct Environment {
    host: Arc<SessionHost>,
    users: auth::Users,
    limits: Arc<limits::Registry>,
    traffic: Arc<traffic::Traffic>,
    slots: Arc<Semaphore>,
    network: Arc<network::Network>,
}
impl Environment {
    fn new(speed: i64, devices: i64, enabled: bool, proxy: Option<Outbound>) -> Self {
        let users = Arc::new(ArcSwap::from_pointee(
            auth::Snapshot::new(
                crate::config::Protocol::Tuic,
                vec![configured_user("7", UUID, PASSWORD, speed, devices)],
            )
            .unwrap(),
        ));
        let limits = Arc::new(limits::Registry::new(users.clone()));
        let traffic = Arc::new(traffic::Traffic::new_with_enabled("7".repeat(32), enabled));
        let slots = Arc::new(Semaphore::new(4));
        let mut route = Route::default();
        let mut outbounds = vec![Outbound::plain("direct", "direct")];
        if let Some(proxy) = proxy {
            route.rules.push(Rule {
                outbound: proxy.tag.clone(),
                network: vec!["tcp".into(), "udp".into()],
                user: vec!["7".into()],
                inbound: vec![TAG.into()],
                ..Default::default()
            });
            outbounds.push(proxy);
        }
        let network = Arc::new(network::Network::new(&route, &outbounds, None).unwrap());
        let host = Arc::new(SessionHost::new(
            users.clone(),
            limits.clone(),
            traffic.clone(),
            network.clone(),
            slots.clone(),
            Arc::from(TAG),
        ));
        Self {
            host,
            users,
            limits,
            traffic,
            slots,
            network,
        }
    }
    fn user(&self) -> User {
        self.host.users()[0].clone()
    }
    fn replace(&self, users: Vec<crate::config::User>) {
        self.users.store(Arc::new(
            auth::Snapshot::new(crate::config::Protocol::Tuic, users).unwrap(),
        ));
        // This is the notification emitted by successful production control replace.
        self.limits.notify_users_changed();
    }
    fn assert_empty(&self) {
        let activity = self.limits.activity();
        assert_eq!(activity.sessions, 0);
        assert!(activity.alive.is_empty());
        assert!(activity.online.is_empty());
        assert!(activity.validate());
        assert_eq!(self.slots.available_permits(), 4);
    }
    fn assert_traffic(&self, up: usize, down: usize) {
        let snapshot = self.traffic.snapshot().unwrap().unwrap();
        assert_eq!(snapshot.traffic.get("7"), Some(&[up as u64, down as u64]));
        assert_eq!(snapshot.traffic.len(), 1);
    }
}

fn destination(address: SocketAddr) -> Destination {
    Destination::new(address.ip().to_string(), address.port()).unwrap()
}
fn peer(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), 19007)
}
fn assert_denied<T>(result: io::Result<T>) {
    match result {
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::ConnectionAborted
        )),
        Ok(_) => panic!("revoked profile was allowed to continue"),
    }
}
fn assert_limited<T>(result: io::Result<T>) {
    match result {
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        Ok(_) => panic!("shared resource limit was bypassed"),
    }
}

struct FixtureTask {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
}
impl FixtureTask {
    async fn finish(mut self) {
        let _ = self.stop.send(true);
        timeout(Duration::from_secs(2), self.task.as_mut().unwrap())
            .await
            .expect("fixture failed to stop")
            .expect("fixture task failed")
            .expect("fixture I/O failed");
        self.task.take();
    }
}
impl Drop for FixtureTask {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct TcpEcho {
    target: Destination,
    task: FixtureTask,
}
impl TcpEcho {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = destination(listener.local_addr().unwrap());
        let (stop, mut changed) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut streams = JoinSet::new();
            loop {
                tokio::select! {
                    _ = changed.changed() => break,
                    _ = streams.join_next(), if !streams.is_empty() => {},
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        streams.spawn(async move {
                            let (mut read, mut write) = stream.into_split();
                            // Reset/EOF are expected when a client is cancelled or revoked.
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                        });
                    }
                }
            }
            streams.abort_all();
            while streams.join_next().await.is_some() {}
            Ok(())
        });
        Self {
            target,
            task: FixtureTask {
                stop,
                task: Some(task),
            },
        }
    }
    async fn finish(self) {
        self.task.finish().await;
    }
}

struct UdpEcho {
    target: Destination,
    address: SocketAddr,
    sources: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    task: FixtureTask,
}
impl UdpEcho {
    async fn start(inject_rogue: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let sources = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = sources.clone();
        let (stop, mut changed) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut buffer = vec![0; 65535];
            loop {
                tokio::select! {
                    _ = changed.changed() => return Ok(()),
                    packet = socket.recv_from(&mut buffer) => {
                        let (n, from) = packet?;
                        {
                            let mut peers = seen.lock().unwrap();
                            if peers.len() >= 256 {return Err(io::Error::other("fixture packet bound exceeded"));}
                            peers.push(from);
                        }
                        if inject_rogue {
                            let attacker = UdpSocket::bind("127.0.0.1:0").await?;
                            attacker.send_to(b"unsolicited-not-billable", from).await?;
                        }
                        socket.send_to(&buffer[..n], from).await?;
                    }
                }
            }
        });
        Self {
            target: destination(address),
            address,
            sources,
            task: FixtureTask {
                stop,
                task: Some(task),
            },
        }
    }
    async fn finish(self) {
        self.task.finish().await;
    }
}

#[derive(Default)]
struct ProxyStats {
    active: AtomicUsize,
    handshakes: AtomicUsize,
    payload: AtomicUsize,
    wire: AtomicUsize,
}
struct ActiveControl(Arc<ProxyStats>);
impl Drop for ActiveControl {
    fn drop(&mut self) {
        self.0.active.store(0, Ordering::Release);
    }
}
struct SocksRelay {
    outbound: Outbound,
    forward_address: SocketAddr,
    stats: Arc<ProxyStats>,
    task: FixtureTask,
}
impl SocksRelay {
    async fn start(origin: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let forward = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forward_address = forward.local_addr().unwrap();
        let mut outbound = Outbound::plain("socks-fixture", "socks");
        outbound.server = Some(address.ip());
        outbound.server_port = Some(address.port());
        outbound.username = Some("fixture-user".into());
        outbound.password = Some("fixture-password".into());
        let stats = Arc::new(ProxyStats::default());
        let observed = stats.clone();
        let (stop, mut changed) = watch::channel(false);
        let task = tokio::spawn(async move {
            let (mut control, _) = tokio::select! {
                _ = changed.changed() => return Ok(()), accepted = listener.accept() => accepted?,
            };
            observed.active.store(1, Ordering::Release);
            let _active = ActiveControl(observed.clone());
            tokio::select! {
                _ = changed.changed() => return Ok(()),
                result = async {
                    let mut greeting = [0; 3]; control.read_exact(&mut greeting).await?;
                    if greeting != [5, 1, 2] {return Err(io::Error::other("SOCKS auth method bypassed"));}
                    control.write_all(&[5, 2]).await?;
                    if control.read_u8().await? != 1 {return Err(io::Error::other("SOCKS auth version"));}
                    let n = control.read_u8().await? as usize; let mut user = vec![0; n]; control.read_exact(&mut user).await?;
                    let n = control.read_u8().await? as usize; let mut password = vec![0; n]; control.read_exact(&mut password).await?;
                    if user != b"fixture-user" || password != b"fixture-password" {return Err(io::Error::other("SOCKS authentication"));}
                    control.write_all(&[1, 0]).await?;
                    let mut request = [0; 10]; control.read_exact(&mut request).await?;
                    if request != [5, 3, 0, 1, 0, 0, 0, 0, 0, 0] {return Err(io::Error::other("SOCKS UDP association"));}
                    let std::net::IpAddr::V4(ip) = relay_address.ip() else {unreachable!()};
                    let mut response = vec![5, 0, 0, 1]; response.extend(ip.octets()); response.extend(relay_address.port().to_be_bytes());
                    control.write_all(&response).await?;
                    Ok::<_, io::Error>(())
                } => result?,
            }
            observed.handshakes.fetch_add(1, Ordering::Relaxed);
            let mut packet = vec![0; 65535];
            let mut response = vec![0; 65535];
            loop {
                tokio::select! {
                    _ = changed.changed() => return Ok(()),
                    closed = control.read_u8() => match closed {
                        Err(error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset) => return Ok(()),
                        value => return Err(io::Error::other(format!("unexpected SOCKS control data: {value:?}"))),
                    },
                    incoming = relay.recv_from(&mut packet) => {
                        let (n, client) = incoming?;
                        if n < 10 || packet[..4] != [0, 0, 0, 1] {return Err(io::Error::other("SOCKS UDP frame"));}
                        let target = SocketAddr::new(std::net::IpAddr::from(<[u8; 4]>::try_from(&packet[4..8]).unwrap()), u16::from_be_bytes([packet[8], packet[9]]));
                        if target != origin {return Err(io::Error::other("SOCKS target mismatch"));}
                        observed.wire.fetch_add(n, Ordering::Relaxed); observed.payload.fetch_add(n - 10, Ordering::Relaxed);
                        forward.send_to(&packet[10..n], origin).await?;
                        let (size, from) = timeout(Duration::from_secs(1), forward.recv_from(&mut response)).await.map_err(|_| io::Error::other("origin did not echo"))??;
                        if from != origin {return Err(io::Error::other("origin source mismatch"));}
                        // A frame from the genuine relay with an unrequested embedded
                        // target must also be filtered before native payload counters.
                        let mut rogue = packet[..10].to_vec(); rogue[8..10].copy_from_slice(&origin.port().wrapping_add(1).to_be_bytes());
                        rogue.extend(b"rogue-relayed-target"); relay.send_to(&rogue, client).await?;
                        let mut reply = packet[..10].to_vec(); reply.extend(&response[..size]); relay.send_to(&reply, client).await?;
                    }
                }
            }
        });
        Self {
            outbound,
            forward_address,
            stats,
            task: FixtureTask {
                stop,
                task: Some(task),
            },
        }
    }
    async fn wait_closed(&self) {
        timeout(Duration::from_secs(1), async {
            while self.stats.active.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping native channel retained SOCKS control connection");
    }
    async fn finish(self) {
        self.task.finish().await;
    }
}

async fn udp_roundtrip(channel: &Arc<dyn Datagram>, target: &Destination, body: &[u8]) {
    assert_eq!(channel.send(body, target).await.unwrap(), body.len());
    let mut buffer = vec![0; 65535];
    let (n, source) = timeout(Duration::from_secs(2), channel.receive(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, body.len());
    assert_eq!(&buffer[..n], body);
    assert_eq!(&source, target);
}

#[tokio::test]
async fn real_tcp_and_udp_payload_are_counted_once_and_rogue_packets_are_not_billed() {
    let tcp = TcpEcho::start().await;
    let udp = UdpEcho::start(true).await;
    let env = Environment::new(0, 1, true, None);
    let user = env.user();
    let source = peer("127.0.0.1");
    let mut stream = env.host.connect(&user, source, &tcp.target).await.unwrap();
    let body: Vec<_> = (0..27031).map(|n| (n % 251) as u8).collect();
    stream.write_all(&body).await.unwrap();
    stream.flush().await.unwrap();
    let mut received: Vec<u8> = Vec::new();
    let mut fragment = [0; 257];
    while received.len() < body.len() {
        let n = timeout(Duration::from_secs(2), stream.read(&mut fragment))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        received.extend_from_slice(&fragment[..n]);
    }
    assert_eq!(received, body);
    let channel = env.host.datagram(&user, source).await.unwrap();
    let mut total = body.len();
    for size in [0, 37, 65507] {
        udp_roundtrip(&channel, &udp.target, &vec![0x73; size]).await;
        total += size;
    }
    drop(stream);
    drop(channel);
    env.assert_traffic(total, total);
    env.assert_empty();
    tcp.finish().await;
    udp.finish().await;
}

#[tokio::test]
async fn real_udp_receive_accepts_fitting_protocol_buffers_without_truncation_or_false_counting() {
    let origin = UdpEcho::start(false).await;
    let env = Environment::new(0, 1, true, None);
    let channel = env
        .host
        .datagram(&env.user(), peer("127.0.0.1"))
        .await
        .unwrap();
    let mut received = [0x9b; 64];
    channel
        .send(b"fitting-payload", &origin.target)
        .await
        .unwrap();
    let (len, from) = timeout(Duration::from_secs(2), channel.receive(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..len], b"fitting-payload");
    assert_eq!(from, origin.target);
    let before = received;
    channel.send(&[0x4d; 65], &origin.target).await.unwrap();
    let error = timeout(Duration::from_secs(2), channel.receive(&mut received))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(received, before, "oversized packet was partially copied");
    channel
        .send(b"after-rejection", &origin.target)
        .await
        .unwrap();
    let (len, _) = timeout(Duration::from_secs(2), channel.receive(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..len], b"after-rejection");
    drop(channel);
    env.assert_traffic(
        b"fitting-payload".len() + 65 + b"after-rejection".len(),
        b"fitting-payload".len() + b"after-rejection".len(),
    );
    env.assert_empty();
    origin.finish().await;
}

#[tokio::test]
async fn real_vless_udp_transport_header_and_auth_do_not_double_count_host_payload() {
    let origin = UdpEcho::start(true).await;
    let users = Arc::new(ArcSwap::from_pointee(
        auth::Snapshot::new(
            crate::config::Protocol::Vless,
            vec![crate::config::User {
                name: "7".into(),
                uuid: Some(UUID.into()),
                password: None,
                flow: None,
                speed_limit: 0,
                device_limit: 1,
            }],
        )
        .unwrap(),
    ));
    let limits = Arc::new(limits::Registry::new(users.clone()));
    let traffic = Arc::new(traffic::Traffic::new_with_enabled("8".repeat(32), true));
    let slots = Arc::new(Semaphore::new(1));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, source) = listener.accept().await.unwrap();
    let (server_users, server_limits, server_traffic, server_slots) = (
        users.clone(),
        limits.clone(),
        traffic.clone(),
        slots.clone(),
    );
    let connection = tokio::spawn(async move {
        crate::connection(
            server,
            crate::config::Protocol::Vless,
            &server_users,
            &server_traffic,
            source.ip(),
            &server_limits,
            &server_slots,
        )
        .await
    });
    let mut handshake = vec![0];
    handshake.extend(auth::uuid(UUID).unwrap());
    handshake.extend([0, 2]);
    handshake.extend(origin.address.port().to_be_bytes());
    handshake.extend([1, 127, 0, 0, 1]);
    client.write_all(&handshake).await.unwrap();
    assert_eq!(client.read_u16().await.unwrap(), 0);
    let mut total = 0;
    for size in [0usize, 61, 5000] {
        let payload = vec![0x84; size];
        client.write_u16(size as u16).await.unwrap();
        client.write_all(&payload).await.unwrap();
        let n = timeout(Duration::from_secs(2), client.read_u16())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n as usize, size);
        let mut reply = vec![0; size];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, payload);
        total += size;
    }
    drop(client);
    timeout(Duration::from_secs(2), connection)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        traffic.snapshot().unwrap().unwrap().traffic["7"],
        [total as u64, total as u64]
    );
    assert_eq!(limits.activity().sessions, 0);
    assert_eq!(slots.available_permits(), 1);
    origin.finish().await;
}

#[tokio::test]
async fn tcp_udp_and_mapped_sources_share_one_device_gate_but_users_remain_independent() {
    let tcp = TcpEcho::start().await;
    let env = Environment::new(0, 1, false, None);
    env.replace(vec![
        configured_user("7", UUID, PASSWORD, 0, 1),
        configured_user("8", OTHER_UUID, "other-user-password", 0, 1),
    ]);
    let profiles = env.host.users();
    let user = profiles.iter().find(|user| &*user.name == "7").unwrap();
    let other = profiles.iter().find(|user| &*user.name == "8").unwrap();
    let first = env
        .host
        .connect(user, peer("127.0.0.1"), &tcp.target)
        .await
        .unwrap();
    let second = env
        .host
        .connect(user, peer("127.0.0.1"), &tcp.target)
        .await
        .unwrap();
    let mapped = env
        .host
        .connect(user, peer("::ffff:127.0.0.1"), &tcp.target)
        .await
        .unwrap();
    let udp = env.host.datagram(user, peer("127.0.0.1")).await.unwrap();
    assert_limited(env.host.connect(user, peer("127.0.0.2"), &tcp.target).await);
    assert_limited(env.host.datagram(user, peer("127.0.0.2")).await);
    let independent = env
        .host
        .connect(other, peer("127.0.0.2"), &tcp.target)
        .await
        .unwrap();
    let activity = env.limits.activity();
    assert!(activity.validate());
    assert_eq!(activity.alive[&7], vec!["127.0.0.1".to_owned()]);
    assert_eq!(activity.online[&7], 4);
    assert_eq!(activity.alive[&8], vec!["127.0.0.2".to_owned()]);
    assert_eq!(activity.sessions, 5);
    drop((first, second, mapped, udp, independent));
    env.assert_empty();
    tcp.finish().await;
}

#[tokio::test]
async fn real_tcp_streams_and_udp_share_the_user_rate_bucket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = destination(listener.local_addr().unwrap());
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = destination(origin.local_addr().unwrap());
    let env = Environment::new(1, 1, false, None);
    let user = env.user();
    let source = peer("127.0.0.1");
    let mut first = env.host.connect(&user, source, &target).await.unwrap();
    let (mut first_peer, _) = listener.accept().await.unwrap();
    let mut second = env.host.connect(&user, source, &target).await.unwrap();
    let (mut second_peer, _) = listener.accept().await.unwrap();
    let udp = env.host.datagram(&user, source).await.unwrap();
    udp.send(&[], &udp_target).await.unwrap();
    let mut buffer = vec![0; 65535];
    assert_eq!(origin.recv_from(&mut buffer).await.unwrap().0, 0);
    // Only the rate clock is paused: all TCP/UDP sockets are already real and open.
    tokio::time::pause();
    first.write_all(&vec![0x41; 60000]).await.unwrap();
    first_peer.read_exact(&mut buffer[..60000]).await.unwrap();
    udp.send(&vec![0x42; 60000], &udp_target).await.unwrap();
    assert_eq!(origin.recv_from(&mut buffer).await.unwrap().0, 60000);
    let payload = vec![0x43; 8192];
    let mut waiting = Box::pin(second.write_all(&payload));
    poll_fn(|cx| {
        assert!(
            waiting.as_mut().poll(cx).is_pending(),
            "separate streams or UDP replenished the user's shared burst"
        );
        Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_millis(20)).await;
    poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_millis(10)).await;
    timeout(Duration::from_secs(1), &mut waiting)
        .await
        .unwrap()
        .unwrap();
    drop(waiting);
    second_peer
        .read_exact(&mut buffer[..payload.len()])
        .await
        .unwrap();
    assert_eq!(&buffer[..payload.len()], payload);
    tokio::time::resume();
    drop((first, second, udp));
    env.assert_empty();
}

async fn hot_change(uuid: Option<&str>, password: Option<&str>) {
    let tcp = TcpEcho::start().await;
    let udp = UdpEcho::start(false).await;
    let env = Environment::new(0, 1, true, None);
    let user = env.user();
    let source = peer("127.0.0.1");
    let mut pending_stream = env.host.connect(&user, source, &tcp.target).await.unwrap();
    let mut old_writer = env.host.connect(&user, source, &tcp.target).await.unwrap();
    let initial = b"before-change-TCP";
    pending_stream.write_all(initial).await.unwrap();
    let mut echo = vec![0; initial.len()];
    pending_stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(echo, initial);
    let channel = env.host.datagram(&user, source).await.unwrap();
    let udp_body = b"before-change-UDP";
    udp_roundtrip(&channel, &udp.target, udp_body).await;
    let read = tokio::spawn(async move {
        let mut byte = [0];
        pending_stream.read(&mut byte).await
    });
    let pending_channel = channel.clone();
    let receive = tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        pending_channel.receive(&mut buffer).await
    });
    tokio::task::yield_now().await;
    assert!(!read.is_finished());
    assert!(!receive.is_finished());
    let replacement = match (uuid, password) {
        (Some(uuid), Some(password)) => vec![configured_user("7", uuid, password, 0, 1)],
        _ => vec![],
    };
    env.replace(replacement);
    assert_denied(old_writer.write(b"old-profile-must-not-flow").await);
    assert_denied(
        channel
            .send(b"old-profile-must-not-flow", &udp.target)
            .await,
    );
    assert_denied(
        timeout(Duration::from_secs(1), read)
            .await
            .expect("pending TCP read was not revoked")
            .unwrap(),
    );
    assert_denied(
        timeout(Duration::from_secs(1), receive)
            .await
            .expect("pending UDP receive was not revoked")
            .unwrap(),
    );
    assert_denied(env.host.connect(&user, source, &tcp.target).await);
    assert_denied(env.host.datagram(&user, source).await);
    // Revocation closes resources even while the caller retains the invalid handles.
    env.assert_empty();
    env.assert_traffic(
        initial.len() + udp_body.len(),
        initial.len() + udp_body.len(),
    );
    if uuid.is_some() {
        let current = env.user();
        assert!(current != user);
        let replacement = env
            .host
            .connect(&current, peer("127.0.0.2"), &tcp.target)
            .await
            .unwrap();
        drop(replacement);
        env.assert_empty();
    }
    drop((old_writer, channel));
    tcp.finish().await;
    udp.finish().await;
}

#[tokio::test]
async fn user_removal_wakes_pending_tcp_udp_and_releases_activity() {
    hot_change(None, None).await;
}
#[tokio::test]
async fn same_id_uuid_change_closes_the_old_profile_and_accepts_the_new_one() {
    hot_change(Some(OTHER_UUID), Some(PASSWORD)).await;
}
#[tokio::test]
async fn same_id_password_change_closes_the_old_profile_and_accepts_the_new_one() {
    hot_change(Some(UUID), Some("replacement-fixture-password")).await;
}

#[tokio::test]
async fn socks_udp_route_auth_cache_payload_and_cancellation_release_all_resources() {
    let origin = UdpEcho::start(false).await;
    let proxy = SocksRelay::start(origin.address).await;
    let env = Environment::new(0, 1, true, Some(proxy.outbound.clone()));
    let user = env.user();
    let channel = env.host.datagram(&user, peer("127.0.0.1")).await.unwrap();
    let bodies = [vec![0x71; 3000], vec![0x72; 37]];
    for body in &bodies {
        udp_roundtrip(&channel, &origin.target, body).await;
    }
    assert_eq!(
        proxy.stats.handshakes.load(Ordering::Relaxed),
        1,
        "same plan opened a new proxy association"
    );
    assert_eq!(proxy.stats.payload.load(Ordering::Relaxed), 3037);
    assert_eq!(proxy.stats.wire.load(Ordering::Relaxed), 3057);
    assert!(
        origin
            .sources
            .lock()
            .unwrap()
            .iter()
            .all(|source| *source == proxy.forward_address),
        "payload bypassed the configured SOCKS UDP relay"
    );
    env.assert_traffic(3037, 3037);
    assert_eq!(env.limits.activity().sessions, 1);
    assert_eq!(env.slots.available_permits(), 3);
    let receive = tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        channel.receive(&mut buffer).await
    });
    tokio::task::yield_now().await;
    assert!(!receive.is_finished());
    receive.abort();
    assert!(receive.await.unwrap_err().is_cancelled());
    env.assert_empty();
    proxy.wait_closed().await;
    let new_channel = env.host.datagram(&user, peer("127.0.0.2")).await.unwrap();
    drop(new_channel);
    env.assert_empty();

    // Prove the completed/cancelled Host receive retained no Graph packet permit.
    // 128 native receive allocations use 8 MiB minus 128 bytes. A leaked old
    // 65535-byte packet would make the final allocation fail.
    let plan = node_outbound::UdpPlan {
        destination: origin.address,
        outbound_tag: "direct".into(),
    };
    let mut packets = Vec::new();
    let mut channels = Vec::new();
    for _ in 0..128 {
        let direct = env.network.udp_channel(&plan).await.unwrap();
        direct.send(&[], origin.address).await.unwrap();
        let packet = timeout(Duration::from_secs(1), direct.receive_packet())
            .await
            .unwrap()
            .unwrap();
        assert!(packet.payload.is_empty());
        packets.push(packet);
        channels.push(direct);
    }
    assert_limited(channels[0].send(&[], origin.address).await);
    drop(packets);
    channels[0].send(&[], origin.address).await.unwrap();
    drop(channels[0].receive_packet().await.unwrap());
    drop(channels);
    // Recovery of every global association permit is exercised with actual sockets.
    let mut all = Vec::new();
    for _ in 0..1024 {
        all.push(env.network.udp_channel(&plan).await.unwrap());
    }
    assert_limited(env.network.udp_channel(&plan).await.map_err(convert));
    drop(all);
    env.assert_empty();
    proxy.finish().await;
    origin.finish().await;
}

#[tokio::test]
async fn profile_change_cancels_a_real_pending_proxy_handshake_and_releases_its_lease() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Outbound::plain("pending-socks", "socks");
    proxy.server = Some(listener.local_addr().unwrap().ip());
    proxy.server_port = Some(listener.local_addr().unwrap().port());
    let env = Environment::new(0, 1, false, Some(proxy));
    let user = env.user();
    let host = env.host.clone();
    let target = Destination::new("203.0.113.7", 443).unwrap();
    let mut connect =
        tokio::spawn(async move { host.connect(&user, peer("127.0.0.1"), &target).await });
    let (mut control, _) = timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut greeting = [0; 3];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    assert_eq!(env.limits.activity().sessions, 1);
    // The proxy deliberately never acknowledges authentication. Actual control
    // replacement must interrupt this existing future before its 10s deadline.
    env.replace(vec![configured_user(
        "7",
        UUID,
        "new-pending-fixture-password",
        0,
        1,
    )]);
    let result = timeout(Duration::from_secs(1), &mut connect).await;
    if result.is_err() {
        connect.abort();
        let _ = connect.await;
        panic!("credential replacement retained a pending proxy handshake");
    }
    assert_denied(result.unwrap().unwrap());
    env.assert_empty();
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(1), control.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        closed, 0,
        "cancelled handshake kept the TCP control socket open"
    );
    let fresh = env
        .host
        .datagram(&env.user(), peer("127.0.0.2"))
        .await
        .unwrap();
    drop(fresh);
    env.assert_empty();
}

#[tokio::test]
async fn reentrant_watch_ready_and_unchanged_profile_notifications_do_not_repoll_or_lose_wakes() {
    #[derive(Default)]
    struct WakeLog(AtomicUsize);
    impl std::task::Wake for WakeLog {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn blocked(stream: &mut RateStream, context: &mut Context<'_>) {
        let mut bytes = [0u8; 1];
        let mut buffer = ReadBuf::new(&mut bytes);
        assert!(
            Pin::new(&mut *stream)
                .poll_read(context, &mut buffer)
                .is_pending()
        );
        assert!(
            Pin::new(&mut *stream)
                .poll_write(context, &[0x62])
                .is_pending()
        );
    }
    let env = Environment::new(0, 1, false, None);
    let profile = env.user();
    let lease = env.host.admit(&profile, peer("127.0.0.1")).unwrap();
    let (transport, mut receiver) = tokio::io::duplex(16);
    let mut stream = RateStream::new(
        Box::new(transport),
        lease,
        env.users.clone(),
        None,
        profile,
        env.limits.subscribe_auth(),
    );
    // Fill the real duplex write buffer, with no data in the reverse direction:
    // subsequent reads and writes both genuinely block on transport readiness.
    stream.write_all(&[0x61; 16]).await.unwrap();
    let wakes = Arc::new(WakeLog::default());
    let waker = std::task::Waker::from(wakes.clone());
    let mut context = Context::from_waker(&waker);

    let mut changes = env.limits.subscribe_auth();
    env.limits.notify_users_changed();
    let reentrant = env.limits.clone();
    // A real watch consumes one change; another change arrives before its
    // Ready(receiver) is returned. This forces the otherwise racy multithreaded
    // interleaving at exactly the await completion boundary, without timing.
    stream.auth_wait = Box::pin(async move {
        changes.changed().await.unwrap();
        reentrant.notify_users_changed();
        (changes, false)
    });
    blocked(&mut stream, &mut context);
    assert!(
        wakes.0.load(Ordering::SeqCst) > 0,
        "a replacement waiter must arrange its next poll"
    );
    blocked(&mut stream, &mut context);

    for _ in 0..32 {
        let before = wakes.0.load(Ordering::SeqCst);
        env.limits.notify_users_changed();
        env.limits.notify_users_changed();
        assert!(
            wakes.0.load(Ordering::SeqCst) > before,
            "unchanged profile notifications lost the I/O waker"
        );
        blocked(&mut stream, &mut context);
    }
    let before = wakes.0.load(Ordering::SeqCst);
    env.replace(vec![configured_user(
        "7",
        UUID,
        "replacement-session-password",
        0,
        1,
    )]);
    assert!(
        wakes.0.load(Ordering::SeqCst) > before,
        "credential revocation did not wake pending I/O"
    );
    let mut bytes = [0u8; 1];
    let mut buffer = ReadBuf::new(&mut bytes);
    match Pin::new(&mut stream).poll_read(&mut context, &mut buffer) {
        Poll::Ready(result) => assert_denied(result),
        Poll::Pending => panic!("revoked read stayed pending"),
    }
    match Pin::new(&mut stream).poll_write(&mut context, &[0x62]) {
        Poll::Ready(result) => assert_denied(result),
        Poll::Pending => panic!("revoked write stayed pending"),
    }
    drop(stream);
    env.assert_empty();
    let mut sent = [0u8; 16];
    receiver.read_exact(&mut sent).await.unwrap();
    assert_eq!(sent, [0x61; 16]);
    assert_eq!(
        receiver.read(&mut bytes).await.unwrap(),
        0,
        "revocation retained the duplex transport"
    );
}
