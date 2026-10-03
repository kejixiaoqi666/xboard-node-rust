use node_core::routing::{Outbound, OutboundTls};
use node_outbound::Graph;
#[path = "../../node-quic/tests/support/pinned_client.rs"]
mod pinned_client;
use serde_json::{Value, json};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
fn files() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "target/proxy-wire-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
struct Official {
    child: std::process::Child,
    log: PathBuf,
    outbound: Outbound,
}
impl Drop for Official {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Official {
    async fn start(kind: &str, method: Option<&str>) -> Self {
        let binary = pinned_client::binary();
        let dir = files();
        let port = unused_port();
        let mut inbound = json!({"type":kind,"listen":"127.0.0.1","listen_port":port});
        let mut outbound = Outbound::plain(&format!("{kind}-{port}"), kind);
        outbound.server = Some(IpAddr::from([127, 0, 0, 1]));
        outbound.server_port = Some(port);
        match kind {
            "socks" | "http" => {
                inbound["users"] = json!([{"username":"proxy-user","password":"proxy-password"}]);
                outbound.username = Some("proxy-user".into());
                outbound.password = Some("proxy-password".into());
            }
            "vless" => {
                inbound["users"] = json!([{"uuid":UUID}]);
                outbound.uuid = Some(UUID.into());
            }
            "trojan" => {
                inbound["users"] = json!([{"password":"proxy-password"}]);
                outbound.password = Some("proxy-password".into());
            }
            "shadowsocks" => {
                let method = method.unwrap();
                let password = match method {
                    "2022-blake3-aes-128-gcm" => "ABEiM0RVZneImaq7zN3u/w==",
                    "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => {
                        "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="
                    }
                    _ => "proxy-password",
                };
                inbound["method"] = json!(method);
                inbound["password"] = json!(password);
                outbound.method = Some(method.into());
                outbound.password = Some(password.into());
            }
            _ => panic!("unknown fixture protocol"),
        }
        if matches!(kind, "vless" | "trojan" | "http") {
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert = dir.join("certificate.pem");
            let key = dir.join("key.pem");
            std::fs::write(&cert, certificate.cert.pem()).unwrap();
            std::fs::write(&key, certificate.signing_key.serialize_pem()).unwrap();
            inbound["tls"] = json!({"enabled":true,"certificate_path":cert,"key_path":key});
            outbound.tls = Some(OutboundTls {
                enabled: true,
                server_name: Some("localhost".into()),
                insecure: false,
                ca_file: Some(cert.to_string_lossy().into()),
                alpn: vec![],
            });
        }
        let config = dir.join("config.json");
        std::fs::write(&config,serde_json::to_vec_pretty(&json!({"log":{"level":"warn"},"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap()).unwrap();
        let log = dir.join("server.log");
        let output = std::fs::File::create(&log).unwrap();
        let mut command = std::process::Command::new(binary);
        command
            .args(["run", "-c"])
            .arg(config)
            .stdout(output.try_clone().unwrap())
            .stderr(output);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let child = command.spawn().unwrap();
        let mut fixture = Self {
            child,
            log,
            outbound,
        };
        timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = fixture.child.try_wait().unwrap() {
                    panic!(
                        "official server exited {status}: {}",
                        std::fs::read_to_string(&fixture.log).unwrap()
                    )
                }
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
        fixture
    }
}
async fn origins() -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let tcp_task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {accepted=tcp.accept()=>{let(mut stream,_)=accepted.unwrap();clients.spawn(async move{let mut bytes=[0;8192];while let Ok(n)=stream.read(&mut bytes).await{if n==0{break}stream.write_all(&bytes[..n]).await.unwrap();}});},_ = clients.join_next(),if !clients.is_empty()=>{}}
        }
    });
    let udp_task = tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        loop {
            let (n, source) = udp.recv_from(&mut bytes).await.unwrap();
            udp.send_to(&bytes[..n], source).await.unwrap();
        }
    });
    (tcp_address, udp_address, tcp_task, udp_task)
}
async fn exercise(graph: &Graph, tag: &str, tcp: SocketAddr, udp: SocketAddr, with_udp: bool) {
    let mut stream = graph
        .connect(tag, tcp)
        .await
        .unwrap_or_else(|e| panic!("{tag} TCP connect: {e}"));
    let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = vec![0; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .unwrap_or_else(|_| panic!("{tag} TCP read timed out"))
        .unwrap_or_else(|e| panic!("{tag} TCP read: {e}"));
    assert_eq!(response, payload);
    stream.shutdown().await.unwrap();
    if with_udp {
        let channel = graph
            .udp_open(tag, udp)
            .await
            .unwrap_or_else(|e| panic!("{tag} UDP open: {e}"));
        let payload = vec![17; 3000];
        channel
            .send(&payload, udp)
            .await
            .unwrap_or_else(|e| panic!("{tag} UDP send: {e}"));
        let mut bytes = vec![0; 65535];
        let (n, source) = timeout(Duration::from_secs(5), channel.receive(&mut bytes))
            .await
            .unwrap_or_else(|_| panic!("{tag} UDP read timed out"))
            .unwrap_or_else(|e| panic!("{tag} UDP read: {e}"));
        assert_eq!(source, udp);
        assert_eq!(&bytes[..n], payload);
        assert!(channel.receive(&mut bytes[..100]).await.is_err());
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires fixed official sing-box v1.14.2; set SING_BOX_BIN after running node-quic/tests/fetch_clients.ps1"]
async fn official_sing_box_servers_tcp_udp_tls_and_multihop_chains() {
    let socks = Official::start("socks", None).await;
    let http = Official::start("http", None).await;
    let vless = Official::start("vless", None).await;
    let trojan = Official::start("trojan", None).await;
    let mut ss = Vec::new();
    for method in [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ] {
        ss.push(Official::start("shadowsocks", Some(method)).await)
    }
    let (tcp, udp, tcp_task, udp_task) = origins().await;
    let mut outbounds = vec![
        socks.outbound.clone(),
        http.outbound.clone(),
        vless.outbound.clone(),
        trojan.outbound.clone(),
    ];
    outbounds.extend(ss.iter().map(|s| s.outbound.clone()));
    let graph = Graph::new(&outbounds).unwrap();
    for outbound in &outbounds {
        exercise(&graph, &outbound.tag, tcp, udp, outbound.kind != "http").await;
    }
    assert_eq!(
        graph
            .udp_open(&http.outbound.tag, udp)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    for (inner, outer) in [
        (&vless.outbound, &socks.outbound),
        (&trojan.outbound, &http.outbound),
        (&ss[0].outbound, &socks.outbound),
        (&socks.outbound, &ss[0].outbound),
        (&http.outbound, &vless.outbound),
    ] {
        let mut inner = inner.clone();
        inner.tag = format!("chain-{}-{}", inner.kind, outer.kind);
        inner.detour = Some(outer.tag.clone());
        let mut route = outbounds.clone();
        route.push(inner.clone());
        exercise(
            &Graph::new(&route).unwrap(),
            &inner.tag,
            tcp,
            udp,
            inner.kind != "http",
        )
        .await;
    }
    let mut middle = vless.outbound.clone();
    middle.tag = "middle".into();
    middle.detour = Some(socks.outbound.tag.clone());
    let mut final_hop = ss[0].outbound.clone();
    final_hop.tag = "three".into();
    final_hop.detour = Some(middle.tag.clone());
    outbounds.extend([middle, final_hop]);
    exercise(&Graph::new(&outbounds).unwrap(), "three", tcp, udp, true).await;
    let mut invalid_socks = socks.outbound.clone();
    invalid_socks.tag = "bad-auth".into();
    invalid_socks.password = Some("wrong-password".into());
    assert!(
        Graph::new(&[invalid_socks])
            .unwrap()
            .connect("bad-auth", tcp)
            .await
            .is_err()
    );
    let mut invalid_tls = vless.outbound.clone();
    invalid_tls.tag = "bad-tls".into();
    invalid_tls.tls.as_mut().unwrap().server_name = Some("other.test".into());
    assert!(
        Graph::new(&[invalid_tls])
            .unwrap()
            .connect("bad-tls", tcp)
            .await
            .is_err()
    );
    let mut impossible = socks.outbound.clone();
    impossible.tag = "unsupported-udp-chain".into();
    impossible.detour = Some(http.outbound.tag.clone());
    assert_eq!(
        Graph::new(&[impossible, http.outbound.clone()])
            .unwrap()
            .udp_open("unsupported-udp-chain", udp)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    tcp_task.abort();
    udp_task.abort();
    let _ = tcp_task.await;
    let _ = udp_task.await;
}
#[tokio::test]
async fn direct_udp_rejects_unsent_sources_and_bounds_targets_sessions_and_buffers() {
    let graph = Graph::new(&[Outbound::plain("direct", "direct")]).unwrap();
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let channel = graph.udp_open("direct", target).await.unwrap();
    channel.send(b"request", target).await.unwrap();
    let mut bytes = vec![0; 65535];
    let (n, client) = origin.recv_from(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..n], b"request");
    let rogue = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    rogue.send_to(b"forged", client).await.unwrap();
    origin.send_to(b"accepted", client).await.unwrap();
    let (n, source) = timeout(Duration::from_secs(1), channel.receive(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, target);
    assert_eq!(&bytes[..n], b"accepted");
    assert!(channel.receive(&mut [0; 100]).await.is_err());
    for p in 20000..20063 {
        channel
            .send(b"x", SocketAddr::new(target.ip(), p))
            .await
            .unwrap();
    }
    assert_eq!(
        channel
            .send(b"x", SocketAddr::new(target.ip(), 20064))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let mut sessions = vec![];
    for _ in 0..1023 {
        sessions.push(graph.udp_open("direct", target).await.unwrap());
    }
    assert_eq!(
        graph.udp_open("direct", target).await.err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(sessions);
    assert!(graph.udp_open("direct", target).await.is_ok());
}
#[test]
fn secrets_are_redacted_and_invalid_ss_keys_fail_before_activation() {
    let raw: Value = json!({"tag":"secret","type":"shadowsocks","server":"127.0.0.1","server_port":8388,"method":"2022-blake3-aes-128-gcm","password":"not-base64"});
    let outbound: Outbound = serde_json::from_value(raw).unwrap();
    assert!(!format!("{outbound:?}").contains("not-base64"));
    assert!(Graph::new(&[outbound]).is_err());
}
