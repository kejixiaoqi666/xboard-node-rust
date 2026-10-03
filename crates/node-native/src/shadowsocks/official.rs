//! Independent, opt-in official sing-box interoperability for every panel SS method.
use super::*;
#[path = "../../../node-extended/tests/support/clients.rs"]
mod clients;
use crate::{auth, limits, network, traffic};
use arc_swap::ArcSwap;
use node_core::shadowsocks::{Cipher, user_password};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    process::{Child, Command, Stdio},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
    task::JoinSet,
};

struct Client(Child);
struct NativeSsHandler {
    users: auth::Users,
    counters: Arc<traffic::Traffic>,
    limits: Arc<limits::Registry>,
    network: Arc<network::Network>,
    service: Arc<Service>,
    slots: Arc<tokio::sync::Semaphore>,
    extended: node_extended::Config,
    cancel: watch::Receiver<bool>,
    source: SocketAddr,
}
#[async_trait::async_trait]
impl node_extended::http2::StreamHandler for NativeSsHandler {
    async fn serve(&self, stream: node_session::BoxStream) -> io::Result<()> {
        connection(
            stream,
            &self.service,
            crate::ConnectionContext {
                users: &self.users,
                traffic: &self.counters,
                limits: &self.limits,
                udp_slots: &self.slots,
                network: &self.network,
                source: self.source,
                extended: self.extended.clone(),
                stop: Some(self.cancel.clone()),
                tag: Arc::from("shadowsocks-in"),
            },
        )
        .await
        .map_err(|error| io::Error::other(format!("native SS admission: {error:?}")))
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command(binary: &Path) -> Command {
    let command = Command::new(binary);
    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;
        let mut command = command;
        command.creation_flags(0x08000000);
        command
    };
    command
}
async fn socks(port: u16, command: u8, target: SocketAddr) -> io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, 0] {
        return Err(io::Error::other("SOCKS auth failed"));
    }
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&match target.ip() {
        IpAddr::V4(ip) => ip.octets(),
        _ => unreachable!(),
    });
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(io::Error::other(format!("SOCKS status {}", head[1])));
    }
    let mut host = [0; 4];
    if head[3] != 1 {
        return Err(io::Error::other("SOCKS test expects IPv4"));
    }
    stream.read_exact(&mut host).await?;
    let port = stream.read_u16().await?;
    Ok((stream, SocketAddr::new(IpAddr::V4(host.into()), port)))
}
async fn tcp_payload(socks_port: u16, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let (mut stream, _) = socks(socks_port, 1, target).await?;
    stream.write_all(payload).await?;
    let mut returned = vec![0; payload.len()];
    stream.read_exact(&mut returned).await?;
    if returned != payload {
        return Err(io::Error::other("TCP payload mismatch"));
    }
    stream.shutdown().await
}
async fn udp_payload(socks_port: u16, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let (_control, mut endpoint) = socks(socks_port, 3, "0.0.0.0:0".parse().unwrap()).await?;
    if endpoint.ip().is_unspecified() {
        endpoint.set_ip("127.0.0.1".parse().unwrap());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut body = vec![0, 0, 0, 1];
    body.extend_from_slice(&match target.ip() {
        IpAddr::V4(ip) => ip.octets(),
        _ => unreachable!(),
    });
    body.extend_from_slice(&target.port().to_be_bytes());
    body.extend_from_slice(payload);
    socket.send_to(&body, endpoint).await?;
    let mut response = vec![0; 65536];
    let (size, _) = socket.recv_from(&mut response).await?;
    if size != body.len() || response[..size] != body {
        return Err(io::Error::other("UDP payload mismatch"));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires pinned official v1.14.2 client in SING_BOX_TEST_CLIENT"]
async fn all_eighteen_methods_official_tcp_udp_and_exact_payload_accounting() {
    let binary = std::path::PathBuf::from(
        std::env::var_os("SING_BOX_TEST_CLIENT").expect("set SING_BOX_TEST_CLIENT"),
    );
    let expected = clients::expected_binary_sha256("sing-box");
    let mut digest = Sha256::new();
    let mut file = std::fs::File::open(&binary).unwrap();
    let mut chunk = [0; 65536];
    loop {
        let count = std::io::Read::read(&mut file, &mut chunk).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    let actual: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual, expected,
        "official client executable SHA256 mismatch"
    );
    let version = command(&binary).arg("version").output().unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).contains("sing-box version 1.14.2"));
    for (method, plugin_mux) in Cipher::ALL
        .into_iter()
        .map(|method| (method, None))
        .chain([(Cipher::Aes128, Some(1)), (Cipher::Aes128, Some(0))])
    {
        let websocket = plugin_mux.is_some();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_target = origin.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            loop {
                let (mut socket, _) = origin.accept().await.unwrap();
                jobs.spawn(async move {
                    let mut bytes = [0; 8192];
                    loop {
                        let size = socket.read(&mut bytes).await.unwrap();
                        if size == 0 {
                            return;
                        }
                        socket.write_all(&bytes[..size]).await.unwrap();
                    }
                });
            }
        });
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = origin.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut bytes = [0; 65536];
            loop {
                let (size, peer) = origin.recv_from(&mut bytes).await.unwrap();
                origin.send_to(&bytes[..size], peer).await.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind = listener.local_addr().unwrap();
        let users: auth::Users = Arc::new(ArcSwap::from(
            super::tests::candidate(method, &[("7", "official-user-key")]).auth,
        ));
        let counters = Arc::new(traffic::Traffic::new(format!(
            "ss-official-{}",
            method.name()
        )));
        let limits = Arc::new(limits::Registry::new(users.clone()));
        let network = Arc::new(network::Network::direct());
        let service = Arc::new(Service::new());
        let udp = super::udp::serve(
            bind,
            super::udp::Context {
                users: users.clone(),
                traffic: counters.clone(),
                limits: limits.clone(),
                network: network.clone(),
                tag: Arc::from("shadowsocks-in"),
            },
            service.clone(),
        )
        .await
        .unwrap();
        let (stop, mut receiver) = watch::channel(false);
        let counter_copy = counters.clone();
        let server = tokio::spawn(async move {
            let slots = Arc::new(tokio::sync::Semaphore::new(1024));
            let extended = node_extended::Config::default();
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                    _=receiver.changed()=>break,
                    accepted=listener.accept()=> {
                        let (stream,source)=accepted.unwrap();let users=users.clone();let counters=counter_copy.clone();let limits=limits.clone();let network=network.clone();let service=service.clone();let slots=slots.clone();let extended=extended.clone();let cancel=receiver.clone();
                        jobs.spawn(async move {
                            let stream:node_session::BoxStream=if websocket {node_extended::websocket::accept(Box::new(stream),node_extended::websocket::WebSocketConfig{path:Some("/proxy".into()),..Default::default()}).await?} else {Box::new(stream)};
                            if plugin_mux.is_some_and(|mux|mux>0) {
                                let handler=Arc::new(NativeSsHandler{users,counters,limits,network,service,slots,extended:extended.clone(),cancel:cancel.clone(),source});
                                return node_extended::mux::serve_plugin_mux(stream,handler,extended,Some(cancel)).await.map_err(Error::Io);
                            }
                            connection(stream,&service,crate::ConnectionContext{users:&users,traffic:&counters,limits:&limits,udp_slots:&slots,network:&network,source,extended,stop:Some(cancel),tag:Arc::from("shadowsocks-in")}).await
                        });
                    },
                    job=jobs.join_next(),if !jobs.is_empty()=> {if let Some(Ok(Err(error)))=job {eprintln!("SS connection: {error:?}");}},
                }
            }
            if tokio::time::timeout(Duration::from_secs(5), async {
                while jobs.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                jobs.abort_all();
                while jobs.join_next().await.is_some() {}
                panic!("native SS listener workers did not join on cancel");
            }
        });
        let socks_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let password = if method.uses_identity_header() {
            format!(
                "{}:{}",
                user_password(method, "server-unique-key"),
                user_password(method, "official-user-key")
            )
        } else {
            user_password(method, "official-user-key").into_owned()
        };
        let directory = std::env::temp_dir().join(format!(
            "xboard-ss-official-{}-{}-{:?}",
            std::process::id(),
            method.name(),
            plugin_mux
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("client.json");
        let log_path = directory.join("client.log");
        let mut config = json!({"log":{"level":"error","timestamp":false},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"127.0.0.1","server_port":bind.port(),"method":method.name(),"password":password}],"route":{"final":"proxy"}});
        if let Some(mux) = plugin_mux {
            config["outbounds"][0]["plugin"] = json!("v2ray-plugin");
            config["outbounds"][0]["plugin_opts"] =
                json!(format!("mode=websocket;path=/proxy;mux={mux}"));
        }
        std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = std::fs::File::create(&log_path).unwrap();
        let mut client = Client(
            command(&binary)
                .args(["run", "-c"])
                .arg(&file)
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        for _ in 0..200 {
            if TcpStream::connect(("127.0.0.1", socks_port)).await.is_ok() {
                break;
            }
            if client.0.try_wait().unwrap().is_some() {
                panic!(
                    "{}: {}",
                    method.name(),
                    std::fs::read_to_string(&log_path).unwrap()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let payload: Vec<u8> = (0..22000).map(|i| (i % 251) as u8).collect();
        for _ in 0..3 {
            let result = tokio::time::timeout(
                Duration::from_secs(8),
                tcp_payload(socks_port, tcp_target, &payload),
            )
            .await;
            assert!(
                matches!(result, Ok(Ok(()))),
                "{} TCP {result:?}; {}",
                method.name(),
                std::fs::read_to_string(&log_path).unwrap()
            );
        }
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            udp_payload(socks_port, udp_target, b"official-client-udp"),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "{} UDP {result:?}; {}",
            method.name(),
            std::fs::read_to_string(&log_path).unwrap()
        );
        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap();
        udp.shutdown().await.unwrap();
        tcp_echo.abort();
        let _ = tcp_echo.await;
        udp_echo.abort();
        let _ = udp_echo.await;
        assert_eq!(
            counters.snapshot().unwrap().unwrap().traffic["7"],
            [66019, 66019],
            "{} framing counted as payload",
            method.name()
        );
        println!(
            "official sing-box v1.14.2 Shadowsocks {} plugin_mux={plugin_mux:?}: TCP 3x22000 + UDP19; up=66019 down=66019; listener joined",
            method.name()
        );
    }
}
