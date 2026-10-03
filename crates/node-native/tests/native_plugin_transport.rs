//! Official client through config::decode -> run_embedded -> the real native
//! listener. Unix execution is explicit; Windows is not reported as acceptance.
#![cfg(unix)]
#[path = "../../node-extended/tests/support/clients.rs"]
mod clients;
#[path = "support/native_fixture.rs"]
mod fixture;
use fixture::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

struct Client(Child);
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn verify_client(binary: &Path) {
    let mut file = std::fs::File::open(binary).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let len = std::io::Read::read(&mut file, &mut buffer).unwrap();
        if len == 0 {
            break;
        }
        digest.update(&buffer[..len]);
    }
    let actual: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(actual, clients::expected_binary_sha256("sing-box"));
    let version = Command::new(binary).arg("version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("sing-box version 1.14.2"));
}
fn pem(label: &str, bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut body = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = (chunk[0] as u32) << 16
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | chunk.get(2).copied().unwrap_or(0) as u32;
        body.extend_from_slice(&[
            TABLE[(word >> 18) as usize],
            TABLE[((word >> 12) & 63) as usize],
            if chunk.len() > 1 {
                TABLE[((word >> 6) & 63) as usize]
            } else {
                b'='
            },
            if chunk.len() > 2 {
                TABLE[(word & 63) as usize]
            } else {
                b'='
            },
        ]);
    }
    let mut text = format!("-----BEGIN {label}-----\n");
    for line in body.chunks(64) {
        text.push_str(std::str::from_utf8(line).unwrap());
        text.push('\n');
    }
    text.push_str(&format!("-----END {label}-----\n"));
    text
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
    let IpAddr::V4(ip) = target.ip() else {
        return Err(io::Error::other("fixture expects IPv4"));
    };
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0 || head[3] != 1 {
        return Err(io::Error::other(format!(
            "SOCKS command rejected: {head:?}"
        )));
    }
    let mut address = [0; 4];
    stream.read_exact(&mut address).await?;
    let port = stream.read_u16().await?;
    Ok((stream, SocketAddr::new(IpAddr::V4(address.into()), port)))
}
async fn payload_tcp(port: u16, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let mut stream = payload_tcp_retained(port, target, payload).await?;
    stream.shutdown().await
}
async fn payload_tcp_retained(
    port: u16,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<TcpStream> {
    let (mut stream, _) = socks(port, 1, target).await?;
    stream.write_all(payload).await?;
    let mut response = vec![0; payload.len()];
    stream.read_exact(&mut response).await?;
    if response != payload {
        return Err(io::Error::other("native plugin TCP payload differs"));
    }
    Ok(stream)
}
async fn payload_udp(port: u16, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let (_control, mut endpoint) = socks(port, 3, "0.0.0.0:0".parse().unwrap()).await?;
    if endpoint.ip().is_unspecified() {
        endpoint.set_ip("127.0.0.1".parse().unwrap());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut body = vec![0, 0, 0, 1];
    let IpAddr::V4(ip) = target.ip() else {
        return Err(io::Error::other("fixture expects IPv4"));
    };
    body.extend_from_slice(&ip.octets());
    body.extend_from_slice(&target.port().to_be_bytes());
    body.extend_from_slice(payload);
    socket.send_to(&body, endpoint).await?;
    let mut response = vec![0; 65536];
    let (size, _) = socket.recv_from(&mut response).await?;
    if response[..size] != body {
        return Err(io::Error::other("native SS UDP payload differs"));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires pinned sing-box v1.14.2 and the actual Unix native runtime"]
async fn official_v2ray_plugin_default_mux_and_mux_zero_through_native_runtime() {
    use std::os::unix::fs::PermissionsExt;
    let binary =
        PathBuf::from(std::env::var_os("SING_BOX_TEST_CLIENT").expect("set SING_BOX_TEST_CLIENT"));
    verify_client(&binary);
    for (tls, mux) in [(false, true), (false, false), (true, true), (true, false)] {
        let directory = Directory::new("nativews");
        let port = free_port();
        let socks_port = free_port();
        let mut value = configuration(port);
        value["inbounds"][0]["transport"] =
            json!({"type":"ws","path":"/proxy","host":"proxy.test","plugin_mux":mux});
        let mut options = String::from("mode=websocket;host=proxy.test;path=/proxy");
        if !mux {
            options.push_str(";mux=0");
        } // Omission verifies the official default mux=1.
        if tls {
            let certificate =
                rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            let certificate_path = directory.file("server.pem");
            let key_path = directory.file("key.pem");
            std::fs::write(
                &certificate_path,
                pem("CERTIFICATE", certificate.cert.der()),
            )
            .unwrap();
            std::fs::write(
                &key_path,
                pem("PRIVATE KEY", &certificate.signing_key.serialize_der()),
            )
            .unwrap();
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            value["inbounds"][0]["tls"] = json!({"enabled":true,"certificate_path":certificate_path,"key_path":key_path,"server_name":"proxy.test"});
            options.push_str(&format!(";tls;cert={}", certificate_path.display()));
        }
        let mut run = NativeRun::start_persistent(&value, &directory);
        run.ready().await;
        let (tcp_target, echo_stop, echo_task) = echo().await;
        let udp_origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = udp_origin.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut buffer = [0; 65536];
            let (size, peer) = udp_origin.recv_from(&mut buffer).await.unwrap();
            udp_origin.send_to(&buffer[..size], peer).await.unwrap();
        });
        let config = json!({"log":{"level":"error","timestamp":false},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"127.0.0.1","server_port":port,"method":"aes-128-gcm","password":"native-plugin-fixture-password","plugin":"v2ray-plugin","plugin_opts":options}],"route":{"final":"proxy"}});
        let path = directory.file("client.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = directory.file("client.log");
        let mut client = Client(
            Command::new(&binary)
                .args(["run", "-c"])
                .arg(path)
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(&log).unwrap())
                .spawn()
                .unwrap(),
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if TcpStream::connect(("127.0.0.1", socks_port)).await.is_ok() {
                    return;
                }
                assert!(
                    client.0.try_wait().unwrap().is_none(),
                    "official client exited: {}",
                    std::fs::read_to_string(&log).unwrap()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let payload: Vec<u8> = (0..22000).map(|n| (n % 251) as u8).collect();
        let mut held = None;
        for index in 0..3 {
            if mux && index == 2 {
                held = Some(
                    tokio::time::timeout(
                        Duration::from_secs(8),
                        payload_tcp_retained(socks_port, tcp_target, &payload),
                    )
                    .await
                    .unwrap()
                    .unwrap(),
                );
                continue;
            }
            let result = tokio::time::timeout(
                Duration::from_secs(8),
                payload_tcp(socks_port, tcp_target, &payload),
            )
            .await;
            assert!(
                matches!(result, Ok(Ok(()))),
                "native WS tls={tls} mux={mux} TCP failed: {result:?}; {}",
                std::fs::read_to_string(&log).unwrap()
            );
        }
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            payload_udp(socks_port, udp_target, b"official-client-udp"),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "native SS raw UDP failed: {result:?}; {}",
            std::fs::read_to_string(&log).unwrap()
        );
        udp_echo.await.unwrap();
        assert_traffic(&run, 66019, 66019).await;
        // Keep the official process and its active mux stream alive until the
        // native stop returns; voluntary client closure cannot satisfy this gate.
        run.stopped(true).await.unwrap();
        assert_persisted_traffic(&directory, 66019, 66019);
        assert_closed(SocketAddr::from(([127, 0, 0, 1], port))).await;
        assert!(
            UdpSocket::bind(("127.0.0.1", port)).await.is_ok(),
            "native raw UDP listener survived stop"
        );
        assert!(!run.control.exists());
        if let Some(mut held) = held {
            let mut byte = [0];
            let result = tokio::time::timeout(Duration::from_secs(2), held.read(&mut byte)).await;
            assert!(
                matches!(result, Ok(Ok(0)))
                    || matches!(&result, Ok(Err(error)) if matches!(error.kind(),io::ErrorKind::ConnectionReset|io::ErrorKind::ConnectionAborted|io::ErrorKind::BrokenPipe|io::ErrorKind::UnexpectedEof)),
                "active official mux stream survived native stop: {result:?}"
            );
        }
        drop(client);
        stop_echo(echo_stop, echo_task).await;
        println!(
            "official sing-box v1.14.2 actual native v2ray-plugin tls={tls} default_mux={mux}: TCP66000 plus native raw UDP19; final durable traffic=(66019,66019); active client retained until stop; TCP/UDP/control released"
        );
    }
}
