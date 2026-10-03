//! Unix-only acceptance of the real native SIP003 process owner. Windows does
//! not run the Unix embedded listener and is deliberately excluded.
#![cfg(unix)]
#[path = "support/native_fixture.rs"]
mod fixture;
use fixture::*;
use serde_json::{Value, json};
use std::{
    io,
    net::{Shutdown, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

unsafe extern "C" {
    fn getpgrp() -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
}
fn alive(pid: u32) -> bool {
    // Signal zero only observes this fixture's recorded child; it sends no signal.
    i32::try_from(pid).is_ok_and(|pid| unsafe { kill(pid, 0) } == 0)
}
fn report(path: &Path, value: &Value) {
    let staging = path.with_extension("tmp");
    std::fs::write(&staging, serde_json::to_vec(value).unwrap()).unwrap();
    std::fs::rename(staging, path).unwrap();
}
fn options() -> Option<std::collections::HashMap<String, String>> {
    let options = std::env::var("SS_PLUGIN_OPTIONS").ok()?;
    let result: std::collections::HashMap<_, _> = options
        .split(';')
        .filter_map(|part| {
            part.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect();
    result.contains_key("fixture-mode").then_some(result)
}

/// The current Rust test executable is the external fixture binary. Its normal
/// test invocation returns immediately; the SIP003 owner selects exactly this
/// test in its own private Unix process group and supplies the real env.
#[test]
fn sip003_fixture_child() {
    let Some(options) = options() else {
        return;
    };
    let remote_host = std::env::var("SS_REMOTE_HOST").unwrap();
    let remote_port = std::env::var("SS_REMOTE_PORT").unwrap();
    let local_host = std::env::var("SS_LOCAL_HOST").unwrap();
    let local_port = std::env::var("SS_LOCAL_PORT").unwrap();
    let remote: SocketAddr = format!("{remote_host}:{remote_port}").parse().unwrap();
    let local: SocketAddr = format!("{local_host}:{local_port}").parse().unwrap();
    let path = Path::new(options.get("fixture-report").unwrap());
    let mode = options.get("fixture-mode").unwrap();
    if mode == "relay-ignore-term" {
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }
    let mut state = json!({"pid":std::process::id(),"group":unsafe {getpgrp()},"remote_host":remote_host,"remote_port":remote_port,"local_host":local_host,"local_port":local_port,"options":std::env::var("SS_PLUGIN_OPTIONS").unwrap(),"ready":false});
    report(path, &state);
    if mode == "exit-before-ready" {
        std::process::exit(37);
    }
    if mode == "never-ready" {
        // Remain a real, observable child while never binding the public port.
        // The native owner must react to node stop rather than waiting 15s.
        loop {
            std::thread::park();
        }
    }
    std::thread::sleep(Duration::from_millis(125));
    let listener = std::net::TcpListener::bind(remote).unwrap();
    state["ready"] = json!(true);
    report(path, &state);
    if mode == "exit-after-ready" {
        std::thread::sleep(Duration::from_millis(500));
        std::process::exit(37);
    }
    for incoming in listener.incoming() {
        let client = incoming.unwrap();
        std::thread::spawn(move || {
            let Ok(private) = std::net::TcpStream::connect(local) else {
                return;
            };
            let mut client_read = client.try_clone().unwrap();
            let mut private_write = private.try_clone().unwrap();
            let upload = std::thread::spawn(move || {
                let _ = io::copy(&mut client_read, &mut private_write);
                let _ = private_write.shutdown(Shutdown::Write);
            });
            let mut private_read = private;
            let mut client_write = client;
            let _ = io::copy(&mut private_read, &mut client_write);
            let _ = client_write.shutdown(Shutdown::Write);
            let _ = upload.join();
        });
    }
}

fn plugin_config(
    directory: &Directory,
    port: u16,
    mode: &str,
) -> (Value, std::path::PathBuf, String) {
    let path = directory.file("plugin-env.json");
    let text = format!(
        "server;fixture-mode={mode};fixture-report={}",
        path.display()
    );
    let mut config = configuration(port);
    config["inbounds"][0]["plugin"] = json!({"binary":std::env::current_exe().unwrap(),"arguments":["--exact","sip003_fixture_child","--nocapture"],"options":text});
    (config, path, text)
}
async fn read_report(path: &Path) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = std::fs::read(path)
                && let Ok(value) = serde_json::from_slice(&bytes)
            {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIP003 child did not write its environment evidence")
}
async fn read_ready_report(path: &Path) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = read_report(path).await;
            if state["ready"] == true {
                return state;
            }
            // The public bind can be observed by the native readiness probe
            // before the child atomically publishes its second evidence file.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIP003 child never published its successful public bind")
}
fn child_endpoints(value: &Value, public_port: u16, expected_options: &str) -> (u32, SocketAddr) {
    let pid = value["pid"].as_u64().unwrap() as u32;
    assert_eq!(
        value["group"].as_i64(),
        Some(pid as i64),
        "plugin did not get its own private process group"
    );
    assert_eq!(value["remote_host"], "127.0.0.1");
    assert_eq!(value["remote_port"], public_port.to_string());
    assert_eq!(value["local_host"], "127.0.0.1");
    assert_eq!(value["options"], expected_options);
    let private_port = value["local_port"]
        .as_str()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    assert_ne!(private_port, 0);
    assert_ne!(private_port, public_port);
    (pid, SocketAddr::from(([127, 0, 0, 1], private_port)))
}
async fn assert_cleanup(run: &NativeRun, pid: u32, public_port: u16, private: SocketAddr) {
    assert!(
        !alive(pid),
        "plugin child survived or remained unreaped after native returned"
    );
    assert_closed(SocketAddr::from(([127, 0, 0, 1], public_port))).await;
    assert_closed(private).await;
    assert!(
        tokio::net::UdpSocket::bind(("127.0.0.1", public_port))
            .await
            .is_ok(),
        "native UDP listener survived plugin shutdown"
    );
    assert!(
        !run.control.exists(),
        "Unix control socket survived native stop"
    );
}

#[tokio::test]
async fn sip003_environment_private_endpoint_real_payload_readiness_and_stop_cleanup() {
    relay_case(false).await;
}

#[tokio::test]
async fn sip003_quiesce_waits_sigterm_resistant_child_before_final_checkpoint() {
    relay_case(true).await;
}

async fn relay_case(ignore_term: bool) {
    let directory = Directory::new("sip003");
    let port = free_port();
    let (value, path, text) = plugin_config(
        &directory,
        port,
        if ignore_term {
            "relay-ignore-term"
        } else {
            "relay"
        },
    );
    let start = Instant::now();
    let mut run = if ignore_term {
        NativeRun::start_persistent(&value, &directory)
    } else {
        NativeRun::start(&value, &directory)
    };
    run.ready().await;
    assert!(
        start.elapsed() >= Duration::from_millis(125),
        "ready was reported before delayed public bind"
    );
    let state = read_ready_report(&path).await;
    assert_eq!(state["ready"], true);
    let (pid, private) = child_endpoints(&state, port, &text);
    assert!(alive(pid));
    let (target, echo_stop, echo_task) = echo().await;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let server = shadowsocks::config::ServerConfig::new(
        ("127.0.0.1", port),
        "native-plugin-fixture-password".to_owned(),
        "aes-128-gcm".parse().unwrap(),
    )
    .unwrap();
    let mut client = shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream::from_stream(
        Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Local,
        )),
        stream,
        &server,
        shadowsocks::relay::socks5::Address::SocketAddress(target),
    );
    let payload: Vec<u8> = (0..66000).map(|n| (n % 251) as u8).collect();
    client.write_all(&payload[..1024]).await.unwrap();
    client.flush().await.unwrap();
    client.write_all(&payload[1024..]).await.unwrap();
    client.flush().await.unwrap();
    let mut returned = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut returned))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(returned, payload);
    assert_traffic(&run, 66000, 66000).await;
    if ignore_term {
        let started = Instant::now();
        let reply = tokio::time::timeout(
            Duration::from_secs(8),
            query(&run.control, "traffic_quiesce"),
        )
        .await
        .expect("quiesce did not finish within its bounded cleanup allowance")
        .unwrap();
        assert!(
            started.elapsed() >= Duration::from_secs(2),
            "fixture did not require the SIGKILL fallback"
        );
        assert_eq!(reply["code"], "ok");
        assert_eq!(reply["quiesced"], true);
        assert!(
            !alive(pid),
            "quiesce acknowledged before reaping the resistant plugin"
        );
        assert_persisted_traffic(&directory, 66000, 66000);
    }
    // Hold the client open: stop must cancel native workers and the external
    // process rather than depending on the client to voluntarily close.
    run.stopped(true).await.unwrap();
    assert_cleanup(&run, pid, port, private).await;
    drop(client);
    stop_echo(echo_stop, echo_task).await;
    println!(
        "SIP003 actual native: delayed public readiness, exact env/private loopback, TCP66000 each direction, stop joined child and freed TCP/UDP/control"
    );
}

#[tokio::test]
async fn sip003_child_exit_before_readiness_fails_start_and_reaps_child() {
    let directory = Directory::new("sip003fail");
    let port = free_port();
    let (value, path, text) = plugin_config(&directory, port, "exit-before-ready");
    let mut run = NativeRun::start(&value, &directory);
    let state = read_report(&path).await;
    let (pid, private) = child_endpoints(&state, port, &text);
    assert!(matches!(
        run.stopped(false).await,
        Err(node_native::Error::Task)
    ));
    assert_eq!(state["ready"], false);
    assert_cleanup(&run, pid, port, private).await;
    println!(
        "SIP003 actual native: pre-ready exit(37) failed startup; child waited and private/public/control released"
    );
}

#[tokio::test]
async fn sip003_child_exit_after_readiness_stops_runtime_and_releases_listeners() {
    let directory = Directory::new("sip003exit");
    let port = free_port();
    let (value, path, text) = plugin_config(&directory, port, "exit-after-ready");
    let mut run = NativeRun::start(&value, &directory);
    run.ready().await;
    let state = read_report(&path).await;
    let (pid, private) = child_endpoints(&state, port, &text);
    assert!(matches!(
        run.stopped(false).await,
        Err(node_native::Error::Task)
    ));
    assert_cleanup(&run, pid, port, private).await;
    println!(
        "SIP003 actual native: post-ready exit(37) stopped runtime; child and all listeners joined/closed"
    );
}

#[tokio::test]
async fn sip003_stop_before_readiness_waits_child_without_exposing_udp() {
    let directory = Directory::new("sip003cancel");
    let port = free_port();
    let (value, path, text) = plugin_config(&directory, port, "never-ready");
    let mut run = NativeRun::start(&value, &directory);
    let state = read_report(&path).await;
    let (pid, private) = child_endpoints(&state, port, &text);
    assert_eq!(state["ready"], false);
    assert!(
        alive(pid),
        "the fixture must be alive during startup cancellation"
    );
    assert_closed(SocketAddr::from(([127, 0, 0, 1], port))).await;
    // A failed bind would prove the native raw UDP listener became externally
    // reachable before the transport plugin was ready. Do not keep this probe
    // bound during stop: it must not hide a late native listener or cleanup bug.
    let udp = tokio::net::UdpSocket::bind(("127.0.0.1", port))
        .await
        .expect("native UDP was exposed before the external plugin became ready");
    drop(udp);
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(3), run.stopped(true))
        .await
        .expect("stop waited for the 15s plugin readiness timeout")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_cleanup(&run, pid, port, private).await;
    println!(
        "SIP003 actual native: live never-ready child canceled and waited within 3s; UDP never exposed before readiness; public/private TCP, UDP and control released"
    );
}
