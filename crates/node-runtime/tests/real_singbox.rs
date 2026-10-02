#[path = "../../../tests/support/mod.rs"]
mod process_support;
mod support;
use node_core::{NodeSpec, UserSpec};
use node_kernel::{
    KernelStatus, SingBoxConfigBuilder, SingBoxProcessKernel, SingBoxProcessKernelConfig,
};
use node_runtime::{NodeRuntime, SyncResult};
use serde_json::json;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct Client(Child);
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn client(
    binary: &PathBuf,
    dir: &process_support::TestDir,
    port: u16,
    server_port: u16,
    uuid: &str,
) -> Client {
    let path = dir.0.join(format!("client-{port}.json"));
    std::fs::write(&path,json!({
        "log":{"level":"error"},
        "inbounds":[{"type":"mixed","tag":"mixed","listen":"127.0.0.1","listen_port":port}],
        "outbounds":[{"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":server_port,"uuid":uuid}],
        "route":{"final":"proxy"}
    }).to_string()).unwrap();
    let child = Command::new(binary)
        .args(["run", "-c"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut client = Client(child);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(client.0.try_wait().unwrap().is_none(), "client exited");
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    client
}

async fn request(proxy_port: u16, origin_port: u16) -> String {
    tokio::time::timeout(Duration::from_secs(3),async {
        let mut stream=TcpStream::connect(("127.0.0.1",proxy_port)).await.unwrap();
        stream.write_all(format!("GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut bytes=Vec::new();
        let _=stream.read_to_end(&mut bytes).await;
        String::from_utf8_lossy(&bytes).into_owned()
    }).await.unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires official sing-box binary via SINGBOX_TEST_BINARY; loopback-only integration"]
async fn rust_rest_to_real_vless_client_and_same_port_user_rotation() {
    let binary =
        PathBuf::from(std::env::var_os("SINGBOX_TEST_BINARY").expect("set SINGBOX_TEST_BINARY"));
    let dir = process_support::TestDir::new();
    let port = process_support::free_port();
    let mut node = NodeSpec::new("vless", port);
    node.listen_ip = Some("127.0.0.1".into());
    let first = UserSpec::new(1, "00000000-0000-4000-8000-000000000001");
    let second = UserSpec::new(2, "00000000-0000-4000-8000-000000000002");
    let panel = support::TestPanel::new(&node, std::slice::from_ref(&first)).await;
    let kernel = SingBoxProcessKernel::new(
        SingBoxProcessKernelConfig {
            executable: binary.clone(),
            args: vec!["run".into(), "-c".into()],
            state_dir: dir.0.join("server"),
            readiness_timeout: Duration::from_secs(5),
            readiness_addr: None,
        },
        SingBoxConfigBuilder::new(),
    );
    let mut runtime = NodeRuntime::new(panel.client(), kernel, 7);
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let _ = stream.read(&mut bytes).await;
            let _=stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nxbord-rust-origin").await;
        }
    });
    let proxy1 = process_support::free_port();
    let _client1 = client(&binary, &dir, proxy1, port, &first.uuid).await;
    assert!(
        request(proxy1, origin_port)
            .await
            .contains("xbord-rust-origin")
    );
    panel.users(std::slice::from_ref(&second));
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 2);
    assert!(
        !request(proxy1, origin_port)
            .await
            .contains("xbord-rust-origin"),
        "removed user must lose access"
    );
    let proxy2 = process_support::free_port();
    let _client2 = client(&binary, &dir, proxy2, port, &second.uuid).await;
    assert!(
        request(proxy2, origin_port)
            .await
            .contains("xbord-rust-origin")
    );
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
    runtime.shutdown().await.unwrap();
    assert_eq!(runtime.status(), KernelStatus::Stopped);
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    origin_task.abort();
}
