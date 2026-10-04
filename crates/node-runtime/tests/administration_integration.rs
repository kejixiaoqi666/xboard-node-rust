#[path = "../../../tests/support/mod.rs"]
mod common;
#[allow(dead_code)] // The shared mock also has user-update helpers used by other tests.
mod support;

use node_admin::{CertConfig, CertificateManager, Secret, SecretResolver};
use node_core::{ActivitySnapshot, AppliedSnapshot, NodeSpec, UserSpec};
use node_kernel::{KernelAdapter, KernelError, KernelStatus};
use node_panel::{Auth, Panel};
use node_runtime::{
    ManagedKernel, NodeRuntime, RuntimeError, RuntimeMetrics, SyncResult,
    administration::{Hook, LocalSnapshotSource, Services},
    observations::Health,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};

const CERT_DOMAIN: &str = "certificate-fixture.example";

#[derive(Default)]
struct KernelState {
    active: Option<AppliedSnapshot>,
    running: bool,
    activated: usize,
    stopped: usize,
    activity: ActivitySnapshot,
    samples: usize,
}

#[derive(Clone, Default)]
struct FakeKernel(Arc<Mutex<KernelState>>);

impl KernelAdapter for FakeKernel {
    type Candidate = AppliedSnapshot;
    fn name(&self) -> &'static str {
        "administration-fixture"
    }
    fn prepare(&self, node: &NodeSpec, users: &[UserSpec]) -> Result<Self::Candidate, KernelError> {
        Ok(AppliedSnapshot {
            config: node.clone(),
            users: users.to_vec(),
        })
    }
    fn activate(&self, candidate: Self::Candidate) -> Result<(), KernelError> {
        let mut state = self.0.lock().unwrap();
        state.active = Some(candidate);
        state.running = true;
        state.activated += 1;
        Ok(())
    }
    fn rollback(&self) -> Result<(), KernelError> {
        Ok(())
    }
    fn status(&self) -> KernelStatus {
        if self.0.lock().unwrap().running {
            KernelStatus::Ready
        } else {
            KernelStatus::Stopped
        }
    }
}

impl ManagedKernel for FakeKernel {
    fn stop(&self) -> Result<(), KernelError> {
        let mut state = self.0.lock().unwrap();
        state.running = false;
        state.stopped += 1;
        Ok(())
    }
    fn activity(&self) -> Result<ActivitySnapshot, KernelError> {
        let mut state = self.0.lock().unwrap();
        state.samples += 1;
        Ok(state.activity.clone())
    }
}

struct NoSecrets;
impl SecretResolver for NoSecrets {
    fn get(&self, _: &str) -> Option<Secret> {
        None
    }
}

fn user() -> UserSpec {
    UserSpec::new(1, "00000000-0000-4000-8000-000000000001")
}

fn settings() -> node_admin::NodeConfig {
    serde_json::from_value(json!({
        "instance_id":"fixture", "id":"fixture-node", "runtime":{},
        "intervals":{}, "websocket":{}, "log":{}, "cert":{}, "standalone":null,
        "health_port":0,
        "kernel":{"type":"singbox","log_level":"info", "custom_outbound":[{"type":"direct","tag":"fixture-direct"}]},
    })).unwrap()
}

fn runtime(
    panel: Panel,
    fake: FakeKernel,
    directory: &Path,
    health: Arc<Health>,
    services: Arc<Services>,
) -> NodeRuntime<FakeKernel> {
    NodeRuntime::new(panel, fake, 7).with_administration(
        Hook::new(Some(settings()), directory.to_path_buf(), services),
        None,
        health,
        directory.to_path_buf(),
        Duration::from_secs(60),
        None,
    )
}

async fn material(directory: &Path) -> node_admin::CertificateFiles {
    // Self mode performs local key/certificate generation, with no CA or DNS.
    CertificateManager::default()
        .ensure(
            &CertConfig {
                cert_mode: "self".into(),
                domain: CERT_DOMAIN.into(),
                ..Default::default()
            },
            directory,
        )
        .await
        .unwrap()
        .unwrap()
}

async fn source_node(directory: &Path) -> (NodeSpec, PathBuf, PathBuf) {
    let files = material(&directory.join("initial-material")).await;
    let cert = directory.join("source-cert.pem");
    let key = directory.join("source-key.pem");
    std::fs::copy(files.cert, &cert).unwrap();
    std::fs::copy(files.key, &key).unwrap();
    let mut node = NodeSpec::new("vless", 443);
    node.domain = Some(CERT_DOMAIN.into());
    node.tls = 1;
    node.cert_config = Some(json!({"cert_mode":"file","cert_file":cert,"key_file":key}));
    (node, cert, key)
}

fn applied_cert(runtime: &NodeRuntime<FakeKernel>) -> PathBuf {
    PathBuf::from(
        runtime.snapshot().unwrap().config.cert_config.unwrap()["cert_file"]
            .as_str()
            .unwrap(),
    )
}

#[tokio::test]
async fn original_panel_config_is_transformed_again_after_both_etags_return_304() {
    let dir = common::TestDir::new();
    let (source, cert, key) = source_node(&dir.0).await;
    let panel = support::TestPanel::new(&source, &[user()]).await;
    let (stop, rx) = watch::channel(false);
    let services = Services::new(Arc::new(NoSecrets), rx);
    let fake = FakeKernel::default();
    let mut runtime = runtime(
        panel.client(),
        fake.clone(),
        &dir.0.join("runtime"),
        Arc::new(Health::default()),
        services.clone(),
    );
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    let initial = applied_cert(&runtime);
    let old_cert = std::fs::read(&initial).unwrap();
    assert_ne!(initial, cert);
    assert_eq!(runtime.snapshot().unwrap().config.custom_outbounds.len(), 1);
    assert!(runtime.snapshot().unwrap().config.domain.is_none());

    let rotated = material(&dir.0.join("rotated-material")).await;
    std::fs::copy(&rotated.cert, &cert).unwrap();
    std::fs::copy(&rotated.key, &key).unwrap();
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    let next = applied_cert(&runtime);
    assert_ne!(next, initial);
    assert!(std::fs::read(next).unwrap() == std::fs::read(&rotated.cert).unwrap());
    assert!(std::fs::read(initial).unwrap() == old_cert);
    assert_eq!(
        runtime.snapshot().unwrap().config.custom_outbounds.len(),
        1,
        "configured outbound must not accumulate on transformed snapshots"
    );
    assert_eq!(runtime.panel().config_etag(), Some("\"config-1\""));
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
    assert_eq!(fake.0.lock().unwrap().activated, 2);
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
    stop.send(true).unwrap();
    services.join().await;
}

#[tokio::test]
async fn failed_certificate_conversion_preserves_snapshot_etags_and_old_material() {
    let dir = common::TestDir::new();
    let (source, _cert, key) = source_node(&dir.0).await;
    let panel = support::TestPanel::new(&source, &[user()]).await;
    let (stop, rx) = watch::channel(false);
    let services = Services::new(Arc::new(NoSecrets), rx);
    let fake = FakeKernel::default();
    let mut runtime = runtime(
        panel.client(),
        fake.clone(),
        &dir.0.join("runtime"),
        Arc::new(Health::default()),
        services.clone(),
    );
    runtime.sync_once().await.unwrap();
    let initial = runtime.snapshot().unwrap();
    let initial_cert = applied_cert(&runtime);
    let old_bytes = std::fs::read(&initial_cert).unwrap();
    let valid_key = std::fs::read(&key).unwrap();
    std::fs::write(&key, b"invalid-local-fixture-key").unwrap();
    {
        let mut data = panel.state.lock().unwrap();
        data.config_tag = 2;
        let mut value: serde_json::Value = serde_json::from_str(&data.config).unwrap();
        value["server_port"] = json!(8443);
        data.config = value.to_string();
    }
    assert!(matches!(
        runtime.sync_once().await,
        Err(RuntimeError::Administration(_))
    ));
    assert!(runtime.snapshot().as_ref() == Some(&initial));
    assert!(fake.0.lock().unwrap().active.as_ref() == Some(&initial));
    assert_eq!(fake.0.lock().unwrap().activated, 1);
    assert_eq!(runtime.panel().config_etag(), Some("\"config-1\""));
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
    assert!(std::fs::read(initial_cert).unwrap() == old_bytes);

    std::fs::write(key, valid_key).unwrap();
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    assert_eq!(runtime.snapshot().unwrap().config.server_port, 8443);
    assert_eq!(runtime.panel().config_etag(), Some("\"config-2\""));
    assert_eq!(runtime.metrics().failed, 1);
    stop.send(true).unwrap();
    services.join().await;
}

/// Reuse the existing config/users/304 mock, adding a negative business ACK for
/// reports. All requests and certificate operations stay on the local machine.
struct RejectReports {
    _upstream: support::TestPanel,
    base: String,
    rejected: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl RejectReports {
    async fn new() -> Self {
        let upstream = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user()]).await;
        let address = upstream.base.strip_prefix("http://").unwrap().to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let rejected = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let report_count = Arc::clone(&rejected);
        let read_count = Arc::clone(&reads);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let _ = tokio::time::timeout(Duration::from_secs(2), async {
                    let mut bytes = Vec::new();
                    let mut buffer = [0; 1024];
                    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                        let count = stream.read(&mut buffer).await?;
                        if count == 0 || bytes.len() > 8192 { return Ok::<(), std::io::Error>(()); }
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    if bytes.starts_with(b"POST /api/v2/server/report ") {
                        report_count.fetch_add(1, Ordering::SeqCst);
                        let body = r#"{"data":false}"#;
                        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
                    } else {
                        read_count.fetch_add(1, Ordering::SeqCst);
                        let mut source = TcpStream::connect(&address).await?;
                        source.write_all(&bytes).await?;
                        let mut response = Vec::new();
                        source.read_to_end(&mut response).await?;
                        stream.write_all(&response).await?;
                    }
                    stream.shutdown().await
                }).await;
            }
        });
        Self {
            _upstream: upstream,
            base,
            rejected,
            reads,
            task,
        }
    }
    fn client(&self) -> Panel {
        Panel::new_for_test(&self.base, Auth::machine("fixture-only-token", 1, 7)).unwrap()
    }
}
impl Drop for RejectReports {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct RuntimeTask {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), RuntimeError>>>,
}
impl RuntimeTask {
    fn spawn(
        mut runtime: NodeRuntime<FakeKernel>,
        stop: watch::Sender<bool>,
        rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            stop,
            task: Some(tokio::spawn(async move {
                runtime.run(Duration::from_secs(60), None, rx).await
            })),
        }
    }
    async fn shutdown(mut self) {
        self.stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.task.take();
    }
}
impl Drop for RuntimeTask {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn wait_for(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected local observation did not arrive");
}

fn set_activity(fake: &FakeKernel, sessions: u32) {
    fake.0.lock().unwrap().activity = ActivitySnapshot {
        alive: [(1, vec!["192.0.2.5".into()])].into(),
        online: [(1, sessions)].into(),
        sessions: sessions.into(),
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_sessions_change_even_when_every_panel_report_is_rejected() {
    let dir = common::TestDir::new();
    let panel = RejectReports::new().await;
    let (stop, rx) = watch::channel(false);
    let services = Services::new(Arc::new(NoSecrets), rx.clone());
    let fake = FakeKernel::default();
    let health = Arc::new(Health::default());
    let mut runtime = NodeRuntime::new(panel.client(), fake.clone(), 7).with_administration(
        Hook::new(None, dir.0.clone(), services.clone()),
        None,
        health.clone(),
        dir.0.clone(),
        Duration::from_secs(60),
        Some(Duration::from_millis(50)),
    );
    runtime.sync_once().await.unwrap();
    set_activity(&fake, 9);
    let task = RuntimeTask::spawn(runtime, stop, rx);
    wait_for(|| {
        let state = health.0.lock().unwrap();
        state.ready && state.sessions == 9
    })
    .await;
    wait_for(|| panel.rejected.load(Ordering::SeqCst) > 0).await;
    set_activity(&fake, 2);
    wait_for(|| health.0.lock().unwrap().sessions == 2).await;
    assert!(fake.0.lock().unwrap().samples >= 2);
    task.shutdown().await;
    assert!(!health.0.lock().unwrap().ready);
    assert_eq!(health.0.lock().unwrap().sessions, 0);
    assert_eq!(fake.0.lock().unwrap().stopped, 1);
    services.join().await;
}

struct Local;
impl LocalSnapshotSource for Local {
    fn snapshot(&self) -> Result<(NodeSpec, Vec<UserSpec>), RuntimeError> {
        Ok((NodeSpec::new("vless", 443), vec![user()]))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_observes_real_kernel_sessions_without_panel_requests() {
    let dir = common::TestDir::new();
    let panel = RejectReports::new().await;
    let (stop, rx) = watch::channel(false);
    let services = Services::new(Arc::new(NoSecrets), rx.clone());
    let fake = FakeKernel::default();
    let health = Arc::new(Health::default());
    let mut runtime = NodeRuntime::new(panel.client(), fake.clone(), 7).with_administration(
        Hook::new(None, dir.0.clone(), services.clone()),
        Some(Arc::new(Local)),
        health.clone(),
        dir.0.clone(),
        Duration::from_secs(60),
        Some(Duration::from_millis(50)),
    );
    runtime.sync_once().await.unwrap();
    set_activity(&fake, 7);
    let task = RuntimeTask::spawn(runtime, stop, rx);
    wait_for(|| health.0.lock().unwrap().sessions == 7).await;
    assert!(fake.0.lock().unwrap().samples > 0);
    assert_eq!(panel.rejected.load(Ordering::SeqCst), 0);
    assert_eq!(panel.reads.load(Ordering::SeqCst), 0);
    task.shutdown().await;
    assert_eq!(fake.0.lock().unwrap().stopped, 1);
    services.join().await;
}

async fn health_request(port: u16, path: &str) -> (u16, serde_json::Value) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap())
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn machine_health_aggregates_metrics_and_rejects_partial_discovery() {
    let first = Arc::new(Health::default());
    let second = Arc::new(Health::default());
    first.update(
        true,
        &RuntimeMetrics {
            sync_attempts: 3,
            applied: 2,
            unchanged: 1,
            failed: 1,
            push_resyncs: 2,
            recovered: 1,
            cache_recoveries: 4,
            cache_write_failures: 1,
            traffic_collected: 5,
            traffic_reports: 3,
            traffic_uncertain: 1,
        },
        Some(4),
    );
    second.update(
        true,
        &RuntimeMetrics {
            sync_attempts: 7,
            applied: 3,
            unchanged: 2,
            failed: 2,
            push_resyncs: 3,
            recovered: 2,
            cache_recoveries: 5,
            cache_write_failures: 2,
            traffic_collected: 9,
            traffic_reports: 2,
            traffic_uncertain: 3,
        },
        Some(6),
    );
    let children = [(7, first), (8, second)];
    let health = Arc::new(Health::default());
    health.expect_nodes(3);
    health.update_fleet(children.clone(), true);
    let port = common::free_port();
    let server = health.clone().listen(port).await.unwrap();
    assert_eq!(health_request(port, "/healthz").await.0, 503);
    let (status, body) = health_request(port, "/metrics").await;
    assert_eq!(status, 200);
    assert_eq!(body["nodes"], 2);
    assert_eq!(body["ready_nodes"], 2);
    assert_eq!(body["desired_nodes"], 3);
    assert_eq!(body["rejected_nodes"], 1);
    assert_eq!(body["sessions"], 10);
    assert_eq!(body["node_metrics"].as_object().unwrap().len(), 2);
    assert_eq!(body["node_metrics"]["7"]["applied"], 2);
    assert_eq!(body["node_metrics"]["8"]["applied"], 3);
    assert_eq!(
        body["metrics"],
        json!({
            "sync_attempts":10,"applied":5,"unchanged":3,"failed":3,
            "push_resyncs":5,"recovered":3,"cache_recoveries":9,"cache_write_failures":3,
            "traffic_collected":14,
            "traffic_reports":5,"traffic_uncertain":4,
        })
    );

    health.expect_nodes(2);
    health.update_fleet(children.clone(), true);
    assert_eq!(health_request(port, "/healthz").await.0, 200);
    let (_, body) = health_request(port, "/metrics").await;
    assert_eq!(body["desired_nodes"], 2);
    assert_eq!(body["rejected_nodes"], 0);
    health.update_fleet(children, false);
    assert_eq!(health_request(port, "/healthz").await.0, 503);
    server.shutdown().await;
    assert!(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
}
