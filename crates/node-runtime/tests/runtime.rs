mod support;
use node_core::{AppliedSnapshot, NodeSpec, UserSpec};
use node_kernel::{KernelAdapter, KernelError, KernelStatus};
use node_panel::WsEvent;
use node_runtime::{ManagedKernel, NodeRuntime, SyncResult};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;

#[derive(Default)]
struct State {
    active: Option<AppliedSnapshot>,
    running: bool,
    reject: bool,
    activated: u32,
    stopped: u32,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);
impl KernelAdapter for Fake {
    type Candidate = AppliedSnapshot;
    fn name(&self) -> &'static str {
        "fake"
    }
    fn prepare(&self, node: &NodeSpec, users: &[UserSpec]) -> Result<Self::Candidate, KernelError> {
        Ok(AppliedSnapshot {
            config: node.clone(),
            users: users.to_vec(),
        })
    }
    fn activate(&self, candidate: Self::Candidate) -> Result<(), KernelError> {
        let mut state = self.0.lock().unwrap();
        if state.reject {
            return Err(KernelError::Activate("fixture rejection".into()));
        }
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
impl ManagedKernel for Fake {
    fn stop(&self) -> Result<(), KernelError> {
        let mut state = self.0.lock().unwrap();
        state.running = false;
        state.stopped += 1;
        Ok(())
    }
}
fn user(id: i64) -> UserSpec {
    UserSpec::new(id, format!("00000000-0000-4000-8000-{id:012}"))
}

#[tokio::test]
async fn stop_cancels_stalled_panel_request_and_still_shuts_down() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        let _ = entered_tx.send(());
        std::future::pending::<()>().await;
    });
    let panel = node_panel::Panel::new_for_test(
        &format!("http://{address}"),
        node_panel::Auth::machine("fixture-token", 1, 7),
    )
    .unwrap();
    let fake = Fake::default();
    let mut runtime = NodeRuntime::new(panel, fake.clone(), 7);
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut task =
        tokio::spawn(async move { runtime.run(Duration::from_secs(30), None, stop_rx).await });
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    stop_tx.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
    server.abort();
    if result.is_err() {
        task.abort();
    }
    assert!(result.is_ok(), "shutdown waited for a stalled HTTP request");
    result.unwrap().unwrap().unwrap();
    assert_eq!(fake.0.lock().unwrap().stopped, 1);
}

#[tokio::test]
async fn failed_user_activation_is_retried_before_etag_commits() {
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let fake = Fake::default();
    let mut runtime = NodeRuntime::new(server.client(), fake.clone(), 7);
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
    server.users(&[user(2)]);
    fake.0.lock().unwrap().reject = true;
    assert!(runtime.sync_once().await.is_err());
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 1);
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
    fake.0.lock().unwrap().reject = false;
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 2);
    assert_eq!(runtime.panel().user_etag(), Some("\"users-2\""));
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
    assert_eq!(fake.0.lock().unwrap().activated, 2);
    assert_eq!(runtime.metrics().failed, 1);
}

#[tokio::test]
async fn partial_fetch_failure_cannot_commit_new_config_etag() {
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let mut runtime = NodeRuntime::new(server.client(), Fake::default(), 7);
    runtime.sync_once().await.unwrap();
    {
        let mut state = server.state.lock().unwrap();
        state.config = serde_json::to_string(&NodeSpec::new("vless", 8443)).unwrap();
        state.config_tag = 2;
        state.users = "not-json".into();
        state.user_tag = 2;
    }
    assert!(runtime.sync_once().await.is_err());
    assert_eq!(runtime.snapshot().unwrap().config.server_port, 443);
    assert_eq!(runtime.panel().config_etag(), Some("\"config-1\""));
    server.users(&[user(1)]);
    runtime.sync_once().await.unwrap();
    assert_eq!(runtime.snapshot().unwrap().config.server_port, 8443);
    assert_eq!(runtime.panel().config_etag(), Some("\"config-2\""));
}

#[tokio::test]
async fn push_payloads_cannot_overwrite_authoritative_rest_or_other_node() {
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(2)]).await;
    let mut runtime = NodeRuntime::new(server.client(), Fake::default(), 7);
    runtime.sync_once().await.unwrap();
    assert!(!runtime.push_hint(&WsEvent::Users {
        node_id: Some(8),
        users: vec![user(1)]
    }));
    assert!(!runtime.push_hint(&WsEvent::Users {
        node_id: None,
        users: vec![user(1)]
    }));
    assert!(runtime.push_hint(&WsEvent::Users {
        node_id: Some(7),
        users: vec![user(1)]
    }));
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 2);
}

#[tokio::test]
async fn crashed_kernel_restarts_even_when_panel_returns_304() {
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let fake = Fake::default();
    let mut runtime = NodeRuntime::new(server.client(), fake.clone(), 7);
    runtime.sync_once().await.unwrap();
    fake.0.lock().unwrap().running = false;
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
    assert_eq!(fake.0.lock().unwrap().activated, 2);
    assert_eq!(runtime.metrics().recovered, 1);
}

#[tokio::test]
async fn last_good_kernel_recovers_before_malformed_panel_fetch() {
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let fake = Fake::default();
    let mut runtime = NodeRuntime::new(server.client(), fake.clone(), 7);
    runtime.sync_once().await.unwrap();
    fake.0.lock().unwrap().running = false;
    {
        let mut state = server.state.lock().unwrap();
        state.config = "broken-panel-response".into();
        state.config_tag += 1;
    }
    assert!(runtime.sync_once().await.is_err());
    assert_eq!(runtime.status(), KernelStatus::Ready);
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 1);
    assert_eq!(runtime.metrics().recovered, 1);
}

#[derive(Clone)]
struct Slow {
    fake: Fake,
    entered: Arc<std::sync::atomic::AtomicBool>,
    release: Arc<std::sync::atomic::AtomicBool>,
}
impl KernelAdapter for Slow {
    type Candidate = AppliedSnapshot;
    fn name(&self) -> &'static str {
        "slow"
    }
    fn prepare(&self, node: &NodeSpec, users: &[UserSpec]) -> Result<Self::Candidate, KernelError> {
        use std::sync::atomic::Ordering;
        self.entered.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.fake.prepare(node, users)
    }
    fn activate(&self, candidate: Self::Candidate) -> Result<(), KernelError> {
        self.fake.activate(candidate)
    }
    fn rollback(&self) -> Result<(), KernelError> {
        self.fake.rollback()
    }
    fn status(&self) -> KernelStatus {
        self.fake.status()
    }
}
impl ManagedKernel for Slow {
    fn stop(&self) -> Result<(), KernelError> {
        self.fake.stop()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_sync_cannot_activate_after_shutdown_returns() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let fake = Fake::default();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let mut runtime = NodeRuntime::new(
        server.client(),
        Slow {
            fake: fake.clone(),
            entered: entered.clone(),
            release: release.clone(),
        },
        7,
    );
    let _release_on_drop = ReleaseOnDrop(release.clone());
    {
        let sync = runtime.sync_once();
        tokio::pin!(sync);
        tokio::select! {
            _ = &mut sync => panic!("prepare should be waiting"),
            _ = tokio::time::timeout(Duration::from_secs(3),async { while !entered.load(Ordering::Acquire) { tokio::time::sleep(Duration::from_millis(2)).await; } }) => {}
        }
    }
    assert!(
        entered.load(Ordering::Acquire),
        "cancellation must reach the blocking preparation"
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        release.store(true, Ordering::Release);
    });
    runtime.shutdown().await.unwrap();
    assert_eq!(fake.0.lock().unwrap().activated, 0);
    assert_eq!(runtime.status(), KernelStatus::Stopped);
    assert!(runtime.snapshot().is_none());
    assert!(matches!(
        runtime.sync_once().await,
        Err(node_runtime::RuntimeError::Closing)
    ));
}

struct ReleaseOnDrop(Arc<std::sync::atomic::AtomicBool>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_update_cannot_reuse_previous_etag_for_a_new_active_snapshot() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let original = NodeSpec::new("vless", 443);
    let server = support::TestPanel::new(&original, &[user(1)]).await;
    let fake = Fake::default();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(true));
    let _release_on_drop = ReleaseOnDrop(release.clone());
    let mut runtime = NodeRuntime::new(
        server.client(),
        Slow {
            fake: fake.clone(),
            entered: entered.clone(),
            release: release.clone(),
        },
        7,
    );
    runtime.sync_once().await.unwrap();
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
    server.users(&[user(2)]);
    {
        let mut state = server.state.lock().unwrap();
        state.config = serde_json::to_string(&NodeSpec::new("vless", 8443)).unwrap();
        state.config_tag = 2;
    }
    entered.store(false, Ordering::Release);
    release.store(false, Ordering::Release);
    {
        let sync = runtime.sync_once();
        tokio::pin!(sync);
        tokio::select! {
            _ = &mut sync => panic!("prepare should be waiting"),
            result = tokio::time::timeout(Duration::from_secs(3),async { while !entered.load(Ordering::Acquire) { tokio::time::sleep(Duration::from_millis(2)).await; } }) => result.unwrap()
        }
    }
    release.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(3), async {
        while runtime.snapshot().unwrap().users[0].id != 2 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    // ETags may be content hashes, so returning to A legitimately reuses A's tag.
    {
        let mut state = server.state.lock().unwrap();
        state.config = serde_json::to_string(&original).unwrap();
        state.config_tag = 1;
        state.users = serde_json::json!({"users":[user(1)]}).to_string();
        state.user_tag = 1;
    }
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 1);
    assert_eq!(runtime.snapshot().unwrap().config.server_port, 443);
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
    runtime.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_waiter_still_commits_worker_snapshot_and_refetches_etag() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let fake = Fake::default();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let _release_on_drop = ReleaseOnDrop(release.clone());
    let mut runtime = NodeRuntime::new(
        server.client(),
        Slow {
            fake: fake.clone(),
            entered: entered.clone(),
            release: release.clone(),
        },
        7,
    );
    {
        let sync = runtime.sync_once();
        tokio::pin!(sync);
        tokio::select! {
            _ = &mut sync => panic!("prepare should be waiting"),
            _ = tokio::time::timeout(Duration::from_secs(3),async { while !entered.load(Ordering::Acquire) { tokio::time::sleep(Duration::from_millis(2)).await; } }) => {}
        }
    }
    release.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(3), async {
        while runtime.snapshot().is_none() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 1);
    assert_eq!(runtime.panel().user_etag(), None);
    assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
    assert_eq!(fake.0.lock().unwrap().activated, 1);
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn run_loop_applies_initial_snapshot_and_shutdown_reaps_kernel() {
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let fake = Fake::default();
    let mut runtime = NodeRuntime::new(server.client(), fake.clone(), 7);
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        runtime
            .run(Duration::from_secs(30), None, stop_rx)
            .await
            .unwrap();
        runtime
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !fake.0.lock().unwrap().running {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // `Fake::activate` is the worker-side commit. Give `run` one scheduling
        // turn to publish its caller-visible applied metric before requesting stop.
        tokio::time::sleep(Duration::from_millis(25)).await;
    })
    .await
    .unwrap();
    stop_tx.send(true).unwrap();
    let runtime = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.status(), KernelStatus::Stopped);
    assert_eq!(runtime.metrics().applied, 1);
    assert_eq!(fake.0.lock().unwrap().stopped, 1);
}

#[tokio::test]
async fn duplicate_users_never_replace_active_set() {
    let server = support::TestPanel::new(&NodeSpec::new("vless", 443), &[user(1)]).await;
    let mut runtime = NodeRuntime::new(server.client(), Fake::default(), 7);
    runtime.sync_once().await.unwrap();
    server.users(&[user(2), user(2)]);
    assert!(runtime.sync_once().await.is_err());
    assert_eq!(runtime.snapshot().unwrap().users[0].id, 1);
    assert_eq!(runtime.panel().user_etag(), Some("\"users-1\""));
}
