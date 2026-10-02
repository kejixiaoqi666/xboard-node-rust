#[path = "../../../tests/support/mod.rs"]
mod support;
use node_core::{NodeSpec, UserSpec};
use node_kernel::{
    KernelAdapter, KernelError, KernelManager, KernelStatus, SingBoxConfigBuilder,
    SingBoxProcessKernel, SingBoxProcessKernelConfig,
};
use std::{
    net::TcpStream,
    time::{Duration, Instant},
};
use support::{TestDir, fixture, free_port};

fn node(port: u16) -> NodeSpec {
    let mut node = NodeSpec::new("vless", port);
    node.listen_ip = Some("127.0.0.1".into());
    node
}
fn user(id: i64) -> UserSpec {
    UserSpec::new(id, format!("00000000-0000-4000-8000-{id:012}"))
}
fn kernel(dir: &TestDir) -> SingBoxProcessKernel {
    SingBoxProcessKernel::new(
        SingBoxProcessKernelConfig {
            executable: fixture(),
            args: vec!["run".into(), "-c".into()],
            state_dir: dir.0.clone(),
            readiness_timeout: Duration::from_secs(2),
            readiness_addr: None,
        },
        SingBoxConfigBuilder::new(),
    )
}
#[test]
fn generated_config_passes_external_check_then_binds_listener() {
    let dir = TestDir::new();
    let port = free_port();
    let adapter = kernel(&dir);
    adapter
        .activate(adapter.prepare(&node(port), &[user(1)]).unwrap())
        .unwrap();
    assert_eq!(adapter.status(), KernelStatus::Ready);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    adapter.stop().unwrap();
}
#[test]
fn same_listener_can_update_users_after_candidate_check() {
    let dir = TestDir::new();
    let port = free_port();
    let mut manager = KernelManager::new(node(port), vec![user(1)], kernel(&dir)).unwrap();
    manager.start().unwrap();
    manager.apply(node(port), vec![user(2)]).unwrap();
    assert_eq!(manager.applied().users[0].id, 2);
    assert_eq!(manager.status(), KernelStatus::Ready);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
}
#[test]
fn failed_same_listener_candidate_restores_previous_users_and_listener() {
    let dir = TestDir::new();
    let port = free_port();
    let mut manager = KernelManager::new(node(port), vec![user(1)], kernel(&dir)).unwrap();
    manager.start().unwrap();
    assert!(matches!(
        manager.apply(node(port), vec![user(99)]),
        Err(KernelError::Activate(_))
    ));
    assert_eq!(manager.applied().users[0].id, 1);
    assert_eq!(manager.status(), KernelStatus::Ready);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
}
#[test]
fn failed_config_check_never_stops_old_listener() {
    let dir = TestDir::new();
    let port = free_port();
    let mut manager = KernelManager::new(node(port), vec![user(1)], kernel(&dir)).unwrap();
    manager.start().unwrap();
    assert!(matches!(
        manager.apply(node(port), vec![user(88)]),
        Err(KernelError::Prepare(_))
    ));
    assert_eq!(manager.applied().users[0].id, 1);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
}
#[test]
fn hanging_config_check_is_bounded_and_reaped() {
    let dir = TestDir::new();
    let adapter = kernel(&dir);
    let started = Instant::now();
    assert!(matches!(
        adapter.prepare(&node(free_port()), &[user(77)]),
        Err(KernelError::Prepare(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}
#[test]
fn occupied_listener_cannot_make_wrong_child_ready() {
    let dir = TestDir::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let adapter = kernel(&dir);
    let candidate = adapter
        .prepare(&node(listener.local_addr().unwrap().port()), &[user(1)])
        .unwrap();
    assert!(matches!(
        adapter.activate(candidate),
        Err(KernelError::Activate(_))
    ));
    assert_eq!(adapter.status(), KernelStatus::Stopped);
}

#[test]
fn streamed_size_limit_counts_json_escaping_and_preserves_active_listener() {
    let dir = TestDir::new();
    let port = free_port();
    let mut manager = KernelManager::new(node(port), vec![user(1)], kernel(&dir)).unwrap();
    manager.start().unwrap();
    let mut large = NodeSpec::new("trojan", port);
    large.listen_ip = Some("127.0.0.1".into());
    large.tls = 1;
    large.cert_config = Some(serde_json::json!({"mode":"file",
        "cert_file":dir.0.join("not-opened-cert.pem"), "key_file":dir.0.join("not-opened-key.pem")}));
    // A 9 MiB credential encodes to over 18 MiB. The limit must apply to
    // serialized output, not only input string lengths, and remove the partial file.
    let users = vec![UserSpec::new(2, "\\".repeat(9 * 1024 * 1024))];
    assert!(matches!(
        manager.apply(large, users),
        Err(KernelError::Prepare(_))
    ));
    assert_eq!(manager.applied().config.protocol, "vless");
    assert_eq!(manager.applied().users[0].id, 1);
    assert_eq!(manager.status(), KernelStatus::Ready);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
}
