#[path = "../../../tests/support/mod.rs"]
mod support;
use node_core::{NodeSpec, UserSpec};
use node_kernel::{
    KernelAdapter, KernelError, KernelManager, KernelStatus, ProcessKernel, ProcessKernelConfig,
};
use std::{net::TcpStream, time::Duration};
use support::{TestDir, fixture, free_port};

fn node(port: u16) -> NodeSpec {
    let mut node = NodeSpec::new("vless", port);
    node.listen_ip = Some("127.0.0.1".into());
    node
}
fn process(dir: &TestDir, port: u16) -> ProcessKernel {
    ProcessKernel::new(ProcessKernelConfig {
        executable: fixture(),
        args: vec!["run".into()],
        state_dir: dir.0.clone(),
        readiness_timeout: Duration::from_secs(2),
        readiness_addr: Some(([127, 0, 0, 1], port).into()),
    })
}
#[test]
fn process_adapter_rejects_missing_executable() {
    let dir = TestDir::new();
    let bad = ProcessKernel::new(ProcessKernelConfig {
        executable: "".into(),
        args: vec![],
        state_dir: dir.0.clone(),
        readiness_timeout: Duration::from_millis(1),
        readiness_addr: None,
    });
    assert!(matches!(
        bad.prepare(&node(443), &[]),
        Err(KernelError::Prepare(_))
    ));
}
#[test]
fn process_adapter_starts_and_stops_child_without_shell_interpolation() {
    let dir = TestDir::new();
    let port = free_port();
    let adapter = process(&dir, port);
    adapter
        .activate(
            adapter
                .prepare(&node(port), &[UserSpec::new(1, "one")])
                .unwrap(),
        )
        .unwrap();
    assert_eq!(adapter.status(), KernelStatus::Ready);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    adapter.stop().unwrap();
    assert_eq!(adapter.status(), KernelStatus::Stopped);
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}
#[test]
fn manager_preserves_active_child_on_prepare_failure() {
    let dir = TestDir::new();
    let port = free_port();
    let mut manager = KernelManager::new(node(port), vec![], process(&dir, port)).unwrap();
    manager.start().unwrap();
    assert!(
        manager
            .apply(NodeSpec::new("unsupported", port), vec![])
            .is_err()
    );
    assert_eq!(manager.status(), KernelStatus::Ready);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
}
#[test]
fn failed_different_port_candidate_keeps_active_child() {
    let dir = TestDir::new();
    let port = free_port();
    let mut manager = KernelManager::new(node(port), vec![], process(&dir, port)).unwrap();
    manager.start().unwrap();
    assert!(matches!(
        manager.apply(node(free_port()), vec![UserSpec::new(99, "reject")]),
        Err(KernelError::Activate(_))
    ));
    assert_eq!(manager.applied().config.server_port, port);
    assert_eq!(manager.status(), KernelStatus::Ready);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
}
#[test]
fn dropping_last_adapter_reaps_child_and_candidate_file() {
    let dir = TestDir::new();
    let port = free_port();
    {
        let adapter = process(&dir, port);
        adapter
            .activate(adapter.prepare(&node(port), &[]).unwrap())
            .unwrap();
    }
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn configured_environment_keys_are_not_passed_to_kernel_child() {
    let dir = TestDir::new();
    let port = free_port();
    let adapter = ProcessKernel::new(ProcessKernelConfig {
        executable: fixture(),
        args: vec!["run".into(), "assert-no-path".into()],
        state_dir: dir.0.clone(),
        readiness_timeout: Duration::from_secs(2),
        readiness_addr: Some(([127, 0, 0, 1], port).into()),
    })
    .without_environment(["PATH".into()]);
    adapter
        .activate(adapter.prepare(&node(port), &[]).unwrap())
        .unwrap();
    assert_eq!(adapter.status(), KernelStatus::Ready);
}
