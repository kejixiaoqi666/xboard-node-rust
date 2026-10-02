use node_core::TrafficSnapshot;
use node_panel::ReportOutcome;
use node_runtime::traffic::{Outbox, Stage, TrafficError};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "xb-traffic-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!path.exists());
        Self(path)
    }
    fn open(&self) -> Outbox {
        Outbox::open(&self.0, "fixture-destination".into()).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Each test owns only these two files in its unique directory.
        for name in ["traffic.json", "traffic.lock"] {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}
fn sample(epoch: char, sequence: u64, bytes: [u64; 2]) -> TrafficSnapshot {
    TrafficSnapshot {
        epoch: epoch.to_string().repeat(32),
        sequence,
        traffic: BTreeMap::from([("100".into(), bytes)]),
    }
}

#[test]
fn kernel_ack_loss_and_epoch_reset_do_not_duplicate_collected_bytes() {
    let dir = Directory::new();
    let mut outbox = dir.open();
    let first = sample('a', 1, [13, 29]);
    assert!(outbox.collect(&first).unwrap());
    drop(outbox);
    let mut outbox = dir.open();
    assert!(!outbox.collect(&first).unwrap());
    assert!(outbox.collect(&sample('a', 2, [7, 11])).unwrap());
    assert!(outbox.collect(&sample('b', 1, [1, 3])).unwrap());
    let batch = outbox.prepare().unwrap().unwrap();
    assert_eq!(batch.traffic[&100], [21, 43]);
    assert_eq!(outbox.prepare().unwrap().unwrap().id, batch.id);
    outbox.sending(batch.id).unwrap();
    outbox
        .finish(batch.id, ReportOutcome::Acknowledged)
        .unwrap();
    drop(outbox);
    let mut outbox = dir.open();
    assert!(!outbox.collect(&sample('b', 1, [1, 3])).unwrap());
    assert!(outbox.prepare().unwrap().is_none());
}
#[test]
fn not_sent_retries_exact_batch_but_crashed_sending_requires_reconciliation() {
    let dir = Directory::new();
    let mut outbox = dir.open();
    outbox.collect(&sample('a', 1, [12, 34])).unwrap();
    let batch = outbox.prepare().unwrap().unwrap();
    outbox.sending(batch.id).unwrap();
    outbox.finish(batch.id, ReportOutcome::NotSent).unwrap();
    assert_eq!(outbox.prepare().unwrap().unwrap().traffic, batch.traffic);
    outbox.sending(batch.id).unwrap();
    drop(outbox);
    let mut outbox = dir.open();
    assert!(matches!(outbox.prepare(), Err(TrafficError::Uncertain)));
    assert_eq!(outbox.status()["batch"]["stage"], "uncertain");
    outbox.collect(&sample('a', 2, [5, 6])).unwrap();
    assert!(outbox.resolve(batch.id + 1, true).is_err());
    outbox.resolve(batch.id, false).unwrap();
    let same = outbox.prepare().unwrap().unwrap();
    assert_eq!(same.traffic, batch.traffic);
    assert_eq!(same.stage, Stage::Prepared);
    outbox.sending(same.id).unwrap();
    outbox.finish(same.id, ReportOutcome::Uncertain).unwrap();
    outbox.resolve(same.id, true).unwrap();
    let next = outbox.prepare().unwrap().unwrap();
    assert_eq!(next.traffic[&100], [5, 6]);
}
#[test]
fn counter_maximum_is_split_into_signed_panel_batches_without_wrapping() {
    let dir = Directory::new();
    let mut outbox = dir.open();
    outbox.collect(&sample('a', 1, [u64::MAX, 0])).unwrap();
    let mut total = 0u64;
    for amount in [i64::MAX, i64::MAX, 1] {
        let batch = outbox.prepare().unwrap().unwrap();
        assert_eq!(batch.traffic[&100], [amount, 0]);
        total = total.checked_add(amount as u64).unwrap();
        outbox.sending(batch.id).unwrap();
        outbox
            .finish(batch.id, ReportOutcome::Acknowledged)
            .unwrap();
    }
    assert_eq!(total, u64::MAX);
    assert!(outbox.prepare().unwrap().is_none());
}
#[test]
fn replay_payload_tampering_sequence_gap_bad_ids_and_overflow_are_rejected() {
    let dir = Directory::new();
    let mut outbox = dir.open();
    outbox.collect(&sample('a', 1, [u64::MAX, 1])).unwrap();
    assert!(outbox.collect(&sample('a', 1, [5, 6])).is_err());
    assert!(outbox.collect(&sample('a', 3, [1, 1])).is_err());
    assert!(outbox.collect(&sample('b', 2, [1, 1])).is_err());
    assert!(matches!(
        outbox.collect(&sample('a', 2, [1, 1])),
        Err(TrafficError::Bound)
    ));
    for id in ["-1", "0", "0100", "+100", "not-a-panel-id"] {
        let mut bad = sample('b', 1, [1, 1]);
        bad.traffic = BTreeMap::from([(id.into(), [1, 1])]);
        assert!(outbox.collect(&bad).is_err());
    }
    assert_eq!(
        outbox.status()["pending"]["100"],
        serde_json::json!([u64::MAX, 1])
    );
}
#[test]
fn journal_owner_destination_and_corruption_are_checked_before_reporting() {
    let dir = Directory::new();
    let outbox = dir.open();
    assert!(matches!(
        Outbox::open(&dir.0, "fixture-destination".into()),
        Err(TrafficError::Locked)
    ));
    drop(outbox);
    assert!(matches!(
        Outbox::open(&dir.0, "other-node".into()),
        Err(TrafficError::Invalid)
    ));
    std::fs::write(dir.0.join("traffic.json"), b"broken journal").unwrap();
    assert!(matches!(
        Outbox::open(&dir.0, "fixture-destination".into()),
        Err(TrafficError::Invalid)
    ));
}

#[test]
fn hot_low_ids_cannot_starve_older_high_id_even_across_restart() {
    let dir = Directory::new();
    let mut outbox = dir.open();
    let older = TrafficSnapshot {
        epoch: "a".repeat(32),
        sequence: 1,
        traffic: BTreeMap::from([("1000".into(), [13, 17])]),
    };
    outbox.collect(&older).unwrap();
    let hot = |sequence| TrafficSnapshot {
        epoch: "a".repeat(32),
        sequence,
        traffic: (1..=512).map(|id| (id.to_string(), [1, 1])).collect(),
    };
    outbox.collect(&hot(2)).unwrap();
    let first = outbox.prepare().unwrap().unwrap();
    assert!(!first.traffic.contains_key(&1000));
    outbox.sending(first.id).unwrap();
    outbox
        .finish(first.id, ReportOutcome::Acknowledged)
        .unwrap();
    drop(outbox);
    let mut outbox = dir.open();
    outbox.collect(&hot(3)).unwrap();
    let second = outbox.prepare().unwrap().unwrap();
    assert_eq!(second.traffic[&1000], [13, 17]);
}
#[test]
fn failed_durable_commit_keeps_native_receipt_unacknowledged_and_stops_writes() {
    let dir = Directory::new();
    let mut outbox = dir.open();
    let path = dir.0.join("traffic.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(outbox.collect(&sample('a', 1, [1, 2])).is_err());
    assert!(matches!(outbox.prepare(), Err(TrafficError::Io)));
    assert_eq!(outbox.status()["pending"], serde_json::json!({}));
    assert_eq!(outbox.status()["io_failed"], true);
    std::fs::remove_dir(path).unwrap();
}

#[tokio::test]
async fn shutdown_collects_multiple_native_batches_before_stopping_kernel() {
    use node_core::{NodeSpec, UserSpec};
    use node_kernel::{KernelAdapter, KernelError, KernelStatus};
    use node_runtime::{ManagedKernel, NodeRuntime};
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex, atomic::AtomicBool},
        time::Duration,
    };
    struct Kernel {
        samples: Arc<Mutex<VecDeque<TrafficSnapshot>>>,
        stopped: Arc<AtomicBool>,
        quiesced: Arc<AtomicBool>,
    }
    impl KernelAdapter for Kernel {
        type Candidate = ();
        fn name(&self) -> &'static str {
            "traffic-fixture"
        }
        fn prepare(&self, _: &NodeSpec, _: &[UserSpec]) -> Result<(), KernelError> {
            Ok(())
        }
        fn activate(&self, _: ()) -> Result<(), KernelError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), KernelError> {
            Ok(())
        }
        fn status(&self) -> KernelStatus {
            if self.stopped.load(Ordering::Relaxed) {
                KernelStatus::Stopped
            } else {
                KernelStatus::Ready
            }
        }
    }
    impl ManagedKernel for Kernel {
        fn stop(&self) -> Result<(), KernelError> {
            assert!(self.quiesced.load(Ordering::Relaxed));
            assert!(self.samples.lock().unwrap().is_empty());
            self.stopped.store(true, Ordering::Relaxed);
            Ok(())
        }
        fn traffic_snapshot(&self) -> Result<Option<TrafficSnapshot>, KernelError> {
            assert!(self.quiesced.load(Ordering::Relaxed));
            Ok(self.samples.lock().unwrap().front().cloned())
        }
        fn traffic_quiesce(&self) -> Result<bool, KernelError> {
            self.quiesced.store(true, Ordering::Relaxed);
            Ok(true)
        }
        fn traffic_ack(&self, snapshot: &TrafficSnapshot) -> Result<(), KernelError> {
            let mut samples = self.samples.lock().unwrap();
            assert_eq!(samples.front(), Some(snapshot));
            samples.pop_front();
            Ok(())
        }
    }
    let dir = Directory::new();
    let mut first = sample('a', 1, [1, 1]);
    first.traffic = (1..=512).map(|id| (id.to_string(), [1, 1])).collect();
    let second = TrafficSnapshot {
        epoch: "a".repeat(32),
        sequence: 2,
        traffic: BTreeMap::from([("1000".into(), [5, 7])]),
    };
    let samples = Arc::new(Mutex::new(VecDeque::from([first, second])));
    let stopped = Arc::new(AtomicBool::new(false));
    let panel = node_panel::Panel::new(
        "https://panel.example.com",
        node_panel::Auth::machine("fixture-only", 1, 7),
    )
    .unwrap();
    let runtime = NodeRuntime::new(
        panel,
        Kernel {
            samples: samples.clone(),
            stopped: stopped.clone(),
            quiesced: Arc::new(AtomicBool::new(false)),
        },
        7,
    )
    .with_traffic(&dir.0, Duration::from_secs(60))
    .unwrap();
    runtime.shutdown().await.unwrap();
    assert!(stopped.load(Ordering::Relaxed));
    let book: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.0.join("traffic.json")).unwrap()).unwrap();
    assert_eq!(book["pending"].as_object().unwrap().len(), 513);
    assert_eq!(book["pending"]["1000"], serde_json::json!([5, 7]));
    assert_eq!(book["receipts"]["a".repeat(32)]["sequence"], 2);
}
#[cfg(unix)]
#[test]
fn private_permissions_and_symlink_files_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Directory::new();
    let outbox = dir.open();
    assert_eq!(
        std::fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let path = dir.0.join("traffic.json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(outbox);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Outbox::open(&dir.0, "fixture-destination".into()),
        Err(TrafficError::Invalid)
    ));
    std::fs::remove_file(&path).unwrap();
    symlink("traffic.lock", &path).unwrap();
    assert!(matches!(
        Outbox::open(&dir.0, "fixture-destination".into()),
        Err(TrafficError::Invalid)
    ));
}

#[tokio::test]
async fn failed_quiescence_stops_kernel_but_never_claims_final_capture() {
    use node_core::{NodeSpec, UserSpec};
    use node_kernel::{KernelAdapter, KernelError, KernelStatus};
    use node_runtime::{ManagedKernel, NodeRuntime};
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };
    struct Kernel(Arc<AtomicBool>);
    impl KernelAdapter for Kernel {
        type Candidate = ();
        fn name(&self) -> &'static str {
            "failed-barrier-fixture"
        }
        fn prepare(&self, _: &NodeSpec, _: &[UserSpec]) -> Result<(), KernelError> {
            Ok(())
        }
        fn activate(&self, _: ()) -> Result<(), KernelError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), KernelError> {
            Ok(())
        }
        fn status(&self) -> KernelStatus {
            KernelStatus::Ready
        }
    }
    impl ManagedKernel for Kernel {
        fn traffic_quiesce(&self) -> Result<bool, KernelError> {
            Err(KernelError::Activate("barrier failed".into()))
        }
        fn traffic_snapshot(&self) -> Result<Option<TrafficSnapshot>, KernelError> {
            panic!("no final capture after a failed barrier")
        }
        fn stop(&self) -> Result<(), KernelError> {
            self.0.store(true, Ordering::Relaxed);
            Ok(())
        }
    }
    let dir = Directory::new();
    let stopped = Arc::new(AtomicBool::new(false));
    let panel = node_panel::Panel::new(
        "https://panel.example.com",
        node_panel::Auth::machine("fixture-only", 1, 7),
    )
    .unwrap();
    let runtime = NodeRuntime::new(panel, Kernel(stopped.clone()), 7)
        .with_traffic(&dir.0, Duration::from_secs(60))
        .unwrap();
    assert!(runtime.shutdown().await.is_err());
    assert!(stopped.load(Ordering::Relaxed));
    drop(runtime);
    let book: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.0.join("traffic.json")).unwrap()).unwrap();
    assert_eq!(book["pending"], serde_json::json!({}));
}
