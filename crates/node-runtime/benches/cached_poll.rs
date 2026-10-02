//! Includes the loopback HTTP fixture cost. No real protocol kernel in this bench.
#[path = "../tests/support/mod.rs"]
mod support;
use node_core::{NodeSpec, UserSpec};
use node_kernel::{KernelAdapter, KernelError, KernelStatus};
use node_runtime::{ManagedKernel, NodeRuntime, SyncResult};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};

struct CountingAllocator;
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Default)]
struct Kernel(AtomicBool);
impl KernelAdapter for Kernel {
    type Candidate = ();
    fn name(&self) -> &'static str {
        "benchmark-no-data-plane"
    }
    fn prepare(&self, _: &NodeSpec, _: &[UserSpec]) -> Result<(), KernelError> {
        Ok(())
    }
    fn activate(&self, _: ()) -> Result<(), KernelError> {
        self.0.store(true, Ordering::Relaxed);
        Ok(())
    }
    fn rollback(&self) -> Result<(), KernelError> {
        Ok(())
    }
    fn status(&self) -> KernelStatus {
        if self.0.load(Ordering::Relaxed) {
            KernelStatus::Ready
        } else {
            KernelStatus::Stopped
        }
    }
}
impl ManagedKernel for Kernel {
    fn stop(&self) -> Result<(), KernelError> {
        self.0.store(false, Ordering::Relaxed);
        Ok(())
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let users: usize = args.first().map_or(10_000, |v| v.parse().unwrap());
    let polls: u64 = args.get(1).map_or(100, |v| v.parse().unwrap());
    assert!((1..=20_000).contains(&users) && (1..=10_000).contains(&polls));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .unwrap()
        .block_on(async {
            let users_list: Vec<_> = (1..=users)
                .map(|id| UserSpec::new(id as i64, format!("00000000-0000-4000-8000-{id:012}")))
                .collect();
            let panel = support::TestPanel::new(&NodeSpec::new("vless", 443), &users_list).await;
            let mut runtime = NodeRuntime::new(panel.client(), Kernel::default(), 7);
            assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Applied);
            panel.users(&users_list);
            assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
            for _ in 0..5 {
                assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
            }
            ALLOCATIONS.store(0, Ordering::Relaxed);
            BYTES.store(0, Ordering::Relaxed);
            let start = Instant::now();
            for _ in 0..polls {
                assert_eq!(runtime.sync_once().await.unwrap(), SyncResult::Unchanged);
            }
            let elapsed = start.elapsed();
            let allocations = ALLOCATIONS.load(Ordering::Relaxed);
            let bytes = BYTES.load(Ordering::Relaxed);
            println!(
                "{}",
                serde_json::json!({
                    "users": users, "polls": polls,
                    "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
                    "microseconds_per_poll": elapsed.as_secs_f64() * 1_000_000.0 / polls as f64,
                    "allocations": allocations, "allocated_bytes": bytes,
                    "allocations_per_poll": allocations as f64 / polls as f64,
                    "bytes_per_poll": bytes as f64 / polls as f64,
                    "scope": "control sync + loopback HTTP fixture; no TLS or protocol kernel",
                    "metrics": runtime.metrics()
                })
            );
            runtime.shutdown().await.unwrap();
        });
}
