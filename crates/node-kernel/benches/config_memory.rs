//! Compare the compatibility DOM API and buffered borrowed serialization.
use node_core::{NodeSpec, UserSpec};
use node_kernel::SingBoxConfigBuilder;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

struct Counting;
static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicI64 = AtomicI64::new(0);
static COUNT: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

fn allocated(size: usize) {
    COUNT.fetch_add(1, Relaxed);
    BYTES.fetch_add(size as u64, Relaxed);
    let live = LIVE.fetch_add(size as i64, Relaxed) + size as i64;
    PEAK.fetch_max(live, Relaxed);
}

// Forward the same pointer/layout to System; count only successful allocations.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as i64, Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            LIVE.fetch_sub(layout.size() as i64, Relaxed);
            allocated(size);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

struct ByteCounter(usize);
impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn main() {
    let builder = SingBoxConfigBuilder::new();
    let mut node = NodeSpec::new("vless", 12345);
    node.listen_ip = Some("127.0.0.1".into());
    for n in [1_usize, 10_000, 20_000] {
        let users: Vec<_> = (1..=n)
            .map(|i| UserSpec::new(i as i64, format!("00000000-0000-4000-8000-{i:012}")))
            .collect();
        for mode in ["dom", "stream"] {
            for trial in 1..=3 {
                let input_live = LIVE.load(Relaxed);
                PEAK.store(input_live, Relaxed);
                let count = COUNT.load(Relaxed);
                let bytes = BYTES.load(Relaxed);
                let start = Instant::now();
                let output_len = if mode == "dom" {
                    let value = builder.build(black_box(&node), black_box(&users)).unwrap();
                    let output = serde_json::to_vec(black_box(&value)).unwrap();
                    let length = output.len();
                    black_box(&output);
                    length
                } else {
                    let mut writer = BufWriter::with_capacity(64 * 1024, ByteCounter(0));
                    builder
                        .write_json(&mut writer, black_box(&node), black_box(&users))
                        .unwrap();
                    writer.flush().unwrap();
                    writer.get_ref().0
                };
                let elapsed_us = start.elapsed().as_micros();
                let allocations = COUNT.load(Relaxed) - count;
                let cumulative = BYTES.load(Relaxed) - bytes;
                let peak = PEAK.load(Relaxed) - input_live;
                let retained = LIVE.load(Relaxed) - input_live;
                assert_eq!(retained, 0);
                assert!(output_len < 16 * 1024 * 1024);
                println!(
                    "{{\"mode\":\"{mode}\",\"users\":{n},\"trial\":{trial},\"elapsed_us\":{elapsed_us},\"allocations\":{allocations},\"cumulative_allocated_bytes\":{cumulative},\"peak_live_bytes_excluding_input\":{peak},\"json_bytes\":{output_len},\"retained_bytes_after_drop\":{retained}}}"
                );
            }
        }
    }
}
