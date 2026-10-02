use node_core::{MAX_TRAFFIC_ROWS, TrafficSnapshot};
use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_USERS: usize = 65536;

#[derive(Default)]
pub(crate) struct Counter {
    bytes: [AtomicU64; 2],
    overflow: AtomicBool,
    dirty: Arc<AtomicBool>,
}
impl Counter {
    fn add(&self, direction: usize, size: usize) {
        if size == 0 {
            return;
        }
        if self.bytes[direction]
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_add(size as u64)
            })
            .is_err()
        {
            self.overflow.store(true, Ordering::Relaxed);
        }
        self.dirty.store(true, Ordering::Release);
    }
    fn read(&self) -> [u64; 2] {
        self.bytes.each_ref().map(|n| n.load(Ordering::Relaxed))
    }
}

struct State {
    epoch: String,
    sequence: u64,
    counters: BTreeMap<Arc<str>, Arc<Counter>>,
    frozen: Option<TrafficSnapshot>,
    cursor: Option<Arc<str>>,
}
pub(crate) struct Traffic(
    Mutex<State>,
    bool,
    Option<crate::traffic_store::Store>,
    String,
    Arc<AtomicBool>,
    Arc<tokio::sync::Semaphore>,
);
impl Traffic {
    #[cfg(test)]
    pub(crate) fn new(epoch: String) -> Self {
        Self::new_with_enabled(epoch, true)
    }
    pub(crate) fn new_with_enabled(epoch: String, enabled: bool) -> Self {
        Self(
            Mutex::new(State {
                epoch,
                sequence: 0,
                counters: BTreeMap::new(),
                frozen: None,
                cursor: None,
            }),
            enabled,
            None,
            String::new(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(tokio::sync::Semaphore::new(2)),
        )
    }
    #[cfg(unix)]
    pub(crate) fn random(enabled: bool) -> io::Result<Self> {
        use std::io::Read;
        let mut bytes = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self::new_with_enabled(
            bytes.iter().map(|b| format!("{b:02x}")).collect(),
            enabled,
        ))
    }
    #[cfg(unix)]
    pub(crate) fn open(directory: &std::path::Path, destination: String) -> io::Result<Self> {
        let (store, book) = crate::traffic_store::Store::open(directory, &destination)?;
        let mut result = Self::random(true)?;
        if let Some(book) = book {
            let state = result
                .0
                .get_mut()
                .map_err(|_| io::Error::other("traffic lock poisoned"))?;
            state.epoch = book.epoch;
            state.sequence = book.sequence;
            state.frozen = book.frozen;
            state.cursor = book.cursor.map(Arc::from);
            state.counters = book
                .counters
                .into_iter()
                .map(|(id, bytes)| {
                    (
                        Arc::from(id),
                        Arc::new(Counter {
                            bytes: bytes.map(AtomicU64::new),
                            overflow: AtomicBool::new(false),
                            dirty: Arc::clone(&result.4),
                        }),
                    )
                })
                .collect();
        }
        result.2 = Some(store);
        result.3 = destination;
        result.checkpoint(true)?;
        Ok(result)
    }
    fn persist(
        &self,
        state: &State,
        subtract: Option<&TrafficSnapshot>,
        clear_frozen: bool,
    ) -> io::Result<()> {
        let Some(store) = &self.2 else {
            return Ok(());
        };
        if state
            .counters
            .values()
            .any(|c| c.overflow.load(Ordering::Relaxed))
        {
            return Err(io::Error::other("traffic counter overflow"));
        }
        let counters = state
            .counters
            .iter()
            .filter_map(|(id, c)| {
                let mut bytes = c.read();
                if let Some(amount) = subtract.and_then(|s| s.traffic.get(id.as_ref())) {
                    bytes[0] -= amount[0];
                    bytes[1] -= amount[1];
                }
                (bytes != [0, 0]).then(|| (id.to_string(), bytes))
            })
            .collect();
        store.commit(&crate::traffic_store::Book {
            version: 1,
            destination: self.3.clone(),
            epoch: state.epoch.clone(),
            sequence: state.sequence,
            counters,
            frozen: if clear_frozen {
                None
            } else {
                state.frozen.clone()
            },
            cursor: state.cursor.as_ref().map(|id| id.to_string()),
        })
    }
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn checkpoint(&self, force: bool) -> io::Result<()> {
        if self.2.is_none() {
            return Ok(());
        }
        self.2.as_ref().expect("persistent store").healthy()?;
        let dirty = self.4.swap(false, Ordering::AcqRel);
        if !force && !dirty {
            return Ok(());
        }
        let state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("traffic lock poisoned"))?;
        self.persist(&state, None, false)
    }
    pub(crate) fn user(&self, id: Arc<str>) -> io::Result<Arc<Counter>> {
        if !crate::traffic_store::valid_id(&id) {
            return Err(io::Error::other("invalid traffic identity"));
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("traffic lock poisoned"))?;
        if let Some(counter) = state.counters.get(&id) {
            return Ok(Arc::clone(counter));
        }
        // Frozen entries stay alive until acknowledged. Active connections also
        // own an Arc, so an update/removal cannot reassign their accounting identity.
        if state.frozen.is_none() && state.counters.len() >= MAX_USERS {
            state.counters.retain(|_, c| {
                Arc::strong_count(c) > 1 || c.read() != [0, 0] || c.overflow.load(Ordering::Relaxed)
            });
        }
        if state.counters.len() >= MAX_USERS {
            return Err(io::Error::other("traffic user limit reached"));
        }
        let counter = Arc::new(Counter {
            bytes: Default::default(),
            overflow: AtomicBool::new(false),
            dirty: Arc::clone(&self.4),
        });
        state.counters.insert(id, Arc::clone(&counter));
        Ok(counter)
    }
    pub(crate) fn snapshot(&self) -> io::Result<Option<TrafficSnapshot>> {
        if let Some(store) = &self.2 {
            store.healthy()?;
        }
        if !self.enabled() {
            return Ok(None);
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("traffic lock poisoned"))?;
        if let Some(frozen) = &state.frozen {
            return Ok(Some(frozen.clone()));
        }
        if state
            .counters
            .values()
            .any(|c| c.overflow.load(Ordering::Relaxed))
        {
            return Err(io::Error::other("traffic counter overflow"));
        }
        let cursor = state.cursor.as_deref();
        let selected: Vec<_> = state
            .counters
            .iter()
            .filter(|(id, _)| cursor.is_none_or(|c| id.as_ref() > c))
            .chain(
                state
                    .counters
                    .iter()
                    .filter(|(id, _)| cursor.is_some_and(|c| id.as_ref() <= c)),
            )
            .map(|(id, c)| (id.to_string(), c.read()))
            .filter(|(_, bytes)| *bytes != [0, 0])
            .take(MAX_TRAFFIC_ROWS)
            .collect();
        state.cursor = selected.last().map(|(id, _)| Arc::from(id.as_str()));
        let traffic: BTreeMap<_, _> = selected.into_iter().collect();
        if traffic.is_empty() {
            state.counters.retain(|_, c| {
                Arc::strong_count(c) > 1 || c.read() != [0, 0] || c.overflow.load(Ordering::Relaxed)
            });
            return Ok(None);
        }
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("traffic sequence overflow"))?;
        let snapshot = TrafficSnapshot {
            epoch: state.epoch.clone(),
            sequence: state.sequence,
            traffic,
        };
        state.frozen = Some(snapshot.clone());
        self.persist(&state, None, false)?;
        Ok(Some(snapshot))
    }
    pub(crate) fn ack(&self, epoch: &str, sequence: u64) -> io::Result<()> {
        if let Some(store) = &self.2 {
            store.healthy()?;
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("traffic lock poisoned"))?;
        if state.epoch != epoch || sequence == 0 || sequence != state.sequence {
            return Err(io::Error::other("traffic acknowledgement mismatch"));
        }
        if let Some(snapshot) = state.frozen.as_ref() {
            self.persist(&state, Some(snapshot), true)?;
        }
        if let Some(snapshot) = state.frozen.take() {
            for (id, bytes) in snapshot.traffic {
                let counter = state
                    .counters
                    .get(id.as_str())
                    .expect("frozen counter retained");
                for (direction, amount) in bytes.into_iter().enumerate() {
                    counter.bytes[direction].fetch_sub(amount, Ordering::Relaxed);
                }
            }
            state.counters.retain(|_, c| {
                Arc::strong_count(c) > 1 || c.read() != [0, 0] || c.overflow.load(Ordering::Relaxed)
            });
        }
        Ok(())
    }
    pub(crate) fn enabled(&self) -> bool {
        self.1
    }
    /// Bound running and queued work even when an async caller is cancelled.
    /// Moving the permit into the worker keeps detached fsync/lock work charged
    /// until it actually ends. Waiting for a permit stays cancellable.
    pub(crate) async fn blocking<T: Send + 'static>(
        self: &Arc<Self>,
        work: impl FnOnce(&Self) -> T + Send + 'static,
    ) -> io::Result<T> {
        let permit = Arc::clone(&self.5)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("native work gate closed"))?;
        let traffic = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(&traffic)
        })
        .await
        .map_err(|_| io::Error::other("native work task failed"))
    }
    #[cfg(test)]
    pub(crate) fn with_metadata_locked_for_test(&self, work: impl FnOnce()) {
        let _state = self.0.lock().unwrap();
        work();
    }
}

/// Account only plaintext payload successfully written to the next socket.
/// Partial writes, errors and cancelled copies retain already forwarded bytes.
pub(crate) struct Counted<S> {
    stream: S,
    counter: Arc<Counter>,
    direction: usize,
}
impl<S> Counted<S> {
    pub(crate) fn new(stream: S, counter: Arc<Counter>, direction: usize) -> Self {
        Self {
            stream,
            counter,
            direction,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.counter.add(self.direction, n);
        }
        result
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = result {
            self.counter.add(self.direction, n);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn registry() -> Traffic {
        Traffic::new("a".repeat(32))
    }
    #[cfg(unix)]
    #[test]
    fn durable_snapshot_ack_and_periodic_tail_survive_reopen() {
        let directory = crate::traffic_store::tests::Directory::new();
        let destination = "fixture-destination".to_string();
        let traffic = Traffic::open(&directory.0, destination.clone()).unwrap();
        let user = traffic.user(Arc::from("9")).unwrap();
        user.add(0, 31);
        user.add(1, 17);
        traffic.checkpoint(false).unwrap();
        user.add(0, 999); // Deliberately not checkpointed: this crash tail is not promised.
        drop(user);
        drop(traffic);
        let traffic = Traffic::open(&directory.0, destination.clone()).unwrap();
        let frozen = traffic.snapshot().unwrap().unwrap();
        assert_eq!(frozen.traffic["9"], [31, 17]);
        let user = traffic.user(Arc::from("9")).unwrap();
        user.add(0, 11);
        traffic.checkpoint(false).unwrap();
        drop(user);
        drop(traffic);
        let traffic = Traffic::open(&directory.0, destination.clone()).unwrap();
        assert_eq!(traffic.snapshot().unwrap(), Some(frozen.clone()));
        traffic.ack(&frozen.epoch, frozen.sequence).unwrap();
        drop(traffic);
        let traffic = Traffic::open(&directory.0, destination).unwrap();
        traffic.ack(&frozen.epoch, frozen.sequence).unwrap();
        let next = traffic.snapshot().unwrap().unwrap();
        assert_eq!(next.epoch, frozen.epoch);
        assert_eq!(next.sequence, frozen.sequence + 1);
        assert_eq!(next.traffic["9"], [11, 0]);
    }
    #[test]
    fn snapshot_retry_ack_and_new_bytes_keep_stable_identity() {
        let traffic = registry();
        let held = traffic.user(Arc::from("100")).unwrap();
        held.add(0, 31);
        held.add(1, 17);
        let first = traffic.snapshot().unwrap().unwrap();
        held.add(0, 9);
        assert_eq!(traffic.snapshot().unwrap(), Some(first.clone()));
        assert!(traffic.ack("wrong", first.sequence).is_err());
        traffic.ack(&first.epoch, first.sequence).unwrap();
        traffic.ack(&first.epoch, first.sequence).unwrap();
        assert!(Arc::ptr_eq(&held, &traffic.user(Arc::from("100")).unwrap()));
        let second = traffic.snapshot().unwrap().unwrap();
        assert_eq!(second.traffic["100"], [9, 0]);
        assert!(traffic.ack(&first.epoch, first.sequence).is_err());
        traffic.ack(&second.epoch, second.sequence).unwrap();
        drop(held);
        assert!(traffic.snapshot().unwrap().is_none());
        assert_eq!(traffic.0.lock().unwrap().counters.len(), 0);
        let _ = traffic.user(Arc::from("200")).unwrap();
        assert_eq!(traffic.0.lock().unwrap().counters.len(), 1);
    }
    #[tokio::test]
    async fn cancelled_slow_storage_work_stays_bounded_across_new_callers() {
        use std::sync::atomic::AtomicUsize;
        let traffic = Arc::new(registry());
        let locked = Arc::clone(&traffic);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            locked.with_metadata_locked_for_test(|| {
                entered_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(std::time::Duration::from_secs(3));
            });
        });
        entered_rx.await.unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        for cycle in 0..4 {
            let mut callers = Vec::new();
            for _ in 0..16 {
                let traffic = Arc::clone(&traffic);
                let started = Arc::clone(&started);
                callers.push(tokio::spawn(async move {
                    traffic
                        .blocking(move |t| {
                            started.fetch_add(1, Ordering::Relaxed);
                            t.user(Arc::from("100"))
                        })
                        .await
                }));
            }
            tokio::time::timeout(std::time::Duration::from_millis(200), async {
                while started.load(Ordering::Relaxed) != 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            tokio::task::yield_now().await;
            for task in callers {
                task.abort();
                assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            }
            assert_eq!(started.load(Ordering::Relaxed), 2, "cycle {cycle}");
            assert_eq!(traffic.5.available_permits(), 0);
        }
        release_tx.send(()).unwrap();
        tokio::task::spawn_blocking(move || holder.join().unwrap())
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(200), async {
            while traffic.5.available_permits() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(started.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn overflow_is_an_error_not_a_wrapped_or_saturated_bill() {
        let traffic = registry();
        let counter = traffic.user(Arc::from("100")).unwrap();
        counter.bytes[0].store(u64::MAX, Ordering::Relaxed);
        counter.add(0, 1);
        assert!(traffic.snapshot().is_err());
    }
    #[tokio::test]
    async fn partial_writes_are_visible_before_connection_close_and_failed_write() {
        let traffic = registry();
        let counter = traffic.user(Arc::from("100")).unwrap();
        let (writer, mut reader) = tokio::io::duplex(3);
        let mut writer = Counted::new(writer, counter, 0);
        assert_eq!(writer.write(b"abcdef").await.unwrap(), 3);
        assert_eq!(traffic.snapshot().unwrap().unwrap().traffic["100"], [3, 0]);
        let mut read = [0; 3];
        reader.read_exact(&mut read).await.unwrap();
        drop(reader);
        assert!(writer.write(b"lost bytes").await.is_err());
        assert_eq!(traffic.snapshot().unwrap().unwrap().traffic["100"], [3, 0]);
    }
}
