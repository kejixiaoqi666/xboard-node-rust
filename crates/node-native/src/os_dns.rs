//! OS getaddrinfo cannot be cancelled. Keep it off Tokio's storage worker pool,
//! and retain admission until the real work ends, even if its client leaves.
use crate::Error;
use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, Mutex, mpsc},
};
use tokio::sync::{OwnedSemaphorePermit, oneshot};

struct Job {
    name: String,
    reply: oneshot::Sender<Result<Vec<IpAddr>, Error>>,
    _permit: OwnedSemaphorePermit,
}

pub(crate) struct OsResolver {
    sender: mpsc::SyncSender<Job>,
}

impl OsResolver {
    pub fn new() -> Result<Self, std::io::Error> {
        Self::with_lookup(2, 64, |name| {
            Ok((name.as_str(), 0)
                .to_socket_addrs()?
                .take(32)
                .map(|s| s.ip())
                .collect())
        })
    }
    fn with_lookup(
        workers: usize,
        capacity: usize,
        lookup: impl Fn(String) -> Result<Vec<IpAddr>, Error> + Send + Sync + 'static,
    ) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let lookup = Arc::new(lookup);
        for _ in 0..workers {
            let receiver = Arc::clone(&receiver);
            let lookup = Arc::clone(&lookup);
            std::thread::Builder::new()
                .name("xbr-os-dns".into())
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(job) = job else {
                            return;
                        };
                        if job.reply.is_closed() {
                            continue;
                        }
                        let result = lookup(job.name);
                        let _ = job.reply.send(result);
                        // job's permit releases here, not when the waiting async task times out.
                    }
                })?;
        }
        Ok(Self { sender })
    }
    pub fn submit(
        &self,
        name: String,
        permit: OwnedSemaphorePermit,
    ) -> Result<oneshot::Receiver<Result<Vec<IpAddr>, Error>>, Error> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Job {
                name,
                reply,
                _permit: permit,
            })
            .map_err(|_| Error::Limited)?;
        Ok(receive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    #[tokio::test]
    async fn timeouts_and_cancelled_clients_keep_running_os_work_bounded_and_off_storage_pool() {
        let (release, held) = mpsc::channel();
        let held = Mutex::new(held);
        let started = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&started);
        let resolver = OsResolver::with_lookup(1, 1, move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            held.lock().unwrap().recv().unwrap();
            Ok(vec![])
        })
        .unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(3));
        let first = resolver
            .submit(
                "slow.test".into(),
                Arc::clone(&slots).acquire_owned().await.unwrap(),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while started.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), first)
                .await
                .is_err()
        );
        assert_eq!(slots.available_permits(), 2);
        let queued = resolver
            .submit(
                "cancelled.test".into(),
                Arc::clone(&slots).acquire_owned().await.unwrap(),
            )
            .unwrap();
        drop(queued);
        for _ in 0..32 {
            assert!(
                resolver
                    .submit(
                        "overflow.test".into(),
                        Arc::clone(&slots).acquire_owned().await.unwrap()
                    )
                    .is_err()
            );
            assert_eq!(slots.available_permits(), 1);
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), tokio::task::spawn_blocking(|| 42))
                .await
                .unwrap()
                .unwrap(),
            42
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while slots.available_permits() != 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "already cancelled queued work must be skipped"
        );
    }
}
