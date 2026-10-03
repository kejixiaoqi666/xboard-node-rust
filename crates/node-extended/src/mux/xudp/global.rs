//! Listener-scoped XUDP GlobalID associations. No detached receive workers.
use node_session::{Datagram, Host, User};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, oneshot, watch},
    task::AbortHandle,
};

const IDLE: Duration = Duration::from_secs(30);
#[derive(Clone, Hash, Eq, PartialEq)]
pub(super) struct Key {
    id: [u8; 8],
    identity: [u8; 32],
    peer: IpAddr,
}
#[derive(Default)]
pub struct GlobalSessions {
    sessions: Mutex<HashMap<Key, Arc<Channel>>>,
    next: AtomicU64,
}
pub(super) struct Lease {
    pub datagram: Arc<dyn Datagram>,
    _session: OwnedSemaphorePermit,
}
pub(super) struct Channel {
    pub lease: Arc<Lease>,
    binding: AsyncMutex<Option<Binding>>,
    active: Arc<AtomicU64>,
    last: Arc<Mutex<Instant>>,
}
struct Binding {
    token: u64,
    abort: AbortHandle,
    done: watch::Receiver<bool>,
    fin: tokio::sync::mpsc::Sender<crate::channel::Outgoing>,
    id: u16,
}
pub(super) struct Completed {
    done: watch::Sender<bool>,
    active: Arc<AtomicU64>,
    last: Arc<Mutex<Instant>>,
    token: u64,
}
impl Drop for Completed {
    fn drop(&mut self) {
        if self
            .active
            .compare_exchange(self.token, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
            && let Ok(mut last) = self.last.lock()
        {
            *last = Instant::now();
        }
        let _ = self.done.send(true);
    }
}
impl GlobalSessions {
    /// Expired idle associations own no workers. Calling this releases their
    /// Host channel and session permit; admissions also prune lazily.
    pub fn purge_idle(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, channel| {
                channel.active.load(Ordering::SeqCst) != 0
                    || channel.last.lock().is_ok_and(|last| last.elapsed() < IDLE)
            });
        }
    }
    pub fn cached_sessions(&self) -> usize {
        self.sessions.lock().map_or(0, |sessions| sessions.len())
    }
    /// The listener owner can release paused associations after all carriers
    /// have joined, without waiting for the reconnect grace period.
    pub fn clear_idle(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, channel| channel.active.load(Ordering::SeqCst) != 0);
        }
    }
    /// Call after publishing a new immutable authentication snapshot. Removes
    /// stale full profiles, including same-name password/UUID replacements.
    /// Paused channels release their Host lease and logical-session permit
    /// immediately; active workers are revoked by the Host's authentication
    /// watch and still joined by their owning carrier.
    pub fn prune_users(&self, users: &[User]) {
        let identities: HashSet<_> = users.iter().map(identity).collect();
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|key, _| identities.contains(&key.identity));
        }
    }
    pub(super) async fn admit(
        &self,
        id: [u8; 8],
        user: &User,
        peer: SocketAddr,
        host: &Arc<dyn Host>,
        config: &crate::Config,
    ) -> io::Result<(Key, Arc<Channel>, u64)> {
        // Reassociation still checks the hot Host identity before reusing the
        // channel. Bind an IP, rather than a transient TCP source port, so the
        // Host's rate and device lease remain attached to the original user/IP.
        if !host.users().iter().any(|candidate| candidate == user) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "XUDP identity was revoked",
            ));
        }
        let key = Key {
            id,
            identity: identity(user),
            peer: canonical(peer.ip()),
        };
        self.purge_idle();
        let existing = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| io::Error::other("XUDP global session lock poisoned"))?;
            if !host.users().iter().any(|candidate| candidate == user) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "XUDP identity was revoked",
                ));
            }
            sessions.get(&key).cloned()
        };
        let channel = match existing {
            Some(channel) => channel,
            None => {
                let budget = config
                    .shared_budget
                    .bind(config.max_queued_bytes, config.max_sessions)?;
                let session = budget.session()?;
                let datagram =
                    tokio::time::timeout(config.handshake_timeout, host.datagram(user, peer))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "XUDP UDP admission timed out")
                        })??;
                let candidate = Arc::new(Channel {
                    lease: Arc::new(Lease {
                        datagram,
                        _session: session,
                    }),
                    binding: AsyncMutex::new(None),
                    active: Arc::new(AtomicU64::new(0)),
                    last: Arc::new(Mutex::new(Instant::now())),
                });
                let mut sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| io::Error::other("XUDP global session lock poisoned"))?;
                // Serialize this final check with prune_users. An asynchronous
                // Host admission that began before the hot update cannot
                // resurrect a paused old-profile cache after the prune.
                if !host.users().iter().any(|current| current == user) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "XUDP identity was revoked during admission",
                    ));
                }
                sessions.entry(key.clone()).or_insert(candidate).clone()
            }
        };
        let token = self
            .next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |token| {
                token.checked_add(1)
            })
            .map_err(|_| io::Error::other("XUDP global generation exhausted"))?
            + 1;
        Ok((key, channel, token))
    }
    pub(super) async fn remove_binding(&self, key: &Key, channel: &Arc<Channel>, token: u64) {
        let mut binding = channel.binding.lock().await;
        if binding
            .as_ref()
            .is_some_and(|binding| binding.token == token)
        {
            *binding = None;
            if let Ok(mut sessions) = self.sessions.lock()
                && sessions
                    .get(key)
                    .is_some_and(|current| Arc::ptr_eq(current, channel))
            {
                sessions.remove(key);
            }
        }
    }
}
impl Channel {
    pub(super) fn completion(&self, token: u64) -> (Completed, watch::Receiver<bool>) {
        let (done, receiver) = watch::channel(false);
        (
            Completed {
                done,
                active: self.active.clone(),
                last: self.last.clone(),
                token,
            },
            receiver,
        )
    }
    pub(super) async fn bind(
        &self,
        token: u64,
        abort: AbortHandle,
        done: watch::Receiver<bool>,
        fin: tokio::sync::mpsc::Sender<crate::channel::Outgoing>,
        id: u16,
        start: oneshot::Sender<()>,
    ) -> io::Result<()> {
        let mut binding = self.binding.lock().await;
        if let Some(mut previous) = binding.take() {
            previous.abort.abort();
            while !*previous.done.borrow() {
                if previous.done.changed().await.is_err() {
                    break;
                }
            }
            let _ = previous
                .fin
                .try_send(crate::channel::Outgoing::Fin(previous.id as u32));
        }
        self.active.store(token, Ordering::SeqCst);
        *binding = Some(Binding {
            token,
            abort,
            done,
            fin,
            id,
        });
        start
            .send(())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XUDP rebind worker closed"))
    }
}
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}
fn identity(user: &User) -> [u8; 32] {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(&(user.name.len() as u64).to_be_bytes());
    digest.update(user.name.as_bytes());
    digest.update(&[user.uuid.is_some() as u8]);
    if let Some(uuid) = user.uuid {
        digest.update(&uuid);
    }
    digest.update(&[user.password.is_some() as u8]);
    let password = user.password.as_deref().unwrap_or_default();
    digest.update(&(password.len() as u64).to_be_bytes());
    digest.update(password.as_bytes());
    digest.finish().as_ref().try_into().unwrap()
}
