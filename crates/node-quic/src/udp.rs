use crate::wire::{self, MAX_PAYLOAD, Mode, Packet};
use bytes::{Bytes, BytesMut};
use node_session::{Datagram, Destination, Host, User};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const SESSION_LIMIT: usize = 1024;
const FRAGMENT_LIMIT: usize = 256;
const TARGET_LIMIT: usize = 64;
const FRAGMENT_TTL: Duration = Duration::from_secs(10);
const SESSION_TTL: Duration = Duration::from_secs(60);
const RECEIVE_POOL: usize = 2 * 1024 * 1024;
const QUEUE_POOL: usize = 6 * 1024 * 1024;
const RECEIVE_BUFFER: usize = 65_535;

pub(crate) struct Budget {
    pub queue: Arc<Semaphore>,
    pub tracker: TaskTracker,
    receive: Arc<Semaphore>,
    sessions: Arc<Semaphore>,
    fragments: Arc<Semaphore>,
}
impl Budget {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Arc::new(Semaphore::new(QUEUE_POOL)),
            tracker: TaskTracker::new(),
            receive: Arc::new(Semaphore::new(RECEIVE_POOL)),
            sessions: Arc::new(Semaphore::new(SESSION_LIMIT)),
            fragments: Arc::new(Semaphore::new(FRAGMENT_LIMIT)),
        })
    }
}

pub(crate) struct HeldBytes {
    pub bytes: Bytes,
    _permit: OwnedSemaphorePermit,
}
impl HeldBytes {
    fn new(
        bytes: Bytes,
        budget: &Budget,
        reserved: Option<OwnedSemaphorePermit>,
    ) -> io::Result<Self> {
        let n = bytes.len().max(1);
        let permit = if let Some(mut permit) = reserved {
            if permit.num_permits() < n {
                return Err(wire::invalid("insufficient packet reservation"));
            }
            let keep = permit
                .split(n)
                .ok_or_else(|| wire::invalid("packet reservation failed"))?;
            drop(permit);
            keep
        } else {
            budget
                .queue
                .clone()
                .try_acquire_many_owned(n as u32)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "UDP queue budget exhausted")
                })?
        };
        Ok(Self {
            bytes,
            _permit: permit,
        })
    }
}
struct Fragment {
    total: u8,
    target: Option<Destination>,
    parts: Vec<Option<HeldBytes>>,
    size: usize,
    updated: Instant,
    _permit: OwnedSemaphorePermit,
}
type FragmentKey = (u32, u16, Mode);

pub(crate) struct Reassembly {
    entries: HashMap<FragmentKey, Fragment>,
    budget: Arc<Budget>,
}
impl Reassembly {
    fn new(budget: Arc<Budget>) -> Self {
        Self {
            entries: HashMap::new(),
            budget,
        }
    }
    fn purge(&mut self) {
        self.entries
            .retain(|_, v| v.updated.elapsed() < FRAGMENT_TTL);
    }
    fn remove_session(&mut self, id: u32) {
        self.entries.retain(|(assoc, _, _), _| *assoc != id);
    }
    fn push(
        &mut self,
        p: Packet,
        reservation: Option<OwnedSemaphorePermit>,
    ) -> io::Result<Option<(u32, Mode, Destination, HeldBytes)>> {
        p.validate()?;
        let Packet {
            assoc,
            id,
            total,
            index,
            target,
            payload,
            mode,
        } = p;
        let held = HeldBytes::new(payload, &self.budget, reservation)?;
        if total == 1 {
            return Ok(Some((
                assoc,
                mode,
                target.ok_or_else(|| wire::invalid("missing UDP target"))?,
                held,
            )));
        }
        let key = (assoc, id, mode);
        if !self.entries.contains_key(&key) {
            let permit = self
                .budget
                .fragments
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "fragment cache limit reached")
                })?;
            self.entries.insert(
                key,
                Fragment {
                    total,
                    target: None,
                    parts: (0..total).map(|_| None).collect(),
                    size: 0,
                    updated: Instant::now(),
                    _permit: permit,
                },
            );
        }
        let entry = self.entries.get_mut(&key).expect("inserted fragment");
        if entry.total != total
            || entry.parts[index as usize].is_some()
            || entry.size + held.bytes.len() > MAX_PAYLOAD
            || target
                .as_ref()
                .is_some_and(|d| entry.target.as_ref().is_some_and(|old| old != d))
        {
            self.entries.remove(&key);
            return Err(wire::invalid("inconsistent or duplicate UDP fragments"));
        }
        if let Some(target) = target {
            entry.target = Some(target);
        }
        entry.size += held.bytes.len();
        entry.updated = Instant::now();
        entry.parts[index as usize] = Some(held);
        if entry.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let entry = self.entries.remove(&key).expect("complete fragment");
        let permit = self
            .budget
            .queue
            .clone()
            .try_acquire_many_owned(entry.size.max(1) as u32)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "UDP reassembly budget exhausted")
            })?;
        let mut combined = BytesMut::with_capacity(entry.size);
        for part in entry.parts {
            combined.extend_from_slice(&part.expect("complete fragment").bytes);
        }
        Ok(Some((
            assoc,
            mode,
            entry
                .target
                .ok_or_else(|| wire::invalid("missing reassembly target"))?,
            HeldBytes {
                bytes: combined.freeze(),
                _permit: permit,
            },
        )))
    }
}

struct Outbound {
    target: Destination,
    payload: HeldBytes,
}
struct Session {
    sender: mpsc::Sender<Outbound>,
    cancel: CancellationToken,
    last: Instant,
    targets: HashSet<Destination>,
    generation: u64,
}

pub(crate) struct Manager {
    sessions: HashMap<u32, Session>,
    pub tasks: JoinSet<(u32, u64)>,
    fragments: Reassembly,
    budget: Arc<Budget>,
    connection: quinn::Connection,
    host: Arc<dyn Host>,
    user: User,
    peer: SocketAddr,
    cancel: CancellationToken,
    generation: u64,
}
impl Manager {
    pub fn new(
        connection: quinn::Connection,
        host: Arc<dyn Host>,
        user: User,
        peer: SocketAddr,
        budget: Arc<Budget>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            tasks: JoinSet::new(),
            fragments: Reassembly::new(budget.clone()),
            budget,
            connection,
            host,
            user,
            peer,
            cancel,
            generation: 0,
        }
    }
    pub fn purge(&mut self) {
        self.fragments.purge();
        self.sessions.retain(|_, v| {
            if v.last.elapsed() > SESSION_TTL {
                v.cancel.cancel();
                false
            } else {
                true
            }
        });
    }
    pub fn finished(&mut self, id: u32, generation: u64) {
        if self
            .sessions
            .get(&id)
            .is_some_and(|s| s.generation == generation)
        {
            self.sessions.remove(&id);
            self.fragments.remove_session(id);
        }
    }
    pub fn dissociate(&mut self, id: u32) {
        if let Some(s) = self.sessions.remove(&id) {
            s.cancel.cancel();
        }
        self.fragments.remove_session(id);
    }
    pub async fn route(
        &mut self,
        p: Packet,
        reservation: Option<OwnedSemaphorePermit>,
    ) -> io::Result<()> {
        let Some((assoc, mode, target, payload)) = self.fragments.push(p, reservation)? else {
            return Ok(());
        };
        if !self.host.users().iter().any(|u| u == &self.user) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "user revoked",
            ));
        }
        if !self.sessions.contains_key(&assoc) {
            let permit = self
                .budget
                .sessions
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "UDP session limit reached")
                })?;
            let channel = timeout(
                Duration::from_secs(10),
                self.host.datagram(&self.user, self.peer),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP admission timed out"))??;
            let (tx, rx) = mpsc::channel(64);
            let cancel = self.cancel.child_token();
            self.generation = self.generation.wrapping_add(1);
            let generation = self.generation;
            let connection = self.connection.clone();
            let budget = self.budget.clone();
            let child = cancel.clone();
            self.tasks
                .spawn(self.budget.tracker.track_future(async move {
                    let _lease = permit;
                    if let Err(e) =
                        session_worker(assoc, mode, channel, connection, rx, budget, child).await
                    {
                        tracing::debug!(error=%e,"QUIC UDP session ended");
                    }
                    (assoc, generation)
                }));
            self.sessions.insert(
                assoc,
                Session {
                    sender: tx,
                    cancel,
                    last: Instant::now(),
                    targets: HashSet::new(),
                    generation,
                },
            );
        }
        let session = self.sessions.get_mut(&assoc).expect("admitted session");
        if !session.targets.contains(&target) && session.targets.len() >= TARGET_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP target limit reached",
            ));
        }
        session
            .sender
            .try_send(Outbound {
                target: target.clone(),
                payload,
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDP session queue full or closed",
                )
            })?;
        session.targets.insert(target);
        session.last = Instant::now();
        Ok(())
    }
    pub async fn shutdown(&mut self) {
        for session in self.sessions.values() {
            session.cancel.cancel();
        }
        self.sessions.clear();
        self.fragments.entries.clear();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

async fn forward(channel: &dyn Datagram, message: Outbound) -> io::Result<()> {
    let n = timeout(
        Duration::from_secs(10),
        channel.send(&message.payload.bytes, &message.target),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP send timed out"))??;
    if n != message.payload.bytes.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP send"));
    }
    Ok(())
}

async fn session_worker(
    assoc: u32,
    mode: Mode,
    channel: Arc<dyn Datagram>,
    connection: quinn::Connection,
    mut rx: mpsc::Receiver<Outbound>,
    budget: Arc<Budget>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let mut packet_id = 0u16;
    loop {
        // Receive buffers have a separate 2 MiB pool, so idle receivers cannot
        // consume the entire queue/reassembly pool. Waiting sessions can still
        // forward client packets while they wait for a receive-buffer slot.
        let lease = tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            message=rx.recv()=>{let Some(message)=message else{return Ok(());};forward(channel.as_ref(),message).await?;continue;},
            permit=budget.receive.clone().acquire_many_owned(RECEIVE_BUFFER as u32)=>permit.map_err(|_|io::Error::other("receive pool closed"))?,
        };
        let mut buffer = vec![0; RECEIVE_BUFFER];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                _=tokio::time::sleep_until(deadline)=>break,
                message=rx.recv()=>{let Some(message)=message else{return Ok(());};forward(channel.as_ref(),message).await?;},
                response=channel.receive(&mut buffer)=>{
                    let (n,target)=response?;
                    if n>buffer.len() {return Err(wire::invalid("host returned oversized datagram"));}
                    let amount=(2*n+16*1024).max(1);
                    if let Ok(_permit)=budget.queue.clone().try_acquire_many_owned(amount as u32) {
                        let payload=Bytes::copy_from_slice(&buffer[..n]);
                        if mode==Mode::TuicStream {
                            let packet=wire::encode_packet(&Packet {assoc,id:packet_id,total:1,index:0,target:Some(target),payload,mode});
                            timeout(Duration::from_secs(10),async {
                                let mut stream=connection.open_uni().await.map_err(io::Error::other)?;
                                stream.write_all(&packet).await.map_err(io::Error::other)?;
                                stream.finish().map_err(io::Error::other)
                            }).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"TUIC UDP response timed out"))??;
                        }else if let Some(mtu)=connection.max_datagram_size() {
                            for packet in wire::split_packet(assoc,packet_id,target,payload,mode,mtu)? {
                                timeout(Duration::from_secs(10),connection.send_datagram_wait(packet)).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"QUIC datagram response timed out"))?.map_err(io::Error::other)?;
                            }
                        }
                        packet_id=packet_id.wrapping_add(1);
                    }
                    break;
                }
            }
        }
        drop(buffer);
        drop(lease);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fragment(
        assoc: u32,
        id: u16,
        index: u8,
        target: Option<&str>,
        payload: &'static [u8],
    ) -> Packet {
        Packet {
            assoc,
            id,
            index,
            total: 2,
            target: target.map(|t| Destination::new(t, 53).unwrap()),
            payload: Bytes::from_static(payload),
            mode: Mode::TuicNative,
        }
    }
    #[test]
    fn fragments_are_keyed_by_session_and_support_reordering() {
        let mut cache = Reassembly::new(Budget::new());
        assert!(
            cache
                .push(fragment(1, 9, 1, None, b"second"), None)
                .unwrap()
                .is_none()
        );
        assert!(
            cache
                .push(fragment(2, 9, 0, Some("two.test"), b"other"), None)
                .unwrap()
                .is_none()
        );
        let complete = cache
            .push(fragment(1, 9, 0, Some("one.test"), b"first"), None)
            .unwrap()
            .unwrap();
        assert_eq!(complete.2.host, "one.test");
        assert_eq!(&complete.3.bytes[..], b"firstsecond");
        assert_eq!(cache.entries.len(), 1);
    }
    #[test]
    fn duplicate_and_mismatched_fragments_release_budget() {
        let budget = Budget::new();
        let mut cache = Reassembly::new(budget.clone());
        cache
            .push(fragment(1, 9, 0, Some("one.test"), b"a"), None)
            .unwrap();
        assert!(
            cache
                .push(fragment(1, 9, 0, Some("one.test"), b"a"), None)
                .is_err()
        );
        assert!(cache.entries.is_empty());
        assert_eq!(budget.queue.available_permits(), QUEUE_POOL);
        cache
            .push(fragment(1, 9, 0, Some("one.test"), b"a"), None)
            .unwrap();
        assert!(
            cache
                .push(fragment(1, 9, 1, Some("other.test"), b"b"), None)
                .is_err()
        );
        assert_eq!(budget.fragments.available_permits(), FRAGMENT_LIMIT);
    }
    #[test]
    fn fragment_allocation_is_bounded_globally() {
        let budget = Budget::new();
        let mut cache = Reassembly::new(budget.clone());
        for id in 0..FRAGMENT_LIMIT {
            cache
                .push(
                    fragment(id as u32, id as u16, 0, Some("one.test"), b"a"),
                    None,
                )
                .unwrap();
        }
        assert!(
            cache
                .push(fragment(999, 999, 0, Some("one.test"), b"a"), None)
                .is_err()
        );
        assert_eq!(cache.entries.len(), FRAGMENT_LIMIT);
        cache.remove_session(0);
        assert_eq!(budget.fragments.available_permits(), 1);
    }
}
