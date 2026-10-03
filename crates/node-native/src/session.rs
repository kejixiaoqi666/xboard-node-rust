//! Payload-only bridge for every protocol. No framing or authentication bytes
//! enter counters. Session ownership belongs to the listener task tree.
use crate::{Error, auth, limits, network, protocol::Address, traffic};
use async_trait::async_trait;
use node_session::{BoxStream, Datagram, Destination, Host, User};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore},
};

pub(crate) struct SessionHost {
    users: auth::Users,
    limits: Arc<limits::Registry>,
    traffic: Arc<traffic::Traffic>,
    network: Arc<network::Network>,
    udp_slots: Arc<Semaphore>,
    tag: Arc<str>,
}
impl SessionHost {
    pub(crate) fn new(
        users: auth::Users,
        limits: Arc<limits::Registry>,
        traffic: Arc<traffic::Traffic>,
        network: Arc<network::Network>,
        udp_slots: Arc<Semaphore>,
        tag: Arc<str>,
    ) -> Self {
        Self {
            users,
            limits,
            traffic,
            network,
            udp_slots,
            tag,
        }
    }
    fn admit(&self, user: &User, peer: SocketAddr) -> io::Result<Arc<limits::Lease>> {
        let current = self.users.load();
        if !current.contains_profile(user) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authentication is no longer current",
            ));
        }
        let policy = current
            .policy(&user.name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "unknown identity"))?;
        self.limits
            .acquire(Arc::clone(&user.name), peer.ip(), policy)
            .map(Arc::new)
            .map_err(convert)
    }
    async fn counter(&self, user: &User) -> io::Result<Option<Arc<traffic::Counter>>> {
        if !self.traffic.enabled() {
            return Ok(None);
        }
        let name = Arc::clone(&user.name);
        self.traffic
            .blocking(move |t| t.user(name))
            .await
            .map_err(|_| io::Error::other("counter worker failed"))?
            .map(Some)
    }
}
fn convert(error: Error) -> io::Error {
    match error {
        Error::Io(error) => error,
        Error::Limited => io::Error::new(io::ErrorKind::WouldBlock, "session limit reached"),
        Error::Blocked | Error::Auth => {
            io::Error::new(io::ErrorKind::PermissionDenied, "session rejected")
        }
        Error::Dns => io::Error::new(io::ErrorKind::NotFound, "destination resolution failed"),
        _ => io::Error::other("session unavailable"),
    }
}
fn address(target: &Destination) -> io::Result<Address> {
    Destination::new(target.host.clone(), target.port)?;
    Ok(match target.host.parse() {
        Ok(ip) => Address::Ip(ip),
        Err(_) => Address::Domain(target.host.clone()),
    })
}
#[async_trait]
impl Host for SessionHost {
    fn users(&self) -> Arc<[User]> {
        self.users.load().profiles()
    }
    async fn connect(
        &self,
        user: &User,
        peer: SocketAddr,
        target: &Destination,
    ) -> io::Result<BoxStream> {
        let lease = self.admit(user, peer)?;
        let changes = self.limits.subscribe_auth();
        let connecting = async {
            let remote = self
                .network
                .connect_for(&address(target)?, target.port, peer, &user.name, &self.tag)
                .await
                .map_err(convert)?;
            if !self.users.load().contains_profile(user) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "identity changed during connection",
                ));
            }
            Ok(Box::new(RateStream::new(
                remote,
                lease,
                self.users.clone(),
                self.counter(user).await?,
                user.clone(),
                self.limits.subscribe_auth(),
            )) as BoxStream)
        };
        tokio::select! {biased;_=revoked(&self.users,user,changes)=>Err(io::Error::new(io::ErrorKind::PermissionDenied,"identity changed during admission")),result=connecting=>result}
    }
    async fn datagram(&self, user: &User, peer: SocketAddr) -> io::Result<Arc<dyn Datagram>> {
        let lease = self.admit(user, peer)?;
        let slot = Arc::clone(&self.udp_slots)
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "UDP session limit reached"))?;
        let changes = self.limits.subscribe_auth();
        let creating = async {
            Ok(routed_datagram(DatagramContext {
                peer,
                lease,
                users: self.users.clone(),
                network: Arc::clone(&self.network),
                tag: Arc::clone(&self.tag),
                user: Arc::clone(&user.name),
                profile: user.clone(),
                changes: self.limits.subscribe_auth(),
                counter: self.counter(user).await?,
                slot: Some(slot),
                count_down: true,
            }))
        };
        tokio::select! {biased;_=revoked(&self.users,user,changes)=>Err(io::Error::new(io::ErrorKind::PermissionDenied,"identity changed during admission")),result=creating=>result}
    }
}
pub(crate) async fn revoked(
    users: &auth::Users,
    profile: &User,
    mut changes: tokio::sync::watch::Receiver<u64>,
) {
    loop {
        if !users.load().contains_profile(profile) {
            return;
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

type Charge = Pin<Box<dyn Future<Output = ()> + Send>>;
fn charge(lease: &Arc<limits::Lease>, users: &auth::Users, amount: usize) -> Charge {
    let lease = Arc::clone(lease);
    let users = Arc::clone(users);
    Box::pin(async move {
        lease.charge(amount, &users).await;
    })
}
struct RateStream {
    inner: Option<BoxStream>,
    lease: Option<Arc<limits::Lease>>,
    users: auth::Users,
    counter: Option<Arc<traffic::Counter>>,
    profile: User,
    auth_wait: AuthWait,
    read_buffer: Box<[u8; 8192]>,
    read_len: usize,
    read_pos: usize,
    read_charge: Option<Charge>,
    write_charge: Option<Charge>,
    write_credit: usize,
    write_reserved: usize,
}
impl RateStream {
    fn new(
        inner: BoxStream,
        lease: Arc<limits::Lease>,
        users: auth::Users,
        counter: Option<Arc<traffic::Counter>>,
        profile: User,
        changes: tokio::sync::watch::Receiver<u64>,
    ) -> Self {
        Self {
            inner: Some(inner),
            lease: Some(lease),
            users,
            counter,
            profile,
            auth_wait: auth_wait(changes),
            read_buffer: Box::new([0; 8192]),
            read_len: 0,
            read_pos: 0,
            read_charge: None,
            write_charge: None,
            write_credit: 0,
            write_reserved: 0,
        }
    }
    fn validate(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let closed = match self.auth_wait.as_mut().poll(cx) {
            Poll::Ready((changes, closed)) => {
                self.auth_wait = auth_wait(changes);
                // Register the new waiter on the next poll. A concurrent second
                // update could make it Ready here; discarding that result would
                // leave a completed async future to be polled again.
                cx.waker().wake_by_ref();
                closed
            }
            Poll::Pending => false,
        };
        if closed || !self.users.load().contains_profile(&self.profile) || self.inner.is_none() {
            self.inner = None;
            self.lease = None;
            self.read_charge = None;
            self.write_charge = None;
            self.read_len = 0;
            self.read_pos = 0;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authenticated session was revoked",
            ))
        } else {
            Ok(())
        }
    }
}
type AuthWait = Pin<Box<dyn Future<Output = (tokio::sync::watch::Receiver<u64>, bool)> + Send>>;
fn auth_wait(mut changes: tokio::sync::watch::Receiver<u64>) -> AuthWait {
    Box::pin(async move {
        let closed = changes.changed().await.is_err();
        (changes, closed)
    })
}
impl AsyncRead for RateStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.validate(cx) {
            return Poll::Ready(Err(error));
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.read_len == this.read_pos {
            let mut buffer = ReadBuf::new(&mut *this.read_buffer);
            match Pin::new(this.inner.as_mut().unwrap()).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    this.read_len = buffer.filled().len();
                    this.read_pos = 0;
                    if this.read_len == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.read_charge = Some(charge(
                        this.lease.as_ref().unwrap(),
                        &this.users,
                        this.read_len,
                    ));
                }
            }
        }
        if let Some(budget) = &mut this.read_charge {
            if budget.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.read_charge = None;
        }
        let size = output.remaining().min(this.read_len - this.read_pos);
        output.put_slice(&this.read_buffer[this.read_pos..this.read_pos + size]);
        this.read_pos += size;
        if let Some(counter) = &this.counter {
            counter.add(1, size);
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for RateStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.validate(cx) {
            return Poll::Ready(Err(error));
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_credit == 0 && this.write_charge.is_none() {
            this.write_reserved = buffer.len().min(8192);
            this.write_charge = Some(charge(
                this.lease.as_ref().unwrap(),
                &this.users,
                this.write_reserved,
            ));
        }
        if let Some(budget) = &mut this.write_charge {
            if budget.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.write_credit = this.write_reserved;
            this.write_charge = None;
        }
        // Never retain the caller's bytes across Pending. Cancellation or a
        // different next buffer cannot inject the previous write's payload.
        let size = buffer.len().min(this.write_credit);
        match Pin::new(this.inner.as_mut().unwrap()).poll_write(cx, &buffer[..size]) {
            Poll::Ready(Ok(size)) => {
                this.write_credit -= size;
                if let Some(counter) = &this.counter {
                    counter.add(0, size);
                }
                Poll::Ready(Ok(size))
            }
            result => result,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.validate(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(this.inner.as_mut().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_charge = None;
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

pub(crate) struct DatagramContext {
    pub peer: SocketAddr,
    pub lease: Arc<limits::Lease>,
    pub users: auth::Users,
    pub network: Arc<network::Network>,
    pub tag: Arc<str>,
    pub user: Arc<str>,
    pub counter: Option<Arc<traffic::Counter>>,
    pub profile: User,
    pub changes: tokio::sync::watch::Receiver<u64>,
    pub slot: Option<OwnedSemaphorePermit>,
    pub count_down: bool,
}
pub(crate) fn routed_datagram(context: DatagramContext) -> Arc<dyn Datagram> {
    Arc::new(UdpSession {
        peer: context.peer,
        lease: std::sync::Mutex::new(Some(context.lease)),
        users: context.users,
        network: context.network,
        tag: context.tag,
        user: context.user,
        profile: context.profile,
        changes: context.changes,
        counter: context.counter,
        channels: Mutex::new(HashMap::new()),
        read_lock: Mutex::new(()),
        send_lock: Mutex::new(()),
        changed: Notify::new(),
        slot: std::sync::Mutex::new(context.slot),
        count_down: context.count_down,
    })
}
struct UdpSession {
    peer: SocketAddr,
    lease: std::sync::Mutex<Option<Arc<limits::Lease>>>,
    users: auth::Users,
    network: Arc<network::Network>,
    profile: User,
    changes: tokio::sync::watch::Receiver<u64>,
    tag: Arc<str>,
    user: Arc<str>,
    counter: Option<Arc<traffic::Counter>>,
    channels: Mutex<HashMap<node_outbound::UdpPlan, Arc<dyn node_outbound::Datagram>>>,
    read_lock: Mutex<()>,
    send_lock: Mutex<()>,
    changed: Notify,
    slot: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
    count_down: bool,
}
impl UdpSession {
    async fn revoked(&self) {
        revoked(&self.users, &self.profile, self.changes.clone()).await;
    }
    async fn close(&self) -> io::Error {
        self.lease.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.channels.lock().await.clear();
        self.changed.notify_waiters();
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated UDP session was revoked",
        )
    }
    fn lease(&self) -> io::Result<Arc<limits::Lease>> {
        self.lease
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "UDP session is closed"))
    }
    async fn send_current(&self, payload: &[u8], target: &Destination) -> io::Result<usize> {
        if payload.len() > 65507 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "oversized UDP payload",
            ));
        }
        let _send = self.send_lock.lock().await;
        let plan = self
            .network
            .udp_plan_for(
                &address(target)?,
                target.port,
                self.peer,
                &self.user,
                &self.tag,
            )
            .await
            .map_err(convert)?;
        let existing = self.channels.lock().await.get(&plan).cloned();
        let channel = match existing {
            Some(channel) => channel,
            None => {
                if self.channels.lock().await.len() >= 64 {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "UDP target limit reached",
                    ));
                }
                let channel = self.network.udp_channel(&plan).await.map_err(convert)?;
                self.channels
                    .lock()
                    .await
                    .insert(plan.clone(), channel.clone());
                channel
            }
        };
        self.lease()?.charge(payload.len(), &self.users).await;
        channel.send(payload, plan.destination).await?;
        let size = payload.len();
        if let Some(counter) = &self.counter {
            counter.add(0, size);
        }
        self.changed.notify_one();
        Ok(size)
    }
    async fn receive_current(&self, buffer: &mut [u8]) -> io::Result<(usize, Destination)> {
        use futures::StreamExt;
        let _read = self.read_lock.lock().await;
        loop {
            let changed = self.changed.notified();
            let channels: Vec<_> = self.channels.lock().await.values().cloned().collect();
            if channels.is_empty() {
                changed.await;
                continue;
            }
            // Each channel retains partial stream frames across cancellation.
            // Waiting channels allocate no output buffers. Completed packets own
            // Graph's shared 8MiB permits until the caller has copied them.
            let mut packets: futures::stream::FuturesUnordered<_> = channels
                .into_iter()
                .map(|channel| async move { channel.receive_packet().await })
                .collect();
            let packet = tokio::select! {
                _=changed=>continue,
                packet=packets.next()=>packet.ok_or_else(||io::Error::other("UDP channels unavailable"))??,
            };
            if packet.payload.len() > 65507 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized remote UDP payload",
                ));
            }
            // Graph returns a complete owned packet. Accept fitting protocol
            // buffers and reject an actual oversized packet before copying or
            // counting; never truncate it to the caller's receive capacity.
            if packet.payload.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP packet exceeds receive buffer",
                ));
            }
            self.lease()?
                .charge(packet.payload.len(), &self.users)
                .await;
            let size = packet.payload.len();
            buffer[..size].copy_from_slice(&packet.payload);
            if self.count_down
                && let Some(counter) = &self.counter
            {
                counter.add(1, size);
            }
            return Ok((
                size,
                Destination::new(packet.source.ip().to_string(), packet.source.port())?,
            ));
        }
    }
}
#[async_trait]
impl Datagram for UdpSession {
    async fn send(&self, payload: &[u8], target: &Destination) -> io::Result<usize> {
        if !self.users.load().contains_profile(&self.profile) {
            return Err(self.close().await);
        }
        tokio::select! {biased;_=self.revoked()=>Err(self.close().await),result=self.send_current(payload,target)=>result}
    }
    async fn receive(&self, buffer: &mut [u8]) -> io::Result<(usize, Destination)> {
        if !self.users.load().contains_profile(&self.profile) {
            return Err(self.close().await);
        }
        tokio::select! {biased;_=self.revoked()=>Err(self.close().await),result=self.receive_current(buffer)=>result}
    }
}

#[cfg(test)]
#[path = "session_integration.rs"]
mod tests;
