//! One listener-wide byte budget for data waiting across multiplexed connections.
use bytes::Bytes;
use futures::ready;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};
use tokio_util::sync::{PollSemaphore, PollSender};

pub(crate) struct Queued {
    pub bytes: Bytes,
    _permit: OwnedSemaphorePermit,
}
impl Queued {
    pub fn with_permit(bytes: Bytes, permit: OwnedSemaphorePermit) -> Self {
        Self {
            bytes,
            _permit: permit,
        }
    }
    /// h2 may retain DATA after a logical stream closes. Store the permit inside
    /// Bytes' owner so it survives until h2 releases its last queued reference.
    pub fn into_owned_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }
    pub fn new(bytes: Bytes, budget: &Arc<Semaphore>) -> io::Result<Self> {
        let permit = budget
            .clone()
            .try_acquire_many_owned(bytes.len() as u32)
            .map_err(|_| crate::invalid("multiplexed byte queue is full"))?;
        Ok(Self {
            bytes,
            _permit: permit,
        })
    }
}
impl AsRef<[u8]> for Queued {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
pub(crate) enum Outgoing {
    Data(u32, Queued),
    Udp(u32, Queued, node_session::Destination),
    Fin(u32),
    Control(u8, u32, Bytes),
    Barrier(tokio::sync::oneshot::Sender<()>),
}
pub(crate) struct ChannelStream {
    id: u32,
    input: mpsc::Receiver<Queued>,
    current: Option<Queued>,
    output: PollSender<Outgoing>,
    budget: PollSemaphore,
    closed: bool,
    chunk: usize,
    send_window: Option<(Arc<Semaphore>, PollSemaphore)>,
    read_credit: Option<(Arc<AtomicUsize>, mpsc::Sender<Outgoing>)>,
}
impl ChannelStream {
    pub fn new(
        id: u32,
        input: mpsc::Receiver<Queued>,
        output: mpsc::Sender<Outgoing>,
        budget: Arc<Semaphore>,
        chunk: usize,
    ) -> Self {
        Self {
            id,
            input,
            current: None,
            output: PollSender::new(output),
            budget: PollSemaphore::new(budget),
            closed: false,
            chunk,
            send_window: None,
            read_credit: None,
        }
    }
    pub fn with_yamux_windows(
        mut self,
        send: Arc<Semaphore>,
        receive: Arc<AtomicUsize>,
        output: mpsc::Sender<Outgoing>,
    ) -> Self {
        self.send_window = Some((send.clone(), PollSemaphore::new(send)));
        self.read_credit = Some((receive, output));
        self
    }
    fn consumed(&self, count: usize) -> io::Result<()> {
        if let Some((receive, output)) = &self.read_credit {
            receive.fetch_add(count, Ordering::AcqRel);
            let mut header = [0u8; 12];
            header[1] = 1; // Yamux Window Update, delta is bytes consumed.
            header[4..8].copy_from_slice(&self.id.to_be_bytes());
            header[8..12].copy_from_slice(&(count as u32).to_be_bytes());
            output
                .try_send(Outgoing::Control(255, 0, Bytes::copy_from_slice(&header)))
                .map_err(|_| crate::invalid("yamux window update queue is full"))?;
        }
        Ok(())
    }
}
impl AsyncRead for ChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(current) = self.current.as_mut() {
                let count = current.bytes.len().min(out.remaining());
                out.put_slice(&current.bytes[..count]);
                current.bytes = current.bytes.slice(count..);
                if current.bytes.is_empty() {
                    self.current = None;
                }
                if count != 0 {
                    self.consumed(count)?;
                    return Poll::Ready(Ok(()));
                }
            }
            match ready!(self.input.poll_recv(cx)) {
                Some(data) => self.current = Some(data),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
impl AsyncWrite for ChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux stream closed",
            )));
        }
        if payload.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut count = payload.len().min(self.chunk);
        if let Some((available, _)) = &self.send_window {
            count = count.min(available.available_permits().max(1));
        }
        let permit = ready!(self.budget.poll_acquire_many(cx, count as u32))
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "mux budget closed"))?;
        let credit = if let Some((_, window)) = self.send_window.as_mut() {
            Some(
                ready!(window.poll_acquire_many(cx, count as u32)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "yamux stream window closed")
                })?,
            )
        } else {
            None
        };
        ready!(self.output.poll_reserve(cx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux writer closed"))?;
        if let Some(credit) = credit {
            credit.forget();
        } // The peer replenishes Window Update credits.
        let id = self.id;
        self.output
            .send_item(Outgoing::Data(
                id,
                Queued {
                    bytes: Bytes::copy_from_slice(&payload[..count]),
                    _permit: permit,
                },
            ))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux writer closed"))?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            ready!(self.output.poll_reserve(cx))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux writer closed"))?;
            let id = self.id;
            self.output
                .send_item(Outgoing::Fin(id))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux writer closed"))?;
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn h2_bytes_owner_retains_global_permit_until_last_reference_drops() {
        let budget = Arc::new(Semaphore::new(32));
        let queued = Queued::new(Bytes::from_static(b"12345678"), &budget).unwrap();
        let first = queued.into_owned_bytes();
        let last = first.clone();
        assert_eq!(budget.available_permits(), 24);
        drop(first);
        assert_eq!(budget.available_permits(), 24);
        drop(last);
        assert_eq!(budget.available_permits(), 32);
    }
}
