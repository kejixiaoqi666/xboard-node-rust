//! AsyncRead/Write over packet codecs without a detached pump task.
use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, TryStreamExt, ready};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::StreamReader;

#[async_trait]
pub(crate) trait PacketReader: Send {
    async fn read_packet(&mut self) -> io::Result<Option<Bytes>>;
}
#[async_trait]
pub(crate) trait PacketWriter: Send {
    async fn write_packet(&mut self, payload: &[u8]) -> io::Result<()>;
    async fn flush(&mut self) -> io::Result<()>;
    async fn finish(&mut self) -> io::Result<()>;
}
type ReadPackets = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;
type WriteFuture = Pin<Box<dyn Future<Output = (Box<dyn PacketWriter>, io::Result<usize>)> + Send>>;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Write,
    Flush,
    Shutdown,
}
pub(crate) struct PacketStream {
    reader: StreamReader<ReadPackets, Bytes>,
    writer: Option<Box<dyn PacketWriter>>,
    pending: Option<(Operation, WriteFuture)>,
    shutdown: bool,
    chunk_size: usize,
}
impl PacketStream {
    pub fn new<R: PacketReader + 'static, W: PacketWriter + 'static>(
        reader: R,
        writer: W,
        chunk_size: usize,
    ) -> Self {
        let packets = futures::stream::try_unfold(reader, |mut reader| async move {
            Ok(reader.read_packet().await?.map(|bytes| (bytes, reader)))
        })
        .into_stream();
        Self {
            reader: StreamReader::new(Box::pin(packets) as ReadPackets),
            writer: Some(Box::new(writer)),
            pending: None,
            shutdown: false,
            chunk_size,
        }
    }
    fn poll_pending(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<(Operation, usize)>>> {
        let Some((kind, fut)) = self.pending.as_mut() else {
            return Poll::Ready(Ok(None));
        };
        let (writer, result) = ready!(fut.as_mut().poll(cx));
        let kind = *kind;
        self.writer = Some(writer);
        self.pending = None;
        Poll::Ready(result.map(|len| Some((kind, len))))
    }
    fn begin(&mut self, kind: Operation, payload: Vec<u8>) {
        let mut writer = self.writer.take().expect("packet writer present when idle");
        self.pending = Some((
            kind,
            Box::pin(async move {
                let result = match kind {
                    Operation::Write => writer.write_packet(&payload).await.map(|()| payload.len()),
                    Operation::Flush => writer.flush().await.map(|()| 0),
                    Operation::Shutdown => writer.finish().await.map(|()| 0),
                };
                (writer, result)
            }),
        ));
    }
}
impl AsyncRead for PacketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}
impl AsyncWrite for PacketStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet stream shut down",
            )));
        }
        if let Some((Operation::Write, len)) = ready!(self.poll_pending(cx))? {
            return Poll::Ready(Ok(len));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = buf.len().min(self.chunk_size);
        self.begin(Operation::Write, buf[..count].to_vec());
        self.poll_pending(cx)
            .map(|r| r.map(|v| v.expect("write result").1))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((Operation::Flush, _)) = ready!(self.poll_pending(cx))? {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }
        self.begin(Operation::Flush, Vec::new());
        self.poll_pending(cx).map(|r| r.map(|_| ()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((Operation::Shutdown, _)) = ready!(self.poll_pending(cx))? {
            self.shutdown = true;
        }
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }
        self.begin(Operation::Shutdown, Vec::new());
        match self.poll_pending(cx) {
            Poll::Ready(result) => {
                self.shutdown = true;
                Poll::Ready(result.map(|_| ()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
