use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub(crate) struct RecordIo<S> {
    inner: S,
    header: [u8; 5],
    used: usize,
    sent: usize,
    body: usize,
}
impl<S> RecordIo<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 5],
            used: 0,
            sent: 0,
            body: 0,
        }
    }
    pub fn into_inner(self) -> io::Result<S> {
        if self.body != 0 || self.used != self.sent {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(self.inner)
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for RecordIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.sent == 5 && this.body == 0 {
            this.used = 0;
            this.sent = 0;
        }
        while this.used < 5 {
            let mut read = ReadBuf::new(&mut this.header[this.used..]);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                return Poll::Ready(if this.used == 0 {
                    Ok(())
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                });
            }
            this.used += n;
        }
        if this.sent < 5 {
            if this.sent == 0 {
                let n = u16::from_be_bytes([this.header[3], this.header[4]]) as usize;
                if n > 18432
                    || !(20..=23).contains(&this.header[0])
                    || this.header[1] != 3
                    || !(1..=3).contains(&this.header[2])
                {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                this.body = n;
            }
            let n = (5 - this.sent).min(out.remaining());
            out.put_slice(&this.header[this.sent..this.sent + n]);
            this.sent += n;
            return Poll::Ready(Ok(()));
        }
        let n = this.body.min(out.remaining());
        let mut read = ReadBuf::new(out.initialize_unfilled_to(n));
        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
        let n = read.filled().len();
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        this.body -= n;
        out.advance(n);
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for RecordIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn tls_record_boundary_leaves_following_raw_bytes_in_transport() {
        let (mut writer, reader) = tokio::io::duplex(128);
        writer
            .write_all(&[23, 3, 3, 0, 3, 1, 2, 3, 9, 8, 7])
            .await
            .unwrap();
        let mut reader = RecordIo::new(reader);
        let mut record = [0; 8];
        reader.read_exact(&mut record).await.unwrap();
        assert_eq!(record, [23, 3, 3, 0, 3, 1, 2, 3]);
        let mut reader = reader.into_inner().unwrap();
        let mut raw = [0; 3];
        reader.read_exact(&mut raw).await.unwrap();
        assert_eq!(raw, [9, 8, 7]);
    }
}
