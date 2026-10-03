#![allow(dead_code)]
use async_trait::async_trait;
use node_session::{BoxStream, Datagram, Destination, Host, User};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex, mpsc},
};
pub const UUID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
pub const UUID_TEXT: &str = "01020304-0506-0708-090a-0b0c0d0e0f10";
pub const PASSWORD: &str = "node-extended-test-only";
pub struct TestHost {
    pub users: RwLock<Arc<[User]>>,
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
    pub active: Arc<AtomicUsize>,
    pub targets: Mutex<Vec<Destination>>,
}
impl TestHost {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(Arc::from([User {
                name: "fixture".into(),
                uuid: Some(UUID),
                password: Some(PASSWORD.into()),
            }])),
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            targets: Mutex::new(Vec::new()),
        })
    }
    fn admit(&self, user: &User) -> io::Result<()> {
        if self.users.read().unwrap().iter().any(|u| u == user) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "revoked fixture identity",
            ))
        }
    }
    pub fn totals(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::SeqCst),
            self.down.load(Ordering::SeqCst),
        )
    }
}
#[async_trait]
impl Host for TestHost {
    fn users(&self) -> Arc<[User]> {
        self.users.read().unwrap().clone()
    }
    async fn connect(
        &self,
        user: &User,
        _: SocketAddr,
        target: &Destination,
    ) -> io::Result<BoxStream> {
        self.admit(user)?;
        self.targets.lock().await.push(target.clone());
        let (stream, mut echo) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let mut buffer = vec![0; 32768];
            while let Ok(len) = echo.read(&mut buffer).await {
                if len == 0 {
                    let _ = echo.shutdown().await;
                    break;
                }
                if echo.write_all(&buffer[..len]).await.is_err() {
                    break;
                }
            }
        });
        self.active.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Accounted {
            stream,
            up: self.up.clone(),
            down: self.down.clone(),
            active: self.active.clone(),
        }))
    }
    async fn datagram(&self, user: &User, _: SocketAddr) -> io::Result<Arc<dyn Datagram>> {
        self.admit(user)?;
        let (tx, rx) = mpsc::channel(64);
        self.active.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(EchoDatagram {
            tx,
            rx: Mutex::new(rx),
            up: self.up.clone(),
            down: self.down.clone(),
            active: self.active.clone(),
        }))
    }
}
struct Accounted {
    stream: tokio::io::DuplexStream,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
}
impl Drop for Accounted {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl AsyncRead for Accounted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let prior = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.down
                .fetch_add((buf.filled().len() - prior) as u64, Ordering::SeqCst);
        }
        result
    }
}
impl AsyncWrite for Accounted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(len)) = &result {
            self.up.fetch_add(*len as u64, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
struct EchoDatagram {
    tx: mpsc::Sender<(Vec<u8>, Destination)>,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, Destination)>>,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
}
impl Drop for EchoDatagram {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl Datagram for EchoDatagram {
    async fn send(&self, payload: &[u8], target: &Destination) -> io::Result<usize> {
        self.tx
            .send((payload.to_vec(), target.clone()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "fixture closed"))?;
        self.up.fetch_add(payload.len() as u64, Ordering::SeqCst);
        Ok(payload.len())
    }
    async fn receive(&self, buffer: &mut [u8]) -> io::Result<(usize, Destination)> {
        let (packet, target) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "fixture closed"))?;
        if packet.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture too big",
            ));
        }
        buffer[..packet.len()].copy_from_slice(&packet);
        self.down.fetch_add(packet.len() as u64, Ordering::SeqCst);
        Ok((packet.len(), target))
    }
}
pub fn peer() -> SocketAddr {
    "127.0.0.1:12345".parse().unwrap()
}
pub async fn anytls_auth<S: AsyncWrite + Unpin>(stream: &mut S) {
    stream
        .write_all(ring::digest::digest(&ring::digest::SHA256, PASSWORD.as_bytes()).as_ref())
        .await
        .unwrap();
    stream.write_u16(30).await.unwrap();
    stream.write_all(&[0; 30]).await.unwrap();
    frame(stream, 4, 0, b"v=2\npadding-md5=update-me").await;
}
pub async fn frame<S: AsyncWrite + Unpin>(stream: &mut S, cmd: u8, id: u32, data: &[u8]) {
    stream.write_u8(cmd).await.unwrap();
    stream.write_u32(id).await.unwrap();
    stream.write_u16(data.len() as u16).await.unwrap();
    stream.write_all(data).await.unwrap();
    stream.flush().await.unwrap();
}
pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, u32, Vec<u8>) {
    let cmd = stream.read_u8().await.unwrap();
    let id = stream.read_u32().await.unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut data = vec![0; len as usize];
    stream.read_exact(&mut data).await.unwrap();
    (cmd, id, data)
}
