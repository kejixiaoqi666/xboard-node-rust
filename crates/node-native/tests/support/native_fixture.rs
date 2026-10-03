//! Local Unix acceptance helpers; no production endpoints or credentials.
#![allow(dead_code)]
use serde_json::{Value, json};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new(label: &str) -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = Path::new("/tmp").join(format!("xb-{label}-{}-{nonce:x}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
pub fn configuration(port: u16) -> Value {
    json!({"log":{"level":"error","timestamp":false},"inbounds":[{"type":"shadowsocks","tag":"shadowsocks-in","listen":"127.0.0.1","listen_port":port,"method":"aes-128-gcm","users":[{"name":"7","password":"native-plugin-fixture-password","speed_limit":0,"device_limit":0}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})
}

pub struct NativeRun {
    pub control: PathBuf,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), node_native::Error>>>,
}
impl NativeRun {
    pub fn start(value: &Value, directory: &Directory) -> Self {
        Self::start_with_persistence(value, directory, false)
    }
    pub fn start_persistent(value: &Value, directory: &Directory) -> Self {
        Self::start_with_persistence(value, directory, true)
    }
    fn start_with_persistence(value: &Value, directory: &Directory, persistent: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;
        node_native::config::decode(&serde_json::to_vec(value).unwrap())
            .expect("native config must decode before runtime");
        let path = directory.file("native.json");
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let control = directory.file("control.sock");
        let mut args = vec![
            "run".into(),
            "-c".into(),
            path.to_string_lossy().into_owned(),
            "--control-socket".into(),
            control.to_string_lossy().into_owned(),
        ];
        if persistent {
            args.extend([
                "--traffic-state".into(),
                directory.0.to_string_lossy().into_owned(),
                "--traffic-destination".into(),
                node_native::traffic_destination("native-plugin-acceptance"),
            ]);
        }
        let (stop, receiver) = watch::channel(false);
        Self {
            control,
            stop,
            task: Some(tokio::spawn(async move {
                node_native::run_embedded(&args, receiver).await
            })),
        }
    }
    pub async fn ready(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(reply) = query(&self.control, "status").await
                    && reply["code"] == "ok"
                {
                    return;
                }
                assert!(
                    !self.task.as_ref().unwrap().is_finished(),
                    "native exited before readiness"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("native control handler did not become ready");
    }
    pub async fn stopped(&mut self, request_stop: bool) -> Result<(), node_native::Error> {
        if request_stop {
            let _ = self.stop.send(true);
        }
        let result = tokio::time::timeout(Duration::from_secs(5), self.task.as_mut().unwrap())
            .await
            .expect("native workers/plugin did not join")
            .unwrap();
        self.task.take();
        result
    }
}
impl Drop for NativeRun {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub async fn query(path: &Path, operation: &str) -> io::Result<Value> {
    let mut socket = UnixStream::connect(path).await?;
    let request = serde_json::to_vec(&json!({"operation":operation})).unwrap();
    socket.write_u32(request.len() as u32).await?;
    socket.write_all(&request).await?;
    let size = socket.read_u32().await? as usize;
    if size > 4 * 1024 * 1024 {
        return Err(io::Error::other("oversized local control response"));
    }
    let mut payload = vec![0; size];
    socket.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(io::Error::other)
}
pub async fn assert_traffic(run: &NativeRun, upload: u64, download: u64) {
    let reply = query(&run.control, "traffic_snapshot").await.unwrap();
    assert_eq!(reply["code"], "ok");
    assert_eq!(
        reply["snapshot"]["traffic"]["7"],
        json!([upload, download]),
        "transport framing was charged as application bytes"
    );
}
pub fn assert_persisted_traffic(directory: &Directory, upload: u64, download: u64) {
    let book: Value = serde_json::from_slice(
        &std::fs::read(directory.file("native-traffic.json"))
            .expect("native stop did not retain its final durable checkpoint"),
    )
    .unwrap();
    assert_eq!(book["version"], 1);
    assert_eq!(
        book["destination"],
        node_native::traffic_destination("native-plugin-acceptance")
    );
    assert_eq!(
        book["counters"]["7"],
        json!([upload, download]),
        "final durable checkpoint differs from the delivered payload"
    );
}
pub async fn assert_closed(address: SocketAddr) {
    let result =
        tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(address)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "listener survived stop: {address}"
    );
}
pub async fn echo() -> (SocketAddr, watch::Sender<bool>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, mut receiver) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut workers = JoinSet::new();
        loop {
            tokio::select! {
                _=receiver.changed()=>break,
                result=listener.accept()=> {let (mut stream,_)=result.unwrap();workers.spawn(async move {let mut bytes=[0;8192];loop {let len=stream.read(&mut bytes).await.unwrap_or(0);if len==0 {return;}if stream.write_all(&bytes[..len]).await.is_err(){return;}}});},
                _=workers.join_next(),if !workers.is_empty()=>(),
            }
        }
        workers.abort_all();
        while workers.join_next().await.is_some() {}
    });
    (address, stop, task)
}

pub async fn stop_echo(stop: watch::Sender<bool>, task: JoinHandle<()>) {
    let _ = stop.send(true);
    task.await.unwrap();
}
