use crate::{
    Error,
    auth::Users,
    config::{Candidate, read_candidate},
};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

const CAPABILITY: &str = "xbord-native-users-v1";

pub struct Listener {
    socket: UnixListener,
    path: PathBuf,
}
impl Drop for Listener {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.file_type().is_socket()) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub fn bind(config: &Path, socket: &Path) -> Result<Listener, Error> {
    if !socket.is_absolute()
        || config.parent() != socket.parent()
        || socket.symlink_metadata().is_ok()
    {
        return Err(Error::Config);
    }
    let directory = config.parent().ok_or(Error::Config)?;
    let meta = std::fs::metadata(directory).map_err(|_| Error::Config)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::Config);
    }
    let listener = Listener {
        socket: UnixListener::bind(socket)?,
        path: socket.to_path_buf(),
    };
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    #[serde(default)]
    expected_digest: Option<String>,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    epoch: Option<String>,
    #[serde(default)]
    sequence: Option<u64>,
}
#[derive(Serialize)]
struct TrafficReply {
    capability: &'static str,
    code: &'static str,
    snapshot: Option<node_core::TrafficSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quiesced: Option<bool>,
}
pub(crate) struct Quiesce {
    pub request: tokio::sync::watch::Sender<bool>,
    pub done: tokio::sync::watch::Receiver<u8>,
    pub limits: Arc<crate::limits::Registry>,
    pub extended: node_extended::Config,
}
#[derive(Serialize)]
struct Reply<'a> {
    capability: &'static str,
    code: &'static str,
    digest: &'a str,
}

pub async fn serve(
    listener: Listener,
    mut state: Candidate,
    users: Users,
    directory: PathBuf,
    traffic: Arc<crate::traffic::Traffic>,
    quiesce: Quiesce,
) -> Result<(), Error> {
    // Release the redundant initial Arc: Users owns the authentication table.
    state.auth = std::sync::Arc::new(crate::auth::Snapshot::new(state.base.protocol, Vec::new())?);
    loop {
        let (mut socket, _) = match listener.socket.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                if let Some(delay) = crate::accept_retry_delay(&error) {
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(Error::Io(error));
            }
        };
        // Read every packet under the short admission deadline. Only an already
        // decoded quiesce request gets the structured shutdown allowance.
        let Ok(Ok(request)) =
            tokio::time::timeout(Duration::from_secs(2), read_request(&mut socket)).await
        else {
            continue;
        };
        let seconds = if request.operation == "traffic_quiesce" {
            node_core::TRAFFIC_QUIESCE_TIMEOUT_SECS
        } else {
            2
        };
        // One serialized operation at a time; digest/status cannot race publication.
        let _ = tokio::time::timeout(
            Duration::from_secs(seconds),
            handle(
                &mut socket,
                request,
                &mut state,
                &users,
                &directory,
                &traffic,
                &quiesce,
            ),
        )
        .await;
    }
}

async fn read_request(socket: &mut UnixStream) -> Result<Request, Error> {
    let length = socket.read_u32().await? as usize;
    if length == 0 || length > 64 * 1024 {
        return Err(Error::Protocol);
    }
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|_| Error::Protocol)
}

async fn handle(
    socket: &mut UnixStream,
    request: Request,
    state: &mut Candidate,
    users: &Users,
    directory: &Path,
    traffic: &Arc<crate::traffic::Traffic>,
    quiesce: &Quiesce,
) -> Result<(), Error> {
    if request.operation == "activity" {
        let activity = quiesce.limits.activity();
        let payload = serde_json::to_vec(&serde_json::json!({"capability":"xbord-native-traffic-v1","code":"ok","snapshot":null,"activity":activity})).map_err(|_|Error::Protocol)?;
        if payload.len() > 4 * 1024 * 1024 {
            return Err(Error::Protocol);
        }
        socket.write_u32(payload.len() as u32).await?;
        socket.write_all(&payload).await?;
        return Ok(());
    }
    if matches!(
        request.operation.as_str(),
        "traffic_snapshot" | "traffic_ack" | "traffic_quiesce"
    ) {
        let mut quiesced = None;
        let (code, snapshot) = if request.operation == "traffic_quiesce" {
            let mut done = quiesce.done.clone();
            quiesce.request.send(true).map_err(|_| Error::Task)?;
            while *done.borrow() == 0 {
                done.changed().await.map_err(|_| Error::Task)?;
            }
            let success = *done.borrow() == 1;
            quiesced = Some(success);
            (if success { "ok" } else { "rejected" }, None)
        } else if request.operation == "traffic_snapshot" {
            match traffic
                .blocking(|t| t.snapshot())
                .await
                .map_err(|_| Error::Task)?
            {
                Ok(snapshot) => ("ok", snapshot),
                Err(_) => ("rejected", None),
            }
        } else {
            let code = match (request.epoch, request.sequence) {
                (Some(epoch), Some(sequence)) => {
                    if traffic
                        .blocking(move |t| t.ack(&epoch, sequence))
                        .await
                        .map_err(|_| Error::Task)?
                        .is_ok()
                    {
                        "ok"
                    } else {
                        "rejected"
                    }
                }
                _ => "rejected",
            };
            (code, None)
        };
        let payload = serde_json::to_vec(&TrafficReply {
            capability: "xbord-native-traffic-v1",
            code,
            snapshot,
            quiesced,
        })
        .map_err(|_| Error::Protocol)?;
        if payload.len() > 256 * 1024 {
            return Err(Error::Protocol);
        }
        socket.write_u32(payload.len() as u32).await?;
        socket.write_all(&payload).await?;
        return Ok(());
    }
    let replacing = request.operation == "replace";
    let code = match request.operation.as_str() {
        "status" => "ok",
        "replace" => apply(request, state, users, directory, traffic).await,
        _ => "rejected",
    };
    if replacing && code == "ok" {
        quiesce.limits.notify_users_changed();
        quiesce
            .extended
            .xudp_sessions
            .prune_users(&users.load().profiles());
    }
    let payload = serde_json::to_vec(&Reply {
        capability: CAPABILITY,
        code,
        digest: &state.digest,
    })
    .map_err(|_| Error::Protocol)?;
    if payload.len() > 8192 {
        return Err(Error::Protocol);
    }
    socket.write_u32(payload.len() as u32).await?;
    socket.write_all(&payload).await?;
    Ok(())
}

async fn apply(
    request: Request,
    state: &mut Candidate,
    users: &Users,
    directory: &Path,
    traffic: &Arc<crate::traffic::Traffic>,
) -> &'static str {
    if request.expected_digest.as_deref() != Some(state.digest.as_str()) {
        return "conflict";
    }
    let Some(path) = request.path else {
        return "rejected";
    };
    if !path.is_absolute() || path.parent() != Some(directory) {
        return "rejected";
    }
    if !std::fs::symlink_metadata(&path)
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o077 == 0)
    {
        return "rejected";
    }
    let candidate = match traffic.blocking(move |_| read_candidate(&path)).await {
        Ok(Ok(candidate)) => candidate,
        _ => return "rejected",
    };
    if request.digest.as_deref() != Some(candidate.digest.as_str()) {
        return "rejected";
    }
    if candidate.base != state.base {
        return "restart_required";
    }
    // No await between publishing the entire table and advancing its digest.
    users.store(candidate.auth);
    state.digest = candidate.digest;
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "xb-rust-native-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, port: u16, id: &str) -> (PathBuf, Candidate) {
            let mut value = crate::tests::config(
                json!([{"name":id,"uuid":format!("00000000-0000-4000-8000-{:012}",id.parse::<u32>().unwrap())}]),
            );
            value["inbounds"][0]["listen_port"] = json!(port);
            let path = self.0.join(name);
            std::fs::write(&path, value.to_string()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let candidate = read_candidate(&path).unwrap();
            (path, candidate)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            for name in ["a.json", "b.json", "c.json"] {
                let _ = std::fs::remove_file(self.0.join(name));
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    #[tokio::test]
    async fn digest_compare_and_restart_required_do_not_publish_stale_or_wrong_base() {
        let directory = Directory::new();
        let (_, mut state) = directory.write("a.json", 12345, "100");
        let (path, next) = directory.write("b.json", 12345, "200");
        let users = Arc::new(ArcSwap::from(state.auth.clone()));
        let previous = state.digest.clone();
        let traffic = Arc::new(crate::traffic::Traffic::new("a".repeat(32)));
        let request = || Request {
            operation: "replace".into(),
            expected_digest: Some(previous.clone()),
            digest: Some(next.digest.clone()),
            path: Some(path.clone()),
            epoch: None,
            sequence: None,
        };
        assert_eq!(
            apply(request(), &mut state, &users, &directory.0, &traffic).await,
            "ok"
        );
        assert_eq!(state.digest, next.digest);
        assert!(
            users
                .load()
                .vless(&crate::auth::uuid("00000000-0000-4000-8000-000000000100").unwrap())
                .is_none()
        );
        assert_eq!(
            apply(request(), &mut state, &users, &directory.0, &traffic).await,
            "conflict"
        );
        let (changed_path, changed) = directory.write("c.json", 12346, "100");
        let req = Request {
            operation: "replace".into(),
            expected_digest: Some(next.digest.clone()),
            digest: Some(changed.digest),
            path: Some(changed_path),
            epoch: None,
            sequence: None,
        };
        assert_eq!(
            apply(req, &mut state, &users, &directory.0, &traffic).await,
            "restart_required"
        );
        assert_eq!(state.digest, next.digest);
    }
    #[tokio::test]
    async fn framed_status_strict_input_and_oversize_frame() {
        for payload in [
            b"{\"operation\":\"status\"}".to_vec(),
            b"{\"operation\":\"status\",\"extra\":1}".to_vec(),
            b"{\"operation\":\"status\"} {}".to_vec(),
            vec![b'x'; 65537],
        ] {
            let directory = Directory::new();
            let (_, mut state) = directory.write("a.json", 12345, "100");
            let users = Arc::new(ArcSwap::from(state.auth.clone()));
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let valid = payload == b"{\"operation\":\"status\"}";
            let task = tokio::spawn(async move {
                let (request, _) = tokio::sync::watch::channel(false);
                let (_, done) = tokio::sync::watch::channel(0_u8);
                let request_payload = read_request(&mut server).await?;
                handle(
                    &mut server,
                    request_payload,
                    &mut state,
                    &users,
                    &directory.0,
                    &Arc::new(crate::traffic::Traffic::new("a".repeat(32))),
                    &Quiesce {
                        request,
                        done,
                        limits: Arc::new(crate::limits::Registry::default()),
                        extended: node_extended::Config::default(),
                    },
                )
                .await
            });
            client.write_u32(payload.len() as u32).await.unwrap();
            if payload.len() <= 65536 {
                client.write_all(&payload).await.unwrap();
            }
            if valid {
                let size = client.read_u32().await.unwrap();
                assert!(size <= 8192);
                let mut body = vec![0; size as usize];
                client.read_exact(&mut body).await.unwrap();
                let reply: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(reply["capability"], CAPABILITY);
                assert_eq!(reply["code"], "ok");
                assert_eq!(reply["digest"].as_str().unwrap().len(), 64);
            }
            assert_eq!(task.await.unwrap().is_ok(), valid);
        }
    }
    #[tokio::test]
    async fn control_binding_never_overwrites_existing_file_and_protects_socket() {
        let directory = Directory::new();
        let (path, _) = directory.write("a.json", 12345, "100");
        assert!(bind(&path, &path).is_err());
        let socket = directory.0.join("private.sock");
        let listener = bind(&path, &socket).unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listener);
        assert!(!socket.exists());
        assert!(path.is_file());
    }
}
