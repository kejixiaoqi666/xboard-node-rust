//! Private, bounded control protocol for the optional native-user kernel.
use crate::KernelError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path, path::PathBuf, time::Duration};

const CAPABILITY: &str = "xbord-native-users-v1";
const MAX_REPLY: usize = 8 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(crate) struct UserControl {
    pub(crate) path: PathBuf,
}

#[derive(Serialize)]
struct Request<'a> {
    operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a Path>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    #[cfg_attr(not(unix), allow(dead_code))]
    capability: String,
    code: String,
    digest: String,
}

pub(crate) enum Replacement {
    Applied,
    RestartRequired,
    Rejected,
    Uncertain,
}

pub(crate) fn file_digest(path: &Path) -> Result<String, KernelError> {
    let mut file = File::open(path)
        .map_err(|_| KernelError::Activate("candidate digest unavailable".into()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| KernelError::Activate("candidate digest unavailable".into()))?;
        if read == 0 {
            break;
        }
        total += read;
        if total > 16 * 1024 * 1024 {
            return Err(KernelError::Activate(
                "candidate exceeds digest bound".into(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

impl UserControl {
    #[cfg(unix)]
    fn call(&self, request: &Request<'_>) -> Result<Response, ()> {
        use socket2::{Domain, SockAddr, Socket, Type};
        use std::{io::Write, os::unix::net::UnixStream, time::Instant};
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let payload = serde_json::to_vec(request).map_err(|_| ())?;
        if payload.len() > 64 * 1024 {
            return Err(());
        }
        let address = SockAddr::unix(&self.path).map_err(|_| ())?;
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(|_| ())?;
        socket
            .connect_timeout(&address, CONTROL_TIMEOUT)
            .map_err(|_| ())?;
        let mut stream: UnixStream = socket.into();
        fn remaining(deadline: Instant) -> Result<Duration, ()> {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or(())
        }
        fn read_bounded(
            stream: &mut UnixStream,
            mut bytes: &mut [u8],
            deadline: Instant,
        ) -> Result<(), ()> {
            while !bytes.is_empty() {
                stream
                    .set_read_timeout(Some(remaining(deadline)?))
                    .map_err(|_| ())?;
                let read = match stream.read(bytes) {
                    Ok(0) => return Err(()),
                    Ok(size) => size,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(()),
                };
                bytes = &mut bytes[read..];
            }
            Ok(())
        }
        let mut packet = (payload.len() as u32).to_be_bytes().to_vec();
        packet.extend_from_slice(&payload);
        let mut pending = packet.as_slice();
        while !pending.is_empty() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| ())?;
            let written = match stream.write(pending) {
                Ok(0) => return Err(()),
                Ok(size) => size,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(()),
            };
            pending = &pending[written..];
        }
        let mut size = [0u8; 4];
        read_bounded(&mut stream, &mut size, deadline)?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > MAX_REPLY {
            return Err(());
        }
        let mut reply = vec![0u8; size];
        read_bounded(&mut stream, &mut reply, deadline)?;
        let reply: Response = serde_json::from_slice(&reply).map_err(|_| ())?;
        if reply.capability != CAPABILITY
            || reply.digest.len() != 64
            || !reply.digest.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(());
        }
        Ok(reply)
    }

    #[cfg(not(unix))]
    fn call(&self, _: &Request<'_>) -> Result<Response, ()> {
        // Configuration validation prevents this mode on unsupported platforms.
        let _ = (&self.path, CAPABILITY, MAX_REPLY, CONTROL_TIMEOUT);
        Err(())
    }

    pub(crate) fn status_digest(&self) -> Result<String, ()> {
        let response = self.call(&Request {
            operation: "status",
            expected_digest: None,
            digest: None,
            path: None,
        })?;
        if response.code != "ok" {
            return Err(());
        }
        Ok(response.digest)
    }

    pub(crate) fn replace(&self, previous: &str, next: &str, path: &Path) -> Replacement {
        let result = self.call(&Request {
            operation: "replace",
            expected_digest: Some(previous),
            digest: Some(next),
            path: Some(path),
        });
        match result {
            Ok(reply) if reply.code == "ok" && reply.digest == next => Replacement::Applied,
            Ok(reply) if reply.code == "restart_required" && reply.digest == previous => {
                Replacement::RestartRequired
            }
            Ok(reply)
                if matches!(reply.code.as_str(), "rejected" | "conflict")
                    && reply.digest == previous =>
            {
                Replacement::Rejected
            }
            // A lost reply is not proof that the update failed. The serialized
            // server answers a subsequent status only after the preceding call.
            _ => match self.status_digest() {
                Ok(digest) if digest == next => Replacement::Applied,
                Ok(digest) if digest == previous => Replacement::Rejected,
                _ => Replacement::Uncertain,
            },
        }
    }
}

impl Drop for UserControl {
    fn drop(&mut self) {
        // Only our unique private socket path is owned, never a user input file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if std::fs::symlink_metadata(&self.path)
                .is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::net::UnixListener,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    fn reconciliation(
        previous: &str,
        next: &str,
        status: &str,
        malformed_size: bool,
    ) -> Replacement {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "xbord-ctrl-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let digest = status.to_owned();
        let worker = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let mut size = [0u8; 4];
            first.read_exact(&mut size).unwrap();
            let mut request = vec![0u8; u32::from_be_bytes(size) as usize];
            first.read_exact(&mut request).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(value["operation"], "replace");
            if malformed_size {
                first
                    .write_all(&((MAX_REPLY + 1) as u32).to_be_bytes())
                    .unwrap();
            }
            // Emulate apply followed by lost/oversized confirmation.
            drop(first);
            let (mut second, _) = listener.accept().unwrap();
            second.read_exact(&mut size).unwrap();
            let mut request = vec![0u8; u32::from_be_bytes(size) as usize];
            second.read_exact(&mut request).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(value["operation"], "status");
            let reply = serde_json::to_vec(
                &serde_json::json!({"capability":CAPABILITY,"code":"ok","digest":digest}),
            )
            .unwrap();
            second
                .write_all(&(reply.len() as u32).to_be_bytes())
                .unwrap();
            second.write_all(&reply).unwrap();
        });
        let control = UserControl { path };
        let result = control.replace(previous, next, Path::new("/private/candidate.json"));
        worker.join().unwrap();
        result
    }

    #[test]
    fn lost_reply_commits_only_after_new_digest_readback() {
        let previous = "a".repeat(64);
        let next = "b".repeat(64);
        assert!(matches!(
            reconciliation(&previous, &next, &next, false),
            Replacement::Applied
        ));
    }

    #[test]
    fn failed_update_retains_previous_and_unknown_digest_is_uncertain() {
        let previous = "a".repeat(64);
        let next = "b".repeat(64);
        assert!(matches!(
            reconciliation(&previous, &next, &previous, false),
            Replacement::Rejected
        ));
        assert!(matches!(
            reconciliation(&previous, &next, &"c".repeat(64), false),
            Replacement::Uncertain
        ));
    }

    #[test]
    fn oversized_confirmation_is_not_allocated_and_is_reconciled() {
        let previous = "a".repeat(64);
        let next = "b".repeat(64);
        assert!(matches!(
            reconciliation(&previous, &next, &next, true),
            Replacement::Applied
        ));
    }
}
