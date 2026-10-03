use node_core::TrafficSnapshot;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    #[cfg_attr(not(unix), allow(dead_code))]
    capability: String,
    #[cfg_attr(not(unix), allow(dead_code))]
    code: String,
    snapshot: Option<TrafficSnapshot>,
    #[serde(default)]
    quiesced: Option<bool>,
    #[serde(default)]
    activity: Option<node_core::ActivitySnapshot>,
}

#[cfg(unix)]
fn call(path: &Path, request: serde_json::Value) -> Result<Reply, crate::KernelError> {
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };
    let failure = || crate::KernelError::Activate("native traffic control failed".into());
    let seconds = if request.get("operation").and_then(serde_json::Value::as_str)
        == Some("traffic_quiesce")
    {
        // Include the server's short packet admission deadline in the total.
        node_core::TRAFFIC_QUIESCE_TIMEOUT_SECS + 2
    } else {
        2
    };
    // Connect is bounded by the private socket backlog timeout, like user CAS.
    let start = Instant::now();
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(|_| failure())?;
    socket
        .connect_timeout(
            &SockAddr::unix(path).map_err(|_| failure())?,
            Duration::from_secs(2),
        )
        .map_err(|_| failure())?;
    let mut stream: UnixStream = socket.into();
    let request = serde_json::to_vec(&request).map_err(|_| failure())?;
    let remaining = || {
        Duration::from_secs(seconds)
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(failure)
    };
    let mut packet = (request.len() as u32).to_be_bytes().to_vec();
    packet.extend(request);
    let mut pending = packet.as_slice();
    while !pending.is_empty() {
        stream
            .set_write_timeout(Some(remaining()?))
            .map_err(|_| failure())?;
        match stream.write(pending) {
            Ok(0) => return Err(failure()),
            Ok(n) => pending = &pending[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(failure()),
        }
    }
    let mut read = |mut bytes: &mut [u8]| -> Result<(), crate::KernelError> {
        while !bytes.is_empty() {
            stream
                .set_read_timeout(Some(remaining()?))
                .map_err(|_| failure())?;
            match stream.read(bytes) {
                Ok(0) => return Err(failure()),
                Ok(n) => bytes = &mut bytes[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(failure()),
            }
        }
        Ok(())
    };
    let mut size = [0; 4];
    read(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > 4 * 1024 * 1024 {
        return Err(failure());
    }
    let mut payload = vec![0; size];
    read(&mut payload)?;
    let reply: Reply = serde_json::from_slice(&payload).map_err(|_| failure())?;
    if reply.capability != "xbord-native-traffic-v1"
        || reply.code != "ok"
        || reply
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !snapshot.validate())
        || reply
            .activity
            .as_ref()
            .is_some_and(|activity| !activity.validate())
    {
        return Err(failure());
    }
    Ok(reply)
}

#[cfg(not(unix))]
fn call(_: &Path, _: serde_json::Value) -> Result<Reply, crate::KernelError> {
    Err(crate::KernelError::Invalid(
        "native traffic requires Unix".into(),
    ))
}

pub(crate) fn snapshot(path: &Path) -> Result<Option<TrafficSnapshot>, crate::KernelError> {
    Ok(call(path, serde_json::json!({"operation":"traffic_snapshot"}))?.snapshot)
}
pub(crate) fn activity(path: &Path) -> Result<node_core::ActivitySnapshot, crate::KernelError> {
    call(path, serde_json::json!({"operation":"activity"}))?
        .activity
        .ok_or_else(|| crate::KernelError::Activate("native activity snapshot missing".into()))
}
pub(crate) fn ack(path: &Path, snapshot: &TrafficSnapshot) -> Result<(), crate::KernelError> {
    let reply = call(
        path,
        serde_json::json!({"operation":"traffic_ack", "epoch":snapshot.epoch, "sequence":snapshot.sequence}),
    )?;
    if reply.snapshot.is_some() {
        return Err(crate::KernelError::Activate(
            "unexpected traffic ack".into(),
        ));
    }
    Ok(())
}
pub(crate) fn quiesce(path: &Path) -> Result<(), crate::KernelError> {
    let reply = call(path, serde_json::json!({"operation":"traffic_quiesce"}))?;
    if reply.quiesced != Some(true) || reply.snapshot.is_some() {
        return Err(crate::KernelError::Activate(
            "native traffic quiesce not confirmed".into(),
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn quiesce_waits_for_structured_cleanup_while_activity_keeps_its_short_deadline() {
        for operation in ["traffic_quiesce", "activity"] {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory =
                std::env::temp_dir().join(format!("xb-control-{}-{nonce:x}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let path = directory.join("c.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut length = [0; 4];
                stream.read_exact(&mut length).unwrap();
                let mut body = vec![0; u32::from_be_bytes(length) as usize];
                stream.read_exact(&mut body).unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["operation"],
                    operation
                );
                std::thread::sleep(Duration::from_millis(2200));
                let reply = serde_json::to_vec(&serde_json::json!({"capability":"xbord-native-traffic-v1","code":"ok","snapshot":null,"quiesced":true})).unwrap();
                let mut packet = (reply.len() as u32).to_be_bytes().to_vec();
                packet.extend(reply);
                let _ = stream.write_all(&packet); // The short activity deadline closes first.
            });
            let result = call(&path, serde_json::json!({"operation":operation}));
            if operation == "traffic_quiesce" {
                assert!(
                    result.is_ok(),
                    "quiesce dropped before its cleanup response"
                );
            } else {
                assert!(
                    result.is_err(),
                    "activity unexpectedly inherited the long shutdown allowance"
                );
            }
            worker.join().unwrap();
            std::fs::remove_file(path).unwrap();
            std::fs::remove_dir(directory).unwrap();
        }
    }
}
