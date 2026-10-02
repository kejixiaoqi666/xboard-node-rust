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
        Duration::from_secs(2)
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
    if size == 0 || size > 256 * 1024 {
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
