//! AnyTLS v2 sessions; TLS is terminated by the caller.
pub mod anytls_padding;
pub mod anytls_types;
use crate::channel::{ChannelStream, Outgoing, Queued};
use anytls_types::{Command, Frame, FrameCodec, StringMap};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use node_session::{BoxStream, Host, User};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
    task::{AbortHandle, JoinSet},
};
use tokio_util::codec::{Decoder, FramedRead};

struct FrameDecoder {
    max: usize,
}
impl Decoder for FrameDecoder {
    type Item = Frame;
    type Error = io::Error;
    fn decode(&mut self, bytes: &mut BytesMut) -> io::Result<Option<Frame>> {
        if bytes.len() >= 7 && u16::from_be_bytes([bytes[5], bytes[6]]) as usize > self.max {
            return Err(crate::invalid("AnyTLS frame exceeds limit"));
        }
        FrameCodec::decode(bytes)
    }
}
async fn authenticate(
    stream: &mut BoxStream,
    host: &dyn Host,
    config: &crate::Config,
) -> io::Result<User> {
    let mut presented = [0; 32];
    stream.read_exact(&mut presented).await?;
    let snapshot = config.authentication.anytls(host.users())?;
    let user = snapshot
        .hashes
        .get(&presented)
        .map(|index| snapshot.users[*index].clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "AnyTLS authentication failed",
            )
        })?;
    let len = stream.read_u16().await? as usize;
    if len > config.max_frame {
        return Err(crate::invalid("AnyTLS auth padding exceeds limit"));
    }
    let mut padding = vec![0; len];
    stream.read_exact(&mut padding).await?;
    Ok(user)
}
struct Entry {
    input: mpsc::Sender<Queued>,
    abort: AbortHandle,
}
pub(crate) async fn serve(
    mut stream: BoxStream,
    peer: SocketAddr,
    host: Arc<dyn Host>,
    config: crate::Config,
    mut cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + config.handshake_timeout;
    let user = tokio::select! {
        biased;
        _ = crate::cancelled(&mut cancel) => return Ok(()),
        result = tokio::time::timeout(config.handshake_timeout, authenticate(&mut stream, host.as_ref(), &config)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS handshake timed out"))??,
    };
    let (read, write) = tokio::io::split(stream);
    let mut read = FramedRead::with_capacity(
        read,
        FrameDecoder {
            max: config.max_frame,
        },
        8192,
    );
    let listener_budget = config
        .shared_budget
        .bind(config.max_queued_bytes, config.max_sessions)?;
    let budget = listener_budget.bytes.clone();
    let (output, output_rx) = mpsc::channel(128);
    let mut jobs: JoinSet<(Option<u32>, io::Result<()>)> = JoinSet::new();
    jobs.spawn(async move { (None, writer_loop(write, output_rx).await) });
    let mut streams: HashMap<u32, Entry> = HashMap::new();
    let mut settings = false;
    let mut version2 = false;
    let mut last_id = 0;
    let settings_deadline = tokio::time::sleep_until(deadline);
    tokio::pin!(settings_deadline);
    let result = loop {
        tokio::select! {
            biased;
            _ = crate::cancelled(&mut cancel) => break Ok(()),
            _ = &mut settings_deadline, if !settings => break Err(io::Error::new(io::ErrorKind::TimedOut, "AnyTLS settings timed out")),
            job = jobs.join_next() => match job {
                Some(Ok((Some(id), _))) => { streams.remove(&id); },
                Some(Ok((None, result))) => break result,
                Some(Err(err)) if !err.is_cancelled() => break Err(io::Error::other(err)),
                _ => (),
            },
            frame = read.next() => {
                let frame = match frame { None => break Ok(()), Some(Err(err)) => break Err(err), Some(Ok(frame)) => frame };
                let outcome: io::Result<()> = (|| {
                    if matches!(frame.cmd, Command::Syn | Command::Fin | Command::HeartRequest | Command::HeartResponse) && !frame.data.is_empty() { return Err(crate::invalid("AnyTLS control frame carries data")); }
                    match frame.cmd {
                        Command::Settings => {
                            if settings || frame.stream_id != 0 { return Err(crate::invalid("duplicate or invalid AnyTLS settings")); }
                            let values = StringMap::from_bytes(&frame.data);
                            let version = values.get("v").and_then(|v| v.parse::<u8>().ok()).ok_or_else(|| crate::invalid("missing AnyTLS protocol version"))?;
                            if version == 0 { return Err(crate::invalid("invalid AnyTLS version")); }
                            version2 = version >= 2; settings = true;
                            if values.get("padding-md5").is_some_and(|hash| hash != config.anytls_padding.md5()) {
                                control(&output, Command::UpdatePaddingScheme, 0, Bytes::copy_from_slice(config.anytls_padding.raw_scheme()))?;
                            }
                            if version2 { control(&output, Command::ServerSettings, 0, Bytes::from_static(b"v=2"))?; }
                        },
                        Command::Syn => {
                            if !settings { return Err(crate::invalid("AnyTLS settings required before SYN")); }
                            if frame.stream_id == 0 || frame.stream_id <= last_id || streams.len() >= config.max_sessions { return Err(crate::invalid("AnyTLS stream ID or session limit violated")); }
                            last_id = frame.stream_id;
                            let session_permit = listener_budget.session()?;
                            let (tx, rx) = mpsc::channel(32);
                            let client = ChannelStream::new(frame.stream_id, rx, output.clone(), budget.clone(), config.max_frame.min(16384));
                            let context = crate::SessionContext { host: host.clone(), user: user.clone(), peer, config: config.clone() };
                            let output = output.clone();
                            let id = frame.stream_id;
                            let abort = jobs.spawn(async move {
                                let _session_permit = session_permit;
                                let result = stream_worker(Box::new(client), id, version2, output.clone(), context).await;
                                // Errors before admission still close only this logical stream.
                                if result.is_err() { let _ = control(&output, Command::Fin, id, Bytes::new()); }
                                (Some(id), result)
                            });
                            streams.insert(id, Entry { input: tx, abort });
                        },
                        Command::Psh => {
                            if !settings { return Err(crate::invalid("AnyTLS data before settings")); }
                            if let Some(entry) = streams.get(&frame.stream_id) && !frame.data.is_empty() {
                                entry.input.try_send(Queued::new(frame.data, &budget)?).map_err(|_| crate::invalid("AnyTLS logical stream queue is full"))?;
                            }
                        },
                        Command::Fin => { if let Some(entry) = streams.remove(&frame.stream_id) { entry.abort.abort(); } },
                        Command::Waste => (),
                        Command::HeartRequest => { if !version2 { return Err(crate::invalid("AnyTLS heartbeat requires v2")); } control(&output, Command::HeartResponse, frame.stream_id, Bytes::new())?; },
                        Command::HeartResponse => (),
                        Command::Alert => return Err(crate::invalid("AnyTLS peer sent alert")),
                        _ => return Err(crate::invalid("unexpected AnyTLS server-only command")),
                    }
                    Ok(())
                })();
                if let Err(err) = outcome { break Err(err); }
            },
        }
    };
    if result.is_err() {
        let _ = control(
            &output,
            Command::Alert,
            0,
            Bytes::from_static(b"invalid AnyTLS session"),
        );
        let (sent, received) = tokio::sync::oneshot::channel();
        if output.try_send(Outgoing::Barrier(sent)).is_ok() {
            tokio::select! { _ = crate::cancelled(&mut cancel) => (), _ = tokio::time::timeout(std::time::Duration::from_millis(500), received) => () }
        }
    }
    streams.clear();
    drop(output);
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}
fn control(output: &mpsc::Sender<Outgoing>, cmd: Command, id: u32, data: Bytes) -> io::Result<()> {
    if data.len() > 65535 {
        return Err(crate::invalid("AnyTLS control data too long"));
    }
    output
        .try_send(Outgoing::Control(cmd as u8, id, data))
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "AnyTLS output queue full"))
}
async fn writer_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut output: mpsc::Receiver<Outgoing>,
) -> io::Result<()> {
    while let Some(out) = output.recv().await {
        if let Outgoing::Barrier(ack) = out {
            let _ = ack.send(());
            continue;
        }
        let (cmd, id, data, _retained) = match out {
            Outgoing::Data(id, queued) => {
                (Command::Psh as u8, id, queued.bytes.clone(), Some(queued))
            }
            Outgoing::Fin(id) => (Command::Fin as u8, id, Bytes::new(), None),
            Outgoing::Control(cmd, id, data) => (cmd, id, data, None),
            Outgoing::Udp(..) => return Err(crate::invalid("invalid AnyTLS writer message")),
            Outgoing::Barrier(_) => unreachable!("barrier handled above"),
        };
        writer.write_u8(cmd).await?;
        writer.write_u32(id).await?;
        writer.write_u16(data.len() as u16).await?;
        writer.write_all(&data).await?;
        writer.flush().await?;
    }
    writer.shutdown().await
}
async fn stream_worker(
    mut client: BoxStream,
    id: u32,
    v2: bool,
    output: mpsc::Sender<Outgoing>,
    context: crate::SessionContext,
) -> io::Result<()> {
    let crate::SessionContext {
        peer,
        host,
        user,
        config,
    } = context;
    let admission = tokio::time::timeout(config.handshake_timeout, async {
        let location = crate::address::read_location(&mut client).await?;
        if matches!(location.address(), crate::address::Address::Hostname(h) if h == crate::mux::uot::UOT_V1 || h == crate::mux::uot::UOT_V2) {
            let datagram = host.datagram(&user, peer).await?;
            let mode = if location.address().to_string() == crate::mux::uot::UOT_V2 {
                let connected = client.read_u8().await?;
                if connected > 1 { return Err(crate::invalid("invalid UoT v2 connect flag")); }
                let destination = crate::address::read_location(&mut client).await?;
                if connected == 1 { crate::mux::uot::Mode::Connected(destination.destination()?) } else { crate::mux::uot::Mode::UotAddress }
            } else { crate::mux::uot::Mode::UotAddress };
            Ok::<_, io::Error>(StreamAdmission::Udp(datagram, mode))
        } else { let remote = host.connect(&user, peer, &location.destination()?).await?; Ok(StreamAdmission::Tcp(remote)) }
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS stream handshake timed out"))?;
    let admission = match admission {
        Ok(admission) => {
            if v2 {
                control(&output, Command::SynAck, id, Bytes::new())?;
            }
            admission
        }
        Err(err) => {
            if v2 {
                let _ = control(
                    &output,
                    Command::SynAck,
                    id,
                    Bytes::from_static(b"destination admission failed"),
                );
            }
            return Err(err);
        }
    };
    match admission {
        StreamAdmission::Tcp(remote) => node_session::relay(client, remote).await,
        StreamAdmission::Udp(datagram, mode) => {
            crate::mux::uot::relay(client, datagram, mode, config.max_frame).await
        }
    }
}
enum StreamAdmission {
    Tcp(BoxStream),
    Udp(Arc<dyn node_session::Datagram>, crate::mux::uot::Mode),
}
