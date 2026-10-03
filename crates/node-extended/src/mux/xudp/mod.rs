//! Xray Mux.Cool/XUDP framing and bounded TCP/UDP logical sessions.
pub mod frame;
mod global;
use crate::channel::{ChannelStream, Outgoing, Queued};
use bytes::{Bytes, BytesMut};
use frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};
use futures::StreamExt;
pub use global::GlobalSessions;
use node_session::{BoxStream, Datagram, Destination, Host, User};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::{AbortHandle, JoinSet},
};
use tokio_util::codec::{Decoder, FramedRead};
struct Decoded {
    metadata: FrameMetadata,
    payload: Bytes,
    global_id: Option<[u8; 8]>,
}
struct FrameDecoder {
    max: usize,
}
impl Decoder for FrameDecoder {
    type Item = Decoded;
    type Error = io::Error;
    fn decode(&mut self, bytes: &mut BytesMut) -> io::Result<Option<Decoded>> {
        if bytes.len() < 2 {
            return Ok(None);
        }
        let metadata_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if metadata_len < 4 || metadata_len > self.max {
            return Err(crate::invalid("XUDP metadata length out of bounds"));
        }
        let offset = 2 + metadata_len;
        if bytes.len() < offset {
            return Ok(None);
        }
        if bytes[5] & !3 != 0 {
            return Err(crate::invalid("unknown XUDP frame options"));
        }
        let has_data = bytes[5] & 1 != 0;
        let mut length = 0;
        if has_data {
            if bytes.len() < offset + 2 {
                return Ok(None);
            }
            length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            if length > self.max {
                return Err(crate::invalid("XUDP datagram exceeds limit"));
            }
            if bytes.len() < offset + 2 + length {
                return Ok(None);
            }
        }
        let possible_global: [u8; 8] = if metadata_len >= 8 {
            bytes[offset - 8..offset].try_into().unwrap()
        } else {
            [0; 8]
        };
        let metadata =
            FrameMetadata::decode(bytes)?.ok_or_else(|| crate::invalid("missing XUDP metadata"))?;
        let mut canonical = BytesMut::new();
        metadata.encode(&mut canonical)?;
        let global_id = match metadata_len.checked_sub(canonical.len() - 2) {
            Some(0) => None,
            Some(8)
                if metadata.status == SessionStatus::New
                    && metadata.network == Some(TargetNetwork::Udp) =>
            {
                (possible_global != [0; 8]).then_some(possible_global)
            }
            _ => return Err(crate::invalid("unexpected XUDP metadata extension")),
        };
        let payload = if has_data {
            let _ = bytes.split_to(2);
            bytes.split_to(length).freeze()
        } else {
            Bytes::new()
        };
        Ok(Some(Decoded {
            metadata,
            payload,
            global_id,
        }))
    }
}
enum Input {
    Tcp(mpsc::Sender<Queued>),
    Udp(mpsc::Sender<(Queued, Destination)>),
}
struct Entry {
    input: Input,
    target: Destination,
    abort: AbortHandle,
    generation: u64,
}
type JobResult = (Option<(u16, u64)>, io::Result<()>);
pub async fn serve(
    stream: BoxStream,
    user: User,
    peer: SocketAddr,
    host: Arc<dyn Host>,
    config: crate::Config,
    mut cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    config.require_multiplex()?;
    config.validate()?;
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
    let mut jobs: JoinSet<JobResult> = JoinSet::new();
    jobs.spawn(async move { (None, writer_loop(write, output_rx).await) });
    let mut sessions: HashMap<u16, Entry> = HashMap::new();
    let mut generation = 0u64;
    let mut attached = HashMap::new();
    let mut stopped = false;
    let result = loop {
        tokio::select! {
            biased;
            _ = crate::cancelled(&mut cancel) => {stopped=true;break Ok(());},
            job = jobs.join_next() => match job {
                Some(Ok((Some((id,generation)), _))) => { if sessions.get(&id).is_some_and(|entry|entry.generation==generation) {sessions.remove(&id);} },
                Some(Ok((None, result))) => break result,
                Some(Err(err)) if !err.is_cancelled() => break Err(io::Error::other(err)),
                Some(Err(_)) => sessions.retain(|_,entry| match &entry.input {Input::Tcp(input)=>!input.is_closed(),Input::Udp(input)=>!input.is_closed()}),
                _ => (),
            },
            incoming = read.next() => {
                let Decoded { metadata, payload,global_id } = match incoming { None => break Ok(()), Some(Err(err)) => break Err(err), Some(Ok(frame)) => frame };
                let id = metadata.session_id;
                let outcome: io::Result<()> = async {
                    match metadata.status {
                        SessionStatus::New => {
                            if sessions.contains_key(&id) || sessions.len() >= config.max_sessions { return Err(crate::invalid("XUDP duplicate session or session limit")); }
                            let target = metadata.target.as_ref().ok_or_else(|| crate::invalid("missing XUDP target"))?.destination()?;
                            let network = metadata.network.ok_or_else(|| crate::invalid("missing XUDP network"))?;
                            generation=generation.checked_add(1).ok_or_else(||io::Error::other("XUDP session generation exhausted"))?;
                            let current_generation=generation;
                            let output = output.clone(); let host = host.clone(); let user = user.clone(); let cfg = config.clone();
                            let (input, abort) = match network {
                                TargetNetwork::Tcp => {
                                    let session_permit=listener_budget.session()?;
                                    let (tx, rx) = mpsc::channel(32);
                                    let client = ChannelStream::new(id as u32, rx, output.clone(), budget.clone(), config.max_frame.min(16384));
                                    let target = target.clone();
                                    let abort = jobs.spawn(async move {
                                        let _session_permit = session_permit;
                                        let result = async {
                                            let remote = tokio::time::timeout(cfg.handshake_timeout, host.connect(&user, peer, &target)).await
                                                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP TCP admission timed out"))??;
                                            node_session::relay(Box::new(client), remote).await
                                        }.await;
                                        if result.is_err() { let _ = output.try_send(Outgoing::Fin(id as u32)); }
                                        (Some((id,current_generation)), result)
                                    });
                                    (Input::Tcp(tx), abort)
                                },
                                TargetNetwork::Udp => {
                                    let (tx, rx) = mpsc::channel(32); let budget = budget.clone();
                                    let global=if let Some(global_id)=global_id {Some(cfg.xudp_sessions.admit(global_id,&user,peer,&host,&cfg).await?)} else {None};
                                    let (datagram,session_permit)=if let Some((_,channel,_))=&global {(channel.lease.datagram.clone(),None)} else {
                                        let permit=listener_budget.session()?;
                                        let datagram=tokio::time::timeout(cfg.handshake_timeout,host.datagram(&user,peer)).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"XUDP UDP admission timed out"))??;
                                        (datagram,Some(permit))
                                    };
                                    let (start,start_rx)=oneshot::channel();
                                    let (completion,done)=if let Some((_,channel,token))=&global {let (guard,done)=channel.completion(*token);(Some(guard),Some(done))} else {(None,None)};
                                    let worker_output=output.clone();let max_frame=cfg.max_frame;
                                    let global_cleanup=global.as_ref().map(|(key,channel,token)|(cfg.xudp_sessions.clone(),key.clone(),channel.clone(),*token));
                                    let abort = jobs.spawn(async move {
                                        let _session_permit = session_permit;
                                        let _completion=completion;
                                        let result=async {start_rx.await.map_err(|_|io::Error::new(io::ErrorKind::BrokenPipe,"XUDP worker admission cancelled"))?;udp_worker(id,rx,worker_output.clone(),budget,datagram,max_frame).await}.await;
                                        if result.is_err() && let Some((registry,key,channel,token))=global_cleanup {registry.remove_binding(&key,&channel,token).await;}
                                        let _ = worker_output.try_send(Outgoing::Fin(id as u32));
                                        (Some((id,current_generation)), result)
                                    });
                                    if let Some((key,channel,token))=global {
                                        channel.bind(token,abort.clone(),done.expect("global completion"),output.clone(),id,start).await?;
                                        attached.retain(|_,(channel,_)| std::sync::Weak::strong_count(channel)>0);
                                        attached.insert(key,(Arc::downgrade(&channel),token));
                                    } else {let _=start.send(());}
                                    (Input::Udp(tx), abort)
                                },
                            };
                            sessions.insert(id, Entry { input, target, abort,generation:current_generation });
                        },
                        SessionStatus::End => { if let Some(session) = sessions.remove(&id) { session.abort.abort(); } return Ok(()); },
                        SessionStatus::KeepAlive => return Ok(()),
                        SessionStatus::Keep => (),
                    }
                    if metadata.option.has_error() { if let Some(session) = sessions.remove(&id) { session.abort.abort(); } return Ok(()); }
                    if metadata.option.has_data() {
                        if let Some(session) = sessions.get(&id) {
                            let data = Queued::new(payload, &budget)?;
                            match &session.input {
                                Input::Tcp(tx) => { if matches!(metadata.network, Some(TargetNetwork::Udp)) { return Err(crate::invalid("XUDP session network changed")); } tx.try_send(data).map_err(|_| crate::invalid("XUDP TCP queue is full"))?; },
                                Input::Udp(tx) => {
                                    if matches!(metadata.network, Some(TargetNetwork::Tcp)) { return Err(crate::invalid("XUDP session network changed")); }
                                    let target = metadata.target.as_ref().map(|t| t.destination()).transpose()?.unwrap_or_else(|| session.target.clone());
                                    tx.try_send((data, target)).map_err(|_| crate::invalid("XUDP UDP queue is full"))?;
                                },
                            }
                        } else { let _ = output.try_send(Outgoing::Fin(id as u32)); }
                    }
                    Ok(())
                }.await;
                if let Err(err) = outcome { break Err(err); }
            },
        }
    };
    sessions.clear();
    drop(output);
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    if stopped {
        for (key, (channel, token)) in attached {
            if let Some(channel) = channel.upgrade() {
                config
                    .xudp_sessions
                    .remove_binding(&key, &channel, token)
                    .await;
            }
        }
    }
    result
}
async fn udp_worker(
    id: u16,
    mut input: mpsc::Receiver<(Queued, Destination)>,
    output: mpsc::Sender<Outgoing>,
    budget: Arc<Semaphore>,
    datagram: Arc<dyn Datagram>,
    max_frame: usize,
) -> io::Result<()> {
    let mut receive_buffer = vec![0; max_frame];
    loop {
        tokio::select! {
            item = input.recv() => {
                let Some((packet, target)) = item else { return Ok(()); };
                if datagram.send(&packet.bytes, &target).await? != packet.bytes.len() { return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP send")); }
            },
            result = datagram.receive(&mut receive_buffer) => {
                let (len, source) = result?;
                if len > max_frame { return Err(crate::invalid("host returned oversized datagram")); }
                let data = Queued::new(Bytes::copy_from_slice(&receive_buffer[..len]), &budget)?;
                output.send(Outgoing::Udp(id as u32, data, source)).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XUDP writer closed"))?;
            },
        }
    }
}
async fn writer_loop<W: AsyncWrite + Unpin>(
    mut write: W,
    mut input: mpsc::Receiver<Outgoing>,
) -> io::Result<()> {
    while let Some(out) = input.recv().await {
        let (id, status, payload, target, _retained) = match out {
            Outgoing::Data(id, data) => (
                id,
                SessionStatus::Keep,
                Some(data.bytes.clone()),
                None,
                Some(data),
            ),
            Outgoing::Udp(id, data, destination) => (
                id,
                SessionStatus::Keep,
                Some(data.bytes.clone()),
                Some(destination),
                Some(data),
            ),
            Outgoing::Fin(id) => (id, SessionStatus::End, None, None, None),
            Outgoing::Control(..) => return Err(crate::invalid("invalid XUDP output message")),
            Outgoing::Barrier(_) => return Err(crate::invalid("invalid XUDP output barrier")),
        };
        let mut metadata = BytesMut::new();
        FrameMetadata {
            session_id: id as u16,
            status,
            option: if payload.is_some() {
                FrameOption::new().with_data()
            } else {
                FrameOption::new()
            },
            network: target.as_ref().map(|_| TargetNetwork::Udp),
            target: target
                .as_ref()
                .map(crate::address::NetLocation::from_destination)
                .transpose()?,
        }
        .encode(&mut metadata)?;
        write.write_all(&metadata).await?;
        if let Some(payload) = payload {
            write.write_u16(payload.len() as u16).await?;
            write.write_all(&payload).await?;
        }
        write.flush().await?;
    }
    write.shutdown().await
}

/// SIP003 v2ray-plugin's outer Mux.Cool transport. Each TCP logical stream
/// still performs the caller's native SS handshake before any Host I/O. The
/// metadata target is a plugin placeholder, not a route or authenticated user.
pub async fn serve_plugin_mux(
    stream: BoxStream,
    handler: Arc<dyn crate::http2::StreamHandler>,
    config: crate::Config,
    mut cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    struct PluginEntry {
        input: mpsc::Sender<Queued>,
        abort: AbortHandle,
        generation: u64,
    }
    config.require_multiplex()?;
    config.validate()?;
    let budget = config
        .shared_budget
        .bind(config.max_queued_bytes, config.max_sessions)?;
    let (read, write) = tokio::io::split(stream);
    let mut read = FramedRead::with_capacity(
        read,
        FrameDecoder {
            max: config.max_frame,
        },
        8192,
    );
    let (output, input) = mpsc::channel(128);
    let mut jobs: JoinSet<JobResult> = JoinSet::new();
    jobs.spawn(async move { (None, writer_loop(write, input).await) });
    let mut sessions: HashMap<u16, PluginEntry> = HashMap::new();
    let mut generation = 0u64;
    let result = loop {
        tokio::select! {
            biased;
            _=crate::cancelled(&mut cancel)=>break Ok(()),
            job=jobs.join_next()=>match job {
                Some(Ok((Some((id,generation)),_)))=>{if sessions.get(&id).is_some_and(|entry|entry.generation==generation) {sessions.remove(&id);}},
                Some(Ok((None,result)))=>break result,
                Some(Err(error)) if !error.is_cancelled()=>break Err(io::Error::other(error)),
                Some(Err(_))=>sessions.retain(|_,entry|!entry.input.is_closed()),
                _=>(),
            },
            incoming=read.next()=> {
                let Decoded{metadata,payload,global_id}=match incoming {Some(Ok(frame))=>frame,Some(Err(error))=>break Err(error),None=>break Ok(())};let id=metadata.session_id;
                let outcome:io::Result<()>= (|| {
                    if global_id.is_some() || metadata.network==Some(TargetNetwork::Udp) {return Err(crate::invalid("SIP003 plugin mux only accepts TCP streams"));}
                    match metadata.status {
                        SessionStatus::New=> {
                            if metadata.network!=Some(TargetNetwork::Tcp) || sessions.contains_key(&id) || sessions.len()>=config.max_sessions {return Err(crate::invalid("invalid SIP003 plugin mux stream"));}
                            generation=generation.checked_add(1).ok_or_else(||io::Error::other("plugin mux generation exhausted"))?;let current=generation;let session=budget.session()?;
                            let (input,receiver)=mpsc::channel(32);let stream=ChannelStream::new(id as u32,receiver,output.clone(),budget.bytes.clone(),config.max_frame.min(16384));let handler=handler.clone();let worker_output=output.clone();
                            let abort=jobs.spawn(async move {let _session=session;let result=handler.serve(Box::new(stream)).await;let _=worker_output.try_send(Outgoing::Fin(id as u32));(Some((id,current)),result)});
                            sessions.insert(id,PluginEntry{input,abort,generation:current});
                        },
                        SessionStatus::End=>{if let Some(entry)=sessions.remove(&id) {entry.abort.abort();}return Ok(());},
                        SessionStatus::KeepAlive=>return Ok(()),
                        SessionStatus::Keep=>(),
                    }
                    if metadata.option.has_error() {if let Some(entry)=sessions.remove(&id) {entry.abort.abort();}return Ok(());}
                    if metadata.option.has_data() {
                        if let Some(entry)=sessions.get(&id) {entry.input.try_send(Queued::new(payload,&budget.bytes)?).map_err(|_|crate::invalid("SIP003 plugin mux queue is full"))?;} else {let _=output.try_send(Outgoing::Fin(id as u32));}
                    }
                    Ok(())
                })();
                if let Err(error)=outcome {break Err(error);}
            },
        }
    };
    sessions.clear();
    drop(output);
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}
