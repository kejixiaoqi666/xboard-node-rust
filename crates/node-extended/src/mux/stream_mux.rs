//! SMUX v1 and YAMUX framing for Sing multiplex payload streams.
//! Wire specifications: xtaci/smux frame.go and hashicorp/yamux spec.md.
//! Session policy, global queue permits and accounting are shared with other muxes.
use crate::{
    SessionContext,
    channel::{ChannelStream, Outgoing, Queued},
};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use node_session::{BoxStream, Host, User};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::{Semaphore, mpsc, watch},
    task::{AbortHandle, JoinSet},
};
use tokio_util::codec::{Decoder, FramedRead};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Smux,
    Yamux,
}
const WINDOW: usize = 256 * 1024;
struct Frame {
    kind: u8,
    flags: u16,
    id: u32,
    argument: u32,
    payload: Bytes,
}
struct Codec {
    kind: Kind,
    max: usize,
}
impl Decoder for Codec {
    type Item = Frame;
    type Error = io::Error;
    fn decode(&mut self, bytes: &mut BytesMut) -> io::Result<Option<Frame>> {
        let header = if self.kind == Kind::Smux { 8 } else { 12 };
        if bytes.len() < header {
            return Ok(None);
        }
        let (kind, flags, id, argument, data_len) = if self.kind == Kind::Smux {
            if bytes[0] != 1 {
                return Err(crate::invalid("unsupported SMUX version"));
            }
            let size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
            if bytes[1] > 3 || (bytes[1] != 2 && size != 0) {
                return Err(crate::invalid("invalid SMUX control frame"));
            }
            let (kind, flags) = match bytes[1] {
                0 => (1, 1),
                1 => (1, 4),
                2 => (0, 0),
                3 => (2, 0),
                _ => unreachable!(),
            };
            (
                kind,
                flags,
                u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
                size as u32,
                size,
            )
        } else {
            if bytes[0] != 0 || bytes[1] > 3 {
                return Err(crate::invalid("invalid YAMUX version/type"));
            }
            let flags = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
            if flags & !15 != 0 {
                return Err(crate::invalid("unknown YAMUX flags"));
            }
            let size = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
            (
                bytes[1],
                flags,
                u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                size,
                if bytes[1] == 0 { size as usize } else { 0 },
            )
        };
        if data_len > self.max {
            return Err(crate::invalid("multiplexed frame exceeds limit"));
        }
        if bytes.len() < header + data_len {
            return Ok(None);
        }
        let _ = bytes.split_to(header);
        let payload = bytes.split_to(data_len).freeze();
        Ok(Some(Frame {
            kind,
            flags,
            id,
            argument,
            payload,
        }))
    }
}
fn encode_header(kind: Kind, frame: &Frame) -> Bytes {
    if kind == Kind::Smux {
        let cmd = if frame.kind == 0 {
            2
        } else if frame.flags & 4 != 0 {
            1
        } else if frame.flags & 1 != 0 {
            0
        } else {
            3
        };
        let mut header = [0u8; 8];
        header[0] = 1;
        header[1] = cmd;
        header[2..4].copy_from_slice(&(frame.payload.len() as u16).to_le_bytes());
        header[4..8].copy_from_slice(&frame.id.to_le_bytes());
        Bytes::copy_from_slice(&header)
    } else {
        let mut header = [0u8; 12];
        header[1] = frame.kind;
        header[2..4].copy_from_slice(&frame.flags.to_be_bytes());
        header[4..8].copy_from_slice(&frame.id.to_be_bytes());
        header[8..12].copy_from_slice(&frame.argument.to_be_bytes());
        Bytes::copy_from_slice(&header)
    }
}
fn control(output: &mpsc::Sender<Outgoing>, kind: Kind, frame: Frame) -> io::Result<()> {
    output
        .try_send(Outgoing::Control(255, 0, encode_header(kind, &frame)))
        .map_err(|_| crate::invalid("multiplexed control queue is full"))
}
struct Entry {
    input: Option<mpsc::Sender<Queued>>,
    abort: AbortHandle,
    send: Arc<Semaphore>,
    receive: Arc<AtomicUsize>,
}
pub(crate) async fn serve(
    stream: BoxStream,
    kind: Kind,
    user: User,
    peer: SocketAddr,
    host: Arc<dyn Host>,
    config: crate::Config,
    mut cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    config.require_multiplex()?;
    let listener = config
        .shared_budget
        .bind(config.max_queued_bytes, config.max_sessions)?;
    let (read, write) = tokio::io::split(stream);
    let mut read = FramedRead::with_capacity(
        read,
        Codec {
            kind,
            max: config.max_frame,
        },
        8192,
    );
    let (output, output_rx) = mpsc::channel(128);
    let mut jobs: JoinSet<(Option<u32>, io::Result<()>)> = JoinSet::new();
    jobs.spawn(async move { (None, writer(write, output_rx, kind).await) });
    let mut entries: HashMap<u32, Entry> = HashMap::new();
    let mut last = 0;
    let result = loop {
        tokio::select! {
            biased;
            _=crate::cancelled(&mut cancel)=>break Ok(()),
            job=jobs.join_next()=>match job {Some(Ok((Some(id),_)))=>{entries.remove(&id);},Some(Ok((None,result)))=>break result,Some(Err(error)) if !error.is_cancelled()=>break Err(io::Error::other(error)),_=>()},
            frame=read.next()=>{
                let frame=match frame {None=>break Ok(()),Some(Err(error))=>break Err(error),Some(Ok(frame))=>frame};
                let outcome:io::Result<()>= (|| {
                    if frame.kind==2 {
                        if kind==Kind::Yamux {
                            if frame.id!=0 || !matches!(frame.flags,1|2) {return Err(crate::invalid("invalid YAMUX ping"));}
                            if frame.flags==1 {control(&output,kind,Frame {flags:2,..frame})?;}
                        }
                        return Ok(());
                    }
                    if frame.kind==3 {
                        if frame.id!=0 || frame.flags!=0 {return Err(crate::invalid("invalid YAMUX GOAWAY"));}
                        return Err(io::Error::new(io::ErrorKind::ConnectionAborted,"peer sent YAMUX GOAWAY"));
                    }
                    if frame.id==0 || frame.id&1==0 {return Err(crate::invalid("invalid multiplexed client stream ID"));}
                    if frame.flags&1!=0 {
                        if frame.flags& (2|8)!=0 || frame.id<=last || entries.contains_key(&frame.id) {return Err(crate::invalid("duplicate/out-of-order multiplexed stream"));}
                        let session=listener.session()?; last=frame.id;
                        let (input,rx)=mpsc::channel(32);
                        let send=Arc::new(Semaphore::new(WINDOW)); let receive=Arc::new(AtomicUsize::new(WINDOW));
                        let mut client=ChannelStream::new(frame.id,rx,output.clone(),listener.bytes.clone(),config.max_frame.min(16384));
                        if kind==Kind::Yamux {
                            client=client.with_yamux_windows(send.clone(),receive.clone(),output.clone());
                            control(&output,kind,Frame {kind:1,flags:2,id:frame.id,argument:0,payload:Bytes::new()})?;
                        }
                        let context=SessionContext {user:user.clone(),peer,host:host.clone(),config:config.clone()};
                        let out=output.clone(); let id=frame.id;
                        let abort=jobs.spawn(async move {let _session=session; let result=super::handle_payload(Box::new(client),context).await; if result.is_err() {let _=out.try_send(Outgoing::Fin(id));} (Some(id),result)});
                        entries.insert(id,Entry {input:Some(input),abort,send,receive});
                    }
                    if frame.flags&8!=0 {if let Some(entry)=entries.remove(&frame.id) {entry.abort.abort();} return Ok(());}
                    let Some(entry)=entries.get_mut(&frame.id) else {
                        if kind==Kind::Yamux {control(&output,kind,Frame {kind:1,flags:8,id:frame.id,argument:0,payload:Bytes::new()})?;}
                        return Ok(());
                    };
                    if frame.kind==1 && kind==Kind::Yamux {
                        let delta=frame.argument as usize;
                        if delta>config.max_queued_bytes || entry.send.available_permits().saturating_add(delta)>config.max_queued_bytes {return Err(crate::invalid("YAMUX send window exceeds limit"));}
                        entry.send.add_permits(delta);
                    }
                    if frame.kind==0 && !frame.payload.is_empty() {
                        if kind==Kind::Yamux {entry.receive.fetch_update(Ordering::AcqRel,Ordering::Acquire,|remaining|remaining.checked_sub(frame.payload.len())).map_err(|_|crate::invalid("YAMUX receive window exceeded"))?;}
                        let queued=Queued::new(frame.payload,&listener.bytes)?;
                        entry.input.as_ref().ok_or_else(||crate::invalid("data after mux stream FIN"))?.try_send(queued).map_err(|_|crate::invalid("mux logical stream queue is full"))?;
                    }
                    if frame.flags&4!=0 {entry.input.take();}
                    Ok(())
                })();
                if let Err(error)=outcome {break Err(error);}
            }
        }
    };
    entries.clear();
    drop(output);
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}
async fn writer<W: AsyncWrite + Unpin>(
    mut write: W,
    mut output: mpsc::Receiver<Outgoing>,
    kind: Kind,
) -> io::Result<()> {
    while let Some(item) = output.recv().await {
        match item {
            Outgoing::Data(id, data) => {
                let frame = Frame {
                    kind: 0,
                    flags: 0,
                    id,
                    argument: data.bytes.len() as u32,
                    payload: data.bytes.clone(),
                };
                write.write_all(&encode_header(kind, &frame)).await?;
                write.write_all(&data.bytes).await?;
            }
            Outgoing::Fin(id) => {
                write
                    .write_all(&encode_header(
                        kind,
                        &Frame {
                            kind: 1,
                            flags: 4,
                            id,
                            argument: 0,
                            payload: Bytes::new(),
                        },
                    ))
                    .await?;
            }
            Outgoing::Control(255, _, header) => write.write_all(&header).await?,
            Outgoing::Barrier(done) => {
                write.flush().await?;
                let _ = done.send(());
            }
            _ => return Err(crate::invalid("invalid multiplexed writer item")),
        }
        write.flush().await?;
    }
    write.shutdown().await
}
