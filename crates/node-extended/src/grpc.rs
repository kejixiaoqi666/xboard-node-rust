//! V2Ray gRPC Tun: uncompressed gRPC messages carrying protobuf bytes field 1.
use crate::io_adapter::{PacketReader, PacketStream, PacketWriter};
use async_trait::async_trait;
use bytes::Bytes;
use node_session::BoxStream;
use std::{io, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Semaphore, watch},
};

#[derive(Clone, Debug)]
pub struct GrpcConfig {
    pub service_name: String,
}
impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: "TunService".into(),
        }
    }
}
pub async fn serve(
    stream: BoxStream,
    transport: GrpcConfig,
    handler: Arc<dyn crate::http2::StreamHandler>,
    config: crate::Config,
    cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    if transport.service_name.len() > 253
        || transport
            .service_name
            .bytes()
            .any(|byte| byte <= 32 || byte == b'/' || byte == 127)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid gRPC service name",
        ));
    }
    crate::http2::serve_mode(
        stream,
        crate::http2::Mode::Grpc(transport),
        handler,
        config,
        cancel,
    )
    .await
}
pub(crate) fn wrap(stream: BoxStream, max: usize, budget: Arc<Semaphore>) -> BoxStream {
    let (read, write) = tokio::io::split(stream);
    Box::new(PacketStream::new(
        Reader { read, max, budget },
        Writer { write },
        max.min(16384),
    ))
}
struct Reader {
    read: tokio::io::ReadHalf<BoxStream>,
    max: usize,
    budget: Arc<Semaphore>,
}
struct Writer {
    write: tokio::io::WriteHalf<BoxStream>,
}
#[async_trait]
impl PacketReader for Reader {
    async fn read_packet(&mut self) -> io::Result<Option<Bytes>> {
        let mut header = [0; 5];
        if self.read.read(&mut header[..1]).await? == 0 {
            return Ok(None);
        }
        self.read.read_exact(&mut header[1..]).await?;
        if header[0] != 0 {
            return Err(crate::invalid("compressed gRPC messages are unsupported"));
        }
        let size = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
        if size < 2 || size > self.max + 11 {
            return Err(crate::invalid("gRPC message exceeds limit"));
        }
        // Acquire before allocating. A saturated malicious carrier fails closed
        // rather than holding unlimited partially decoded protobuf buffers.
        let permit = self
            .budget
            .clone()
            .try_acquire_many_owned(size as u32)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "gRPC listener queue is full")
            })?;
        let mut body = vec![0; size];
        self.read.read_exact(&mut body).await?;
        let (offset, len) = protobuf_payload(&body)?;
        if len > self.max {
            return Err(crate::invalid("gRPC payload exceeds limit"));
        }
        Ok(Some(
            crate::channel::Queued::with_permit(
                Bytes::from(body).slice(offset..offset + len),
                permit,
            )
            .into_owned_bytes(),
        ))
    }
}
fn protobuf_payload(body: &[u8]) -> io::Result<(usize, usize)> {
    if body.first() != Some(&10) {
        return Err(crate::invalid("gRPC Tun requires protobuf field 1"));
    }
    let mut value = 0usize;
    for (index, &byte) in body.iter().skip(1).take(5).enumerate() {
        value |= ((byte & 127) as usize) << (index * 7);
        if byte & 128 == 0 {
            let offset = index + 2;
            if (index > 0 && byte == 0) || offset.checked_add(value) != Some(body.len()) {
                return Err(crate::invalid("invalid gRPC protobuf byte length"));
            }
            return Ok((offset, value));
        }
    }
    Err(crate::invalid("invalid gRPC protobuf varint"))
}
#[async_trait]
impl PacketWriter for Writer {
    async fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut len = payload.len();
        let mut varint = Vec::with_capacity(5);
        while len >= 128 {
            varint.push((len as u8) | 128);
            len >>= 7;
        }
        varint.push(len as u8);
        self.write.write_u8(0).await?;
        self.write
            .write_u32((1 + varint.len() + payload.len()) as u32)
            .await?;
        self.write.write_u8(10).await?;
        self.write.write_all(&varint).await?;
        self.write.write_all(payload).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        self.write.flush().await
    }
    async fn finish(&mut self) -> io::Result<()> {
        self.write.shutdown().await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protobuf_rejects_noncanonical_lengths_and_trailing_fields() {
        assert_eq!(protobuf_payload(&[10, 3, 1, 2, 3]).unwrap(), (2, 3));
        for body in [
            &[10, 128, 0][..],
            &[10, 3, 1, 2][..],
            &[10, 0, 10, 0][..],
            &[18, 0][..],
        ] {
            assert!(protobuf_payload(body).is_err());
        }
    }
}
