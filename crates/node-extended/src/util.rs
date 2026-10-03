use tokio::io::{AsyncWrite, AsyncWriteExt};
pub async fn write_all<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    writer.write_all(data).await
}
