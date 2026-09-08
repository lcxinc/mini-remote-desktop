use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::{
    encode_frame_message, FrameHeader, FRAME_HEADER_LEN, ParsedFrameMessage,
};

pub async fn write_frame_message<W>(
    writer: &mut W,
    header: &FrameHeader,
    payload: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes = encode_frame_message(header, payload);
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame_message<R>(reader: &mut R) -> Result<ParsedFrameMessage>
where
    R: AsyncRead + Unpin,
{
    let mut header_buf = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header_buf).await?;

    let header = crate::protocol::parse_frame_header(&header_buf)?;

    let mut payload = vec![0u8; header.payload_len as usize];
    if header.payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(ParsedFrameMessage {
        header,
        payload,
    })
}
