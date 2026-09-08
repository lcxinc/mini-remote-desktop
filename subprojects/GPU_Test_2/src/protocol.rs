use anyhow::{anyhow, ensure, Result};

pub const FRAME_MAGIC: u32 = 0x4D52_4431;
pub const FRAME_VERSION: u16 = 2;  // Bump for capture_time_ns field
pub const FRAME_HEADER_LEN: usize = 4 + 2 + 2 + 4 + 4 + 8 + 8 + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub width: u32,
    pub height: u32,
    pub pts: u64,
    pub capture_time_ns: u64,  // Absolute UNIX epoch timestamp (ns) when frame was captured
    pub payload_len: u32,
}

pub fn parse_frame_header(bytes: &[u8; FRAME_HEADER_LEN]) -> Result<FrameHeader> {
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    ensure!(magic == FRAME_MAGIC, "invalid frame magic");

    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    ensure!(version == FRAME_VERSION, "unsupported frame version");

    let width = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let height = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let pts = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let capture_time_ns = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let payload_len = u32::from_le_bytes(bytes[32..36].try_into().unwrap());

    Ok(FrameHeader::new(width, height, pts, capture_time_ns, payload_len))
}

impl FrameHeader {
    pub fn new(width: u32, height: u32, pts: u64, capture_time_ns: u64, payload_len: u32) -> Self {
        Self {
            width,
            height,
            pts,
            capture_time_ns,
            payload_len,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFrameMessage {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

pub fn encode_frame_message(header: &FrameHeader, payload: &[u8]) -> Vec<u8> {
    assert_eq!(header.payload_len as usize, payload.len());

    let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    bytes.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&header.width.to_le_bytes());
    bytes.extend_from_slice(&header.height.to_le_bytes());
    bytes.extend_from_slice(&header.pts.to_le_bytes());
    bytes.extend_from_slice(&header.capture_time_ns.to_le_bytes());
    bytes.extend_from_slice(&header.payload_len.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn decode_frame_message(bytes: &[u8]) -> Result<ParsedFrameMessage> {
    ensure!(bytes.len() >= FRAME_HEADER_LEN, "frame message truncated");

    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    ensure!(magic == FRAME_MAGIC, "invalid frame magic");

    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    ensure!(version == FRAME_VERSION, "unsupported frame version");

    let width = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let height = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let pts = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let capture_time_ns = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let payload_len = u32::from_le_bytes(bytes[32..36].try_into().unwrap());

    let expected_len = FRAME_HEADER_LEN
        .checked_add(payload_len as usize)
        .ok_or_else(|| anyhow!("frame payload length overflow"))?;
    ensure!(bytes.len() == expected_len, "frame payload length mismatch");

    Ok(ParsedFrameMessage {
        header: FrameHeader::new(width, height, pts, capture_time_ns, payload_len),
        payload: bytes[FRAME_HEADER_LEN..].to_vec(),
    })
}
