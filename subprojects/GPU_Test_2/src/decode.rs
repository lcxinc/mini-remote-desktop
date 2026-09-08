use anyhow::{anyhow, Result};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use openh264::nal_units;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

pub fn decode_first_frame(bitstream: &[u8]) -> Result<DecodedFrame> {
    let mut decoder = Decoder::new().map_err(|err| anyhow!("failed to create decoder: {err}"))?;

    for packet in nal_units(bitstream) {
        let maybe_yuv = decoder
            .decode(packet)
            .map_err(|err| anyhow!("invalid H.264 payload: {err}"))?;

        if let Some(yuv) = maybe_yuv {
            let (width, height) = yuv.dimensions();
            let mut rgb = vec![0u8; yuv.rgb8_len()];
            yuv.write_rgb8(&mut rgb);
            return Ok(DecodedFrame {
                width: width as u32,
                height: height as u32,
                rgb,
            });
        }
    }

    Err(anyhow!("invalid H.264 payload: no decodable frame found"))
}

/// A persistent H.264 decoder that maintains state across multiple frames.
pub struct StreamingDecoder {
    decoder: Decoder,
    latest_frame: Option<DecodedFrame>,
}

impl StreamingDecoder {
    /// Create a new streaming decoder.
    pub fn new() -> Result<Self> {
        let decoder = Decoder::new().map_err(|err| anyhow!("failed to create decoder: {err}"))?;
        Ok(Self {
            decoder,
            latest_frame: None,
        })
    }

    /// Decode a single H.264 packet.
    ///
    /// Returns Ok(Some(frame)) if a new frame was decoded from this packet.
    /// Returns Ok(None) if the packet was processed but produced no new frame (common for P-frames).
    /// Returns Err only for critical decoder failures.
    /// The decoder remains usable after errors.
    pub fn decode_packet(&mut self, bitstream: &[u8]) -> Result<Option<&DecodedFrame>> {
        for packet in nal_units(bitstream) {
            let maybe_yuv = self
                .decoder
                .decode(packet)
                .map_err(|err| anyhow!("decode error: {err}"))?;

            if let Some(yuv) = maybe_yuv {
                let (width, height) = yuv.dimensions();
                let mut rgb = vec![0u8; yuv.rgb8_len()];
                yuv.write_rgb8(&mut rgb);

                self.latest_frame = Some(DecodedFrame {
                    width: width as u32,
                    height: height as u32,
                    rgb,
                });

                return Ok(self.latest_frame.as_ref());
            }
        }

        // No frame produced from this packet - don't return stale frame
        Ok(None)
    }

    /// Get the latest decoded frame, if any.
    pub fn latest_frame(&self) -> Option<&DecodedFrame> {
        self.latest_frame.as_ref()
    }
}
