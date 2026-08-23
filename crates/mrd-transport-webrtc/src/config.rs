use std::fmt;

use mrd_pipeline_core::VideoCodec;

use crate::{H264Profile, TransportError, DEFAULT_MAX_H264_ACCESS_UNIT_BYTES};

const DATA_CHANNEL_WIRE_BUDGET_OVERHEAD: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnectionRole {
    Offerer,
    Answerer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceTransportPolicy {
    All,
    Relay,
}

#[derive(Clone, PartialEq, Eq)]
pub struct IceServerConfig {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

impl IceServerConfig {
    pub fn new(urls: Vec<String>, username: String, credential: String) -> Self {
        Self {
            urls,
            username,
            credential,
        }
    }
}

impl fmt::Debug for IceServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let urls = redacted_urls(&self.urls);
        formatter
            .debug_struct("IceServerConfig")
            .field("urls", &urls)
            .field("username", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for IceServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let urls = redacted_urls(&self.urls);
        write!(
            formatter,
            "IceServerConfig {{ urls: {:?}, username: [REDACTED], credential: [REDACTED] }}",
            urls
        )
    }
}

fn redacted_urls(urls: &[String]) -> Vec<String> {
    urls.iter()
        .map(|url| match url.rsplit_once('@') {
            Some((prefix, host)) if prefix.contains(':') => {
                let scheme_end = prefix.find(':').expect("prefix contains a colon");
                format!("{}:[REDACTED]@{host}", &prefix[..scheme_end])
            }
            _ => url.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264CodecProfile {
    Baseline,
    High,
}

impl From<H264CodecProfile> for H264Profile {
    fn from(value: H264CodecProfile) -> Self {
        match value {
            H264CodecProfile::Baseline => H264Profile::Baseline,
            H264CodecProfile::High => H264Profile::High,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H264CodecConfig {
    pub profile: H264CodecProfile,
    pub profile_level_id: String,
    pub packetization_mode: u8,
}

impl Default for H264CodecConfig {
    fn default() -> Self {
        Self {
            profile: H264CodecProfile::Baseline,
            profile_level_id: "42e01f".to_owned(),
            packetization_mode: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoCodecConfig {
    H264(H264CodecConfig),
    Unsupported(VideoCodec),
}

impl Default for VideoCodecConfig {
    fn default() -> Self {
        Self::H264(H264CodecConfig::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConnectionConfig {
    pub role: PeerConnectionRole,
    pub ice_servers: Vec<IceServerConfig>,
    pub ice_transport_policy: IceTransportPolicy,
    pub video_codec: VideoCodecConfig,
    pub include_loopback_candidates: bool,
    pub fps: u32,
    pub mtu: u16,
    pub event_queue_capacity: usize,
    pub max_h264_access_unit_bytes: usize,
    pub video_queue_bytes: usize,
    pub reliable_queue_bytes: usize,
    pub realtime_queue_bytes: usize,
    pub bulk_queue_bytes: usize,
}

impl Default for PeerConnectionConfig {
    fn default() -> Self {
        Self {
            role: PeerConnectionRole::Offerer,
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
            video_codec: VideoCodecConfig::default(),
            include_loopback_candidates: false,
            fps: 60,
            mtu: 1200,
            event_queue_capacity: 64,
            max_h264_access_unit_bytes: DEFAULT_MAX_H264_ACCESS_UNIT_BYTES,
            video_queue_bytes: 16 * 1024 * 1024,
            reliable_queue_bytes: 4 * 1024 * 1024 + DATA_CHANNEL_WIRE_BUDGET_OVERHEAD,
            realtime_queue_bytes: 64 * 1024,
            bulk_queue_bytes: 16 * 1024 * 1024 + DATA_CHANNEL_WIRE_BUDGET_OVERHEAD,
        }
    }
}

impl PeerConnectionConfig {
    pub(crate) fn preflight(&self) -> Result<&H264CodecConfig, TransportError> {
        let codec = match &self.video_codec {
            VideoCodecConfig::H264(codec) => codec,
            VideoCodecConfig::Unsupported(codec) => {
                return Err(TransportError::Message(format!(
                    "unsupported WebRTC video codec: {codec:?}"
                )));
            }
        };
        if codec.packetization_mode != 1 {
            return Err(TransportError::Message(format!(
                "unsupported H.264 packetization-mode {}; expected 1",
                codec.packetization_mode
            )));
        }
        if codec.profile_level_id.len() != 6
            || !codec
                .profile_level_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(TransportError::Message(
                "H.264 profile-level-id must contain exactly six hexadecimal digits".into(),
            ));
        }
        let prefix = codec.profile_level_id[..2].to_ascii_lowercase();
        let profile_matches = match codec.profile {
            H264CodecProfile::Baseline => prefix == "42",
            H264CodecProfile::High => prefix == "64",
        };
        if !profile_matches {
            return Err(TransportError::Message(format!(
                "H.264 profile-level-id {} does not match {:?}",
                codec.profile_level_id, codec.profile
            )));
        }
        if self.fps == 0 {
            return Err(TransportError::Message(
                "WebRTC fps must be non-zero".into(),
            ));
        }
        if self.event_queue_capacity == 0 {
            return Err(TransportError::Message(
                "WebRTC event queue capacity must be non-zero".into(),
            ));
        }
        if self.max_h264_access_unit_bytes == 0
            || self.video_queue_bytes == 0
            || self.reliable_queue_bytes == 0
            || self.realtime_queue_bytes == 0
            || self.bulk_queue_bytes == 0
        {
            return Err(TransportError::Message(
                "WebRTC byte budgets must be non-zero".into(),
            ));
        }
        if self.max_h264_access_unit_bytes > self.video_queue_bytes {
            return Err(TransportError::Message(
                "WebRTC H.264 access-unit limit exceeds the completed-video queue byte budget"
                    .into(),
            ));
        }
        if [
            self.video_queue_bytes,
            self.reliable_queue_bytes,
            self.realtime_queue_bytes,
            self.bulk_queue_bytes,
        ]
        .into_iter()
        .any(|bytes| bytes > tokio::sync::Semaphore::MAX_PERMITS)
        {
            return Err(TransportError::Message(
                "WebRTC queue byte budget exceeds semaphore capacity".into(),
            ));
        }
        Ok(codec)
    }
}
