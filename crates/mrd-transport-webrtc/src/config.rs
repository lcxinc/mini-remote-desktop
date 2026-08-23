use std::fmt;

use mrd_pipeline_core::VideoCodec;
use zeroize::{Zeroize, Zeroizing};

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

#[derive(PartialEq, Eq)]
pub struct IceServerConfig {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

impl Clone for IceServerConfig {
    fn clone(&self) -> Self {
        Self {
            urls: self.urls.clone(),
            username: self.username.clone(),
            credential: self.credential.clone(),
        }
    }
}

impl Drop for IceServerConfig {
    fn drop(&mut self) {
        for url in &mut self.urls {
            url.zeroize();
        }
        self.urls.clear();
        self.username.zeroize();
        self.credential.zeroize();
    }
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
        formatter
            .debug_struct("IceServerConfig")
            .field("urls", &RedactedUrls(&self.urls))
            .field("username", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for IceServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let urls = self
            .urls
            .iter()
            .map(|url| redact_ice_server_url(url))
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            formatter,
            "IceServerConfig {{ urls: [{urls}], username: [REDACTED], credential: [REDACTED] }}"
        )
    }
}

struct RedactedUrls<'a>(&'a [String]);

impl fmt::Debug for RedactedUrls<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.0.iter().map(|url| RedactedUrl(url)))
            .finish()
    }
}

struct RedactedUrl<'a>(&'a str);

impl fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&redact_ice_server_url(self.0))
    }
}

/// Preserve the endpoint fields operators need while suppressing every URI component that can
/// carry credentials. TURN's URI syntax is deliberately parsed here instead of using a generic
/// URL formatter because `turn:host:port` is an opaque URI in common URL libraries.
pub(crate) fn redact_ice_server_url(url: &str) -> String {
    let trimmed = url.trim();
    let Some((scheme, remainder)) = trimmed.split_once(':') else {
        return "[REDACTED]".into();
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "turn" | "turns") {
        return format!("{scheme}:[REDACTED]");
    }

    let (without_fragment, fragment) = remainder
        .split_once('#')
        .map_or((remainder, None), |(base, value)| (base, Some(value)));
    let (endpoint_and_path, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, None), |(base, value)| {
            (base, Some(value))
        });
    let path_offset = endpoint_and_path.find('/');
    let endpoint = path_offset.map_or(endpoint_and_path, |offset| &endpoint_and_path[..offset]);
    let has_path = path_offset.is_some();
    let (had_userinfo, endpoint) = endpoint
        .rsplit_once('@')
        .map_or((false, endpoint), |(_, public_endpoint)| {
            (true, public_endpoint)
        });

    let mut output = format!("{scheme}:");
    if had_userinfo {
        output.push_str("[REDACTED]@");
    }
    if endpoint.is_empty() {
        output.push_str("[REDACTED]");
    } else {
        output.push_str(endpoint);
    }
    if has_path {
        output.push_str("/[REDACTED]");
    }
    if let Some(query) = query {
        output.push('?');
        output.push_str(
            &query
                .split('&')
                .map(|parameter| {
                    let Some((name, value)) = parameter.split_once('=') else {
                        return "[REDACTED]";
                    };
                    if name.eq_ignore_ascii_case("transport")
                        && matches!(value.to_ascii_lowercase().as_str(), "udp" | "tcp")
                    {
                        if value.eq_ignore_ascii_case("udp") {
                            "transport=udp"
                        } else {
                            "transport=tcp"
                        }
                    } else {
                        "[REDACTED]"
                    }
                })
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    if fragment.is_some() {
        output.push_str("#[REDACTED]");
    }
    output
}

pub(crate) type SecretValues = Zeroizing<Vec<Zeroizing<String>>>;

pub(crate) fn ice_server_secret_values(ice_servers: &[IceServerConfig]) -> SecretValues {
    let mut secrets = Zeroizing::new(Vec::new());
    for server in ice_servers {
        secrets.push(Zeroizing::new(server.username.clone()));
        secrets.push(Zeroizing::new(server.credential.clone()));
        for url in &server.urls {
            collect_url_secrets(url, &mut secrets);
        }
    }
    normalize_secret_values(secrets)
}

pub(crate) fn normalize_secret_values(mut secrets: SecretValues) -> SecretValues {
    secrets.retain(|secret| !secret.is_empty());
    secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
    secrets
}

fn collect_url_secrets(url: &str, secrets: &mut SecretValues) {
    let Some((_, remainder)) = url.trim().split_once(':') else {
        secrets.push(Zeroizing::new(url.to_owned()));
        return;
    };
    let (without_fragment, fragment) = remainder
        .split_once('#')
        .map_or((remainder, None), |(base, value)| (base, Some(value)));
    if let Some(fragment) = fragment {
        secrets.push(Zeroizing::new(fragment.to_owned()));
    }
    let (endpoint_and_path, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, None), |(base, value)| {
            (base, Some(value))
        });
    if let Some(query) = query {
        for parameter in query.split('&') {
            let is_public_transport = parameter.split_once('=').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("transport")
                    && matches!(value.to_ascii_lowercase().as_str(), "udp" | "tcp")
            });
            if !is_public_transport {
                secrets.push(Zeroizing::new(parameter.to_owned()));
                if let Some((_, value)) = parameter.split_once('=') {
                    secrets.push(Zeroizing::new(value.to_owned()));
                }
            }
        }
    }
    let path_offset = endpoint_and_path.find('/');
    let endpoint = path_offset.map_or(endpoint_and_path, |offset| &endpoint_and_path[..offset]);
    if let Some(offset) = path_offset {
        let path = &endpoint_and_path[offset + 1..];
        secrets.push(Zeroizing::new(path.to_owned()));
        secrets.extend(
            path.split('/')
                .map(|value| Zeroizing::new(value.to_owned())),
        );
    }
    if let Some((userinfo, _)) = endpoint.rsplit_once('@') {
        secrets.push(Zeroizing::new(userinfo.to_owned()));
        secrets.extend(
            userinfo
                .split(':')
                .map(|value| Zeroizing::new(value.to_owned())),
        );
    }
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

#[cfg(test)]
mod secret_lifetime_tests {
    use super::IceServerConfig;

    #[test]
    fn ice_server_config_and_clones_have_zeroizing_drop_owners() {
        assert!(std::mem::needs_drop::<IceServerConfig>());
        let config = IceServerConfig::new(
            vec!["turn:url-user-9x:url-pass-8y@relay.invalid?credential=url-secret-7z".into()],
            "sensitive-user".into(),
            "sensitive-credential".into(),
        );
        let cloned = config.clone();
        let debug = format!("{cloned:?}");
        let display = cloned.to_string();
        for secret in [
            "url-user-9x",
            "url-pass-8y",
            "url-secret-7z",
            "sensitive-user",
            "sensitive-credential",
        ] {
            assert!(!debug.contains(secret));
            assert!(!display.contains(secret));
        }
    }
}
