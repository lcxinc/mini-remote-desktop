use std::{fmt, net::IpAddr, time::Duration};

use async_trait::async_trait;
use mrd_transport_webrtc::{probe_turn_relay, IceServerConfig, TurnRelayProbeConfig};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessHealth {
    Healthy,
    Degraded,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoturnSnapshot {
    /// Changes whenever the process instance or applied configuration changes.
    /// A PID alone is insufficient because coturn can hot-reload credentials.
    pub generation: u64,
    pub applied_secret_version: u64,
    pub health: ProcessHealth,
    pub active_allocations: u32,
    pub current_egress_bps: u64,
}

impl CoturnSnapshot {
    pub fn healthy(active_allocations: u32, current_egress_bps: u64) -> Self {
        Self {
            generation: 1,
            applied_secret_version: 1,
            health: ProcessHealth::Healthy,
            active_allocations,
            current_egress_bps,
        }
    }

    pub fn with_generation(mut self, generation: u64, applied_secret_version: u64) -> Self {
        self.generation = generation;
        self.applied_secret_version = applied_secret_version;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocationProbeEvidence {
    /// A fake, port-open check, unavailable live environment, or any other
    /// observation which cannot prove a TURN allocation and relayed traffic.
    NonEvidence,
    Live(LiveAllocationEvidence),
}

impl AllocationProbeEvidence {
    pub fn is_real_roundtrip(&self) -> bool {
        matches!(self, Self::Live(_))
    }

    pub fn proof_sha256(&self) -> Option<[u8; 32]> {
        match self {
            Self::NonEvidence => None,
            Self::Live(evidence) => Some(evidence.proof_sha256),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveAllocationEvidence {
    proof_sha256: [u8; 32],
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

impl LiveAllocationEvidence {
    /// Constructs evidence only after the caller has completed the production
    /// allocation + bidirectional relay roundtrip. Kept crate-private so
    /// downstream adapters and external tests cannot manufacture `Live`.
    #[cfg(test)]
    pub(crate) fn from_verified_roundtrip(proof_sha256: [u8; 32]) -> Self {
        Self {
            proof_sha256,
            packets_sent: 1,
            packets_received: 1,
            bytes_sent: 1,
            bytes_received: 1,
        }
    }

    pub(crate) fn from_broker_roundtrip(
        proof_sha256: [u8; 32],
        packets_sent: u64,
        packets_received: u64,
        bytes_sent: u64,
        bytes_received: u64,
    ) -> Option<Self> {
        if proof_sha256.iter().all(|byte| *byte == 0)
            || packets_sent == 0
            || packets_received == 0
            || bytes_sent == 0
            || bytes_received == 0
        {
            return None;
        }
        Some(Self {
            proof_sha256,
            packets_sent,
            packets_received,
            bytes_sent,
            bytes_received,
        })
    }

    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    pub fn proof_sha256(&self) -> [u8; 32] {
        self.proof_sha256
    }

    pub fn packets_received(&self) -> u64 {
        self.packets_received
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }
}

#[async_trait]
pub trait LocalAllocationProbePort: Send + Sync {
    async fn probe(&self) -> Result<AllocationProbeEvidence, ProcessError>;
}

pub struct WebRtcLocalAllocationProbe {
    urls: Vec<String>,
    username: SecretString,
    credential: SecretString,
    timeout: Duration,
}

impl WebRtcLocalAllocationProbe {
    pub fn new(
        urls: Vec<String>,
        username: SecretString,
        credential: SecretString,
        timeout: Duration,
    ) -> Result<Self, ProcessError> {
        if urls.is_empty()
            || urls.len() > 4
            || urls.iter().any(|url| {
                url.is_empty() || url.len() > 512 || url.contains('@') || !is_local_turn_url(url)
            })
            || username.expose_secret().is_empty()
            || username.expose_secret().len() > 512
            || credential.expose_secret().is_empty()
            || credential.expose_secret().len() > 512
            || timeout.is_zero()
            || timeout > Duration::from_secs(60)
        {
            return Err(ProcessError::ProbeUnavailable);
        }
        Ok(Self {
            urls,
            username,
            credential,
            timeout,
        })
    }
}

fn is_local_turn_url(value: &str) -> bool {
    let Some(authority_and_query) = value
        .strip_prefix("turn:")
        .or_else(|| value.strip_prefix("turns:"))
    else {
        return false;
    };
    let mut parts = authority_and_query.split('?');
    let authority = parts.next().unwrap_or_default();
    let query = parts.next();
    if parts.next().is_some()
        || query.is_some_and(|query| !matches!(query, "transport=udp" | "transport=tcp"))
    {
        return false;
    }
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((host, port)) = ipv6.split_once("]:") else {
            return false;
        };
        (host, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return false;
        };
        (host, port)
    };
    let local_host = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    local_host && port.parse::<u16>().is_ok_and(|port| port != 0)
}

impl fmt::Debug for WebRtcLocalAllocationProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebRtcLocalAllocationProbe")
            .field("url_count", &self.urls.len())
            .field("username", &"REDACTED")
            .field("credential", &"REDACTED")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[async_trait]
impl LocalAllocationProbePort for WebRtcLocalAllocationProbe {
    async fn probe(&self) -> Result<AllocationProbeEvidence, ProcessError> {
        let evidence = probe_turn_relay(TurnRelayProbeConfig {
            ice_servers: vec![IceServerConfig::new(
                self.urls.clone(),
                self.username.expose_secret().to_owned(),
                self.credential.expose_secret().to_owned(),
            )],
            timeout: self.timeout,
        })
        .await
        .map_err(|_| ProcessError::ProbeUnavailable)?;
        let pair = evidence.selected_pair();
        let mut hasher = Sha256::new();
        hasher.update(b"MRD_TURN_LIVE_PROBE_V1\0");
        hasher.update(pair.local_candidate_id.as_bytes());
        hasher.update([0]);
        hasher.update(pair.remote_candidate_id.as_bytes());
        hasher.update(pair.packets_sent.to_be_bytes());
        hasher.update(pair.packets_received.to_be_bytes());
        hasher.update(pair.bytes_sent.to_be_bytes());
        hasher.update(pair.bytes_received.to_be_bytes());
        let proof_sha256: [u8; 32] = hasher.finalize().into();
        let live = LiveAllocationEvidence::from_broker_roundtrip(
            proof_sha256,
            u64::from(pair.packets_sent),
            u64::from(pair.packets_received),
            pair.bytes_sent,
            pair.bytes_received,
        )
        .ok_or(ProcessError::ProbeInvalid)?;
        Ok(AllocationProbeEvidence::Live(live))
    }
}

#[derive(PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        use ring::digest::{digest, SHA256};
        let value = digest(&SHA256, self.0.as_slice());
        let mut result = [0u8; 32];
        result.copy_from_slice(value.as_ref());
        result
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.0.to_vec())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(REDACTED)")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("REDACTED")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProcessError {
    #[error("relay_process_unavailable")]
    Unavailable,
    #[error("relay_probe_unavailable")]
    ProbeUnavailable,
    #[error("relay_probe_invalid")]
    ProbeInvalid,
    #[error("relay_secret_apply_failed")]
    SecretApplyFailed,
}

impl ProcessError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unavailable => "relay_process_unavailable",
            Self::ProbeUnavailable => "relay_probe_unavailable",
            Self::ProbeInvalid => "relay_probe_invalid",
            Self::SecretApplyFailed => "relay_secret_apply_failed",
        }
    }
}

#[async_trait]
pub trait CoturnRuntimePort: Send + Sync {
    async fn snapshot(&self) -> Result<CoturnSnapshot, ProcessError>;
    async fn restart(&self) -> Result<(), ProcessError>;
    async fn apply_secret(&self, version: u64, secret: SecretBytes) -> Result<(), ProcessError>;
    async fn set_draining(&self, draining: bool) -> Result<(), ProcessError>;
    async fn probe_local_allocation(&self) -> Result<AllocationProbeEvidence, ProcessError>;
}
