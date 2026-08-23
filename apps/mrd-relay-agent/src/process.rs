use std::{fmt, net::SocketAddr};

use async_trait::async_trait;
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
    pub health: ProcessHealth,
    pub active_allocations: u32,
    pub current_egress_bps: u64,
}

impl CoturnSnapshot {
    pub fn healthy(active_allocations: u32, current_egress_bps: u64) -> Self {
        Self {
            health: ProcessHealth::Healthy,
            active_allocations,
            current_egress_bps,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationProbeEvidence {
    pub allocated_relay_address: Option<SocketAddr>,
    pub permission_installed: bool,
    pub sent_nonce: [u8; 16],
    pub received_nonce: Option<[u8; 16]>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl AllocationProbeEvidence {
    pub fn is_real_roundtrip(&self) -> bool {
        self.allocated_relay_address.is_some()
            && self.permission_installed
            && self.received_nonce == Some(self.sent_nonce)
            && self.bytes_sent >= self.sent_nonce.len() as u64
            && self.bytes_received >= self.sent_nonce.len() as u64
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
