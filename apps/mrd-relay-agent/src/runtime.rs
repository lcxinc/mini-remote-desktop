use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    backend::{BackendError, NodeDirective, RelayBackendPort, SignedHeartbeat},
    process::{AllocationProbeEvidence, CoturnRuntimePort, ProcessError, ProcessHealth},
};

const HEARTBEAT_INTERVAL_MS: u64 = 5_000;
const MAX_RESTART_ATTEMPTS: u8 = 3;
const MAX_BACKEND_BACKOFF_MS: u64 = 30_000;

pub trait ClockPort: Send + Sync {
    fn monotonic_ms(&self) -> u64;
    fn unix_seconds(&self) -> i64;
}

#[async_trait]
pub trait SleeperPort: Send + Sync {
    async fn sleep(&self, duration: Duration);
}

pub trait JitterPort: Send + Sync {
    fn jitter_ms(&self, upper_exclusive: u64) -> u64;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStateSnapshot {
    pub last_directive_sequence: u64,
    pub secret_version: u64,
    pub secret_digest: Option<[u8; 32]>,
    pub draining: bool,
}

pub trait RuntimeStateStorePort: Send + Sync {
    fn load(&self) -> Result<RuntimeStateSnapshot, RuntimeError>;
    fn atomic_store(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError>;
}

#[derive(Default)]
struct VolatileRuntimeStateStore {
    state: Mutex<RuntimeStateSnapshot>,
}

impl RuntimeStateStorePort for VolatileRuntimeStateStore {
    fn load(&self) -> Result<RuntimeStateSnapshot, RuntimeError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| RuntimeError::StateIo)
    }

    fn atomic_store(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError> {
        *self.state.lock().map_err(|_| RuntimeError::StateIo)? = state.clone();
        Ok(())
    }
}

pub struct SystemClock {
    started: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockPort for SystemClock {
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn unix_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or(0)
    }
}

pub struct TokioSleeper;

#[async_trait]
impl SleeperPort for TokioSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

pub struct RandomJitter;

impl JitterPort for RandomJitter {
    fn jitter_ms(&self, upper_exclusive: u64) -> u64 {
        if upper_exclusive == 0 {
            0
        } else {
            rand::Rng::gen_range(&mut rand::thread_rng(), 0..upper_exclusive)
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("relay_identity_io")]
    IdentityIo,
    #[error("relay_identity_invalid")]
    IdentityInvalid,
    #[error("relay_identity_permissions_invalid")]
    IdentityPermissions,
    #[error("relay_enrollment_missing")]
    EnrollmentMissing,
    #[error("relay_renewal_conflict")]
    RenewalConflict,
    #[error("relay_certificate_invalid")]
    CertificateInvalid,
    #[error("{0}")]
    Backend(BackendError),
    #[error("{0}")]
    Process(ProcessError),
    #[error("relay_directive_replayed")]
    DirectiveReplay,
    #[error("relay_secret_version_replayed")]
    SecretVersionReplay,
    #[error("relay_secret_update_requires_drain")]
    SecretUpdateUnsafe,
    #[error("relay_runtime_state_io")]
    StateIo,
    #[error("relay_runtime_state_invalid")]
    StateInvalid,
}

impl PartialEq for RuntimeError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

pub struct AgentRuntime<B, C, K, S, J>
where
    B: RelayBackendPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
{
    backend: Arc<B>,
    coturn: Arc<C>,
    clock: Arc<K>,
    sleeper: Arc<S>,
    jitter: Arc<J>,
    next_heartbeat_at_ms: u64,
    restart_attempts: u8,
    process_health: ProcessHealth,
    last_directive_sequence: u64,
    secret_version: u64,
    secret_digest: Option<[u8; 32]>,
    draining: bool,
    state_store: Arc<dyn RuntimeStateStorePort>,
}

impl<B, C, K, S, J> AgentRuntime<B, C, K, S, J>
where
    B: RelayBackendPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
{
    pub fn new_volatile(
        backend: Arc<B>,
        coturn: Arc<C>,
        clock: Arc<K>,
        sleeper: Arc<S>,
        jitter: Arc<J>,
    ) -> Self {
        Self::new_with_state_store(
            backend,
            coturn,
            clock,
            sleeper,
            jitter,
            Arc::new(VolatileRuntimeStateStore::default()),
        )
        .expect("a new volatile runtime state is valid")
    }

    pub fn new_with_state_store(
        backend: Arc<B>,
        coturn: Arc<C>,
        clock: Arc<K>,
        sleeper: Arc<S>,
        jitter: Arc<J>,
        state_store: Arc<dyn RuntimeStateStorePort>,
    ) -> Result<Self, RuntimeError> {
        let now = clock.monotonic_ms();
        let state = state_store.load()?;
        if (state.secret_version == 0) != state.secret_digest.is_none() {
            return Err(RuntimeError::StateInvalid);
        }
        Ok(Self {
            backend,
            coturn,
            clock,
            sleeper,
            jitter,
            next_heartbeat_at_ms: now,
            restart_attempts: 0,
            process_health: ProcessHealth::Failed,
            last_directive_sequence: state.last_directive_sequence,
            secret_version: state.secret_version,
            secret_digest: state.secret_digest,
            draining: state.draining,
            state_store,
        })
    }

    pub fn delay_until_next_heartbeat(&self) -> Duration {
        Duration::from_millis(
            self.next_heartbeat_at_ms
                .saturating_sub(self.clock.monotonic_ms()),
        )
    }

    pub fn note_heartbeat_attempt(&mut self) {
        let now = self.clock.monotonic_ms();
        self.next_heartbeat_at_ms = self
            .next_heartbeat_at_ms
            .saturating_add(HEARTBEAT_INTERVAL_MS);
        if self.next_heartbeat_at_ms <= now {
            self.next_heartbeat_at_ms = now.saturating_add(HEARTBEAT_INTERVAL_MS);
        }
    }

    pub async fn wait_until_next_heartbeat(&self) {
        self.sleeper.sleep(self.delay_until_next_heartbeat()).await;
    }

    pub fn backend_retry_delay(&self, attempt: u32) -> Duration {
        let shift = attempt.min(20);
        let base = 250u64.saturating_mul(1u64 << shift);
        let bounded = base.min(MAX_BACKEND_BACKOFF_MS);
        let remaining = MAX_BACKEND_BACKOFF_MS.saturating_sub(bounded);
        let jitter_upper = remaining.min(bounded / 4).saturating_add(1);
        let jitter = self
            .jitter
            .jitter_ms(jitter_upper)
            .min(jitter_upper.saturating_sub(1));
        Duration::from_millis(bounded.saturating_add(jitter))
    }

    pub async fn supervise_coturn_once(&mut self) -> Result<(), RuntimeError> {
        let health = match self.coturn.snapshot().await {
            Ok(snapshot) => snapshot.health,
            Err(_) => ProcessHealth::Failed,
        };
        self.process_health = health;
        match health {
            ProcessHealth::Healthy | ProcessHealth::Degraded => {
                self.restart_attempts = 0;
            }
            ProcessHealth::Failed if self.restart_attempts < MAX_RESTART_ATTEMPTS => {
                self.restart_attempts += 1;
                let _ = self.coturn.restart().await;
            }
            ProcessHealth::Failed => {}
        }
        Ok(())
    }

    pub async fn heartbeat_once(&mut self, heartbeat: SignedHeartbeat) -> Result<(), RuntimeError> {
        self.note_heartbeat_attempt();
        let directive = self
            .backend
            .heartbeat(heartbeat)
            .await
            .map_err(RuntimeError::Backend)?;
        self.apply_directive(directive).await
    }

    pub async fn probe_coturn_once(&mut self) -> Result<AllocationProbeEvidence, RuntimeError> {
        let evidence = self
            .coturn
            .probe_local_allocation()
            .await
            .map_err(RuntimeError::Process)?;
        if !evidence.is_real_roundtrip() {
            return Err(RuntimeError::Process(ProcessError::ProbeInvalid));
        }
        Ok(evidence)
    }

    pub async fn apply_directive(&mut self, directive: NodeDirective) -> Result<(), RuntimeError> {
        if directive.sequence <= self.last_directive_sequence {
            return Err(RuntimeError::DirectiveReplay);
        }
        if directive.secret_update.is_some() && !directive.draining {
            return Err(RuntimeError::SecretUpdateUnsafe);
        }
        let mut next_secret_version = self.secret_version;
        let mut next_secret_digest = self.secret_digest;
        if let Some(update) = directive.secret_update {
            let update_digest = update.secret.digest();
            if update.version < self.secret_version
                || update.version == 0
                || (update.version == self.secret_version
                    && self.secret_digest != Some(update_digest))
            {
                return Err(RuntimeError::SecretVersionReplay);
            }
            if update.version > self.secret_version {
                self.coturn
                    .apply_secret(update.version, update.secret)
                    .await
                    .map_err(RuntimeError::Process)?;
                next_secret_version = update.version;
                next_secret_digest = Some(update_digest);
            }
        }
        if directive.draining != self.draining {
            self.coturn
                .set_draining(directive.draining)
                .await
                .map_err(RuntimeError::Process)?;
        }
        let next = RuntimeStateSnapshot {
            last_directive_sequence: directive.sequence,
            secret_version: next_secret_version,
            secret_digest: next_secret_digest,
            draining: directive.draining,
        };
        self.state_store.atomic_store(&next)?;
        self.last_directive_sequence = next.last_directive_sequence;
        self.secret_version = next.secret_version;
        self.secret_digest = next.secret_digest;
        self.draining = next.draining;
        Ok(())
    }

    pub fn process_health(&self) -> ProcessHealth {
        self.process_health
    }

    pub fn restart_attempts(&self) -> u8 {
        self.restart_attempts
    }

    pub fn is_draining(&self) -> bool {
        self.draining
    }
}

impl From<ProcessError> for RuntimeError {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}
