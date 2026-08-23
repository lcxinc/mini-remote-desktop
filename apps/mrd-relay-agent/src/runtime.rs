use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU8, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::rand::{SecureRandom as _, SystemRandom};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    backend::{
        BackendError, EnrollmentRequest, HeartbeatPayload, NodeDirective,
        RelayBackendClientFactoryPort, RelayBackendPort, RelayHealth, SignedHeartbeat,
        SwappableRelayBackend,
    },
    identity::{CertificateState, IdentityFsPort},
    metrics::MetricsPort,
    process::{
        AllocationProbeEvidence, CoturnRuntimePort, LocalAllocationProbePort, ProcessError,
        ProcessHealth, SecretBytes,
    },
};

const HEARTBEAT_INTERVAL_MS: u64 = 5_000;
const MAX_RESTART_ATTEMPTS: u8 = 3;
const MAX_BACKEND_BACKOFF_MS: u64 = 30_000;

#[allow(clippy::too_many_arguments)]
fn generate_pending_rotation(
    identity_epoch: u64,
    directive_sequence: u64,
    secret_version: u64,
    not_before_unix_seconds: i64,
    old_credential_deadline_unix_seconds: i64,
    rotation_challenge: String,
    observed_wall_unix_seconds: i64,
    observed_monotonic_ms: u64,
) -> Result<PendingSecretRotation, RuntimeError> {
    let random = SystemRandom::new();
    let mut rotation_id = [0u8; 24];
    let mut secret = Zeroizing::new([0u8; 32]);
    random
        .fill(&mut rotation_id)
        .map_err(|_| RuntimeError::StateInvalid)?;
    random
        .fill(secret.as_mut())
        .map_err(|_| RuntimeError::StateInvalid)?;
    Ok(PendingSecretRotation {
        identity_epoch,
        directive_sequence,
        rotation_id: URL_SAFE_NO_PAD.encode(rotation_id),
        secret_version,
        turn_rest_secret: PersistentSecret::new(URL_SAFE_NO_PAD.encode(secret.as_ref())),
        not_before_unix_seconds,
        old_credential_deadline_unix_seconds,
        rotation_challenge,
        observed_wall_unix_seconds,
        observed_monotonic_ms,
        phase: SecretRotationPhase::Intent,
        probe_evidence_sha256: None,
    })
}

fn safe_window_elapsed(pending: &PendingSecretRotation, clock: &dyn ClockPort) -> bool {
    let remaining_seconds = pending
        .old_credential_deadline_unix_seconds
        .saturating_sub(pending.observed_wall_unix_seconds)
        .max(0) as u64;
    let deadline_monotonic_ms = pending
        .observed_monotonic_ms
        .saturating_add(remaining_seconds.saturating_mul(1_000));
    clock.monotonic_ms() >= deadline_monotonic_ms
}

fn pending_secret_digest(pending: &PendingSecretRotation) -> Result<[u8; 32], RuntimeError> {
    use ring::digest::{digest, SHA256};

    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(pending.turn_rest_secret.expose())
            .map_err(|_| RuntimeError::StateInvalid)?,
    );
    if decoded.len() != 32 {
        return Err(RuntimeError::StateInvalid);
    }
    let value = digest(&SHA256, &decoded);
    let mut output = [0u8; 32];
    output.copy_from_slice(value.as_ref());
    Ok(output)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostPressureSnapshot {
    pub packet_loss_bps: u16,
    pub cpu_usage_bps: u16,
    pub memory_usage_bps: u16,
    pub measured_rtt_ms: Option<u32>,
    pub recent_failure_bps: u16,
}

pub struct HeartbeatSampler<M: MetricsPort> {
    metrics: Arc<M>,
    boot_id: String,
    endpoints: Vec<String>,
    max_allocations: u32,
    max_egress_bps: u64,
}

impl<M: MetricsPort> HeartbeatSampler<M> {
    pub fn new(
        metrics: Arc<M>,
        endpoints: Vec<String>,
        max_allocations: u32,
        max_egress_bps: u64,
    ) -> Result<Self, RuntimeError> {
        let mut boot_id = [0u8; 16];
        SystemRandom::new()
            .fill(&mut boot_id)
            .map_err(|_| RuntimeError::StateInvalid)?;
        let sampler = Self {
            metrics,
            boot_id: URL_SAFE_NO_PAD.encode(boot_id),
            endpoints,
            max_allocations,
            max_egress_bps,
        };
        if sampler.endpoints.is_empty()
            || sampler.endpoints.len() > 4
            || sampler.max_allocations == 0
            || sampler.max_egress_bps == 0
        {
            return Err(RuntimeError::StateInvalid);
        }
        Ok(sampler)
    }

    pub async fn sample(
        &self,
        identity_epoch: u64,
        process_health: ProcessHealth,
        listener_health: ProcessHealth,
        probe_health: RelayHealth,
        pressure: HostPressureSnapshot,
        applied_secret_version: u64,
    ) -> Result<HeartbeatPayload, RuntimeError> {
        let metrics = self
            .metrics
            .collect()
            .await
            .map_err(|_| RuntimeError::StateInvalid)?;
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| RuntimeError::StateInvalid)?;
        let payload = HeartbeatPayload {
            identity_epoch,
            boot_id: self.boot_id.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            process_health: process_health.into(),
            listener_health: listener_health.into(),
            probe_health,
            active_allocations: metrics.active_allocations,
            current_ingress_bps: metrics.current_ingress_bps,
            current_egress_bps: metrics.current_egress_bps,
            max_allocations: self.max_allocations,
            max_egress_bps: self.max_egress_bps,
            packet_loss_bps: pressure.packet_loss_bps,
            cpu_usage_bps: pressure.cpu_usage_bps,
            memory_usage_bps: pressure.memory_usage_bps,
            measured_rtt_ms: pressure.measured_rtt_ms,
            recent_failure_bps: pressure.recent_failure_bps,
            endpoints: self.endpoints.clone(),
            applied_secret_version,
        };
        payload.validate().map_err(RuntimeError::Backend)?;
        Ok(payload)
    }
}

impl From<ProcessHealth> for RelayHealth {
    fn from(value: ProcessHealth) -> Self {
        match value {
            ProcessHealth::Healthy => Self::Healthy,
            ProcessHealth::Degraded => Self::Degraded,
            ProcessHealth::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityMaintenance {
    PendingApproval,
    Activated { identity_epoch: u64 },
    Ready { identity_epoch: u64 },
    Renewed { identity_epoch: u64 },
}

pub struct IdentityLifecycle {
    mtls_installed: bool,
    renewal_window: Duration,
}

#[derive(Clone, Default)]
pub struct SharedRelayHealth {
    process: Arc<AtomicU8>,
    listener: Arc<AtomicU8>,
    probe: Arc<AtomicU8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayHealthSnapshot {
    pub process: ProcessHealth,
    pub listener: ProcessHealth,
    pub probe: RelayHealth,
}

impl SharedRelayHealth {
    fn decode_process(encoded: u8) -> ProcessHealth {
        match encoded {
            2 => ProcessHealth::Healthy,
            1 => ProcessHealth::Degraded,
            _ => ProcessHealth::Failed,
        }
    }

    fn encode_process(health: ProcessHealth) -> u8 {
        match health {
            ProcessHealth::Healthy => 2,
            ProcessHealth::Degraded => 1,
            ProcessHealth::Failed => 0,
        }
    }

    fn encode_probe(health: RelayHealth) -> u8 {
        match health {
            RelayHealth::Healthy => 3,
            RelayHealth::Degraded => 2,
            RelayHealth::Failed => 1,
            RelayHealth::NonEvidence => 0,
        }
    }

    fn decode_probe(encoded: u8) -> RelayHealth {
        match encoded {
            3 => RelayHealth::Healthy,
            2 => RelayHealth::Degraded,
            1 => RelayHealth::Failed,
            _ => RelayHealth::NonEvidence,
        }
    }

    pub fn snapshot(&self) -> RelayHealthSnapshot {
        RelayHealthSnapshot {
            process: Self::decode_process(self.process.load(Ordering::Acquire)),
            listener: Self::decode_process(self.listener.load(Ordering::Acquire)),
            probe: Self::decode_probe(self.probe.load(Ordering::Acquire)),
        }
    }

    pub fn set(&self, snapshot: RelayHealthSnapshot) {
        self.process
            .store(Self::encode_process(snapshot.process), Ordering::Release);
        self.listener
            .store(Self::encode_process(snapshot.listener), Ordering::Release);
        self.probe
            .store(Self::encode_probe(snapshot.probe), Ordering::Release);
    }
}

impl IdentityLifecycle {
    pub fn new(renewal_window: Duration) -> Result<Self, RuntimeError> {
        if renewal_window.is_zero() || renewal_window > Duration::from_secs(7 * 24 * 60 * 60) {
            return Err(RuntimeError::StateInvalid);
        }
        Ok(Self {
            mtls_installed: false,
            renewal_window,
        })
    }

    pub async fn maintain_once<F: IdentityFsPort>(
        &mut self,
        identity: &mut CertificateState<F>,
        enrollment_backend: &dyn RelayBackendPort,
        slot: &SwappableRelayBackend,
        factory: &dyn RelayBackendClientFactoryPort,
        enrollment: Option<EnrollmentRequest>,
        now_unix_seconds: i64,
    ) -> Result<IdentityMaintenance, RuntimeError> {
        if identity.active_certificate().is_none() {
            if !identity.has_pending_enrollment() {
                identity
                    .enroll(
                        enrollment_backend,
                        enrollment.ok_or(RuntimeError::EnrollmentMissing)?,
                    )
                    .await?;
            }
            if !identity.pickup(enrollment_backend).await? {
                return Ok(IdentityMaintenance::PendingApproval);
            }
            identity.install_active_backend(factory, slot)?;
            self.mtls_installed = true;
            return Ok(IdentityMaintenance::Activated {
                identity_epoch: identity.identity_epoch(),
            });
        }
        if !self.mtls_installed {
            identity.install_active_backend(factory, slot)?;
            self.mtls_installed = true;
        }
        let certificate = identity
            .active_certificate()
            .ok_or(RuntimeError::EnrollmentMissing)?;
        let renewal_due_at = certificate
            .expires_at_unix_seconds
            .saturating_sub(i64::try_from(self.renewal_window.as_secs()).unwrap_or(i64::MAX));
        if now_unix_seconds >= renewal_due_at {
            let renewal_id = identity
                .pending_renewal_id()
                .map(str::to_owned)
                .unwrap_or(generate_rotation_identifier()?);
            identity
                .renew_and_swap(slot, &renewal_id, now_unix_seconds, factory, slot)
                .await?;
            return Ok(IdentityMaintenance::Renewed {
                identity_epoch: identity.identity_epoch(),
            });
        }
        Ok(IdentityMaintenance::Ready {
            identity_epoch: identity.identity_epoch(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn backend_worker_once<F, C, K, S, J, M>(
    lifecycle: &mut IdentityLifecycle,
    identity: &mut CertificateState<F>,
    enrollment_backend: &dyn RelayBackendPort,
    slot: &SwappableRelayBackend,
    factory: &dyn RelayBackendClientFactoryPort,
    enrollment: Option<EnrollmentRequest>,
    runtime: &mut AgentRuntime<SwappableRelayBackend, C, K, S, J>,
    sampler: &HeartbeatSampler<M>,
    process_health: ProcessHealth,
    listener_health: ProcessHealth,
    probe_health: RelayHealth,
    pressure: HostPressureSnapshot,
) -> Result<IdentityMaintenance, RuntimeError>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
{
    let maintenance = lifecycle
        .maintain_once(
            identity,
            enrollment_backend,
            slot,
            factory,
            enrollment,
            runtime.clock.unix_seconds(),
        )
        .await?;
    if maintenance == IdentityMaintenance::PendingApproval {
        return Ok(maintenance);
    }
    if let IdentityMaintenance::Renewed { identity_epoch } = maintenance {
        runtime.activate_identity_epoch(identity_epoch)?;
    }
    runtime
        .heartbeat_cycle(
            identity,
            sampler,
            process_health,
            listener_health,
            probe_health,
            pressure,
        )
        .await?;
    // Directives are not merely reported to a caller: the production worker
    // drives the crash-recoverable secret transaction on every heartbeat.
    // A future safety deadline returns `false` and is revisited next cycle.
    let _ = runtime.advance_secret_rotation(identity).await?;
    Ok(maintenance)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_backend_worker<F, C, K, S, J, M>(
    lifecycle: &mut IdentityLifecycle,
    identity: &mut CertificateState<F>,
    enrollment_backend: &dyn RelayBackendPort,
    slot: &SwappableRelayBackend,
    factory: &dyn RelayBackendClientFactoryPort,
    enrollment: Option<EnrollmentRequest>,
    runtime: &mut AgentRuntime<SwappableRelayBackend, C, K, S, J>,
    sampler: &HeartbeatSampler<M>,
    supervisor_health: &SharedRelayHealth,
    pressure: HostPressureSnapshot,
) -> Result<(), RuntimeError>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
{
    let mut backend_attempt = 0u32;
    loop {
        let health = supervisor_health.snapshot();
        match backend_worker_once(
            lifecycle,
            identity,
            enrollment_backend,
            slot,
            factory,
            enrollment.clone(),
            runtime,
            sampler,
            health.process,
            health.listener,
            health.probe,
            pressure,
        )
        .await
        {
            Ok(IdentityMaintenance::PendingApproval) => {
                backend_attempt = 0;
                runtime.sleeper.sleep(Duration::from_secs(5)).await;
            }
            Ok(_) => backend_attempt = 0,
            Err(RuntimeError::Backend(BackendError::Unavailable)) => {
                let delay = runtime.backend_retry_delay(backend_attempt);
                backend_attempt = backend_attempt.saturating_add(1);
                runtime.sleeper.sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
}

pub struct CoturnSupervisor<C, S, P>
where
    C: CoturnRuntimePort,
    S: SleeperPort,
    P: LocalAllocationProbePort,
{
    coturn: Arc<C>,
    sleeper: Arc<S>,
    probe: Arc<P>,
    shared_health: SharedRelayHealth,
    restart_attempts: u8,
}

impl<C, S, P> CoturnSupervisor<C, S, P>
where
    C: CoturnRuntimePort,
    S: SleeperPort,
    P: LocalAllocationProbePort,
{
    pub fn new(
        coturn: Arc<C>,
        sleeper: Arc<S>,
        probe: Arc<P>,
        shared_health: SharedRelayHealth,
    ) -> Self {
        Self {
            coturn,
            sleeper,
            probe,
            shared_health,
            restart_attempts: 0,
        }
    }

    pub fn restart_attempts(&self) -> u8 {
        self.restart_attempts
    }

    pub async fn supervise_once(&mut self) -> Result<(), RuntimeError> {
        let process_health = self
            .coturn
            .snapshot()
            .await
            .map(|snapshot| snapshot.health)
            .unwrap_or(ProcessHealth::Failed);
        let probe_health = if process_health == ProcessHealth::Failed {
            RelayHealth::Failed
        } else {
            match self.probe.probe().await {
                Ok(AllocationProbeEvidence::Live(_)) => RelayHealth::Healthy,
                Ok(AllocationProbeEvidence::NonEvidence) => RelayHealth::NonEvidence,
                Err(_) => RelayHealth::Failed,
            }
        };
        let verified_healthy =
            process_health == ProcessHealth::Healthy && probe_health == RelayHealth::Healthy;
        self.shared_health.set(RelayHealthSnapshot {
            process: process_health,
            listener: process_health,
            probe: probe_health,
        });
        if verified_healthy {
            self.restart_attempts = 0;
        } else if self.restart_attempts < MAX_RESTART_ATTEMPTS {
            let delay_seconds = 1u64 << self.restart_attempts;
            self.sleeper
                .sleep(Duration::from_secs(delay_seconds.min(4)))
                .await;
            self.restart_attempts = self.restart_attempts.saturating_add(1);
            let _ = self.coturn.restart().await;
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), RuntimeError> {
        loop {
            self.supervise_once().await?;
            self.sleeper.sleep(Duration::from_secs(1)).await;
            // An injected sleeper is allowed to complete immediately. Yielding
            // keeps an unhealthy local process from starving the backend task
            // in deterministic tests or embedders with a virtual clock.
            tokio::task::yield_now().await;
        }
    }
}

pub struct PortableRelayAgent<F, C, K, S, J, M, P>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
    P: LocalAllocationProbePort,
{
    lifecycle: IdentityLifecycle,
    identity: CertificateState<F>,
    enrollment_backend: Arc<dyn RelayBackendPort>,
    slot: Arc<SwappableRelayBackend>,
    factory: Arc<dyn RelayBackendClientFactoryPort>,
    enrollment: Option<EnrollmentRequest>,
    runtime: AgentRuntime<SwappableRelayBackend, C, K, S, J>,
    sampler: HeartbeatSampler<M>,
    shared_health: SharedRelayHealth,
    supervisor: CoturnSupervisor<C, S, P>,
    pressure: HostPressureSnapshot,
}

pub struct PortableRelayAgentDeps<F, C, K, S, J, M, P>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
    P: LocalAllocationProbePort,
{
    pub identity: CertificateState<F>,
    pub enrollment_backend: Arc<dyn RelayBackendPort>,
    pub initial_backend: Arc<dyn RelayBackendPort>,
    pub factory: Arc<dyn RelayBackendClientFactoryPort>,
    pub coturn: Arc<C>,
    pub clock: Arc<K>,
    pub sleeper: Arc<S>,
    pub jitter: Arc<J>,
    pub state_store: Arc<dyn RuntimeStateStorePort>,
    pub metrics: Arc<M>,
    pub probe: Arc<P>,
}

pub struct PortableRelayAgentConfig {
    pub enrollment: Option<EnrollmentRequest>,
    pub endpoints: Vec<String>,
    pub max_allocations: u32,
    pub max_egress_bps: u64,
    pub pressure: HostPressureSnapshot,
    pub renewal_window: Duration,
}

impl<F, C, K, S, J, M, P> PortableRelayAgent<F, C, K, S, J, M, P>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
    P: LocalAllocationProbePort,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: CertificateState<F>,
        enrollment_backend: Arc<dyn RelayBackendPort>,
        initial_backend: Arc<dyn RelayBackendPort>,
        factory: Arc<dyn RelayBackendClientFactoryPort>,
        enrollment: Option<EnrollmentRequest>,
        coturn: Arc<C>,
        clock: Arc<K>,
        sleeper: Arc<S>,
        jitter: Arc<J>,
        state_store: Arc<dyn RuntimeStateStorePort>,
        metrics: Arc<M>,
        probe: Arc<P>,
        endpoints: Vec<String>,
        max_allocations: u32,
        max_egress_bps: u64,
        pressure: HostPressureSnapshot,
        renewal_window: Duration,
    ) -> Result<Self, RuntimeError> {
        let shared_health = SharedRelayHealth::default();
        let slot = Arc::new(SwappableRelayBackend::new(initial_backend));
        let runtime = AgentRuntime::new_with_state_store(
            slot.clone(),
            coturn.clone(),
            clock,
            sleeper.clone(),
            jitter,
            state_store,
        )?;
        let sampler = HeartbeatSampler::new(metrics, endpoints, max_allocations, max_egress_bps)?;
        let supervisor = CoturnSupervisor::new(coturn, sleeper, probe, shared_health.clone());
        Ok(Self {
            lifecycle: IdentityLifecycle::new(renewal_window)?,
            identity,
            enrollment_backend,
            slot,
            factory,
            enrollment,
            runtime,
            sampler,
            shared_health,
            supervisor,
            pressure,
        })
    }

    pub async fn run(&mut self) -> Result<(), RuntimeError> {
        tokio::try_join!(
            run_backend_worker(
                &mut self.lifecycle,
                &mut self.identity,
                self.enrollment_backend.as_ref(),
                self.slot.as_ref(),
                self.factory.as_ref(),
                self.enrollment.clone(),
                &mut self.runtime,
                &self.sampler,
                &self.shared_health,
                self.pressure,
            ),
            self.supervisor.run(),
        )?;
        Ok(())
    }
}

pub async fn run_agent<F, C, K, S, J, M, P>(
    dependencies: PortableRelayAgentDeps<F, C, K, S, J, M, P>,
    config: PortableRelayAgentConfig,
) -> Result<(), RuntimeError>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
    P: LocalAllocationProbePort,
{
    let mut agent = PortableRelayAgent::new(
        dependencies.identity,
        dependencies.enrollment_backend,
        dependencies.initial_backend,
        dependencies.factory,
        config.enrollment,
        dependencies.coturn,
        dependencies.clock,
        dependencies.sleeper,
        dependencies.jitter,
        dependencies.state_store,
        dependencies.metrics,
        dependencies.probe,
        config.endpoints,
        config.max_allocations,
        config.max_egress_bps,
        config.pressure,
        config.renewal_window,
    )?;
    agent.run().await
}

fn generate_rotation_identifier() -> Result<String, RuntimeError> {
    let mut identifier = [0u8; 24];
    SystemRandom::new()
        .fill(&mut identifier)
        .map_err(|_| RuntimeError::StateInvalid)?;
    Ok(URL_SAFE_NO_PAD.encode(identifier))
}

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

const MAX_RUNTIME_STATE_BYTES: u64 = 64 * 1024;

const fn initial_identity_epoch() -> u64 {
    1
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretRotationPhase {
    Intent,
    Uploaded,
    Applied,
    Probed,
}

#[derive(Serialize, Deserialize)]
pub struct PersistentSecret(String);

impl PersistentSecret {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl Clone for PersistentSecret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for PersistentSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PersistentSecret {}

impl std::fmt::Debug for PersistentSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PersistentSecret(REDACTED)")
    }
}

impl Drop for PersistentSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingSecretRotation {
    pub identity_epoch: u64,
    pub directive_sequence: u64,
    pub rotation_id: String,
    pub secret_version: u64,
    pub turn_rest_secret: PersistentSecret,
    pub not_before_unix_seconds: i64,
    pub old_credential_deadline_unix_seconds: i64,
    pub rotation_challenge: String,
    pub observed_wall_unix_seconds: i64,
    pub observed_monotonic_ms: u64,
    pub phase: SecretRotationPhase,
    pub probe_evidence_sha256: Option<[u8; 32]>,
}

impl std::fmt::Debug for PendingSecretRotation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingSecretRotation")
            .field("identity_epoch", &self.identity_epoch)
            .field("directive_sequence", &self.directive_sequence)
            .field("rotation_id", &self.rotation_id)
            .field("secret_version", &self.secret_version)
            .field("turn_rest_secret", &"REDACTED")
            .field("not_before_unix_seconds", &self.not_before_unix_seconds)
            .field(
                "old_credential_deadline_unix_seconds",
                &self.old_credential_deadline_unix_seconds,
            )
            .field("rotation_challenge", &self.rotation_challenge)
            .field("phase", &self.phase)
            .field("probe_evidence_sha256", &self.probe_evidence_sha256)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStateSnapshot {
    #[serde(default = "initial_identity_epoch")]
    pub identity_epoch: u64,
    pub last_directive_sequence: u64,
    pub secret_version: u64,
    pub secret_digest: Option<[u8; 32]>,
    pub draining: bool,
    #[serde(default)]
    pub pending_rotation: Option<PendingSecretRotation>,
}

impl Default for RuntimeStateSnapshot {
    fn default() -> Self {
        Self {
            identity_epoch: initial_identity_epoch(),
            last_directive_sequence: 0,
            secret_version: 0,
            secret_digest: None,
            draining: false,
            pending_rotation: None,
        }
    }
}

impl std::fmt::Debug for RuntimeStateSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeStateSnapshot")
            .field("identity_epoch", &self.identity_epoch)
            .field("last_directive_sequence", &self.last_directive_sequence)
            .field("secret_version", &self.secret_version)
            .field("secret_digest", &self.secret_digest.map(|_| "REDACTED"))
            .field("draining", &self.draining)
            .field("pending_rotation", &self.pending_rotation)
            .finish()
    }
}

pub trait RuntimeStateStorePort: Send + Sync {
    fn load(&self) -> Result<RuntimeStateSnapshot, RuntimeError>;
    fn atomic_store(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError>;
}

pub struct StdRuntimeStateStore {
    path: PathBuf,
}

impl StdRuntimeStateStore {
    pub fn new(path: PathBuf) -> Result<Self, RuntimeError> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(RuntimeError::StateInvalid);
        }
        Ok(Self { path })
    }

    fn temporary_path(&self) -> PathBuf {
        self.path.with_extension(format!(
            "tmp-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }
}

impl RuntimeStateStorePort for StdRuntimeStateStore {
    fn load(&self) -> Result<RuntimeStateSnapshot, RuntimeError> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RuntimeStateSnapshot::default())
            }
            Err(_) => return Err(RuntimeError::StateIo),
        };
        if !metadata.is_file() || metadata.len() > MAX_RUNTIME_STATE_BYTES {
            return Err(RuntimeError::StateInvalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(RuntimeError::StateInvalid);
            }
        }
        let body = Zeroizing::new(fs::read(&self.path).map_err(|_| RuntimeError::StateIo)?);
        serde_json::from_slice(&body).map_err(|_| RuntimeError::StateInvalid)
    }

    fn atomic_store(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError> {
        let parent = self.path.parent().ok_or(RuntimeError::StateInvalid)?;
        fs::create_dir_all(parent).map_err(|_| RuntimeError::StateIo)?;
        let temporary = self.temporary_path();
        let body =
            Zeroizing::new(serde_json::to_vec(state).map_err(|_| RuntimeError::StateInvalid)?);
        if body.len() > MAX_RUNTIME_STATE_BYTES as usize {
            return Err(RuntimeError::StateInvalid);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| RuntimeError::StateIo)?;
        let result = (|| {
            file.write_all(&body).map_err(|_| RuntimeError::StateIo)?;
            file.sync_all().map_err(|_| RuntimeError::StateIo)?;
            atomic_replace_runtime_path(&temporary, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(not(windows))]
fn atomic_replace_runtime_path(from: &Path, to: &Path) -> Result<(), RuntimeError> {
    fs::rename(from, to).map_err(|_| RuntimeError::StateIo)?;
    fs::File::open(to.parent().ok_or(RuntimeError::StateInvalid)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RuntimeError::StateIo)
}

#[cfg(windows)]
fn atomic_replace_runtime_path(from: &Path, to: &Path) -> Result<(), RuntimeError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers are NUL-terminated and live through the call.
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(RuntimeError::StateIo)
    } else {
        Ok(())
    }
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
    identity_epoch: u64,
    last_directive_sequence: u64,
    secret_version: u64,
    secret_digest: Option<[u8; 32]>,
    draining: bool,
    pending_rotation: Option<PendingSecretRotation>,
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
        let mut state = state_store.load()?;
        if (state.secret_version == 0) != state.secret_digest.is_none() {
            return Err(RuntimeError::StateInvalid);
        }
        if let Some(pending) = state.pending_rotation.as_mut() {
            if pending.identity_epoch != state.identity_epoch
                || pending.secret_version <= state.secret_version
                || pending.old_credential_deadline_unix_seconds < pending.not_before_unix_seconds
                || URL_SAFE_NO_PAD
                    .decode(&pending.rotation_challenge)
                    .ok()
                    .filter(|decoded| decoded.len() == 32)
                    .is_none_or(|decoded| {
                        URL_SAFE_NO_PAD.encode(decoded) != pending.rotation_challenge
                    })
            {
                return Err(RuntimeError::StateInvalid);
            }
            // A monotonic origin is process-local. Rebase the persisted absolute
            // deadline at each restart using the injected wall clock.
            pending.observed_wall_unix_seconds = clock.unix_seconds();
            pending.observed_monotonic_ms = now;
            state_store.atomic_store(&state)?;
        }
        Ok(Self {
            backend,
            coturn,
            clock,
            sleeper,
            jitter,
            next_heartbeat_at_ms: now,
            identity_epoch: state.identity_epoch,
            last_directive_sequence: state.last_directive_sequence,
            secret_version: state.secret_version,
            secret_digest: state.secret_digest,
            draining: state.draining,
            pending_rotation: state.pending_rotation,
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

    pub async fn heartbeat_once(&mut self, heartbeat: SignedHeartbeat) -> Result<(), RuntimeError> {
        self.note_heartbeat_attempt();
        let directive = self
            .backend
            .heartbeat(heartbeat)
            .await
            .map_err(RuntimeError::Backend)?;
        self.apply_directive(directive).await
    }

    pub async fn heartbeat_cycle<F, M>(
        &mut self,
        identity: &mut CertificateState<F>,
        sampler: &HeartbeatSampler<M>,
        process_health: ProcessHealth,
        listener_health: ProcessHealth,
        probe_health: RelayHealth,
        pressure: HostPressureSnapshot,
    ) -> Result<(), RuntimeError>
    where
        F: IdentityFsPort,
        M: MetricsPort,
    {
        self.wait_until_next_heartbeat().await;
        let payload = sampler
            .sample(
                identity.identity_epoch(),
                process_health,
                listener_health,
                probe_health,
                pressure,
                self.secret_version,
            )
            .await?;
        let heartbeat = identity.sign_heartbeat(self.clock.unix_seconds(), payload)?;
        self.heartbeat_once(heartbeat).await
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
        if directive.identity_epoch != self.identity_epoch {
            return Err(RuntimeError::DirectiveReplay);
        }
        if directive.sequence <= self.last_directive_sequence {
            return Err(RuntimeError::DirectiveReplay);
        }
        if directive.secret_update.is_some() && !directive.desired.draining {
            return Err(RuntimeError::SecretUpdateUnsafe);
        }
        if directive.desired.secret_version < self.secret_version {
            return Err(RuntimeError::SecretVersionReplay);
        }
        let mut next_secret_version = self.secret_version;
        let mut next_secret_digest = self.secret_digest;
        let mut next_pending_rotation = self.pending_rotation.clone();
        if directive.desired.secret_version > self.secret_version && self.secret_version > 0 {
            if !directive.desired.draining {
                return Err(RuntimeError::SecretUpdateUnsafe);
            }
            let (Some(not_before), Some(deadline)) = (
                directive.desired.not_before_unix_seconds,
                directive.desired.old_credential_deadline_unix_seconds,
            ) else {
                return Err(RuntimeError::SecretUpdateUnsafe);
            };
            let Some(rotation_challenge) = directive.desired.rotation_challenge.clone() else {
                return Err(RuntimeError::SecretUpdateUnsafe);
            };
            if deadline < not_before {
                return Err(RuntimeError::SecretUpdateUnsafe);
            }
            match &next_pending_rotation {
                Some(pending)
                    if pending.identity_epoch != directive.identity_epoch
                        || pending.secret_version != directive.desired.secret_version =>
                {
                    return Err(RuntimeError::SecretVersionReplay)
                }
                Some(pending) if pending.rotation_challenge != rotation_challenge => {
                    return Err(RuntimeError::SecretVersionReplay)
                }
                Some(_) => {}
                None => {
                    next_pending_rotation = Some(generate_pending_rotation(
                        directive.identity_epoch,
                        directive.sequence,
                        directive.desired.secret_version,
                        not_before,
                        deadline,
                        rotation_challenge,
                        self.clock.unix_seconds(),
                        self.clock.monotonic_ms(),
                    )?);
                    // Persist secret intent before any drain or process side effect.
                    let intent = RuntimeStateSnapshot {
                        identity_epoch: self.identity_epoch,
                        last_directive_sequence: self.last_directive_sequence,
                        secret_version: self.secret_version,
                        secret_digest: self.secret_digest,
                        draining: self.draining,
                        pending_rotation: next_pending_rotation.clone(),
                    };
                    self.state_store.atomic_store(&intent)?;
                    self.pending_rotation = intent.pending_rotation;
                }
            }
        }
        if directive.desired.draining != self.draining {
            self.coturn
                .set_draining(directive.desired.draining)
                .await
                .map_err(RuntimeError::Process)?;
        }
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
        let next = RuntimeStateSnapshot {
            identity_epoch: self.identity_epoch,
            last_directive_sequence: directive.sequence,
            secret_version: next_secret_version,
            secret_digest: next_secret_digest,
            draining: directive.desired.draining,
            pending_rotation: next_pending_rotation,
        };
        self.state_store.atomic_store(&next)?;
        self.last_directive_sequence = next.last_directive_sequence;
        self.secret_version = next.secret_version;
        self.secret_digest = next.secret_digest;
        self.draining = next.draining;
        self.pending_rotation = next.pending_rotation;
        Ok(())
    }

    pub async fn advance_secret_rotation<F: IdentityFsPort>(
        &mut self,
        identity: &mut CertificateState<F>,
    ) -> Result<bool, RuntimeError> {
        let Some(mut pending) = self.pending_rotation.clone() else {
            return Ok(false);
        };
        if pending.identity_epoch != self.identity_epoch
            || identity.identity_epoch() != self.identity_epoch
        {
            return Err(RuntimeError::DirectiveReplay);
        }
        if !self.draining {
            return Err(RuntimeError::SecretUpdateUnsafe);
        }
        if pending.phase == SecretRotationPhase::Intent {
            let request = identity.prepare_secret_upload(
                self.clock.unix_seconds(),
                pending.rotation_id.clone(),
                pending.secret_version,
                SecretString::from(pending.turn_rest_secret.expose().to_owned()),
            )?;
            self.backend
                .upload_secret(request)
                .await
                .map_err(RuntimeError::Backend)?;
            pending.phase = SecretRotationPhase::Uploaded;
            self.persist_pending_rotation(pending.clone())?;
        }
        if !safe_window_elapsed(&pending, self.clock.as_ref()) {
            return Ok(false);
        }
        let snapshot = self
            .coturn
            .snapshot()
            .await
            .map_err(RuntimeError::Process)?;
        if snapshot.active_allocations != 0 {
            return Ok(false);
        }
        if pending.phase == SecretRotationPhase::Uploaded {
            let secret = URL_SAFE_NO_PAD
                .decode(pending.turn_rest_secret.expose())
                .map(SecretBytes::new)
                .map_err(|_| RuntimeError::StateInvalid)?;
            self.coturn
                .apply_secret(pending.secret_version, secret)
                .await
                .map_err(RuntimeError::Process)?;
            pending.phase = SecretRotationPhase::Applied;
            self.persist_pending_rotation(pending.clone())?;
        }
        if pending.phase == SecretRotationPhase::Applied {
            let evidence = self
                .coturn
                .probe_local_allocation()
                .await
                .map_err(RuntimeError::Process)?;
            let proof = evidence
                .proof_sha256()
                .ok_or(RuntimeError::Process(ProcessError::ProbeInvalid))?;
            pending.probe_evidence_sha256 = Some(proof);
            pending.phase = SecretRotationPhase::Probed;
            self.persist_pending_rotation(pending.clone())?;
        }
        let proof = pending
            .probe_evidence_sha256
            .ok_or(RuntimeError::StateInvalid)?;
        let pending_secret_digest = pending_secret_digest(&pending)?;
        let request = identity.prepare_secret_commit(
            self.clock.unix_seconds(),
            pending.rotation_id.clone(),
            pending.secret_version,
            pending.rotation_challenge.clone(),
            pending_secret_digest,
            proof,
            pending.turn_rest_secret.expose(),
        )?;
        self.backend
            .commit_secret(request)
            .await
            .map_err(RuntimeError::Backend)?;
        let digest = pending_secret_digest;
        let committed = RuntimeStateSnapshot {
            identity_epoch: self.identity_epoch,
            last_directive_sequence: self.last_directive_sequence,
            secret_version: pending.secret_version,
            secret_digest: Some(digest),
            draining: self.draining,
            pending_rotation: None,
        };
        self.state_store.atomic_store(&committed)?;
        self.secret_version = committed.secret_version;
        self.secret_digest = committed.secret_digest;
        self.pending_rotation = None;
        Ok(true)
    }

    fn persist_pending_rotation(
        &mut self,
        pending: PendingSecretRotation,
    ) -> Result<(), RuntimeError> {
        let state = RuntimeStateSnapshot {
            identity_epoch: self.identity_epoch,
            last_directive_sequence: self.last_directive_sequence,
            secret_version: self.secret_version,
            secret_digest: self.secret_digest,
            draining: self.draining,
            pending_rotation: Some(pending.clone()),
        };
        self.state_store.atomic_store(&state)?;
        self.pending_rotation = Some(pending);
        Ok(())
    }

    pub fn is_draining(&self) -> bool {
        self.draining
    }

    pub fn activate_identity_epoch(&mut self, identity_epoch: u64) -> Result<(), RuntimeError> {
        if identity_epoch != self.identity_epoch.saturating_add(1) {
            return Err(RuntimeError::DirectiveReplay);
        }
        let state = RuntimeStateSnapshot {
            identity_epoch,
            last_directive_sequence: 0,
            secret_version: self.secret_version,
            secret_digest: self.secret_digest,
            // Fail safe: renewal never silently resumes a draining node.
            draining: self.draining,
            pending_rotation: None,
        };
        self.state_store.atomic_store(&state)?;
        self.identity_epoch = identity_epoch;
        self.last_directive_sequence = 0;
        self.pending_rotation = None;
        Ok(())
    }
}

impl From<ProcessError> for RuntimeError {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}
