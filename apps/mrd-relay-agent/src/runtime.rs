use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
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
        RelayBackendClientFactoryPort, RelayBackendPort, RelayHealth, SecretRotationStatus,
        SignedHeartbeat, SwappableRelayBackend,
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
const BACKEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const LOCAL_SAMPLE_TIMEOUT: Duration = Duration::from_secs(2);

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
    let mut secret = Zeroizing::new([0u8; 32]);
    random
        .fill(secret.as_mut())
        .map_err(|_| RuntimeError::StateInvalid)?;
    Ok(PendingSecretRotation {
        identity_epoch,
        directive_sequence,
        rotation_id: generate_rotation_identifier()?,
        secret_version,
        turn_rest_secret: PersistentSecret::new(URL_SAFE_NO_PAD.encode(secret.as_ref())),
        not_before_unix_seconds,
        old_credential_deadline_unix_seconds,
        rotation_challenge,
        observed_wall_unix_seconds,
        observed_monotonic_ms,
        phase: SecretRotationPhase::Intent,
        probe_evidence_sha256: None,
        probe_generation: None,
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

fn commit_unknown_can_retry_exact(
    loaded_from_store: bool,
    pending_generation: Option<u64>,
    pending_secret_version: u64,
    current: &crate::process::CoturnSnapshot,
) -> bool {
    !loaded_from_store
        && pending_generation.is_some_and(|generation| generation != 0)
        && pending_generation == Some(current.generation)
        && current.applied_secret_version == pending_secret_version
        && current.health == ProcessHealth::Healthy
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
            .map_err(|_| RuntimeError::MetricsUnavailable)?;
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

#[derive(Clone)]
pub struct SharedRelayHealth {
    state: Arc<Mutex<SharedRelayHealthState>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayHealthSnapshot {
    pub process: ProcessHealth,
    pub listener: ProcessHealth,
    pub probe: RelayHealth,
}

#[derive(Clone, Copy)]
struct SharedRelayHealthState {
    snapshot: RelayHealthSnapshot,
    generation: u64,
    observed_monotonic_ms: u64,
    probe_in_progress: bool,
}

impl Default for SharedRelayHealth {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(SharedRelayHealthState {
                snapshot: RelayHealthSnapshot {
                    process: ProcessHealth::Failed,
                    listener: ProcessHealth::Failed,
                    probe: RelayHealth::NonEvidence,
                },
                generation: 0,
                observed_monotonic_ms: 0,
                probe_in_progress: false,
            })),
        }
    }
}

impl SharedRelayHealth {
    pub fn snapshot(&self) -> RelayHealthSnapshot {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot
    }

    pub fn set(&self, snapshot: RelayHealthSnapshot) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.snapshot = snapshot;
        state.probe_in_progress = false;
    }

    fn begin_probe(&self, process: ProcessHealth, generation: u64, observed_monotonic_ms: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = SharedRelayHealthState {
            snapshot: RelayHealthSnapshot {
                process,
                listener: process,
                probe: RelayHealth::NonEvidence,
            },
            generation,
            observed_monotonic_ms,
            probe_in_progress: true,
        };
    }

    fn finish_probe(
        &self,
        snapshot: RelayHealthSnapshot,
        generation: u64,
        observed_monotonic_ms: u64,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = SharedRelayHealthState {
            snapshot,
            generation,
            observed_monotonic_ms,
            probe_in_progress: false,
        };
    }

    pub fn snapshot_for_heartbeat(&self, now_monotonic_ms: u64) -> RelayHealthSnapshot {
        let state = *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.probe_in_progress
            || state.generation == 0
            || now_monotonic_ms.saturating_sub(state.observed_monotonic_ms)
                > HEARTBEAT_INTERVAL_MS.saturating_mul(2)
        {
            RelayHealthSnapshot {
                process: state.snapshot.process,
                listener: state.snapshot.listener,
                probe: RelayHealth::NonEvidence,
            }
        } else {
            state.snapshot
        }
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
        self.maintain_once_with_renewal_policy(
            identity,
            enrollment_backend,
            slot,
            factory,
            enrollment,
            now_unix_seconds,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn maintain_once_with_renewal_policy<F: IdentityFsPort>(
        &mut self,
        identity: &mut CertificateState<F>,
        enrollment_backend: &dyn RelayBackendPort,
        slot: &SwappableRelayBackend,
        factory: &dyn RelayBackendClientFactoryPort,
        enrollment: Option<EnrollmentRequest>,
        now_unix_seconds: i64,
        allow_renewal: bool,
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
        // A previously constructed reqwest/rustls client may keep a TLS
        // connection alive beyond the CA validity window. Revalidate the
        // complete persisted chain against the current wall clock before
        // every signed maintenance/heartbeat cycle, not only at load time.
        identity.validate_active_certificate_at(now_unix_seconds)?;
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
        if allow_renewal && now_unix_seconds >= renewal_due_at {
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
    K: ClockPort + 'static,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
{
    backend_worker_once_impl(
        lifecycle,
        identity,
        enrollment_backend,
        slot,
        factory,
        enrollment,
        runtime,
        sampler,
        process_health,
        listener_health,
        probe_health,
        pressure,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn backend_worker_once_impl<F, C, K, S, J, M>(
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
    wait_for_deadline: bool,
) -> Result<IdentityMaintenance, RuntimeError>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort + 'static,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
{
    runtime.validate_identity_secret_linkage(identity)?;
    if identity.active_certificate().is_none()
        && !identity.has_pending_enrollment()
        && runtime.bootstrap_secret.is_none()
    {
        if let Some(enrollment) = enrollment.as_ref() {
            runtime.stage_initial_secret(&enrollment.turn_rest_secret)?;
        }
    }
    // A certificate renewal changes identity_epoch and the server atomically
    // cancels epoch-scoped rotation state. Never renew while this process has
    // a durable secret transaction: Applied/Probed must retain their secret,
    // and CommitUnknown must reconcile its exact proof before either side can
    // move to a new epoch.
    let allow_renewal = !runtime.has_pending_rotation();
    let maintenance_future = lifecycle.maintain_once_with_renewal_policy(
        identity,
        enrollment_backend,
        slot,
        factory,
        enrollment,
        runtime.clock.unix_seconds(),
        allow_renewal,
    );
    let maintenance = if wait_for_deadline {
        maintenance_future.await?
    } else {
        match tokio::time::timeout(Duration::from_secs(1), maintenance_future).await {
            Ok(Ok(maintenance)) => maintenance,
            Ok(Err(error))
                if active_identity_can_heartbeat(
                    lifecycle,
                    identity,
                    runtime.clock.unix_seconds(),
                ) && retryable_identity_maintenance_error(&error) =>
            {
                IdentityMaintenance::Ready {
                    identity_epoch: identity.identity_epoch(),
                }
            }
            Ok(Err(error)) => return Err(error),
            Err(_)
                if active_identity_can_heartbeat(
                    lifecycle,
                    identity,
                    runtime.clock.unix_seconds(),
                ) =>
            {
                IdentityMaintenance::Ready {
                    identity_epoch: identity.identity_epoch(),
                }
            }
            Err(_) => return Err(RuntimeError::Backend(BackendError::Unavailable)),
        }
    };
    if maintenance == IdentityMaintenance::PendingApproval {
        return Ok(maintenance);
    }
    runtime.activate_staged_initial_secret().await?;
    if let IdentityMaintenance::Renewed { identity_epoch } = maintenance {
        runtime.activate_identity_epoch(identity_epoch)?;
    }
    if runtime.rotation_requires_reconcile_before_heartbeat() {
        let reconciled = if wait_for_deadline {
            runtime.advance_secret_rotation(identity).await?
        } else {
            tokio::time::timeout(
                LOCAL_SAMPLE_TIMEOUT,
                runtime.advance_secret_rotation(identity),
            )
            .await
            .map_err(|_| RuntimeError::Backend(BackendError::Unavailable))??
        };
        if !reconciled {
            return Err(RuntimeError::Backend(BackendError::Unavailable));
        }
    }
    if wait_for_deadline {
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
    } else {
        runtime
            .heartbeat_cycle_at_deadline(
                identity,
                sampler,
                process_health,
                listener_health,
                probe_health,
                pressure,
            )
            .await?;
    }
    // Directives are not merely reported to a caller: the production worker
    // drives the crash-recoverable secret transaction on every heartbeat.
    // A future safety deadline returns `false` and is revisited next cycle.
    if wait_for_deadline {
        let _ = runtime.advance_secret_rotation(identity).await?;
    } else {
        match tokio::time::timeout(
            LOCAL_SAMPLE_TIMEOUT,
            runtime.advance_secret_rotation(identity),
        )
        .await
        {
            Ok(result) => {
                let _ = result?;
            }
            Err(_) => return Err(RuntimeError::Process(ProcessError::ProbeUnavailable)),
        }
    }
    Ok(maintenance)
}

fn retryable_identity_maintenance_error(error: &RuntimeError) -> bool {
    matches!(
        error,
        RuntimeError::Backend(BackendError::Unavailable | BackendError::TlsInvalid)
            | RuntimeError::IdentityIo
            | RuntimeError::IdentityPermissions
    )
}

fn active_identity_can_heartbeat<F: IdentityFsPort>(
    lifecycle: &IdentityLifecycle,
    identity: &CertificateState<F>,
    now_unix_seconds: i64,
) -> bool {
    lifecycle.mtls_installed
        && identity
            .validate_active_certificate_at(now_unix_seconds)
            .is_ok()
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
    K: ClockPort + 'static,
    S: SleeperPort,
    J: JitterPort,
    M: MetricsPort,
{
    let mut backend_attempt = 0u32;
    loop {
        runtime.wait_until_next_heartbeat().await;
        let health = supervisor_health.snapshot_for_heartbeat(runtime.clock.monotonic_ms());
        match backend_worker_once_impl(
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
            false,
        )
        .await
        {
            Ok(IdentityMaintenance::PendingApproval) => {
                backend_attempt = 0;
                runtime.sleeper.sleep(Duration::from_secs(5)).await;
            }
            Ok(_) => backend_attempt = 0,
            Err(
                RuntimeError::Backend(BackendError::Unavailable)
                | RuntimeError::MetricsUnavailable
                | RuntimeError::Process(_),
            ) => {
                let delay = runtime.backend_retry_delay(backend_attempt);
                backend_attempt = backend_attempt.saturating_add(1);
                runtime.sleeper.sleep(delay).await;
                tokio::task::yield_now().await;
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
    clock: Arc<dyn ClockPort>,
    local_ready: Arc<AtomicBool>,
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
        Self::new_with_clock(
            coturn,
            sleeper,
            probe,
            shared_health,
            Arc::new(SystemClock::new()),
        )
    }

    pub fn new_with_clock(
        coturn: Arc<C>,
        sleeper: Arc<S>,
        probe: Arc<P>,
        shared_health: SharedRelayHealth,
        clock: Arc<dyn ClockPort>,
    ) -> Self {
        Self::new_with_clock_and_readiness(
            coturn,
            sleeper,
            probe,
            shared_health,
            clock,
            Arc::new(AtomicBool::new(true)),
        )
    }

    fn new_with_clock_and_readiness(
        coturn: Arc<C>,
        sleeper: Arc<S>,
        probe: Arc<P>,
        shared_health: SharedRelayHealth,
        clock: Arc<dyn ClockPort>,
        local_ready: Arc<AtomicBool>,
    ) -> Self {
        Self {
            coturn,
            sleeper,
            probe,
            clock,
            local_ready,
            shared_health,
            restart_attempts: 0,
        }
    }

    pub fn restart_attempts(&self) -> u8 {
        self.restart_attempts
    }

    pub async fn supervise_once(&mut self) -> Result<(), RuntimeError> {
        if !self.local_ready.load(Ordering::Acquire) {
            self.shared_health.finish_probe(
                RelayHealthSnapshot {
                    process: ProcessHealth::Failed,
                    listener: ProcessHealth::Failed,
                    probe: RelayHealth::NonEvidence,
                },
                0,
                self.clock.monotonic_ms(),
            );
            return Ok(());
        }
        let initial = self
            .coturn
            .snapshot()
            .await
            .unwrap_or(crate::process::CoturnSnapshot {
                generation: 0,
                applied_secret_version: 0,
                health: ProcessHealth::Failed,
                active_allocations: 0,
                current_egress_bps: 0,
            });
        let process_health = initial.health;
        // Invalidate the previous allocation proof before starting any new
        // asynchronous probe.  A slow or wedged probe must never leave an old
        // Healthy sample visible to the next heartbeat.
        self.shared_health.begin_probe(
            process_health,
            initial.generation,
            self.clock.monotonic_ms(),
        );
        let (process_health, generation, probe_health) =
            if process_health == ProcessHealth::Failed {
                (process_health, initial.generation, RelayHealth::Failed)
            } else {
                match self.probe.probe().await {
                    Ok(AllocationProbeEvidence::Live(_)) => {
                        let after = self.coturn.snapshot().await.unwrap_or(
                            crate::process::CoturnSnapshot {
                                generation: 0,
                                applied_secret_version: 0,
                                health: ProcessHealth::Failed,
                                active_allocations: 0,
                                current_egress_bps: 0,
                            },
                        );
                        let stable = initial.generation != 0
                            && after.generation == initial.generation
                            && after.applied_secret_version == initial.applied_secret_version
                            && after.health == ProcessHealth::Healthy;
                        (
                            after.health,
                            after.generation,
                            if stable {
                                RelayHealth::Healthy
                            } else {
                                RelayHealth::NonEvidence
                            },
                        )
                    }
                    Ok(AllocationProbeEvidence::NonEvidence) => {
                        (process_health, initial.generation, RelayHealth::NonEvidence)
                    }
                    Err(_) => (process_health, initial.generation, RelayHealth::Failed),
                }
            };
        let verified_healthy =
            process_health == ProcessHealth::Healthy && probe_health == RelayHealth::Healthy;
        self.shared_health.finish_probe(
            RelayHealthSnapshot {
                process: process_health,
                listener: process_health,
                probe: probe_health,
            },
            generation,
            self.clock.monotonic_ms(),
        );
        if verified_healthy {
            self.restart_attempts = 0;
        } else if process_health != ProcessHealth::Degraded
            && self.restart_attempts < MAX_RESTART_ATTEMPTS
        {
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
    pub backend_backoff_cap: Duration,
}

impl<F, C, K, S, J, M, P> PortableRelayAgent<F, C, K, S, J, M, P>
where
    F: IdentityFsPort,
    C: CoturnRuntimePort,
    K: ClockPort + 'static,
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
        backend_backoff_cap: Duration,
    ) -> Result<Self, RuntimeError> {
        let shared_health = SharedRelayHealth::default();
        let slot = Arc::new(SwappableRelayBackend::new(initial_backend));
        let mut runtime = AgentRuntime::new_with_state_store_and_backoff_cap(
            slot.clone(),
            coturn.clone(),
            clock,
            sleeper.clone(),
            jitter,
            state_store,
            backend_backoff_cap,
        )?;
        // The validated identity bundle is authoritative.  Finish the only
        // permitted cross-file crash window before any worker can sign or send
        // a request with stale epoch-local sequence or rotation state.
        runtime.reconcile_identity_epoch(identity.identity_epoch())?;
        runtime.validate_identity_secret_linkage(&identity)?;
        let sampler = HeartbeatSampler::new(metrics, endpoints, max_allocations, max_egress_bps)?;
        let supervisor = CoturnSupervisor::new_with_clock_and_readiness(
            coturn,
            sleeper,
            probe,
            shared_health.clone(),
            runtime.clock.clone(),
            runtime.local_ready.clone(),
        );
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
    K: ClockPort + 'static,
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
        config.backend_backoff_cap,
    )?;
    agent.run().await
}

fn generate_rotation_identifier() -> Result<String, RuntimeError> {
    let random = SystemRandom::new();
    generate_rotation_identifier_with(|identifier| random.fill(identifier).map_err(|_| ()))
}

fn generate_rotation_identifier_with(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<String, RuntimeError> {
    for _ in 0..128 {
        let mut identifier = Zeroizing::new([0u8; 24]);
        fill(identifier.as_mut()).map_err(|_| RuntimeError::StateInvalid)?;
        let encoded = URL_SAFE_NO_PAD.encode(identifier.as_ref());
        if encoded
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Ok(encoded);
        }
    }
    Err(RuntimeError::StateInvalid)
}

fn valid_persisted_operation_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
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
    CommitUnknown,
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
    #[serde(default)]
    pub probe_generation: Option<u64>,
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
            .field("rotation_challenge", &"REDACTED")
            .field("phase", &self.phase)
            .field("probe_evidence_sha256", &self.probe_evidence_sha256)
            .field("probe_generation", &self.probe_generation)
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
    #[serde(default)]
    pub bootstrap_secret: Option<PersistentSecret>,
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
            bootstrap_secret: None,
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
            .field(
                "bootstrap_secret",
                &self.bootstrap_secret.as_ref().map(|_| "REDACTED"),
            )
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
    #[error("relay_metrics_unavailable")]
    MetricsUnavailable,
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
    backend_backoff_cap_ms: u64,
    next_heartbeat_at_ms: u64,
    identity_epoch: u64,
    last_directive_sequence: u64,
    secret_version: u64,
    secret_digest: Option<[u8; 32]>,
    draining: bool,
    pending_rotation: Option<PendingSecretRotation>,
    bootstrap_secret: Option<PersistentSecret>,
    commit_unknown_loaded_from_store: bool,
    local_ready: Arc<AtomicBool>,
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
        Self::new_with_state_store_and_backoff_cap(
            backend,
            coturn,
            clock,
            sleeper,
            jitter,
            state_store,
            Duration::from_millis(MAX_BACKEND_BACKOFF_MS),
        )
    }

    pub fn new_with_state_store_and_backoff_cap(
        backend: Arc<B>,
        coturn: Arc<C>,
        clock: Arc<K>,
        sleeper: Arc<S>,
        jitter: Arc<J>,
        state_store: Arc<dyn RuntimeStateStorePort>,
        backend_backoff_cap: Duration,
    ) -> Result<Self, RuntimeError> {
        let backend_backoff_cap_ms = u64::try_from(backend_backoff_cap.as_millis())
            .map_err(|_| RuntimeError::StateInvalid)?;
        if !(1_000..=MAX_BACKEND_BACKOFF_MS).contains(&backend_backoff_cap_ms) {
            return Err(RuntimeError::StateInvalid);
        }
        let now = clock.monotonic_ms();
        let mut state = state_store.load()?;
        if (state.secret_version == 0) != state.secret_digest.is_none() {
            return Err(RuntimeError::StateInvalid);
        }
        if (state.secret_version > 0 && state.bootstrap_secret.is_some())
            || state.bootstrap_secret.as_ref().is_some_and(|secret| {
                URL_SAFE_NO_PAD
                    .decode(secret.expose())
                    .ok()
                    .filter(|decoded| decoded.len() == 32)
                    .is_none_or(|decoded| URL_SAFE_NO_PAD.encode(decoded) != secret.expose())
            })
        {
            return Err(RuntimeError::StateInvalid);
        }
        if let Some(pending) = state.pending_rotation.as_mut() {
            if pending.identity_epoch != state.identity_epoch
                || pending.secret_version <= state.secret_version
                || pending.old_credential_deadline_unix_seconds < pending.not_before_unix_seconds
                || (matches!(
                    pending.phase,
                    SecretRotationPhase::Probed | SecretRotationPhase::CommitUnknown
                ) != (pending.probe_evidence_sha256.is_some()
                    && pending.probe_generation.is_some_and(|value| value != 0)))
                || (!matches!(
                    pending.phase,
                    SecretRotationPhase::Probed | SecretRotationPhase::CommitUnknown
                ) && (pending.probe_evidence_sha256.is_some()
                    || pending.probe_generation.is_some()))
                || pending.directive_sequence == 0
                || !valid_persisted_operation_id(&pending.rotation_id)
                || URL_SAFE_NO_PAD
                    .decode(pending.turn_rest_secret.expose())
                    .ok()
                    .filter(|decoded| decoded.len() == 32)
                    .is_none_or(|decoded| {
                        URL_SAFE_NO_PAD.encode(decoded) != pending.turn_rest_secret.expose()
                    })
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
            if pending.phase == SecretRotationPhase::Probed {
                // A process/config generation cannot be trusted across an
                // agent restart. Keep the applied secret transaction, but
                // force a fresh production allocation proof before commit.
                pending.phase = SecretRotationPhase::Applied;
                pending.probe_evidence_sha256 = None;
                pending.probe_generation = None;
            }
            // A monotonic origin is process-local. Rebase the persisted absolute
            // deadline at each restart using the injected wall clock.
            pending.observed_wall_unix_seconds = clock.unix_seconds();
            pending.observed_monotonic_ms = now;
            state_store.atomic_store(&state)?;
        }
        let commit_unknown_loaded_from_store = state
            .pending_rotation
            .as_ref()
            .is_some_and(|pending| pending.phase == SecretRotationPhase::CommitUnknown);
        Ok(Self {
            backend,
            coturn,
            clock,
            sleeper,
            jitter,
            backend_backoff_cap_ms,
            next_heartbeat_at_ms: now,
            identity_epoch: state.identity_epoch,
            last_directive_sequence: state.last_directive_sequence,
            secret_version: state.secret_version,
            secret_digest: state.secret_digest,
            draining: state.draining,
            pending_rotation: state.pending_rotation,
            bootstrap_secret: state.bootstrap_secret,
            commit_unknown_loaded_from_store,
            local_ready: Arc::new(AtomicBool::new(state.secret_version > 0)),
            state_store,
        })
    }

    pub fn stage_initial_secret(&mut self, secret: &SecretString) -> Result<(), RuntimeError> {
        if self.secret_version > 0 {
            return Ok(());
        }
        let exposed = secrecy::ExposeSecret::expose_secret(secret);
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(exposed)
                .map_err(|_| RuntimeError::StateInvalid)?,
        );
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != exposed {
            return Err(RuntimeError::StateInvalid);
        }
        if let Some(existing) = self.bootstrap_secret.as_ref() {
            if existing.expose() != exposed {
                return Err(RuntimeError::StateInvalid);
            }
            return Ok(());
        }
        let staged = PersistentSecret::new(exposed.to_owned());
        let state = RuntimeStateSnapshot {
            identity_epoch: self.identity_epoch,
            last_directive_sequence: self.last_directive_sequence,
            secret_version: self.secret_version,
            secret_digest: self.secret_digest,
            bootstrap_secret: Some(staged.clone()),
            draining: self.draining,
            pending_rotation: self.pending_rotation.clone(),
        };
        self.state_store.atomic_store(&state)?;
        self.bootstrap_secret = Some(staged);
        Ok(())
    }

    fn validate_identity_secret_linkage<F: IdentityFsPort>(
        &self,
        identity: &CertificateState<F>,
    ) -> Result<(), RuntimeError> {
        let active = identity.active_certificate().is_some();
        if (active && self.secret_version == 0 && self.bootstrap_secret.is_none())
            || (!active && self.secret_version > 0)
            || (!active && identity.has_pending_enrollment() && self.bootstrap_secret.is_none())
        {
            return Err(RuntimeError::StateInvalid);
        }
        Ok(())
    }

    pub async fn activate_staged_initial_secret(&mut self) -> Result<(), RuntimeError> {
        if self.secret_version > 0 {
            return Ok(());
        }
        let staged = self
            .bootstrap_secret
            .as_ref()
            .ok_or(RuntimeError::StateInvalid)?;
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(staged.expose())
                .map_err(|_| RuntimeError::StateInvalid)?,
        );
        if decoded.len() != 32 {
            return Err(RuntimeError::StateInvalid);
        }
        let secret = SecretBytes::new(decoded.to_vec());
        let digest = secret.digest();
        self.coturn
            .apply_secret(1, secret)
            .await
            .map_err(RuntimeError::Process)?;
        let committed = RuntimeStateSnapshot {
            identity_epoch: self.identity_epoch,
            last_directive_sequence: self.last_directive_sequence,
            secret_version: 1,
            secret_digest: Some(digest),
            bootstrap_secret: None,
            draining: self.draining,
            pending_rotation: self.pending_rotation.clone(),
        };
        self.state_store.atomic_store(&committed)?;
        self.secret_version = 1;
        self.secret_digest = Some(digest);
        self.bootstrap_secret = None;
        self.local_ready.store(true, Ordering::Release);
        Ok(())
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
        let bounded = base.min(self.backend_backoff_cap_ms);
        let remaining = self.backend_backoff_cap_ms.saturating_sub(bounded);
        let jitter_upper = remaining.min(bounded / 4).saturating_add(1);
        let jitter = self
            .jitter
            .jitter_ms(jitter_upper)
            .min(jitter_upper.saturating_sub(1));
        Duration::from_millis(bounded.saturating_add(jitter))
    }

    pub async fn heartbeat_once(&mut self, heartbeat: SignedHeartbeat) -> Result<(), RuntimeError> {
        self.note_heartbeat_attempt();
        let directive =
            tokio::time::timeout(BACKEND_REQUEST_TIMEOUT, self.backend.heartbeat(heartbeat))
                .await
                .map_err(|_| RuntimeError::Backend(BackendError::Unavailable))?
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
        self.heartbeat_cycle_at_deadline(
            identity,
            sampler,
            process_health,
            listener_health,
            probe_health,
            pressure,
        )
        .await
    }

    async fn heartbeat_cycle_at_deadline<F, M>(
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
        let payload = tokio::time::timeout(
            LOCAL_SAMPLE_TIMEOUT,
            sampler.sample(
                identity.identity_epoch(),
                process_health,
                listener_health,
                probe_health,
                pressure,
                self.secret_version,
            ),
        )
        .await
        .map_err(|_| RuntimeError::MetricsUnavailable)??;
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
                        bootstrap_secret: self.bootstrap_secret.clone(),
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
            bootstrap_secret: self.bootstrap_secret.clone(),
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
        if pending.phase == SecretRotationPhase::CommitUnknown {
            let proof = pending
                .probe_evidence_sha256
                .ok_or(RuntimeError::StateInvalid)?;
            let digest = pending_secret_digest(&pending)?;
            let retry_exact = if self.commit_unknown_loaded_from_store {
                false
            } else {
                let current = self
                    .coturn
                    .snapshot()
                    .await
                    .map_err(RuntimeError::Process)?;
                commit_unknown_can_retry_exact(
                    false,
                    pending.probe_generation,
                    pending.secret_version,
                    &current,
                )
            };
            if retry_exact {
                // The response was lost in this process/config generation.
                // Require a fresh real roundtrip, but resend the exact durable
                // proof body; only authentication headers receive a fresh
                // timestamp/sequence.
                self.ensure_current_rotation_is_live(&pending, pending.probe_generation)
                    .await?;
                let request = identity.prepare_secret_commit(
                    self.clock.unix_seconds(),
                    pending.rotation_id.clone(),
                    pending.secret_version,
                    pending.rotation_challenge.clone(),
                    digest,
                    proof,
                    pending.turn_rest_secret.expose(),
                )?;
                self.backend
                    .commit_secret(request)
                    .await
                    .map_err(RuntimeError::Backend)?;
                return self.finalize_pending_rotation(&pending, digest);
            }
            let request = identity.prepare_secret_rotation_status(
                self.clock.unix_seconds(),
                pending.rotation_id.clone(),
                pending.secret_version,
                pending.rotation_challenge.clone(),
                digest,
                proof,
                pending.turn_rest_secret.expose(),
            )?;
            match self
                .backend
                .rotation_status(request)
                .await
                .map_err(RuntimeError::Backend)?
            {
                SecretRotationStatus::CommittedExact {
                    active_secret_version,
                } if active_secret_version == pending.secret_version => {
                    self.ensure_current_rotation_is_live(&pending, None).await?;
                    return self.finalize_pending_rotation(&pending, digest);
                }
                SecretRotationStatus::Pending {
                    active_secret_version,
                } if active_secret_version == self.secret_version => {
                    pending.phase = SecretRotationPhase::Applied;
                    pending.probe_evidence_sha256 = None;
                    pending.probe_generation = None;
                    self.persist_pending_rotation(pending.clone())?;
                    self.commit_unknown_loaded_from_store = false;
                }
                SecretRotationStatus::Unknown { .. }
                | SecretRotationStatus::CommittedExact { .. }
                | SecretRotationStatus::Pending { .. } => {
                    return Err(RuntimeError::Backend(BackendError::ProtocolInvalid));
                }
            }
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
            let before = self
                .coturn
                .snapshot()
                .await
                .map_err(RuntimeError::Process)?;
            let evidence = self
                .coturn
                .probe_local_allocation()
                .await
                .map_err(RuntimeError::Process)?;
            let after = self
                .coturn
                .snapshot()
                .await
                .map_err(RuntimeError::Process)?;
            let proof = evidence
                .proof_sha256()
                .ok_or(RuntimeError::Process(ProcessError::ProbeInvalid))?;
            if before.generation == 0
                || after.generation != before.generation
                || after.applied_secret_version != pending.secret_version
                || after.health != ProcessHealth::Healthy
            {
                return Err(RuntimeError::Process(ProcessError::ProbeInvalid));
            }
            pending.probe_evidence_sha256 = Some(proof);
            pending.probe_generation = Some(after.generation);
            pending.phase = SecretRotationPhase::Probed;
            self.persist_pending_rotation(pending.clone())?;
        }
        let current = self
            .coturn
            .snapshot()
            .await
            .map_err(RuntimeError::Process)?;
        if pending.probe_generation != Some(current.generation)
            || current.applied_secret_version != pending.secret_version
            || current.health != ProcessHealth::Healthy
        {
            pending.phase = SecretRotationPhase::Applied;
            pending.probe_evidence_sha256 = None;
            pending.probe_generation = None;
            self.persist_pending_rotation(pending)?;
            return Ok(false);
        }
        let proof = pending
            .probe_evidence_sha256
            .ok_or(RuntimeError::StateInvalid)?;
        let pending_secret_digest = pending_secret_digest(&pending)?;
        // Persist the ambiguous outcome state before sending. A crash or lost
        // response can then reconcile the exact proof without first
        // advertising the old active version in another heartbeat.
        pending.phase = SecretRotationPhase::CommitUnknown;
        self.persist_pending_rotation(pending.clone())?;
        self.commit_unknown_loaded_from_store = false;
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
        self.finalize_pending_rotation(&pending, pending_secret_digest)
    }

    async fn ensure_current_rotation_is_live(
        &self,
        pending: &PendingSecretRotation,
        expected_generation: Option<u64>,
    ) -> Result<(), RuntimeError> {
        let initial = self
            .coturn
            .snapshot()
            .await
            .map_err(RuntimeError::Process)?;
        if expected_generation.is_some_and(|generation| {
            initial.generation != generation
                || initial.applied_secret_version != pending.secret_version
                || initial.health != ProcessHealth::Healthy
        }) {
            return Err(RuntimeError::Process(ProcessError::ProbeInvalid));
        }
        if initial.applied_secret_version != pending.secret_version {
            let secret = URL_SAFE_NO_PAD
                .decode(pending.turn_rest_secret.expose())
                .map(SecretBytes::new)
                .map_err(|_| RuntimeError::StateInvalid)?;
            self.coturn
                .apply_secret(pending.secret_version, secret)
                .await
                .map_err(RuntimeError::Process)?;
        }
        let before = self
            .coturn
            .snapshot()
            .await
            .map_err(RuntimeError::Process)?;
        let evidence = self
            .coturn
            .probe_local_allocation()
            .await
            .map_err(RuntimeError::Process)?;
        let after = self
            .coturn
            .snapshot()
            .await
            .map_err(RuntimeError::Process)?;
        if evidence.proof_sha256().is_none()
            || before.generation == 0
            || expected_generation.is_some_and(|generation| before.generation != generation)
            || after.generation != before.generation
            || after.applied_secret_version != pending.secret_version
            || after.health != ProcessHealth::Healthy
        {
            return Err(RuntimeError::Process(ProcessError::ProbeInvalid));
        }
        Ok(())
    }

    fn finalize_pending_rotation(
        &mut self,
        pending: &PendingSecretRotation,
        digest: [u8; 32],
    ) -> Result<bool, RuntimeError> {
        let committed = RuntimeStateSnapshot {
            identity_epoch: self.identity_epoch,
            last_directive_sequence: self.last_directive_sequence,
            secret_version: pending.secret_version,
            secret_digest: Some(digest),
            bootstrap_secret: None,
            draining: self.draining,
            pending_rotation: None,
        };
        self.state_store.atomic_store(&committed)?;
        self.secret_version = committed.secret_version;
        self.secret_digest = committed.secret_digest;
        self.pending_rotation = None;
        self.commit_unknown_loaded_from_store = false;
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
            bootstrap_secret: self.bootstrap_secret.clone(),
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

    pub fn rotation_requires_reconcile_before_heartbeat(&self) -> bool {
        self.pending_rotation
            .as_ref()
            .is_some_and(|pending| pending.phase == SecretRotationPhase::CommitUnknown)
    }

    fn has_pending_rotation(&self) -> bool {
        self.pending_rotation.is_some()
    }

    pub fn activate_identity_epoch(&mut self, identity_epoch: u64) -> Result<(), RuntimeError> {
        self.reconcile_identity_epoch(identity_epoch)
    }

    /// Reconciles the independently persisted identity and runtime bundles.
    ///
    /// The identity bundle is authoritative after it has passed certificate
    /// validation.  A crash between promoting a renewed identity bundle and
    /// updating this runtime bundle may leave the latter exactly one epoch
    /// behind.  That single forward step is safe to finish idempotently; a
    /// rollback or a larger gap is evidence of corruption and fails closed.
    pub fn reconcile_identity_epoch(&mut self, identity_epoch: u64) -> Result<(), RuntimeError> {
        if identity_epoch == self.identity_epoch {
            return Ok(());
        }
        if identity_epoch != self.identity_epoch.saturating_add(1) {
            return Err(RuntimeError::StateInvalid);
        }
        if self.pending_rotation.is_some() {
            // A forward identity crash-window is only safe when there is no
            // epoch-scoped secret transaction to orphan. Applied or ambiguous
            // coturn state cannot be reconstructed by silently clearing it.
            return Err(RuntimeError::StateInvalid);
        }
        let state = RuntimeStateSnapshot {
            identity_epoch,
            last_directive_sequence: 0,
            secret_version: self.secret_version,
            secret_digest: self.secret_digest,
            bootstrap_secret: self.bootstrap_secret.clone(),
            // Fail safe: renewal never silently resumes a draining node.
            draining: self.draining,
            pending_rotation: None,
        };
        self.state_store.atomic_store(&state)?;
        self.identity_epoch = identity_epoch;
        self.last_directive_sequence = 0;
        self.pending_rotation = None;
        self.commit_unknown_loaded_from_store = false;
        Ok(())
    }
}

impl From<ProcessError> for RuntimeError {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}

#[cfg(test)]
mod identifier_tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa,
        KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };

    use super::{
        commit_unknown_can_retry_exact, generate_rotation_identifier_with, AgentRuntime, ClockPort,
        JitterPort, ProcessHealth, RuntimeError, RuntimeStateSnapshot, RuntimeStateStorePort,
        SleeperPort,
    };
    use crate::{
        backend::{
            BackendError, DesiredNodeState, EnrollmentRequest, EnrollmentStatus, NodeCertificate,
            NodeDirective, PickupRequest, RelayBackendPort, RelayNodeState, RenewalRequest,
            SecretCommitRequest, SecretRotationStatus, SecretRotationStatusRequest,
            SecretUploadRequest, SignedHeartbeat,
        },
        identity::{CertificateState, IdentityFsPort, StoredIdentity},
        process::{
            AllocationProbeEvidence, CoturnRuntimePort, CoturnSnapshot, LiveAllocationEvidence,
            ProcessError, SecretBytes,
        },
    };

    #[test]
    fn generated_operation_ids_reject_non_alphanumeric_first_char_without_losing_length() {
        let mut fills = 0usize;
        let identifier = generate_rotation_identifier_with(|bytes| {
            fills += 1;
            bytes.fill(if fills == 1 { 0xf8 } else { 0x04 });
            Ok(())
        })
        .unwrap();
        assert_eq!(fills, 2);
        assert_eq!(identifier.len(), 32);
        assert!(identifier.as_bytes()[0].is_ascii_alphanumeric());
        assert!(identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
    }

    #[test]
    fn generated_operation_ids_are_always_schema_compatible_across_many_samples() {
        for _ in 0..10_000 {
            let identifier = super::generate_rotation_identifier().unwrap();
            assert!((8..=128).contains(&identifier.len()));
            assert!(identifier.as_bytes()[0].is_ascii_alphanumeric());
        }
    }

    #[test]
    fn commit_unknown_only_retries_exact_body_in_the_same_live_process_generation() {
        let current = CoturnSnapshot::healthy(0, 0).with_generation(7, 2);
        assert!(commit_unknown_can_retry_exact(false, Some(7), 2, &current));
        assert!(!commit_unknown_can_retry_exact(true, Some(7), 2, &current));
        assert!(!commit_unknown_can_retry_exact(false, Some(8), 2, &current));
        assert!(!commit_unknown_can_retry_exact(
            false,
            Some(7),
            2,
            &CoturnSnapshot {
                health: ProcessHealth::Failed,
                ..current
            },
        ));
        assert!(!commit_unknown_can_retry_exact(
            false,
            Some(7),
            2,
            &CoturnSnapshot {
                applied_secret_version: 1,
                ..current
            },
        ));
    }

    #[derive(Default)]
    struct TestIdentityFs(Mutex<Option<StoredIdentity>>);

    impl IdentityFsPort for TestIdentityFs {
        fn load(&self) -> Result<Option<StoredIdentity>, RuntimeError> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn atomic_replace(&self, identity: &StoredIdentity) -> Result<(), RuntimeError> {
            *self.0.lock().unwrap() = Some(identity.clone());
            Ok(())
        }

        fn enforce_strict_permissions(&self) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    struct TestBackend {
        commits: Mutex<Vec<SecretCommitRequest>>,
        statuses: Mutex<Vec<SecretRotationStatusRequest>>,
        commit_results: Mutex<VecDeque<Result<(), BackendError>>>,
    }

    #[async_trait]
    impl RelayBackendPort for TestBackend {
        async fn enroll(
            &self,
            _request: EnrollmentRequest,
        ) -> Result<EnrollmentStatus, BackendError> {
            Err(BackendError::Unavailable)
        }

        async fn pickup(
            &self,
            _request: PickupRequest,
        ) -> Result<Option<NodeCertificate>, BackendError> {
            Err(BackendError::Unavailable)
        }

        async fn renew(&self, _request: RenewalRequest) -> Result<NodeCertificate, BackendError> {
            Err(BackendError::Unavailable)
        }

        async fn heartbeat(
            &self,
            _heartbeat: SignedHeartbeat,
        ) -> Result<NodeDirective, BackendError> {
            Err(BackendError::Unavailable)
        }

        async fn upload_secret(&self, _request: SecretUploadRequest) -> Result<(), BackendError> {
            Ok(())
        }

        async fn commit_secret(&self, request: SecretCommitRequest) -> Result<(), BackendError> {
            self.commits.lock().unwrap().push(request);
            self.commit_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(()))
        }

        async fn rotation_status(
            &self,
            request: SecretRotationStatusRequest,
        ) -> Result<SecretRotationStatus, BackendError> {
            self.statuses.lock().unwrap().push(request);
            Err(BackendError::ProtocolInvalid)
        }
    }

    struct TestCoturn {
        snapshots: Mutex<VecDeque<CoturnSnapshot>>,
        probes: Mutex<VecDeque<AllocationProbeEvidence>>,
    }

    #[async_trait]
    impl CoturnRuntimePort for TestCoturn {
        async fn snapshot(&self) -> Result<CoturnSnapshot, ProcessError> {
            self.snapshots
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(ProcessError::Unavailable)
        }

        async fn restart(&self) -> Result<(), ProcessError> {
            Ok(())
        }

        async fn apply_secret(
            &self,
            _version: u64,
            _secret: SecretBytes,
        ) -> Result<(), ProcessError> {
            Ok(())
        }

        async fn set_draining(&self, _draining: bool) -> Result<(), ProcessError> {
            Ok(())
        }

        async fn probe_local_allocation(&self) -> Result<AllocationProbeEvidence, ProcessError> {
            self.probes
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(ProcessError::ProbeUnavailable)
        }
    }

    struct TestClock;

    impl ClockPort for TestClock {
        fn monotonic_ms(&self) -> u64 {
            1_800_000_000_000
        }

        fn unix_seconds(&self) -> i64 {
            1_800_000_000
        }
    }

    struct TestSleeper;

    #[async_trait]
    impl SleeperPort for TestSleeper {
        async fn sleep(&self, _duration: Duration) {}
    }

    struct TestJitter;

    impl JitterPort for TestJitter {
        fn jitter_ms(&self, _upper_exclusive: u64) -> u64 {
            0
        }
    }

    #[derive(Default)]
    struct TestStateStore(Mutex<RuntimeStateSnapshot>);

    impl RuntimeStateStorePort for TestStateStore {
        fn load(&self) -> Result<RuntimeStateSnapshot, RuntimeError> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn atomic_store(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError> {
            *self.0.lock().unwrap() = state.clone();
            Ok(())
        }
    }

    fn test_ca_pem() -> String {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "MRD runtime unit CA");
        params.distinguished_name = name;
        params.not_before = date_time_ymd(2025, 1, 1);
        params.not_after = date_time_ymd(2035, 1, 1);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.self_signed(&key).unwrap().pem()
    }

    #[tokio::test]
    async fn same_generation_commit_unknown_freshly_probes_then_retries_exact_persisted_proof() {
        let backend = Arc::new(TestBackend {
            commits: Mutex::new(Vec::new()),
            statuses: Mutex::new(Vec::new()),
            commit_results: Mutex::new(VecDeque::from([Err(BackendError::Unavailable), Ok(())])),
        });
        let generation_one = CoturnSnapshot::healthy(0, 0).with_generation(7, 1);
        let generation_two = CoturnSnapshot::healthy(0, 0).with_generation(7, 2);
        let coturn = Arc::new(TestCoturn {
            snapshots: Mutex::new(VecDeque::from([
                generation_one,
                generation_two.clone(),
                generation_two.clone(),
                generation_two.clone(),
                generation_two.clone(),
                generation_two.clone(),
                generation_two.clone(),
                generation_two,
            ])),
            probes: Mutex::new(VecDeque::from([
                AllocationProbeEvidence::Live(LiveAllocationEvidence::from_verified_roundtrip(
                    [0x11; 32],
                )),
                AllocationProbeEvidence::Live(LiveAllocationEvidence::from_verified_roundtrip(
                    [0x22; 32],
                )),
            ])),
        });
        let state_store = Arc::new(TestStateStore(Mutex::new(RuntimeStateSnapshot {
            identity_epoch: 1,
            secret_version: 1,
            secret_digest: Some([1; 32]),
            ..RuntimeStateSnapshot::default()
        })));
        let clock = Arc::new(TestClock);
        let mut runtime = AgentRuntime::new_with_state_store(
            backend.clone(),
            coturn,
            clock.clone(),
            Arc::new(TestSleeper),
            Arc::new(TestJitter),
            state_store.clone(),
        )
        .unwrap();
        let mut identity = CertificateState::new(
            Arc::new(TestIdentityFs::default()),
            "relay-hkg-1",
            &test_ca_pem(),
            clock,
        )
        .unwrap();
        runtime
            .apply_directive(NodeDirective {
                identity_epoch: 1,
                sequence: 1,
                state: RelayNodeState::Draining,
                desired: DesiredNodeState {
                    draining: true,
                    secret_version: 2,
                    not_before_unix_seconds: Some(1_800_000_000),
                    old_credential_deadline_unix_seconds: Some(1_800_000_000),
                    rotation_challenge: Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".into()),
                },
                secret_update: None,
            })
            .await
            .unwrap();

        assert_eq!(
            runtime.advance_secret_rotation(&mut identity).await,
            Err(RuntimeError::Backend(BackendError::Unavailable))
        );
        assert!(runtime.rotation_requires_reconcile_before_heartbeat());
        assert!(runtime
            .advance_secret_rotation(&mut identity)
            .await
            .unwrap());

        assert!(backend.statuses.lock().unwrap().is_empty());
        let commits = backend.commits.lock().unwrap();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].rotation_id, commits[1].rotation_id);
        assert_eq!(
            commits[0].probe_evidence_sha256,
            "11".repeat(32),
            "the first production Live proof is persisted"
        );
        assert_eq!(
            commits[1].probe_evidence_sha256, commits[0].probe_evidence_sha256,
            "the fresh retry probe validates liveness but must not replace the durable proof"
        );
        assert_eq!(commits[1].proof_mac, commits[0].proof_mac);
        assert_ne!(
            commits[1].authentication.sequence,
            commits[0].authentication.sequence
        );
        let committed = state_store.0.lock().unwrap();
        assert_eq!(committed.secret_version, 2);
        assert!(committed.pending_rotation.is_none());
    }
}
