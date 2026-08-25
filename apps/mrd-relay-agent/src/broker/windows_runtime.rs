use std::{
    collections::BTreeMap,
    ffi::{c_void, OsStr, OsString},
    io::Read as _,
    os::windows::{ffi::OsStrExt as _, io::AsRawHandle as _},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mrd_transport_webrtc::{probe_turn_relay, IceServerConfig, TurnRelayProbeConfig};
use ring::rand::SecureRandom as _;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, PipeMode, ServerOptions},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use zeroize::Zeroizing;

use crate::{
    broker::{
        decode_request_frame, derive_coturn_rest_credentials, encode_response_frame,
        parse_docker_engine_stats_http, render_coturn_config, select_windows_pending_recovery,
        validate_probe_stability, ProbeStabilityObservation, WindowsPendingRecoveryAction,
        WindowsPendingRecoveryObservation,
    },
    metrics::{MetricsLimits, NativeCoturnScrapePort as _, ReqwestNativeCoturnScrape},
    platform::{
        broker_drain_proof_payload,
        linux::linux_probe_loopback_host,
        probe_proof_sha256,
        windows::{
            drive_windows_service_after_start_pending, target_command_plan,
            validate_windows_authenticode_claim, validate_windows_counter_epoch,
            validate_windows_delegated_generation, validate_windows_generation_transition,
            verify_windows_agent_process_id, verify_windows_maintenance_process_id,
            windows_maintenance_action_allowed, WindowsAuthenticodeClaim, WindowsDataRootLayout,
            WindowsGenerationTransition, WindowsServiceStatusUpdate, WindowsTargetConfig,
            BROKER_PIPE, BROKER_SERVICE, COTURN_CONFIG_DESTINATION, DOCKER_CAP_DROP,
            DOCKER_CONFIG_ARGUMENT, DOCKER_CONTAINER, DOCKER_ENGINE_PIPE, DOCKER_ENTRYPOINT,
            DOCKER_IPC_MODE, DOCKER_NETWORK_MODE, DOCKER_SECURITY_OPTION, DOCKER_USER,
            WINDOWS_MANAGED_LABEL_KEY, WINDOWS_MANAGED_LABEL_VALUE,
        },
        BrokerAction, BrokerRequest, CommandExecutorPort as _, CommandOutput, CommandPlan,
        CoturnTarget, StdCommandExecutor, TrafficCounterSource, TransportCapability,
        FRAME_HEADER_BYTES, MAX_CONTROL_OUTPUT_BYTES,
    },
    process::SecretBytes,
    secure_store::{
        AtomicEnvelopeFile as _, BoundSecretStore, DpapiMachineProtector, HardenedAtomicFile,
        SecretStorePurpose,
    },
};

const MAX_BROKER_CONFIG_BYTES: usize = 64 * 1024;
const PIPE_BUFFER_BYTES: u32 = 8 * 1024;
const PIPE_INSTANCES: u32 = 16;
const PIPE_LISTENER_RETRY_DELAY: Duration = Duration::from_millis(25);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT_REASON: &str = "relay_broker_request_timeout";
const TARGET_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TARGET_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STORE_PAYLOAD_BYTES: usize = 16 * 1024;
const METRICS_URL: &str = "http://127.0.0.1:9641/metrics";
const DOCKER_FRESH_CONFIG_PLACEHOLDER: &[u8] =
    b"# MRD broker placeholder v1; no TURN listener\nno-udp\nno-tcp\nno-tls\nno-dtls\n";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
static CONTROL_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectedAgentRole {
    Service,
    Maintenance {
        agent_service_process_id: Option<u32>,
        agent_executable_sha256: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConnectedAgentIdentity {
    client_process_id: u32,
    role: ConnectedAgentRole,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BrokerRuntimeError {
    #[error("relay_broker_cli_invalid")]
    CliInvalid,
    #[error("relay_broker_config_invalid")]
    ConfigInvalid,
    #[error("relay_broker_service_failed")]
    ServiceFailed,
    #[error("relay_broker_peer_rejected")]
    PeerRejected,
    #[error("relay_broker_frame_invalid")]
    FrameInvalid,
    #[error("relay_broker_state_invalid")]
    StateInvalid,
    #[error("relay_broker_target_failed")]
    TargetFailed,
    #[error("relay_broker_io_failed")]
    IoFailed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsBrokerConfigWire {
    schema_version: u8,
    pipe: String,
    target_config_path: PathBuf,
    enrollment_token_path: PathBuf,
    turn_rest_secret_path: PathBuf,
    pipe_acl: Vec<String>,
    verify_client_token_twice: bool,
    minimal_environment: Vec<String>,
    node_id: String,
    broker_service_sid: String,
    active_turn_secret_path: PathBuf,
    runtime_state_path: PathBuf,
    journal_path: PathBuf,
}

impl WindowsBrokerConfigWire {
    fn load(path: &Path) -> Result<Self, BrokerRuntimeError> {
        if !windows_local_file(path) {
            return Err(BrokerRuntimeError::ConfigInvalid);
        }
        let broker_sid = lookup_account_sid_string("NT SERVICE\\mrd-relay-coturn-control")?;
        let parent = path.parent().ok_or(BrokerRuntimeError::ConfigInvalid)?;
        let file =
            HardenedAtomicFile::new_windows(parent.to_path_buf(), path.to_path_buf(), &broker_sid)
                .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
        let encoded = file
            .read(MAX_BROKER_CONFIG_BYTES)
            .map_err(|_| BrokerRuntimeError::ConfigInvalid)?
            .ok_or(BrokerRuntimeError::ConfigInvalid)?;
        let config: Self =
            serde_json::from_slice(&encoded).map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
        config.validate(path, &broker_sid)?;
        Ok(config)
    }

    fn validate(&self, own_path: &Path, actual_broker_sid: &str) -> Result<(), BrokerRuntimeError> {
        let expected_acl = [
            "SYSTEM",
            "BUILTIN\\Administrators",
            "NT SERVICE\\mrd-relay-agent",
        ];
        let data_root =
            WindowsDataRootLayout::from_layout_path(own_path, &["broker", "broker.json"])
                .ok_or(BrokerRuntimeError::ConfigInvalid)?;
        if self.schema_version != 1
            || self.pipe != BROKER_PIPE
            || self.pipe_acl != expected_acl
            || !self.verify_client_token_twice
            || self.minimal_environment != ["SystemRoot", "ProgramFiles", "ProgramData"]
            || !valid_node_id(&self.node_id)
            || !self
                .broker_service_sid
                .eq_ignore_ascii_case(actual_broker_sid)
            || !data_root.matches_path(&self.target_config_path, &["broker", "target.json"])
            || !data_root.matches_path(
                &self.enrollment_token_path,
                &["secrets", "enrollment-token.dpapi"],
            )
            || !data_root.matches_path(
                &self.turn_rest_secret_path,
                &["secrets", "turn-rest-secret.dpapi"],
            )
            || !data_root.matches_path(
                &self.active_turn_secret_path,
                &["broker", "active-turn-secret.dpapi"],
            )
            || !data_root.matches_path(&self.runtime_state_path, &["broker", "control-state.dpapi"])
            || !data_root.matches_path(&self.journal_path, &["broker", "control-journal.dpapi"])
        {
            return Err(BrokerRuntimeError::ConfigInvalid);
        }
        Ok(())
    }

    fn load_target(&self) -> Result<WindowsTargetConfig, BrokerRuntimeError> {
        let parent = self
            .target_config_path
            .parent()
            .ok_or(BrokerRuntimeError::ConfigInvalid)?;
        let file = HardenedAtomicFile::new_windows(
            parent.to_path_buf(),
            self.target_config_path.clone(),
            &self.broker_service_sid,
        )
        .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
        let encoded = file
            .read(MAX_BROKER_CONFIG_BYTES)
            .map_err(|_| BrokerRuntimeError::ConfigInvalid)?
            .ok_or(BrokerRuntimeError::ConfigInvalid)?;
        let expected_root = WindowsDataRootLayout::from_layout_path(
            &self.target_config_path,
            &["broker", "target.json"],
        )
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
        let target =
            WindowsTargetConfig::parse(&encoded).map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
        if !expected_root.matches_path(target.baseline_path(), &["broker", "turnserver.conf.base"])
        {
            return Err(BrokerRuntimeError::ConfigInvalid);
        }
        Ok(target)
    }

    fn stores(&self) -> Result<WindowsBrokerStores, BrokerRuntimeError> {
        let protector = Arc::new(DpapiMachineProtector::new());
        let active = broker_store(
            &self.active_turn_secret_path,
            &self.broker_service_sid,
            &self.node_id,
            SecretStorePurpose::BrokerActiveTurnSecret,
            protector.clone(),
        )?;
        let state = broker_store(
            &self.runtime_state_path,
            &self.broker_service_sid,
            &self.node_id,
            SecretStorePurpose::BrokerControlState,
            protector.clone(),
        )?;
        let journal = broker_store(
            &self.journal_path,
            &self.broker_service_sid,
            &self.node_id,
            SecretStorePurpose::BrokerControlJournal,
            protector,
        )?;
        Ok(WindowsBrokerStores {
            active,
            state,
            journal,
        })
    }
}

type BrokerStore = BoundSecretStore<HardenedAtomicFile, DpapiMachineProtector>;

struct WindowsBrokerStores {
    active: BrokerStore,
    state: BrokerStore,
    journal: BrokerStore,
}

fn broker_store(
    path: &Path,
    broker_sid: &str,
    node_id: &str,
    purpose: SecretStorePurpose,
    protector: Arc<DpapiMachineProtector>,
) -> Result<BrokerStore, BrokerRuntimeError> {
    let parent = path.parent().ok_or(BrokerRuntimeError::ConfigInvalid)?;
    let file = Arc::new(
        HardenedAtomicFile::new_windows(parent.to_path_buf(), path.to_path_buf(), broker_sid)
            .map_err(|_| BrokerRuntimeError::ConfigInvalid)?,
    );
    BoundSecretStore::new(file, protector, node_id, purpose)
        .map_err(|_| BrokerRuntimeError::ConfigInvalid)
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WindowsCommittedState {
    schema_version: u8,
    target: String,
    generation: u64,
    applied_secret_version: u64,
    target_epoch: String,
    secret_sha256: String,
    config_sha256: String,
    draining: bool,
    #[serde(default)]
    drain_completed: bool,
    external_restart_detected: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct ZeroizingBase64Url(Zeroizing<String>);

impl ZeroizingBase64Url {
    fn from_raw(raw: &[u8]) -> Result<Self, BrokerRuntimeError> {
        if raw.len() != 32 {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        let mut encoded = Zeroizing::new([0_u8; 43]);
        let written = URL_SAFE_NO_PAD
            .encode_slice(raw, encoded.as_mut_slice())
            .map_err(|_| BrokerRuntimeError::StateInvalid)?;
        if written != encoded.len() {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        let value = std::str::from_utf8(encoded.as_slice())
            .map_err(|_| BrokerRuntimeError::StateInvalid)?;
        let mut owner = Zeroizing::new(String::with_capacity(value.len()));
        owner.push_str(value);
        Ok(Self(owner))
    }

    fn decode_raw(&self) -> Result<Zeroizing<Vec<u8>>, BrokerRuntimeError> {
        if self.0.len() != 43
            || !self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        let mut raw = Zeroizing::new(vec![0_u8; 32]);
        let written = URL_SAFE_NO_PAD
            .decode_slice(self.0.as_bytes(), raw.as_mut_slice())
            .map_err(|_| BrokerRuntimeError::StateInvalid)?;
        if written != raw.len() {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        let mut canonical = Zeroizing::new([0_u8; 43]);
        let canonical_len = URL_SAFE_NO_PAD
            .encode_slice(raw.as_slice(), canonical.as_mut_slice())
            .map_err(|_| BrokerRuntimeError::StateInvalid)?;
        if canonical_len != canonical.len() || canonical.as_slice() != self.0.as_bytes() {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        Ok(raw)
    }
}

impl Serialize for ZeroizingBase64Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ZeroizingBase64Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecretVisitor;

        impl serde::de::Visitor<'_> for SecretVisitor {
            type Value = ZeroizingBase64Url;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a canonical zeroizing base64url secret")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut owner = Zeroizing::new(String::with_capacity(value.len()));
                owner.push_str(value);
                Ok(ZeroizingBase64Url(owner))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ZeroizingBase64Url(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(SecretVisitor)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveSecretEnvelope {
    schema_version: u8,
    target: String,
    version: u64,
    raw_secret_b64: ZeroizingBase64Url,
    secret_sha256: String,
}

type LoadedActiveSecret = (ActiveSecretEnvelope, Zeroizing<Vec<u8>>);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsPendingTransaction {
    target: String,
    desired_version: u64,
    desired_secret_b64: ZeroizingBase64Url,
    desired_secret_sha256: String,
    desired_config_sha256: String,
    previous_state: Option<WindowsCommittedState>,
    previous_active: Option<ActiveSecretEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    docker_phase: Option<DockerSecretPhase>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum DockerSecretPhase {
    VerifyIdentity,
    WriteDesiredConfig,
    RestartTarget,
    PersistGeneration { epoch: String },
    VerifyLive { epoch: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DockerSecretRecoveryAction {
    VerifyIdentity,
    WriteDesiredConfig,
    RestartTarget,
    PersistGeneration,
    VerifyLive,
}

fn select_docker_secret_recovery(
    phase: &DockerSecretPhase,
    previous_epoch: Option<&str>,
    current_epoch: Option<&str>,
    target_active: bool,
    identity_generation: Option<u64>,
    desired_generation: u64,
) -> Result<DockerSecretRecoveryAction, BrokerRuntimeError> {
    if desired_generation == 0
        || identity_generation.is_none()
        || current_epoch.is_none_or(|epoch| !valid_epoch(epoch))
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let generation_is_recoverable = identity_generation
        .is_some_and(|value| recoverable_docker_apply_generation(value, desired_generation));
    if !generation_is_recoverable {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    match phase {
        DockerSecretPhase::VerifyIdentity => Ok(DockerSecretRecoveryAction::VerifyIdentity),
        DockerSecretPhase::WriteDesiredConfig => Ok(DockerSecretRecoveryAction::WriteDesiredConfig),
        DockerSecretPhase::RestartTarget => {
            let restart_already_observed =
                target_active && previous_epoch.is_some() && current_epoch != previous_epoch;
            if restart_already_observed {
                Ok(DockerSecretRecoveryAction::PersistGeneration)
            } else {
                Ok(DockerSecretRecoveryAction::RestartTarget)
            }
        }
        DockerSecretPhase::PersistGeneration { epoch } => {
            if !target_active || current_epoch != Some(epoch.as_str()) {
                return Err(BrokerRuntimeError::StateInvalid);
            }
            if identity_generation == Some(desired_generation) {
                Ok(DockerSecretRecoveryAction::VerifyLive)
            } else {
                Ok(DockerSecretRecoveryAction::PersistGeneration)
            }
        }
        DockerSecretPhase::VerifyLive { epoch } => {
            if !target_active
                || current_epoch != Some(epoch.as_str())
                || identity_generation != Some(desired_generation)
            {
                return Err(BrokerRuntimeError::StateInvalid);
            }
            Ok(DockerSecretRecoveryAction::VerifyLive)
        }
    }
}

fn recoverable_docker_apply_generation(current: u64, desired: u64) -> bool {
    current == desired
        || desired
            .checked_sub(1)
            .is_some_and(|previous| previous != 0 && current == previous)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsPendingDrainTransaction {
    target: String,
    desired_draining: bool,
    previous_state: WindowsCommittedState,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsJournalEnvelope {
    schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<WindowsPendingTransaction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    drain_pending: Option<WindowsPendingDrainTransaction>,
}

enum WindowsPendingOperation {
    Secret(WindowsPendingTransaction),
    Drain(WindowsPendingDrainTransaction),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DockerIdentity {
    schema_version: u8,
    target: String,
    container_id: String,
    image_id: String,
    image_reference: String,
    generation: u64,
}

struct TargetObservation {
    reported_generation: Option<u64>,
    epoch: String,
    active: bool,
    healthy: bool,
    active_allocations: u32,
    counter_source: TrafficCounterSource,
    total_ingress_bytes: u64,
    total_egress_bytes: u64,
    measurement_monotonic_ns: u64,
    reported_secret_version: Option<u64>,
    config_sha256: String,
    draining: bool,
    drain_completed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegatedSnapshot {
    target: String,
    generation: u64,
    applied_secret_version: u64,
    health: String,
    active_allocations: u32,
    counter_source: TrafficCounterSource,
    counter_epoch: String,
    total_ingress_bytes: u64,
    total_egress_bytes: u64,
    measurement_monotonic_ns: u64,
    configured_max_allocations: u32,
    configured_max_egress_bps: u64,
    relay_min_port: u16,
    relay_max_port: u16,
    transport_capabilities: Vec<TransportCapability>,
    configured_endpoints: Vec<String>,
    draining: bool,
    drain_completed: bool,
}

#[derive(Serialize)]
struct SnapshotResponse<'a> {
    target: &'static str,
    generation: u64,
    applied_secret_version: u64,
    health: &'static str,
    active_allocations: u32,
    counter_source: &'static str,
    counter_epoch: &'a str,
    total_ingress_bytes: u64,
    total_egress_bytes: u64,
    measurement_monotonic_ns: u64,
    configured_max_allocations: u32,
    configured_max_egress_bps: u64,
    relay_min_port: u16,
    relay_max_port: u16,
    transport_capabilities: &'a [TransportCapability],
    configured_endpoints: &'a [String],
    draining: bool,
    drain_completed: bool,
}

#[derive(Serialize)]
struct ProbeResponse<'a> {
    target: &'static str,
    generation: u64,
    applied_secret_version: u64,
    challenge: &'a str,
    listener_reachable: bool,
    credential_authenticated: bool,
    allocation_created: bool,
    permission_created: bool,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    local_candidate_kind: &'static str,
    remote_candidate_kind: &'static str,
    local_candidate_id: &'a str,
    remote_candidate_id: &'a str,
    proof_sha256: &'a str,
}

define_windows_service!(ffi_service_main, service_main);

pub fn run_windows_service(config_path: PathBuf) -> Result<(), BrokerRuntimeError> {
    if CONFIG_PATH.set(config_path).is_err() {
        return Err(BrokerRuntimeError::ServiceFailed);
    }
    service_dispatcher::start(BROKER_SERVICE, ffi_service_main)
        .map_err(|_| BrokerRuntimeError::ServiceFailed)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = registered_service_main() {
        eprintln!("{error}");
    }
}

fn registered_service_main() -> Result<(), BrokerRuntimeError> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(BROKER_SERVICE, handler)
        .map_err(|_| BrokerRuntimeError::ServiceFailed)?;
    set_service_status(
        &status,
        ServiceState::StartPending,
        1,
        ServiceExitCode::Win32(0),
    )?;
    drive_windows_service_after_start_pending(
        || {
            let config_path = CONFIG_PATH.get().ok_or(BrokerRuntimeError::ServiceFailed)?;
            let config = WindowsBrokerConfigWire::load(config_path)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|_| BrokerRuntimeError::ServiceFailed)?;
            Ok((runtime, config))
        },
        |(runtime, config)| runtime.block_on(run_pipe_server(config, stop_rx)),
        |update| match update {
            WindowsServiceStatusUpdate::Running => {
                set_service_status(&status, ServiceState::Running, 0, ServiceExitCode::Win32(0))
            }
            WindowsServiceStatusUpdate::StopPending => set_service_status(
                &status,
                ServiceState::StopPending,
                1,
                ServiceExitCode::Win32(0),
            ),
            WindowsServiceStatusUpdate::StoppedSuccess => {
                set_service_status(&status, ServiceState::Stopped, 0, ServiceExitCode::Win32(0))
            }
            WindowsServiceStatusUpdate::StoppedFailure => set_service_status(
                &status,
                ServiceState::Stopped,
                0,
                ServiceExitCode::ServiceSpecific(1),
            ),
        },
    )
}

fn set_service_status(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
    exit_code: ServiceExitCode,
) -> Result<(), BrokerRuntimeError> {
    handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint,
            wait_hint: if state == ServiceState::StartPending {
                Duration::from_secs(30)
            } else {
                Duration::ZERO
            },
            process_id: None,
        })
        .map_err(|_| BrokerRuntimeError::ServiceFailed)
}

async fn run_pipe_server(
    config: WindowsBrokerConfigWire,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), BrokerRuntimeError> {
    let config = Arc::new(config);
    let agent_sid = lookup_account_sid_string("NT SERVICE\\mrd-relay-agent")?;
    let descriptor = PipeSecurityDescriptor::new(&agent_sid)?;
    let mut server = create_pipe_server(true, descriptor.attributes())
        .map_err(|_| BrokerRuntimeError::IoFailed)?;
    let mut requests = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            connected = server.connect() => {
                match pipe_listener_outcome(connected)? {
                    PipeListenerOutcome::Connected => loop {
                        match create_pipe_server(false, descriptor.attributes()) {
                            Ok(next) => {
                                // Keep the connected instance alive until its
                                // replacement listener exists. This preserves
                                // pipe-name ownership even when capacity is
                                // temporarily exhausted.
                                let mut connected = std::mem::replace(&mut server, next);
                                let config = config.clone();
                                requests.spawn(async move {
                                    isolate_connected_request(
                                        REQUEST_TIMEOUT,
                                        serve_connected_pipe(&mut connected, &config),
                                    )
                                    .await
                                });
                                break;
                            }
                            Err(error) => match pipe_listener_outcome(Err(error))? {
                                PipeListenerOutcome::Retry => {
                                    tokio::select! {
                                        completed = requests.join_next(), if !requests.is_empty() => {
                                            request_join_outcome(completed)?;
                                        }
                                        changed = stop.changed() => {
                                            if changed.is_err() || *stop.borrow() {
                                                requests.abort_all();
                                                while requests.join_next().await.is_some() {}
                                                return Ok(());
                                            }
                                        }
                                        _ = tokio::time::sleep(PIPE_LISTENER_RETRY_DELAY) => {}
                                    }
                                }
                                PipeListenerOutcome::Connected => {
                                    return Err(BrokerRuntimeError::ServiceFailed);
                                }
                            },
                        }
                    },
                    PipeListenerOutcome::Retry => {
                        if let Err(error) = server.disconnect() {
                            match pipe_listener_outcome(Err(error))? {
                                PipeListenerOutcome::Retry => {}
                                PipeListenerOutcome::Connected => {
                                    return Err(BrokerRuntimeError::ServiceFailed);
                                }
                            }
                        }
                        tokio::time::sleep(PIPE_LISTENER_RETRY_DELAY).await;
                    }
                }
            }
            completed = requests.join_next(), if !requests.is_empty() => {
                request_join_outcome(completed)?;
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    requests.abort_all();
                    while requests.join_next().await.is_some() {}
                    return Ok(());
                }
            }
        }
    }
}

async fn isolate_connected_request<F>(
    timeout: Duration,
    request: F,
) -> Result<(), BrokerRuntimeError>
where
    F: std::future::Future<Output = Result<(), BrokerRuntimeError>>,
{
    match tokio::time::timeout(timeout, request).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("{error}"),
        Err(_) => eprintln!("{REQUEST_TIMEOUT_REASON}"),
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipeListenerOutcome {
    Connected,
    Retry,
}

fn pipe_listener_outcome(
    result: std::io::Result<()>,
) -> Result<PipeListenerOutcome, BrokerRuntimeError> {
    match result {
        Ok(()) => Ok(PipeListenerOutcome::Connected),
        Err(error) if recoverable_pipe_listener_error(&error) => Ok(PipeListenerOutcome::Retry),
        Err(_) => Err(BrokerRuntimeError::IoFailed),
    }
}

fn recoverable_pipe_listener_error(error: &std::io::Error) -> bool {
    use windows_sys::Win32::Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED,
    };

    error.raw_os_error().is_some_and(|code| {
        [
            ERROR_PIPE_BUSY,
            ERROR_BROKEN_PIPE,
            ERROR_NO_DATA,
            ERROR_PIPE_NOT_CONNECTED,
        ]
        .into_iter()
        .any(|recoverable| code == recoverable as i32)
    })
}

fn request_join_outcome(
    completed: Option<Result<Result<(), BrokerRuntimeError>, tokio::task::JoinError>>,
) -> Result<(), BrokerRuntimeError> {
    completed
        .ok_or(BrokerRuntimeError::ServiceFailed)?
        .map_err(|_| BrokerRuntimeError::ServiceFailed)?
        .map_err(|_| BrokerRuntimeError::ServiceFailed)
}

fn create_pipe_server(first: bool, attributes: *mut c_void) -> std::io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .access_inbound(true)
        .access_outbound(true)
        .first_pipe_instance(first)
        .pipe_mode(PipeMode::Byte)
        .reject_remote_clients(true)
        .max_instances(PIPE_INSTANCES as usize)
        .in_buffer_size(PIPE_BUFFER_BYTES)
        .out_buffer_size(PIPE_BUFFER_BYTES);
    // SAFETY: PipeSecurityDescriptor owns a live, self-relative security
    // descriptor for the duration of CreateNamedPipeW. Tokio does not retain
    // the SECURITY_ATTRIBUTES pointer after this call returns.
    unsafe { options.create_with_security_attributes_raw(BROKER_PIPE, attributes) }
}

async fn serve_connected_pipe(
    server: &mut NamedPipeServer,
    config: &WindowsBrokerConfigWire,
) -> Result<(), BrokerRuntimeError> {
    let first_identity = verify_connected_agent(server).await?;
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    server
        .read_exact(&mut header)
        .await
        .map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    BrokerRequest::validate_header(header).map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    let action =
        BrokerAction::from_byte(header[5]).map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    // Re-read the pipe client PID and live SCM/token claim after the header.
    // A maintenance console is authorized only for read-only snapshot/probe,
    // and is rejected before any secret payload can be read.
    let second_identity = verify_connected_agent(server).await?;
    if first_identity != second_identity
        || matches!(second_identity.role, ConnectedAgentRole::Maintenance { .. })
            && !windows_maintenance_action_allowed(action)
    {
        return Err(BrokerRuntimeError::PeerRejected);
    }
    let metadata_len = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| BrokerRuntimeError::FrameInvalid)?,
    ) as usize;
    let secret_len = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| BrokerRuntimeError::FrameInvalid)?,
    ) as usize;
    let total = FRAME_HEADER_BYTES
        .checked_add(metadata_len)
        .and_then(|value| value.checked_add(secret_len))
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(total));
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    server
        .read_exact(&mut frame[FRAME_HEADER_BYTES..])
        .await
        .map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    ensure_no_buffered_pipe_bytes(server)?;
    let request = decode_request_frame(frame).map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    let payload = dispatch_request(config, request).await?;
    let response = encode_response_frame(&payload).map_err(|_| BrokerRuntimeError::TargetFailed)?;
    server
        .write_all(&response)
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)?;
    server
        .flush()
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)?;
    server
        .disconnect()
        .map_err(|_| BrokerRuntimeError::IoFailed)
}

fn ensure_no_buffered_pipe_bytes(server: &NamedPipeServer) -> Result<(), BrokerRuntimeError> {
    let mut available = 0_u32;
    // SAFETY: server owns a live connected pipe and `available` is a writable
    // scalar. No payload is copied by this zero-length PeekNamedPipe call.
    if unsafe {
        windows_sys::Win32::System::Pipes::PeekNamedPipe(
            server.as_raw_handle().cast(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    } == 0
        || available != 0
    {
        return Err(BrokerRuntimeError::FrameInvalid);
    }
    Ok(())
}

async fn verify_connected_agent(
    server: &NamedPipeServer,
) -> Result<ConnectedAgentIdentity, BrokerRuntimeError> {
    let mut process_id = 0_u32;
    // SAFETY: server owns a connected live pipe handle and process_id is a
    // writable u32 for the duration of the call.
    if unsafe {
        windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
            server.as_raw_handle().cast(),
            &mut process_id,
        )
    } == 0
    {
        return Err(BrokerRuntimeError::PeerRejected);
    }
    tokio::task::spawn_blocking(move || {
        if verify_windows_agent_process_id(process_id).is_ok() {
            return Ok(ConnectedAgentIdentity {
                client_process_id: process_id,
                role: ConnectedAgentRole::Service,
            });
        }
        let claim = verify_windows_maintenance_process_id(process_id)
            .map_err(|_| BrokerRuntimeError::PeerRejected)?;
        verified_authenticode_signer(&claim.client_executable)
            .map_err(|_| BrokerRuntimeError::PeerRejected)?;
        Ok(ConnectedAgentIdentity {
            client_process_id: process_id,
            role: ConnectedAgentRole::Maintenance {
                agent_service_process_id: claim.agent_service_process_id,
                agent_executable_sha256: claim.agent_service_executable_sha256,
            },
        })
    })
    .await
    .map_err(|_| BrokerRuntimeError::PeerRejected)?
}

async fn dispatch_request(
    config: &WindowsBrokerConfigWire,
    request: BrokerRequest,
) -> Result<Vec<u8>, BrokerRuntimeError> {
    let _guard = CONTROL_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let target = config.load_target()?;
    if request.target() != target.target() {
        return Err(BrokerRuntimeError::FrameInvalid);
    }
    let stores = config.stores()?;
    reconcile_pending(&target, &stores, &config.broker_service_sid).await?;
    match request.action() {
        BrokerAction::Snapshot => {
            snapshot_payload(
                &target,
                &stores,
                &config.broker_service_sid,
                request.snapshot_challenge(),
            )
            .await
        }
        BrokerAction::Restart => {
            restart_transaction(&target, &stores, &config.broker_service_sid).await?;
            snapshot_payload(&target, &stores, &config.broker_service_sid, None).await
        }
        BrokerAction::ApplySecret => {
            apply_secret_transaction(&target, &stores, &config.broker_service_sid, &request)
                .await?;
            snapshot_payload(&target, &stores, &config.broker_service_sid, None).await
        }
        BrokerAction::SetDraining => {
            set_draining_transaction(
                &target,
                &stores,
                &config.broker_service_sid,
                request.draining().ok_or(BrokerRuntimeError::FrameInvalid)?,
            )
            .await?;
            snapshot_payload(&target, &stores, &config.broker_service_sid, None).await
        }
        BrokerAction::Probe => {
            probe_payload(&target, &stores, &config.broker_service_sid, &request).await
        }
    }
}

async fn snapshot_payload(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
    drain_challenge: Option<&[u8; 32]>,
) -> Result<Vec<u8>, BrokerRuntimeError> {
    let (state, observation) = verified_snapshot(target, stores, broker_sid).await?;
    if let Some(challenge) = drain_challenge {
        if state.external_restart_detected
            || !state.draining
            || !state.drain_completed
            || observation.active_allocations != 0
        {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        return broker_drain_proof_payload(
            target.target(),
            state.generation,
            state.applied_secret_version,
            challenge,
        )
        .map_err(|_| BrokerRuntimeError::StateInvalid);
    }
    serialize_snapshot(target, &state, &observation)
}

async fn verified_snapshot(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
) -> Result<(WindowsCommittedState, TargetObservation), BrokerRuntimeError> {
    let mut state = load_state(stores)?.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_state(&state, target.target())?;
    let (active, _) = load_active(stores)?.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_active_against_state(&active, &state, target.target())?;
    let observation = observe_target(target, broker_sid, Some(&state), false).await?;
    validate_observation(target, &state, &observation)?;
    let reported_generation = observation
        .reported_generation
        .ok_or(BrokerRuntimeError::TargetFailed)?;
    let same_epoch = observation.epoch == state.target_epoch;
    let transition = validate_windows_generation_transition(
        target.target(),
        state.generation,
        same_epoch,
        reported_generation,
    )
    .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    if transition != WindowsGenerationTransition::Stable {
        let next_generation = state
            .generation
            .checked_add(1)
            .ok_or(BrokerRuntimeError::StateInvalid)?;
        if transition == WindowsGenerationTransition::AdvanceDockerIdentityAndState {
            advance_docker_identity_generation(
                target,
                broker_sid,
                state.generation,
                next_generation,
            )?;
        }
        state.generation = next_generation;
        state.target_epoch.clone_from(&observation.epoch);
        state.drain_completed = false;
        state.external_restart_detected = true;
        store_state(stores, &state)?;
    } else {
        let completed = next_drain_completed(
            state.drain_completed,
            state.draining,
            &state.target_epoch,
            &observation.epoch,
            observation.drain_completed,
        );
        if completed != state.drain_completed {
            state.drain_completed = completed;
            store_state(stores, &state)?;
        }
    }
    Ok((state, observation))
}

fn serialize_snapshot(
    target: &WindowsTargetConfig,
    state: &WindowsCommittedState,
    observation: &TargetObservation,
) -> Result<Vec<u8>, BrokerRuntimeError> {
    let health = if state.external_restart_detected {
        "failed"
    } else if state.draining && state.drain_completed {
        "degraded"
    } else if !observation.active {
        "failed"
    } else if state.draining || !observation.healthy {
        "degraded"
    } else {
        "healthy"
    };
    let response = SnapshotResponse {
        target: target.target().as_str(),
        generation: state.generation,
        applied_secret_version: state.applied_secret_version,
        health,
        active_allocations: observation.active_allocations,
        counter_source: counter_source_name(observation.counter_source),
        counter_epoch: &observation.epoch,
        total_ingress_bytes: observation.total_ingress_bytes,
        total_egress_bytes: observation.total_egress_bytes,
        measurement_monotonic_ns: observation.measurement_monotonic_ns,
        configured_max_allocations: target.max_allocations(),
        configured_max_egress_bps: target.max_egress_bps(),
        relay_min_port: target.relay_ports().0,
        relay_max_port: target.relay_ports().1,
        transport_capabilities: target.transport_capabilities(),
        configured_endpoints: target.configured_endpoints(),
        draining: state.draining,
        drain_completed: state.drain_completed,
    };
    serde_json::to_vec(&response).map_err(|_| BrokerRuntimeError::StateInvalid)
}

async fn restart_transaction(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
) -> Result<(), BrokerRuntimeError> {
    let (mut state, before) = verified_snapshot(target, stores, broker_sid).await?;
    if state.external_restart_detected
        || (state.draining && (!state.drain_completed || before.active_allocations != 0))
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let next_generation = state
        .generation
        .checked_add(1)
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    let after = restart_target(target, broker_sid, Some(&state), next_generation).await?;
    require_new_epoch(&before, &after)?;
    require_reported_generation(&after, next_generation)?;
    require_reported_version(target.target(), &after, state.applied_secret_version)?;
    state.generation = next_generation;
    state.target_epoch = after.epoch;
    state.draining = false;
    state.drain_completed = false;
    state.external_restart_detected = false;
    store_state(stores, &state)
}

async fn apply_secret_transaction(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
    request: &BrokerRequest,
) -> Result<(), BrokerRuntimeError> {
    let version = request
        .secret_version()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let secret = request.secret().ok_or(BrokerRuntimeError::FrameInvalid)?;
    if secret.as_slice().len() != 32 {
        return Err(BrokerRuntimeError::FrameInvalid);
    }
    let previous_state = load_state(stores)?;
    if let Some(state) = previous_state.as_ref() {
        validate_state(state, target.target())?;
        if version < state.applied_secret_version
            || version
                > state
                    .applied_secret_version
                    .checked_add(1)
                    .ok_or(BrokerRuntimeError::StateInvalid)?
        {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        if version == state.applied_secret_version {
            let (active, _) = load_active(stores)?.ok_or(BrokerRuntimeError::StateInvalid)?;
            if !exact_replay_secret_matches(state, &active, secret.as_slice()) {
                return Err(BrokerRuntimeError::StateInvalid);
            }
            let (verified, _) = verified_snapshot(target, stores, broker_sid).await?;
            if verified.external_restart_detected {
                return Err(BrokerRuntimeError::StateInvalid);
            }
            // This is a lost-response replay of an already committed exact
            // version+digest. Preserve the current drain state and do not
            // restart or require a new allocation while the node is draining.
            return Ok(());
        }
    } else if version != 1 {
        return Err(BrokerRuntimeError::StateInvalid);
    }

    let previous_active = load_active(stores)?.map(|(active, _)| active);
    let desired_secret_sha256 = sha256_hex(secret.as_slice());
    let desired_config_sha256 =
        desired_config_sha256(target, broker_sid, version, secret.as_slice())?;
    let mut pending = WindowsPendingTransaction {
        target: target.target().as_str().to_owned(),
        desired_version: version,
        desired_secret_b64: ZeroizingBase64Url::from_raw(secret.as_slice())?,
        desired_secret_sha256,
        desired_config_sha256,
        previous_state: previous_state.clone(),
        previous_active,
        docker_phase: (target.target() == CoturnTarget::Docker)
            .then_some(DockerSecretPhase::VerifyIdentity),
    };
    store_secret_journal(stores, Some(pending.clone()))?;
    let next_generation = previous_state
        .as_ref()
        .map_or(Some(1), |state| state.generation.checked_add(1))
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    let before_epoch = previous_state
        .as_ref()
        .map(|state| state.target_epoch.as_str());
    let observed = apply_target(
        target,
        broker_sid,
        version,
        secret.as_slice(),
        previous_state.as_ref(),
        next_generation,
        Some((stores, &mut pending)),
    )
    .await?;
    require_reported_generation(&observed, next_generation)?;
    if !observed.active
        || observed.epoch.is_empty()
        || before_epoch == Some(observed.epoch.as_str())
        || !observation_reports_desired(target.target(), &observed, &pending)
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    require_live_secret_allocation(
        target,
        broker_sid,
        secret.as_slice(),
        &observed,
        version,
        &pending.desired_config_sha256,
    )
    .await?;
    commit_pending(stores, target, pending, observed, next_generation)
}

fn exact_replay_secret_matches(
    state: &WindowsCommittedState,
    active: &ActiveSecretEnvelope,
    raw_secret: &[u8],
) -> bool {
    raw_secret.len() == 32
        && active.target == state.target
        && active.version == state.applied_secret_version
        && active.secret_sha256 == state.secret_sha256
        && active.secret_sha256 == sha256_hex(raw_secret)
}

fn next_drain_completed(
    current: bool,
    draining: bool,
    committed_epoch: &str,
    observed_epoch: &str,
    observed_completion: bool,
) -> bool {
    draining && committed_epoch == observed_epoch && (current || observed_completion)
}

fn docker_drain_completed(
    draining: bool,
    running: bool,
    status: &str,
    exit_code: i64,
    observed_active_allocations: Option<u32>,
) -> bool {
    draining
        && ((running && observed_active_allocations == Some(0))
            || (!running && status == "exited" && exit_code == 0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainRecoveryAction {
    RemoveJournal,
    CommitObserved,
    ReplayTarget,
}

#[allow(clippy::too_many_arguments)]
fn select_drain_recovery(
    target: CoturnTarget,
    desired_draining: bool,
    previous_generation: u64,
    previous_epoch: &str,
    outer_generation: u64,
    outer_epoch: &str,
    outer_draining: bool,
    observed_generation: u64,
    observed_epoch: &str,
    observed_draining: bool,
    observed_drain_completed: bool,
    observed_active: bool,
) -> Result<DrainRecoveryAction, BrokerRuntimeError> {
    if previous_generation == 0
        || !valid_epoch(previous_epoch)
        || !valid_epoch(outer_epoch)
        || !valid_epoch(observed_epoch)
        || observed_generation == 0
        || target == CoturnTarget::LinuxSystemd
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let next_generation = previous_generation
        .checked_add(1)
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    let outer_is_previous = outer_generation == previous_generation
        && outer_epoch == previous_epoch
        && outer_draining != desired_draining;
    let outer_is_desired = if desired_draining {
        outer_generation == previous_generation && outer_epoch == previous_epoch && outer_draining
    } else {
        outer_generation == next_generation && outer_epoch != previous_epoch && !outer_draining
    };
    if outer_is_desired {
        let observation_matches = if desired_draining {
            observed_generation == previous_generation
                && observed_epoch == previous_epoch
                && (target == CoturnTarget::Docker || observed_draining)
        } else {
            observed_generation == next_generation
                && observed_epoch == outer_epoch
                && (target == CoturnTarget::Docker || !observed_draining)
        };
        return observation_matches
            .then_some(DrainRecoveryAction::RemoveJournal)
            .ok_or(BrokerRuntimeError::StateInvalid);
    }
    if !outer_is_previous {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    if desired_draining {
        if observed_epoch != previous_epoch || observed_generation != previous_generation {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        if (target != CoturnTarget::Docker && observed_draining)
            || (target == CoturnTarget::Docker && observed_drain_completed && !observed_active)
        {
            return Ok(DrainRecoveryAction::CommitObserved);
        }
        return Ok(DrainRecoveryAction::ReplayTarget);
    }
    let target_exit_observed = observed_epoch != previous_epoch
        && match target {
            CoturnTarget::WindowsService | CoturnTarget::Wsl2 => {
                observed_generation == next_generation && !observed_draining
            }
            CoturnTarget::Docker => {
                matches!(observed_generation, value if value == previous_generation || value == next_generation)
            }
            CoturnTarget::LinuxSystemd => false,
        };
    if target_exit_observed {
        Ok(DrainRecoveryAction::CommitObserved)
    } else if observed_generation == previous_generation
        && observed_epoch == previous_epoch
        && (target == CoturnTarget::Docker || observed_draining)
    {
        Ok(DrainRecoveryAction::ReplayTarget)
    } else {
        Err(BrokerRuntimeError::StateInvalid)
    }
}

async fn set_draining_transaction(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
    draining: bool,
) -> Result<(), BrokerRuntimeError> {
    let (state, before) = verified_snapshot(target, stores, broker_sid).await?;
    if state.external_restart_detected {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    if state.draining == draining {
        return Ok(());
    }
    if !draining && (!state.drain_completed || before.active_allocations != 0) {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let next_generation = if draining {
        state.generation
    } else {
        state
            .generation
            .checked_add(1)
            .ok_or(BrokerRuntimeError::StateInvalid)?
    };
    let pending = WindowsPendingDrainTransaction {
        target: target.target().as_str().to_owned(),
        desired_draining: draining,
        previous_state: state.clone(),
    };
    // Persist intent before changing the delegated target. Recovery either
    // proves the target transition or safely replays the idempotent action.
    store_drain_journal(stores, pending.clone())?;
    let after =
        set_target_draining(target, broker_sid, draining, Some(&state), next_generation).await?;
    commit_drain_transition(stores, target, pending, after)
}

async fn probe_payload(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
    request: &BrokerRequest,
) -> Result<Vec<u8>, BrokerRuntimeError> {
    let expected_generation = request
        .probe_generation()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let expected_version = request
        .probe_secret_version()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let challenge = request
        .probe_challenge()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let (state, observation) = verified_snapshot(target, stores, broker_sid).await?;
    if state.generation != expected_generation
        || state.applied_secret_version != expected_version
        || state.draining
        || state.external_restart_detected
        || !observation.active
        || !observation.healthy
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let (active, raw_secret) = load_active(stores)?.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_active_against_state(&active, &state, target.target())?;
    let probe_urls = trusted_windows_probe_urls(target, broker_sid)?;
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerRuntimeError::TargetFailed)?
        .as_secs()
        .checked_add(60)
        .ok_or(BrokerRuntimeError::TargetFailed)?;
    let challenge_hex = hex(challenge);
    let username = Zeroizing::new(format!(
        "{expiry}:mrd-local-preflight:{challenge_hex}:{}",
        target.target().as_str()
    ));
    let credentials = derive_coturn_rest_credentials(&raw_secret, &username)
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let evidence = probe_turn_relay(TurnRelayProbeConfig {
        ice_servers: vec![IceServerConfig::new(
            probe_urls.to_vec(),
            credentials.username().to_owned(),
            credentials.credential().to_owned(),
        )],
        timeout: PROBE_TIMEOUT,
    })
    .await
    .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let pair = evidence.selected_pair();
    if !evidence.has_relay_pair() || !evidence.control_round_trip() || !evidence.media_round_trip()
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let before = probe_stability_observation(target.target(), &state, &observation);
    let (after_state, after_observation) = verified_snapshot(target, stores, broker_sid).await?;
    let after = probe_stability_observation(target.target(), &after_state, &after_observation);
    validate_probe_stability(&before, &after).map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let proof = probe_proof_sha256(
        target.target(),
        state.generation,
        state.applied_secret_version,
        challenge,
        &pair.local_candidate_id,
        &pair.remote_candidate_id,
        u64::from(pair.packets_sent),
        u64::from(pair.packets_received),
        pair.bytes_sent,
        pair.bytes_received,
    )
    .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let proof_hex = hex(&proof);
    let response = ProbeResponse {
        target: target.target().as_str(),
        generation: state.generation,
        applied_secret_version: state.applied_secret_version,
        challenge: &challenge_hex,
        listener_reachable: true,
        credential_authenticated: true,
        allocation_created: true,
        permission_created: true,
        packets_sent: u64::from(pair.packets_sent),
        packets_received: u64::from(pair.packets_received),
        bytes_sent: pair.bytes_sent,
        bytes_received: pair.bytes_received,
        local_candidate_kind: "relay",
        remote_candidate_kind: "relay",
        local_candidate_id: &pair.local_candidate_id,
        remote_candidate_id: &pair.remote_candidate_id,
        proof_sha256: &proof_hex,
    };
    serde_json::to_vec(&response).map_err(|_| BrokerRuntimeError::TargetFailed)
}

fn probe_stability_observation(
    target: CoturnTarget,
    state: &WindowsCommittedState,
    observation: &TargetObservation,
) -> ProbeStabilityObservation {
    ProbeStabilityObservation {
        target,
        generation: state.generation,
        applied_secret_version: state.applied_secret_version,
        epoch: observation.epoch.clone(),
        active: observation.active && observation.healthy,
        draining: state.draining || observation.draining,
        external_restart_detected: state.external_restart_detected,
    }
}

async fn require_live_secret_allocation(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    raw_secret: &[u8],
    before: &TargetObservation,
    expected_version: u64,
    expected_config_sha256: &str,
) -> Result<(), BrokerRuntimeError> {
    if raw_secret.len() != 32 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let mut challenge = [0_u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    if challenge.iter().all(|byte| *byte == 0) {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let probe_urls = trusted_windows_probe_urls(target, broker_sid)?;
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerRuntimeError::TargetFailed)?
        .as_secs()
        .checked_add(60)
        .ok_or(BrokerRuntimeError::TargetFailed)?;
    let username = Zeroizing::new(format!(
        "{expiry}:mrd-apply-proof:{}:{}",
        hex(&challenge),
        target.target().as_str()
    ));
    let credentials = derive_coturn_rest_credentials(raw_secret, &username)
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let evidence = probe_turn_relay(TurnRelayProbeConfig {
        ice_servers: vec![IceServerConfig::new(
            probe_urls.to_vec(),
            credentials.username().to_owned(),
            credentials.credential().to_owned(),
        )],
        timeout: PROBE_TIMEOUT,
    })
    .await
    .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    if !evidence.has_relay_pair() || !evidence.control_round_trip() || !evidence.media_round_trip()
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let after = observe_target(target, broker_sid, None, false).await?;
    validate_live_allocation_target_stability(
        target.target(),
        before,
        &after,
        expected_version,
        expected_config_sha256,
    )?;
    Ok(())
}

fn trusted_windows_probe_urls(
    target: &WindowsTargetConfig,
    broker_sid: &str,
) -> Result<[String; 2], BrokerRuntimeError> {
    let baseline =
        read_hardened_target_file(target.baseline_path(), broker_sid, MAX_TARGET_OUTPUT_BYTES)?;
    windows_probe_urls_from_trusted_baseline(&baseline, target.configured_endpoints())
}

fn windows_probe_urls_from_trusted_baseline(
    trusted_baseline: &[u8],
    configured_endpoints: &[String],
) -> Result<[String; 2], BrokerRuntimeError> {
    let host = linux_probe_loopback_host(trusted_baseline)
        .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
    let port = strict_configured_turn_listener_port(configured_endpoints)
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    Ok([
        format!("turn:{host}:{port}?transport=udp"),
        format!("turn:{host}:{port}?transport=tcp"),
    ])
}

fn strict_configured_turn_listener_port(configured_endpoints: &[String]) -> Option<u16> {
    let mut udp = None;
    let mut tcp = None;
    for endpoint in configured_endpoints {
        let Some(remainder) = endpoint.strip_prefix("turn:") else {
            continue;
        };
        let (authority, transport) = remainder.split_once("?transport=")?;
        let port = strict_turn_authority_port(authority)?;
        let slot = match transport {
            "udp" => &mut udp,
            "tcp" => &mut tcp,
            _ => return None,
        };
        if slot.replace(port).is_some() {
            return None;
        }
    }
    match (udp, tcp) {
        (Some(udp), Some(tcp)) if udp == tcp => Some(udp),
        _ => None,
    }
}

fn strict_turn_authority_port(authority: &str) -> Option<u16> {
    let port = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed.split_once("]:")?;
        host.parse::<std::net::Ipv6Addr>().ok()?;
        port
    } else {
        let (host, port) = authority.rsplit_once(':')?;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        port
    };
    if port.is_empty() || port.starts_with('0') || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>()
        .ok()
        .filter(|parsed| *parsed != 0 && parsed.to_string() == port)
}

fn validate_live_allocation_target_stability(
    target: CoturnTarget,
    before: &TargetObservation,
    after: &TargetObservation,
    expected_version: u64,
    expected_config_sha256: &str,
) -> Result<(), BrokerRuntimeError> {
    if !before.active
        || !before.healthy
        || before.draining
        || !after.active
        || !after.healthy
        || after.draining
        || !valid_epoch(&before.epoch)
        || before.epoch != after.epoch
        || before.reported_generation.is_none()
        || before.reported_generation != after.reported_generation
        || before.counter_source != after.counter_source
        || before.measurement_monotonic_ns == 0
        || after.measurement_monotonic_ns < before.measurement_monotonic_ns
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let material_matches = match target {
        CoturnTarget::Docker => {
            !expected_config_sha256.is_empty()
                && before.config_sha256 == expected_config_sha256
                && after.config_sha256 == expected_config_sha256
        }
        CoturnTarget::WindowsService | CoturnTarget::Wsl2 => {
            expected_version != 0
                && before.reported_secret_version == Some(expected_version)
                && after.reported_secret_version == Some(expected_version)
        }
        CoturnTarget::LinuxSystemd => false,
    };
    if !material_matches {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(())
}

fn load_store_json<T: DeserializeOwned>(
    store: &BrokerStore,
) -> Result<Option<T>, BrokerRuntimeError> {
    let Some(payload) = store.load().map_err(|_| BrokerRuntimeError::StateInvalid)? else {
        return Ok(None);
    };
    if payload.is_empty() || payload.len() > MAX_STORE_PAYLOAD_BYTES {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

struct BoundedStoreJsonWriter<'a> {
    output: &'a mut Vec<u8>,
}

impl std::io::Write for BoundedStoreJsonWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_STORE_PAYLOAD_BYTES.saturating_sub(self.output.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "relay_broker_store_payload_too_large",
            ));
        }
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn store_json<T: Serialize>(store: &BrokerStore, value: &T) -> Result<(), BrokerRuntimeError> {
    let mut payload = Zeroizing::new(Vec::with_capacity(MAX_STORE_PAYLOAD_BYTES));
    let allocation_capacity = payload.capacity();
    serde_json::to_writer(
        &mut BoundedStoreJsonWriter {
            output: &mut payload,
        },
        value,
    )
    .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    if payload.is_empty()
        || payload.len() > MAX_STORE_PAYLOAD_BYTES
        || payload.capacity() != allocation_capacity
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    store
        .atomic_replace(&payload)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn load_state(
    stores: &WindowsBrokerStores,
) -> Result<Option<WindowsCommittedState>, BrokerRuntimeError> {
    load_store_json(&stores.state)
}

fn store_state(
    stores: &WindowsBrokerStores,
    state: &WindowsCommittedState,
) -> Result<(), BrokerRuntimeError> {
    validate_state(
        state,
        parse_target_name(&state.target).ok_or(BrokerRuntimeError::StateInvalid)?,
    )?;
    store_json(&stores.state, state)
}

fn load_active(
    stores: &WindowsBrokerStores,
) -> Result<Option<LoadedActiveSecret>, BrokerRuntimeError> {
    let Some(active): Option<ActiveSecretEnvelope> = load_store_json(&stores.active)? else {
        return Ok(None);
    };
    validate_active(&active)?;
    let raw = active.raw_secret_b64.decode_raw()?;
    if sha256_hex(&raw) != active.secret_sha256 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(Some((active, raw)))
}

fn store_active(
    stores: &WindowsBrokerStores,
    active: &ActiveSecretEnvelope,
) -> Result<(), BrokerRuntimeError> {
    validate_active(active)?;
    store_json(&stores.active, active)
}

fn load_journal(
    stores: &WindowsBrokerStores,
) -> Result<Option<WindowsPendingOperation>, BrokerRuntimeError> {
    let Some(journal): Option<WindowsJournalEnvelope> = load_store_json(&stores.journal)? else {
        return Ok(None);
    };
    classify_journal(journal)
}

fn classify_journal(
    journal: WindowsJournalEnvelope,
) -> Result<Option<WindowsPendingOperation>, BrokerRuntimeError> {
    if journal.schema_version != 1 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    match (journal.pending, journal.drain_pending) {
        (Some(pending), None) => {
            validate_pending(&pending)?;
            Ok(Some(WindowsPendingOperation::Secret(pending)))
        }
        (None, Some(pending)) => {
            validate_drain_pending(&pending)?;
            Ok(Some(WindowsPendingOperation::Drain(pending)))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(BrokerRuntimeError::StateInvalid),
    }
}

fn store_secret_journal(
    stores: &WindowsBrokerStores,
    pending: Option<WindowsPendingTransaction>,
) -> Result<(), BrokerRuntimeError> {
    if let Some(value) = pending.as_ref() {
        validate_pending(value)?;
    }
    store_json(
        &stores.journal,
        &WindowsJournalEnvelope {
            schema_version: 1,
            pending,
            drain_pending: None,
        },
    )
}

fn store_drain_journal(
    stores: &WindowsBrokerStores,
    pending: WindowsPendingDrainTransaction,
) -> Result<(), BrokerRuntimeError> {
    validate_drain_pending(&pending)?;
    store_json(
        &stores.journal,
        &WindowsJournalEnvelope {
            schema_version: 1,
            pending: None,
            drain_pending: Some(pending),
        },
    )
}

fn clear_journal(stores: &WindowsBrokerStores) -> Result<(), BrokerRuntimeError> {
    store_secret_journal(stores, None)
}

fn validate_state(
    state: &WindowsCommittedState,
    expected_target: CoturnTarget,
) -> Result<(), BrokerRuntimeError> {
    if state.schema_version != 1
        || state.target != expected_target.as_str()
        || state.generation == 0
        || state.applied_secret_version == 0
        || !valid_epoch(&state.target_epoch)
        || !valid_sha256_hex(&state.secret_sha256)
        || !valid_sha256_hex(&state.config_sha256)
        || (state.drain_completed && !state.draining)
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn validate_active(active: &ActiveSecretEnvelope) -> Result<(), BrokerRuntimeError> {
    if active.schema_version != 1
        || parse_target_name(&active.target).is_none()
        || active.version == 0
        || !valid_sha256_hex(&active.secret_sha256)
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let raw = active.raw_secret_b64.decode_raw()?;
    if sha256_hex(&raw) != active.secret_sha256 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn validate_active_against_state(
    active: &ActiveSecretEnvelope,
    state: &WindowsCommittedState,
    target: CoturnTarget,
) -> Result<(), BrokerRuntimeError> {
    if active.target != target.as_str()
        || active.version != state.applied_secret_version
        || active.secret_sha256 != state.secret_sha256
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn validate_pending(pending: &WindowsPendingTransaction) -> Result<(), BrokerRuntimeError> {
    let target = parse_target_name(&pending.target).ok_or(BrokerRuntimeError::StateInvalid)?;
    if pending.desired_version == 0
        || !valid_sha256_hex(&pending.desired_secret_sha256)
        || !valid_sha256_hex(&pending.desired_config_sha256)
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let raw = pending.desired_secret_b64.decode_raw()?;
    if sha256_hex(&raw) != pending.desired_secret_sha256 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    if let Some(state) = pending.previous_state.as_ref() {
        validate_state(state, target)?;
        if pending.desired_version
            != state
                .applied_secret_version
                .checked_add(1)
                .ok_or(BrokerRuntimeError::StateInvalid)?
        {
            return Err(BrokerRuntimeError::StateInvalid);
        }
    } else if pending.desired_version != 1 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    if let Some(active) = pending.previous_active.as_ref() {
        validate_active(active)?;
        let state = pending
            .previous_state
            .as_ref()
            .ok_or(BrokerRuntimeError::StateInvalid)?;
        validate_active_against_state(active, state, target)?;
    } else if pending.previous_state.is_some() {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    match (target, pending.docker_phase.as_ref()) {
        (CoturnTarget::Docker, Some(DockerSecretPhase::PersistGeneration { epoch }))
        | (CoturnTarget::Docker, Some(DockerSecretPhase::VerifyLive { epoch }))
            if !valid_epoch(epoch) =>
        {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        (CoturnTarget::Docker, _) => {}
        (_, None) => {}
        (_, Some(_)) => return Err(BrokerRuntimeError::StateInvalid),
    }
    Ok(())
}

fn validate_drain_pending(
    pending: &WindowsPendingDrainTransaction,
) -> Result<(), BrokerRuntimeError> {
    let target = parse_target_name(&pending.target).ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_state(&pending.previous_state, target)?;
    if pending.previous_state.target != pending.target
        || pending.previous_state.external_restart_detected
        || pending.previous_state.draining == pending.desired_draining
        || (!pending.desired_draining && !pending.previous_state.drain_completed)
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

async fn reconcile_pending(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
) -> Result<(), BrokerRuntimeError> {
    match load_journal(stores)? {
        None => Ok(()),
        Some(WindowsPendingOperation::Secret(pending)) => {
            reconcile_secret_pending(target, stores, broker_sid, pending).await
        }
        Some(WindowsPendingOperation::Drain(pending)) => {
            reconcile_drain_pending(target, stores, broker_sid, pending).await
        }
    }
}

async fn reconcile_secret_pending(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
    pending: WindowsPendingTransaction,
) -> Result<(), BrokerRuntimeError> {
    if pending.target != target.target().as_str() {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    if target.target() == CoturnTarget::Docker {
        return reconcile_docker_secret_pending(target, stores, broker_sid, pending).await;
    }
    let current_state = load_state(stores)?;
    let current_active = load_active(stores)?.map(|(active, _)| active);
    let observation = match observe_target(
        target,
        broker_sid,
        current_state.as_ref().or(pending.previous_state.as_ref()),
        pending.previous_state.is_none(),
    )
    .await
    {
        Ok(observation) => Some(observation),
        Err(_) if pending.previous_state.is_none() => None,
        Err(error) => return Err(error),
    };
    let config_matches = observation.as_ref().is_some_and(|observed| {
        if target.target() == CoturnTarget::Docker {
            observed.config_sha256 == pending.desired_config_sha256
        } else {
            true
        }
    });
    let target_reports_desired = observation
        .as_ref()
        .is_some_and(|observed| observation_reports_desired(target.target(), observed, &pending));
    let recovery = select_windows_pending_recovery(&WindowsPendingRecoveryObservation {
        committed_marker_matches_desired: current_state.as_ref().is_some_and(|state| {
            state.target == pending.target
                && state.applied_secret_version == pending.desired_version
                && state.secret_sha256 == pending.desired_secret_sha256
                && state.config_sha256 == pending.desired_config_sha256
        }),
        active_secret_matches_desired: current_active.as_ref().is_some_and(|active| {
            active.target == pending.target
                && active.version == pending.desired_version
                && active.secret_sha256 == pending.desired_secret_sha256
        }),
        target_config_matches_desired: config_matches
            || (target.target() != CoturnTarget::Docker && observation.is_none()),
        target_reports_desired_version: target_reports_desired,
        previous_epoch: pending
            .previous_state
            .as_ref()
            .map(|state| state.target_epoch.clone()),
        current_epoch: observation.as_ref().map(|observed| observed.epoch.clone()),
        target_active: observation.as_ref().is_some_and(|observed| observed.active),
    });
    match recovery {
        WindowsPendingRecoveryAction::RemoveJournal => {
            let observed = observation
                .as_ref()
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            let committed_generation = current_state
                .as_ref()
                .map(|state| state.generation)
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            require_reported_generation(observed, committed_generation)?;
            let raw = pending.desired_secret_b64.decode_raw()?;
            require_live_secret_allocation(
                target,
                broker_sid,
                &raw,
                observed,
                pending.desired_version,
                &pending.desired_config_sha256,
            )
            .await?;
            clear_journal(stores)
        }
        WindowsPendingRecoveryAction::CommitDesired => {
            let observed = observation.ok_or(BrokerRuntimeError::StateInvalid)?;
            let raw = pending.desired_secret_b64.decode_raw()?;
            require_live_secret_allocation(
                target,
                broker_sid,
                &raw,
                &observed,
                pending.desired_version,
                &pending.desired_config_sha256,
            )
            .await?;
            let generation = pending
                .previous_state
                .as_ref()
                .map_or(Some(1), |state| state.generation.checked_add(1))
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            commit_pending(stores, target, pending, observed, generation)
        }
        WindowsPendingRecoveryAction::RetryDesired => {
            let raw = pending.desired_secret_b64.decode_raw()?;
            let generation = pending
                .previous_state
                .as_ref()
                .map_or(Some(1), |state| state.generation.checked_add(1))
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            let mut pending = pending;
            let state_hint = pending.previous_state.clone();
            let observed = apply_target(
                target,
                broker_sid,
                pending.desired_version,
                &raw,
                state_hint.as_ref(),
                generation,
                Some((stores, &mut pending)),
            )
            .await?;
            if !observed.active
                || !observation_reports_desired(target.target(), &observed, &pending)
            {
                return Err(BrokerRuntimeError::TargetFailed);
            }
            require_live_secret_allocation(
                target,
                broker_sid,
                &raw,
                &observed,
                pending.desired_version,
                &pending.desired_config_sha256,
            )
            .await?;
            commit_pending(stores, target, pending, observed, generation)
        }
        WindowsPendingRecoveryAction::FailClosed => Err(BrokerRuntimeError::StateInvalid),
    }
}

async fn reconcile_docker_secret_pending(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
    mut pending: WindowsPendingTransaction,
) -> Result<(), BrokerRuntimeError> {
    let current_state = load_state(stores)?;
    let current_active = load_active(stores)?.map(|(active, _)| active);
    let committed_desired = current_state.as_ref().is_some_and(|state| {
        state.target == pending.target
            && state.applied_secret_version == pending.desired_version
            && state.secret_sha256 == pending.desired_secret_sha256
            && state.config_sha256 == pending.desired_config_sha256
    });
    let active_desired = current_active.as_ref().is_some_and(|active| {
        active.target == pending.target
            && active.version == pending.desired_version
            && active.secret_sha256 == pending.desired_secret_sha256
    });
    let raw = pending.desired_secret_b64.decode_raw()?;
    if committed_desired {
        if !active_desired {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        let state = current_state
            .as_ref()
            .ok_or(BrokerRuntimeError::StateInvalid)?;
        let observed = observe_docker(target, broker_sid, Some(state), false).await?;
        require_reported_generation(&observed, state.generation)?;
        require_live_secret_allocation(
            target,
            broker_sid,
            &raw,
            &observed,
            pending.desired_version,
            &pending.desired_config_sha256,
        )
        .await?;
        return clear_journal(stores);
    }
    if pending.docker_phase.is_none()
        || current_state != pending.previous_state
        || !active_matches_previous_or_desired(
            current_active.as_ref(),
            pending.previous_active.as_ref(),
            &pending,
        )
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let generation = pending
        .previous_state
        .as_ref()
        .map_or(Some(1), |state| state.generation.checked_add(1))
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    let state_hint = pending.previous_state.clone();
    let observed = apply_target(
        target,
        broker_sid,
        pending.desired_version,
        &raw,
        state_hint.as_ref(),
        generation,
        Some((stores, &mut pending)),
    )
    .await?;
    if !observed.active
        || state_hint
            .as_ref()
            .is_some_and(|state| observed.epoch == state.target_epoch)
        || observed.config_sha256 != pending.desired_config_sha256
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    require_live_secret_allocation(
        target,
        broker_sid,
        &raw,
        &observed,
        pending.desired_version,
        &pending.desired_config_sha256,
    )
    .await?;
    commit_pending(stores, target, pending, observed, generation)
}

fn active_matches_previous_or_desired(
    current: Option<&ActiveSecretEnvelope>,
    previous: Option<&ActiveSecretEnvelope>,
    pending: &WindowsPendingTransaction,
) -> bool {
    let same = |left: &ActiveSecretEnvelope, right: &ActiveSecretEnvelope| {
        left.schema_version == right.schema_version
            && left.target == right.target
            && left.version == right.version
            && left.secret_sha256 == right.secret_sha256
            && left.raw_secret_b64 == right.raw_secret_b64
    };
    match current {
        Some(current) => {
            previous.is_some_and(|previous| same(current, previous))
                || (current.target == pending.target
                    && current.version == pending.desired_version
                    && current.secret_sha256 == pending.desired_secret_sha256
                    && current.raw_secret_b64 == pending.desired_secret_b64)
        }
        None => previous.is_none(),
    }
}

async fn reconcile_drain_pending(
    target: &WindowsTargetConfig,
    stores: &WindowsBrokerStores,
    broker_sid: &str,
    pending: WindowsPendingDrainTransaction,
) -> Result<(), BrokerRuntimeError> {
    validate_drain_pending(&pending)?;
    if pending.target != target.target().as_str() {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let current = load_state(stores)?.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_state(&current, target.target())?;
    let (active, _) = load_active(stores)?.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_active_against_state(&active, &current, target.target())?;
    if !same_committed_material(&current, &pending.previous_state) {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    validate_drain_outer_state(&current, &pending.previous_state)?;

    let mut observation_hint = current.clone();
    if pending.desired_draining {
        // Docker cannot expose the SIGUSR1 latch directly. A desired-state
        // hint allows inspection of an exact clean exit without requiring the
        // container to still be running; the selector below still requires
        // completion evidence before it treats the action as applied.
        observation_hint.draining = true;
        observation_hint.drain_completed = false;
    }
    let mut observed = observe_target(target, broker_sid, Some(&observation_hint), false).await?;
    validate_drain_recovery_observation(target, &pending.previous_state, &observed)?;
    let reported_generation = observed
        .reported_generation
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    let action = select_drain_recovery(
        target.target(),
        pending.desired_draining,
        pending.previous_state.generation,
        &pending.previous_state.target_epoch,
        current.generation,
        &current.target_epoch,
        current.draining,
        reported_generation,
        &observed.epoch,
        observed.draining,
        observed.drain_completed,
        observed.active,
    )?;
    match action {
        DrainRecoveryAction::RemoveJournal => clear_journal(stores),
        DrainRecoveryAction::CommitObserved => {
            let next_generation = pending
                .previous_state
                .generation
                .checked_add(1)
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            if target.target() == CoturnTarget::Docker
                && !pending.desired_draining
                && reported_generation == pending.previous_state.generation
            {
                advance_docker_identity_generation(
                    target,
                    broker_sid,
                    pending.previous_state.generation,
                    next_generation,
                )?;
                observed.reported_generation = Some(next_generation);
            }
            observed.draining = pending.desired_draining;
            if !pending.desired_draining {
                observed.drain_completed = false;
            }
            commit_drain_transition(stores, target, pending, observed)
        }
        DrainRecoveryAction::ReplayTarget => {
            let next_generation = if pending.desired_draining {
                pending.previous_state.generation
            } else {
                pending
                    .previous_state
                    .generation
                    .checked_add(1)
                    .ok_or(BrokerRuntimeError::StateInvalid)?
            };
            let observed = set_target_draining(
                target,
                broker_sid,
                pending.desired_draining,
                Some(&pending.previous_state),
                next_generation,
            )
            .await?;
            commit_drain_transition(stores, target, pending, observed)
        }
    }
}

fn same_committed_material(
    current: &WindowsCommittedState,
    previous: &WindowsCommittedState,
) -> bool {
    current.schema_version == previous.schema_version
        && current.target == previous.target
        && current.applied_secret_version == previous.applied_secret_version
        && current.secret_sha256 == previous.secret_sha256
        && current.config_sha256 == previous.config_sha256
        && !current.external_restart_detected
}

fn validate_drain_outer_state(
    current: &WindowsCommittedState,
    previous: &WindowsCommittedState,
) -> Result<(), BrokerRuntimeError> {
    let same_lifecycle = current.generation == previous.generation
        && current.target_epoch == previous.target_epoch
        && current.draining == previous.draining;
    if same_lifecycle && current.drain_completed != previous.drain_completed {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn validate_drain_recovery_observation(
    target: &WindowsTargetConfig,
    previous: &WindowsCommittedState,
    observation: &TargetObservation,
) -> Result<(), BrokerRuntimeError> {
    if !valid_epoch(&observation.epoch)
        || observation.reported_generation.is_none()
        || observation.measurement_monotonic_ns == 0
        || (observation.drain_completed
            && (!observation.draining || observation.active_allocations != 0))
        || (!observation.active && !observation.drain_completed)
        || (target.target() != CoturnTarget::Docker
            && observation.reported_secret_version != Some(previous.applied_secret_version))
        || (target.target() == CoturnTarget::Docker
            && observation.config_sha256 != previous.config_sha256)
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(())
}

fn commit_drain_transition(
    stores: &WindowsBrokerStores,
    target: &WindowsTargetConfig,
    pending: WindowsPendingDrainTransaction,
    observation: TargetObservation,
) -> Result<(), BrokerRuntimeError> {
    let mut state = pending.previous_state;
    let expected_generation = if pending.desired_draining {
        state.generation
    } else {
        state
            .generation
            .checked_add(1)
            .ok_or(BrokerRuntimeError::StateInvalid)?
    };
    require_reported_generation(&observation, expected_generation)?;
    require_reported_version(target.target(), &observation, state.applied_secret_version)?;
    if target.target() == CoturnTarget::Docker && observation.config_sha256 != state.config_sha256 {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    if pending.desired_draining {
        if observation.epoch != state.target_epoch || !observation.draining {
            return Err(BrokerRuntimeError::TargetFailed);
        }
    } else if !observation.active || observation.epoch == state.target_epoch || observation.draining
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    state.generation = expected_generation;
    state.target_epoch = observation.epoch;
    state.draining = pending.desired_draining;
    state.drain_completed = pending.desired_draining && observation.drain_completed;
    state.external_restart_detected = false;
    store_state(stores, &state)?;
    clear_journal(stores)
}

fn commit_pending(
    stores: &WindowsBrokerStores,
    target: &WindowsTargetConfig,
    pending: WindowsPendingTransaction,
    observation: TargetObservation,
    generation: u64,
) -> Result<(), BrokerRuntimeError> {
    if !observation.active || !valid_epoch(&observation.epoch) {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    require_reported_generation(&observation, generation)?;
    let active = ActiveSecretEnvelope {
        schema_version: 1,
        target: pending.target.clone(),
        version: pending.desired_version,
        raw_secret_b64: pending.desired_secret_b64.clone(),
        secret_sha256: pending.desired_secret_sha256.clone(),
    };
    store_active(stores, &active)?;
    let state = WindowsCommittedState {
        schema_version: 1,
        target: target.target().as_str().to_owned(),
        generation,
        applied_secret_version: pending.desired_version,
        target_epoch: observation.epoch,
        secret_sha256: pending.desired_secret_sha256.clone(),
        config_sha256: pending.desired_config_sha256.clone(),
        draining: false,
        drain_completed: false,
        external_restart_detected: false,
    };
    store_state(stores, &state)?;
    clear_journal(stores)
}

fn observation_reports_desired(
    target: CoturnTarget,
    observation: &TargetObservation,
    pending: &WindowsPendingTransaction,
) -> bool {
    if target == CoturnTarget::Docker {
        observation.config_sha256 == pending.desired_config_sha256
    } else {
        observation.reported_secret_version == Some(pending.desired_version)
    }
}

async fn observe_target(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    state_hint: Option<&WindowsCommittedState>,
    allow_fresh_name_recovery: bool,
) -> Result<TargetObservation, BrokerRuntimeError> {
    match target.target() {
        CoturnTarget::WindowsService | CoturnTarget::Wsl2 => {
            execute_delegated(target, BrokerRequest::snapshot(target.target()), state_hint).await
        }
        CoturnTarget::Docker => {
            observe_docker(target, broker_sid, state_hint, allow_fresh_name_recovery).await
        }
        CoturnTarget::LinuxSystemd => Err(BrokerRuntimeError::ConfigInvalid),
    }
}

async fn restart_target(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    state_hint: Option<&WindowsCommittedState>,
    next_generation: u64,
) -> Result<TargetObservation, BrokerRuntimeError> {
    match target.target() {
        CoturnTarget::WindowsService | CoturnTarget::Wsl2 => {
            execute_delegated(target, BrokerRequest::restart(target.target()), state_hint).await
        }
        CoturnTarget::Docker => {
            let identity = load_docker_identity(target, broker_sid)?
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            verify_identity_generation(&identity, state_hint)?;
            execute_docker(
                target,
                [
                    "restart".to_owned(),
                    "--time".to_owned(),
                    "30".to_owned(),
                    identity.container_id.clone(),
                ],
            )
            .await?;
            let mut next = identity;
            next.generation = next_generation;
            store_docker_identity(target, broker_sid, &next)?;
            observe_docker(target, broker_sid, state_hint, false).await
        }
        CoturnTarget::LinuxSystemd => Err(BrokerRuntimeError::ConfigInvalid),
    }
}

async fn apply_target(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    version: u64,
    raw_secret: &[u8],
    state_hint: Option<&WindowsCommittedState>,
    next_generation: u64,
    docker_journal: Option<(&WindowsBrokerStores, &mut WindowsPendingTransaction)>,
) -> Result<TargetObservation, BrokerRuntimeError> {
    match target.target() {
        CoturnTarget::WindowsService | CoturnTarget::Wsl2 => {
            let request = BrokerRequest::apply_secret(
                target.target(),
                version,
                SecretBytes::new(raw_secret.to_vec()),
            )
            .map_err(|_| BrokerRuntimeError::FrameInvalid)?;
            execute_delegated(target, request, state_hint).await
        }
        CoturnTarget::Docker => {
            let (stores, pending) = docker_journal.ok_or(BrokerRuntimeError::StateInvalid)?;
            apply_docker(
                target,
                broker_sid,
                raw_secret,
                state_hint,
                next_generation,
                stores,
                pending,
            )
            .await
        }
        CoturnTarget::LinuxSystemd => Err(BrokerRuntimeError::ConfigInvalid),
    }
}

async fn set_target_draining(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    draining: bool,
    state_hint: Option<&WindowsCommittedState>,
    next_generation: u64,
) -> Result<TargetObservation, BrokerRuntimeError> {
    match target.target() {
        CoturnTarget::WindowsService | CoturnTarget::Wsl2 => {
            execute_delegated(
                target,
                BrokerRequest::set_draining(target.target(), draining),
                state_hint,
            )
            .await
        }
        CoturnTarget::Docker => {
            let identity = load_docker_identity(target, broker_sid)?
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            verify_identity_generation(&identity, state_hint)?;
            let arguments = if draining {
                vec![
                    "kill".to_owned(),
                    "--signal".to_owned(),
                    "SIGUSR1".to_owned(),
                    identity.container_id.clone(),
                ]
            } else {
                vec![
                    "restart".to_owned(),
                    "--time".to_owned(),
                    "30".to_owned(),
                    identity.container_id.clone(),
                ]
            };
            execute_docker(target, arguments).await?;
            if !draining {
                let mut next = identity;
                next.generation = next_generation;
                store_docker_identity(target, broker_sid, &next)?;
            }
            let desired_state_hint = state_hint.cloned().map(|mut state| {
                state.draining = draining;
                state.drain_completed = false;
                state
            });
            let mut observed =
                observe_docker(target, broker_sid, desired_state_hint.as_ref(), false).await?;
            observed.draining = draining;
            observed.drain_completed =
                draining && observed.active && observed.healthy && observed.active_allocations == 0;
            Ok(observed)
        }
        CoturnTarget::LinuxSystemd => Err(BrokerRuntimeError::ConfigInvalid),
    }
}

async fn execute_delegated(
    target: &WindowsTargetConfig,
    request: BrokerRequest,
    state_hint: Option<&WindowsCommittedState>,
) -> Result<TargetObservation, BrokerRuntimeError> {
    if let Some(expected) = target.native_expected_hashes() {
        verify_file_sha256(expected.wrapper, expected.wrapper_sha256)?;
        verify_authenticode_signer(expected.wrapper, expected.wrapper_signer)?;
        verify_file_sha256(expected.coturn_binary, expected.coturn_sha256)?;
    }
    let plan = target_command_plan(&target.broker_config(None), request)
        .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
    let output = tokio::time::timeout(TARGET_TIMEOUT, StdCommandExecutor.execute(plan))
        .await
        .map_err(|_| BrokerRuntimeError::TargetFailed)?
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    parse_delegated_snapshot(target, output, state_hint)
}

fn parse_delegated_snapshot(
    target: &WindowsTargetConfig,
    output: CommandOutput,
    state_hint: Option<&WindowsCommittedState>,
) -> Result<TargetObservation, BrokerRuntimeError> {
    if output.exit_code() != 0
        || output.stdout().is_empty()
        || output.stdout().len() > MAX_CONTROL_OUTPUT_BYTES
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let snapshot: DelegatedSnapshot =
        serde_json::from_slice(output.stdout()).map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let expected_source = match target.target() {
        CoturnTarget::WindowsService => TrafficCounterSource::WindowsVerifiedWrapper,
        CoturnTarget::Wsl2 => TrafficCounterSource::WslSystemdIpAccounting,
        _ => return Err(BrokerRuntimeError::ConfigInvalid),
    };
    if snapshot.target != target.target().as_str()
        || snapshot.generation == 0
        || snapshot.applied_secret_version == 0
        || !matches!(snapshot.health.as_str(), "healthy" | "degraded" | "failed")
        || snapshot.counter_source != expected_source
        || !valid_epoch(&snapshot.counter_epoch)
        || snapshot.measurement_monotonic_ns == 0
        || snapshot.configured_max_allocations != target.max_allocations()
        || snapshot.configured_max_egress_bps != target.max_egress_bps()
        || snapshot.relay_min_port != target.relay_ports().0
        || snapshot.relay_max_port != target.relay_ports().1
        || snapshot.transport_capabilities != target.transport_capabilities()
        || snapshot.configured_endpoints != target.configured_endpoints()
        || (snapshot.drain_completed && (!snapshot.draining || snapshot.active_allocations != 0))
        || state_hint
            .is_some_and(|state| snapshot.applied_secret_version < state.applied_secret_version)
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(TargetObservation {
        reported_generation: Some(snapshot.generation),
        epoch: snapshot.counter_epoch,
        active: snapshot.health != "failed",
        healthy: snapshot.health == "healthy",
        active_allocations: snapshot.active_allocations,
        counter_source: snapshot.counter_source,
        total_ingress_bytes: snapshot.total_ingress_bytes,
        total_egress_bytes: snapshot.total_egress_bytes,
        measurement_monotonic_ns: snapshot.measurement_monotonic_ns,
        reported_secret_version: Some(snapshot.applied_secret_version),
        config_sha256: state_hint.map_or_else(String::new, |state| state.config_sha256.clone()),
        draining: snapshot.draining,
        drain_completed: snapshot.drain_completed,
    })
}

fn require_new_epoch(
    before: &TargetObservation,
    after: &TargetObservation,
) -> Result<(), BrokerRuntimeError> {
    if !after.active || after.epoch == before.epoch {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(())
}

fn require_reported_generation(
    observation: &TargetObservation,
    expected: u64,
) -> Result<(), BrokerRuntimeError> {
    let reported = observation
        .reported_generation
        .ok_or(BrokerRuntimeError::TargetFailed)?;
    validate_windows_delegated_generation(reported, expected)
        .map_err(|_| BrokerRuntimeError::TargetFailed)
}

fn require_reported_version(
    target: CoturnTarget,
    observation: &TargetObservation,
    expected: u64,
) -> Result<(), BrokerRuntimeError> {
    if target != CoturnTarget::Docker && observation.reported_secret_version != Some(expected) {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(())
}

fn validate_observation(
    target: &WindowsTargetConfig,
    state: &WindowsCommittedState,
    observation: &TargetObservation,
) -> Result<(), BrokerRuntimeError> {
    let lifecycle_valid = observation.active || (state.draining && observation.drain_completed);
    if !lifecycle_valid
        || !valid_epoch(&observation.epoch)
        || observation.measurement_monotonic_ns == 0
        || observation.draining != state.draining
        || (observation.drain_completed && (!state.draining || observation.active_allocations != 0))
        || (target.target() != CoturnTarget::Docker
            && observation.reported_secret_version != Some(state.applied_secret_version))
        || (target.target() == CoturnTarget::Docker
            && observation.config_sha256 != state.config_sha256)
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DockerInspectSummary {
    id: String,
    image_id: String,
    image_reference: String,
    name: String,
    labels: BTreeMap<String, String>,
    path: String,
    args: Vec<String>,
    user: String,
    privileged: bool,
    cap_add: Option<Vec<String>>,
    cap_drop: Option<Vec<String>>,
    network_mode: String,
    pid_mode: String,
    ipc_mode: String,
    userns_mode: String,
    devices: Option<Vec<serde_json::Value>>,
    publish_all_ports: bool,
    port_bindings: BTreeMap<String, Option<Vec<DockerInspectPortBinding>>>,
    security_opt: Vec<String>,
    restart_policy: String,
    readonly_rootfs: bool,
    running: bool,
    status: String,
    exit_code: i64,
    started_at: String,
    mounts: Vec<DockerInspectMount>,
}

#[derive(Deserialize, Serialize)]
struct DockerInspectMount {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Source")]
    source: PathBuf,
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "RW")]
    read_write: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DockerInspectPortBinding {
    #[serde(rename = "HostIp")]
    host_ip: String,
    #[serde(rename = "HostPort")]
    host_port: String,
}

async fn apply_docker(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    raw_secret: &[u8],
    state_hint: Option<&WindowsCommittedState>,
    next_generation: u64,
    stores: &WindowsBrokerStores,
    pending: &mut WindowsPendingTransaction,
) -> Result<TargetObservation, BrokerRuntimeError> {
    loop {
        let phase = pending
            .docker_phase
            .clone()
            .ok_or(BrokerRuntimeError::StateInvalid)?;
        match phase {
            DockerSecretPhase::VerifyIdentity => {
                let verified =
                    prepare_docker_apply_target(target, broker_sid, next_generation, pending)
                        .await?;
                let action = select_docker_secret_recovery(
                    &DockerSecretPhase::VerifyIdentity,
                    state_hint.map(|state| state.target_epoch.as_str()),
                    Some(&verified.epoch),
                    verified.running,
                    Some(verified.identity.generation),
                    next_generation,
                )?;
                if action != DockerSecretRecoveryAction::VerifyIdentity {
                    return Err(BrokerRuntimeError::StateInvalid);
                }
                store_docker_secret_phase(stores, pending, DockerSecretPhase::WriteDesiredConfig)?;
            }
            DockerSecretPhase::WriteDesiredConfig => {
                verify_before_docker_secret_write(
                    prepare_docker_apply_target(target, broker_sid, next_generation, pending),
                    |_| write_docker_secret_material(target, broker_sid, raw_secret),
                )
                .await?;
                store_docker_secret_phase(stores, pending, DockerSecretPhase::RestartTarget)?;
            }
            DockerSecretPhase::RestartTarget => {
                require_desired_docker_host_config(target, broker_sid, pending)?;
                let verified =
                    prepare_docker_apply_target(target, broker_sid, next_generation, pending)
                        .await?;
                let action = select_docker_secret_recovery(
                    &DockerSecretPhase::RestartTarget,
                    state_hint.map(|state| state.target_epoch.as_str()),
                    Some(&verified.epoch),
                    verified.running,
                    Some(verified.identity.generation),
                    next_generation,
                )?;
                let restarted = match action {
                    DockerSecretRecoveryAction::RestartTarget => {
                        if verified.running {
                            execute_docker(
                                target,
                                [
                                    "restart".to_owned(),
                                    "--time".to_owned(),
                                    "30".to_owned(),
                                    verified.identity.container_id.clone(),
                                ],
                            )
                            .await?;
                        } else {
                            execute_docker(
                                target,
                                ["start".to_owned(), verified.identity.container_id.clone()],
                            )
                            .await?;
                        }
                        let restarted = prepare_docker_apply_target(
                            target,
                            broker_sid,
                            next_generation,
                            pending,
                        )
                        .await?;
                        if !restarted.running
                            || state_hint.is_some_and(|state| restarted.epoch == state.target_epoch)
                        {
                            return Err(BrokerRuntimeError::TargetFailed);
                        }
                        restarted
                    }
                    DockerSecretRecoveryAction::PersistGeneration => verified,
                    _ => return Err(BrokerRuntimeError::StateInvalid),
                };
                store_docker_secret_phase(
                    stores,
                    pending,
                    DockerSecretPhase::PersistGeneration {
                        epoch: restarted.epoch,
                    },
                )?;
            }
            DockerSecretPhase::PersistGeneration { ref epoch } => {
                require_desired_docker_host_config(target, broker_sid, pending)?;
                let mut verified =
                    prepare_docker_apply_target(target, broker_sid, next_generation, pending)
                        .await?;
                let action = select_docker_secret_recovery(
                    &phase,
                    state_hint.map(|state| state.target_epoch.as_str()),
                    Some(&verified.epoch),
                    verified.running,
                    Some(verified.identity.generation),
                    next_generation,
                )?;
                if action == DockerSecretRecoveryAction::PersistGeneration {
                    verified.identity.generation = next_generation;
                    store_docker_identity(target, broker_sid, &verified.identity)?;
                } else if action != DockerSecretRecoveryAction::VerifyLive {
                    return Err(BrokerRuntimeError::StateInvalid);
                }
                store_docker_secret_phase(
                    stores,
                    pending,
                    DockerSecretPhase::VerifyLive {
                        epoch: epoch.clone(),
                    },
                )?;
            }
            DockerSecretPhase::VerifyLive { ref epoch } => {
                require_desired_docker_host_config(target, broker_sid, pending)?;
                let verified =
                    prepare_docker_apply_target(target, broker_sid, next_generation, pending)
                        .await?;
                if select_docker_secret_recovery(
                    &phase,
                    state_hint.map(|state| state.target_epoch.as_str()),
                    Some(&verified.epoch),
                    verified.running,
                    Some(verified.identity.generation),
                    next_generation,
                )? != DockerSecretRecoveryAction::VerifyLive
                {
                    return Err(BrokerRuntimeError::StateInvalid);
                }
                let observed = observe_docker(target, broker_sid, state_hint, false).await?;
                if observed.epoch != *epoch
                    || observed.config_sha256 != pending.desired_config_sha256
                {
                    return Err(BrokerRuntimeError::TargetFailed);
                }
                return Ok(observed);
            }
        }
    }
}

struct VerifiedDockerApplyTarget {
    identity: DockerIdentity,
    running: bool,
    epoch: String,
}

fn store_docker_secret_phase(
    stores: &WindowsBrokerStores,
    pending: &mut WindowsPendingTransaction,
    phase: DockerSecretPhase,
) -> Result<(), BrokerRuntimeError> {
    pending.docker_phase = Some(phase);
    store_secret_journal(stores, Some(pending.clone()))
}

fn require_desired_docker_host_config(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    pending: &WindowsPendingTransaction,
) -> Result<(), BrokerRuntimeError> {
    let configured = read_hardened_target_file(
        target
            .docker_config_source()
            .ok_or(BrokerRuntimeError::ConfigInvalid)?,
        broker_sid,
        MAX_TARGET_OUTPUT_BYTES,
    )?;
    if sha256_hex(&configured) != pending.desired_config_sha256 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

async fn verify_before_docker_secret_write<T, F, Fut>(
    verification: Fut,
    write_secret: F,
) -> Result<T, BrokerRuntimeError>
where
    Fut: std::future::Future<Output = Result<T, BrokerRuntimeError>>,
    F: FnOnce(&T) -> Result<(), BrokerRuntimeError>,
{
    let verified = verification.await?;
    write_secret(&verified)?;
    Ok(verified)
}

async fn prepare_docker_apply_target(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    next_generation: u64,
    pending: &WindowsPendingTransaction,
) -> Result<VerifiedDockerApplyTarget, BrokerRuntimeError> {
    require_docker_host_config_phase(target, broker_sid, pending)?;
    let image_id = docker_image_id(target).await?;
    let mut identity = load_docker_identity(target, broker_sid)?;
    if identity.is_none() {
        if pending.previous_state.is_some()
            || !matches!(
                pending.docker_phase,
                Some(DockerSecretPhase::VerifyIdentity)
            )
        {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        identity = recover_fresh_docker_identity(target, &image_id, next_generation).await?;
        if let Some(recovered) = identity.as_ref() {
            store_docker_identity(target, broker_sid, recovered)?;
        }
    }
    if identity.is_none() {
        let output = execute_plan(
            target
                .docker_fresh_create_plan()
                .map_err(|_| BrokerRuntimeError::ConfigInvalid)?,
        )
        .await?;
        let container_id = parse_single_container_id(output.stdout())?;
        let inspected = docker_inspect_raw(target, &container_id).await?;
        validate_docker_inspect(target, &inspected, Some(&container_id), &image_id, false)?;
        let created = DockerIdentity {
            schema_version: 1,
            target: "docker".to_owned(),
            container_id,
            image_id: image_id.clone(),
            image_reference: target
                .docker_image()
                .ok_or(BrokerRuntimeError::ConfigInvalid)?
                .to_owned(),
            generation: next_generation,
        };
        store_docker_identity(target, broker_sid, &created)?;
        identity = Some(created);
    }
    let identity = identity.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_docker_identity(target, &identity)?;
    if identity.image_id != image_id
        || !recoverable_docker_apply_generation(identity.generation, next_generation)
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let inspected = docker_inspect_raw(target, &identity.container_id).await?;
    validate_docker_inspect(
        target,
        &inspected,
        Some(&identity.container_id),
        &identity.image_id,
        false,
    )?;
    Ok(VerifiedDockerApplyTarget {
        identity,
        running: inspected.running,
        epoch: format!("{}:{}", inspected.id, inspected.started_at),
    })
}

fn require_docker_host_config_phase(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    pending: &WindowsPendingTransaction,
) -> Result<(), BrokerRuntimeError> {
    let configured = read_hardened_target_file(
        target
            .docker_config_source()
            .ok_or(BrokerRuntimeError::ConfigInvalid)?,
        broker_sid,
        MAX_TARGET_OUTPUT_BYTES,
    )?;
    let phase = pending
        .docker_phase
        .as_ref()
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    let previous = pending
        .previous_state
        .as_ref()
        .map(|state| state.config_sha256.as_str());
    if !docker_host_config_allowed_for_phase(
        phase,
        previous,
        &pending.desired_config_sha256,
        &configured,
    ) {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn docker_host_config_allowed_for_phase(
    phase: &DockerSecretPhase,
    previous_config_sha256: Option<&str>,
    desired_config_sha256: &str,
    configured: &[u8],
) -> bool {
    let configured_sha256 = sha256_hex(configured);
    let matches_desired = configured_sha256 == desired_config_sha256;
    let matches_previous = previous_config_sha256 == Some(configured_sha256.as_str());
    let matches_fresh_placeholder =
        previous_config_sha256.is_none() && configured == DOCKER_FRESH_CONFIG_PLACEHOLDER;
    match phase {
        DockerSecretPhase::VerifyIdentity => matches_previous || matches_fresh_placeholder,
        DockerSecretPhase::WriteDesiredConfig => {
            matches_previous || matches_fresh_placeholder || matches_desired
        }
        DockerSecretPhase::RestartTarget
        | DockerSecretPhase::PersistGeneration { .. }
        | DockerSecretPhase::VerifyLive { .. } => matches_desired,
    }
}

fn write_docker_secret_material(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    raw_secret: &[u8],
) -> Result<(), BrokerRuntimeError> {
    let rendered = render_docker_material(target, broker_sid, raw_secret)?;
    let config_path = target
        .docker_config_source()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    hardened_target_file(config_path, broker_sid)?
        .atomic_replace(rendered.bytes(), MAX_TARGET_OUTPUT_BYTES)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn render_docker_material(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    raw_secret: &[u8],
) -> Result<crate::broker::RenderedCoturnConfig, BrokerRuntimeError> {
    let baseline =
        read_hardened_target_file(target.baseline_path(), broker_sid, MAX_TARGET_OUTPUT_BYTES)?;
    let rendered = render_coturn_config(
        &baseline,
        raw_secret,
        "/run/mrd/tls/fullchain.pem",
        "/run/mrd/tls/privkey.pem",
    )
    .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
    if rendered.configured_max_allocations() != target.max_allocations()
        || rendered.configured_max_egress_bps() != target.max_egress_bps()
        || rendered.relay_ports() != target.relay_ports()
        || rendered.transport_capabilities() != target.transport_capabilities()
        || rendered.configured_endpoints() != target.configured_endpoints()
    {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    Ok(rendered)
}

fn desired_config_sha256(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    version: u64,
    raw_secret: &[u8],
) -> Result<String, BrokerRuntimeError> {
    if target.target() == CoturnTarget::Docker {
        let rendered = render_docker_material(target, broker_sid, raw_secret)?;
        Ok(sha256_hex(rendered.bytes()))
    } else {
        let mut hasher = Sha256::new();
        hasher.update(b"MRD_DELEGATED_COTURN_CONFIG_V1\0");
        hasher.update(target.target().as_str().as_bytes());
        hasher.update(version.to_be_bytes());
        hasher.update(raw_secret);
        Ok(hex(&hasher.finalize()))
    }
}

async fn observe_docker(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    state_hint: Option<&WindowsCommittedState>,
    allow_fresh_name_recovery: bool,
) -> Result<TargetObservation, BrokerRuntimeError> {
    let identity = load_docker_identity(target, broker_sid)?;
    let reference = if let Some(identity) = identity.as_ref() {
        validate_docker_identity(target, identity)?;
        identity.container_id.as_str()
    } else if allow_fresh_name_recovery {
        target
            .docker_container_name()
            .ok_or(BrokerRuntimeError::ConfigInvalid)?
    } else {
        return Err(BrokerRuntimeError::StateInvalid);
    };
    let draining = state_hint.is_some_and(|state| state.draining);
    let require_running = !draining;
    let image_id = docker_image_id(target).await?;
    let inspected = docker_inspect(target, reference, require_running).await?;
    let expected_id = identity.as_ref().map(|value| value.container_id.as_str());
    validate_docker_inspect(target, &inspected, expected_id, &image_id, require_running)?;
    if let Some(identity) = identity.as_ref() {
        if identity.image_id != image_id || identity.container_id != inspected.id {
            return Err(BrokerRuntimeError::TargetFailed);
        }
        if let Some(state) = state_hint {
            if identity.generation != state.generation
                && identity.generation
                    != state
                        .generation
                        .checked_add(1)
                        .ok_or(BrokerRuntimeError::StateInvalid)?
            {
                return Err(BrokerRuntimeError::StateInvalid);
            }
        }
    }
    let counters = if inspected.running {
        Some(docker_engine_stats(&inspected.id).await?)
    } else {
        None
    };
    let generated = read_hardened_target_file(
        target
            .docker_config_source()
            .ok_or(BrokerRuntimeError::ConfigInvalid)?,
        broker_sid,
        MAX_TARGET_OUTPUT_BYTES,
    )?;
    let native = if inspected.running {
        native_scrape().await.ok()
    } else {
        None
    };
    let drain_completed = docker_drain_completed(
        draining,
        inspected.running,
        &inspected.status,
        inspected.exit_code,
        native.as_ref().map(|value| value.active_allocations),
    );
    Ok(TargetObservation {
        reported_generation: identity.as_ref().map(|identity| identity.generation),
        epoch: format!("{}:{}", inspected.id, inspected.started_at),
        active: inspected.running,
        healthy: inspected.running && native.is_some(),
        active_allocations: native.map_or(0, |value| value.active_allocations),
        counter_source: TrafficCounterSource::DockerEngineStats,
        total_ingress_bytes: counters
            .as_ref()
            .map_or(0, |value| value.total_ingress_bytes),
        total_egress_bytes: counters
            .as_ref()
            .map_or(0, |value| value.total_egress_bytes),
        measurement_monotonic_ns: monotonic_ns()?,
        reported_secret_version: None,
        config_sha256: sha256_hex(&generated),
        draining,
        drain_completed,
    })
}

async fn recover_fresh_docker_identity(
    target: &WindowsTargetConfig,
    image_id: &str,
    generation: u64,
) -> Result<Option<DockerIdentity>, BrokerRuntimeError> {
    let name = target
        .docker_container_name()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    let inspected = match docker_inspect_raw(target, name).await {
        Ok(inspected) => inspected,
        Err(BrokerRuntimeError::TargetFailed) => return Ok(None),
        Err(error) => return Err(error),
    };
    validate_docker_inspect(target, &inspected, None, image_id, false)?;
    Ok(Some(DockerIdentity {
        schema_version: 1,
        target: "docker".to_owned(),
        container_id: inspected.id,
        image_id: image_id.to_owned(),
        image_reference: target
            .docker_image()
            .ok_or(BrokerRuntimeError::ConfigInvalid)?
            .to_owned(),
        generation,
    }))
}

async fn execute_plan(plan: CommandPlan) -> Result<CommandOutput, BrokerRuntimeError> {
    execute_plan_with_limit(plan, MAX_CONTROL_OUTPUT_BYTES).await
}

async fn execute_plan_with_limit(
    plan: CommandPlan,
    output_limit: usize,
) -> Result<CommandOutput, BrokerRuntimeError> {
    let plan = plan
        .with_output_limit(output_limit)
        .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
    let output = tokio::time::timeout(TARGET_TIMEOUT, StdCommandExecutor.execute(plan))
        .await
        .map_err(|_| BrokerRuntimeError::TargetFailed)?
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    if output.exit_code() != 0 || output.stdout().len() > output_limit {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(output)
}

async fn execute_docker<I>(
    target: &WindowsTargetConfig,
    arguments: I,
) -> Result<CommandOutput, BrokerRuntimeError>
where
    I: IntoIterator<Item = String>,
{
    let executable = target
        .docker_executable()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    let plan =
        CommandPlan::new(executable, arguments).map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
    execute_plan(plan).await
}

async fn docker_image_id(target: &WindowsTargetConfig) -> Result<String, BrokerRuntimeError> {
    let image = target
        .docker_image()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    let output = execute_docker(
        target,
        [
            "image".to_owned(),
            "inspect".to_owned(),
            "--format".to_owned(),
            "{{.Id}}".to_owned(),
            image.to_owned(),
        ],
    )
    .await?;
    let value = one_ascii_line(output.stdout())?;
    if !valid_image_id(value) {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(value.to_owned())
}

async fn docker_inspect(
    target: &WindowsTargetConfig,
    reference: &str,
    require_running: bool,
) -> Result<DockerInspectSummary, BrokerRuntimeError> {
    let inspected = docker_inspect_raw(target, reference).await?;
    let image_id = docker_image_id(target).await?;
    validate_docker_inspect(target, &inspected, None, &image_id, require_running)?;
    Ok(inspected)
}

async fn docker_inspect_raw(
    target: &WindowsTargetConfig,
    reference: &str,
) -> Result<DockerInspectSummary, BrokerRuntimeError> {
    if reference != DOCKER_CONTAINER && !valid_container_id(reference) {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    const FORMAT: &str = concat!(
        "{\"id\":{{json .Id}},",
        "\"image_id\":{{json .Image}},",
        "\"image_reference\":{{json .Config.Image}},",
        "\"name\":{{json .Name}},",
        "\"labels\":{{json .Config.Labels}},",
        "\"path\":{{json .Path}},",
        "\"args\":{{json .Args}},",
        "\"user\":{{json .Config.User}},",
        "\"privileged\":{{json .HostConfig.Privileged}},",
        "\"cap_add\":{{json .HostConfig.CapAdd}},",
        "\"cap_drop\":{{json .HostConfig.CapDrop}},",
        "\"network_mode\":{{json .HostConfig.NetworkMode}},",
        "\"pid_mode\":{{json .HostConfig.PidMode}},",
        "\"ipc_mode\":{{json .HostConfig.IpcMode}},",
        "\"userns_mode\":{{json .HostConfig.UsernsMode}},",
        "\"devices\":{{json .HostConfig.Devices}},",
        "\"publish_all_ports\":{{json .HostConfig.PublishAllPorts}},",
        "\"port_bindings\":{{json .HostConfig.PortBindings}},",
        "\"security_opt\":{{json .HostConfig.SecurityOpt}},",
        "\"restart_policy\":{{json .HostConfig.RestartPolicy.Name}},",
        "\"readonly_rootfs\":{{json .HostConfig.ReadonlyRootfs}},",
        "\"running\":{{json .State.Running}},",
        "\"status\":{{json .State.Status}},",
        "\"exit_code\":{{json .State.ExitCode}},",
        "\"started_at\":{{json .State.StartedAt}},",
        "\"mounts\":{{json .Mounts}}}"
    );
    let output = execute_docker(
        target,
        [
            "inspect".to_owned(),
            "--type".to_owned(),
            "container".to_owned(),
            "--format".to_owned(),
            FORMAT.to_owned(),
            reference.to_owned(),
        ],
    )
    .await?;
    serde_json::from_slice(output.stdout()).map_err(|_| BrokerRuntimeError::TargetFailed)
}

fn validate_docker_inspect(
    target: &WindowsTargetConfig,
    inspected: &DockerInspectSummary,
    expected_container_id: Option<&str>,
    expected_image_id: &str,
    require_running: bool,
) -> Result<(), BrokerRuntimeError> {
    let expected_mounts = target
        .docker_mounts()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    let expected_ports = target
        .docker_published_ports()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    if !valid_container_id(&inspected.id)
        || expected_container_id.is_some_and(|value| value != inspected.id)
        || inspected.image_id != expected_image_id
        || inspected.image_reference != target.docker_image().unwrap_or_default()
        || inspected.name != format!("/{DOCKER_CONTAINER}")
        || validate_docker_process_spec(inspected).is_err()
        || inspected.restart_policy != "no"
        || !inspected.readonly_rootfs
        || (require_running && !inspected.running)
        || !matches!(inspected.status.as_str(), "created" | "running" | "exited")
        || inspected.started_at.is_empty()
        || inspected.started_at.len() > 128
        || !inspected.started_at.is_ascii()
        || inspected.mounts.len() != expected_mounts.len()
        || validate_docker_port_bindings(inspected, expected_ports).is_err()
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    if inspected.status == "exited" && inspected.exit_code != 0 {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    for (source, destination) in expected_mounts {
        let matching = inspected.mounts.iter().filter(|mount| {
            mount.kind == "bind"
                && windows_paths_equal(&mount.source, source)
                && mount.destination == destination
                && !mount.read_write
        });
        if matching.count() != 1 {
            return Err(BrokerRuntimeError::TargetFailed);
        }
    }
    Ok(())
}

fn validate_docker_process_spec(
    inspected: &DockerInspectSummary,
) -> Result<(), BrokerRuntimeError> {
    let expected_labels = BTreeMap::from([(
        WINDOWS_MANAGED_LABEL_KEY.to_owned(),
        WINDOWS_MANAGED_LABEL_VALUE.to_owned(),
    )]);
    if inspected.labels != expected_labels
        || inspected.path != DOCKER_ENTRYPOINT
        || inspected.args != [DOCKER_CONFIG_ARGUMENT, COTURN_CONFIG_DESTINATION]
        || inspected.user != DOCKER_USER
        || inspected.privileged
        || inspected
            .cap_add
            .as_ref()
            .is_some_and(|values| !values.is_empty())
        || !inspected
            .cap_drop
            .as_ref()
            .is_some_and(|values| values.len() == 1 && values[0] == DOCKER_CAP_DROP)
        || inspected.network_mode != DOCKER_NETWORK_MODE
        || !inspected.pid_mode.is_empty()
        || inspected.ipc_mode != DOCKER_IPC_MODE
        || !inspected.userns_mode.is_empty()
        || inspected
            .devices
            .as_ref()
            .is_some_and(|devices| !devices.is_empty())
        || inspected.publish_all_ports
        || inspected.security_opt != [DOCKER_SECURITY_OPTION]
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(())
}

fn validate_docker_port_bindings(
    inspected: &DockerInspectSummary,
    published_ports: &[String],
) -> Result<(), BrokerRuntimeError> {
    let mut expected = BTreeMap::new();
    for specification in published_ports {
        expand_expected_inspect_port(specification, &mut expected)?;
    }
    if inspected.port_bindings.len() != expected.len() {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    for (key, (expected_ip, expected_port)) in expected {
        let binding = inspected
            .port_bindings
            .get(&key)
            .and_then(Option::as_ref)
            .filter(|bindings| bindings.len() == 1)
            .and_then(|bindings| bindings.first())
            .ok_or(BrokerRuntimeError::TargetFailed)?;
        if binding.host_ip != expected_ip || binding.host_port != expected_port.to_string() {
            return Err(BrokerRuntimeError::TargetFailed);
        }
    }
    Ok(())
}

fn expand_expected_inspect_port(
    specification: &str,
    output: &mut BTreeMap<String, (String, u16)>,
) -> Result<(), BrokerRuntimeError> {
    let (mapping, protocol) = specification
        .rsplit_once('/')
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    if !matches!(protocol, "tcp" | "udp") {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    let parts: Vec<_> = mapping.split(':').collect();
    let (host_ip, host_range, container_range) = match parts.as_slice() {
        [host, container] => ("", *host, *container),
        [ip, host, container] => (*ip, *host, *container),
        _ => return Err(BrokerRuntimeError::ConfigInvalid),
    };
    let host_ports = parse_port_range(host_range)?;
    let container_ports = parse_port_range(container_range)?;
    if host_ports.len() != container_ports.len() {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    for (host_port, container_port) in host_ports.into_iter().zip(container_ports) {
        if output
            .insert(
                format!("{container_port}/{protocol}"),
                (host_ip.to_owned(), host_port),
            )
            .is_some()
        {
            return Err(BrokerRuntimeError::ConfigInvalid);
        }
    }
    Ok(())
}

fn parse_port_range(value: &str) -> Result<Vec<u16>, BrokerRuntimeError> {
    if let Some((first, last)) = value.split_once('-') {
        let first = first
            .parse::<u16>()
            .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
        let last = last
            .parse::<u16>()
            .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
        if first == 0 || first > last || usize::from(last - first) > 1024 {
            return Err(BrokerRuntimeError::ConfigInvalid);
        }
        Ok((first..=last).collect())
    } else {
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .map(|port| vec![port])
            .ok_or(BrokerRuntimeError::ConfigInvalid)
    }
}

async fn docker_engine_stats(
    container_id: &str,
) -> Result<crate::broker::DockerNetworkCounters, BrokerRuntimeError> {
    if !valid_container_id(container_id) {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    tokio::time::timeout(TARGET_TIMEOUT, async {
        let mut pipe = ClientOptions::new()
            .read(true)
            .write(true)
            .open(DOCKER_ENGINE_PIPE)
            .map_err(|_| BrokerRuntimeError::TargetFailed)?;
        let request = format!(
            "GET /v1.41/containers/{container_id}/stats?stream=false&one-shot=true HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        pipe.write_all(request.as_bytes())
            .await
            .map_err(|_| BrokerRuntimeError::TargetFailed)?;
        pipe.flush()
            .await
            .map_err(|_| BrokerRuntimeError::TargetFailed)?;
        let mut response = Vec::with_capacity(64 * 1024);
        pipe.take((MAX_TARGET_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .await
            .map_err(|_| BrokerRuntimeError::TargetFailed)?;
        if response.len() > MAX_TARGET_OUTPUT_BYTES {
            return Err(BrokerRuntimeError::TargetFailed);
        }
        parse_docker_engine_stats_http(&response).map_err(|_| BrokerRuntimeError::TargetFailed)
    })
    .await
    .map_err(|_| BrokerRuntimeError::TargetFailed)?
}

fn load_docker_identity(
    target: &WindowsTargetConfig,
    broker_sid: &str,
) -> Result<Option<DockerIdentity>, BrokerRuntimeError> {
    let path = target
        .docker_identity_path()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    let file = hardened_target_file(path, broker_sid)?;
    let Some(encoded) = file
        .read(MAX_STORE_PAYLOAD_BYTES)
        .map_err(|_| BrokerRuntimeError::StateInvalid)?
    else {
        return Ok(None);
    };
    let identity: DockerIdentity =
        serde_json::from_slice(&encoded).map_err(|_| BrokerRuntimeError::StateInvalid)?;
    validate_docker_identity(target, &identity)?;
    Ok(Some(identity))
}

fn store_docker_identity(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    identity: &DockerIdentity,
) -> Result<(), BrokerRuntimeError> {
    validate_docker_identity(target, identity)?;
    let encoded = serde_json::to_vec(identity).map_err(|_| BrokerRuntimeError::StateInvalid)?;
    let path = target
        .docker_identity_path()
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    hardened_target_file(path, broker_sid)?
        .atomic_replace(&encoded, MAX_STORE_PAYLOAD_BYTES)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn advance_docker_identity_generation(
    target: &WindowsTargetConfig,
    broker_sid: &str,
    committed_generation: u64,
    next_generation: u64,
) -> Result<(), BrokerRuntimeError> {
    let mut identity =
        load_docker_identity(target, broker_sid)?.ok_or(BrokerRuntimeError::StateInvalid)?;
    if !docker_identity_requires_generation_write(
        identity.generation,
        committed_generation,
        next_generation,
    )? {
        return Ok(());
    }
    identity.generation = next_generation;
    store_docker_identity(target, broker_sid, &identity)
}

fn docker_identity_requires_generation_write(
    identity_generation: u64,
    committed_generation: u64,
    next_generation: u64,
) -> Result<bool, BrokerRuntimeError> {
    if committed_generation == 0
        || next_generation
            != committed_generation
                .checked_add(1)
                .ok_or(BrokerRuntimeError::StateInvalid)?
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    match identity_generation {
        value if value == committed_generation => Ok(true),
        value if value == next_generation => Ok(false),
        _ => Err(BrokerRuntimeError::StateInvalid),
    }
}

fn validate_docker_identity(
    target: &WindowsTargetConfig,
    identity: &DockerIdentity,
) -> Result<(), BrokerRuntimeError> {
    if identity.schema_version != 1
        || identity.target != "docker"
        || !valid_container_id(&identity.container_id)
        || !valid_image_id(&identity.image_id)
        || identity.image_reference != target.docker_image().unwrap_or_default()
        || identity.generation == 0
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn verify_identity_generation(
    identity: &DockerIdentity,
    state: Option<&WindowsCommittedState>,
) -> Result<(), BrokerRuntimeError> {
    if state.is_some_and(|state| identity.generation != state.generation) {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn hardened_target_file(
    path: &Path,
    broker_sid: &str,
) -> Result<HardenedAtomicFile, BrokerRuntimeError> {
    let parent = path.parent().ok_or(BrokerRuntimeError::ConfigInvalid)?;
    HardenedAtomicFile::new_windows(parent.to_path_buf(), path.to_path_buf(), broker_sid)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn read_hardened_target_file(
    path: &Path,
    broker_sid: &str,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, BrokerRuntimeError> {
    hardened_target_file(path, broker_sid)?
        .read(max_bytes)
        .map_err(|_| BrokerRuntimeError::StateInvalid)?
        .ok_or(BrokerRuntimeError::StateInvalid)
}

fn verify_file_sha256(path: &Path, expected: [u8; 32]) -> Result<(), BrokerRuntimeError> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.file_size() == 0
        || metadata.file_size() > 512 * 1024 * 1024
    {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    let mut file = std::fs::File::open(path).map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| BrokerRuntimeError::ConfigInvalid)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    Ok(())
}

fn verify_authenticode_signer(
    path: &Path,
    expected_signer: &str,
) -> Result<(), BrokerRuntimeError> {
    let signer_subject = verified_authenticode_signer(path)?;
    validate_windows_authenticode_claim(&WindowsAuthenticodeClaim {
        signature_trusted: true,
        signer_subject,
        expected_signer_subject: expected_signer.to_owned(),
    })
    .map_err(|_| BrokerRuntimeError::ConfigInvalid)
}

fn verified_authenticode_signer(path: &Path) -> Result<String, BrokerRuntimeError> {
    use windows_sys::Win32::Security::{
        Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE},
        WinTrust::{
            WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
            WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
            WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
        },
    };

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
    file_info.pcwszFilePath = path_wide.as_ptr();
    let mut trust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.Anonymous.pFile = &mut file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
        | WTD_DISABLE_MD2_MD4
        | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    trust_data.dwUIContext = WTD_UICONTEXT_EXECUTE;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: all WinTrust structures contain their documented sizes and
    // pointers to live storage for the duration of verification.
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        )
    };
    let signer_result = if status == 0 {
        // SAFETY: successful stateful verification owns provider data until
        // WTD_STATEACTION_CLOSE below. Null/empty chain pointers are rejected.
        unsafe {
            let provider = WTHelperProvDataFromStateData(trust_data.hWVTStateData);
            let signer = if provider.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
            };
            if signer.is_null()
                || (*signer).csCertChain == 0
                || (*signer).pasCertChain.is_null()
                || (*(*signer).pasCertChain).pCert.is_null()
            {
                Err(BrokerRuntimeError::ConfigInvalid)
            } else {
                let certificate = (*(*signer).pasCertChain).pCert;
                let length = CertGetNameStringW(
                    certificate,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    0,
                );
                if length <= 1 || length > 257 {
                    Err(BrokerRuntimeError::ConfigInvalid)
                } else {
                    let mut subject = vec![0_u16; length as usize];
                    let written = CertGetNameStringW(
                        certificate,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        std::ptr::null(),
                        subject.as_mut_ptr(),
                        length,
                    );
                    if written != length || subject.last() != Some(&0) {
                        Err(BrokerRuntimeError::ConfigInvalid)
                    } else {
                        subject.pop();
                        String::from_utf16(&subject).map_err(|_| BrokerRuntimeError::ConfigInvalid)
                    }
                }
            }
        }
    } else {
        Err(BrokerRuntimeError::ConfigInvalid)
    };
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: this closes the state handle opened by the verification call;
    // the same action GUID and structure are required by WinVerifyTrust.
    unsafe {
        let _ = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        );
    }
    signer_result
}

async fn native_scrape() -> Result<crate::metrics::NativeCoturnScrape, BrokerRuntimeError> {
    let url = METRICS_URL
        .parse()
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let client = ReqwestNativeCoturnScrape::new(url, MetricsLimits::default())
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    client
        .scrape()
        .await
        .map_err(|_| BrokerRuntimeError::TargetFailed)
}

fn parse_single_container_id(output: &[u8]) -> Result<String, BrokerRuntimeError> {
    let value = one_ascii_line(output)?;
    if !valid_container_id(value) {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(value.to_owned())
}

fn one_ascii_line(output: &[u8]) -> Result<&str, BrokerRuntimeError> {
    let text = std::str::from_utf8(output).map_err(|_| BrokerRuntimeError::TargetFailed)?;
    let value = text.strip_suffix('\n').unwrap_or(text);
    let value = value.strip_suffix('\r').unwrap_or(value);
    if value.is_empty()
        || !value.is_ascii()
        || value.contains(['\r', '\n', '\0'])
        || value.len() > 512
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(value)
}

fn valid_container_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_sha256_hex)
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_epoch(value: &str) -> bool {
    validate_windows_counter_epoch(value).is_ok()
}

fn parse_target_name(value: &str) -> Option<CoturnTarget> {
    CoturnTarget::ALL
        .into_iter()
        .find(|target| target.as_str() == value)
}

fn counter_source_name(source: TrafficCounterSource) -> &'static str {
    match source {
        TrafficCounterSource::SystemdIpAccounting => "systemd_ip_accounting",
        TrafficCounterSource::WindowsVerifiedWrapper => "windows_verified_wrapper",
        TrafficCounterSource::DockerEngineStats => "docker_engine_stats",
        TrafficCounterSource::WslSystemdIpAccounting => "wsl_systemd_ip_accounting",
    }
}

fn sha256_hex(value: &[u8]) -> String {
    hex(&Sha256::digest(value))
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn monotonic_ns() -> Result<u64, BrokerRuntimeError> {
    let mut counter = 0_i64;
    let mut frequency = 0_i64;
    // SAFETY: both APIs write one i64 to live initialized storage.
    if unsafe { QueryPerformanceCounter(&mut counter) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
        || counter <= 0
        || frequency <= 0
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    u64::try_from(counter)
        .ok()
        .and_then(|value| value.checked_mul(1_000_000_000))
        .and_then(|value| value.checked_div(frequency as u64))
        .filter(|value| *value != 0)
        .ok_or(BrokerRuntimeError::TargetFailed)
}

fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .replace('/', "\\")
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy().replace('/', "\\"))
}

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn QueryPerformanceCounter(performance_count: *mut i64) -> i32;
    fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
}

struct PipeSecurityDescriptor {
    descriptor: *mut c_void,
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

impl PipeSecurityDescriptor {
    fn new(agent_sid: &str) -> Result<Self, BrokerRuntimeError> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        if !valid_service_sid(agent_sid) {
            return Err(BrokerRuntimeError::ConfigInvalid);
        }
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{agent_sid})");
        let wide = wide(&sddl);
        let mut descriptor = std::ptr::null_mut();
        let mut descriptor_len = 0_u32;
        // SAFETY: wide is NUL-terminated and both output pointers refer to live
        // initialized storage. LocalFree owns the successful result below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut descriptor_len,
            )
        } == 0
            || descriptor.is_null()
            || descriptor_len == 0
        {
            return Err(BrokerRuntimeError::ConfigInvalid);
        }
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Self {
            descriptor,
            attributes,
        })
    }

    fn attributes(&self) -> *mut c_void {
        (&self.attributes as *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES)
            .cast_mut()
            .cast()
    }
}

impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: the SDDL conversion allocated this descriptor with
            // LocalAlloc and this owner frees it exactly once.
            unsafe {
                let _ = windows_sys::Win32::Foundation::LocalFree(self.descriptor);
            }
            self.descriptor = std::ptr::null_mut();
        }
    }
}

fn lookup_account_sid_string(account: &str) -> Result<String, BrokerRuntimeError> {
    use windows_sys::Win32::Security::{Authorization::ConvertSidToStringSidW, LookupAccountNameW};

    let account = wide(account);
    let mut sid_len = 0_u32;
    let mut domain_len = 0_u32;
    let mut sid_use = 0_i32;
    // SAFETY: this is the documented sizing probe with live output scalars.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut sid_use,
        );
    }
    if sid_len == 0 || sid_len > 1024 || domain_len > 32_768 {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    let mut sid = vec![0_u8; sid_len as usize];
    let mut domain = vec![0_u16; domain_len.max(1) as usize];
    // SAFETY: both buffers match their advertised writable sizes.
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    } == 0
    {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: sid contains the SID returned by LookupAccountNameW and the
    // output pointer is a live PWSTR slot.
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut sid_string) } == 0
        || sid_string.is_null()
    {
        return Err(BrokerRuntimeError::ConfigInvalid);
    }
    let length = (0..256)
        .find(|index| unsafe { *sid_string.add(*index) } == 0)
        .ok_or(BrokerRuntimeError::ConfigInvalid)?;
    // SAFETY: the bounded scan found the terminal NUL in the LocalAlloc buffer.
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, length) })
        .map_err(|_| BrokerRuntimeError::ConfigInvalid);
    // SAFETY: ConvertSidToStringSidW allocated with LocalAlloc.
    unsafe {
        let _ = windows_sys::Win32::Foundation::LocalFree(sid_string.cast());
    }
    value
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn windows_local_file(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
        && !value.starts_with("\\\\")
        && !value[2..].contains(':')
        && !value.contains('\0')
        && path.file_name().is_some()
        && !value
            .split(['\\', '/'])
            .any(|component| matches!(component, "." | ".."))
}

fn valid_service_sid(value: &str) -> bool {
    let Some(parts) = value.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let components: Vec<_> = parts.split('-').collect();
    components.len() == 5
        && components.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 10
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
}

fn valid_node_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        classify_journal, docker_drain_completed, docker_host_config_allowed_for_phase,
        docker_identity_requires_generation_write, exact_replay_secret_matches,
        isolate_connected_request, next_drain_completed, pipe_listener_outcome,
        request_join_outcome, select_docker_secret_recovery, select_drain_recovery, sha256_hex,
        validate_docker_port_bindings, validate_docker_process_spec, validate_drain_outer_state,
        validate_live_allocation_target_stability, verify_before_docker_secret_write,
        windows_probe_urls_from_trusted_baseline, ActiveSecretEnvelope, BrokerRuntimeError,
        DockerInspectSummary, DockerSecretPhase, DockerSecretRecoveryAction, DrainRecoveryAction,
        PipeListenerOutcome, TargetObservation, WindowsBrokerConfigWire, WindowsCommittedState,
        WindowsJournalEnvelope, WindowsPendingDrainTransaction, WindowsPendingOperation,
        WindowsPendingTransaction, ZeroizingBase64Url, DOCKER_FRESH_CONFIG_PLACEHOLDER,
    };
    use crate::platform::{CoturnTarget, TrafficCounterSource};

    fn target_observation(epoch: &str, version: u64, config_sha256: &str) -> TargetObservation {
        TargetObservation {
            reported_generation: Some(8),
            epoch: epoch.to_owned(),
            active: true,
            healthy: true,
            active_allocations: 1,
            counter_source: TrafficCounterSource::WindowsVerifiedWrapper,
            total_ingress_bytes: 8,
            total_egress_bytes: 16,
            measurement_monotonic_ns: 20,
            reported_secret_version: Some(version),
            config_sha256: config_sha256.to_owned(),
            draining: false,
            drain_completed: false,
        }
    }

    const BROKER_SID: &str = "S-1-5-80-1-2-3-4-5";

    #[test]
    fn windows_secret_envelopes_have_only_zeroizing_base64_owners() {
        let source = include_str!("windows_runtime.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "raw_secret_b64: String",
            "desired_secret_b64: String",
            "URL_SAFE_NO_PAD.encode(secret.as_slice())",
        ] {
            assert!(
                !production.contains(forbidden),
                "ordinary secret owner remains: {forbidden}"
            );
        }
        let store_json = production
            .split("fn store_json")
            .nth(1)
            .unwrap()
            .split("fn load_state")
            .next()
            .unwrap();
        for forbidden in ["serde_json::to_vec", ".reserve("] {
            assert!(
                !store_json.contains(forbidden),
                "secret store serialization can leave a stale allocation: {forbidden}"
            );
        }
        assert!(store_json.contains("serde_json::to_writer"));
    }

    #[test]
    fn bounded_store_json_writer_rejects_growth_before_reallocation() {
        use std::io::Write as _;

        let mut output = Vec::with_capacity(super::MAX_STORE_PAYLOAD_BYTES);
        let allocation_capacity = output.capacity();
        {
            let mut writer = super::BoundedStoreJsonWriter {
                output: &mut output,
            };
            writer
                .write_all(&vec![0x5a; super::MAX_STORE_PAYLOAD_BYTES])
                .unwrap();
            assert!(writer.write_all(b"x").is_err());
        }
        assert_eq!(output.len(), super::MAX_STORE_PAYLOAD_BYTES);
        assert_eq!(output.capacity(), allocation_capacity);
    }

    #[test]
    fn windows_probe_and_apply_urls_follow_the_unique_trusted_listener_family() {
        let ipv6_endpoints = vec![
            "turn:[2606:4700:4700::1111]:3478?transport=udp".to_owned(),
            "turn:[2606:4700:4700::1111]:3478?transport=tcp".to_owned(),
            "turns:[2606:4700:4700::1111]:5349?transport=tcp".to_owned(),
        ];
        assert_eq!(
            windows_probe_urls_from_trusted_baseline(
                b"listening-port=3478\nlistening-ip=::\nexternal-ip=2606:4700:4700::1111\n",
                &ipv6_endpoints,
            )
            .unwrap(),
            [
                "turn:[::1]:3478?transport=udp",
                "turn:[::1]:3478?transport=tcp",
            ]
        );

        let ipv4_endpoints = vec![
            "turn:192.0.0.9:3478?transport=udp".to_owned(),
            "turn:192.0.0.9:3478?transport=tcp".to_owned(),
        ];
        assert_eq!(
            windows_probe_urls_from_trusted_baseline(
                b"listening-port=3478\nlistening-ip=0.0.0.0\n",
                &ipv4_endpoints,
            )
            .unwrap(),
            [
                "turn:127.0.0.1:3478?transport=udp",
                "turn:127.0.0.1:3478?transport=tcp",
            ]
        );

        for invalid in [
            b"listening-port=3478\n".as_slice(),
            b"listening-ip=127.0.0.1\n".as_slice(),
            b"listening-ip=0.0.0.0\nlistening-ip=::\n".as_slice(),
        ] {
            assert!(windows_probe_urls_from_trusted_baseline(invalid, &ipv6_endpoints).is_err());
        }
        let mismatched_ports = vec![
            "turn:192.0.0.9:3478?transport=udp".to_owned(),
            "turn:192.0.0.9:3479?transport=tcp".to_owned(),
        ];
        assert!(windows_probe_urls_from_trusted_baseline(
            b"listening-ip=0.0.0.0\n",
            &mismatched_ports,
        )
        .is_err());
    }

    #[tokio::test]
    async fn request_timeout_is_connection_local_but_listener_and_join_panics_remain_fatal() {
        use std::{future::pending, io, time::Duration};

        assert_eq!(
            isolate_connected_request(
                Duration::from_millis(1),
                pending::<Result<(), BrokerRuntimeError>>(),
            )
            .await,
            Ok(())
        );
        assert_eq!(
            isolate_connected_request(Duration::from_secs(1), async {
                Err(BrokerRuntimeError::FrameInvalid)
            },)
            .await,
            Ok(())
        );
        assert_eq!(
            pipe_listener_outcome(Err(io::Error::new(io::ErrorKind::BrokenPipe, "private"))),
            Err(BrokerRuntimeError::IoFailed)
        );

        let mut requests = tokio::task::JoinSet::new();
        requests.spawn(async {
            panic!("request task panic");
            #[allow(unreachable_code)]
            Ok::<(), BrokerRuntimeError>(())
        });
        assert_eq!(
            request_join_outcome(requests.join_next().await),
            Err(BrokerRuntimeError::ServiceFailed)
        );
    }

    #[tokio::test]
    async fn seventeenth_pipe_instance_is_retryable_and_capacity_recovers() {
        use std::io;
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe = format!(
            r"\\.\pipe\mrd-relay-capacity-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let create = |first| {
            let mut options = ServerOptions::new();
            options.first_pipe_instance(first).max_instances(16);
            options.create(&pipe)
        };
        let mut instances = Vec::new();
        for index in 0..16 {
            instances.push(create(index == 0).unwrap());
        }
        let saturated = create(false).unwrap_err();
        assert_eq!(saturated.raw_os_error(), Some(231));
        assert_eq!(
            pipe_listener_outcome(Err(saturated)),
            Ok(PipeListenerOutcome::Retry)
        );

        instances.pop();
        instances.push(create(false).unwrap());
        assert_eq!(instances.len(), 16);

        for code in [109, 232, 233] {
            assert_eq!(
                pipe_listener_outcome(Err(io::Error::from_raw_os_error(code))),
                Ok(PipeListenerOutcome::Retry),
                "accept race {code} became service-fatal"
            );
        }
        assert_eq!(
            pipe_listener_outcome(Err(io::Error::from_raw_os_error(5))),
            Err(BrokerRuntimeError::IoFailed)
        );
    }

    #[test]
    fn fresh_docker_create_accepts_only_the_exact_inert_placeholder_before_secret_write() {
        let desired = b"static-auth-secret=never-before-identity\n";
        let desired_sha256 = sha256_hex(desired);
        assert!(docker_host_config_allowed_for_phase(
            &DockerSecretPhase::VerifyIdentity,
            None,
            &desired_sha256,
            DOCKER_FRESH_CONFIG_PLACEHOLDER,
        ));
        assert!(!docker_host_config_allowed_for_phase(
            &DockerSecretPhase::VerifyIdentity,
            None,
            &desired_sha256,
            desired,
        ));

        let mut altered = DOCKER_FRESH_CONFIG_PLACEHOLDER.to_vec();
        altered.push(b'\n');
        assert!(!docker_host_config_allowed_for_phase(
            &DockerSecretPhase::VerifyIdentity,
            None,
            &desired_sha256,
            &altered,
        ));
        for bytes in [DOCKER_FRESH_CONFIG_PLACEHOLDER, desired.as_slice()] {
            assert!(docker_host_config_allowed_for_phase(
                &DockerSecretPhase::WriteDesiredConfig,
                None,
                &desired_sha256,
                bytes,
            ));
        }
        assert!(!docker_host_config_allowed_for_phase(
            &DockerSecretPhase::RestartTarget,
            None,
            &desired_sha256,
            DOCKER_FRESH_CONFIG_PLACEHOLDER,
        ));
        assert!(docker_host_config_allowed_for_phase(
            &DockerSecretPhase::RestartTarget,
            None,
            &desired_sha256,
            desired,
        ));

        let previous = b"static-auth-secret=previous-committed-material\n";
        let previous_sha256 = sha256_hex(previous);
        assert!(docker_host_config_allowed_for_phase(
            &DockerSecretPhase::VerifyIdentity,
            Some(&previous_sha256),
            &desired_sha256,
            previous,
        ));
        assert!(!docker_host_config_allowed_for_phase(
            &DockerSecretPhase::VerifyIdentity,
            Some(&previous_sha256),
            &desired_sha256,
            b"unknown-config",
        ));
    }

    fn exact_docker_process() -> DockerInspectSummary {
        serde_json::from_value(serde_json::json!({
            "id": "a".repeat(64),
            "image_id": format!("sha256:{}", "b".repeat(64)),
            "image_reference": format!("coturn/coturn:4.17.2@sha256:{}", "c".repeat(64)),
            "name": "/mrd-coturn",
            "labels": {"io.mrd.relay.managed": "true"},
            "path": "/usr/bin/turnserver",
            "args": ["--config", "/run/mrd/turnserver.conf"],
            "user": "65534:65534",
            "privileged": false,
            "cap_add": null,
            "cap_drop": ["ALL"],
            "network_mode": "bridge",
            "pid_mode": "",
            "ipc_mode": "private",
            "userns_mode": "",
            "devices": null,
            "publish_all_ports": false,
            "port_bindings": {
                "3478/tcp": [{"HostIp": "", "HostPort": "3478"}],
                "9641/tcp": [{"HostIp": "127.0.0.1", "HostPort": "9641"}]
            },
            "security_opt": ["no-new-privileges:true"],
            "restart_policy": "no",
            "readonly_rootfs": true,
            "running": false,
            "status": "created",
            "exit_code": 0,
            "started_at": "0001-01-01T00:00:00Z",
            "mounts": []
        }))
        .unwrap()
    }

    #[test]
    fn docker_process_spec_rejects_command_privilege_capability_network_and_security_overrides() {
        let exact = exact_docker_process();
        assert_eq!(validate_docker_process_spec(&exact), Ok(()));

        let mut empty_devices = serde_json::to_value(&exact).unwrap();
        empty_devices["devices"] = serde_json::json!([]);
        assert_eq!(
            validate_docker_process_spec(&serde_json::from_value(empty_devices).unwrap()),
            Ok(())
        );

        let mut value = serde_json::to_value(&exact).unwrap();
        value["path"] = serde_json::json!("/bin/sh");
        assert!(validate_docker_process_spec(&serde_json::from_value(value).unwrap()).is_err());

        for (field, invalid) in [
            ("user", serde_json::json!("")),
            ("privileged", serde_json::json!(true)),
            ("cap_add", serde_json::json!(["NET_ADMIN"])),
            ("cap_drop", serde_json::json!([])),
            ("network_mode", serde_json::json!("host")),
            ("pid_mode", serde_json::json!("host")),
            ("ipc_mode", serde_json::json!("host")),
            ("userns_mode", serde_json::json!("host")),
            (
                "devices",
                serde_json::json!([{
                    "PathOnHost": "C:\\\\attacker-device",
                    "PathInContainer": "/dev/attacker",
                    "CgroupPermissions": "rwm"
                }]),
            ),
            ("publish_all_ports", serde_json::json!(true)),
            ("security_opt", serde_json::json!([])),
        ] {
            let mut value = serde_json::to_value(&exact).unwrap();
            value[field] = invalid;
            assert!(
                validate_docker_process_spec(&serde_json::from_value(value).unwrap()).is_err(),
                "accepted override in {field}"
            );
        }

        let mut value = serde_json::to_value(&exact).unwrap();
        value["args"] = serde_json::json!(["--config", "/tmp/attacker.conf"]);
        assert!(validate_docker_process_spec(&serde_json::from_value(value).unwrap()).is_err());
    }

    #[test]
    fn docker_port_bindings_are_an_exact_single_binding_per_expected_port() {
        let expected = [
            "3478:3478/tcp".to_owned(),
            "127.0.0.1:9641:9641/tcp".to_owned(),
        ];
        let exact = exact_docker_process();
        assert_eq!(validate_docker_port_bindings(&exact, &expected), Ok(()));

        let mut duplicate = serde_json::to_value(&exact).unwrap();
        duplicate["port_bindings"]["3478/tcp"] = serde_json::json!([
            {"HostIp": "", "HostPort": "3478"},
            {"HostIp": "0.0.0.0", "HostPort": "3478"}
        ]);
        assert!(validate_docker_port_bindings(
            &serde_json::from_value(duplicate).unwrap(),
            &expected,
        )
        .is_err());

        for invalid_bindings in [serde_json::Value::Null, serde_json::json!([])] {
            let mut invalid = serde_json::to_value(&exact).unwrap();
            invalid["port_bindings"]["3478/tcp"] = invalid_bindings;
            assert!(validate_docker_port_bindings(
                &serde_json::from_value(invalid).unwrap(),
                &expected,
            )
            .is_err());
        }

        let mut normalized_wildcard = serde_json::to_value(&exact).unwrap();
        normalized_wildcard["port_bindings"]["3478/tcp"][0]["HostIp"] =
            serde_json::json!("0.0.0.0");
        assert!(validate_docker_port_bindings(
            &serde_json::from_value(normalized_wildcard).unwrap(),
            &expected,
        )
        .is_err());

        let mut extra = serde_json::to_value(&exact).unwrap();
        extra["port_bindings"]["5349/tcp"] =
            serde_json::json!([{"HostIp": "", "HostPort": "5349"}]);
        assert!(
            validate_docker_port_bindings(&serde_json::from_value(extra).unwrap(), &expected,)
                .is_err()
        );

        let mut public_metrics = serde_json::to_value(&exact).unwrap();
        public_metrics["port_bindings"]["9641/tcp"][0]["HostIp"] = serde_json::json!("");
        assert!(validate_docker_port_bindings(
            &serde_json::from_value(public_metrics).unwrap(),
            &expected,
        )
        .is_err());

        let mut wrong_host_port = serde_json::to_value(&exact).unwrap();
        wrong_host_port["port_bindings"]["3478/tcp"][0]["HostPort"] = serde_json::json!("13478");
        assert!(validate_docker_port_bindings(
            &serde_json::from_value(wrong_host_port).unwrap(),
            &expected,
        )
        .is_err());

        let mut missing = serde_json::to_value(&exact).unwrap();
        missing["port_bindings"]
            .as_object_mut()
            .unwrap()
            .remove("3478/tcp");
        assert!(validate_docker_port_bindings(
            &serde_json::from_value(missing).unwrap(),
            &expected,
        )
        .is_err());
    }

    #[tokio::test]
    async fn docker_secret_write_is_fenced_behind_successful_exact_identity_verification() {
        use std::sync::{Arc, Mutex};

        let effects = Arc::new(Mutex::new(Vec::new()));
        let verify_effects = Arc::clone(&effects);
        let write_effects = Arc::clone(&effects);
        let result = verify_before_docker_secret_write(
            async move {
                verify_effects.lock().unwrap().push("verify");
                Err::<(), _>(BrokerRuntimeError::TargetFailed)
            },
            move |_| {
                write_effects.lock().unwrap().push("secret-write");
                Ok(())
            },
        )
        .await;
        assert_eq!(result, Err(BrokerRuntimeError::TargetFailed));
        assert_eq!(*effects.lock().unwrap(), ["verify"]);

        effects.lock().unwrap().clear();
        let verify_effects = Arc::clone(&effects);
        let write_effects = Arc::clone(&effects);
        verify_before_docker_secret_write(
            async move {
                verify_effects.lock().unwrap().push("verify");
                Ok::<_, BrokerRuntimeError>(())
            },
            move |_| {
                write_effects.lock().unwrap().push("secret-write");
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(*effects.lock().unwrap(), ["verify", "secret-write"]);
    }

    #[test]
    fn docker_secret_phase_recovery_closes_all_three_apply_crash_windows() {
        // Desired host bytes alone never prove the old process loaded them.
        assert_eq!(
            select_docker_secret_recovery(
                &DockerSecretPhase::RestartTarget,
                Some("container:old"),
                Some("container:old"),
                true,
                Some(7),
                8,
            ),
            Ok(DockerSecretRecoveryAction::RestartTarget)
        );

        // A restart completed but the protected identity generation write was
        // lost. The exact new epoch advances to the idempotent generation step.
        assert_eq!(
            select_docker_secret_recovery(
                &DockerSecretPhase::RestartTarget,
                Some("container:old"),
                Some("container:new"),
                true,
                Some(7),
                8,
            ),
            Ok(DockerSecretRecoveryAction::PersistGeneration)
        );

        // Fresh create and identity persistence completed, but start did not.
        assert_eq!(
            select_docker_secret_recovery(
                &DockerSecretPhase::RestartTarget,
                None,
                Some("container:not-started"),
                false,
                Some(1),
                1,
            ),
            Ok(DockerSecretRecoveryAction::RestartTarget)
        );

        let persisted = DockerSecretPhase::PersistGeneration {
            epoch: "container:new".to_owned(),
        };
        assert_eq!(
            select_docker_secret_recovery(
                &persisted,
                Some("container:old"),
                Some("container:new"),
                true,
                Some(7),
                8,
            ),
            Ok(DockerSecretRecoveryAction::PersistGeneration)
        );
        assert_eq!(
            select_docker_secret_recovery(
                &persisted,
                Some("container:old"),
                Some("container:new"),
                true,
                Some(8),
                8,
            ),
            Ok(DockerSecretRecoveryAction::VerifyLive)
        );
        assert_eq!(
            select_docker_secret_recovery(
                &DockerSecretPhase::WriteDesiredConfig,
                Some("container:old"),
                Some("container:old"),
                true,
                Some(9),
                8,
            ),
            Err(BrokerRuntimeError::StateInvalid)
        );
    }

    fn broker_config() -> WindowsBrokerConfigWire {
        WindowsBrokerConfigWire {
            schema_version: 1,
            pipe: r"\\.\pipe\mrd-relay-coturn-control".to_owned(),
            target_config_path: PathBuf::from(r"d:\中继数据\mrd\relayagent\BROKER\target.json"),
            enrollment_token_path: PathBuf::from(
                r"D:\中继数据\MRD\RelayAgent\secrets\enrollment-token.dpapi",
            ),
            turn_rest_secret_path: PathBuf::from(
                r"D:\中继数据\MRD\RelayAgent\secrets\turn-rest-secret.dpapi",
            ),
            pipe_acl: vec![
                "SYSTEM".to_owned(),
                "BUILTIN\\Administrators".to_owned(),
                "NT SERVICE\\mrd-relay-agent".to_owned(),
            ],
            verify_client_token_twice: true,
            minimal_environment: vec![
                "SystemRoot".to_owned(),
                "ProgramFiles".to_owned(),
                "ProgramData".to_owned(),
            ],
            node_id: "relay:test:1".to_owned(),
            broker_service_sid: BROKER_SID.to_owned(),
            active_turn_secret_path: PathBuf::from(
                r"D:\中继数据\MRD\RelayAgent\broker\active-turn-secret.dpapi",
            ),
            runtime_state_path: PathBuf::from(
                r"D:\中继数据\MRD\RelayAgent\broker\control-state.dpapi",
            ),
            journal_path: PathBuf::from(r"D:\中继数据\MRD\RelayAgent\broker\control-journal.dpapi"),
        }
    }

    #[test]
    fn broker_config_accepts_an_exact_custom_unicode_data_root_layout() {
        assert_eq!(
            broker_config().validate(
                Path::new(r"D:\中继数据\MRD\RelayAgent\broker\broker.json"),
                BROKER_SID,
            ),
            Ok(())
        );
    }

    #[test]
    fn broker_config_rejects_paths_outside_the_exact_data_root_layout() {
        let own_path = Path::new(r"D:\中继数据\MRD\RelayAgent\broker\broker.json");

        let mut config = broker_config();
        config.target_config_path =
            PathBuf::from(r"D:\中继数据\MRD\RelayAgent-evil\broker\target.json");
        assert_eq!(
            config.validate(own_path, BROKER_SID),
            Err(BrokerRuntimeError::ConfigInvalid)
        );

        let mut config = broker_config();
        config.enrollment_token_path =
            PathBuf::from(r"E:\中继数据\MRD\RelayAgent\secrets\enrollment-token.dpapi");
        assert_eq!(
            config.validate(own_path, BROKER_SID),
            Err(BrokerRuntimeError::ConfigInvalid)
        );

        let mut config = broker_config();
        config.turn_rest_secret_path =
            PathBuf::from(r"D:\中继数据\MRD\RelayAgent\secrets\..\secrets\turn-rest-secret.dpapi");
        assert_eq!(
            config.validate(own_path, BROKER_SID),
            Err(BrokerRuntimeError::ConfigInvalid)
        );

        let mut config = broker_config();
        config.active_turn_secret_path =
            PathBuf::from(r"D:\中继数据\MRD\RelayAgent\broker\nested\active-turn-secret.dpapi");
        assert_eq!(
            config.validate(own_path, BROKER_SID),
            Err(BrokerRuntimeError::ConfigInvalid)
        );

        let mut config = broker_config();
        config.runtime_state_path =
            PathBuf::from(r"D:\中继数据\MRD\RelayAgent-copy\broker\control-state.dpapi");
        assert_eq!(
            config.validate(own_path, BROKER_SID),
            Err(BrokerRuntimeError::ConfigInvalid)
        );

        let mut config = broker_config();
        config.journal_path =
            PathBuf::from(r"D:\中继数据\MRD\RelayAgent\broker\control-journal.dpapi:stream");
        assert_eq!(
            config.validate(own_path, BROKER_SID),
            Err(BrokerRuntimeError::ConfigInvalid)
        );

        assert_eq!(
            broker_config().validate(
                Path::new(r"D:\中继数据\MRD\RelayAgent\broker\nested\broker.json"),
                BROKER_SID,
            ),
            Err(BrokerRuntimeError::ConfigInvalid)
        );
    }

    #[test]
    fn draining_exact_secret_replay_is_idempotent_but_a_different_digest_is_rejected() {
        let secret = [0x5a; 32];
        let digest = sha256_hex(&secret);
        let state = WindowsCommittedState {
            schema_version: 1,
            target: "windows-service".to_owned(),
            generation: 7,
            applied_secret_version: 3,
            target_epoch: "service-epoch-7".to_owned(),
            secret_sha256: digest.clone(),
            config_sha256: "11".repeat(32),
            draining: true,
            drain_completed: false,
            external_restart_detected: false,
        };
        let active = ActiveSecretEnvelope {
            schema_version: 1,
            target: state.target.clone(),
            version: state.applied_secret_version,
            raw_secret_b64: ZeroizingBase64Url::from_raw(&secret).unwrap(),
            secret_sha256: digest,
        };

        assert!(exact_replay_secret_matches(&state, &active, &secret));
        assert!(!exact_replay_secret_matches(&state, &active, &[0x33; 32]));
    }

    #[test]
    fn legacy_committed_state_defaults_drain_completion_to_false() {
        let encoded = format!(
            r#"{{"schema_version":1,"target":"windows-service","generation":7,"applied_secret_version":3,"target_epoch":"service-epoch-7","secret_sha256":"{}","config_sha256":"{}","draining":true,"external_restart_detected":false}}"#,
            "11".repeat(32),
            "22".repeat(32),
        );
        let decoded: WindowsCommittedState = serde_json::from_str(&encoded).unwrap();
        assert!(!decoded.drain_completed);
    }

    #[test]
    fn docker_external_restart_generation_recovery_is_idempotent_across_state_write_loss() {
        assert_eq!(docker_identity_requires_generation_write(7, 7, 8), Ok(true));
        // Simulate identity=8 having committed before the outer state=7 write
        // was lost. A retry must not advance again or become permanently
        // invalid; it only needs to finish the outer state transition.
        assert_eq!(
            docker_identity_requires_generation_write(8, 7, 8),
            Ok(false)
        );
        assert_eq!(
            docker_identity_requires_generation_write(9, 7, 8),
            Err(BrokerRuntimeError::StateInvalid)
        );
    }

    #[test]
    fn drain_recovery_never_guesses_across_target_and_outer_state_crash_windows() {
        for target in [
            CoturnTarget::WindowsService,
            CoturnTarget::Wsl2,
            CoturnTarget::Docker,
        ] {
            // A delegated helper can prove that enter-drain already happened;
            // Docker cannot expose its SIGUSR1 latch and must replay unless it
            // has reached an exact clean exit.
            assert_eq!(
                select_drain_recovery(
                    target,
                    true,
                    7,
                    "epoch-a",
                    7,
                    "epoch-a",
                    false,
                    7,
                    "epoch-a",
                    target != CoturnTarget::Docker,
                    false,
                    true,
                ),
                Ok(if target == CoturnTarget::Docker {
                    DrainRecoveryAction::ReplayTarget
                } else {
                    DrainRecoveryAction::CommitObserved
                })
            );

            // Once outer state is committed, a lost response only removes
            // the journal after target observation is consistent.
            assert_eq!(
                select_drain_recovery(
                    target, true, 7, "epoch-a", 7, "epoch-a", true, 7, "epoch-a", true, false,
                    true,
                ),
                Ok(DrainRecoveryAction::RemoveJournal)
            );

            let observed_draining = target == CoturnTarget::Docker;
            assert_eq!(
                select_drain_recovery(
                    target,
                    false,
                    7,
                    "epoch-a",
                    8,
                    "epoch-b",
                    false,
                    8,
                    "epoch-b",
                    observed_draining,
                    false,
                    true,
                ),
                Ok(DrainRecoveryAction::RemoveJournal)
            );
        }

        for target in [CoturnTarget::WindowsService, CoturnTarget::Wsl2] {
            assert_eq!(
                select_drain_recovery(
                    target, false, 7, "epoch-a", 7, "epoch-a", true, 8, "epoch-b", false, false,
                    true,
                ),
                Ok(DrainRecoveryAction::CommitObserved)
            );
        }
        // Docker may have restarted before its protected identity generation
        // write. The new exact start epoch is sufficient to commit observed;
        // identity advancement is separately idempotent.
        assert_eq!(
            select_drain_recovery(
                CoturnTarget::Docker,
                false,
                7,
                "container:start-a",
                7,
                "container:start-a",
                true,
                7,
                "container:start-b",
                true,
                false,
                true,
            ),
            Ok(DrainRecoveryAction::CommitObserved)
        );
        assert_eq!(
            select_drain_recovery(
                CoturnTarget::Docker,
                false,
                7,
                "container:start-a",
                7,
                "container:start-a",
                true,
                7,
                "container:start-a",
                true,
                false,
                true,
            ),
            Ok(DrainRecoveryAction::ReplayTarget)
        );
        assert_eq!(
            select_drain_recovery(
                CoturnTarget::Docker,
                true,
                7,
                "container:start-a",
                7,
                "container:start-a",
                false,
                7,
                "container:start-a",
                true,
                true,
                true,
            ),
            Ok(DrainRecoveryAction::ReplayTarget)
        );
        // A running container with zero allocations does not prove SIGUSR1
        // was sent. Only an exact clean exit can close this lost-response
        // window without replaying the idempotent signal.
        assert_eq!(
            select_drain_recovery(
                CoturnTarget::Docker,
                true,
                7,
                "container:start-a",
                7,
                "container:start-a",
                false,
                7,
                "container:start-a",
                true,
                true,
                false,
            ),
            Ok(DrainRecoveryAction::CommitObserved)
        );

        for target in [CoturnTarget::WindowsService, CoturnTarget::Wsl2] {
            assert_eq!(
                select_drain_recovery(
                    target, true, 7, "epoch-a", 7, "epoch-a", false, 7, "epoch-a", false, false,
                    true,
                ),
                Ok(DrainRecoveryAction::ReplayTarget)
            );
            assert_eq!(
                select_drain_recovery(
                    target, false, 7, "epoch-a", 7, "epoch-a", true, 7, "epoch-a", true, true,
                    true,
                ),
                Ok(DrainRecoveryAction::ReplayTarget)
            );
        }
    }

    #[test]
    fn legacy_secret_journal_is_readable_but_mixed_pending_operations_fail_closed() {
        let secret = [0x5a; 32];
        let pending = WindowsPendingTransaction {
            target: "windows-service".to_owned(),
            desired_version: 1,
            desired_secret_b64: ZeroizingBase64Url::from_raw(&secret).unwrap(),
            desired_secret_sha256: sha256_hex(&secret),
            desired_config_sha256: "11".repeat(32),
            previous_state: None,
            previous_active: None,
            docker_phase: None,
        };
        let legacy = serde_json::json!({"schema_version": 1, "pending": pending});
        let decoded: WindowsJournalEnvelope = serde_json::from_value(legacy).unwrap();
        assert!(matches!(
            classify_journal(decoded),
            Ok(Some(WindowsPendingOperation::Secret(_)))
        ));

        let previous_state = WindowsCommittedState {
            schema_version: 1,
            target: "windows-service".to_owned(),
            generation: 7,
            applied_secret_version: 3,
            target_epoch: "service-epoch-7".to_owned(),
            secret_sha256: "22".repeat(32),
            config_sha256: "33".repeat(32),
            draining: false,
            drain_completed: false,
            external_restart_detected: false,
        };
        let drain_pending = WindowsPendingDrainTransaction {
            target: "windows-service".to_owned(),
            desired_draining: true,
            previous_state,
        };
        let drain_envelope = WindowsJournalEnvelope {
            schema_version: 1,
            pending: None,
            drain_pending: Some(drain_pending.clone()),
        };
        assert!(matches!(
            classify_journal(drain_envelope),
            Ok(Some(WindowsPendingOperation::Drain(_)))
        ));

        let mixed = WindowsJournalEnvelope {
            schema_version: 1,
            pending: Some(WindowsPendingTransaction {
                target: "windows-service".to_owned(),
                desired_version: 1,
                desired_secret_b64: ZeroizingBase64Url::from_raw(&secret).unwrap(),
                desired_secret_sha256: sha256_hex(&secret),
                desired_config_sha256: "11".repeat(32),
                previous_state: None,
                previous_active: None,
                docker_phase: None,
            }),
            drain_pending: Some(drain_pending),
        };
        assert_eq!(
            classify_journal(mixed).err(),
            Some(BrokerRuntimeError::StateInvalid)
        );
    }

    #[test]
    fn drain_recovery_rejects_an_outer_completion_latch_rollback() {
        let previous = WindowsCommittedState {
            schema_version: 1,
            target: "windows-service".to_owned(),
            generation: 7,
            applied_secret_version: 3,
            target_epoch: "service-epoch-7".to_owned(),
            secret_sha256: "22".repeat(32),
            config_sha256: "33".repeat(32),
            draining: true,
            drain_completed: true,
            external_restart_detected: false,
        };
        assert!(validate_drain_outer_state(&previous, &previous).is_ok());
        let rolled_back = WindowsCommittedState {
            drain_completed: false,
            ..previous.clone()
        };
        assert_eq!(
            validate_drain_outer_state(&rolled_back, &previous),
            Err(BrokerRuntimeError::StateInvalid)
        );
    }

    #[test]
    fn live_allocation_proof_requires_the_same_target_epoch_and_desired_material() {
        let before = target_observation("service-epoch-8", 4, "11");
        let after = target_observation("service-epoch-8", 4, "11");
        assert!(validate_live_allocation_target_stability(
            CoturnTarget::WindowsService,
            &before,
            &after,
            4,
            "unused-for-native",
        )
        .is_ok());

        for changed in [
            target_observation("service-epoch-9", 4, "11"),
            target_observation("service-epoch-8", 3, "11"),
            TargetObservation {
                draining: true,
                ..target_observation("service-epoch-8", 4, "11")
            },
        ] {
            assert!(validate_live_allocation_target_stability(
                CoturnTarget::WindowsService,
                &before,
                &changed,
                4,
                "unused-for-native",
            )
            .is_err());
        }

        let docker_before = TargetObservation {
            counter_source: TrafficCounterSource::DockerEngineStats,
            reported_secret_version: None,
            ..target_observation("container:start-a", 4, "aa")
        };
        let docker_after = TargetObservation {
            counter_source: TrafficCounterSource::DockerEngineStats,
            reported_secret_version: None,
            ..target_observation("container:start-a", 4, "bb")
        };
        assert!(validate_live_allocation_target_stability(
            CoturnTarget::Docker,
            &docker_before,
            &docker_after,
            4,
            "aa",
        )
        .is_err());
    }

    #[test]
    fn drain_completion_latches_only_for_the_committed_drain_epoch_and_resets_on_lifecycle_change()
    {
        assert!(next_drain_completed(
            false, true, "epoch-4", "epoch-4", true,
        ));
        assert!(next_drain_completed(
            true, true, "epoch-4", "epoch-4", false,
        ));
        assert!(!next_drain_completed(
            true, false, "epoch-4", "epoch-4", true,
        ));
        assert!(!next_drain_completed(
            true, true, "epoch-4", "epoch-5", true,
        ));
    }

    #[test]
    fn docker_drain_completion_requires_a_trusted_zero_scrape_or_exact_clean_exit() {
        assert!(docker_drain_completed(true, true, "running", 0, Some(0)));
        assert!(!docker_drain_completed(true, true, "running", 0, None));
        assert!(!docker_drain_completed(true, true, "running", 0, Some(1)));
        assert!(docker_drain_completed(true, false, "exited", 0, None));
        assert!(!docker_drain_completed(true, false, "exited", 1, None));
        assert!(!docker_drain_completed(true, false, "created", 0, None));
        assert!(!docker_drain_completed(false, false, "exited", 0, None));
    }
}
