use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::process::{
    AllocationProbeEvidence, CoturnRuntimePort, CoturnSnapshot, LiveAllocationEvidence,
    LocalAllocationProbePort, ProcessError, ProcessHealth, SecretBytes,
};

pub mod linux;
pub mod windows;

const MAX_ARGUMENTS: usize = 48;
const MAX_ARGUMENT_BYTES: usize = 1024;
pub(crate) const MAX_CONTROL_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_MAGIC: &[u8; 4] = b"MRDC";
const FRAME_VERSION: u8 = 1;
pub(crate) const FRAME_HEADER_BYTES: usize = 16;
const MAX_METADATA_BYTES: usize = 48;
pub(crate) const RAW_TURN_SECRET_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CoturnTarget {
    LinuxSystemd = 1,
    WindowsService = 2,
    Docker = 3,
    Wsl2 = 4,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TransportCapability {
    TurnUdp,
    TurnTcp,
    TurnsTcp,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficCounterSource {
    SystemdIpAccounting,
    WindowsVerifiedWrapper,
    DockerEngineStats,
    WslSystemdIpAccounting,
}

impl TrafficCounterSource {
    const fn matches_target(self, target: CoturnTarget) -> bool {
        matches!(
            (self, target),
            (Self::SystemdIpAccounting, CoturnTarget::LinuxSystemd)
                | (Self::WindowsVerifiedWrapper, CoturnTarget::WindowsService)
                | (Self::DockerEngineStats, CoturnTarget::Docker)
                | (Self::WslSystemdIpAccounting, CoturnTarget::Wsl2)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformExpectation {
    max_allocations: u32,
    max_egress_bps: u64,
    relay_min_port: u16,
    relay_max_port: u16,
    transport_capabilities: Vec<TransportCapability>,
    endpoints: Vec<String>,
}

impl PlatformExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_allocations: u32,
        max_egress_bps: u64,
        relay_min_port: u16,
        relay_max_port: u16,
        transport_capabilities: Vec<TransportCapability>,
        endpoints: Vec<String>,
    ) -> Result<Self, PlatformError> {
        let capability_set: BTreeSet<_> = transport_capabilities.iter().copied().collect();
        let endpoint_set: BTreeSet<_> = endpoints.iter().collect();
        let endpoint_capabilities: Option<BTreeSet<_>> = endpoints
            .iter()
            .map(|endpoint| endpoint_transport(endpoint))
            .collect();
        if max_allocations == 0
            || max_egress_bps == 0
            || max_egress_bps % 8 != 0
            || relay_min_port < 1024
            || relay_min_port > relay_max_port
            || transport_capabilities.is_empty()
            || transport_capabilities.len() != capability_set.len()
            || endpoints.is_empty()
            || endpoints.len() > 4
            || endpoints.len() != endpoint_set.len()
            || endpoint_capabilities.as_ref() != Some(&capability_set)
        {
            return Err(PlatformError::ConfigInvalid);
        }
        Ok(Self {
            max_allocations,
            max_egress_bps,
            relay_min_port,
            relay_max_port,
            transport_capabilities,
            endpoints,
        })
    }

    pub const fn max_allocations(&self) -> u32 {
        self.max_allocations
    }

    pub const fn max_egress_bps(&self) -> u64 {
        self.max_egress_bps
    }

    pub const fn relay_min_port(&self) -> u16 {
        self.relay_min_port
    }

    pub const fn relay_max_port(&self) -> u16 {
        self.relay_max_port
    }

    pub fn transport_capabilities(&self) -> &[TransportCapability] {
        &self.transport_capabilities
    }

    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }
}

fn endpoint_transport(endpoint: &str) -> Option<TransportCapability> {
    if !crate::config::is_public_turn_endpoint(endpoint) {
        return None;
    }
    if let Some(remainder) = endpoint.strip_prefix("turns:") {
        return (!remainder.contains("?transport=udp")).then_some(TransportCapability::TurnsTcp);
    }
    let remainder = endpoint.strip_prefix("turn:")?;
    if remainder.ends_with("?transport=tcp") {
        Some(TransportCapability::TurnTcp)
    } else {
        Some(TransportCapability::TurnUdp)
    }
}

impl CoturnTarget {
    pub const ALL: [Self; 4] = [
        Self::LinuxSystemd,
        Self::WindowsService,
        Self::Docker,
        Self::Wsl2,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxSystemd => "linux-systemd",
            Self::WindowsService => "windows-service",
            Self::Docker => "docker",
            Self::Wsl2 => "wsl2",
        }
    }

    fn from_byte(value: u8) -> Result<Self, PlatformError> {
        match value {
            1 => Ok(Self::LinuxSystemd),
            2 => Ok(Self::WindowsService),
            3 => Ok(Self::Docker),
            4 => Ok(Self::Wsl2),
            _ => Err(PlatformError::ControlFrameInvalid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BrokerAction {
    Snapshot = 1,
    Restart = 2,
    ApplySecret = 3,
    SetDraining = 4,
    Probe = 5,
}

impl BrokerAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Restart => "restart",
            Self::ApplySecret => "apply-secret",
            Self::SetDraining => "set-draining",
            Self::Probe => "probe",
        }
    }

    pub(crate) fn from_byte(value: u8) -> Result<Self, PlatformError> {
        match value {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::Restart),
            3 => Ok(Self::ApplySecret),
            4 => Ok(Self::SetDraining),
            5 => Ok(Self::Probe),
            _ => Err(PlatformError::ControlFrameInvalid),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    #[error("relay_platform_config_invalid")]
    ConfigInvalid,
    #[error("relay_command_plan_invalid")]
    CommandInvalid,
    #[error("relay_control_frame_invalid")]
    ControlFrameInvalid,
    #[error("relay_broker_peer_identity_invalid")]
    PeerIdentityInvalid,
}

pub struct BrokerRequest {
    target: CoturnTarget,
    action: BrokerAction,
    metadata: Vec<u8>,
    secret: Option<SecretBytes>,
}

impl BrokerRequest {
    pub fn snapshot(target: CoturnTarget) -> Self {
        Self::without_payload(target, BrokerAction::Snapshot)
    }

    pub fn snapshot_with_drain_challenge(
        target: CoturnTarget,
        challenge: [u8; 32],
    ) -> Result<Self, PlatformError> {
        if challenge.iter().all(|byte| *byte == 0) {
            return Err(PlatformError::ControlFrameInvalid);
        }
        Ok(Self {
            target,
            action: BrokerAction::Snapshot,
            metadata: challenge.to_vec(),
            secret: None,
        })
    }

    pub fn restart(target: CoturnTarget) -> Self {
        Self::without_payload(target, BrokerAction::Restart)
    }

    pub fn probe(
        target: CoturnTarget,
        generation: u64,
        applied_secret_version: u64,
        challenge: [u8; 32],
    ) -> Result<Self, PlatformError> {
        if generation == 0 || applied_secret_version == 0 || challenge.iter().all(|byte| *byte == 0)
        {
            return Err(PlatformError::ControlFrameInvalid);
        }
        let mut metadata = Vec::with_capacity(48);
        metadata.extend_from_slice(&generation.to_be_bytes());
        metadata.extend_from_slice(&applied_secret_version.to_be_bytes());
        metadata.extend_from_slice(&challenge);
        Ok(Self {
            target,
            action: BrokerAction::Probe,
            metadata,
            secret: None,
        })
    }

    fn without_payload(target: CoturnTarget, action: BrokerAction) -> Self {
        Self {
            target,
            action,
            metadata: Vec::new(),
            secret: None,
        }
    }

    pub fn apply_secret(
        target: CoturnTarget,
        version: u64,
        secret: SecretBytes,
    ) -> Result<Self, PlatformError> {
        if version == 0 || secret.as_slice().len() != RAW_TURN_SECRET_BYTES {
            return Err(PlatformError::ControlFrameInvalid);
        }
        Ok(Self {
            target,
            action: BrokerAction::ApplySecret,
            metadata: version.to_be_bytes().to_vec(),
            secret: Some(secret),
        })
    }

    pub fn set_draining(target: CoturnTarget, draining: bool) -> Self {
        Self {
            target,
            action: BrokerAction::SetDraining,
            metadata: vec![u8::from(draining)],
            secret: None,
        }
    }

    pub const fn target(&self) -> CoturnTarget {
        self.target
    }

    pub const fn action(&self) -> BrokerAction {
        self.action
    }

    pub fn secret_version(&self) -> Option<u64> {
        if self.action != BrokerAction::ApplySecret || self.metadata.len() != 8 {
            return None;
        }
        Some(u64::from_be_bytes(
            self.metadata.as_slice().try_into().ok()?,
        ))
    }

    pub fn draining(&self) -> Option<bool> {
        if self.action != BrokerAction::SetDraining {
            return None;
        }
        match self.metadata.as_slice() {
            [0] => Some(false),
            [1] => Some(true),
            _ => None,
        }
    }

    pub fn probe_generation(&self) -> Option<u64> {
        self.probe_fields().map(|fields| fields.0)
    }

    pub fn probe_secret_version(&self) -> Option<u64> {
        self.probe_fields().map(|fields| fields.1)
    }

    pub fn probe_challenge(&self) -> Option<&[u8; 32]> {
        self.probe_fields().map(|fields| fields.2)
    }

    pub fn snapshot_challenge(&self) -> Option<&[u8; 32]> {
        if self.action != BrokerAction::Snapshot || self.metadata.len() != 32 {
            return None;
        }
        self.metadata.as_slice().try_into().ok()
    }

    fn probe_fields(&self) -> Option<(u64, u64, &[u8; 32])> {
        if self.action != BrokerAction::Probe || self.metadata.len() != 48 {
            return None;
        }
        let generation = u64::from_be_bytes(self.metadata[..8].try_into().ok()?);
        let version = u64::from_be_bytes(self.metadata[8..16].try_into().ok()?);
        let challenge = self.metadata[16..48].try_into().ok()?;
        Some((generation, version, challenge))
    }

    pub const fn has_secret_payload(&self) -> bool {
        self.secret.is_some()
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    pub fn frame_header(&self) -> [u8; FRAME_HEADER_BYTES] {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..4].copy_from_slice(FRAME_MAGIC);
        header[4] = FRAME_VERSION;
        header[5] = self.action as u8;
        header[6] = self.target as u8;
        header[8..12].copy_from_slice(&(self.metadata.len() as u32).to_be_bytes());
        let secret_len = self
            .secret
            .as_ref()
            .map_or(0, |secret| secret.as_slice().len());
        header[12..16].copy_from_slice(&(secret_len as u32).to_be_bytes());
        header
    }

    pub fn validate_header(header: [u8; FRAME_HEADER_BYTES]) -> Result<(), PlatformError> {
        if &header[..4] != FRAME_MAGIC
            || header[4] != FRAME_VERSION
            || header[7] != 0
            || CoturnTarget::from_byte(header[6]).is_err()
        {
            return Err(PlatformError::ControlFrameInvalid);
        }
        let action = BrokerAction::from_byte(header[5])?;
        let metadata_len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
        let secret_len = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
        let lengths_match = match action {
            BrokerAction::Snapshot => matches!(metadata_len, 0 | 32) && secret_len == 0,
            BrokerAction::Restart => metadata_len == 0 && secret_len == 0,
            BrokerAction::Probe => metadata_len == 48 && secret_len == 0,
            BrokerAction::ApplySecret => metadata_len == 8 && secret_len == RAW_TURN_SECRET_BYTES,
            BrokerAction::SetDraining => metadata_len == 1 && secret_len == 0,
        };
        if !lengths_match || metadata_len > MAX_METADATA_BYTES {
            return Err(PlatformError::ControlFrameInvalid);
        }
        Ok(())
    }

    pub(crate) fn from_frame_parts(
        header: [u8; FRAME_HEADER_BYTES],
        metadata: Vec<u8>,
        secret: Option<SecretBytes>,
    ) -> Result<Self, PlatformError> {
        Self::validate_header(header)?;
        let target = CoturnTarget::from_byte(header[6])?;
        let action = BrokerAction::from_byte(header[5])?;
        let request = Self {
            target,
            action,
            metadata,
            secret,
        };
        let semantic_valid = match action {
            BrokerAction::Snapshot => {
                (request.metadata.is_empty()
                    || request
                        .snapshot_challenge()
                        .is_some_and(|challenge| challenge.iter().any(|byte| *byte != 0)))
                    && request.secret.is_none()
            }
            BrokerAction::Restart => request.metadata.is_empty() && request.secret.is_none(),
            BrokerAction::Probe => {
                request
                    .probe_fields()
                    .is_some_and(|(generation, version, challenge)| {
                        generation != 0
                            && version != 0
                            && challenge.iter().any(|byte| *byte != 0)
                            && request.secret.is_none()
                    })
            }
            BrokerAction::ApplySecret => {
                request.secret_version().is_some_and(|version| version != 0)
                    && request
                        .secret
                        .as_ref()
                        .is_some_and(|secret| secret.as_slice().len() == RAW_TURN_SECRET_BYTES)
            }
            BrokerAction::SetDraining => request.draining().is_some() && request.secret.is_none(),
        };
        if !semantic_valid {
            return Err(PlatformError::ControlFrameInvalid);
        }
        Ok(request)
    }

    pub(crate) fn secret(&self) -> Option<&SecretBytes> {
        self.secret.as_ref()
    }

    pub(crate) fn into_parts(self) -> (CoturnTarget, BrokerAction, Vec<u8>, Option<SecretBytes>) {
        (self.target, self.action, self.metadata, self.secret)
    }
}

impl fmt::Debug for BrokerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerRequest")
            .field("target", &self.target)
            .field("action", &self.action)
            .field("metadata_bytes", &self.metadata.len())
            .field(
                "secret_payload",
                &if self.secret.is_some() {
                    "REDACTED"
                } else {
                    "NONE"
                },
            )
            .finish()
    }
}

#[async_trait]
pub trait BrokerControlPort: Send + Sync {
    async fn exchange(&self, request: BrokerRequest) -> Result<CommandOutput, ProcessError>;
}

pub struct CommandPlan {
    executable: PathBuf,
    arguments: Vec<OsString>,
    secret_stdin: Option<SecretBytes>,
    timeout: Duration,
    output_limit: usize,
}

impl CommandPlan {
    pub fn new<E, I, A>(executable: E, arguments: I) -> Result<Self, PlatformError>
    where
        E: Into<PathBuf>,
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        let executable = executable.into();
        let arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
        if !portable_absolute_path(&executable)
            || prohibited_executable(&executable)
            || arguments.len() > MAX_ARGUMENTS
            || arguments.iter().any(|argument| !literal_argument(argument))
        {
            return Err(PlatformError::CommandInvalid);
        }
        Ok(Self {
            executable,
            arguments,
            secret_stdin: None,
            timeout: DEFAULT_COMMAND_TIMEOUT,
            output_limit: MAX_CONTROL_OUTPUT_BYTES,
        })
    }

    pub fn with_secret_stdin(mut self, secret: SecretBytes) -> Result<Self, PlatformError> {
        if secret.is_empty() || self.secret_stdin.is_some() {
            return Err(PlatformError::CommandInvalid);
        }
        self.secret_stdin = Some(secret);
        Ok(self)
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub fn has_secret_stdin(&self) -> bool {
        self.secret_stdin.is_some()
    }

    pub fn with_output_limit(mut self, output_limit: usize) -> Result<Self, PlatformError> {
        if !(1..=MAX_COMMAND_OUTPUT_BYTES).contains(&output_limit) {
            return Err(PlatformError::CommandInvalid);
        }
        self.output_limit = output_limit;
        Ok(self)
    }

    fn into_parts(self) -> (PathBuf, Vec<OsString>, Option<SecretBytes>, Duration, usize) {
        (
            self.executable,
            self.arguments,
            self.secret_stdin,
            self.timeout,
            self.output_limit,
        )
    }
}

impl fmt::Debug for CommandPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandPlan")
            .field("executable", &self.executable)
            .field("arguments", &self.arguments)
            .field(
                "stdin",
                &if self.secret_stdin.is_some() {
                    "REDACTED"
                } else {
                    "NONE"
                },
            )
            .field("timeout", &self.timeout)
            .field("output_limit", &self.output_limit)
            .finish()
    }
}

fn portable_absolute_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return false;
    }
    if value.starts_with("\\\\") || value.starts_with("//") {
        // Network shares and Win32 device namespaces are not acceptable
        // executable identities for a privileged broker plan.
        return false;
    }
    let bytes = value.as_bytes();
    let windows_drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    if windows_drive_absolute && value[2..].contains(':') {
        // Reject alternate data streams and malformed drive paths.
        return false;
    }
    let absolute = value.starts_with('/') || windows_drive_absolute;
    absolute
        && !value
            .split(['/', '\\'])
            .any(|component| matches!(component, "." | ".."))
}

fn prohibited_executable(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return true;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    )
}

fn literal_argument(argument: &OsStr) -> bool {
    let Some(value) = argument.to_str() else {
        return false;
    };
    !value.is_empty()
        && value.len() <= MAX_ARGUMENT_BYTES
        && !value.chars().any(char::is_control)
        && !value.contains(['*', '?', '[', ']'])
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "-c" | "/c" | "/k" | "--command"
        )
}

pub struct CommandOutput {
    exit_code: i32,
    stdout: Vec<u8>,
}

impl CommandOutput {
    pub fn new(exit_code: i32, stdout: Vec<u8>) -> Self {
        Self { exit_code, stdout }
    }

    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
}

impl fmt::Debug for CommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandOutput")
            .field("exit_code", &self.exit_code)
            .field("stdout_bytes", &self.stdout.len())
            .finish()
    }
}

#[async_trait]
pub trait CommandExecutorPort: Send + Sync {
    async fn execute(&self, plan: CommandPlan) -> Result<CommandOutput, ProcessError>;
}

pub struct StdCommandExecutor;

#[async_trait]
impl CommandExecutorPort for StdCommandExecutor {
    async fn execute(&self, plan: CommandPlan) -> Result<CommandOutput, ProcessError> {
        let (executable, arguments, secret_stdin, timeout, output_limit) = plan.into_parts();
        let has_stdin = secret_stdin.is_some();
        let mut command = tokio::process::Command::new(executable);
        command
            .args(arguments)
            .env_clear()
            .kill_on_drop(true)
            .stdin(if has_stdin {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            for name in ["SystemRoot", "ProgramFiles", "ProgramData"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = command.spawn().map_err(|_| ProcessError::Unavailable)?;
        let stdout = child.stdout.take().ok_or(ProcessError::Unavailable)?;
        let stdin = child.stdin.take();
        let operation = async {
            let write = async move {
                if let (Some(mut stdin), Some(secret)) = (stdin, secret_stdin) {
                    stdin
                        .write_all(secret.as_slice())
                        .await
                        .map_err(|_| ProcessError::SecretApplyFailed)?;
                    stdin
                        .shutdown()
                        .await
                        .map_err(|_| ProcessError::SecretApplyFailed)?;
                }
                Ok::<(), ProcessError>(())
            };
            let read = async move {
                let mut output = Vec::new();
                stdout
                    .take((output_limit + 1) as u64)
                    .read_to_end(&mut output)
                    .await
                    .map_err(|_| ProcessError::Unavailable)?;
                if output.len() > output_limit {
                    return Err(ProcessError::ProbeInvalid);
                }
                Ok::<Vec<u8>, ProcessError>(output)
            };
            let wait = async { child.wait().await.map_err(|_| ProcessError::Unavailable) };
            let ((), stdout, status) = tokio::try_join!(write, read, wait)?;
            Ok::<CommandOutput, ProcessError>(CommandOutput {
                exit_code: status.code().unwrap_or(-1),
                stdout,
            })
        };
        tokio::time::timeout(timeout, operation)
            .await
            .map_err(|_| ProcessError::Unavailable)?
    }
}

pub trait ProtectedSecretStorePort: Send + Sync {
    fn load(&self) -> Result<Option<(u64, SecretBytes)>, ProcessError>;
    fn atomic_replace(&self, version: u64, secret: SecretBytes) -> Result<(), ProcessError>;
}

#[derive(Clone)]
struct CounterSample {
    generation: u64,
    source: TrafficCounterSource,
    epoch: String,
    ingress_bytes: u64,
    egress_bytes: u64,
    monotonic_ns: u64,
}

pub struct PlatformCoturnRuntime {
    target: CoturnTarget,
    broker: Arc<dyn BrokerControlPort>,
    expectation: PlatformExpectation,
    latest_snapshot: Mutex<Option<CoturnSnapshot>>,
    latest_counter: Mutex<Option<CounterSample>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformTrafficSample {
    pub generation: u64,
    pub active_allocations: u32,
    pub current_ingress_bps: u64,
    pub current_egress_bps: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PreflightEvidence {
    schema_version: u8,
    scope: &'static str,
    target: &'static str,
    generation: u64,
    applied_secret_version: u64,
    challenge_sha256: String,
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
    proof_sha256: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DrainProofEvidence {
    schema_version: u8,
    scope: &'static str,
    target: &'static str,
    generation: u64,
    applied_secret_version: u64,
    draining: bool,
    active_allocations: u32,
    drain_completed: bool,
    challenge_sha256: String,
    proof_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainProofWire {
    schema_version: u8,
    scope: String,
    target: String,
    generation: u64,
    applied_secret_version: u64,
    draining: bool,
    active_allocations: u32,
    drain_completed: bool,
    challenge_sha256: String,
    proof_sha256: String,
}

impl PlatformCoturnRuntime {
    pub fn new(
        target: CoturnTarget,
        broker: Arc<dyn BrokerControlPort>,
        expectation: PlatformExpectation,
    ) -> Result<Self, PlatformError> {
        Ok(Self {
            target,
            broker,
            expectation,
            latest_snapshot: Mutex::new(None),
            latest_counter: Mutex::new(None),
        })
    }

    pub const fn target(&self) -> CoturnTarget {
        self.target
    }

    async fn control_snapshot(
        &self,
        request: BrokerRequest,
    ) -> Result<ControlSnapshot, ProcessError> {
        let output = self.broker.exchange(request).await?;
        let mut observed = parse_control_snapshot(self.target, &self.expectation, output)?;
        let rate = self.normalize_counter(&observed.counter)?;
        match rate {
            Some((ingress_bps, egress_bps)) => {
                observed.snapshot.current_egress_bps = egress_bps;
                observed.rate_bps = Some((ingress_bps, egress_bps));
            }
            None if observed.snapshot.health == ProcessHealth::Healthy => {
                observed.snapshot.health = ProcessHealth::Degraded;
            }
            None => {}
        }
        Ok(observed)
    }

    /// Collects allocation count and current target-network bitrate from one
    /// strictly verified broker snapshot. A first sample, epoch change, or
    /// counter reset fails closed rather than reporting a fabricated zero.
    pub async fn collect_metrics_sample(&self) -> Result<PlatformTrafficSample, ProcessError> {
        let observed = self
            .control_snapshot(BrokerRequest::snapshot(self.target))
            .await?;
        self.remember(&observed)?;
        let (current_ingress_bps, current_egress_bps) =
            observed.rate_bps.ok_or(ProcessError::ProbeInvalid)?;
        if observed.snapshot.health != ProcessHealth::Healthy {
            return Err(ProcessError::ProbeInvalid);
        }
        Ok(PlatformTrafficSample {
            generation: observed.snapshot.generation,
            active_allocations: observed.snapshot.active_allocations,
            current_ingress_bps,
            current_egress_bps,
        })
    }

    /// Performs only read-only broker operations. It neither opens identity or
    /// runtime state nor reads bootstrap credentials, so deployment verification
    /// can safely run concurrently with the daemon.
    pub async fn preflight(&self, challenge: [u8; 32]) -> Result<PreflightEvidence, ProcessError> {
        if challenge.iter().all(|byte| *byte == 0) {
            return Err(ProcessError::ProbeInvalid);
        }
        let observed = self
            .control_snapshot(BrokerRequest::snapshot(self.target))
            .await?;
        self.remember(&observed)?;
        let generation = observed.snapshot.generation;
        let applied_secret_version = observed.snapshot.applied_secret_version;
        let request =
            BrokerRequest::probe(self.target, generation, applied_secret_version, challenge)
                .map_err(|_| ProcessError::ProbeInvalid)?;
        let output = self.broker.exchange(request).await?;
        let evidence = parse_probe_evidence(
            self.target,
            generation,
            applied_secret_version,
            &challenge,
            output,
        )?;
        let challenge_sha256: [u8; 32] = Sha256::digest(challenge).into();
        Ok(PreflightEvidence {
            schema_version: 1,
            scope: "local",
            target: self.target.as_str(),
            generation,
            applied_secret_version,
            challenge_sha256: encode_lower_hex(&challenge_sha256),
            listener_reachable: true,
            credential_authenticated: true,
            allocation_created: true,
            permission_created: true,
            packets_sent: evidence.packets_sent(),
            packets_received: evidence.packets_received(),
            bytes_sent: evidence.bytes_sent(),
            bytes_received: evidence.bytes_received(),
            local_candidate_kind: "relay",
            remote_candidate_kind: "relay",
            proof_sha256: encode_lower_hex(&evidence.proof_sha256()),
        })
    }

    /// Produces a read-only, challenge-bound proof only after the privileged
    /// broker has durably committed a zero-allocation drain for this target
    /// epoch. Unknown allocation state never qualifies as completion.
    pub async fn drain_proof(
        &self,
        challenge: [u8; 32],
    ) -> Result<DrainProofEvidence, ProcessError> {
        let request = BrokerRequest::snapshot_with_drain_challenge(self.target, challenge)
            .map_err(|_| ProcessError::ProbeInvalid)?;
        let output = self.broker.exchange(request).await?;
        parse_drain_proof_evidence(self.target, &challenge, output)
    }

    fn normalize_counter(
        &self,
        current: &CounterSample,
    ) -> Result<Option<(u64, u64)>, ProcessError> {
        let mut previous = self.latest_counter.lock().unwrap();
        let rate = previous.as_ref().and_then(|prior| {
            if prior.generation != current.generation
                || prior.source != current.source
                || prior.epoch != current.epoch
                || current.monotonic_ns <= prior.monotonic_ns
                || current.ingress_bytes < prior.ingress_bytes
                || current.egress_bytes < prior.egress_bytes
            {
                return None;
            }
            let elapsed = current.monotonic_ns.checked_sub(prior.monotonic_ns)?;
            let ingress_bits = current
                .ingress_bytes
                .checked_sub(prior.ingress_bytes)?
                .checked_mul(8)?;
            let egress_bits = current
                .egress_bytes
                .checked_sub(prior.egress_bytes)?
                .checked_mul(8)?;
            Some((
                ingress_bits
                    .checked_mul(1_000_000_000)?
                    .checked_div(elapsed)?,
                egress_bits
                    .checked_mul(1_000_000_000)?
                    .checked_div(elapsed)?,
            ))
        });
        *previous = Some(current.clone());
        Ok(rate)
    }

    fn remember(&self, observed: &ControlSnapshot) -> Result<(), ProcessError> {
        let mut latest = self.latest_snapshot.lock().unwrap();
        if let Some(previous) = latest.as_ref() {
            if observed.snapshot.generation < previous.generation
                || observed.snapshot.applied_secret_version < previous.applied_secret_version
            {
                return Err(ProcessError::ProbeInvalid);
            }
        }
        *latest = Some(observed.snapshot.clone());
        Ok(())
    }

    fn require_generation_advance(
        &self,
        observed: &ControlSnapshot,
        requested_version: Option<u64>,
    ) -> Result<(), ProcessError> {
        let latest = self.latest_snapshot.lock().unwrap();
        if let Some(previous) = latest.as_ref() {
            let exact_idempotent_replay = requested_version.is_some_and(|version| {
                previous.applied_secret_version == version
                    && observed.snapshot.applied_secret_version == version
                    && observed.snapshot.generation == previous.generation
            });
            if observed.snapshot.generation <= previous.generation && !exact_idempotent_replay {
                return Err(ProcessError::ProbeInvalid);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CoturnRuntimePort for PlatformCoturnRuntime {
    async fn snapshot(&self) -> Result<CoturnSnapshot, ProcessError> {
        let observed = self
            .control_snapshot(BrokerRequest::snapshot(self.target))
            .await?;
        self.remember(&observed)?;
        Ok(observed.snapshot)
    }

    async fn restart(&self) -> Result<(), ProcessError> {
        let observed = self
            .control_snapshot(BrokerRequest::restart(self.target))
            .await?;
        self.require_generation_advance(&observed, None)?;
        self.remember(&observed)
    }

    async fn apply_secret(&self, version: u64, secret: SecretBytes) -> Result<(), ProcessError> {
        let request = BrokerRequest::apply_secret(self.target, version, secret)
            .map_err(|_| ProcessError::SecretApplyFailed)?;
        let observed = self
            .control_snapshot(request)
            .await
            .map_err(|_| ProcessError::SecretApplyFailed)?;
        if observed.snapshot.applied_secret_version != version {
            return Err(ProcessError::SecretApplyFailed);
        }
        self.require_generation_advance(&observed, Some(version))
            .map_err(|_| ProcessError::SecretApplyFailed)?;
        self.remember(&observed)
            .map_err(|_| ProcessError::SecretApplyFailed)
    }

    async fn set_draining(&self, draining: bool) -> Result<(), ProcessError> {
        let observed = self
            .control_snapshot(BrokerRequest::set_draining(self.target, draining))
            .await?;
        if observed.draining != draining {
            return Err(ProcessError::ProbeInvalid);
        }
        self.remember(&observed)
    }

    async fn probe_local_allocation(&self) -> Result<AllocationProbeEvidence, ProcessError> {
        let (generation, applied_secret_version) = {
            let latest = self.latest_snapshot.lock().unwrap();
            let latest = latest.as_ref().ok_or(ProcessError::ProbeInvalid)?;
            (latest.generation, latest.applied_secret_version)
        };
        let mut challenge = [0_u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut challenge)
            .map_err(|_| ProcessError::ProbeUnavailable)?;
        let request =
            BrokerRequest::probe(self.target, generation, applied_secret_version, challenge)
                .map_err(|_| ProcessError::ProbeInvalid)?;
        let output = self.broker.exchange(request).await?;
        let evidence = parse_probe_evidence(
            self.target,
            generation,
            applied_secret_version,
            &challenge,
            output,
        )?;
        Ok(AllocationProbeEvidence::Live(evidence))
    }
}

#[async_trait]
impl LocalAllocationProbePort for PlatformCoturnRuntime {
    async fn probe(&self) -> Result<AllocationProbeEvidence, ProcessError> {
        CoturnRuntimePort::probe_local_allocation(self).await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlSnapshotWire {
    target: String,
    generation: u64,
    applied_secret_version: u64,
    health: ControlHealth,
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

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlHealth {
    Healthy,
    Degraded,
    Failed,
}

struct ControlSnapshot {
    snapshot: CoturnSnapshot,
    counter: CounterSample,
    rate_bps: Option<(u64, u64)>,
    draining: bool,
}

fn parse_control_snapshot(
    expected_target: CoturnTarget,
    expectation: &PlatformExpectation,
    output: CommandOutput,
) -> Result<ControlSnapshot, ProcessError> {
    if output.exit_code != 0
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_CONTROL_OUTPUT_BYTES
    {
        return Err(ProcessError::Unavailable);
    }
    let wire: ControlSnapshotWire =
        serde_json::from_slice(&output.stdout).map_err(|_| ProcessError::ProbeInvalid)?;
    if wire.target != expected_target.as_str()
        || wire.generation == 0
        || wire.applied_secret_version == 0
        || !wire.counter_source.matches_target(expected_target)
        || wire.counter_epoch.is_empty()
        || wire.counter_epoch.len() > 128
        || !wire.counter_epoch.is_ascii()
        || wire.measurement_monotonic_ns == 0
        || wire.configured_max_allocations != expectation.max_allocations
        || wire.configured_max_egress_bps != expectation.max_egress_bps
        || wire.configured_max_egress_bps % 8 != 0
        || wire.relay_min_port != expectation.relay_min_port
        || wire.relay_max_port != expectation.relay_max_port
        || wire.transport_capabilities != expectation.transport_capabilities
        || wire.configured_endpoints != expectation.endpoints
        || (wire.drain_completed && (!wire.draining || wire.active_allocations != 0))
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let health = match wire.health {
        ControlHealth::Healthy => ProcessHealth::Healthy,
        ControlHealth::Degraded => ProcessHealth::Degraded,
        ControlHealth::Failed => ProcessHealth::Failed,
    };
    Ok(ControlSnapshot {
        snapshot: CoturnSnapshot {
            generation: wire.generation,
            applied_secret_version: wire.applied_secret_version,
            health,
            active_allocations: wire.active_allocations,
            current_egress_bps: 0,
        },
        counter: CounterSample {
            generation: wire.generation,
            source: wire.counter_source,
            epoch: wire.counter_epoch,
            ingress_bytes: wire.total_ingress_bytes,
            egress_bytes: wire.total_egress_bytes,
            monotonic_ns: wire.measurement_monotonic_ns,
        },
        rate_bps: None,
        draining: wire.draining,
    })
}

fn parse_drain_proof_evidence(
    expected_target: CoturnTarget,
    expected_challenge: &[u8; 32],
    output: CommandOutput,
) -> Result<DrainProofEvidence, ProcessError> {
    if output.exit_code != 0
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_CONTROL_OUTPUT_BYTES
    {
        return Err(ProcessError::Unavailable);
    }
    let wire: DrainProofWire =
        serde_json::from_slice(&output.stdout).map_err(|_| ProcessError::ProbeInvalid)?;
    let challenge_sha256 = decode_lower_hex_sha256(&wire.challenge_sha256)?;
    let proof_sha256 = decode_lower_hex_sha256(&wire.proof_sha256)?;
    let expected_challenge_sha256: [u8; 32] = Sha256::digest(expected_challenge).into();
    let expected_proof = drain_proof_sha256(
        expected_target,
        wire.generation,
        wire.applied_secret_version,
        expected_challenge,
    )
    .map_err(|_| ProcessError::ProbeInvalid)?;
    if wire.schema_version != 1
        || wire.scope != "local"
        || wire.target != expected_target.as_str()
        || wire.generation == 0
        || wire.applied_secret_version == 0
        || !wire.draining
        || wire.active_allocations != 0
        || !wire.drain_completed
        || challenge_sha256 != expected_challenge_sha256
        || proof_sha256 != expected_proof
    {
        return Err(ProcessError::ProbeInvalid);
    }
    Ok(DrainProofEvidence {
        schema_version: 1,
        scope: "local",
        target: expected_target.as_str(),
        generation: wire.generation,
        applied_secret_version: wire.applied_secret_version,
        draining: true,
        active_allocations: 0,
        drain_completed: true,
        challenge_sha256: wire.challenge_sha256,
        proof_sha256: wire.proof_sha256,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeEvidenceWire {
    target: String,
    generation: u64,
    applied_secret_version: u64,
    challenge: String,
    listener_reachable: bool,
    credential_authenticated: bool,
    allocation_created: bool,
    permission_created: bool,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    local_candidate_kind: String,
    remote_candidate_kind: String,
    local_candidate_id: String,
    remote_candidate_id: String,
    proof_sha256: String,
}

fn parse_probe_evidence(
    expected_target: CoturnTarget,
    expected_generation: u64,
    expected_secret_version: u64,
    expected_challenge: &[u8; 32],
    output: CommandOutput,
) -> Result<LiveAllocationEvidence, ProcessError> {
    if output.exit_code != 0
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_CONTROL_OUTPUT_BYTES
    {
        return Err(ProcessError::ProbeUnavailable);
    }
    let wire: ProbeEvidenceWire =
        serde_json::from_slice(&output.stdout).map_err(|_| ProcessError::ProbeInvalid)?;
    let response_challenge = decode_lower_hex_sha256(&wire.challenge)?;
    if wire.target != expected_target.as_str()
        || wire.generation != expected_generation
        || wire.applied_secret_version != expected_secret_version
        || response_challenge != *expected_challenge
        || !wire.listener_reachable
        || !wire.credential_authenticated
        || !wire.allocation_created
        || !wire.permission_created
        || wire.local_candidate_kind != "relay"
        || wire.remote_candidate_kind != "relay"
        || wire.packets_sent == 0
        || wire.packets_received == 0
        || wire.bytes_sent == 0
        || wire.bytes_received == 0
        || !valid_candidate_id(&wire.local_candidate_id)
        || !valid_candidate_id(&wire.remote_candidate_id)
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let proof = decode_lower_hex_sha256(&wire.proof_sha256)?;
    let expected_proof = probe_proof_sha256(
        expected_target,
        expected_generation,
        expected_secret_version,
        expected_challenge,
        &wire.local_candidate_id,
        &wire.remote_candidate_id,
        wire.packets_sent,
        wire.packets_received,
        wire.bytes_sent,
        wire.bytes_received,
    )
    .map_err(|_| ProcessError::ProbeInvalid)?;
    if proof != expected_proof {
        return Err(ProcessError::ProbeInvalid);
    }
    LiveAllocationEvidence::from_broker_roundtrip(
        proof,
        wire.packets_sent,
        wire.packets_received,
        wire.bytes_sent,
        wire.bytes_received,
    )
    .ok_or(ProcessError::ProbeInvalid)
}

fn valid_candidate_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

#[allow(clippy::too_many_arguments)]
pub fn probe_proof_sha256(
    target: CoturnTarget,
    generation: u64,
    applied_secret_version: u64,
    challenge: &[u8; 32],
    local_candidate_id: &str,
    remote_candidate_id: &str,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
) -> Result<[u8; 32], PlatformError> {
    if generation == 0
        || applied_secret_version == 0
        || challenge.iter().all(|byte| *byte == 0)
        || !valid_candidate_id(local_candidate_id)
        || !valid_candidate_id(remote_candidate_id)
        || packets_sent == 0
        || packets_received == 0
        || bytes_sent == 0
        || bytes_received == 0
    {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let generation = generation.to_be_bytes();
    let version = applied_secret_version.to_be_bytes();
    let packets_sent = packets_sent.to_be_bytes();
    let packets_received = packets_received.to_be_bytes();
    let bytes_sent = bytes_sent.to_be_bytes();
    let bytes_received = bytes_received.to_be_bytes();
    let fields: [&[u8]; 10] = [
        target.as_str().as_bytes(),
        &generation,
        &version,
        challenge,
        local_candidate_id.as_bytes(),
        remote_candidate_id.as_bytes(),
        &packets_sent,
        &packets_received,
        &bytes_sent,
        &bytes_received,
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"MRD_RELAY_BROKER_PROBE_V1\0");
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| PlatformError::ControlFrameInvalid)?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

pub fn drain_proof_sha256(
    target: CoturnTarget,
    generation: u64,
    applied_secret_version: u64,
    challenge: &[u8; 32],
) -> Result<[u8; 32], PlatformError> {
    if generation == 0 || applied_secret_version == 0 || challenge.iter().all(|byte| *byte == 0) {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let generation = generation.to_be_bytes();
    let version = applied_secret_version.to_be_bytes();
    let active_allocations = 0_u32.to_be_bytes();
    let challenge_sha256: [u8; 32] = Sha256::digest(challenge).into();
    let fields: [&[u8]; 10] = [
        &[1],
        b"local",
        target.as_str().as_bytes(),
        &generation,
        &version,
        &[1],
        &active_allocations,
        &[1],
        &challenge_sha256,
        challenge,
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"MRD_RELAY_DRAIN_PROOF_V1\0");
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| PlatformError::ControlFrameInvalid)?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn broker_drain_proof_payload(
    target: CoturnTarget,
    generation: u64,
    applied_secret_version: u64,
    challenge: &[u8; 32],
) -> Result<Vec<u8>, PlatformError> {
    let challenge_sha256: [u8; 32] = Sha256::digest(challenge).into();
    let proof_sha256 = drain_proof_sha256(target, generation, applied_secret_version, challenge)?;
    serde_json::to_vec(&DrainProofEvidence {
        schema_version: 1,
        scope: "local",
        target: target.as_str(),
        generation,
        applied_secret_version,
        draining: true,
        active_allocations: 0,
        drain_completed: true,
        challenge_sha256: encode_lower_hex(&challenge_sha256),
        proof_sha256: encode_lower_hex(&proof_sha256),
    })
    .map_err(|_| PlatformError::ControlFrameInvalid)
}

fn decode_lower_hex_sha256(value: &str) -> Result<[u8; 32], ProcessError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut result = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(ProcessError::ProbeInvalid)?;
        let low = hex_nibble(chunk[1]).ok_or(ProcessError::ProbeInvalid)?;
        result[index] = (high << 4) | low;
    }
    if result.iter().all(|byte| *byte == 0) {
        return Err(ProcessError::ProbeInvalid);
    }
    Ok(result)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
