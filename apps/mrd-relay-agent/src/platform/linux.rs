use std::path::PathBuf;

#[cfg(unix)]
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::process::ProcessError;

use super::{BrokerControlPort, BrokerRequest, CommandOutput, CoturnTarget, PlatformError};

#[cfg(unix)]
use super::MAX_CONTROL_OUTPUT_BYTES;

pub const COTURN_UNIT: &str = "mrd-coturn.service";
pub const AGENT_USER: &str = "mrd-relay";
pub const ROOT_CONTROL_HELPER: &str = "/usr/local/libexec/mrd-relay-coturn-control";
pub const LINUX_CONTROL_SOCKET: &str = "/run/mrd-relay-coturn-control/control.sock";
pub const BOOTSTRAP_CREDENTIAL_NAME: &str = "turn-rest-secret";
pub const BOOTSTRAP_CREDENTIAL_PATH: &str = "/etc/mrd-relay-agent/secrets/turn-rest-secret";
pub const GENERATED_CONFIG_PATH: &str = "/etc/mrd-relay-agent/secrets/turnserver.generated.conf";
pub const COTURN_CERT_CREDENTIAL_PATH: &str = "/run/credentials/mrd-coturn.service/turn-cert";
pub const COTURN_KEY_CREDENTIAL_PATH: &str = "/run/credentials/mrd-coturn.service/turn-key";

#[cfg(unix)]
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

pub fn linux_probe_loopback_host(rendered_config: &[u8]) -> Result<&'static str, PlatformError> {
    let rendered_config =
        std::str::from_utf8(rendered_config).map_err(|_| PlatformError::ConfigInvalid)?;
    let mut listener = None;
    for line in rendered_config.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(value) = line.strip_prefix("listening-ip=") else {
            continue;
        };
        if listener.replace(value).is_some() {
            return Err(PlatformError::ConfigInvalid);
        }
    }
    match listener {
        Some("0.0.0.0") => Ok("127.0.0.1"),
        Some("::") => Ok("[::1]"),
        _ => Err(PlatformError::ConfigInvalid),
    }
}

pub fn validate_unique_wsl_interop_registration(
    registrations: &[(&str, &str)],
) -> Result<(), PlatformError> {
    if registrations.len() != 1
        || !matches!(registrations[0].0, "WSLInterop" | "WSLInterop-late")
        || !valid_wsl_interop_body(registrations[0].1)
    {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(())
}

fn valid_wsl_interop_body(body: &str) -> bool {
    let mut enabled = false;
    let mut interpreter = false;
    let mut flags = false;
    let mut offset = false;
    let mut magic = false;
    for line in body.lines() {
        let seen = match line {
            "enabled" => &mut enabled,
            "interpreter /init" => &mut interpreter,
            "flags: P" | "flags: PF" => &mut flags,
            "offset 0" => &mut offset,
            "magic 4d5a" => &mut magic,
            _ => return false,
        };
        if *seen {
            return false;
        }
        *seen = true;
    }
    enabled && interpreter && flags && offset && magic
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinuxDrainJournalPhase {
    IntentPersisted,
    TargetMutationIssued,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxCommittedState {
    pub schema_version: u8,
    pub target: String,
    pub generation: u64,
    pub applied_secret_version: u64,
    pub invocation_id: String,
    pub secret_sha256: String,
    pub config_sha256: String,
    pub draining: bool,
    #[serde(default)]
    pub drain_completed: bool,
    #[serde(default)]
    pub external_restart_detected: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxPendingSecretJournal {
    pub schema_version: u8,
    pub target: String,
    pub desired_version: u64,
    pub desired_secret_sha256: String,
    pub desired_config_sha256: String,
    pub previous_state: Option<LinuxCommittedState>,
    pub had_previous_secret: bool,
    pub had_previous_config: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinuxPendingDrainOperation {
    SetDraining,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxPendingDrainJournal {
    pub schema_version: u8,
    pub target: String,
    pub operation: LinuxPendingDrainOperation,
    pub desired_draining: bool,
    pub phase: LinuxDrainJournalPhase,
    pub previous_state: LinuxCommittedState,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum LinuxPendingOperation {
    Secret(LinuxPendingSecretJournal),
    Drain(LinuxPendingDrainJournal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxDrainStateClaim {
    pub generation: u64,
    pub invocation_id: String,
    pub draining: bool,
    pub drain_completed: bool,
    pub external_restart_detected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxDrainJournalClaim {
    pub desired_draining: bool,
    pub phase: LinuxDrainJournalPhase,
    pub previous_state: LinuxDrainStateClaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxDrainTargetClaim {
    pub invocation_id: Option<String>,
    pub target_active: bool,
    pub clean_exit: bool,
    pub active_allocations: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxDrainRecoveryAction {
    ApplyDrainSignal,
    CommitDrained,
    RestartUndrained,
    CommitUndrained,
    ClearJournal,
}

pub fn select_linux_drain_recovery(
    journal: &LinuxDrainJournalClaim,
    current: &LinuxDrainStateClaim,
    target: &LinuxDrainTargetClaim,
) -> Result<LinuxDrainRecoveryAction, PlatformError> {
    validate_linux_drain_claim(journal, current, target)?;
    let previous = &journal.previous_state;
    if journal.desired_draining {
        let committed_draining = current.generation == previous.generation
            && current.invocation_id == previous.invocation_id
            && current.draining
            && !current.external_restart_detected;
        if current != previous && !committed_draining {
            return Err(PlatformError::ConfigInvalid);
        }
        if target.invocation_id.as_deref() != Some(previous.invocation_id.as_str()) {
            return Err(PlatformError::ConfigInvalid);
        }
        if target.target_active {
            return if committed_draining
                && journal.phase == LinuxDrainJournalPhase::TargetMutationIssued
            {
                Ok(LinuxDrainRecoveryAction::ClearJournal)
            } else {
                Ok(LinuxDrainRecoveryAction::ApplyDrainSignal)
            };
        }
        if target.clean_exit {
            return if committed_draining
                && current.drain_completed
                && journal.phase == LinuxDrainJournalPhase::TargetMutationIssued
            {
                Ok(LinuxDrainRecoveryAction::ClearJournal)
            } else {
                Ok(LinuxDrainRecoveryAction::CommitDrained)
            };
        }
        return Err(PlatformError::ConfigInvalid);
    }

    if current == previous {
        if target.target_active
            && target.invocation_id.as_deref() == Some(previous.invocation_id.as_str())
        {
            return if target.active_allocations == Some(0) {
                Ok(LinuxDrainRecoveryAction::RestartUndrained)
            } else {
                Err(PlatformError::ConfigInvalid)
            };
        }
        if target.clean_exit
            && target.invocation_id.as_deref() == Some(previous.invocation_id.as_str())
        {
            return Ok(LinuxDrainRecoveryAction::RestartUndrained);
        }
        if target.target_active
            && target
                .invocation_id
                .as_deref()
                .is_some_and(|invocation| invocation != previous.invocation_id)
        {
            return Ok(LinuxDrainRecoveryAction::CommitUndrained);
        }
        return Err(PlatformError::ConfigInvalid);
    }

    if current.generation
        == previous
            .generation
            .checked_add(1)
            .ok_or(PlatformError::ConfigInvalid)?
        && current.invocation_id != previous.invocation_id
        && !current.draining
        && !current.drain_completed
        && !current.external_restart_detected
        && target.target_active
        && target.invocation_id.as_deref() == Some(current.invocation_id.as_str())
    {
        return Ok(LinuxDrainRecoveryAction::ClearJournal);
    }
    Err(PlatformError::ConfigInvalid)
}

fn validate_linux_drain_claim(
    journal: &LinuxDrainJournalClaim,
    current: &LinuxDrainStateClaim,
    target: &LinuxDrainTargetClaim,
) -> Result<(), PlatformError> {
    let previous = &journal.previous_state;
    for state in [previous, current] {
        if state.generation == 0
            || state.invocation_id.len() != 32
            || !state
                .invocation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || (state.drain_completed && !state.draining)
            || state.external_restart_detected
        {
            return Err(PlatformError::ConfigInvalid);
        }
    }
    if (journal.desired_draining && (previous.draining || previous.drain_completed))
        || (!journal.desired_draining && (!previous.draining || !previous.drain_completed))
        || (target.target_active && target.clean_exit)
        || (target.target_active && target.invocation_id.is_none())
        || target.invocation_id.as_deref().is_some_and(|value| {
            value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(())
}

/// Security-relevant facts collected from the connected Unix peer and the
/// fixed socket/helper paths. Policy evaluation stays pure so tests never
/// need to contact a real privileged service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxBrokerPeerClaim {
    pub peer_uid: u32,
    pub peer_pid: u32,
    pub peer_executable: PathBuf,
    pub socket_uid: u32,
    pub socket_gid: u32,
    pub expected_agent_gid: u32,
    pub socket_mode: u32,
    pub parent_uid: u32,
    pub parent_gid: u32,
    pub parent_mode: u32,
    pub helper_uid: u32,
    pub helper_mode: u32,
    pub socket_is_socket: bool,
    pub socket_or_parent_is_symlink: bool,
}

pub fn validate_linux_broker_peer_claim(claim: &LinuxBrokerPeerClaim) -> Result<(), PlatformError> {
    let helper_has_unsafe_mode = claim.helper_mode & 0o6022 != 0;
    if claim.peer_uid != 0
        || claim.peer_pid == 0
        || claim.socket_uid != 0
        || claim.parent_uid != 0
        || claim.expected_agent_gid == 0
        || claim.socket_gid != claim.expected_agent_gid
        || claim.parent_gid != claim.expected_agent_gid
        || claim.socket_mode != 0o660
        || claim.parent_mode != 0o750
        || claim.helper_uid != 0
        || claim.helper_mode & 0o100 == 0
        || helper_has_unsafe_mode
        || !claim.socket_is_socket
        || claim.socket_or_parent_is_symlink
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

pub struct LinuxBrokerClient;

#[async_trait]
impl BrokerControlPort for LinuxBrokerClient {
    async fn exchange(&self, request: BrokerRequest) -> Result<CommandOutput, ProcessError> {
        if request.target() != CoturnTarget::LinuxSystemd {
            return Err(ProcessError::ProbeInvalid);
        }
        #[cfg(unix)]
        {
            tokio::time::timeout(CONTROL_TIMEOUT, exchange_unix(request))
                .await
                .map_err(|_| ProcessError::Unavailable)?
        }
        #[cfg(not(unix))]
        {
            drop(request);
            Err(ProcessError::Unavailable)
        }
    }
}

#[cfg(unix)]
async fn exchange_unix(request: BrokerRequest) -> Result<CommandOutput, ProcessError> {
    use std::{
        fs,
        os::unix::fs::{FileTypeExt as _, MetadataExt as _},
        path::Path,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::UnixStream,
    };

    let socket_path = Path::new(LINUX_CONTROL_SOCKET);
    let parent_path = socket_path.parent().ok_or(ProcessError::ProbeInvalid)?;
    let helper_path = Path::new(ROOT_CONTROL_HELPER);
    let socket_metadata =
        fs::symlink_metadata(socket_path).map_err(|_| ProcessError::Unavailable)?;
    let parent_metadata =
        fs::symlink_metadata(parent_path).map_err(|_| ProcessError::Unavailable)?;
    let helper_metadata =
        fs::symlink_metadata(helper_path).map_err(|_| ProcessError::Unavailable)?;
    if helper_metadata.file_type().is_symlink() || !helper_metadata.file_type().is_file() {
        return Err(ProcessError::ProbeInvalid);
    }

    let mut stream = UnixStream::connect(LINUX_CONTROL_SOCKET)
        .await
        .map_err(|_| ProcessError::Unavailable)?;
    let expected_agent_gid = lookup_agent_gid()?;
    let credential = stream.peer_cred().map_err(|_| ProcessError::Unavailable)?;
    let peer_pid = credential
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or(ProcessError::ProbeInvalid)?;
    let claim = LinuxBrokerPeerClaim {
        peer_uid: credential.uid(),
        peer_pid,
        // systemd Accept=yes can expose PID 1 as the root socket peer while
        // activation hands the accepted descriptor to the fixed helper.
        peer_executable: PathBuf::new(),
        socket_uid: socket_metadata.uid(),
        socket_gid: socket_metadata.gid(),
        expected_agent_gid,
        socket_mode: socket_metadata.mode() & 0o7777,
        parent_uid: parent_metadata.uid(),
        parent_gid: parent_metadata.gid(),
        parent_mode: parent_metadata.mode() & 0o7777,
        helper_uid: helper_metadata.uid(),
        helper_mode: helper_metadata.mode() & 0o7777,
        socket_is_socket: socket_metadata.file_type().is_socket(),
        socket_or_parent_is_symlink: socket_metadata.file_type().is_symlink()
            || parent_metadata.file_type().is_symlink(),
    };
    validate_linux_broker_peer_claim(&claim).map_err(|_| ProcessError::ProbeInvalid)?;

    // No request bytes, including ApplySecret, are written before the
    // connected peer and fixed-path invariants pass.
    let header = request.frame_header();
    BrokerRequest::validate_header(header).map_err(|_| ProcessError::ProbeInvalid)?;
    stream
        .write_all(&header)
        .await
        .map_err(|_| ProcessError::Unavailable)?;
    stream
        .write_all(request.metadata())
        .await
        .map_err(|_| ProcessError::Unavailable)?;
    if let Some(secret) = request.secret() {
        stream
            .write_all(secret.as_slice())
            .await
            .map_err(|_| ProcessError::SecretApplyFailed)?;
    }
    stream
        .shutdown()
        .await
        .map_err(|_| ProcessError::Unavailable)?;

    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|_| ProcessError::Unavailable)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_CONTROL_OUTPUT_BYTES {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut stdout = vec![0_u8; length];
    stream
        .read_exact(&mut stdout)
        .await
        .map_err(|_| ProcessError::Unavailable)?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .await
        .map_err(|_| ProcessError::Unavailable)?
        != 0
    {
        return Err(ProcessError::ProbeInvalid);
    }
    Ok(CommandOutput::new(0, stdout))
}

#[cfg(unix)]
fn lookup_agent_gid() -> Result<u32, ProcessError> {
    use std::ffi::CString;

    let user = CString::new(AGENT_USER).map_err(|_| ProcessError::ProbeInvalid)?;
    // SAFETY: zero is a valid initial representation for passwd. The reentrant
    // lookup initializes the entry and returns a pointer into the live buffer.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    // SAFETY: every pointer refers to live, correctly-sized storage for the
    // duration of getpwnam_r, and the CString is NUL terminated.
    let status = unsafe {
        libc::getpwnam_r(
            user.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || entry.pw_gid == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    Ok(entry.pw_gid)
}
