use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::time::Duration;

use crate::process::ProcessError;
use serde::Deserialize;

use super::{
    BrokerAction, BrokerRequest, CommandPlan, CoturnTarget, PlatformError, PlatformExpectation,
    TransportCapability,
};

pub const BROKER_SERVICE: &str = "mrd-relay-coturn-control";
pub const AGENT_SERVICE: &str = "mrd-relay-agent";
pub const BROKER_PIPE: &str = r"\\.\pipe\mrd-relay-coturn-control";
pub const NATIVE_SERVICE: &str = "mrd-coturn";
pub const DOCKER_CONTAINER: &str = "mrd-coturn";
pub const WSL_DISTRIBUTION: &str = "MRDRelay";
pub const TARGET_CONTROL_HELPER: &str = "/usr/local/libexec/mrd-relay-coturn-control";
pub const DPAPI_SECRET_RELATIVE_PATH: &str = "MRD\\RelayAgent\\secrets\\turn-rest-secret.dpapi";
pub const WINDOWS_MANAGED_LABEL: &str = "io.mrd.relay.managed=true";
pub const DOCKER_ENGINE_PIPE: &str = r"\\.\pipe\docker_engine";
#[cfg(windows)]
pub(crate) const WINDOWS_MANAGED_LABEL_KEY: &str = "io.mrd.relay.managed";
#[cfg(windows)]
pub(crate) const WINDOWS_MANAGED_LABEL_VALUE: &str = "true";
pub(crate) const DOCKER_ENTRYPOINT: &str = "/usr/bin/turnserver";
pub(crate) const DOCKER_CONFIG_ARGUMENT: &str = "--config";
pub(crate) const DOCKER_USER: &str = "65534:65534";
pub(crate) const DOCKER_NETWORK_MODE: &str = "bridge";
pub(crate) const DOCKER_IPC_MODE: &str = "private";
pub(crate) const DOCKER_CAP_DROP: &str = "ALL";
pub(crate) const DOCKER_SECURITY_OPTION: &str = "no-new-privileges:true";
pub(crate) const COTURN_CONFIG_DESTINATION: &str = "/run/mrd/turnserver.conf";
const COTURN_TLS_DESTINATION: &str = "/run/mrd/tls";
const MAX_TARGET_CONFIG_BYTES: usize = 64 * 1024;

#[cfg(windows)]
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsServiceStatusUpdate {
    Running,
    StopPending,
    StoppedSuccess,
    StoppedFailure,
}

/// Drives the SCM states that follow a successfully reported `START_PENDING`.
///
/// Service registration and the initial `START_PENDING` report deliberately
/// remain outside this helper: until that report succeeds there is no valid
/// SCM status handle/state from which to promise a terminal transition.
pub fn drive_windows_service_after_start_pending<Configured, Error, Configure, Body, Report>(
    configure: Configure,
    body: Body,
    mut report: Report,
) -> Result<(), Error>
where
    Configure: FnOnce() -> Result<Configured, Error>,
    Body: FnOnce(Configured) -> Result<(), Error>,
    Report: FnMut(WindowsServiceStatusUpdate) -> Result<(), Error>,
{
    let report_failure = |primary_error, report: &mut Report| match report(
        WindowsServiceStatusUpdate::StoppedFailure,
    ) {
        Ok(()) => Err(primary_error),
        Err(terminal_error) => Err(terminal_error),
    };

    let configured = match configure() {
        Ok(configured) => configured,
        Err(error) => return report_failure(error, &mut report),
    };
    if let Err(error) = report(WindowsServiceStatusUpdate::Running) {
        return report_failure(error, &mut report);
    }
    if let Err(error) = body(configured) {
        return report_failure(error, &mut report);
    }
    if let Err(error) = report(WindowsServiceStatusUpdate::StopPending) {
        return report_failure(error, &mut report);
    }
    report(WindowsServiceStatusUpdate::StoppedSuccess)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsBrokerPeerClaim {
    pub server_is_local_system: bool,
    pub server_has_expected_restricted_service_sid: bool,
    pub server_process_id: u32,
    pub scm_service_process_id: u32,
    pub server_executable: PathBuf,
    pub server_executable_sha256: [u8; 32],
    pub expected_executable: PathBuf,
    pub expected_executable_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsAgentPeerClaim {
    pub client_is_local_service: bool,
    pub client_has_expected_restricted_service_sid: bool,
    pub client_process_id: u32,
    pub scm_service_process_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsMaintenancePeerClaim {
    pub client_is_elevated_administrator: bool,
    pub client_process_id: u32,
    pub agent_service_process_id: Option<u32>,
    pub client_executable: PathBuf,
    pub agent_service_executable: PathBuf,
    pub client_executable_sha256: [u8; 32],
    pub agent_service_executable_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsAuthenticodeClaim {
    pub signature_trusted: bool,
    pub signer_subject: String,
    pub expected_signer_subject: String,
}

pub fn validate_windows_authenticode_claim(
    claim: &WindowsAuthenticodeClaim,
) -> Result<(), PlatformError> {
    if !claim.signature_trusted
        || !valid_signer(&claim.signer_subject)
        || !valid_signer(&claim.expected_signer_subject)
        || claim.signer_subject != claim.expected_signer_subject
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

pub fn validate_windows_agent_service_sid(
    configured: &str,
    resolved: &str,
) -> Result<(), PlatformError> {
    if !valid_service_sid(configured) || !valid_service_sid(resolved) || configured != resolved {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

#[cfg(windows)]
pub fn resolve_windows_agent_service_sid() -> Result<String, PlatformError> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Security::{Authorization::ConvertSidToStringSidW, LookupAccountNameW};

    let account: Vec<u16> = std::ffi::OsStr::new("NT SERVICE\\mrd-relay-agent")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
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
        return Err(PlatformError::PeerIdentityInvalid);
    }
    let mut sid = vec![0_u8; sid_len as usize];
    let mut domain = vec![0_u16; domain_len.max(1) as usize];
    // SAFETY: buffers match the sizes returned by the sizing probe.
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
        return Err(PlatformError::PeerIdentityInvalid);
    }
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: sid contains the Windows-validated SID and sid_string is a live
    // output slot for the LocalAlloc-owned textual representation.
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut sid_string) } == 0
        || sid_string.is_null()
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    let result = (|| {
        let length = (0..256)
            .find(|index| unsafe { *sid_string.add(*index) } == 0)
            .ok_or(PlatformError::PeerIdentityInvalid)?;
        // SAFETY: the bounded scan found the terminal NUL in this live buffer.
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, length) })
            .map_err(|_| PlatformError::PeerIdentityInvalid)?;
        if !valid_service_sid(&value) {
            return Err(PlatformError::PeerIdentityInvalid);
        }
        Ok(value)
    })();
    // SAFETY: ConvertSidToStringSidW allocated this exact pointer.
    unsafe {
        let _ = windows_sys::Win32::Foundation::LocalFree(sid_string.cast());
    }
    result
}

pub fn validate_windows_agent_peer_claim(
    claim: &WindowsAgentPeerClaim,
) -> Result<(), PlatformError> {
    if !claim.client_is_local_service
        || !claim.client_has_expected_restricted_service_sid
        || claim.client_process_id <= 1
        || claim.client_process_id != claim.scm_service_process_id
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

pub fn validate_windows_maintenance_peer_claim(
    claim: &WindowsMaintenancePeerClaim,
) -> Result<(), PlatformError> {
    if !claim.client_is_elevated_administrator
        || claim.client_process_id <= 1
        || claim
            .agent_service_process_id
            .is_some_and(|process_id| process_id <= 1 || process_id == claim.client_process_id)
        || !is_local_drive_absolute_path(&claim.client_executable)
        || !is_local_drive_absolute_path(&claim.agent_service_executable)
        || !windows_paths_equal(&claim.client_executable, &claim.agent_service_executable)
        || claim
            .agent_service_executable_sha256
            .iter()
            .all(|byte| *byte == 0)
        || claim.client_executable_sha256 != claim.agent_service_executable_sha256
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

pub fn parse_windows_agent_service_command(command: &str) -> Result<PathBuf, PlatformError> {
    if command.is_empty()
        || command.encode_utf16().count() > 32 * 1024
        || command.chars().any(char::is_control)
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    let remainder = command
        .strip_prefix('"')
        .ok_or(PlatformError::PeerIdentityInvalid)?;
    let (executable, remainder) = remainder
        .split_once('"')
        .ok_or(PlatformError::PeerIdentityInvalid)?;
    let executable = PathBuf::from(executable);
    let parsed_executable =
        WindowsAbsolutePath::parse(&executable).ok_or(PlatformError::PeerIdentityInvalid)?;
    if !parsed_executable
        .components
        .last()
        .is_some_and(|name| name.eq_ignore_ascii_case("mrd-relay-agent.exe"))
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    let config = remainder
        .strip_prefix(" run --config \"")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(PlatformError::PeerIdentityInvalid)?;
    if config.contains('"') || !is_local_drive_absolute_path(Path::new(config)) {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(executable)
}

pub const fn windows_maintenance_action_allowed(action: BrokerAction) -> bool {
    matches!(action, BrokerAction::Snapshot | BrokerAction::Probe)
}

pub fn validate_windows_delegated_generation(
    reported_generation: u64,
    expected_generation: u64,
) -> Result<(), PlatformError> {
    if reported_generation == 0
        || expected_generation == 0
        || reported_generation != expected_generation
    {
        return Err(PlatformError::ControlFrameInvalid);
    }
    Ok(())
}

pub fn validate_windows_counter_epoch(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        return Err(PlatformError::ControlFrameInvalid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsGenerationTransition {
    Stable,
    AdvanceState,
    AdvanceDockerIdentityAndState,
}

pub fn validate_windows_generation_transition(
    target: CoturnTarget,
    committed_generation: u64,
    same_epoch: bool,
    reported_generation: u64,
) -> Result<WindowsGenerationTransition, PlatformError> {
    if committed_generation == 0 || reported_generation == 0 {
        return Err(PlatformError::ControlFrameInvalid);
    }
    if same_epoch {
        return if reported_generation == committed_generation {
            Ok(WindowsGenerationTransition::Stable)
        } else {
            Err(PlatformError::ControlFrameInvalid)
        };
    }
    let next = committed_generation
        .checked_add(1)
        .ok_or(PlatformError::ControlFrameInvalid)?;
    match target {
        CoturnTarget::WindowsService | CoturnTarget::Wsl2 if reported_generation == next => {
            Ok(WindowsGenerationTransition::AdvanceState)
        }
        CoturnTarget::Docker if reported_generation == committed_generation => {
            Ok(WindowsGenerationTransition::AdvanceDockerIdentityAndState)
        }
        CoturnTarget::Docker if reported_generation == next => {
            Ok(WindowsGenerationTransition::AdvanceState)
        }
        _ => Err(PlatformError::ControlFrameInvalid),
    }
}

pub fn validate_windows_broker_peer_claim(
    claim: &WindowsBrokerPeerClaim,
) -> Result<(), PlatformError> {
    if !claim.server_is_local_system
        || !claim.server_has_expected_restricted_service_sid
        || claim.server_process_id <= 1
        || claim.scm_service_process_id != claim.server_process_id
        || !is_local_drive_absolute_path(&claim.server_executable)
        || !is_local_drive_absolute_path(&claim.expected_executable)
        || !windows_paths_equal(&claim.server_executable, &claim.expected_executable)
        || claim
            .expected_executable_sha256
            .iter()
            .all(|byte| *byte == 0)
        || claim.server_executable_sha256 != claim.expected_executable_sha256
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

fn is_local_drive_absolute_path(path: &std::path::Path) -> bool {
    WindowsAbsolutePath::parse(path).is_some()
}

fn windows_paths_equal(left: &std::path::Path, right: &std::path::Path) -> bool {
    let Some(left) = WindowsAbsolutePath::parse(left) else {
        return false;
    };
    let Some(right) = WindowsAbsolutePath::parse(right) else {
        return false;
    };
    left.drive.eq_ignore_ascii_case(&right.drive)
        && left.components.len() == right.components.len()
        && left
            .components
            .iter()
            .zip(&right.components)
            .all(|(left, right)| windows_component_equal(left, right))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsAbsolutePath {
    drive: u8,
    components: Vec<String>,
}

impl WindowsAbsolutePath {
    fn parse(path: &Path) -> Option<Self> {
        let value = path.to_str()?;
        let bytes = value.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !matches!(bytes[2], b'\\' | b'/')
            || value.chars().any(char::is_control)
        {
            return None;
        }
        let tail = &value[3..];
        let components = if tail.is_empty() {
            Vec::new()
        } else {
            let components: Vec<_> = tail.split(['\\', '/']).collect();
            if components
                .iter()
                .any(|component| !valid_windows_path_component(component))
            {
                return None;
            }
            components.into_iter().map(str::to_owned).collect()
        };
        Some(Self {
            drive: bytes[0],
            components,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WindowsDataRootLayout {
    absolute: WindowsAbsolutePath,
}

impl WindowsDataRootLayout {
    pub(crate) fn from_layout_path(path: &Path, relative: &[&str]) -> Option<Self> {
        let absolute = WindowsAbsolutePath::parse(path)?;
        if relative.is_empty()
            || absolute.components.len() <= relative.len()
            || !absolute.components[absolute.components.len() - relative.len()..]
                .iter()
                .zip(relative)
                .all(|(actual, expected)| windows_component_equal(actual, expected))
        {
            return None;
        }
        let root_components =
            absolute.components[..absolute.components.len() - relative.len()].to_vec();
        Some(Self {
            absolute: WindowsAbsolutePath {
                drive: absolute.drive,
                components: root_components,
            },
        })
    }

    pub(crate) fn matches_path(&self, path: &Path, relative: &[&str]) -> bool {
        let Some(candidate) = WindowsAbsolutePath::parse(path) else {
            return false;
        };
        let expected_len = self.absolute.components.len() + relative.len();
        if !candidate.drive.eq_ignore_ascii_case(&self.absolute.drive)
            || candidate.components.len() != expected_len
        {
            return false;
        }
        let (candidate_root, candidate_relative) = candidate
            .components
            .split_at(self.absolute.components.len());
        candidate_root
            .iter()
            .zip(&self.absolute.components)
            .all(|(actual, expected)| windows_component_equal(actual, expected))
            && candidate_relative
                .iter()
                .zip(relative)
                .all(|(actual, expected)| windows_component_equal(actual, expected))
    }

    fn safe_for_docker_mount_syntax(&self) -> bool {
        self.absolute
            .components
            .iter()
            .all(|component| !component.contains([',', '=']))
    }
}

fn valid_windows_path_component(component: &str) -> bool {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.ends_with([' ', '.'])
        || component
            .chars()
            .any(|character| character.is_control() || r#"<>:"/\|?*"#.contains(character))
    {
        return false;
    }
    let stem = component.split('.').next().unwrap_or_default();
    let legacy_reserved = ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved));
    let bytes = stem.as_bytes();
    let numbered_reserved = bytes.len() == 4
        && (bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"))
        && matches!(bytes[3], b'1'..=b'9');
    !legacy_reserved && !numbered_reserved
}

#[cfg(windows)]
fn windows_component_equal(left: &str, right: &str) -> bool {
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    let left: Vec<_> = left.encode_utf16().collect();
    let right: Vec<_> = right.encode_utf16().collect();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: both pointers reference live UTF-16 buffers for their exact
    // lengths; CompareStringOrdinal neither retains nor mutates them.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

#[cfg(not(windows))]
fn windows_component_equal(left: &str, right: &str) -> bool {
    left == right || left.eq_ignore_ascii_case(right)
}

pub enum WindowsBrokerConfig {
    Native {
        verified_wrapper: Option<PathBuf>,
    },
    Docker {
        executable: PathBuf,
        container_id: Option<String>,
    },
    Wsl2 {
        executable: PathBuf,
    },
}

/// Strict, protected broker-side target contract. This is intentionally
/// separate from the agent configuration: only the LocalSystem broker can read
/// the target document, and every target-specific field is closed before any
/// privileged command or Docker Engine request is constructed.
pub struct WindowsTargetConfig {
    target: CoturnTarget,
    max_allocations: u32,
    max_egress_bps: u64,
    relay_min_port: u16,
    relay_max_port: u16,
    transport_capabilities: Vec<TransportCapability>,
    configured_endpoints: Vec<String>,
    baseline_path: PathBuf,
    kind: WindowsTargetKind,
}

enum WindowsTargetKind {
    Native {
        wrapper: PathBuf,
        wrapper_sha256: [u8; 32],
        wrapper_signer: String,
        coturn_binary: PathBuf,
        coturn_sha256: [u8; 32],
    },
    Docker {
        executable: PathBuf,
        container_name: String,
        identity_path: PathBuf,
        image: String,
        mounts: Vec<DockerMount>,
        published_ports: Vec<String>,
    },
    Wsl2 {
        executable: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
enum WindowsTargetName {
    Native,
    Docker,
    Wsl2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsTargetWire {
    schema_version: u8,
    target: WindowsTargetName,
    control_pipe: String,
    minimum_coturn_version: String,
    tls_port: u16,
    relay_port_min: u16,
    relay_port_max: u16,
    max_allocations: u32,
    max_egress_bps: u64,
    coturn_bps_capacity_bytes_per_second: u64,
    metrics_bind: String,
    local_acceptance_command: Vec<String>,
    turnserver_baseline_path: PathBuf,
    configured_endpoints: Vec<String>,
    transport_capabilities: Vec<TransportCapability>,
    #[serde(rename = "VerifiedNativeDrainWrapper")]
    verified_native_drain_wrapper: Option<PathBuf>,
    native_coturn_binary: Option<PathBuf>,
    native_wrapper_sha256: Option<String>,
    native_wrapper_signer: Option<String>,
    native_coturn_sha256: Option<String>,
    #[serde(rename = "RestartPolicy")]
    restart_policy: Option<String>,
    docker_executable: Option<PathBuf>,
    container_name: Option<String>,
    expected_container_id_state_path: Option<PathBuf>,
    image: Option<String>,
    labels: Option<BTreeMap<String, String>>,
    read_only_rootfs: Option<bool>,
    bind_mounts: Option<Vec<DockerMountWire>>,
    published_ports: Option<Vec<String>>,
    wsl_executable: Option<PathBuf>,
    distribution: Option<String>,
    owner: Option<String>,
    networking_mode: Option<String>,
    systemd_required: Option<bool>,
    #[serde(rename = "IPAccounting")]
    ip_accounting: Option<String>,
    live_udp_range_probe_required: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DockerMountWire {
    source: PathBuf,
    destination: String,
    read_only: bool,
}

struct DockerMount {
    source: PathBuf,
    destination: String,
}

pub struct NativeBinaryExpectation<'a> {
    pub wrapper: &'a Path,
    pub wrapper_sha256: [u8; 32],
    pub wrapper_signer: &'a str,
    pub coturn_binary: &'a Path,
    pub coturn_sha256: [u8; 32],
}

impl WindowsTargetConfig {
    pub fn parse(encoded: &[u8]) -> Result<Self, PlatformError> {
        if encoded.is_empty() || encoded.len() > MAX_TARGET_CONFIG_BYTES {
            return Err(PlatformError::ConfigInvalid);
        }
        let wire: WindowsTargetWire =
            serde_json::from_slice(encoded).map_err(|_| PlatformError::ConfigInvalid)?;
        wire.try_into()
    }

    pub const fn target(&self) -> CoturnTarget {
        self.target
    }

    pub fn docker_fresh_create_plan(&self) -> Result<CommandPlan, PlatformError> {
        let WindowsTargetKind::Docker {
            executable,
            container_name,
            image,
            mounts,
            published_ports,
            ..
        } = &self.kind
        else {
            return Err(PlatformError::ConfigInvalid);
        };
        let mut arguments = vec![
            OsString::from("create"),
            OsString::from("--name"),
            OsString::from(container_name),
            OsString::from("--label"),
            OsString::from(WINDOWS_MANAGED_LABEL),
            OsString::from("--restart"),
            OsString::from("no"),
            OsString::from("--read-only"),
            OsString::from("--entrypoint"),
            OsString::from(DOCKER_ENTRYPOINT),
            OsString::from("--user"),
            OsString::from(DOCKER_USER),
            OsString::from("--network"),
            OsString::from(DOCKER_NETWORK_MODE),
            OsString::from("--ipc"),
            OsString::from(DOCKER_IPC_MODE),
            OsString::from("--cap-drop"),
            OsString::from(DOCKER_CAP_DROP),
            OsString::from("--security-opt"),
            OsString::from(DOCKER_SECURITY_OPTION),
            OsString::from("--pull"),
            OsString::from("never"),
        ];
        for mount in mounts {
            arguments.push(OsString::from("--mount"));
            arguments.push(OsString::from(format!(
                "type=bind,src={},dst={},readonly",
                mount.source.to_string_lossy(),
                mount.destination
            )));
        }
        for published in published_ports {
            arguments.push(OsString::from("--publish"));
            arguments.push(OsString::from(published));
        }
        arguments.extend([
            OsString::from(image),
            OsString::from(DOCKER_CONFIG_ARGUMENT),
            OsString::from(COTURN_CONFIG_DESTINATION),
        ]);
        CommandPlan::new(executable, arguments)
    }

    pub const fn max_allocations(&self) -> u32 {
        self.max_allocations
    }

    pub const fn max_egress_bps(&self) -> u64 {
        self.max_egress_bps
    }

    pub const fn relay_ports(&self) -> (u16, u16) {
        (self.relay_min_port, self.relay_max_port)
    }

    pub fn transport_capabilities(&self) -> &[TransportCapability] {
        &self.transport_capabilities
    }

    pub fn configured_endpoints(&self) -> &[String] {
        &self.configured_endpoints
    }

    pub fn baseline_path(&self) -> &Path {
        &self.baseline_path
    }

    pub fn broker_config(&self, container_id: Option<String>) -> WindowsBrokerConfig {
        match &self.kind {
            WindowsTargetKind::Native { wrapper, .. } => {
                WindowsBrokerConfig::native(Some(wrapper.clone()))
            }
            WindowsTargetKind::Docker { executable, .. } => WindowsBrokerConfig::Docker {
                executable: executable.clone(),
                container_id,
            },
            WindowsTargetKind::Wsl2 { executable } => WindowsBrokerConfig::wsl2(executable.clone()),
        }
    }

    pub fn docker_identity_path(&self) -> Option<&Path> {
        match &self.kind {
            WindowsTargetKind::Docker { identity_path, .. } => Some(identity_path),
            _ => None,
        }
    }

    pub fn docker_image(&self) -> Option<&str> {
        match &self.kind {
            WindowsTargetKind::Docker { image, .. } => Some(image),
            _ => None,
        }
    }

    pub fn docker_container_name(&self) -> Option<&str> {
        match &self.kind {
            WindowsTargetKind::Docker { container_name, .. } => Some(container_name),
            _ => None,
        }
    }

    pub fn docker_config_source(&self) -> Option<&Path> {
        match &self.kind {
            WindowsTargetKind::Docker { mounts, .. } => mounts
                .iter()
                .find(|mount| mount.destination == COTURN_CONFIG_DESTINATION)
                .map(|mount| mount.source.as_path()),
            _ => None,
        }
    }

    pub fn docker_executable(&self) -> Option<&Path> {
        match &self.kind {
            WindowsTargetKind::Docker { executable, .. } => Some(executable),
            _ => None,
        }
    }

    pub fn docker_mounts(&self) -> Option<Vec<(&Path, &str)>> {
        match &self.kind {
            WindowsTargetKind::Docker { mounts, .. } => Some(
                mounts
                    .iter()
                    .map(|mount| (mount.source.as_path(), mount.destination.as_str()))
                    .collect(),
            ),
            _ => None,
        }
    }

    pub fn docker_published_ports(&self) -> Option<&[String]> {
        match &self.kind {
            WindowsTargetKind::Docker {
                published_ports, ..
            } => Some(published_ports),
            _ => None,
        }
    }

    pub fn native_expected_hashes(&self) -> Option<NativeBinaryExpectation<'_>> {
        match &self.kind {
            WindowsTargetKind::Native {
                wrapper,
                wrapper_sha256,
                wrapper_signer,
                coturn_binary,
                coturn_sha256,
            } => Some(NativeBinaryExpectation {
                wrapper,
                wrapper_sha256: *wrapper_sha256,
                wrapper_signer,
                coturn_binary,
                coturn_sha256: *coturn_sha256,
            }),
            _ => None,
        }
    }
}

impl TryFrom<WindowsTargetWire> for WindowsTargetConfig {
    type Error = PlatformError;

    fn try_from(wire: WindowsTargetWire) -> Result<Self, Self::Error> {
        let data_root = WindowsDataRootLayout::from_layout_path(
            &wire.turnserver_baseline_path,
            &["broker", "turnserver.conf.base"],
        )
        .ok_or(PlatformError::ConfigInvalid)?;
        let expectation = PlatformExpectation::new(
            wire.max_allocations,
            wire.max_egress_bps,
            wire.relay_port_min,
            wire.relay_port_max,
            wire.transport_capabilities.clone(),
            wire.configured_endpoints.clone(),
        )?;
        let turns_port_matches = wire.configured_endpoints.iter().all(|endpoint| {
            !endpoint.starts_with("turns:")
                || endpoint
                    .split('?')
                    .next()
                    .and_then(|authority| authority.rsplit_once(':'))
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    == Some(wire.tls_port)
        });
        if wire.schema_version != 1
            || wire.control_pipe != BROKER_PIPE
            || wire.minimum_coturn_version != "4.17.2"
            || wire.metrics_bind != "127.0.0.1:9641"
            || wire.local_acceptance_command
                != [
                    "preflight",
                    "--config",
                    "ABSOLUTE_CONFIG",
                    "--challenge",
                    "HEX64",
                ]
            || wire.coturn_bps_capacity_bytes_per_second
                != wire
                    .max_egress_bps
                    .checked_div(8)
                    .ok_or(PlatformError::ConfigInvalid)?
            || !turns_port_matches
        {
            return Err(PlatformError::ConfigInvalid);
        }

        let target = match wire.target {
            WindowsTargetName::Native => CoturnTarget::WindowsService,
            WindowsTargetName::Docker => CoturnTarget::Docker,
            WindowsTargetName::Wsl2 => CoturnTarget::Wsl2,
        };
        let kind = match target {
            CoturnTarget::WindowsService => {
                reject_docker_and_wsl_fields(&wire)?;
                let wrapper = wire
                    .verified_native_drain_wrapper
                    .ok_or(PlatformError::ConfigInvalid)?;
                let coturn_binary = wire
                    .native_coturn_binary
                    .ok_or(PlatformError::ConfigInvalid)?;
                let wrapper_sha256 = decode_lower_sha256(
                    wire.native_wrapper_sha256
                        .as_deref()
                        .ok_or(PlatformError::ConfigInvalid)?,
                )?;
                let coturn_sha256 = decode_lower_sha256(
                    wire.native_coturn_sha256
                        .as_deref()
                        .ok_or(PlatformError::ConfigInvalid)?,
                )?;
                let wrapper_signer = wire
                    .native_wrapper_signer
                    .filter(|value| valid_signer(value))
                    .ok_or(PlatformError::ConfigInvalid)?;
                if wire.restart_policy.as_deref() != Some("Restart=no")
                    || !is_local_drive_absolute_path(&wrapper)
                    || !is_local_drive_absolute_path(&coturn_binary)
                    || windows_paths_equal(&wrapper, &coturn_binary)
                {
                    return Err(PlatformError::ConfigInvalid);
                }
                WindowsTargetKind::Native {
                    wrapper,
                    wrapper_sha256,
                    wrapper_signer,
                    coturn_binary,
                    coturn_sha256,
                }
            }
            CoturnTarget::Docker => {
                reject_native_and_wsl_fields(&wire)?;
                let executable = wire.docker_executable.ok_or(PlatformError::ConfigInvalid)?;
                let container_name = wire.container_name.ok_or(PlatformError::ConfigInvalid)?;
                let identity_path = wire
                    .expected_container_id_state_path
                    .ok_or(PlatformError::ConfigInvalid)?;
                let image = wire.image.ok_or(PlatformError::ConfigInvalid)?;
                let labels = wire.labels.ok_or(PlatformError::ConfigInvalid)?;
                let mounts = wire.bind_mounts.ok_or(PlatformError::ConfigInvalid)?;
                let published_ports = wire.published_ports.ok_or(PlatformError::ConfigInvalid)?;
                let expected_ports =
                    expected_docker_ports(wire.tls_port, wire.relay_port_min, wire.relay_port_max);
                let actual_ports: BTreeSet<_> = published_ports.iter().cloned().collect();
                let mount_destinations: BTreeSet<_> = mounts
                    .iter()
                    .map(|mount| mount.destination.as_str())
                    .collect();
                if wire.restart_policy.as_deref() != Some("restart=no")
                    || wire.read_only_rootfs != Some(true)
                    || !data_root.safe_for_docker_mount_syntax()
                    || !is_local_drive_absolute_path(&executable)
                    || container_name != DOCKER_CONTAINER
                    || !data_root.matches_path(&identity_path, &["broker", "docker-identity.json"])
                    || !canonical_docker_image(&image)
                    || labels.len() != 1
                    || labels.get("io.mrd.relay.managed").map(String::as_str) != Some("true")
                    || mounts.len() != 2
                    || mount_destinations
                        != BTreeSet::from([COTURN_CONFIG_DESTINATION, COTURN_TLS_DESTINATION])
                    || mounts
                        .iter()
                        .any(|mount| !mount.read_only || !mount.destination.starts_with('/'))
                    || !mounts.iter().all(|mount| match mount.destination.as_str() {
                        COTURN_CONFIG_DESTINATION => {
                            data_root.matches_path(&mount.source, &["broker", "docker-envelope"])
                        }
                        COTURN_TLS_DESTINATION => data_root.matches_path(&mount.source, &["tls"]),
                        _ => false,
                    })
                    || published_ports.len() != expected_ports.len()
                    || actual_ports != expected_ports
                {
                    return Err(PlatformError::ConfigInvalid);
                }
                WindowsTargetKind::Docker {
                    executable,
                    container_name,
                    identity_path,
                    image,
                    mounts: mounts
                        .into_iter()
                        .map(|mount| DockerMount {
                            source: mount.source,
                            destination: mount.destination,
                        })
                        .collect(),
                    published_ports,
                }
            }
            CoturnTarget::Wsl2 => {
                reject_native_and_docker_fields(&wire)?;
                let executable = wire.wsl_executable.ok_or(PlatformError::ConfigInvalid)?;
                if wire.restart_policy.is_some()
                    || !is_local_drive_absolute_path(&executable)
                    || wire.distribution.as_deref() != Some(WSL_DISTRIBUTION)
                    || wire.owner.as_deref() != Some("LocalSystem")
                    || wire.networking_mode.as_deref() != Some("mirrored")
                    || wire.systemd_required != Some(true)
                    || wire.ip_accounting.as_deref() != Some("yes")
                    || wire.live_udp_range_probe_required != Some(true)
                {
                    return Err(PlatformError::ConfigInvalid);
                }
                WindowsTargetKind::Wsl2 { executable }
            }
            CoturnTarget::LinuxSystemd => return Err(PlatformError::ConfigInvalid),
        };
        Ok(Self {
            target,
            max_allocations: expectation.max_allocations(),
            max_egress_bps: expectation.max_egress_bps(),
            relay_min_port: expectation.relay_min_port(),
            relay_max_port: expectation.relay_max_port(),
            transport_capabilities: expectation.transport_capabilities().to_vec(),
            configured_endpoints: expectation.endpoints().to_vec(),
            baseline_path: wire.turnserver_baseline_path,
            kind,
        })
    }
}

fn reject_docker_and_wsl_fields(wire: &WindowsTargetWire) -> Result<(), PlatformError> {
    if wire.docker_executable.is_some()
        || wire.container_name.is_some()
        || wire.expected_container_id_state_path.is_some()
        || wire.image.is_some()
        || wire.labels.is_some()
        || wire.read_only_rootfs.is_some()
        || wire.bind_mounts.is_some()
        || wire.published_ports.is_some()
        || wire.wsl_executable.is_some()
        || wire.distribution.is_some()
        || wire.owner.is_some()
        || wire.networking_mode.is_some()
        || wire.systemd_required.is_some()
        || wire.ip_accounting.is_some()
        || wire.live_udp_range_probe_required.is_some()
    {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(())
}

fn reject_native_and_wsl_fields(wire: &WindowsTargetWire) -> Result<(), PlatformError> {
    if wire.verified_native_drain_wrapper.is_some()
        || wire.native_coturn_binary.is_some()
        || wire.native_wrapper_sha256.is_some()
        || wire.native_wrapper_signer.is_some()
        || wire.native_coturn_sha256.is_some()
        || wire.wsl_executable.is_some()
        || wire.distribution.is_some()
        || wire.owner.is_some()
        || wire.networking_mode.is_some()
        || wire.systemd_required.is_some()
        || wire.ip_accounting.is_some()
        || wire.live_udp_range_probe_required.is_some()
    {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(())
}

fn reject_native_and_docker_fields(wire: &WindowsTargetWire) -> Result<(), PlatformError> {
    if wire.verified_native_drain_wrapper.is_some()
        || wire.native_coturn_binary.is_some()
        || wire.native_wrapper_sha256.is_some()
        || wire.native_wrapper_signer.is_some()
        || wire.native_coturn_sha256.is_some()
        || wire.docker_executable.is_some()
        || wire.container_name.is_some()
        || wire.expected_container_id_state_path.is_some()
        || wire.image.is_some()
        || wire.labels.is_some()
        || wire.read_only_rootfs.is_some()
        || wire.bind_mounts.is_some()
        || wire.published_ports.is_some()
    {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(())
}

fn expected_docker_ports(tls_port: u16, min: u16, max: u16) -> BTreeSet<String> {
    [
        "3478:3478/udp".to_owned(),
        "3478:3478/tcp".to_owned(),
        format!("{tls_port}:{tls_port}/tcp"),
        format!("{min}-{max}:{min}-{max}/udp"),
        format!("{min}-{max}:{min}-{max}/tcp"),
        "127.0.0.1:9641:9641/tcp".to_owned(),
    ]
    .into_iter()
    .collect()
}

fn canonical_docker_image(value: &str) -> bool {
    let Some((tagged, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    let Some((name, tag)) = tagged.rsplit_once(':') else {
        return false;
    };
    !name.is_empty()
        && !tag.is_empty()
        && !tag.contains(':')
        && !name.rsplit('/').next().unwrap_or_default().contains(':')
        && !tagged.contains('@')
        && tagged.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
        && lower_hex(digest, 64)
}

fn valid_signer(value: &str) -> bool {
    (8..=256).contains(&value.len()) && value.is_ascii() && !value.chars().any(char::is_control)
}

fn valid_service_sid(value: &str) -> bool {
    let Some(components) = value.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let components: Vec<_> = components.split('-').collect();
    components.len() == 5
        && components.iter().all(|component| {
            !component.is_empty()
                && component.len() <= 10
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && component.parse::<u32>().is_ok()
        })
}

fn decode_lower_sha256(value: &str) -> Result<[u8; 32], PlatformError> {
    if !lower_hex(value, 64) || value.bytes().all(|byte| byte == b'0') {
        return Err(PlatformError::ConfigInvalid);
    }
    let mut result = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(result)
}

fn lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hex_value(value: u8) -> Result<u8, PlatformError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(PlatformError::ConfigInvalid),
    }
}

impl WindowsBrokerConfig {
    pub fn native(verified_wrapper: Option<PathBuf>) -> Self {
        Self::Native { verified_wrapper }
    }

    pub fn docker(executable: PathBuf) -> Self {
        Self::Docker {
            executable,
            container_id: None,
        }
    }

    pub fn docker_bound(executable: PathBuf, container_id: String) -> Self {
        Self::Docker {
            executable,
            container_id: Some(container_id),
        }
    }

    pub fn wsl2(executable: PathBuf) -> Self {
        Self::Wsl2 { executable }
    }
}

pub fn target_command_plan(
    config: &WindowsBrokerConfig,
    request: BrokerRequest,
) -> Result<CommandPlan, PlatformError> {
    let (target, action, metadata, secret) = request.into_parts();
    if action == BrokerAction::Probe {
        // The privileged broker performs the authenticated relay probe itself;
        // it never hands the active secret to a child command.
        return Err(PlatformError::CommandInvalid);
    }
    let plan = match (config, target) {
        (
            WindowsBrokerConfig::Native {
                verified_wrapper: Some(executable),
            },
            CoturnTarget::WindowsService,
        ) => CommandPlan::new(executable, action_arguments(action, &metadata)?)?,
        (
            WindowsBrokerConfig::Docker {
                executable,
                container_id: Some(container_id),
            },
            CoturnTarget::Docker,
        ) if valid_container_id(container_id) => {
            // Docker has no in-container MRD helper. The host broker owns the
            // protected bind-mounted envelope and invokes Engine operations
            // only against the persisted, re-inspected 64-hex container ID.
            if action == BrokerAction::ApplySecret || secret.is_some() {
                return Err(PlatformError::CommandInvalid);
            }
            let arguments = match action {
                BrokerAction::Snapshot if metadata.is_empty() => vec![
                    OsString::from("inspect"),
                    OsString::from("--type"),
                    OsString::from("container"),
                    OsString::from(container_id),
                ],
                BrokerAction::Restart if metadata.is_empty() => vec![
                    OsString::from("restart"),
                    OsString::from("--time"),
                    OsString::from("30"),
                    OsString::from(container_id),
                ],
                BrokerAction::SetDraining if matches!(metadata.as_slice(), [0] | [1]) => {
                    if metadata == [1] {
                        vec![
                            OsString::from("kill"),
                            OsString::from("--signal"),
                            OsString::from("SIGUSR1"),
                            OsString::from(container_id),
                        ]
                    } else {
                        vec![
                            OsString::from("restart"),
                            OsString::from("--time"),
                            OsString::from("30"),
                            OsString::from(container_id),
                        ]
                    }
                }
                _ => return Err(PlatformError::CommandInvalid),
            };
            CommandPlan::new(executable, arguments)?
        }
        (WindowsBrokerConfig::Wsl2 { executable }, CoturnTarget::Wsl2) => {
            let mut arguments = vec![
                OsString::from("--distribution"),
                OsString::from(WSL_DISTRIBUTION),
                OsString::from("--user"),
                OsString::from("root"),
                OsString::from("--exec"),
                OsString::from(TARGET_CONTROL_HELPER),
                OsString::from("--wsl-broker"),
            ];
            arguments.extend(action_arguments(action, &metadata)?);
            CommandPlan::new(executable, arguments)?
        }
        _ => return Err(PlatformError::ConfigInvalid),
    };
    if action == BrokerAction::ApplySecret {
        plan.with_secret_stdin(secret.ok_or(PlatformError::ControlFrameInvalid)?)
    } else if secret.is_some() {
        Err(PlatformError::ControlFrameInvalid)
    } else {
        Ok(plan)
    }
}

fn valid_container_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn action_arguments(action: BrokerAction, metadata: &[u8]) -> Result<Vec<OsString>, PlatformError> {
    match action {
        BrokerAction::Snapshot | BrokerAction::Restart if metadata.is_empty() => {
            Ok(vec![OsString::from(action.as_str())])
        }
        BrokerAction::ApplySecret if metadata.len() == 8 => {
            let version = u64::from_be_bytes(
                metadata
                    .try_into()
                    .map_err(|_| PlatformError::ControlFrameInvalid)?,
            );
            if version == 0 {
                return Err(PlatformError::ControlFrameInvalid);
            }
            Ok(vec![
                OsString::from(action.as_str()),
                OsString::from(version.to_string()),
            ])
        }
        BrokerAction::SetDraining if matches!(metadata, [0] | [1]) => Ok(vec![
            OsString::from(action.as_str()),
            OsString::from(if metadata == [1] { "true" } else { "false" }),
        ]),
        _ => Err(PlatformError::ControlFrameInvalid),
    }
}

pub struct WindowsBrokerClient {
    expected_executable: PathBuf,
    expected_executable_sha256: [u8; 32],
}

impl WindowsBrokerClient {
    pub fn new(
        expected_executable: PathBuf,
        expected_executable_sha256: [u8; 32],
    ) -> Result<Self, PlatformError> {
        if !is_local_drive_absolute_path(&expected_executable)
            || expected_executable_sha256.iter().all(|byte| *byte == 0)
        {
            return Err(PlatformError::ConfigInvalid);
        }
        Ok(Self {
            expected_executable,
            expected_executable_sha256,
        })
    }
}

#[async_trait::async_trait]
impl super::BrokerControlPort for WindowsBrokerClient {
    async fn exchange(
        &self,
        request: super::BrokerRequest,
    ) -> Result<super::CommandOutput, ProcessError> {
        if request.target() == CoturnTarget::LinuxSystemd {
            return Err(ProcessError::ProbeInvalid);
        }
        #[cfg(windows)]
        {
            tokio::time::timeout(
                CONTROL_TIMEOUT,
                exchange_windows_pipe(
                    request,
                    &self.expected_executable,
                    self.expected_executable_sha256,
                ),
            )
            .await
            .map_err(|_| ProcessError::Unavailable)?
        }
        #[cfg(not(windows))]
        {
            let _ = (&self.expected_executable, self.expected_executable_sha256);
            drop(request);
            Err(ProcessError::Unavailable)
        }
    }
}

#[cfg(windows)]
async fn exchange_windows_pipe(
    request: super::BrokerRequest,
    expected_executable: &std::path::Path,
    expected_executable_sha256: [u8; 32],
) -> Result<super::CommandOutput, ProcessError> {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::windows::named_pipe::ClientOptions,
    };

    let mut pipe = ClientOptions::new()
        .read(true)
        .write(true)
        .open(BROKER_PIPE)
        .map_err(|_| ProcessError::Unavailable)?;
    verify_connected_windows_broker(&pipe, expected_executable, expected_executable_sha256).await?;

    // No request bytes, including ApplySecret, are written before the fixed
    // broker process identity and LocalSystem token have been verified.
    let header = request.frame_header();
    super::BrokerRequest::validate_header(header).map_err(|_| ProcessError::ProbeInvalid)?;
    let total = header
        .len()
        .checked_add(request.metadata().len())
        .and_then(|value| {
            value.checked_add(request.secret().map_or(0, |secret| secret.as_slice().len()))
        })
        .ok_or(ProcessError::ProbeInvalid)?;
    let mut frame = zeroize::Zeroizing::new(Vec::with_capacity(total));
    frame.extend_from_slice(&header);
    frame.extend_from_slice(request.metadata());
    if let Some(secret) = request.secret() {
        frame.extend_from_slice(secret.as_slice());
    }
    // One bounded write makes the server's post-frame PeekNamedPipe trailing
    // check meaningful; ApplySecret bytes still leave this process only after
    // the broker's SCM PID, LocalSystem token, service SID, path and hash pass.
    pipe.write_all(&frame).await.map_err(|_| {
        if request.has_secret_payload() {
            ProcessError::SecretApplyFailed
        } else {
            ProcessError::Unavailable
        }
    })?;
    pipe.flush().await.map_err(|_| ProcessError::Unavailable)?;
    let mut length = [0_u8; 4];
    pipe.read_exact(&mut length)
        .await
        .map_err(|_| ProcessError::Unavailable)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > super::MAX_CONTROL_OUTPUT_BYTES {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut stdout = vec![0_u8; length];
    pipe.read_exact(&mut stdout)
        .await
        .map_err(|_| ProcessError::Unavailable)?;
    let mut trailing = [0_u8; 1];
    match pipe.read(&mut trailing).await {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
        Ok(_) | Err(_) => return Err(ProcessError::ProbeInvalid),
    }
    Ok(super::CommandOutput::new(0, stdout))
}

#[cfg(windows)]
async fn verify_connected_windows_broker(
    pipe: &tokio::net::windows::named_pipe::NamedPipeClient,
    expected_executable: &std::path::Path,
    expected_executable_sha256: [u8; 32],
) -> Result<(), ProcessError> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle as _};

    let mut server_process_id = 0_u32;
    // SAFETY: `pipe` owns a live named-pipe handle for this entire call and
    // `server_process_id` is a valid writable u32.
    let succeeded = unsafe {
        win32::GetNamedPipeServerProcessId(
            pipe.as_raw_handle().cast::<c_void>(),
            &mut server_process_id,
        )
    };
    if succeeded == 0 || server_process_id <= 1 {
        return Err(ProcessError::ProbeInvalid);
    }

    let expected_executable = expected_executable.to_path_buf();
    let claim = tokio::task::spawn_blocking(move || {
        collect_windows_broker_peer_claim(
            server_process_id,
            expected_executable,
            expected_executable_sha256,
        )
    })
    .await
    .map_err(|_| ProcessError::Unavailable)??;
    validate_windows_broker_peer_claim(&claim).map_err(|_| ProcessError::ProbeInvalid)
}

#[cfg(windows)]
fn collect_windows_broker_peer_claim(
    server_process_id: u32,
    expected_executable: PathBuf,
    expected_executable_sha256: [u8; 32],
) -> Result<WindowsBrokerPeerClaim, ProcessError> {
    use std::{fs::File, io::Read as _, os::windows::ffi::OsStringExt as _, ptr};

    use sha2::{Digest as _, Sha256};

    // SAFETY: OpenProcess has no Rust-side aliasing requirements; the returned
    // handle is checked and then owned by WinHandle.
    let process = unsafe {
        win32::OpenProcess(
            win32::PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            server_process_id,
        )
    };
    let process = WinHandle::new(process).ok_or(ProcessError::ProbeInvalid)?;

    let mut executable = vec![0_u16; win32::MAX_WINDOWS_PATH_CHARS];
    let mut executable_len =
        u32::try_from(executable.len()).map_err(|_| ProcessError::ProbeInvalid)?;
    // SAFETY: the process handle remains live and `executable` exposes a
    // writable buffer with its precise capacity in `executable_len`.
    let query_ok = unsafe {
        win32::QueryFullProcessImageNameW(
            process.get(),
            0,
            executable.as_mut_ptr(),
            &mut executable_len,
        )
    };
    if query_ok == 0 || executable_len == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    executable.truncate(executable_len as usize);
    let server_executable = PathBuf::from(std::ffi::OsString::from_wide(&executable));

    let mut token = ptr::null_mut();
    // SAFETY: process is valid and `token` is a writable HANDLE slot.
    let token_ok =
        unsafe { win32::OpenProcessToken(process.get(), win32::TOKEN_QUERY, &mut token) };
    if token_ok == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    let token = WinHandle::new(token).ok_or(ProcessError::ProbeInvalid)?;
    let server_is_local_system = token_is_local_system(token.get())?;
    let server_has_expected_restricted_service_sid =
        token_has_expected_restricted_service_sid(token.get())?;
    let scm_service_process_id = query_broker_service_process_id()?;

    let metadata = std::fs::metadata(&server_executable).map_err(|_| ProcessError::ProbeInvalid)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > win32::MAX_BROKER_EXE_BYTES {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut executable_file =
        File::open(&server_executable).map_err(|_| ProcessError::ProbeInvalid)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = executable_file
            .read(&mut buffer)
            .map_err(|_| ProcessError::ProbeInvalid)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let server_executable_sha256: [u8; 32] = hasher.finalize().into();

    Ok(WindowsBrokerPeerClaim {
        server_is_local_system,
        server_has_expected_restricted_service_sid,
        server_process_id,
        scm_service_process_id,
        server_executable,
        server_executable_sha256,
        expected_executable,
        expected_executable_sha256,
    })
}

#[cfg(windows)]
pub(crate) fn verify_windows_agent_process_id(client_process_id: u32) -> Result<(), ProcessError> {
    use std::ptr;

    if client_process_id <= 1 {
        return Err(ProcessError::ProbeInvalid);
    }
    // SAFETY: OpenProcess has no Rust-side aliasing requirements; the returned
    // handle is checked and then owned by WinHandle.
    let process = unsafe {
        win32::OpenProcess(
            win32::PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            client_process_id,
        )
    };
    let process = WinHandle::new(process).ok_or(ProcessError::ProbeInvalid)?;
    let mut token = ptr::null_mut();
    // SAFETY: process is valid and token is a live writable HANDLE slot.
    if unsafe { win32::OpenProcessToken(process.get(), win32::TOKEN_QUERY, &mut token) } == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    let token = WinHandle::new(token).ok_or(ProcessError::ProbeInvalid)?;
    let claim = WindowsAgentPeerClaim {
        client_is_local_service: token_is_well_known_account(
            token.get(),
            win32::WIN_LOCAL_SERVICE_SID,
        )?,
        client_has_expected_restricted_service_sid: token_has_restricted_service_sid(
            token.get(),
            "NT SERVICE\\mrd-relay-agent",
        )?,
        client_process_id,
        scm_service_process_id: query_service_process_id(AGENT_SERVICE)?,
    };
    validate_windows_agent_peer_claim(&claim).map_err(|_| ProcessError::ProbeInvalid)
}

#[cfg(windows)]
pub(crate) fn verify_windows_maintenance_process_id(
    client_process_id: u32,
) -> Result<WindowsMaintenancePeerClaim, ProcessError> {
    use std::{
        fs::File,
        io::Read as _,
        os::windows::{ffi::OsStringExt as _, fs::MetadataExt as _},
        ptr,
    };

    use sha2::{Digest as _, Sha256};

    fn process_path(process_id: u32) -> Result<PathBuf, ProcessError> {
        // SAFETY: OpenProcess has no Rust-side aliasing requirements; the
        // returned handle is checked and then owned by WinHandle.
        let process =
            unsafe { win32::OpenProcess(win32::PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        let process = WinHandle::new(process).ok_or(ProcessError::ProbeInvalid)?;
        let mut executable = vec![0_u16; win32::MAX_WINDOWS_PATH_CHARS];
        let mut executable_len =
            u32::try_from(executable.len()).map_err(|_| ProcessError::ProbeInvalid)?;
        // SAFETY: process is live and executable is a writable buffer of the
        // exact length advertised in executable_len.
        if unsafe {
            win32::QueryFullProcessImageNameW(
                process.get(),
                0,
                executable.as_mut_ptr(),
                &mut executable_len,
            )
        } == 0
            || executable_len == 0
        {
            return Err(ProcessError::ProbeInvalid);
        }
        executable.truncate(executable_len as usize);
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&executable)))
    }

    fn executable_sha256(path: &Path) -> Result<[u8; 32], ProcessError> {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        let metadata = std::fs::metadata(path).map_err(|_| ProcessError::ProbeInvalid)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() == 0
            || metadata.len() > win32::MAX_BROKER_EXE_BYTES
        {
            return Err(ProcessError::ProbeInvalid);
        }
        let mut input = File::open(path).map_err(|_| ProcessError::ProbeInvalid)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = input
                .read(&mut buffer)
                .map_err(|_| ProcessError::ProbeInvalid)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(hasher.finalize().into())
    }

    if client_process_id <= 1 {
        return Err(ProcessError::ProbeInvalid);
    }
    let agent_service = query_windows_agent_service_identity()?;
    let client_executable = process_path(client_process_id)?;
    let agent_service_executable = agent_service.executable;
    let agent_service_executable_sha256 = executable_sha256(&agent_service_executable)?;
    if let Some(agent_service_process_id) = agent_service.process_id {
        let running_executable = process_path(agent_service_process_id)?;
        if !windows_paths_equal(&running_executable, &agent_service_executable)
            || executable_sha256(&running_executable)? != agent_service_executable_sha256
        {
            return Err(ProcessError::ProbeInvalid);
        }
    }

    // SAFETY: the process handle is checked and remains owned through the
    // token query below.
    let process = unsafe {
        win32::OpenProcess(
            win32::PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            client_process_id,
        )
    };
    let process = WinHandle::new(process).ok_or(ProcessError::ProbeInvalid)?;
    let mut token = ptr::null_mut();
    // SAFETY: process is live and token is a writable HANDLE slot.
    if unsafe { win32::OpenProcessToken(process.get(), win32::TOKEN_QUERY, &mut token) } == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    let token = WinHandle::new(token).ok_or(ProcessError::ProbeInvalid)?;
    let claim = WindowsMaintenancePeerClaim {
        client_is_elevated_administrator: token_is_elevated_administrator(token.get())?,
        client_process_id,
        agent_service_process_id: agent_service.process_id,
        client_executable_sha256: executable_sha256(&client_executable)?,
        agent_service_executable_sha256,
        client_executable,
        agent_service_executable,
    };
    validate_windows_maintenance_peer_claim(&claim).map_err(|_| ProcessError::ProbeInvalid)?;
    Ok(claim)
}

#[cfg(windows)]
fn token_is_elevated_administrator(token: *mut std::ffi::c_void) -> Result<bool, ProcessError> {
    let mut sid = [0_u8; win32::SECURITY_MAX_SID_SIZE];
    let mut sid_len = u32::try_from(sid.len()).map_err(|_| ProcessError::ProbeInvalid)?;
    // SAFETY: sid is a suitably sized writable buffer and sid_len advertises
    // its exact capacity.
    if unsafe {
        win32::CreateWellKnownSid(
            win32::WIN_BUILTIN_ADMINISTRATORS_SID,
            std::ptr::null(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
        )
    } == 0
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut is_member = 0_i32;
    // SAFETY: token is live, sid contains a Windows-created SID, and
    // is_member is a writable result scalar.
    if unsafe { win32::CheckTokenMembership(token, sid.as_ptr().cast(), &mut is_member) } == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    Ok(is_member != 0)
}

#[cfg(windows)]
fn token_has_expected_restricted_service_sid(
    token: *mut std::ffi::c_void,
) -> Result<bool, ProcessError> {
    token_has_restricted_service_sid(token, "NT SERVICE\\mrd-relay-coturn-control")
}

#[cfg(windows)]
fn token_has_restricted_service_sid(
    token: *mut std::ffi::c_void,
    account_name: &str,
) -> Result<bool, ProcessError> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt as _, ptr};

    let account: Vec<u16> = std::ffi::OsStr::new(account_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sid_len = 0_u32;
    let mut domain_len = 0_u32;
    let mut sid_use = 0_i32;
    // SAFETY: null output buffers are the documented sizing probe; all size
    // outputs are valid writable scalars and account is NUL terminated.
    unsafe {
        win32::LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut sid_use,
        );
    }
    if sid_len == 0
        || sid_len > win32::MAX_SID_BYTES
        || domain_len > win32::MAX_WINDOWS_PATH_CHARS as u32
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut service_sid = vec![0_u8; sid_len as usize];
    let mut domain = vec![0_u16; domain_len.max(1) as usize];
    // SAFETY: both output buffers match the lengths supplied to Windows.
    let lookup_ok = unsafe {
        win32::LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            service_sid.as_mut_ptr().cast::<c_void>(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if lookup_ok == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    let service_sid = service_sid.as_ptr().cast::<c_void>();
    Ok(
        token_group_contains_sid(token, win32::TOKEN_GROUPS_CLASS, service_sid)?
            && token_group_contains_sid(token, win32::TOKEN_RESTRICTED_SIDS_CLASS, service_sid)?,
    )
}

#[cfg(windows)]
fn token_group_contains_sid(
    token: *mut std::ffi::c_void,
    information_class: i32,
    expected_sid: *const std::ffi::c_void,
) -> Result<bool, ProcessError> {
    use std::{ffi::c_void, ptr};

    let mut required = 0_u32;
    // SAFETY: documented sizing probe with a valid return-length pointer.
    unsafe {
        win32::GetTokenInformation(token, information_class, ptr::null_mut(), 0, &mut required);
    }
    if required < u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX)
        || required > win32::MAX_TOKEN_INFORMATION_BYTES
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut buffer = vec![0_u8; required as usize];
    // SAFETY: buffer has exactly required writable bytes.
    let query_ok = unsafe {
        win32::GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    };
    if query_ok == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    // SAFETY: successful TOKEN_GROUPS responses begin with a u32 count.
    let count = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    if count > win32::MAX_TOKEN_GROUPS {
        return Err(ProcessError::ProbeInvalid);
    }
    let first_group_offset: usize = if std::mem::size_of::<usize>() == 8 {
        8
    } else {
        4
    };
    let entry_bytes = std::mem::size_of::<win32::SidAndAttributesRaw>();
    let required_entries = first_group_offset
        .checked_add(
            count
                .checked_mul(entry_bytes)
                .ok_or(ProcessError::ProbeInvalid)?,
        )
        .ok_or(ProcessError::ProbeInvalid)?;
    if required_entries > buffer.len() {
        return Err(ProcessError::ProbeInvalid);
    }
    for index in 0..count {
        // SAFETY: bounds above cover every fixed-size SID_AND_ATTRIBUTES
        // entry; read_unaligned avoids relying on Vec<u8> alignment.
        let group = unsafe {
            ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(first_group_offset + index * entry_bytes)
                    .cast::<win32::SidAndAttributesRaw>(),
            )
        };
        if group.sid.is_null() {
            return Err(ProcessError::ProbeInvalid);
        }
        // SAFETY: token group SID pointers and expected_sid are Windows-owned
        // valid SID objects for the duration of this call.
        if unsafe { win32::EqualSid(group.sid.cast_const(), expected_sid) != 0 } {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn query_broker_service_process_id() -> Result<u32, ProcessError> {
    query_service_process_id(BROKER_SERVICE)
}

#[cfg(windows)]
struct WindowsAgentServiceIdentity {
    executable: PathBuf,
    process_id: Option<u32>,
}

#[cfg(windows)]
fn query_windows_agent_service_identity() -> Result<WindowsAgentServiceIdentity, ProcessError> {
    use std::{os::windows::ffi::OsStrExt as _, ptr};

    // SAFETY: null machine/database select the local active SCM database.
    let manager =
        unsafe { win32::OpenSCManagerW(ptr::null(), ptr::null(), win32::SC_MANAGER_CONNECT) };
    let manager = ScHandle::new(manager).ok_or(ProcessError::ProbeInvalid)?;
    let service_name: Vec<u16> = std::ffi::OsStr::new(AGENT_SERVICE)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: manager is live and service_name is NUL terminated.
    let service = unsafe {
        win32::OpenServiceW(
            manager.get(),
            service_name.as_ptr(),
            win32::SERVICE_QUERY_STATUS | win32::SERVICE_QUERY_CONFIG,
        )
    };
    let service = ScHandle::new(service).ok_or(ProcessError::ProbeInvalid)?;

    let mut status = win32::ServiceStatusProcessRaw::default();
    let mut needed = 0_u32;
    // SAFETY: status is writable and its exact size is supplied.
    if unsafe {
        win32::QueryServiceStatusEx(
            service.get(),
            win32::SC_STATUS_PROCESS_INFO,
            (&mut status as *mut win32::ServiceStatusProcessRaw).cast(),
            std::mem::size_of::<win32::ServiceStatusProcessRaw>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let process_id = match (status.current_state, status.process_id) {
        (win32::SERVICE_RUNNING, process_id) if process_id > 1 => Some(process_id),
        (win32::SERVICE_STOPPED, 0) => None,
        _ => return Err(ProcessError::ProbeInvalid),
    };

    needed = 0;
    // SAFETY: this documented sizing probe writes only needed.
    unsafe {
        let _ = win32::QueryServiceConfigW(service.get(), ptr::null_mut(), 0, &mut needed);
    }
    if needed < std::mem::size_of::<win32::QueryServiceConfigRaw>() as u32
        || needed > win32::MAX_SERVICE_CONFIG_BYTES
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let word_count = (needed as usize)
        .checked_add(std::mem::size_of::<u64>() - 1)
        .ok_or(ProcessError::ProbeInvalid)?
        / std::mem::size_of::<u64>();
    let mut config_buffer = vec![0_u64; word_count];
    // SAFETY: the u64-backed buffer is suitably aligned and contains at least
    // needed writable bytes. QueryServiceConfigW keeps all string pointers
    // inside this buffer for the duration of the call.
    if unsafe {
        win32::QueryServiceConfigW(
            service.get(),
            config_buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(ProcessError::ProbeInvalid);
    }
    // SAFETY: successful QueryServiceConfigW initialized the leading fixed
    // QUERY_SERVICE_CONFIGW structure in the aligned buffer.
    let config = unsafe {
        &*config_buffer
            .as_ptr()
            .cast::<win32::QueryServiceConfigRaw>()
    };
    let command_pointer = config.binary_path_name;
    let start = config_buffer.as_ptr() as usize;
    let end = start
        .checked_add(config_buffer.len() * std::mem::size_of::<u64>())
        .ok_or(ProcessError::ProbeInvalid)?;
    let command_start = command_pointer as usize;
    if command_pointer.is_null()
        || command_start < start
        || command_start >= end
        || !command_start.is_multiple_of(std::mem::align_of::<u16>())
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let max_units = (end - command_start) / std::mem::size_of::<u16>();
    // SAFETY: the pointer was range/alignment checked and max_units stays
    // wholly inside the live SCM output buffer.
    let units = unsafe { std::slice::from_raw_parts(command_pointer, max_units) };
    let command_len = units
        .iter()
        .position(|unit| *unit == 0)
        .filter(|length| *length != 0 && *length <= win32::MAX_WINDOWS_PATH_CHARS)
        .ok_or(ProcessError::ProbeInvalid)?;
    let command =
        String::from_utf16(&units[..command_len]).map_err(|_| ProcessError::ProbeInvalid)?;
    let executable =
        parse_windows_agent_service_command(&command).map_err(|_| ProcessError::ProbeInvalid)?;
    Ok(WindowsAgentServiceIdentity {
        executable,
        process_id,
    })
}

#[cfg(windows)]
fn query_service_process_id(service_name: &str) -> Result<u32, ProcessError> {
    use std::{os::windows::ffi::OsStrExt as _, ptr};

    // SAFETY: null machine/database select the local active SCM database.
    let manager =
        unsafe { win32::OpenSCManagerW(ptr::null(), ptr::null(), win32::SC_MANAGER_CONNECT) };
    let manager = ScHandle::new(manager).ok_or(ProcessError::ProbeInvalid)?;
    let service_name: Vec<u16> = std::ffi::OsStr::new(service_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: manager is valid and service_name is NUL terminated.
    let service = unsafe {
        win32::OpenServiceW(
            manager.get(),
            service_name.as_ptr(),
            win32::SERVICE_QUERY_STATUS,
        )
    };
    let service = ScHandle::new(service).ok_or(ProcessError::ProbeInvalid)?;
    let mut status = win32::ServiceStatusProcessRaw::default();
    let mut needed = 0_u32;
    // SAFETY: status is a writable buffer with its exact byte length.
    let query_ok = unsafe {
        win32::QueryServiceStatusEx(
            service.get(),
            win32::SC_STATUS_PROCESS_INFO,
            (&mut status as *mut win32::ServiceStatusProcessRaw).cast::<u8>(),
            std::mem::size_of::<win32::ServiceStatusProcessRaw>() as u32,
            &mut needed,
        )
    };
    if query_ok == 0 || status.current_state != win32::SERVICE_RUNNING || status.process_id <= 1 {
        return Err(ProcessError::ProbeInvalid);
    }
    Ok(status.process_id)
}

#[cfg(windows)]
fn token_is_local_system(token: *mut std::ffi::c_void) -> Result<bool, ProcessError> {
    token_is_well_known_account(token, win32::WIN_LOCAL_SYSTEM_SID)
}

#[cfg(windows)]
fn token_is_well_known_account(
    token: *mut std::ffi::c_void,
    well_known_sid_type: i32,
) -> Result<bool, ProcessError> {
    use std::{ffi::c_void, ptr};

    let mut required = 0_u32;
    // SAFETY: the null probe is the documented way to obtain the required
    // TOKEN_USER buffer size; `required` is a valid writable u32.
    unsafe {
        win32::GetTokenInformation(
            token,
            win32::TOKEN_USER_CLASS,
            ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required < std::mem::size_of::<win32::TokenUserRaw>() as u32
        || required > win32::MAX_TOKEN_INFORMATION_BYTES
    {
        return Err(ProcessError::ProbeInvalid);
    }
    let mut token_user = vec![0_u8; required as usize];
    // SAFETY: token_user is a writable buffer of exactly `required` bytes.
    let token_ok = unsafe {
        win32::GetTokenInformation(
            token,
            win32::TOKEN_USER_CLASS,
            token_user.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    };
    if token_ok == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    // SAFETY: GetTokenInformation(TokenUser) wrote a TOKEN_USER at the start
    // of the suitably aligned allocator-backed buffer. read_unaligned avoids
    // relying on Vec<u8>'s alignment.
    let token_user =
        unsafe { std::ptr::read_unaligned(token_user.as_ptr().cast::<win32::TokenUserRaw>()) };
    if token_user.user.sid.is_null() {
        return Err(ProcessError::ProbeInvalid);
    }

    let mut local_system_sid = [0_u8; win32::SECURITY_MAX_SID_SIZE];
    let mut sid_len = local_system_sid.len() as u32;
    // SAFETY: local_system_sid is a writable buffer of sid_len bytes and no
    // domain SID is needed for WinLocalSystemSid.
    let sid_ok = unsafe {
        win32::CreateWellKnownSid(
            well_known_sid_type,
            ptr::null(),
            local_system_sid.as_mut_ptr().cast::<c_void>(),
            &mut sid_len,
        )
    };
    if sid_ok == 0 {
        return Err(ProcessError::ProbeInvalid);
    }
    // SAFETY: both arguments point at SID structures supplied by Windows.
    Ok(unsafe {
        win32::EqualSid(
            token_user.user.sid.cast_const(),
            local_system_sid.as_ptr().cast::<c_void>(),
        ) != 0
    })
}

#[cfg(windows)]
struct WinHandle(*mut std::ffi::c_void);

#[cfg(windows)]
impl WinHandle {
    fn new(handle: *mut std::ffi::c_void) -> Option<Self> {
        (!handle.is_null()).then_some(Self(handle))
    }

    fn get(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

#[cfg(windows)]
impl Drop for WinHandle {
    fn drop(&mut self) {
        // SAFETY: WinHandle is created only for unique non-null handles
        // returned by OpenProcess/OpenProcessToken and closes exactly once.
        unsafe {
            win32::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct ScHandle(*mut std::ffi::c_void);

#[cfg(windows)]
impl ScHandle {
    fn new(handle: *mut std::ffi::c_void) -> Option<Self> {
        (!handle.is_null()).then_some(Self(handle))
    }

    fn get(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

#[cfg(windows)]
impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: ScHandle uniquely owns an SCM handle and closes once.
        unsafe {
            win32::CloseServiceHandle(self.0);
        }
    }
}

#[cfg(windows)]
mod win32 {
    use std::ffi::c_void;

    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_USER_CLASS: i32 = 1;
    pub const TOKEN_GROUPS_CLASS: i32 = 2;
    pub const TOKEN_RESTRICTED_SIDS_CLASS: i32 = 11;
    pub const WIN_LOCAL_SYSTEM_SID: i32 = 22;
    pub const WIN_LOCAL_SERVICE_SID: i32 = 23;
    pub const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
    pub const SECURITY_MAX_SID_SIZE: usize = 68;
    pub const MAX_TOKEN_INFORMATION_BYTES: u32 = 64 * 1024;
    pub const MAX_TOKEN_GROUPS: usize = 1024;
    pub const MAX_SID_BYTES: u32 = 1024;
    pub const MAX_WINDOWS_PATH_CHARS: usize = 32_768;
    pub const MAX_BROKER_EXE_BYTES: u64 = 256 * 1024 * 1024;
    pub const MAX_SERVICE_CONFIG_BYTES: u32 = 64 * 1024;
    pub const SC_MANAGER_CONNECT: u32 = 0x0001;
    pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
    pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
    pub const SC_STATUS_PROCESS_INFO: i32 = 0;
    pub const SERVICE_STOPPED: u32 = 1;
    pub const SERVICE_RUNNING: u32 = 4;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SidAndAttributesRaw {
        pub sid: *mut c_void,
        pub attributes: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TokenUserRaw {
        pub user: SidAndAttributesRaw,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ServiceStatusProcessRaw {
        pub service_type: u32,
        pub current_state: u32,
        pub controls_accepted: u32,
        pub win32_exit_code: u32,
        pub service_specific_exit_code: u32,
        pub check_point: u32,
        pub wait_hint: u32,
        pub process_id: u32,
        pub service_flags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct QueryServiceConfigRaw {
        pub service_type: u32,
        pub start_type: u32,
        pub error_control: u32,
        pub binary_path_name: *const u16,
        pub load_order_group: *const u16,
        pub tag_id: u32,
        pub dependencies: *const u16,
        pub service_start_name: *const u16,
        pub display_name: *const u16,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetNamedPipeServerProcessId(pipe: *mut c_void, process_id: *mut u32) -> i32;
        pub fn OpenProcess(access: u32, inherit_handle: i32, process_id: u32) -> *mut c_void;
        pub fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            executable_name: *mut u16,
            size: *mut u32,
        ) -> i32;
        pub fn CloseHandle(handle: *mut c_void) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn OpenProcessToken(
            process: *mut c_void,
            desired_access: u32,
            token: *mut *mut c_void,
        ) -> i32;
        pub fn GetTokenInformation(
            token: *mut c_void,
            information_class: i32,
            information: *mut c_void,
            information_len: u32,
            return_len: *mut u32,
        ) -> i32;
        pub fn CreateWellKnownSid(
            sid_type: i32,
            domain_sid: *const c_void,
            sid: *mut c_void,
            sid_size: *mut u32,
        ) -> i32;
        pub fn EqualSid(first_sid: *const c_void, second_sid: *const c_void) -> i32;
        pub fn CheckTokenMembership(
            token: *mut c_void,
            sid_to_check: *const c_void,
            is_member: *mut i32,
        ) -> i32;
        pub fn LookupAccountNameW(
            system_name: *const u16,
            account_name: *const u16,
            sid: *mut c_void,
            sid_size: *mut u32,
            referenced_domain_name: *mut u16,
            referenced_domain_name_size: *mut u32,
            sid_name_use: *mut i32,
        ) -> i32;
        pub fn OpenSCManagerW(
            machine_name: *const u16,
            database_name: *const u16,
            desired_access: u32,
        ) -> *mut c_void;
        pub fn OpenServiceW(
            manager: *mut c_void,
            service_name: *const u16,
            desired_access: u32,
        ) -> *mut c_void;
        pub fn QueryServiceStatusEx(
            service: *mut c_void,
            information_level: i32,
            buffer: *mut u8,
            buffer_size: u32,
            bytes_needed: *mut u32,
        ) -> i32;
        pub fn QueryServiceConfigW(
            service: *mut c_void,
            service_config: *mut QueryServiceConfigRaw,
            buffer_size: u32,
            bytes_needed: *mut u32,
        ) -> i32;
        pub fn CloseServiceHandle(handle: *mut c_void) -> i32;
    }
}

#[cfg(test)]
mod service_lifecycle_tests {
    use std::cell::Cell;

    use super::{drive_windows_service_after_start_pending, WindowsServiceStatusUpdate};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestError {
        Configure,
        Body,
        RunningStatus,
        StopPendingStatus,
        TerminalStatus,
    }

    #[test]
    fn configuration_failure_reports_service_specific_stopped_without_running_the_body() {
        let body_called = Cell::new(false);
        let mut statuses = Vec::new();

        let result = drive_windows_service_after_start_pending(
            || Err::<(), _>(TestError::Configure),
            |()| {
                body_called.set(true);
                Ok(())
            },
            |status| {
                statuses.push(status);
                Ok(())
            },
        );

        assert_eq!(result, Err(TestError::Configure));
        assert!(!body_called.get());
        assert_eq!(statuses, [WindowsServiceStatusUpdate::StoppedFailure]);
    }

    #[test]
    fn body_failure_reports_running_then_service_specific_stopped() {
        let mut statuses = Vec::new();

        let result = drive_windows_service_after_start_pending(
            || Ok(()),
            |()| Err(TestError::Body),
            |status| {
                statuses.push(status);
                Ok(())
            },
        );

        assert_eq!(result, Err(TestError::Body));
        assert_eq!(
            statuses,
            [
                WindowsServiceStatusUpdate::Running,
                WindowsServiceStatusUpdate::StoppedFailure,
            ]
        );
    }

    #[test]
    fn running_status_failure_still_reports_service_specific_stopped() {
        let body_called = Cell::new(false);
        let mut statuses = Vec::new();

        let result = drive_windows_service_after_start_pending(
            || Ok(()),
            |()| {
                body_called.set(true);
                Ok(())
            },
            |status| {
                statuses.push(status);
                if status == WindowsServiceStatusUpdate::Running {
                    Err(TestError::RunningStatus)
                } else {
                    Ok(())
                }
            },
        );

        assert_eq!(result, Err(TestError::RunningStatus));
        assert!(!body_called.get());
        assert_eq!(
            statuses,
            [
                WindowsServiceStatusUpdate::Running,
                WindowsServiceStatusUpdate::StoppedFailure,
            ]
        );
    }

    #[test]
    fn stop_pending_failure_is_converted_to_service_specific_stopped() {
        let mut statuses = Vec::new();

        let result = drive_windows_service_after_start_pending(
            || Ok(()),
            |()| Ok(()),
            |status| {
                statuses.push(status);
                if status == WindowsServiceStatusUpdate::StopPending {
                    Err(TestError::StopPendingStatus)
                } else {
                    Ok(())
                }
            },
        );

        assert_eq!(result, Err(TestError::StopPendingStatus));
        assert_eq!(
            statuses,
            [
                WindowsServiceStatusUpdate::Running,
                WindowsServiceStatusUpdate::StopPending,
                WindowsServiceStatusUpdate::StoppedFailure,
            ]
        );
    }

    #[test]
    fn normal_stop_reports_stop_pending_then_win32_stopped() {
        let mut statuses = Vec::new();

        let result = drive_windows_service_after_start_pending(
            || Ok(()),
            |()| Ok(()),
            |status| {
                statuses.push(status);
                Ok::<_, TestError>(())
            },
        );

        assert_eq!(result, Ok(()));
        assert_eq!(
            statuses,
            [
                WindowsServiceStatusUpdate::Running,
                WindowsServiceStatusUpdate::StopPending,
                WindowsServiceStatusUpdate::StoppedSuccess,
            ]
        );
    }

    #[test]
    fn terminal_status_failure_is_returned_on_both_success_and_failure_paths() {
        for body_result in [Ok(()), Err(TestError::Body)] {
            let mut statuses = Vec::new();

            let result = drive_windows_service_after_start_pending(
                || Ok(()),
                |()| body_result,
                |status| {
                    statuses.push(status);
                    if matches!(
                        status,
                        WindowsServiceStatusUpdate::StoppedSuccess
                            | WindowsServiceStatusUpdate::StoppedFailure
                    ) {
                        Err(TestError::TerminalStatus)
                    } else {
                        Ok(())
                    }
                },
            );

            assert_eq!(result, Err(TestError::TerminalStatus));
            assert!(matches!(
                statuses.last(),
                Some(
                    WindowsServiceStatusUpdate::StoppedSuccess
                        | WindowsServiceStatusUpdate::StoppedFailure
                )
            ));
        }
    }
}

#[cfg(test)]
mod data_root_tests {
    use serde_json::{json, Value};

    use super::WindowsTargetConfig;

    fn docker_target_document() -> Value {
        json!({
            "schema_version": 1,
            "target": "Docker",
            "control_pipe": "\\\\.\\pipe\\mrd-relay-coturn-control",
            "minimum_coturn_version": "4.17.2",
            "tls_port": 5349,
            "relay_port_min": 49160,
            "relay_port_max": 49260,
            "max_allocations": 100,
            "max_egress_bps": 1_000_000_000_u64,
            "coturn_bps_capacity_bytes_per_second": 125_000_000_u64,
            "metrics_bind": "127.0.0.1:9641",
            "local_acceptance_command": [
                "preflight", "--config", "ABSOLUTE_CONFIG", "--challenge", "HEX64"
            ],
            "turnserver_baseline_path":
                "D:\\中继数据\\MRD\\RelayAgent\\broker\\turnserver.conf.base",
            "configured_endpoints": [
                "turn:relay.example.test:3478?transport=udp",
                "turn:relay.example.test:3478?transport=tcp",
                "turns:relay.example.test:5349?transport=tcp"
            ],
            "transport_capabilities": ["turn_udp", "turn_tcp", "turns_tcp"],
            "RestartPolicy": "restart=no",
            "docker_executable":
                "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
            "container_name": "mrd-coturn",
            "expected_container_id_state_path":
                "d:\\中继数据\\mrd\\relayagent\\BROKER\\docker-identity.json",
            "image": concat!(
                "coturn/coturn:4.17.2@sha256:",
                "aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e"
            ),
            "labels": {"io.mrd.relay.managed": "true"},
            "read_only_rootfs": true,
            "bind_mounts": [
                {
                    "source": "D:\\中继数据\\MRD\\RelayAgent\\broker\\docker-envelope",
                    "destination": "/run/mrd/turnserver.conf",
                    "read_only": true
                },
                {
                    "source": "D:\\中继数据\\MRD\\RelayAgent\\tls",
                    "destination": "/run/mrd/tls",
                    "read_only": true
                }
            ],
            "published_ports": [
                "3478:3478/udp", "3478:3478/tcp", "5349:5349/tcp",
                "49160-49260:49160-49260/udp", "49160-49260:49160-49260/tcp",
                "127.0.0.1:9641:9641/tcp"
            ]
        })
    }

    #[test]
    fn docker_target_accepts_an_exact_custom_unicode_data_root_layout() {
        let encoded = serde_json::to_vec(&docker_target_document()).unwrap();
        let target = WindowsTargetConfig::parse(&encoded).unwrap();

        assert_eq!(
            target.baseline_path().to_string_lossy(),
            r"D:\中继数据\MRD\RelayAgent\broker\turnserver.conf.base"
        );
        assert_eq!(
            target.docker_identity_path().unwrap().to_string_lossy(),
            r"d:\中继数据\mrd\relayagent\BROKER\docker-identity.json"
        );
    }

    #[test]
    fn docker_target_rejects_paths_outside_the_exact_data_root_layout() {
        for (pointer, invalid_path) in [
            (
                "/turnserver_baseline_path",
                r"D:\中继数据\MRD\RelayAgent\broker\other.conf.base",
            ),
            (
                "/expected_container_id_state_path",
                r"D:\中继数据\MRD\RelayAgent-evil\broker\docker-identity.json",
            ),
            (
                "/expected_container_id_state_path",
                r"E:\中继数据\MRD\RelayAgent\broker\docker-identity.json",
            ),
            (
                "/bind_mounts/0/source",
                r"D:\中继数据\MRD\RelayAgent\broker\sub\docker-envelope",
            ),
            (
                "/bind_mounts/1/source",
                r"D:\中继数据\MRD\RelayAgent\tls-copy",
            ),
            (
                "/bind_mounts/0/source",
                r"D:\中继数据\MRD\RelayAgent\broker\..\broker\docker-envelope",
            ),
            (
                "/bind_mounts/0/source",
                r"D:\中继数据\MRD\RelayAgent\broker\docker-envelope:stream",
            ),
        ] {
            let mut document = docker_target_document();
            *document.pointer_mut(pointer).unwrap() = Value::String(invalid_path.to_owned());
            let encoded = serde_json::to_vec(&document).unwrap();
            assert!(
                WindowsTargetConfig::parse(&encoded).is_err(),
                "accepted {pointer}={invalid_path}"
            );
        }
    }

    #[test]
    fn docker_target_rejects_mount_ambiguous_data_root_components() {
        for replacement in ["中继,数据", "中继=数据"] {
            let mut document = docker_target_document();
            for pointer in [
                "/turnserver_baseline_path",
                "/expected_container_id_state_path",
                "/bind_mounts/0/source",
                "/bind_mounts/1/source",
            ] {
                let current = document.pointer(pointer).unwrap().as_str().unwrap();
                *document.pointer_mut(pointer).unwrap() =
                    Value::String(current.replace("中继数据", replacement));
            }
            let encoded = serde_json::to_vec(&document).unwrap();
            assert!(
                WindowsTargetConfig::parse(&encoded).is_err(),
                "accepted Docker DataRoot component {replacement}"
            );
        }
    }
}
