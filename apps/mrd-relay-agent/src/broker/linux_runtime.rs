use std::{
    ffi::{CStr, CString},
    fs::File,
    io::Read as _,
    os::{fd::FromRawFd as _, unix::fs::MetadataExt as _},
    path::Path,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mrd_transport_webrtc::{probe_turn_relay, IceServerConfig, TurnRelayProbeConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    process::Command,
};
use zeroize::Zeroizing;

use crate::{
    broker::{
        canonical_turn_secret_bytes, decode_request_frame, derive_coturn_rest_credentials,
        encode_response_frame, render_linux_coturn_config, select_pending_recovery,
        validate_probe_stability, CoturnRestCredentials, LinuxClientPeerClaim,
        PendingRecoveryAction, PendingRecoveryObservation, ProbeStabilityObservation,
        RenderedCoturnConfig, SocketActivationClaim,
    },
    metrics::{MetricsLimits, NativeCoturnScrapePort as _, ReqwestNativeCoturnScrape},
    platform::{
        broker_drain_proof_payload,
        linux::{
            linux_probe_loopback_host, select_linux_drain_recovery,
            validate_unique_wsl_interop_registration, LinuxCommittedState as CommittedState,
            LinuxDrainJournalClaim, LinuxDrainJournalPhase, LinuxDrainRecoveryAction,
            LinuxDrainStateClaim, LinuxDrainTargetClaim, LinuxPendingDrainJournal,
            LinuxPendingDrainOperation, LinuxPendingOperation,
            LinuxPendingSecretJournal as PendingJournal, AGENT_USER, COTURN_UNIT,
            GENERATED_CONFIG_PATH,
        },
        probe_proof_sha256, BrokerAction, BrokerRequest, CoturnTarget, FRAME_HEADER_BYTES,
        MAX_CONTROL_OUTPUT_BYTES,
    },
    process::SecretBytes,
    secure_store::{AtomicEnvelopeFile as _, HardenedAtomicFile},
};

const FIRST_SOCKET_FD: i32 = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(14);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(6);
const START_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PRIVATE_FILE_BYTES: usize = 128 * 1024;
const MAX_STATE_BYTES: usize = 32 * 1024;
const BASE_CONFIG_PATH: &str = "/etc/mrd-relay-agent/coturn/turnserver.conf.base";
const SECRET_PATH: &str = "/etc/mrd-relay-agent/secrets/turn-rest-secret";
const STATE_DIRECTORY: &str = "/var/lib/mrd-coturn";
const STATE_PATH: &str = "/var/lib/mrd-coturn/control-state.json";
const JOURNAL_PATH: &str = "/var/lib/mrd-coturn/control-journal.json";
const BACKUP_SECRET_PATH: &str = "/var/lib/mrd-coturn/control-previous-secret";
const BACKUP_CONFIG_PATH: &str = "/var/lib/mrd-coturn/control-previous-config";
const LOCK_PATH: &str = "/var/lib/mrd-coturn/control.lock";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const METRICS_URL: &str = "http://127.0.0.1:9641/metrics";
const EXPECTED_SOCKET_FD_NAME: &str = "mrd-relay-coturn-control";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BrokerRuntimeError {
    #[error("relay_broker_cli_invalid")]
    CliInvalid,
    #[error("relay_broker_activation_invalid")]
    ActivationInvalid,
    #[error("relay_broker_peer_rejected")]
    PeerRejected,
    #[error("relay_broker_frame_invalid")]
    FrameInvalid,
    #[error("relay_broker_lock_failed")]
    LockFailed,
    #[error("relay_broker_state_invalid")]
    StateInvalid,
    #[error("relay_broker_target_failed")]
    TargetFailed,
    #[error("relay_broker_probe_failed")]
    ProbeFailed,
    #[error("relay_broker_io_failed")]
    IoFailed,
}

#[derive(Default)]
struct SystemdObservation {
    invocation_id: Option<String>,
    active_state: String,
    sub_state: String,
    main_pid: u32,
    ingress_bytes: Option<u64>,
    egress_bytes: Option<u64>,
    result: String,
    exec_main_status: i32,
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
    transport_capabilities: &'a [crate::platform::TransportCapability],
    configured_endpoints: &'a [String],
    draining: bool,
    drain_completed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DelegatedSnapshotWire {
    target: String,
    generation: u64,
    applied_secret_version: u64,
    health: String,
    active_allocations: u32,
    counter_source: String,
    counter_epoch: String,
    total_ingress_bytes: u64,
    total_egress_bytes: u64,
    measurement_monotonic_ns: u64,
    configured_max_allocations: u32,
    configured_max_egress_bps: u64,
    relay_min_port: u16,
    relay_max_port: u16,
    transport_capabilities: Vec<crate::platform::TransportCapability>,
    configured_endpoints: Vec<String>,
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

struct VerifiedMaterial {
    raw_secret: Zeroizing<Vec<u8>>,
    rendered: RenderedCoturnConfig,
    secret_sha256: String,
    config_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WslBrokerAction {
    Snapshot,
    Restart,
    ApplySecret(u64),
    SetDraining(bool),
}

#[derive(Clone, Copy)]
struct LinuxDrainCompletionObservation<'a> {
    invocation_id: Option<&'a str>,
    target_active: bool,
    clean_exit: bool,
    active_allocations: Option<u32>,
}

pub async fn run_linux_socket_activated() -> Result<(), BrokerRuntimeError> {
    tokio::time::timeout(REQUEST_TIMEOUT, run_linux_socket_activated_inner())
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)?
}

pub async fn run_linux_wsl_broker(
    arguments: Vec<std::ffi::OsString>,
) -> Result<(), BrokerRuntimeError> {
    tokio::time::timeout(REQUEST_TIMEOUT, run_linux_wsl_broker_inner(arguments))
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)?
}

async fn run_linux_wsl_broker_inner(
    arguments: Vec<std::ffi::OsString>,
) -> Result<(), BrokerRuntimeError> {
    let action = parse_wsl_action(&arguments)?;
    if unsafe { libc::geteuid() } != 0 || !has_wsl2_kernel_evidence()? {
        return Err(BrokerRuntimeError::ActivationInvalid);
    }
    let input = read_wsl_stdin().await?;
    let secret = validate_wsl_stdin(action, input)?;
    let request = build_wsl_request(action, secret)?;
    let payload = {
        let _lock = acquire_global_lock()?;
        handle_request(request).await?
    };
    let payload = relabel_wsl_snapshot(&payload)?;
    let mut stdout = tokio::io::stdout();
    stdout
        .write_all(&payload)
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)?;
    stdout
        .flush()
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)
}

fn parse_wsl_action(
    arguments: &[std::ffi::OsString],
) -> Result<WslBrokerAction, BrokerRuntimeError> {
    let arguments = arguments
        .iter()
        .map(|value| value.to_str())
        .collect::<Option<Vec<_>>>()
        .ok_or(BrokerRuntimeError::CliInvalid)?;
    match arguments.as_slice() {
        ["snapshot"] => Ok(WslBrokerAction::Snapshot),
        ["restart"] => Ok(WslBrokerAction::Restart),
        ["apply-secret", version] => {
            if version.is_empty()
                || version.starts_with('0')
                || version.len() > 20
                || !version.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(BrokerRuntimeError::CliInvalid);
            }
            let version = version
                .parse::<u64>()
                .ok()
                .filter(|value| *value != 0)
                .ok_or(BrokerRuntimeError::CliInvalid)?;
            Ok(WslBrokerAction::ApplySecret(version))
        }
        ["set-draining", "true"] => Ok(WslBrokerAction::SetDraining(true)),
        ["set-draining", "false"] => Ok(WslBrokerAction::SetDraining(false)),
        _ => Err(BrokerRuntimeError::CliInvalid),
    }
}

async fn read_wsl_stdin() -> Result<Zeroizing<Vec<u8>>, BrokerRuntimeError> {
    let mut input = Zeroizing::new(Vec::with_capacity(33));
    tokio::io::stdin()
        .take(33)
        .read_to_end(&mut input)
        .await
        .map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    Ok(input)
}

fn validate_wsl_stdin(
    action: WslBrokerAction,
    mut input: Zeroizing<Vec<u8>>,
) -> Result<Option<SecretBytes>, BrokerRuntimeError> {
    match action {
        WslBrokerAction::ApplySecret(_) if input.len() == 32 => {
            Ok(Some(SecretBytes::new(std::mem::take(&mut *input))))
        }
        WslBrokerAction::ApplySecret(_) => Err(BrokerRuntimeError::FrameInvalid),
        _ if input.is_empty() => Ok(None),
        _ => Err(BrokerRuntimeError::FrameInvalid),
    }
}

fn build_wsl_request(
    action: WslBrokerAction,
    secret: Option<SecretBytes>,
) -> Result<BrokerRequest, BrokerRuntimeError> {
    match (action, secret) {
        (WslBrokerAction::Snapshot, None) => {
            Ok(BrokerRequest::snapshot(CoturnTarget::LinuxSystemd))
        }
        (WslBrokerAction::Restart, None) => Ok(BrokerRequest::restart(CoturnTarget::LinuxSystemd)),
        (WslBrokerAction::ApplySecret(version), Some(secret)) => {
            BrokerRequest::apply_secret(CoturnTarget::LinuxSystemd, version, secret)
                .map_err(|_| BrokerRuntimeError::FrameInvalid)
        }
        (WslBrokerAction::SetDraining(draining), None) => Ok(BrokerRequest::set_draining(
            CoturnTarget::LinuxSystemd,
            draining,
        )),
        _ => Err(BrokerRuntimeError::FrameInvalid),
    }
}

fn relabel_wsl_snapshot(payload: &[u8]) -> Result<Vec<u8>, BrokerRuntimeError> {
    if payload.is_empty() || payload.len() > MAX_CONTROL_OUTPUT_BYTES {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let mut snapshot: DelegatedSnapshotWire =
        serde_json::from_slice(payload).map_err(|_| BrokerRuntimeError::StateInvalid)?;
    if snapshot.target != CoturnTarget::LinuxSystemd.as_str()
        || snapshot.counter_source != "systemd_ip_accounting"
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    snapshot.target = CoturnTarget::Wsl2.as_str().to_owned();
    snapshot.counter_source = "wsl_systemd_ip_accounting".to_owned();
    let encoded = serde_json::to_vec(&snapshot).map_err(|_| BrokerRuntimeError::StateInvalid)?;
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_OUTPUT_BYTES {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(encoded)
}

fn has_wsl2_kernel_evidence() -> Result<bool, BrokerRuntimeError> {
    let uname_release = uname_release()?;
    let release = read_bounded_proc(Path::new("/proc/sys/kernel/osrelease"), 256)?;
    let release =
        std::str::from_utf8(&release).map_err(|_| BrokerRuntimeError::ActivationInvalid)?;
    let version = read_bounded_proc(Path::new("/proc/version"), 512)?;
    let version =
        std::str::from_utf8(&version).map_err(|_| BrokerRuntimeError::ActivationInvalid)?;
    let mut registrations = Vec::new();
    for name in ["WSLInterop", "WSLInterop-late"] {
        let path = Path::new("/proc/sys/fs/binfmt_misc").join(name);
        let Some(value) = read_optional_bounded_proc(&path, 256)? else {
            continue;
        };
        let value = std::str::from_utf8(&value)
            .map_err(|_| BrokerRuntimeError::ActivationInvalid)?
            .to_owned();
        registrations.push((name, value));
    }
    let registration_refs: Vec<_> = registrations
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    validate_unique_wsl_interop_registration(&registration_refs)
        .map_err(|_| BrokerRuntimeError::ActivationInvalid)?;
    let interop = registrations
        .first()
        .map(|(_, value)| value.as_str())
        .ok_or(BrokerRuntimeError::ActivationInvalid)?;
    Ok(valid_wsl2_kernel_evidence(
        &uname_release,
        release,
        version,
        interop,
    ))
}

fn uname_release() -> Result<String, BrokerRuntimeError> {
    // SAFETY: zero is a valid initial representation for utsname and uname
    // writes exactly one complete value to the live output pointer.
    let mut value: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut value) } != 0 {
        return Err(BrokerRuntimeError::ActivationInvalid);
    }
    // SAFETY: a successful uname call guarantees NUL termination for release.
    let release = unsafe { CStr::from_ptr(value.release.as_ptr()) }
        .to_str()
        .map_err(|_| BrokerRuntimeError::ActivationInvalid)?;
    if release.is_empty() || release.len() > 256 {
        return Err(BrokerRuntimeError::ActivationInvalid);
    }
    Ok(release.to_owned())
}

fn valid_wsl2_kernel_evidence(
    uname_release: &str,
    proc_release: &str,
    proc_version: &str,
    interop: &str,
) -> bool {
    let uname_release = uname_release.trim().to_ascii_lowercase();
    let proc_release = proc_release.trim().to_ascii_lowercase();
    let proc_version = proc_version.trim().to_ascii_lowercase();
    let expected_version_prefix = format!("linux version {proc_release} ");
    uname_release == proc_release
        && proc_release.contains("microsoft-standard-wsl2")
        && proc_version.starts_with(&expected_version_prefix)
        && validate_unique_wsl_interop_registration(&[("WSLInterop", interop)]).is_ok()
}

fn read_bounded_proc(path: &Path, limit: u64) -> Result<Vec<u8>, BrokerRuntimeError> {
    read_optional_bounded_proc(path, limit)?.ok_or(BrokerRuntimeError::ActivationInvalid)
}

fn read_optional_bounded_proc(
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, BrokerRuntimeError> {
    let mut value = Vec::new();
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BrokerRuntimeError::ActivationInvalid),
    };
    file.take(limit + 1)
        .read_to_end(&mut value)
        .map_err(|_| BrokerRuntimeError::ActivationInvalid)?;
    if value.is_empty() || value.len() > limit as usize {
        return Err(BrokerRuntimeError::ActivationInvalid);
    }
    Ok(Some(value))
}

async fn run_linux_socket_activated_inner() -> Result<(), BrokerRuntimeError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(BrokerRuntimeError::ActivationInvalid);
    }
    let activation = socket_activation_claim()?;
    super::validate_socket_activation(&activation)
        .map_err(|_| BrokerRuntimeError::ActivationInvalid)?;

    // SAFETY: systemd promised exactly one owned descriptor at FD 3 and all
    // socket shape checks above completed before ownership is transferred.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(FIRST_SOCKET_FD) };
    std_stream
        .set_nonblocking(true)
        .map_err(|_| BrokerRuntimeError::IoFailed)?;
    let mut stream = UnixStream::from_std(std_stream).map_err(|_| BrokerRuntimeError::IoFailed)?;
    let credential = stream
        .peer_cred()
        .map_err(|_| BrokerRuntimeError::PeerRejected)?;
    let expected_agent_uid = lookup_uid(AGENT_USER)?;
    let peer = LinuxClientPeerClaim {
        peer_uid: credential.uid(),
        expected_agent_uid,
        peer_pid: credential
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .unwrap_or(0),
    };
    super::validate_linux_client_peer(&peer).map_err(|_| BrokerRuntimeError::PeerRejected)?;

    // The peer is authenticated before a single request byte (and therefore
    // before any possible raw secret byte) is read.
    let request = read_request(&mut stream).await?;
    let _lock = acquire_global_lock()?;
    let payload = handle_request(request).await?;
    let response = encode_response_frame(&payload).map_err(|_| BrokerRuntimeError::StateInvalid)?;
    stream
        .write_all(&response)
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)?;
    stream
        .shutdown()
        .await
        .map_err(|_| BrokerRuntimeError::IoFailed)
}

fn socket_activation_claim() -> Result<SocketActivationClaim, BrokerRuntimeError> {
    let current_pid = std::process::id();
    let listen_pid = parse_activation_value("LISTEN_PID")?;
    let listen_fds = parse_activation_value("LISTEN_FDS")?;
    let listen_fd_names =
        std::env::var("LISTEN_FDNAMES").map_err(|_| BrokerRuntimeError::ActivationInvalid)?;
    if !valid_socket_fd_names(Some(&listen_fd_names), listen_fds) {
        return Err(BrokerRuntimeError::ActivationInvalid);
    }
    let fd_is_connected_unix_stream = connected_unix_stream(FIRST_SOCKET_FD);
    Ok(SocketActivationClaim {
        current_pid,
        listen_pid,
        listen_fds,
        first_fd: FIRST_SOCKET_FD,
        fd_is_connected_unix_stream,
    })
}

fn valid_socket_fd_names(value: Option<&str>, listen_fds: u32) -> bool {
    listen_fds == 1 && value == Some(EXPECTED_SOCKET_FD_NAME)
}

fn parse_activation_value(name: &str) -> Result<u32, BrokerRuntimeError> {
    let value = std::env::var(name).map_err(|_| BrokerRuntimeError::ActivationInvalid)?;
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BrokerRuntimeError::ActivationInvalid);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(BrokerRuntimeError::ActivationInvalid)
}

fn connected_unix_stream(fd: i32) -> bool {
    let mut socket_type = 0_i32;
    let mut socket_type_len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: both output pointers refer to initialized, correctly-sized live
    // storage and fd is only inspected here.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut socket_type_len,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return false;
    }
    // SAFETY: zero initialization is valid for sockaddr_storage and the kernel
    // writes at most the supplied buffer length.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_len,
        )
    } != 0
    {
        return false;
    }
    i32::from(address.ss_family) == libc::AF_UNIX
}

fn lookup_uid(user: &str) -> Result<u32, BrokerRuntimeError> {
    let user = CString::new(user).map_err(|_| BrokerRuntimeError::PeerRejected)?;
    // SAFETY: zero is a valid initial representation for passwd; getpwnam_r
    // initializes every field before returning a non-null result pointer.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    // SAFETY: all pointers refer to live storage for the duration of the call.
    let status = unsafe {
        libc::getpwnam_r(
            user.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || entry.pw_uid == 0 {
        return Err(BrokerRuntimeError::PeerRejected);
    }
    Ok(entry.pw_uid)
}

async fn read_request(stream: &mut UnixStream) -> Result<BrokerRequest, BrokerRuntimeError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    BrokerRequest::validate_header(header).map_err(|_| BrokerRuntimeError::FrameInvalid)?;
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
    stream
        .read_exact(&mut frame[FRAME_HEADER_BYTES..])
        .await
        .map_err(|_| BrokerRuntimeError::FrameInvalid)?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .await
        .map_err(|_| BrokerRuntimeError::FrameInvalid)?
        != 0
    {
        return Err(BrokerRuntimeError::FrameInvalid);
    }
    decode_request_frame(frame).map_err(|_| BrokerRuntimeError::FrameInvalid)
}

fn acquire_global_lock() -> Result<File, BrokerRuntimeError> {
    use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _};

    verify_root_directory(Path::new(STATE_DIRECTORY))?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(LOCK_PATH)
        .map_err(|_| BrokerRuntimeError::LockFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| BrokerRuntimeError::LockFailed)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(BrokerRuntimeError::LockFailed);
    }
    // SAFETY: file owns a live descriptor and flock changes only its advisory
    // lock state. Closing the returned File releases the global lock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(BrokerRuntimeError::LockFailed);
    }
    Ok(file)
}

async fn handle_request(request: BrokerRequest) -> Result<Vec<u8>, BrokerRuntimeError> {
    if request.target() != CoturnTarget::LinuxSystemd {
        return Err(BrokerRuntimeError::FrameInvalid);
    }
    reconcile_pending().await?;
    match request.action() {
        BrokerAction::Snapshot => snapshot_payload(request.snapshot_challenge()).await,
        BrokerAction::Restart => {
            restart_committed().await?;
            snapshot_payload(None).await
        }
        BrokerAction::ApplySecret => {
            apply_secret_transaction(&request).await?;
            snapshot_payload(None).await
        }
        BrokerAction::SetDraining => {
            set_draining(request.draining().ok_or(BrokerRuntimeError::FrameInvalid)?).await?;
            snapshot_payload(None).await
        }
        BrokerAction::Probe => probe_payload(&request).await,
    }
}

async fn snapshot_payload(
    drain_challenge: Option<&[u8; 32]>,
) -> Result<Vec<u8>, BrokerRuntimeError> {
    let (mut state, material, systemd, external_restart) = verified_current_state().await?;
    let target_active =
        systemd.active_state == "active" && systemd.sub_state == "running" && systemd.main_pid != 0;
    let scrape = if target_active {
        native_scrape().await.ok()
    } else {
        None
    };
    let active_allocations = scrape.as_ref().map(|value| value.active_allocations);
    let health = classify_snapshot_health(
        external_restart,
        state.draining,
        scrape.is_some(),
        systemd.ingress_bytes,
        systemd.egress_bytes,
    );
    let epoch = systemd
        .invocation_id
        .as_deref()
        .unwrap_or(state.invocation_id.as_str());
    let clean_exit = systemd_clean_drain_exit(
        &systemd.active_state,
        &systemd.sub_state,
        systemd.main_pid,
        &systemd.result,
        systemd.exec_main_status,
    );
    let drain_completed = linux_drain_completed(
        state.draining,
        state.drain_completed,
        external_restart,
        &state.invocation_id,
        LinuxDrainCompletionObservation {
            invocation_id: systemd.invocation_id.as_deref(),
            target_active,
            clean_exit,
            active_allocations,
        },
    );
    if state.drain_completed != drain_completed {
        state.drain_completed = drain_completed;
        store_state(&state)?;
    }
    if let Some(challenge) = drain_challenge {
        let trusted_zero = (target_active && active_allocations == Some(0)) || clean_exit;
        if external_restart || !state.draining || !drain_completed || !trusted_zero {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        return broker_drain_proof_payload(
            CoturnTarget::LinuxSystemd,
            state.generation,
            state.applied_secret_version,
            challenge,
        )
        .map_err(|_| BrokerRuntimeError::StateInvalid);
    }
    let response = SnapshotResponse {
        target: CoturnTarget::LinuxSystemd.as_str(),
        generation: state.generation,
        applied_secret_version: state.applied_secret_version,
        health,
        active_allocations: active_allocations.unwrap_or(0),
        counter_source: "systemd_ip_accounting",
        counter_epoch: epoch,
        total_ingress_bytes: systemd.ingress_bytes.unwrap_or(0),
        total_egress_bytes: systemd.egress_bytes.unwrap_or(0),
        measurement_monotonic_ns: monotonic_ns()?,
        configured_max_allocations: material.rendered.configured_max_allocations(),
        configured_max_egress_bps: material.rendered.configured_max_egress_bps(),
        relay_min_port: material.rendered.relay_ports().0,
        relay_max_port: material.rendered.relay_ports().1,
        transport_capabilities: material.rendered.transport_capabilities(),
        configured_endpoints: material.rendered.configured_endpoints(),
        draining: state.draining,
        drain_completed,
    };
    serde_json::to_vec(&response).map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn classify_snapshot_health(
    external_restart: bool,
    draining: bool,
    has_scrape: bool,
    ingress_bytes: Option<u64>,
    egress_bytes: Option<u64>,
) -> &'static str {
    if !external_restart
        && !draining
        && has_scrape
        && ingress_bytes.is_some()
        && egress_bytes.is_some()
    {
        "healthy"
    } else if draining || has_scrape {
        "degraded"
    } else {
        "failed"
    }
}

fn linux_drain_completed(
    draining: bool,
    latched: bool,
    external_restart: bool,
    committed_invocation_id: &str,
    observation: LinuxDrainCompletionObservation<'_>,
) -> bool {
    if !draining || external_restart || committed_invocation_id.is_empty() {
        return false;
    }
    if observation
        .invocation_id
        .is_some_and(|value| value != committed_invocation_id)
    {
        return false;
    }
    latched
        || (observation.invocation_id == Some(committed_invocation_id)
            && ((observation.target_active && observation.active_allocations == Some(0))
                || observation.clean_exit))
}

fn systemd_clean_drain_exit(
    active_state: &str,
    sub_state: &str,
    main_pid: u32,
    result: &str,
    exec_main_status: i32,
) -> bool {
    active_state == "inactive"
        && sub_state == "dead"
        && main_pid == 0
        && result == "success"
        && exec_main_status == 0
}

async fn verified_current_state(
) -> Result<(CommittedState, VerifiedMaterial, SystemdObservation, bool), BrokerRuntimeError> {
    let mut state = load_state()?.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_state(&state)?;
    let material = load_verified_material()?;
    if state.secret_sha256 != material.secret_sha256
        || state.config_sha256 != material.config_sha256
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let systemd = systemd_show().await?;
    let mut external_restart = state.external_restart_detected;
    if systemd.active_state == "active" && systemd.invocation_id.is_none() {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    if let Some(invocation) = systemd.invocation_id.as_ref() {
        if invocation != &state.invocation_id {
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            state.invocation_id.clone_from(invocation);
            state.drain_completed = false;
            state.external_restart_detected = true;
            store_state(&state)?;
            external_restart = true;
        }
    }
    if systemd.active_state == "active" && systemd.main_pid == 0 {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok((state, material, systemd, external_restart))
}

fn load_verified_material() -> Result<VerifiedMaterial, BrokerRuntimeError> {
    let source = read_private_file(Path::new(SECRET_PATH), 64)?;
    if source.len() != 43
        || !source
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let mut raw_secret = Zeroizing::new(vec![0_u8; 33]);
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(source.as_slice(), raw_secret.as_mut_slice())
        .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    if decoded_len != 32 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    raw_secret.truncate(decoded_len);
    let canonical_secret = canonical_turn_secret_bytes(raw_secret.as_slice())
        .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    if canonical_secret.as_slice() != source.as_slice() {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let template = read_private_file(Path::new(BASE_CONFIG_PATH), MAX_PRIVATE_FILE_BYTES)?;
    let rendered = render_linux_coturn_config(&template, &raw_secret)
        .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    let actual_config =
        read_private_file(Path::new(GENERATED_CONFIG_PATH), MAX_PRIVATE_FILE_BYTES)?;
    if actual_config.as_slice() != rendered.bytes() {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(VerifiedMaterial {
        secret_sha256: sha256_hex(source.as_slice()),
        config_sha256: sha256_hex(actual_config.as_slice()),
        raw_secret,
        rendered,
    })
}

async fn apply_secret_transaction(request: &BrokerRequest) -> Result<(), BrokerRuntimeError> {
    let version = request
        .secret_version()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let secret = request.secret().ok_or(BrokerRuntimeError::FrameInvalid)?;
    if secret.as_slice().len() != 32 {
        return Err(BrokerRuntimeError::FrameInvalid);
    }
    let previous_state = load_state()?;
    if let Some(state) = previous_state.as_ref() {
        validate_state(state)?;
        if version < state.applied_secret_version || version > state.applied_secret_version + 1 {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        if version == state.applied_secret_version {
            let (current, _, _, _) = verified_current_state().await?;
            if current.applied_secret_version == version
                && raw_secret_matches_committed(secret.as_slice(), &current.secret_sha256)
            {
                return Ok(());
            }
            return Err(BrokerRuntimeError::StateInvalid);
        }
    } else if version != 1 {
        return Err(BrokerRuntimeError::StateInvalid);
    }

    let template = read_private_file(Path::new(BASE_CONFIG_PATH), MAX_PRIVATE_FILE_BYTES)?;
    let rendered = render_linux_coturn_config(&template, secret.as_slice())
        .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    let canonical_secret = canonical_turn_secret_bytes(secret.as_slice())
        .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    let previous_secret = read_optional_private_file(Path::new(SECRET_PATH), 64)?;
    let previous_config =
        read_optional_private_file(Path::new(GENERATED_CONFIG_PATH), MAX_PRIVATE_FILE_BYTES)?;
    store_optional_backup(
        Path::new(BACKUP_SECRET_PATH),
        previous_secret.as_ref().map(|value| value.as_slice()),
    )?;
    store_optional_backup(
        Path::new(BACKUP_CONFIG_PATH),
        previous_config.as_ref().map(|value| value.as_slice()),
    )?;
    let journal = PendingJournal {
        schema_version: 1,
        target: CoturnTarget::LinuxSystemd.as_str().to_owned(),
        desired_version: version,
        desired_secret_sha256: sha256_hex(&canonical_secret),
        desired_config_sha256: sha256_hex(rendered.bytes()),
        previous_state: previous_state.clone(),
        had_previous_secret: previous_secret.is_some(),
        had_previous_config: previous_config.is_some(),
    };
    store_json(Path::new(JOURNAL_PATH), &journal, MAX_STATE_BYTES)?;
    atomic_replace(Path::new(SECRET_PATH), &canonical_secret, 64)?;
    atomic_replace(
        Path::new(GENERATED_CONFIG_PATH),
        rendered.bytes(),
        MAX_PRIVATE_FILE_BYTES,
    )?;

    let applied = async {
        let previous_invocation = previous_state
            .as_ref()
            .map(|state| state.invocation_id.as_str());
        systemctl(&["restart", COTURN_UNIT]).await?;
        let systemd = wait_for_new_active_invocation(previous_invocation).await?;
        let material = load_verified_material()?;
        if material.secret_sha256 != journal.desired_secret_sha256
            || material.config_sha256 != journal.desired_config_sha256
        {
            return Err(BrokerRuntimeError::StateInvalid);
        }
        let invocation_id = systemd
            .invocation_id
            .ok_or(BrokerRuntimeError::TargetFailed)?;
        let state = CommittedState {
            schema_version: 1,
            target: CoturnTarget::LinuxSystemd.as_str().to_owned(),
            generation: previous_state
                .as_ref()
                .map_or(Some(1), |state| state.generation.checked_add(1))
                .ok_or(BrokerRuntimeError::StateInvalid)?,
            applied_secret_version: version,
            invocation_id,
            secret_sha256: journal.desired_secret_sha256.clone(),
            config_sha256: journal.desired_config_sha256.clone(),
            draining: false,
            drain_completed: false,
            external_restart_detected: false,
        };
        store_state(&state)
    }
    .await;
    if let Err(error) = applied {
        rollback_pending(&journal).await?;
        return Err(error);
    }
    remove_transaction_artifacts()?;
    Ok(())
}

fn raw_secret_matches_committed(raw_secret: &[u8], committed_sha256: &str) -> bool {
    if raw_secret.len() != 32 || !valid_sha256(committed_sha256) {
        return false;
    }
    let Ok(canonical) = canonical_turn_secret_bytes(raw_secret) else {
        return false;
    };
    let actual_sha256 = sha256_hex(&canonical);
    actual_sha256 == committed_sha256
}

async fn reconcile_pending() -> Result<(), BrokerRuntimeError> {
    let Some(pending) =
        load_json::<LinuxPendingOperation>(Path::new(JOURNAL_PATH), MAX_STATE_BYTES)?
    else {
        remove_stale_backup(Path::new(BACKUP_SECRET_PATH))?;
        remove_stale_backup(Path::new(BACKUP_CONFIG_PATH))?;
        return Ok(());
    };
    match pending {
        LinuxPendingOperation::Secret(journal) => reconcile_secret_pending(&journal).await,
        LinuxPendingOperation::Drain(journal) => {
            if read_optional_private_file(Path::new(BACKUP_SECRET_PATH), MAX_PRIVATE_FILE_BYTES)?
                .is_some()
                || read_optional_private_file(
                    Path::new(BACKUP_CONFIG_PATH),
                    MAX_PRIVATE_FILE_BYTES,
                )?
                .is_some()
            {
                return Err(BrokerRuntimeError::StateInvalid);
            }
            reconcile_drain_pending(journal).await
        }
    }
}

async fn reconcile_secret_pending(journal: &PendingJournal) -> Result<(), BrokerRuntimeError> {
    validate_journal(journal)?;
    let secret_matches = file_sha256(Path::new(SECRET_PATH), 64)?
        .is_some_and(|digest| digest == journal.desired_secret_sha256);
    let config_matches = file_sha256(Path::new(GENERATED_CONFIG_PATH), MAX_PRIVATE_FILE_BYTES)?
        .is_some_and(|digest| digest == journal.desired_config_sha256);
    let current_state = load_state()?;
    let committed_marker_matches_desired = current_state.as_ref().is_some_and(|state| {
        state.applied_secret_version == journal.desired_version
            && state.secret_sha256 == journal.desired_secret_sha256
            && state.config_sha256 == journal.desired_config_sha256
    });
    let systemd = systemd_show().await.unwrap_or_default();
    let observation = PendingRecoveryObservation {
        committed_marker_matches_desired,
        desired_secret_and_config_match: secret_matches && config_matches,
        previous_invocation: journal
            .previous_state
            .as_ref()
            .map(|state| state.invocation_id.clone()),
        current_invocation: systemd.invocation_id.clone(),
        target_active: systemd.active_state == "active" && systemd.main_pid != 0,
    };
    match select_pending_recovery(&observation) {
        PendingRecoveryAction::RemoveJournal => remove_transaction_artifacts(),
        PendingRecoveryAction::Rollback => rollback_pending(journal).await,
        PendingRecoveryAction::RestartAndVerify => {
            let previous = journal
                .previous_state
                .as_ref()
                .map(|state| state.invocation_id.as_str());
            systemctl(&["restart", COTURN_UNIT]).await?;
            let systemd = wait_for_new_active_invocation(previous).await?;
            commit_recovered(journal, systemd)?;
            remove_transaction_artifacts()
        }
        PendingRecoveryAction::Commit => {
            commit_recovered(journal, systemd)?;
            remove_transaction_artifacts()
        }
    }
}

async fn reconcile_drain_pending(
    mut journal: LinuxPendingDrainJournal,
) -> Result<(), BrokerRuntimeError> {
    validate_drain_journal(&journal)?;
    let current = load_state()?.ok_or(BrokerRuntimeError::StateInvalid)?;
    validate_state(&current)?;
    if !same_drain_material(&current, &journal.previous_state) {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let material = load_verified_material()?;
    if material.secret_sha256 != current.secret_sha256
        || material.config_sha256 != current.config_sha256
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let systemd = systemd_show().await?;
    let target_active =
        systemd.active_state == "active" && systemd.sub_state == "running" && systemd.main_pid != 0;
    let clean_exit = systemd_clean_drain_exit(
        &systemd.active_state,
        &systemd.sub_state,
        systemd.main_pid,
        &systemd.result,
        systemd.exec_main_status,
    );
    let active_allocations = if !journal.desired_draining
        && target_active
        && systemd.invocation_id.as_deref() == Some(journal.previous_state.invocation_id.as_str())
    {
        Some(native_scrape().await?.active_allocations)
    } else {
        None
    };
    let action = select_linux_drain_recovery(
        &drain_journal_claim(&journal),
        &drain_state_claim(&current),
        &LinuxDrainTargetClaim {
            invocation_id: systemd.invocation_id.clone(),
            target_active,
            clean_exit,
            active_allocations,
        },
    )
    .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    match action {
        LinuxDrainRecoveryAction::ApplyDrainSignal => {
            systemctl(&["kill", "--kill-whom=main", "--signal=SIGUSR1", COTURN_UNIT]).await?;
            journal.phase = LinuxDrainJournalPhase::TargetMutationIssued;
            store_drain_journal(&journal)?;
            let mut committed = current;
            committed.draining = true;
            committed.drain_completed = false;
            committed.external_restart_detected = false;
            store_state(&committed)?;
            clear_drain_journal()
        }
        LinuxDrainRecoveryAction::CommitDrained => {
            journal.phase = LinuxDrainJournalPhase::TargetMutationIssued;
            store_drain_journal(&journal)?;
            let mut committed = current;
            committed.draining = true;
            committed.drain_completed = true;
            committed.external_restart_detected = false;
            store_state(&committed)?;
            clear_drain_journal()
        }
        LinuxDrainRecoveryAction::RestartUndrained => {
            systemctl(&["restart", COTURN_UNIT]).await?;
            journal.phase = LinuxDrainJournalPhase::TargetMutationIssued;
            store_drain_journal(&journal)?;
            let systemd =
                wait_for_new_active_invocation(Some(journal.previous_state.invocation_id.as_str()))
                    .await?;
            let invocation_id = systemd
                .invocation_id
                .ok_or(BrokerRuntimeError::TargetFailed)?;
            commit_undrained(&journal, invocation_id)
        }
        LinuxDrainRecoveryAction::CommitUndrained => {
            journal.phase = LinuxDrainJournalPhase::TargetMutationIssued;
            store_drain_journal(&journal)?;
            let invocation_id = systemd
                .invocation_id
                .ok_or(BrokerRuntimeError::TargetFailed)?;
            commit_undrained(&journal, invocation_id)
        }
        LinuxDrainRecoveryAction::ClearJournal => clear_drain_journal(),
    }
}

fn same_drain_material(current: &CommittedState, previous: &CommittedState) -> bool {
    current.schema_version == previous.schema_version
        && current.target == previous.target
        && current.applied_secret_version == previous.applied_secret_version
        && current.secret_sha256 == previous.secret_sha256
        && current.config_sha256 == previous.config_sha256
}

fn drain_state_claim(state: &CommittedState) -> LinuxDrainStateClaim {
    LinuxDrainStateClaim {
        generation: state.generation,
        invocation_id: state.invocation_id.clone(),
        draining: state.draining,
        drain_completed: state.drain_completed,
        external_restart_detected: state.external_restart_detected,
    }
}

fn drain_journal_claim(journal: &LinuxPendingDrainJournal) -> LinuxDrainJournalClaim {
    LinuxDrainJournalClaim {
        desired_draining: journal.desired_draining,
        phase: journal.phase,
        previous_state: drain_state_claim(&journal.previous_state),
    }
}

fn store_drain_journal(journal: &LinuxPendingDrainJournal) -> Result<(), BrokerRuntimeError> {
    store_json(
        Path::new(JOURNAL_PATH),
        &LinuxPendingOperation::Drain(journal.clone()),
        MAX_STATE_BYTES,
    )
}

fn clear_drain_journal() -> Result<(), BrokerRuntimeError> {
    remove_private_file(Path::new(JOURNAL_PATH))
}

fn commit_undrained(
    journal: &LinuxPendingDrainJournal,
    invocation_id: String,
) -> Result<(), BrokerRuntimeError> {
    if invocation_id == journal.previous_state.invocation_id {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let mut committed = journal.previous_state.clone();
    committed.generation = committed
        .generation
        .checked_add(1)
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    committed.invocation_id = invocation_id;
    committed.draining = false;
    committed.drain_completed = false;
    committed.external_restart_detected = false;
    store_state(&committed)?;
    clear_drain_journal()
}

fn commit_recovered(
    journal: &PendingJournal,
    systemd: SystemdObservation,
) -> Result<(), BrokerRuntimeError> {
    let invocation_id = systemd
        .invocation_id
        .filter(|_| systemd.active_state == "active" && systemd.main_pid != 0)
        .ok_or(BrokerRuntimeError::TargetFailed)?;
    let material = load_verified_material()?;
    if material.secret_sha256 != journal.desired_secret_sha256
        || material.config_sha256 != journal.desired_config_sha256
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    let state = CommittedState {
        schema_version: 1,
        target: CoturnTarget::LinuxSystemd.as_str().to_owned(),
        generation: journal
            .previous_state
            .as_ref()
            .map_or(Some(1), |state| state.generation.checked_add(1))
            .ok_or(BrokerRuntimeError::StateInvalid)?,
        applied_secret_version: journal.desired_version,
        invocation_id,
        secret_sha256: journal.desired_secret_sha256.clone(),
        config_sha256: journal.desired_config_sha256.clone(),
        draining: false,
        drain_completed: false,
        external_restart_detected: false,
    };
    store_state(&state)
}

async fn rollback_pending(journal: &PendingJournal) -> Result<(), BrokerRuntimeError> {
    restore_backup(
        Path::new(BACKUP_SECRET_PATH),
        Path::new(SECRET_PATH),
        journal.had_previous_secret,
        64,
    )?;
    restore_backup(
        Path::new(BACKUP_CONFIG_PATH),
        Path::new(GENERATED_CONFIG_PATH),
        journal.had_previous_config,
        MAX_PRIVATE_FILE_BYTES,
    )?;
    match journal.previous_state.as_ref() {
        Some(previous) => {
            systemctl(&["restart", COTURN_UNIT]).await?;
            let systemd = wait_for_new_active_invocation(Some(&previous.invocation_id)).await?;
            let material = load_verified_material()?;
            if material.secret_sha256 != previous.secret_sha256
                || material.config_sha256 != previous.config_sha256
            {
                return Err(BrokerRuntimeError::StateInvalid);
            }
            let mut restored = previous.clone();
            restored.generation = restored
                .generation
                .checked_add(1)
                .ok_or(BrokerRuntimeError::StateInvalid)?;
            restored.invocation_id = systemd
                .invocation_id
                .ok_or(BrokerRuntimeError::TargetFailed)?;
            restored.draining = false;
            restored.drain_completed = false;
            restored.external_restart_detected = false;
            store_state(&restored)?;
        }
        None => {
            let _ = systemctl(&["stop", COTURN_UNIT]).await;
            remove_private_file(Path::new(STATE_PATH))?;
        }
    }
    remove_transaction_artifacts()
}

async fn restart_committed() -> Result<(), BrokerRuntimeError> {
    let (state, _, _, _) = verified_current_state().await?;
    if state.draining {
        return set_draining(false).await;
    }
    systemctl(&["restart", COTURN_UNIT]).await?;
    let systemd = wait_for_new_active_invocation(Some(&state.invocation_id)).await?;
    let mut next = state;
    next.generation = next
        .generation
        .checked_add(1)
        .ok_or(BrokerRuntimeError::StateInvalid)?;
    next.invocation_id = systemd
        .invocation_id
        .ok_or(BrokerRuntimeError::TargetFailed)?;
    next.draining = false;
    next.drain_completed = false;
    next.external_restart_detected = false;
    store_state(&next)
}

async fn set_draining(draining: bool) -> Result<(), BrokerRuntimeError> {
    let (mut state, _, systemd, external_restart) = verified_current_state().await?;
    if external_restart {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    if draining {
        if state.draining {
            return Ok(());
        }
        if systemd.active_state != "active" || systemd.main_pid == 0 {
            return Err(BrokerRuntimeError::TargetFailed);
        }
        let journal = LinuxPendingDrainJournal {
            schema_version: 1,
            target: CoturnTarget::LinuxSystemd.as_str().to_owned(),
            operation: LinuxPendingDrainOperation::SetDraining,
            desired_draining: true,
            phase: LinuxDrainJournalPhase::IntentPersisted,
            previous_state: state,
        };
        store_drain_journal(&journal)?;
        reconcile_drain_pending(journal).await
    } else {
        if !state.draining {
            return Ok(());
        }
        let target_active = systemd.active_state == "active"
            && systemd.sub_state == "running"
            && systemd.main_pid != 0;
        let clean_exit = systemd_clean_drain_exit(
            &systemd.active_state,
            &systemd.sub_state,
            systemd.main_pid,
            &systemd.result,
            systemd.exec_main_status,
        );
        if systemd.invocation_id.as_deref() != Some(state.invocation_id.as_str()) {
            return Err(BrokerRuntimeError::TargetFailed);
        }
        let trusted_zero = if target_active {
            native_scrape().await?.active_allocations == 0
        } else {
            clean_exit
        };
        if !trusted_zero {
            return Err(BrokerRuntimeError::TargetFailed);
        }
        if !state.drain_completed {
            state.drain_completed = true;
            store_state(&state)?;
        }
        let journal = LinuxPendingDrainJournal {
            schema_version: 1,
            target: CoturnTarget::LinuxSystemd.as_str().to_owned(),
            operation: LinuxPendingDrainOperation::SetDraining,
            desired_draining: false,
            phase: LinuxDrainJournalPhase::IntentPersisted,
            previous_state: state,
        };
        store_drain_journal(&journal)?;
        reconcile_drain_pending(journal).await
    }
}

async fn probe_payload(request: &BrokerRequest) -> Result<Vec<u8>, BrokerRuntimeError> {
    let expected_generation = request
        .probe_generation()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let expected_version = request
        .probe_secret_version()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let challenge = request
        .probe_challenge()
        .ok_or(BrokerRuntimeError::FrameInvalid)?;
    let (state, material, systemd, external_restart) = verified_current_state().await?;
    let before = ProbeStabilityObservation {
        target: CoturnTarget::LinuxSystemd,
        generation: state.generation,
        applied_secret_version: state.applied_secret_version,
        epoch: systemd.invocation_id.clone().unwrap_or_default(),
        active: systemd.active_state == "active"
            && systemd.sub_state == "running"
            && systemd.main_pid != 0,
        draining: state.draining,
        external_restart_detected: external_restart,
    };
    if before.generation != expected_generation
        || before.applied_secret_version != expected_version
        || validate_probe_stability(&before, &before).is_err()
    {
        return Err(BrokerRuntimeError::ProbeFailed);
    }
    let listening_port = material
        .rendered
        .configured_endpoints()
        .first()
        .and_then(|endpoint| strict_turn_endpoint_port(endpoint))
        .ok_or(BrokerRuntimeError::ProbeFailed)?;
    let loopback_host = linux_probe_loopback_host(material.rendered.bytes())
        .map_err(|_| BrokerRuntimeError::ProbeFailed)?;
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerRuntimeError::ProbeFailed)?
        .as_secs()
        .checked_add(300)
        .ok_or(BrokerRuntimeError::ProbeFailed)?;
    let credentials = linux_probe_credentials(expires, challenge, &material.raw_secret)?;
    let urls = vec![
        format!("turn:{loopback_host}:{listening_port}?transport=udp"),
        format!("turn:{loopback_host}:{listening_port}?transport=tcp"),
    ];
    let evidence = probe_turn_relay(TurnRelayProbeConfig {
        ice_servers: vec![IceServerConfig::new(
            urls,
            credentials.username().to_owned(),
            credentials.credential().to_owned(),
        )],
        timeout: PROBE_TIMEOUT,
    })
    .await
    .map_err(|_| BrokerRuntimeError::ProbeFailed)?;
    if !evidence.has_relay_pair() || !evidence.control_round_trip() || !evidence.media_round_trip()
    {
        return Err(BrokerRuntimeError::ProbeFailed);
    }
    let (after_state, _, after_systemd, after_external_restart) = verified_current_state().await?;
    let after = ProbeStabilityObservation {
        target: CoturnTarget::LinuxSystemd,
        generation: after_state.generation,
        applied_secret_version: after_state.applied_secret_version,
        epoch: after_systemd.invocation_id.clone().unwrap_or_default(),
        active: after_systemd.active_state == "active"
            && after_systemd.sub_state == "running"
            && after_systemd.main_pid != 0,
        draining: after_state.draining,
        external_restart_detected: after_external_restart,
    };
    if validate_probe_stability(&before, &after).is_err() {
        return Err(BrokerRuntimeError::ProbeFailed);
    }
    let pair = evidence.selected_pair();
    let proof = probe_proof_sha256(
        CoturnTarget::LinuxSystemd,
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
    .map_err(|_| BrokerRuntimeError::ProbeFailed)?;
    let challenge_hex = hex(challenge);
    let proof_hex = hex(&proof);
    let response = ProbeResponse {
        target: CoturnTarget::LinuxSystemd.as_str(),
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
    serde_json::to_vec(&response).map_err(|_| BrokerRuntimeError::ProbeFailed)
}

fn linux_probe_credentials(
    expires: u64,
    challenge: &[u8; 32],
    raw_secret: &[u8],
) -> Result<CoturnRestCredentials, BrokerRuntimeError> {
    let username = Zeroizing::new(format!(
        "{expires}:mrd-local-preflight:{}:{}",
        hex(challenge),
        CoturnTarget::LinuxSystemd.as_str()
    ));
    derive_coturn_rest_credentials(raw_secret, &username)
        .map_err(|_| BrokerRuntimeError::ProbeFailed)
}

fn strict_turn_endpoint_port(endpoint: &str) -> Option<u16> {
    let remainder = endpoint
        .strip_prefix("turn:")
        .or_else(|| endpoint.strip_prefix("turns:"))?;
    let authority = match remainder.split_once('?') {
        Some((authority, query)) => {
            if query.contains('?') || !matches!(query, "transport=udp" | "transport=tcp") {
                return None;
            }
            authority
        }
        None => remainder,
    };
    let port = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed.split_once("]:")?;
        if host.is_empty()
            || port.is_empty()
            || port.contains(':')
            || host.parse::<std::net::Ipv6Addr>().is_err()
        {
            return None;
        }
        port
    } else {
        let (host, port) = authority.rsplit_once(':')?;
        if host.is_empty()
            || port.is_empty()
            || host.contains([':', '[', ']', '@'])
            || port.contains(':')
        {
            return None;
        }
        port
    };
    port.parse::<u16>().ok().filter(|port| *port != 0)
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

async fn systemctl(arguments: &[&str]) -> Result<(), BrokerRuntimeError> {
    let mut command = Command::new(SYSTEMCTL);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(COMMAND_TIMEOUT, command.status())
        .await
        .map_err(|_| BrokerRuntimeError::TargetFailed)?
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    if !status.success() {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(())
}

async fn systemd_show() -> Result<SystemdObservation, BrokerRuntimeError> {
    let mut command = Command::new(SYSTEMCTL);
    command
        .args([
            "show",
            COTURN_UNIT,
            "--property=InvocationID",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=IPIngressBytes",
            "--property=IPEgressBytes",
            "--property=Result",
            "--property=ExecMainStatus",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| BrokerRuntimeError::TargetFailed)?
        .map_err(|_| BrokerRuntimeError::TargetFailed)?;
    if !output.status.success() || output.stdout.len() > MAX_CONTROL_OUTPUT_BYTES {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    parse_systemd_show(&output.stdout)
}

fn parse_systemd_show(output: &[u8]) -> Result<SystemdObservation, BrokerRuntimeError> {
    let text = std::str::from_utf8(output).map_err(|_| BrokerRuntimeError::TargetFailed)?;
    if !text.is_ascii() {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or(BrokerRuntimeError::TargetFailed)?;
        if values.insert(key, value).is_some() {
            return Err(BrokerRuntimeError::TargetFailed);
        }
    }
    for required in [
        "InvocationID",
        "ActiveState",
        "SubState",
        "MainPID",
        "IPIngressBytes",
        "IPEgressBytes",
        "Result",
        "ExecMainStatus",
    ] {
        if !values.contains_key(required) {
            return Err(BrokerRuntimeError::TargetFailed);
        }
    }
    let invocation = values["InvocationID"];
    let invocation_id = if invocation.is_empty() {
        None
    } else if invocation.len() == 32 && invocation.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(invocation.to_ascii_lowercase())
    } else {
        return Err(BrokerRuntimeError::TargetFailed);
    };
    Ok(SystemdObservation {
        invocation_id,
        active_state: bounded_token(values["ActiveState"])?.to_owned(),
        sub_state: bounded_token(values["SubState"])?.to_owned(),
        main_pid: values["MainPID"]
            .parse()
            .map_err(|_| BrokerRuntimeError::TargetFailed)?,
        ingress_bytes: parse_optional_counter(values["IPIngressBytes"]),
        egress_bytes: parse_optional_counter(values["IPEgressBytes"]),
        result: bounded_token(values["Result"])?.to_owned(),
        exec_main_status: values["ExecMainStatus"]
            .parse()
            .map_err(|_| BrokerRuntimeError::TargetFailed)?,
    })
}

fn bounded_token(value: &str) -> Result<&str, BrokerRuntimeError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(BrokerRuntimeError::TargetFailed);
    }
    Ok(value)
}

fn parse_optional_counter(value: &str) -> Option<u64> {
    value.parse::<u64>().ok()
}

async fn wait_for_new_active_invocation(
    previous: Option<&str>,
) -> Result<SystemdObservation, BrokerRuntimeError> {
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    loop {
        let observed = systemd_show().await?;
        let advanced = observed
            .invocation_id
            .as_deref()
            .is_some_and(|value| previous != Some(value));
        if observed.active_state == "active"
            && observed.sub_state == "running"
            && observed.main_pid != 0
            && advanced
        {
            return Ok(observed);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(BrokerRuntimeError::TargetFailed);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn load_state() -> Result<Option<CommittedState>, BrokerRuntimeError> {
    load_json(Path::new(STATE_PATH), MAX_STATE_BYTES)
}

fn store_state(state: &CommittedState) -> Result<(), BrokerRuntimeError> {
    validate_state(state)?;
    store_json(Path::new(STATE_PATH), state, MAX_STATE_BYTES)
}

fn validate_state(state: &CommittedState) -> Result<(), BrokerRuntimeError> {
    if state.schema_version != 1
        || state.target != CoturnTarget::LinuxSystemd.as_str()
        || state.generation == 0
        || state.applied_secret_version == 0
        || state.invocation_id.len() != 32
        || !state
            .invocation_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || (state.drain_completed && !state.draining)
        || !valid_sha256(&state.secret_sha256)
        || !valid_sha256(&state.config_sha256)
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn validate_journal(journal: &PendingJournal) -> Result<(), BrokerRuntimeError> {
    if journal.schema_version != 1
        || journal.target != CoturnTarget::LinuxSystemd.as_str()
        || journal.desired_version == 0
        || !valid_sha256(&journal.desired_secret_sha256)
        || !valid_sha256(&journal.desired_config_sha256)
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    if let Some(state) = journal.previous_state.as_ref() {
        validate_state(state)?;
        if journal.desired_version != state.applied_secret_version + 1 {
            return Err(BrokerRuntimeError::StateInvalid);
        }
    } else if journal.desired_version != 1 {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn validate_drain_journal(journal: &LinuxPendingDrainJournal) -> Result<(), BrokerRuntimeError> {
    validate_state(&journal.previous_state)?;
    if journal.schema_version != 1
        || journal.target != CoturnTarget::LinuxSystemd.as_str()
        || journal.operation != LinuxPendingDrainOperation::SetDraining
        || journal.previous_state.external_restart_detected
        || (journal.desired_draining
            && (journal.previous_state.draining || journal.previous_state.drain_completed))
        || (!journal.desired_draining
            && (!journal.previous_state.draining || !journal.previous_state.drain_completed))
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    Ok(())
}

fn load_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<T>, BrokerRuntimeError> {
    let Some(bytes) = read_optional_private_file(path, max_bytes)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn store_json<T: Serialize>(
    path: &Path,
    value: &T,
    max_bytes: usize,
) -> Result<(), BrokerRuntimeError> {
    let encoded =
        Zeroizing::new(serde_json::to_vec(value).map_err(|_| BrokerRuntimeError::StateInvalid)?);
    atomic_replace(path, &encoded, max_bytes)
}

fn read_private_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, BrokerRuntimeError> {
    read_optional_private_file(path, max_bytes)?.ok_or(BrokerRuntimeError::StateInvalid)
}

fn read_optional_private_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, BrokerRuntimeError> {
    let parent = path.parent().ok_or(BrokerRuntimeError::StateInvalid)?;
    let file = HardenedAtomicFile::new_linux(parent.to_path_buf(), path.to_path_buf())
        .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    file.read(max_bytes)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn atomic_replace(path: &Path, value: &[u8], max_bytes: usize) -> Result<(), BrokerRuntimeError> {
    let parent = path.parent().ok_or(BrokerRuntimeError::StateInvalid)?;
    let file = HardenedAtomicFile::new_linux(parent.to_path_buf(), path.to_path_buf())
        .map_err(|_| BrokerRuntimeError::StateInvalid)?;
    file.atomic_replace(value, max_bytes)
        .map_err(|_| BrokerRuntimeError::StateInvalid)
}

fn store_optional_backup(path: &Path, value: Option<&[u8]>) -> Result<(), BrokerRuntimeError> {
    match value {
        Some(value) => atomic_replace(path, value, MAX_PRIVATE_FILE_BYTES),
        None => remove_private_file(path),
    }
}

fn restore_backup(
    backup: &Path,
    destination: &Path,
    existed: bool,
    max_bytes: usize,
) -> Result<(), BrokerRuntimeError> {
    if existed {
        let value = read_private_file(backup, max_bytes)?;
        atomic_replace(destination, &value, max_bytes)
    } else {
        remove_private_file(destination)
    }
}

fn remove_transaction_artifacts() -> Result<(), BrokerRuntimeError> {
    remove_private_file(Path::new(JOURNAL_PATH))?;
    remove_private_file(Path::new(BACKUP_SECRET_PATH))?;
    remove_private_file(Path::new(BACKUP_CONFIG_PATH))
}

fn remove_stale_backup(path: &Path) -> Result<(), BrokerRuntimeError> {
    remove_private_file(path)
}

fn remove_private_file(path: &Path) -> Result<(), BrokerRuntimeError> {
    let Some(metadata) = std::fs::symlink_metadata(path)
        .map(Some)
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            }
        })
        .map_err(|_| BrokerRuntimeError::IoFailed)?
    else {
        return Ok(());
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(BrokerRuntimeError::StateInvalid);
    }
    std::fs::remove_file(path).map_err(|_| BrokerRuntimeError::IoFailed)?;
    sync_directory(path.parent().ok_or(BrokerRuntimeError::StateInvalid)?)
}

fn verify_root_directory(path: &Path) -> Result<(), BrokerRuntimeError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| BrokerRuntimeError::LockFailed)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(BrokerRuntimeError::LockFailed);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), BrokerRuntimeError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| BrokerRuntimeError::IoFailed)?;
    directory
        .sync_all()
        .map_err(|_| BrokerRuntimeError::IoFailed)
}

fn file_sha256(path: &Path, max_bytes: usize) -> Result<Option<String>, BrokerRuntimeError> {
    read_optional_private_file(path, max_bytes).map(|bytes| bytes.map(|bytes| sha256_hex(&bytes)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn monotonic_ns() -> Result<u64, BrokerRuntimeError> {
    // SAFETY: zero is a valid initial representation and clock_gettime writes
    // exactly one timespec to the live output pointer.
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(BrokerRuntimeError::IoFailed);
    }
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|nanos| nanos.checked_add(value.tv_nsec as u64))
        .filter(|value| *value != 0)
        .ok_or(BrokerRuntimeError::IoFailed)
}

#[cfg(test)]
mod wsl_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ring::hmac;

    #[test]
    fn wsl_stdin_is_exactly_raw32_for_apply_and_empty_for_other_actions() {
        let raw = vec![0x5a; 32];
        let secret =
            validate_wsl_stdin(WslBrokerAction::ApplySecret(7), Zeroizing::new(raw.clone()))
                .unwrap()
                .unwrap();
        assert_eq!(secret.as_slice(), raw);

        for invalid in [vec![0x5a; 31], vec![0x5a; 33]] {
            assert_eq!(
                validate_wsl_stdin(WslBrokerAction::ApplySecret(7), Zeroizing::new(invalid))
                    .unwrap_err(),
                BrokerRuntimeError::FrameInvalid
            );
        }
        assert!(
            validate_wsl_stdin(WslBrokerAction::Snapshot, Zeroizing::new(Vec::new()))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            validate_wsl_stdin(WslBrokerAction::Restart, Zeroizing::new(vec![0x00])).unwrap_err(),
            BrokerRuntimeError::FrameInvalid
        );
    }

    #[test]
    fn wsl2_evidence_requires_matching_uname_proc_kernel_and_interop_records() {
        let release = "5.15.167.4-microsoft-standard-WSL2";
        let version = "Linux version 5.15.167.4-microsoft-standard-WSL2 (Microsoft@Microsoft.com)";
        let interop = "enabled\ninterpreter /init\nflags: P\noffset 0\nmagic 4d5a\n";
        assert!(valid_wsl2_kernel_evidence(
            release, release, version, interop
        ));
        let interop_pf = "enabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n";
        assert!(valid_wsl2_kernel_evidence(
            release, release, version, interop_pf
        ));

        assert!(!valid_wsl2_kernel_evidence(
            "6.8.0-generic",
            release,
            version,
            interop
        ));
        assert!(!valid_wsl2_kernel_evidence(
            release,
            release,
            "Linux version 6.8.0-generic",
            interop
        ));
        assert!(!valid_wsl2_kernel_evidence(release, release, version, ""));
        assert!(!valid_wsl2_kernel_evidence(
            "4.4.0-microsoft-standard",
            "4.4.0-microsoft-standard",
            "Linux version 4.4.0-microsoft-standard",
            interop
        ));
    }

    #[test]
    fn wsl_snapshot_is_strictly_deserialized_and_canonically_relabelled() {
        const LINUX: &[u8] = br#"{"target":"linux-systemd","generation":3,"applied_secret_version":7,"health":"healthy","active_allocations":2,"counter_source":"systemd_ip_accounting","counter_epoch":"0123456789abcdef0123456789abcdef","total_ingress_bytes":11,"total_egress_bytes":13,"measurement_monotonic_ns":17,"configured_max_allocations":128,"configured_max_egress_bps":80000000,"relay_min_port":49152,"relay_max_port":65535,"transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],"configured_endpoints":["turn:relay.test:3478?transport=udp","turn:relay.test:3478?transport=tcp","turns:relay.test:5349?transport=tcp"],"draining":false,"drain_completed":false}"#;
        const WSL: &[u8] = br#"{"target":"wsl2","generation":3,"applied_secret_version":7,"health":"healthy","active_allocations":2,"counter_source":"wsl_systemd_ip_accounting","counter_epoch":"0123456789abcdef0123456789abcdef","total_ingress_bytes":11,"total_egress_bytes":13,"measurement_monotonic_ns":17,"configured_max_allocations":128,"configured_max_egress_bps":80000000,"relay_min_port":49152,"relay_max_port":65535,"transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],"configured_endpoints":["turn:relay.test:3478?transport=udp","turn:relay.test:3478?transport=tcp","turns:relay.test:5349?transport=tcp"],"draining":false,"drain_completed":false}"#;

        assert_eq!(relabel_wsl_snapshot(LINUX).unwrap(), WSL);

        let mut unknown = LINUX.to_vec();
        unknown.pop();
        unknown.extend_from_slice(br#","secret":"must-not-be-accepted"}"#);
        assert_eq!(
            relabel_wsl_snapshot(&unknown).unwrap_err(),
            BrokerRuntimeError::StateInvalid
        );

        let wrong_target = String::from_utf8(LINUX.to_vec())
            .unwrap()
            .replace("linux-systemd", "wsl2");
        assert_eq!(
            relabel_wsl_snapshot(wrong_target.as_bytes()).unwrap_err(),
            BrokerRuntimeError::StateInvalid
        );

        let missing_drain_completion = String::from_utf8(LINUX.to_vec())
            .unwrap()
            .replace(",\"drain_completed\":false", "");
        assert_eq!(
            relabel_wsl_snapshot(missing_drain_completion.as_bytes()).unwrap_err(),
            BrokerRuntimeError::StateInvalid
        );

        let completed_linux = String::from_utf8(LINUX.to_vec())
            .unwrap()
            .replace("\"health\":\"healthy\"", "\"health\":\"degraded\"")
            .replace("\"active_allocations\":2", "\"active_allocations\":0")
            .replace(
                "\"draining\":false,\"drain_completed\":false",
                "\"draining\":true,\"drain_completed\":true",
            );
        let completed_wsl = String::from_utf8(WSL.to_vec())
            .unwrap()
            .replace("\"health\":\"healthy\"", "\"health\":\"degraded\"")
            .replace("\"active_allocations\":2", "\"active_allocations\":0")
            .replace(
                "\"draining\":false,\"drain_completed\":false",
                "\"draining\":true,\"drain_completed\":true",
            );
        assert_eq!(
            relabel_wsl_snapshot(completed_linux.as_bytes()).unwrap(),
            completed_wsl.as_bytes()
        );
    }

    #[test]
    fn wsl_actions_build_only_linux_systemd_state_machine_requests() {
        let snapshot = build_wsl_request(WslBrokerAction::Snapshot, None).unwrap();
        assert_eq!(snapshot.target(), CoturnTarget::LinuxSystemd);
        assert_eq!(snapshot.action(), BrokerAction::Snapshot);

        let apply = build_wsl_request(
            WslBrokerAction::ApplySecret(9),
            Some(SecretBytes::new(vec![0x33; 32])),
        )
        .unwrap();
        assert_eq!(apply.target(), CoturnTarget::LinuxSystemd);
        assert_eq!(apply.action(), BrokerAction::ApplySecret);
        assert_eq!(apply.secret_version(), Some(9));
        assert_eq!(apply.secret().unwrap().as_slice(), &[0x33; 32]);

        let draining = build_wsl_request(WslBrokerAction::SetDraining(true), None).unwrap();
        assert_eq!(draining.target(), CoturnTarget::LinuxSystemd);
        assert_eq!(draining.draining(), Some(true));

        assert_eq!(
            build_wsl_request(WslBrokerAction::ApplySecret(9), None).unwrap_err(),
            BrokerRuntimeError::FrameInvalid
        );
        assert_eq!(
            build_wsl_request(
                WslBrokerAction::Restart,
                Some(SecretBytes::new(vec![0x44; 32]))
            )
            .unwrap_err(),
            BrokerRuntimeError::FrameInvalid
        );
    }

    #[test]
    fn snapshot_health_requires_both_systemd_network_counters() {
        assert_eq!(
            classify_snapshot_health(false, false, true, Some(11), Some(13)),
            "healthy"
        );
        assert_eq!(
            classify_snapshot_health(false, false, true, None, Some(13)),
            "degraded"
        );
        assert_eq!(
            classify_snapshot_health(false, false, true, Some(11), None),
            "degraded"
        );
        assert_eq!(
            classify_snapshot_health(false, false, true, None, None),
            "degraded"
        );
        assert_eq!(
            classify_snapshot_health(false, false, false, Some(11), Some(13)),
            "failed"
        );
        assert_eq!(
            classify_snapshot_health(false, true, false, None, None),
            "degraded"
        );
        assert_eq!(
            classify_snapshot_health(true, false, true, Some(11), Some(13)),
            "degraded"
        );
    }

    #[test]
    fn same_version_replay_requires_the_exact_committed_raw_secret() {
        let raw = vec![0x6b; 32];
        let canonical = canonical_turn_secret_bytes(&raw).unwrap();
        let committed_sha256 = sha256_hex(&canonical);

        assert!(raw_secret_matches_committed(&raw, &committed_sha256));

        let mut different = raw.clone();
        different[31] ^= 0x01;
        assert!(!raw_secret_matches_committed(&different, &committed_sha256));
        assert!(!raw_secret_matches_committed(&raw, &sha256_hex(&raw)));
        assert!(!raw_secret_matches_committed(&raw[..31], &committed_sha256));
    }

    #[test]
    fn probe_listener_port_strictly_parses_host_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            strict_turn_endpoint_port("turn:relay.example.test:3478?transport=udp"),
            Some(3478)
        );
        assert_eq!(
            strict_turn_endpoint_port("turn:192.0.2.10:3478?transport=tcp"),
            Some(3478)
        );
        assert_eq!(
            strict_turn_endpoint_port("turn:[2001:db8::10]:3478?transport=udp"),
            Some(3478)
        );
        assert_eq!(
            strict_turn_endpoint_port("turns:[::1]:5349?transport=tcp"),
            Some(5349)
        );

        for invalid in [
            "turn:2001:db8::10:3478?transport=udp",
            "turn:[2001:db8::10:3478?transport=udp",
            "turn:[2001:db8::10]3478?transport=udp",
            "turn:relay.example.test:0?transport=udp",
            "turn:relay.example.test:not-a-port?transport=udp",
            "https://relay.example.test:3478?transport=udp",
            "turn:relay.example.test:3478?transport=udp?extra=true",
        ] {
            assert_eq!(strict_turn_endpoint_port(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn local_probe_uses_the_unique_rendered_listener_family() {
        assert_eq!(
            linux_probe_loopback_host(
                b"listening-port=3478\nlistening-ip=0.0.0.0\nexternal-ip=198.20.0.10\n"
            )
            .unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            linux_probe_loopback_host(
                b"listening-port=3478\nlistening-ip=::\nexternal-ip=2606:4700:4700::1111\n"
            )
            .unwrap(),
            "[::1]"
        );

        for invalid in [
            b"listening-port=3478\n".as_slice(),
            b"listening-ip=127.0.0.1\n".as_slice(),
            b"listening-ip=0.0.0.0\nlistening-ip=::\n".as_slice(),
            b"listening-ip=::\nlistening-ip=::\n".as_slice(),
            b"listening-ip = ::\n".as_slice(),
            b"listening-ip=0.0.0.0\n# listening-ip=::\n".as_slice(),
        ] {
            if invalid.ends_with(b"# listening-ip=::\n") {
                assert_eq!(linux_probe_loopback_host(invalid), Ok("127.0.0.1"));
            } else {
                assert!(linux_probe_loopback_host(invalid).is_err());
            }
        }
    }

    #[test]
    fn socket_activation_requires_the_exact_deployed_fd_name() {
        assert!(valid_socket_fd_names(Some("mrd-relay-coturn-control"), 1));

        for (names, listen_fds) in [
            (None, 1),
            (Some(""), 1),
            (Some("unknown"), 1),
            (Some("mrd-relay-coturn-control:extra"), 1),
            (Some("mrd-relay-coturn-control"), 2),
        ] {
            assert!(!valid_socket_fd_names(names, listen_fds));
        }
    }

    #[test]
    fn forced_relay_probe_rejects_a_generation_change_inside_the_probe_window() {
        let before = ProbeStabilityObservation {
            target: CoturnTarget::LinuxSystemd,
            generation: 11,
            applied_secret_version: 7,
            epoch: "0123456789abcdef0123456789abcdef".to_owned(),
            active: true,
            draining: false,
            external_restart_detected: false,
        };
        assert!(validate_probe_stability(&before, &before).is_ok());

        let changed_generation = ProbeStabilityObservation {
            generation: 12,
            ..before.clone()
        };
        assert!(validate_probe_stability(&before, &changed_generation).is_err());

        let changed_version = ProbeStabilityObservation {
            applied_secret_version: 8,
            ..before.clone()
        };
        assert!(validate_probe_stability(&before, &changed_version).is_err());

        let changed_invocation = ProbeStabilityObservation {
            epoch: "fedcba9876543210fedcba9876543210".to_owned(),
            ..before.clone()
        };
        assert!(validate_probe_stability(&before, &changed_invocation).is_err());

        for unsafe_after in [
            ProbeStabilityObservation {
                active: false,
                ..before.clone()
            },
            ProbeStabilityObservation {
                draining: true,
                ..before.clone()
            },
            ProbeStabilityObservation {
                external_restart_detected: true,
                ..before.clone()
            },
        ] {
            assert!(validate_probe_stability(&before, &unsafe_after).is_err());
        }
    }

    #[test]
    fn linux_probe_uses_canonical_secret_and_exact_four_part_username() {
        let raw_secret = [0x42; 32];
        let challenge = [0xa5; 32];
        let credentials = linux_probe_credentials(2_000_000_000, &challenge, &raw_secret).unwrap();
        let expected_username = format!(
            "2000000000:mrd-local-preflight:{}:linux-systemd",
            "a5".repeat(32)
        );
        let canonical_secret = canonical_turn_secret_bytes(&raw_secret).unwrap();
        let expected_credential = STANDARD.encode(
            hmac::sign(
                &hmac::Key::new(
                    hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                    canonical_secret.as_slice(),
                ),
                expected_username.as_bytes(),
            )
            .as_ref(),
        );

        assert_eq!(credentials.username(), expected_username);
        assert_eq!(credentials.credential(), expected_credential);
    }

    #[test]
    fn linux_drain_completion_latches_active_zero_and_same_epoch_clean_exit() {
        let invocation = "0123456789abcdef0123456789abcdef";
        let active_zero = LinuxDrainCompletionObservation {
            invocation_id: Some(invocation),
            target_active: true,
            clean_exit: false,
            active_allocations: Some(0),
        };
        assert!(linux_drain_completed(
            true,
            false,
            false,
            invocation,
            active_zero,
        ));

        let clean_exit = LinuxDrainCompletionObservation {
            invocation_id: Some(invocation),
            target_active: false,
            clean_exit: true,
            active_allocations: None,
        };
        assert!(linux_drain_completed(
            true, false, false, invocation, clean_exit,
        ));

        let unavailable = LinuxDrainCompletionObservation {
            invocation_id: None,
            target_active: false,
            clean_exit: false,
            active_allocations: None,
        };
        assert!(!linux_drain_completed(
            true,
            false,
            false,
            invocation,
            unavailable,
        ));
        assert!(linux_drain_completed(
            true,
            true,
            false,
            invocation,
            unavailable,
        ));

        let new_epoch = LinuxDrainCompletionObservation {
            invocation_id: Some("fedcba9876543210fedcba9876543210"),
            ..active_zero
        };
        assert!(!linux_drain_completed(
            true, true, false, invocation, new_epoch,
        ));
        assert!(!linux_drain_completed(
            true,
            true,
            true,
            invocation,
            active_zero,
        ));
        assert!(!linux_drain_completed(
            false,
            true,
            false,
            invocation,
            active_zero,
        ));
        assert!(!linux_drain_completed(true, false, false, "", active_zero,));
    }

    #[test]
    fn committed_drain_latch_is_persisted_backward_compatibly_and_state_bound() {
        let mut state = CommittedState {
            schema_version: 1,
            target: CoturnTarget::LinuxSystemd.as_str().to_owned(),
            generation: 3,
            applied_secret_version: 7,
            invocation_id: "0123456789abcdef0123456789abcdef".to_owned(),
            secret_sha256: "a".repeat(64),
            config_sha256: "b".repeat(64),
            draining: true,
            drain_completed: true,
            external_restart_detected: false,
        };
        assert!(validate_state(&state).is_ok());
        let encoded = serde_json::to_string(&state).unwrap();
        assert!(encoded.contains("\"drain_completed\":true"));

        let legacy = encoded.replace(",\"drain_completed\":true", "");
        let legacy: CommittedState = serde_json::from_str(&legacy).unwrap();
        assert!(!legacy.drain_completed);

        state.draining = false;
        assert_eq!(
            validate_state(&state).unwrap_err(),
            BrokerRuntimeError::StateInvalid
        );
    }

    #[test]
    fn systemd_clean_drain_exit_requires_the_exact_successful_dead_state() {
        assert!(systemd_clean_drain_exit(
            "inactive", "dead", 0, "success", 0
        ));
        for (active_state, sub_state, main_pid, result, status) in [
            ("active", "running", 17, "success", 0),
            ("deactivating", "stop-sigterm", 17, "success", 0),
            ("inactive", "dead", 0, "exit-code", 0),
            ("inactive", "dead", 0, "success", 1),
            ("inactive", "dead", 17, "success", 0),
        ] {
            assert!(!systemd_clean_drain_exit(
                active_state,
                sub_state,
                main_pid,
                result,
                status,
            ));
        }
    }
}
