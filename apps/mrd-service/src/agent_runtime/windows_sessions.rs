//! Launch and supervise one authenticated Session Agent per interactive Windows session.

use super::{
    inspect_windows_process, AgentConnectionId, AgentRegistry, AgentServer, ExecuteGrantIssuer,
    ExpectedAgentSession, ReplacementPolicy, WindowsAgentPipe,
};
use mrd_agent_ipc::{
    derive_registration_public_key, windows_agent_bootstrap_pipe_name, write_agent_bootstrap,
    AgentBootstrap, BoundEd25519RegistrationVerifier, ServiceToAgent, StopAgent, StopReason,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{c_void, OsStr},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::task::JoinHandle;
use windows::{
    core::{Owned, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            RemoteDesktop::{
                WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken,
                WTS_SESSION_INFOW,
            },
            Threading::{
                CreateProcessAsUserW, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW,
                CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
    },
};
use zeroize::Zeroizing;

const AGENT_ADMISSION_LIFETIME_MS: u64 = 30_000;
const AGENT_HEARTBEAT_INTERVAL_MS: u32 = 2_000;
const AGENT_HANDSHAKE_TIMEOUT_MS: u32 = 10_000;
const AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(8);

/// Failures at the trusted Windows session-launch boundary.
#[derive(Debug, Error)]
pub enum WindowsSessionAgentError {
    #[error("interactive Windows session id is invalid")]
    InvalidSession,
    #[error("Session Agent executable does not exist: {0}")]
    AgentExecutableMissing(PathBuf),
    #[error("Session Agent process creation returned an invalid process id")]
    InvalidProcess,
    #[error("secure random generation failed")]
    EntropyUnavailable,
    #[error("system clock is before the Unix epoch")]
    ClockUnavailable,
    #[error("Agent registration key derivation failed: {0}")]
    RegistrationKey(String),
    #[error("Agent registry rejected the launched process: {0}")]
    Registry(String),
    #[error("Agent pipe failed: {0}")]
    Pipe(String),
    #[error("Agent bootstrap failed: {0}")]
    Bootstrap(String),
    #[error("Agent server failed: {0}")]
    Server(String),
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

/// Resolve the Session Agent installed beside the service binary.
pub fn installed_session_agent_path() -> Result<PathBuf, WindowsSessionAgentError> {
    if let Some(path) = std::env::var_os("MRD_SESSION_AGENT_EXE") {
        let path = PathBuf::from(path);
        return path
            .is_file()
            .then_some(path.clone())
            .ok_or(WindowsSessionAgentError::AgentExecutableMissing(path));
    }
    let mut path = std::env::current_exe().map_err(windows::core::Error::from)?;
    path.set_file_name("mrd-session-agent.exe");
    path.is_file()
        .then_some(path.clone())
        .ok_or(WindowsSessionAgentError::AgentExecutableMissing(path))
}

/// Enumerate bounded, currently active local or RDP interactive sessions.
pub fn eligible_interactive_sessions() -> Result<Vec<u32>, WindowsSessionAgentError> {
    let mut sessions = std::ptr::null_mut::<WTS_SESSION_INFOW>();
    let mut count = 0_u32;
    unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut sessions, &mut count)? };
    let sessions = WtsSessionBuffer(sessions);
    if count > 1_024 || (count != 0 && sessions.0.is_null()) {
        return Err(WindowsSessionAgentError::InvalidSession);
    }
    let entries = unsafe { std::slice::from_raw_parts(sessions.0, count as usize) };
    let mut eligible: Vec<u32> = entries
        .iter()
        .filter(|entry| is_eligible_session(entry.SessionId, entry.State))
        .map(|entry| entry.SessionId)
        .collect();
    eligible.sort_unstable();
    eligible.dedup();
    Ok(eligible)
}

fn is_eligible_session(
    session_id: u32,
    state: windows::Win32::System::RemoteDesktop::WTS_CONNECTSTATE_CLASS,
) -> bool {
    session_id != 0 && state == WTSActive
}

struct WtsSessionBuffer(*mut WTS_SESSION_INFOW);

impl Drop for WtsSessionBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WTSFreeMemory(self.0.cast()) };
        }
    }
}

/// Owns launched processes, bootstrap tasks, and exact-session revocation.
pub struct WindowsSessionAgentSupervisor {
    registry: Arc<AgentRegistry>,
    server: Arc<AgentServer>,
    issuer: Arc<ExecuteGrantIssuer>,
    executable: PathBuf,
    agents: BTreeMap<u32, ManagedAgent>,
    desired_sessions: BTreeSet<u32>,
}

struct ManagedAgent {
    process: Owned<HANDLE>,
    process_id: u32,
    connection_task: JoinHandle<Result<(), WindowsSessionAgentError>>,
}

// Windows process handles are process-wide kernel objects and may be waited or
// closed from a Tokio worker other than the launching thread.
unsafe impl Send for ManagedAgent {}

impl WindowsSessionAgentSupervisor {
    pub fn new(
        registry: Arc<AgentRegistry>,
        server: Arc<AgentServer>,
        issuer: Arc<ExecuteGrantIssuer>,
        executable: PathBuf,
    ) -> Result<Self, WindowsSessionAgentError> {
        if !executable.is_file() {
            return Err(WindowsSessionAgentError::AgentExecutableMissing(executable));
        }
        Ok(Self {
            registry,
            server,
            issuer,
            executable,
            agents: BTreeMap::new(),
            desired_sessions: BTreeSet::new(),
        })
    }

    pub fn contains_session(&self, session_id: u32) -> bool {
        self.agents.contains_key(&session_id)
    }

    pub async fn launch(&mut self, session_id: u32) -> Result<(), WindowsSessionAgentError> {
        if session_id == 0 {
            return Err(WindowsSessionAgentError::InvalidSession);
        }
        self.desired_sessions.insert(session_id);
        self.launch_once(session_id).await
    }

    async fn launch_once(&mut self, session_id: u32) -> Result<(), WindowsSessionAgentError> {
        if self.agents.contains_key(&session_id) {
            return Ok(());
        }

        let mut launched = launch_process_in_session(session_id, &self.executable)?;
        let process_id = launched.process_id;
        let verified = inspect_windows_process(process_id)
            .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
        if verified.windows_session_id() != session_id {
            return Err(WindowsSessionAgentError::InvalidSession);
        }

        let mut registration_seed = Zeroizing::new([0_u8; 32]);
        SystemRandom::new()
            .fill(&mut *registration_seed)
            .map_err(|_| WindowsSessionAgentError::EntropyUnavailable)?;
        let registration_key = derive_registration_public_key(&registration_seed)
            .map_err(|error| WindowsSessionAgentError::RegistrationKey(error.to_string()))?;
        let verifier = Arc::new(
            BoundEd25519RegistrationVerifier::new(
                registration_key.key_id,
                registration_key.public_key,
            )
            .map_err(|error| WindowsSessionAgentError::RegistrationKey(error.to_string()))?,
        );
        self.registry
            .expect_session(
                ExpectedAgentSession {
                    windows_session_id: session_id,
                    logon_sid_hash: *verified.logon_sid_hash(),
                    process_id,
                    process_creation_time: verified.process_creation_time(),
                    agent_key_id: registration_key.key_id,
                    expires_at_ms: now_ms()?.saturating_add(AGENT_ADMISSION_LIFETIME_MS),
                    replacement_policy: ReplacementPolicy::RejectExisting,
                },
                verifier,
            )
            .map_err(|error| WindowsSessionAgentError::Registry(error.to_string()))?;

        let bootstrap_name = windows_agent_bootstrap_pipe_name(
            session_id,
            process_id,
            verified.process_creation_time(),
        );
        let control_name = format!(
            r"\\.\pipe\mrd-agent-control-v2-service-{}-session-{session_id}-process-{process_id}",
            std::process::id()
        );
        let bootstrap_pipe = WindowsAgentPipe::create_for_process(&bootstrap_name, &verified)
            .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
        let control_pipe = WindowsAgentPipe::create_for_process(&control_name, &verified)
            .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
        let service_process = inspect_windows_process(std::process::id())
            .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
        let connection_id = random_connection_id()?;
        let server = Arc::clone(&self.server);
        let issuer = Arc::clone(&self.issuer);
        let connection_task = tokio::spawn(async move {
            bootstrap_and_serve(
                bootstrap_pipe,
                control_pipe,
                control_name,
                registration_seed,
                registration_key.key_id,
                service_process.process_creation_time(),
                connection_id,
                server,
                issuer,
            )
            .await
        });
        self.agents.insert(
            session_id,
            ManagedAgent {
                process: launched
                    .process
                    .take()
                    .ok_or(WindowsSessionAgentError::InvalidProcess)?,
                process_id,
                connection_task,
            },
        );
        Ok(())
    }

    /// Restart failed Agent generations while their Windows session remains eligible.
    pub async fn reconcile(&mut self) {
        let stale: Vec<u32> = self
            .agents
            .iter()
            .filter_map(|(session_id, managed)| {
                (managed.connection_task.is_finished() || process_has_exited(&managed.process))
                    .then_some(*session_id)
            })
            .collect();
        for session_id in stale {
            if let Some(managed) = self.agents.remove(&session_id) {
                if !process_has_exited(&managed.process) {
                    let _ = unsafe { TerminateProcess(*managed.process, 1) };
                }
                if !managed.connection_task.is_finished() {
                    managed.connection_task.abort();
                }
                let _ = managed.connection_task.await;
                tracing::warn!(session_id, "restarting failed Session Agent generation");
            }
        }
        let desired: Vec<u32> = self.desired_sessions.iter().copied().collect();
        for session_id in desired {
            if !self.agents.contains_key(&session_id) {
                if let Err(error) = self.launch_once(session_id).await {
                    tracing::warn!(session_id, "Session Agent restart deferred: {error}");
                }
            }
        }
    }

    pub async fn stop_session(
        &mut self,
        session_id: u32,
        reason: StopReason,
    ) -> Result<(), WindowsSessionAgentError> {
        self.desired_sessions.remove(&session_id);
        let Some(managed) = self.agents.remove(&session_id) else {
            return Ok(());
        };
        if let Some(active) = self.registry.active_for_session_at(session_id, now_ms()?) {
            let _ = self.server.send_to_connection(
                active.connection_id,
                ServiceToAgent::StopAgent(StopAgent {
                    request_id: random_nonzero::<16>()?,
                    deadline_ms: now_ms()?.saturating_add(AGENT_STOP_TIMEOUT.as_millis() as u64),
                    reason,
                }),
            );
        }
        wait_or_terminate(&managed.process, AGENT_STOP_TIMEOUT)?;
        if !managed.connection_task.is_finished() {
            managed.connection_task.abort();
        }
        let _ = managed.connection_task.await;
        tracing::info!(
            session_id,
            process_id = managed.process_id,
            "Session Agent stopped"
        );
        Ok(())
    }

    pub async fn stop_all(&mut self, reason: StopReason) -> Result<(), WindowsSessionAgentError> {
        self.desired_sessions.clear();
        let sessions: Vec<u32> = self.agents.keys().copied().collect();
        for session_id in sessions {
            self.stop_session(session_id, reason).await?;
        }
        let _ = self.registry.invalidate_all();
        Ok(())
    }
}

struct LaunchedProcess {
    process: Option<Owned<HANDLE>>,
    process_id: u32,
}

impl Drop for LaunchedProcess {
    fn drop(&mut self) {
        if let Some(process) = self.process.as_ref() {
            let _ = unsafe { TerminateProcess(**process, 1) };
        }
    }
}

fn launch_process_in_session(
    session_id: u32,
    executable: &Path,
) -> Result<LaunchedProcess, WindowsSessionAgentError> {
    let mut raw_token = HANDLE::default();
    unsafe { WTSQueryUserToken(session_id, &mut raw_token)? };
    let token = unsafe { Owned::new(raw_token) };
    let mut environment: *mut c_void = std::ptr::null_mut();
    unsafe { CreateEnvironmentBlock(&mut environment, Some(*token), false)? };
    let environment = EnvironmentBlock(environment);
    let executable_wide = wide_nul(executable.as_os_str());
    let current_directory = executable.parent().map(|path| wide_nul(path.as_os_str()));
    let mut desktop = wide_nul(OsStr::new(r"winsta0\default"));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessAsUserW(
            Some(*token),
            PCWSTR(executable_wide.as_ptr()),
            None,
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            Some(environment.0.cast_const()),
            current_directory
                .as_ref()
                .map(|value| PCWSTR(value.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            &startup,
            &mut process_info,
        )?;
    }
    if process_info.dwProcessId == 0 || process_info.hProcess.is_invalid() {
        return Err(WindowsSessionAgentError::InvalidProcess);
    }
    unsafe { CloseHandle(process_info.hThread)? };
    Ok(LaunchedProcess {
        process: Some(unsafe { Owned::new(process_info.hProcess) }),
        process_id: process_info.dwProcessId,
    })
}

struct EnvironmentBlock(*mut c_void);

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { DestroyEnvironmentBlock(self.0) };
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn bootstrap_and_serve(
    mut bootstrap_pipe: WindowsAgentPipe,
    mut control_pipe: WindowsAgentPipe,
    control_name: String,
    registration_seed: Zeroizing<[u8; 32]>,
    expected_agent_key_id: [u8; 32],
    service_process_creation_time: u64,
    connection_id: AgentConnectionId,
    server: Arc<AgentServer>,
    issuer: Arc<ExecuteGrantIssuer>,
) -> Result<(), WindowsSessionAgentError> {
    bootstrap_pipe
        .connect()
        .await
        .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
    let bootstrap_peer = bootstrap_pipe
        .inspect_peer()
        .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
    let mut bootstrap_stream = bootstrap_pipe.into_stream();
    write_agent_bootstrap(
        &mut bootstrap_stream,
        AgentBootstrap {
            control_endpoint: &control_name,
            service_process_id: std::process::id(),
            service_process_creation_time,
            heartbeat_interval_ms: AGENT_HEARTBEAT_INTERVAL_MS,
            handshake_timeout_ms: AGENT_HANDSHAKE_TIMEOUT_MS,
            registration_seed,
            expected_agent_key_id,
            execute_grant_issuer_key_id: issuer.key_id(),
            execute_grant_public_key: issuer.public_key(),
        },
    )
    .await
    .map_err(|error| WindowsSessionAgentError::Bootstrap(error.to_string()))?;
    drop(bootstrap_stream);
    drop(bootstrap_peer);

    control_pipe
        .connect()
        .await
        .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
    let control_peer = control_pipe
        .inspect_peer()
        .map_err(|error| WindowsSessionAgentError::Pipe(error.to_string()))?;
    let observed = control_peer.cloned_identity();
    let _process_guard = control_peer;
    server
        .serve_connection(control_pipe.into_stream(), connection_id, observed)
        .await
        .map_err(|error| WindowsSessionAgentError::Server(error.to_string()))?;
    Ok(())
}

fn wait_or_terminate(
    process: &Owned<HANDLE>,
    timeout: Duration,
) -> Result<(), WindowsSessionAgentError> {
    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    match unsafe { WaitForSingleObject(**process, timeout_ms) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => {
            unsafe { TerminateProcess(**process, 1)? };
            let _ = unsafe { WaitForSingleObject(**process, 2_000) };
            Ok(())
        }
        _ => Err(windows::core::Error::from_thread().into()),
    }
}

fn process_has_exited(process: &Owned<HANDLE>) -> bool {
    (unsafe { WaitForSingleObject(**process, 0) }) == WAIT_OBJECT_0
}

fn random_connection_id() -> Result<AgentConnectionId, WindowsSessionAgentError> {
    AgentConnectionId::from_bytes(random_nonzero::<16>()?)
        .map_err(|error| WindowsSessionAgentError::Registry(error.to_string()))
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], WindowsSessionAgentError> {
    let random = SystemRandom::new();
    for _ in 0..4 {
        let mut bytes = [0_u8; N];
        random
            .fill(&mut bytes)
            .map_err(|_| WindowsSessionAgentError::EntropyUnavailable)?;
        if bytes != [0; N] {
            return Ok(bytes);
        }
    }
    Err(WindowsSessionAgentError::EntropyUnavailable)
}

fn now_ms() -> Result<u64, WindowsSessionAgentError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WindowsSessionAgentError::ClockUnavailable)?
        .as_millis() as u64)
}

fn wide_nul(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::RemoteDesktop::WTSDisconnected;

    #[test]
    fn active_session_filter_rejects_session_zero() {
        assert!(!is_eligible_session(0, WTSActive));
        assert!(!is_eligible_session(7, WTSDisconnected));
        assert!(is_eligible_session(7, WTSActive));
    }

    #[test]
    fn desktop_name_is_nul_terminated() {
        let value = wide_nul(OsStr::new(r"winsta0\default"));
        assert_eq!(value.last(), Some(&0));
        assert_eq!(value.iter().filter(|value| **value == 0).count(), 1);
    }
}
