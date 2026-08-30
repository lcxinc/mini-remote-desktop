//! Authenticated launcher bootstrap and OS-derived process identity.

use crate::runtime::{
    AgentExit, AgentRuntimeError, PrivateEndpointError, RegistrationSigner,
    RegistrationSigningError,
};
use ed25519_dalek::{Signer, SigningKey};
use mrd_agent_ipc::{derive_registration_public_key, AgentBootstrapError};
use std::sync::Mutex;
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(windows)]
use crate::input::InputResourceManager;
#[cfg(windows)]
use crate::native_consent::NativeConsentBackend;
#[cfg(windows)]
use crate::runtime::{
    connect_private_endpoint, AgentRuntime, AgentRuntimeConfig, PrivateAgentEndpoint,
    PrivateAgentStream, SessionDescriptor, SystemClock,
};
#[cfg(windows)]
use crate::windows_consent::WindowsConsentSurfaceDriver;
#[cfg(windows)]
use crate::windows_desktop::WindowsTrustedDesktopStateSource;
#[cfg(windows)]
use mrd_agent_ipc::{
    read_agent_bootstrap, windows_agent_bootstrap_pipe_name, BoundEd25519ExecuteGrantVerifier,
    ReceivedAgentBootstrap,
};
#[cfg(windows)]
use std::{sync::Arc, time::Duration};

#[cfg(windows)]
const BOOTSTRAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(windows)]
const BOOTSTRAP_READ_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(windows)]
const PIPE_CONNECT_RETRY: Duration = Duration::from_millis(20);
#[cfg(windows)]
const MAX_RUNTIME_INTERVAL: Duration = Duration::from_secs(60);

/// Authenticated launcher and platform-identity failures.
#[derive(Debug, Error)]
pub enum AgentLauncherError {
    /// This platform has no authenticated launcher implementation yet.
    #[error("authenticated launcher bootstrap is unsupported on this platform")]
    UnsupportedPlatform,
    /// OS process/token identity could not be established.
    #[error("trusted agent process identity is unavailable")]
    PlatformIdentity,
    /// The derived bootstrap pipe did not appear within the launch deadline.
    #[error("authenticated launcher bootstrap timed out")]
    BootstrapTimeout,
    /// Bootstrap or control pipe server differs from the claimed service process.
    #[error("launcher bootstrap service identity mismatch")]
    ServiceIdentityMismatch,
    /// Bootstrap timing configuration is unsafe.
    #[error("launcher bootstrap timing configuration is invalid")]
    InvalidTiming,
    /// One-shot registration signer state is poisoned or inconsistent.
    #[error("launcher registration signer is unavailable")]
    SignerUnavailable,
    /// Protected bootstrap record was malformed or truncated.
    #[error(transparent)]
    Bootstrap(#[from] AgentBootstrapError),
    /// Platform-local endpoint parsing or opening failed.
    #[error(transparent)]
    Endpoint(#[from] PrivateEndpointError),
    /// Agent runtime registration or lifecycle failed.
    #[error(transparent)]
    Runtime(#[from] AgentRuntimeError),
    /// The attended native authority could not be assembled safely.
    #[cfg(windows)]
    #[error("attended native authority is unavailable")]
    AttendedAuthorityUnavailable,
    /// Windows security/process API failed.
    #[cfg(windows)]
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
}

/// Registration signer that consumes and zeroizes its per-launch seed once.
pub struct OneShotEd25519Signer {
    key_id: [u8; 32],
    seed: Mutex<Option<Zeroizing<[u8; 32]>>>,
}

impl OneShotEd25519Signer {
    /// Bind a zeroizing seed to the key id authenticated in the bootstrap.
    pub fn new(
        seed: Zeroizing<[u8; 32]>,
        expected_key_id: [u8; 32],
    ) -> Result<Self, AgentLauncherError> {
        let derived = derive_registration_public_key(&seed)?;
        if derived.key_id != expected_key_id {
            return Err(AgentLauncherError::SignerUnavailable);
        }
        Ok(Self {
            key_id: expected_key_id,
            seed: Mutex::new(Some(seed)),
        })
    }
}

impl RegistrationSigner for OneShotEd25519Signer {
    fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], RegistrationSigningError> {
        let seed = self
            .seed
            .lock()
            .map_err(|_| RegistrationSigningError::Unavailable)?
            .take()
            .ok_or(RegistrationSigningError::Unavailable)?;
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(signing_key.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_seed_can_sign_only_once() {
        let seed = Zeroizing::new([42; 32]);
        let key = derive_registration_public_key(&seed).unwrap();
        let signer = OneShotEd25519Signer::new(seed, key.key_id).unwrap();

        assert!(signer.sign(b"registration transcript").is_ok());
        assert_eq!(
            signer.sign(b"second transcript"),
            Err(RegistrationSigningError::Unavailable)
        );
    }

    #[cfg(windows)]
    #[test]
    fn execute_verifier_binding_rejects_mismatched_bootstrap_material() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let signer = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let public_key: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
        let key_id = mrd_agent_ipc::derive_execute_grant_issuer_key_id(&public_key);
        assert!(bind_execute_verifier(key_id, public_key).is_ok());
        assert!(matches!(
            bind_execute_verifier([7; 32], public_key),
            Err(AgentLauncherError::Bootstrap(
                AgentBootstrapError::InvalidExecuteGrantIssuerKey
            ))
        ));
        assert!(matches!(
            bind_execute_verifier(key_id, [0; 32]),
            Err(AgentLauncherError::Bootstrap(
                AgentBootstrapError::InvalidExecuteGrantIssuerKey
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn production_media_executor_never_claims_unassembled_capture() {
        use crate::runtime::AuthorizedCommandExecutor;
        use mrd_agent_ipc::AgentCapability;

        let executor = build_windows_media_executor();
        assert!(!executor
            .capabilities()
            .as_set()
            .contains(&AgentCapability::Capture));
    }
}

#[cfg(windows)]
fn build_windows_media_executor() -> crate::media::MediaExecutor<
    crate::capture::UnavailableCaptureAdapter,
    crate::windows_render::WindowsRenderAdapter,
> {
    crate::media::MediaExecutor::new(
        crate::capture::UnavailableCaptureAdapter,
        crate::windows_render::WindowsRenderAdapter::new(),
    )
}

/// Start the production agent only from an authenticated launcher bootstrap.
pub async fn run_from_authenticated_launcher() -> Result<AgentExit, AgentLauncherError> {
    #[cfg(windows)]
    {
        run_windows_launcher().await
    }

    #[cfg(not(windows))]
    {
        Err(AgentLauncherError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
async fn run_windows_launcher() -> Result<AgentExit, AgentLauncherError> {
    let descriptor = windows_platform::current_session_descriptor()?;
    let bootstrap_name = windows_agent_bootstrap_pipe_name(
        descriptor.windows_session_id,
        descriptor.process_id,
        descriptor.process_creation_time,
    );
    let bootstrap_endpoint = PrivateAgentEndpoint::parse(&bootstrap_name)?;
    let mut bootstrap_stream = connect_until(&bootstrap_endpoint).await?;
    let received = tokio::time::timeout(
        BOOTSTRAP_READ_TIMEOUT,
        read_agent_bootstrap(&mut bootstrap_stream),
    )
    .await
    .map_err(|_| AgentLauncherError::BootstrapTimeout)??;
    if received.service_process_id() != descriptor.parent_process_id {
        return Err(AgentLauncherError::ServiceIdentityMismatch);
    }
    if received.service_process_creation_time() != descriptor.parent_process.creation_time {
        return Err(AgentLauncherError::ServiceIdentityMismatch);
    }
    let bootstrap_service = windows_platform::verify_pipe_server(
        &bootstrap_stream,
        received.service_process_id(),
        received.service_process_creation_time(),
    )?;
    let launch = build_launch(descriptor, received)?;
    drop(bootstrap_stream);

    let control_stream = connect_until(&launch.endpoint).await?;
    let control_service = windows_platform::verify_pipe_server(
        &control_stream,
        launch.service_process_id,
        launch.service_process_creation_time,
    )?;
    drop(bootstrap_service);

    let runtime = AgentRuntime::new(
        launch.config,
        Arc::new(SystemClock),
        Arc::new(launch.signer),
    )?
    .with_attended_authority(
        {
            let (driver, availability) = WindowsConsentSurfaceDriver::start()
                .map_err(|_| AgentLauncherError::AttendedAuthorityUnavailable)?;
            Arc::new(NativeConsentBackend::new(driver, availability))
        },
        Arc::new(launch.execute_verifier.clone()),
        Arc::new(
            WindowsTrustedDesktopStateSource::start(launch.windows_session_id)
                .map_err(|_| AgentLauncherError::AttendedAuthorityUnavailable)?,
        ),
        launch.execute_grant_issuer_key_id,
        Box::new(build_windows_media_executor()),
    )?
    .with_input_backend(Box::new(InputResourceManager::new(
        mrd_input::windows::WindowsSendInputInjector::new(),
    )));
    let result = runtime.run(control_stream).await;
    drop(control_service);
    result.map_err(Into::into)
}

#[cfg(windows)]
struct PlatformSessionDescriptor {
    session: SessionDescriptor,
    parent_process_id: u32,
    parent_process: windows_platform::ServiceProcessGuard,
    process_id: u32,
    process_creation_time: u64,
    windows_session_id: u32,
}

#[cfg(windows)]
struct AuthenticatedLaunch {
    endpoint: PrivateAgentEndpoint,
    service_process_id: u32,
    service_process_creation_time: u64,
    config: AgentRuntimeConfig,
    signer: OneShotEd25519Signer,
    execute_grant_issuer_key_id: [u8; 32],
    execute_verifier: BoundEd25519ExecuteGrantVerifier,
    windows_session_id: u32,
    _parent_process: windows_platform::ServiceProcessGuard,
}

#[cfg(windows)]
fn build_launch(
    descriptor: PlatformSessionDescriptor,
    bootstrap: ReceivedAgentBootstrap,
) -> Result<AuthenticatedLaunch, AgentLauncherError> {
    let (
        endpoint,
        service_process_id,
        service_process_creation_time,
        heartbeat_interval_ms,
        handshake_timeout_ms,
        expected_agent_key_id,
        seed,
        execute_grant_issuer_key_id,
        execute_grant_public_key,
    ) = bootstrap.into_parts();
    let heartbeat_interval = Duration::from_millis(u64::from(heartbeat_interval_ms));
    let handshake_timeout = Duration::from_millis(u64::from(handshake_timeout_ms));
    if heartbeat_interval.is_zero()
        || heartbeat_interval > MAX_RUNTIME_INTERVAL
        || handshake_timeout.is_zero()
        || handshake_timeout > MAX_RUNTIME_INTERVAL
    {
        return Err(AgentLauncherError::InvalidTiming);
    }
    let execute_verifier =
        bind_execute_verifier(execute_grant_issuer_key_id, execute_grant_public_key)?;
    Ok(AuthenticatedLaunch {
        endpoint: PrivateAgentEndpoint::parse(endpoint)?,
        service_process_id,
        service_process_creation_time,
        config: AgentRuntimeConfig {
            session: descriptor.session,
            heartbeat_interval,
            handshake_timeout,
        },
        signer: OneShotEd25519Signer::new(seed, expected_agent_key_id)?,
        execute_grant_issuer_key_id,
        execute_verifier,
        windows_session_id: descriptor.windows_session_id,
        _parent_process: descriptor.parent_process,
    })
}

#[cfg(windows)]
fn bind_execute_verifier(
    expected_key_id: [u8; 32],
    public_key: [u8; 32],
) -> Result<BoundEd25519ExecuteGrantVerifier, AgentLauncherError> {
    BoundEd25519ExecuteGrantVerifier::new(expected_key_id, public_key)
        .map_err(AgentLauncherError::Bootstrap)
}

#[cfg(windows)]
async fn connect_until(
    endpoint: &PrivateAgentEndpoint,
) -> Result<PrivateAgentStream, AgentLauncherError> {
    let deadline = tokio::time::Instant::now() + BOOTSTRAP_CONNECT_TIMEOUT;
    loop {
        match connect_private_endpoint(endpoint).await {
            Ok(stream) => return Ok(stream),
            Err(PrivateEndpointError::Io(error)) if retryable_pipe_error(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(AgentLauncherError::BootstrapTimeout);
                }
                tokio::time::sleep(PIPE_CONNECT_RETRY).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(windows)]
fn retryable_pipe_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(2 | 231))
}

#[cfg(windows)]
mod windows_platform {
    use super::{AgentLauncherError, PlatformSessionDescriptor};
    use crate::runtime::{PrivateAgentStream, SessionDescriptor};
    use mrd_agent_ipc::hash_windows_logon_sid;
    use ring::rand::{SecureRandom, SystemRandom};
    use std::{
        mem::{size_of, size_of_val},
        os::windows::io::AsRawHandle,
        ptr,
    };
    use windows::{
        core::Owned,
        Win32::{
            Foundation::{FILETIME, HANDLE},
            Security::{
                GetLengthSid, GetTokenInformation, IsValidSid, TokenLogonSid, TokenSessionId, PSID,
                SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
            },
            System::{
                Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
                Pipes::GetNamedPipeServerProcessId,
                SystemServices::SE_GROUP_LOGON_ID,
                Threading::{
                    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
                    OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
                },
            },
        },
    };

    const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
    const SECURITY_MAX_SID_SIZE: usize = 68;

    pub(super) struct ServiceProcessGuard {
        _process: Owned<HANDLE>,
        pub(super) creation_time: u64,
    }

    // Windows kernel process handles are process-wide and safe to retain/drop
    // after a Tokio task migrates; the raw pointer is never dereferenced.
    unsafe impl Send for ServiceProcessGuard {}

    pub(super) fn current_session_descriptor(
    ) -> Result<PlatformSessionDescriptor, AgentLauncherError> {
        let process_id = unsafe { GetCurrentProcessId() };
        let parent_process_id = parent_process_id(process_id)?;
        let parent_process = open_service_process(parent_process_id)?;
        let process = unsafe { GetCurrentProcess() };
        let process_creation_time = process_creation_time(process)?;
        let token = open_process_token(process)?;
        let logon_sid = token_logon_sid(&token)?;
        let logon_sid_hash =
            hash_windows_logon_sid(&logon_sid).ok_or(AgentLauncherError::PlatformIdentity)?;
        let windows_session_id = token_scalar::<u32>(&token, TokenSessionId)?;
        if process_id == 0 || windows_session_id == 0 {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        let random = SystemRandom::new();
        let mut agent_instance_id = [0_u8; 16];
        let mut agent_nonce = [0_u8; 32];
        random
            .fill(&mut agent_instance_id)
            .map_err(|_| AgentLauncherError::PlatformIdentity)?;
        random
            .fill(&mut agent_nonce)
            .map_err(|_| AgentLauncherError::PlatformIdentity)?;
        let session = SessionDescriptor::new(
            agent_instance_id,
            process_id,
            process_creation_time,
            logon_sid_hash,
            windows_session_id,
            agent_nonce,
            1,
        )?;
        Ok(PlatformSessionDescriptor {
            session,
            parent_process_id,
            parent_process,
            process_id,
            process_creation_time,
            windows_session_id,
        })
    }

    fn parent_process_id(process_id: u32) -> Result<u32, AgentLauncherError> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
        // SAFETY: CreateToolhelp32Snapshot returned a new owned snapshot handle.
        let snapshot = unsafe { Owned::new(snapshot) };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..PROCESSENTRY32W::default()
        };
        unsafe { Process32FirstW(*snapshot, &mut entry)? };
        loop {
            if entry.th32ProcessID == process_id {
                return (entry.th32ParentProcessID != 0)
                    .then_some(entry.th32ParentProcessID)
                    .ok_or(AgentLauncherError::PlatformIdentity);
            }
            if unsafe { Process32NextW(*snapshot, &mut entry) }.is_err() {
                return Err(AgentLauncherError::PlatformIdentity);
            }
        }
    }

    pub(super) fn verify_pipe_server(
        pipe: &PrivateAgentStream,
        expected_process_id: u32,
        expected_creation_time: u64,
    ) -> Result<ServiceProcessGuard, AgentLauncherError> {
        let mut process_id = 0_u32;
        unsafe {
            GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut process_id)?;
        }
        if process_id == 0 || process_id != expected_process_id {
            return Err(AgentLauncherError::ServiceIdentityMismatch);
        }
        let process = open_service_process(expected_process_id)?;
        if process.creation_time != expected_creation_time {
            return Err(AgentLauncherError::ServiceIdentityMismatch);
        }
        Ok(process)
    }

    fn open_service_process(process_id: u32) -> Result<ServiceProcessGuard, AgentLauncherError> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)? };
        // SAFETY: OpenProcess returned a new owned process handle.
        let process = unsafe { Owned::new(handle) };
        let creation_time = process_creation_time(*process)?;
        Ok(ServiceProcessGuard {
            _process: process,
            creation_time,
        })
    }

    fn process_creation_time(process: HANDLE) -> Result<u64, AgentLauncherError> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user)? };
        Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    fn open_process_token(process: HANDLE) -> Result<Owned<HANDLE>, AgentLauncherError> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token)? };
        // SAFETY: OpenProcessToken returned a new owned token handle.
        Ok(unsafe { Owned::new(token) })
    }

    fn token_logon_sid(token: &Owned<HANDLE>) -> Result<Vec<u8>, AgentLauncherError> {
        let buffer = token_information(token, TokenLogonSid)?;
        if buffer.byte_len < size_of::<TOKEN_GROUPS>() {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        // SAFETY: storage is usize-aligned and size-checked.
        let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
        let first = ptr::addr_of!(groups.Groups).cast::<SID_AND_ATTRIBUTES>();
        let offset = first as usize - buffer.as_ptr() as usize;
        let count = groups.GroupCount as usize;
        let available = buffer.byte_len.saturating_sub(offset) / size_of::<SID_AND_ATTRIBUTES>();
        if count == 0 || count > available || count > 1_024 {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        // SAFETY: count is bounded by the returned buffer.
        let entries = unsafe { std::slice::from_raw_parts(first, count) };
        let mask = SE_GROUP_LOGON_ID as u32;
        let mut matching = entries
            .iter()
            .filter(|entry| entry.Attributes & mask == mask);
        let sid = matching
            .next()
            .ok_or(AgentLauncherError::PlatformIdentity)?;
        if matching.next().is_some() {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        copy_valid_sid(sid.Sid)
    }

    fn copy_valid_sid(sid: PSID) -> Result<Vec<u8>, AgentLauncherError> {
        if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        let length = unsafe { GetLengthSid(sid) } as usize;
        if !(8..=SECURITY_MAX_SID_SIZE).contains(&length) {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        // SAFETY: IsValidSid and GetLengthSid validated this exact range.
        Ok(unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), length) }.to_vec())
    }

    fn token_scalar<T: Copy>(
        token: &Owned<HANDLE>,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<T, AgentLauncherError> {
        let buffer = token_information(token, class)?;
        if buffer.byte_len < size_of::<T>() {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        // SAFETY: storage is usize-aligned for the requested scalar.
        Ok(unsafe { *buffer.as_ptr().cast::<T>() })
    }

    struct AlignedTokenBuffer {
        words: Vec<usize>,
        byte_len: usize,
    }

    impl AlignedTokenBuffer {
        fn as_ptr(&self) -> *const u8 {
            self.words.as_ptr().cast()
        }
    }

    fn token_information(
        token: &Owned<HANDLE>,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<AlignedTokenBuffer, AgentLauncherError> {
        let mut required = 0_u32;
        let _ = unsafe { GetTokenInformation(**token, class, None, 0, &mut required) };
        let required = required as usize;
        if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        let mut words = vec![0_usize; required.div_ceil(size_of::<usize>())];
        let mut returned = required as u32;
        unsafe {
            GetTokenInformation(
                **token,
                class,
                Some(words.as_mut_ptr().cast()),
                required as u32,
                &mut returned,
            )?
        };
        let returned = returned as usize;
        if returned == 0 || returned > size_of_val(words.as_slice()) {
            return Err(AgentLauncherError::PlatformIdentity);
        }
        Ok(AlignedTokenBuffer {
            words,
            byte_len: returned,
        })
    }
}
