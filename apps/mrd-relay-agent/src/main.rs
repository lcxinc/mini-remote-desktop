use std::{
    ffi::OsString,
    io::Write as _,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

#[cfg(windows)]
use std::io::Read as _;

#[cfg(windows)]
use std::sync::{Mutex, OnceLock};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mrd_relay_agent::{
    backend::{
        EnrollmentRequest, RelayBackendClientFactoryPort, RelayBackendPort, ReqwestRelayBackend,
        ReqwestRelayBackendFactory,
    },
    config::{ProductionAgentConfig, ProductionTargetConfig},
    identity::{CertificateState, IdentityFsPort},
    metrics::{MetricsLimits, PlatformMetrics, ReqwestNativeCoturnScrape},
    platform::{
        linux::LinuxBrokerClient, windows::WindowsBrokerClient, BrokerControlPort,
        PlatformCoturnRuntime,
    },
    runtime::{
        run_agent, HostPressureSnapshot, PortableRelayAgentConfig, PortableRelayAgentDeps,
        RandomJitter, RuntimeError, RuntimeStateStorePort, SystemClock, TokioSleeper,
        CERTIFICATE_LIFETIME_RENEWAL_WINDOW_CAP,
    },
};
use ring::rand::{SecureRandom as _, SystemRandom};
use secrecy::SecretString;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use mrd_relay_agent::secure_store::{
    read_linux_integrity_file, HardenedAtomicFile, LinuxPlaintextProtector, SecureIdentityStore,
    SecureRuntimeStateStore, StrictCredentialFile,
};

#[derive(Debug)]
struct CliFailure {
    exit_code: u8,
    reason: &'static str,
}

impl CliFailure {
    const fn usage() -> Self {
        Self {
            exit_code: 64,
            reason: "relay_cli_invalid",
        }
    }

    const fn config() -> Self {
        Self {
            exit_code: 65,
            reason: "relay_agent_config_invalid",
        }
    }

    const fn unavailable() -> Self {
        Self {
            exit_code: 69,
            reason: "relay_platform_unavailable",
        }
    }

    const fn runtime() -> Self {
        Self {
            exit_code: 70,
            reason: "relay_agent_runtime_failed",
        }
    }

    #[cfg(windows)]
    const fn service() -> Self {
        Self {
            exit_code: 70,
            reason: "relay_agent_service_failed",
        }
    }
}

enum CliCommand {
    Validate {
        config: PathBuf,
    },
    Preflight {
        config: PathBuf,
        challenge: Option<[u8; 32]>,
    },
    DrainProof {
        config: PathBuf,
        challenge: [u8; 32],
    },
    Run {
        config: PathBuf,
    },
    ProvisionWindows {
        config: PathBuf,
        purpose: ProvisionPurpose,
    },
}

#[derive(Clone, Copy)]
enum ProvisionPurpose {
    Enrollment,
    Turn,
}

#[tokio::main]
async fn main() -> ExitCode {
    match async_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.reason);
            ExitCode::from(error.exit_code)
        }
    }
}

async fn async_main() -> Result<(), CliFailure> {
    match parse_cli(std::env::args_os().skip(1).collect())? {
        CliCommand::Validate { config } => {
            ProductionAgentConfig::load(&config).map_err(|_| CliFailure::config())?;
            Ok(())
        }
        CliCommand::Preflight { config, challenge } => {
            #[cfg(windows)]
            let config = load_windows_operational_config(&config)?;
            #[cfg(not(windows))]
            let config = ProductionAgentConfig::load(&config).map_err(|_| CliFailure::config())?;
            let challenge = challenge.map_or_else(generate_challenge, Ok)?;
            let runtime = build_platform_runtime(&config)?;
            let evidence = runtime
                .preflight(challenge)
                .await
                .map_err(|_| CliFailure::unavailable())?;
            let mut output = std::io::BufWriter::new(std::io::stdout().lock());
            serde_json::to_writer(&mut output, &evidence).map_err(|_| CliFailure::runtime())?;
            output.write_all(b"\n").map_err(|_| CliFailure::runtime())?;
            output.flush().map_err(|_| CliFailure::runtime())
        }
        CliCommand::DrainProof { config, challenge } => {
            #[cfg(windows)]
            let config = load_windows_operational_config(&config)?;
            #[cfg(not(windows))]
            let config = ProductionAgentConfig::load(&config).map_err(|_| CliFailure::config())?;
            let runtime = build_platform_runtime(&config)?;
            let evidence = runtime
                .drain_proof(challenge)
                .await
                .map_err(|_| CliFailure::unavailable())?;
            let mut output = std::io::BufWriter::new(std::io::stdout().lock());
            serde_json::to_writer(&mut output, &evidence).map_err(|_| CliFailure::runtime())?;
            output.write_all(b"\n").map_err(|_| CliFailure::runtime())?;
            output.flush().map_err(|_| CliFailure::runtime())
        }
        CliCommand::Run {
            config: config_path,
        } => {
            #[cfg(windows)]
            {
                run_windows_agent_service(config_path)
            }
            #[cfg(not(windows))]
            {
                let config =
                    ProductionAgentConfig::load(&config_path).map_err(|_| CliFailure::config())?;
                run_production_agent(config).await
            }
        }
        CliCommand::ProvisionWindows { config, purpose } => {
            #[cfg(windows)]
            {
                let config = load_windows_operational_config(&config)?;
                provision_windows(&config, purpose)
            }
            #[cfg(not(windows))]
            {
                drop((config, purpose));
                Err(CliFailure::unavailable())
            }
        }
    }
}

#[cfg(windows)]
static WINDOWS_AGENT_CONFIG_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

#[cfg(windows)]
windows_service::define_windows_service!(agent_ffi_service_main, agent_service_main);

#[cfg(windows)]
fn run_windows_agent_service(config_path: PathBuf) -> Result<(), CliFailure> {
    WINDOWS_AGENT_CONFIG_PATH
        .set(Mutex::new(Some(config_path)))
        .map_err(|_| CliFailure::service())?;
    windows_service::service_dispatcher::start(
        mrd_relay_agent::platform::windows::AGENT_SERVICE,
        agent_ffi_service_main,
    )
    .map_err(|_| CliFailure::service())
}

#[cfg(windows)]
fn agent_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = registered_agent_service_main() {
        eprintln!("{}", error.reason);
    }
}

#[cfg(windows)]
fn registered_agent_service_main() -> Result<(), CliFailure> {
    use mrd_relay_agent::platform::windows::{
        drive_windows_service_after_start_pending, WindowsServiceStatusUpdate,
    };
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(
        mrd_relay_agent::platform::windows::AGENT_SERVICE,
        handler,
    )
    .map_err(|_| CliFailure::service())?;
    let set_status = |state, controls, checkpoint, wait_hint, exit_code| {
        status
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: controls,
                exit_code,
                checkpoint,
                wait_hint,
                process_id: None,
            })
            .map_err(|_| CliFailure::service())
    };
    set_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        1,
        Duration::from_secs(30),
        ServiceExitCode::Win32(0),
    )?;
    drive_windows_service_after_start_pending(
        || {
            let config_path = WINDOWS_AGENT_CONFIG_PATH
                .get()
                .ok_or_else(CliFailure::service)?
                .lock()
                .map_err(|_| CliFailure::service())?
                .take()
                .ok_or_else(CliFailure::service)?;
            let config = load_windows_operational_config(&config_path)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|_| CliFailure::service())?;
            Ok((runtime, config))
        },
        |(runtime, config)| {
            runtime.block_on(async {
                tokio::select! {
                    result = run_production_agent(config) => result,
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            Ok(())
                        } else {
                            Err(CliFailure::service())
                        }
                    }
                }
            })
        },
        |update| match update {
            WindowsServiceStatusUpdate::Running => set_status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                0,
                Duration::ZERO,
                ServiceExitCode::Win32(0),
            ),
            WindowsServiceStatusUpdate::StopPending => set_status(
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                1,
                Duration::from_secs(30),
                ServiceExitCode::Win32(0),
            ),
            WindowsServiceStatusUpdate::StoppedSuccess => set_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::ZERO,
                ServiceExitCode::Win32(0),
            ),
            WindowsServiceStatusUpdate::StoppedFailure => set_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::ZERO,
                ServiceExitCode::ServiceSpecific(1),
            ),
        },
    )
}

#[cfg(windows)]
fn load_windows_operational_config(path: &Path) -> Result<ProductionAgentConfig, CliFailure> {
    use mrd_relay_agent::{
        config::WindowsDataLayout,
        platform::windows::{
            resolve_windows_agent_service_sid, validate_windows_agent_service_sid,
        },
        secure_store::WindowsTrustedStaticFile,
    };

    let resolved_sid = resolve_windows_agent_service_sid().map_err(|_| CliFailure::config())?;
    let layout = WindowsDataLayout::from_config_path(path).map_err(|_| CliFailure::config())?;
    let file = WindowsTrustedStaticFile::new_windows(
        layout.data_root().to_path_buf(),
        path.to_path_buf(),
        &resolved_sid,
    )
    .map_err(|_| CliFailure::config())?;
    let encoded = file.read(64 * 1024).map_err(|_| CliFailure::config())?;
    let verified = ProductionAgentConfig::from_slice_at_path(&encoded, path)
        .map_err(|_| CliFailure::config())?;
    validate_windows_agent_service_sid(
        verified
            .target_config()
            .agent_service_sid()
            .ok_or_else(CliFailure::config)?,
        &resolved_sid,
    )
    .map_err(|_| CliFailure::config())?;
    Ok(verified)
}

fn parse_cli(arguments: Vec<OsString>) -> Result<CliCommand, CliFailure> {
    let command = arguments
        .first()
        .and_then(|value| value.to_str())
        .ok_or_else(CliFailure::usage)?;
    if arguments.get(1).and_then(|value| value.to_str()) != Some("--config") {
        return Err(CliFailure::usage());
    }
    let config = arguments
        .get(2)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(CliFailure::usage)?;
    match (command, arguments.len()) {
        ("validate", 3) => Ok(CliCommand::Validate { config }),
        ("run", 3) => Ok(CliCommand::Run { config }),
        ("preflight", 3) => Ok(CliCommand::Preflight {
            config,
            challenge: None,
        }),
        ("preflight", 5)
            if arguments.get(3).and_then(|value| value.to_str()) == Some("--challenge") =>
        {
            let challenge = arguments
                .get(4)
                .and_then(|value| value.to_str())
                .ok_or_else(CliFailure::usage)
                .and_then(parse_challenge)?;
            Ok(CliCommand::Preflight {
                config,
                challenge: Some(challenge),
            })
        }
        ("drain-proof", 5)
            if arguments.get(3).and_then(|value| value.to_str()) == Some("--challenge") =>
        {
            let challenge = arguments
                .get(4)
                .and_then(|value| value.to_str())
                .ok_or_else(CliFailure::usage)
                .and_then(parse_challenge)?;
            Ok(CliCommand::DrainProof { config, challenge })
        }
        ("provision-windows", 5)
            if arguments.get(3).and_then(|value| value.to_str()) == Some("--purpose") =>
        {
            let purpose = match arguments.get(4).and_then(|value| value.to_str()) {
                Some("enrollment") => ProvisionPurpose::Enrollment,
                Some("turn") => ProvisionPurpose::Turn,
                _ => return Err(CliFailure::usage()),
            };
            Ok(CliCommand::ProvisionWindows { config, purpose })
        }
        _ => Err(CliFailure::usage()),
    }
}

fn parse_challenge(value: &str) -> Result<[u8; 32], CliFailure> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CliFailure::usage());
    }
    let mut challenge = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        challenge[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    if challenge.iter().all(|byte| *byte == 0) {
        return Err(CliFailure::usage());
    }
    Ok(challenge)
}

fn hex_nibble(value: u8) -> Result<u8, CliFailure> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CliFailure::usage()),
    }
}

fn generate_challenge() -> Result<[u8; 32], CliFailure> {
    let mut challenge = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| CliFailure::runtime())?;
    if challenge.iter().all(|byte| *byte == 0) {
        return Err(CliFailure::runtime());
    }
    Ok(challenge)
}

fn build_platform_runtime(
    config: &ProductionAgentConfig,
) -> Result<Arc<PlatformCoturnRuntime>, CliFailure> {
    let broker: Arc<dyn BrokerControlPort> = match config.target_config() {
        ProductionTargetConfig::LinuxSystemd => Arc::new(LinuxBrokerClient),
        target => {
            let (executable, sha256) = target.broker_identity().ok_or_else(CliFailure::config)?;
            Arc::new(
                WindowsBrokerClient::new(executable.to_path_buf(), sha256)
                    .map_err(|_| CliFailure::config())?,
            )
        }
    };
    PlatformCoturnRuntime::new(
        config.target(),
        broker,
        config.platform_expectation().clone(),
    )
    .map(Arc::new)
    .map_err(|_| CliFailure::config())
}

async fn run_production_agent(config: ProductionAgentConfig) -> Result<(), CliFailure> {
    let runtime = build_platform_runtime(&config)?;
    #[cfg(windows)]
    {
        run_windows(config, runtime).await
    }
    #[cfg(target_os = "linux")]
    {
        run_linux(config, runtime).await
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        drop((config, runtime));
        Err(CliFailure::unavailable())
    }
}

#[cfg(target_os = "linux")]
async fn run_linux(
    config: ProductionAgentConfig,
    runtime: Arc<PlatformCoturnRuntime>,
) -> Result<(), CliFailure> {
    if config.target() != mrd_relay_agent::platform::CoturnTarget::LinuxSystemd {
        return Err(CliFailure::config());
    }
    let protector = Arc::new(LinuxPlaintextProtector::new());
    let trusted_ca = read_linux_integrity_file(&config.agent().trusted_ca_path, 64 * 1024)
        .map_err(|_| CliFailure::runtime())?;
    let identity_file = Arc::new(linux_hardened_file(&config.agent().identity_path)?);
    let runtime_file = Arc::new(linux_hardened_file(&config.agent().runtime_state_path)?);
    let identity = Arc::new(
        SecureIdentityStore::new(identity_file, protector.clone(), &config.agent().node_id)
            .map_err(|_| CliFailure::runtime())?,
    );
    let state_store: Arc<dyn RuntimeStateStorePort> = Arc::new(
        SecureRuntimeStateStore::new(runtime_file, protector, &config.agent().node_id)
            .map_err(|_| CliFailure::runtime())?,
    );
    let enrollment =
        StrictCredentialFile::new_linux(config.enrollment_token_path().to_path_buf(), 512)
            .map_err(|_| CliFailure::runtime())?;
    let turn_secret =
        StrictCredentialFile::new_linux(config.turn_rest_secret_path().to_path_buf(), 43)
            .map_err(|_| CliFailure::runtime())?;
    run_with_stores(
        config,
        runtime,
        trusted_ca,
        identity,
        state_store,
        move || {
            Ok((
                validate_loaded_secret(
                    enrollment
                        .read_secret()
                        .map_err(|_| CliFailure::runtime())?,
                    512,
                    false,
                )?,
                validate_loaded_secret(
                    turn_secret
                        .read_secret()
                        .map_err(|_| CliFailure::runtime())?,
                    43,
                    true,
                )?,
            ))
        },
    )
    .await
}

#[cfg(target_os = "linux")]
fn linux_hardened_file(path: &Path) -> Result<HardenedAtomicFile, CliFailure> {
    let parent = path.parent().ok_or_else(CliFailure::config)?;
    HardenedAtomicFile::new_linux(parent.to_path_buf(), path.to_path_buf())
        .map_err(|_| CliFailure::runtime())
}

#[cfg(windows)]
async fn run_windows(
    config: ProductionAgentConfig,
    runtime: Arc<PlatformCoturnRuntime>,
) -> Result<(), CliFailure> {
    use mrd_relay_agent::secure_store::{
        BoundSecretStore, DpapiMachineProtector, SecretStorePurpose, SecureIdentityStore,
        SecureRuntimeStateStore,
    };

    if config.target() == mrd_relay_agent::platform::CoturnTarget::LinuxSystemd {
        return Err(CliFailure::config());
    }
    let service_sid = config
        .target_config()
        .agent_service_sid()
        .ok_or_else(CliFailure::config)?
        .to_owned();
    let protector = Arc::new(DpapiMachineProtector::new());
    let data_root = config.windows_data_root().ok_or_else(CliFailure::config)?;
    let trusted_ca = mrd_relay_agent::secure_store::WindowsTrustedStaticFile::new_windows(
        data_root.to_path_buf(),
        config.agent().trusted_ca_path.clone(),
        &service_sid,
    )
    .map_err(|_| CliFailure::runtime())?
    .read(64 * 1024)
    .map_err(|_| CliFailure::runtime())?;
    let identity_file = Arc::new(windows_hardened_file(
        &config.agent().identity_path,
        &service_sid,
    )?);
    let runtime_file = Arc::new(windows_hardened_file(
        &config.agent().runtime_state_path,
        &service_sid,
    )?);
    let enrollment_file = Arc::new(windows_hardened_file(
        config.enrollment_token_path(),
        &service_sid,
    )?);
    let secret_file = Arc::new(windows_hardened_file(
        config.turn_rest_secret_path(),
        &service_sid,
    )?);
    let identity = Arc::new(
        SecureIdentityStore::new(identity_file, protector.clone(), &config.agent().node_id)
            .map_err(|_| CliFailure::runtime())?,
    );
    let state_store: Arc<dyn RuntimeStateStorePort> = Arc::new(
        SecureRuntimeStateStore::new(runtime_file, protector.clone(), &config.agent().node_id)
            .map_err(|_| CliFailure::runtime())?,
    );
    let enrollment_store = BoundSecretStore::new(
        enrollment_file,
        protector.clone(),
        &config.agent().node_id,
        SecretStorePurpose::BootstrapEnrollmentToken,
    )
    .map_err(|_| CliFailure::runtime())?;
    let secret_store = BoundSecretStore::new(
        secret_file,
        protector,
        &config.agent().node_id,
        SecretStorePurpose::TurnRestSecret,
    )
    .map_err(|_| CliFailure::runtime())?;
    run_with_stores(
        config,
        runtime,
        trusted_ca,
        identity,
        state_store,
        move || {
            let enrollment = enrollment_store
                .load()
                .map_err(|_| CliFailure::runtime())?
                .ok_or_else(CliFailure::runtime)?;
            let secret = secret_store
                .load()
                .map_err(|_| CliFailure::runtime())?
                .ok_or_else(CliFailure::runtime)?;
            Ok((
                validate_loaded_secret(enrollment, 512, false)?,
                validate_loaded_secret(secret, 43, true)?,
            ))
        },
    )
    .await
}

#[cfg(windows)]
fn windows_hardened_file(
    path: &Path,
    service_sid: &str,
) -> Result<mrd_relay_agent::secure_store::HardenedAtomicFile, CliFailure> {
    let parent = path.parent().ok_or_else(CliFailure::config)?;
    mrd_relay_agent::secure_store::HardenedAtomicFile::new_windows(
        parent.to_path_buf(),
        path.to_path_buf(),
        service_sid,
    )
    .map_err(|_| CliFailure::runtime())
}

#[cfg(windows)]
fn provision_windows(
    config: &ProductionAgentConfig,
    purpose: ProvisionPurpose,
) -> Result<(), CliFailure> {
    use mrd_relay_agent::secure_store::{
        BoundSecretStore, DpapiMachineProtector, SecretStorePurpose,
    };

    if config.target() == mrd_relay_agent::platform::CoturnTarget::LinuxSystemd {
        return Err(CliFailure::config());
    }
    let service_sid = config
        .target_config()
        .agent_service_sid()
        .ok_or_else(CliFailure::config)?;
    let (path, store_purpose, max_bytes, turn_secret, purpose_name) = match purpose {
        ProvisionPurpose::Enrollment => (
            config.enrollment_token_path(),
            SecretStorePurpose::BootstrapEnrollmentToken,
            512,
            false,
            "enrollment",
        ),
        ProvisionPurpose::Turn => (
            config.turn_rest_secret_path(),
            SecretStorePurpose::TurnRestSecret,
            43,
            true,
            "turn",
        ),
    };
    let plaintext = read_stdin_secret(max_bytes, turn_secret)?;
    let file = Arc::new(windows_hardened_file(path, service_sid)?);
    let store = BoundSecretStore::new(
        file,
        Arc::new(DpapiMachineProtector::new()),
        &config.agent().node_id,
        store_purpose,
    )
    .map_err(|_| CliFailure::runtime())?;
    store
        .atomic_replace(&plaintext)
        .map_err(|_| CliFailure::runtime())?;
    let loaded = store
        .load()
        .map_err(|_| CliFailure::runtime())?
        .ok_or_else(CliFailure::runtime)?;
    let verification_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &plaintext);
    let loaded_tag = ring::hmac::sign(&verification_key, &loaded);
    ring::hmac::verify(&verification_key, &plaintext, loaded_tag.as_ref())
        .map_err(|_| CliFailure::runtime())?;
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    writeln!(
        output,
        "{{\"schema_version\":1,\"status\":\"provisioned\",\"purpose\":\"{purpose_name}\"}}"
    )
    .map_err(|_| CliFailure::runtime())?;
    output.flush().map_err(|_| CliFailure::runtime())
}

#[cfg(windows)]
fn read_stdin_secret(
    max_bytes: usize,
    turn_secret: bool,
) -> Result<Zeroizing<Vec<u8>>, CliFailure> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(max_bytes));
    std::io::stdin()
        .lock()
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CliFailure::runtime())?;
    if bytes.len() > max_bytes {
        return Err(CliFailure::runtime());
    }
    let _ = validate_loaded_secret(bytes.clone(), max_bytes, turn_secret)?;
    Ok(bytes)
}

async fn run_with_stores<F, L>(
    config: ProductionAgentConfig,
    runtime: Arc<PlatformCoturnRuntime>,
    trusted_ca: Zeroizing<Vec<u8>>,
    identity_fs: Arc<F>,
    state_store: Arc<dyn RuntimeStateStorePort>,
    load_bootstrap: L,
) -> Result<(), CliFailure>
where
    F: IdentityFsPort,
    L: FnOnce() -> Result<(SecretString, SecretString), CliFailure>,
{
    let trusted_ca_text = std::str::from_utf8(&trusted_ca).map_err(|_| CliFailure::config())?;
    let clock = Arc::new(SystemClock::new());
    let identity = CertificateState::new(
        identity_fs,
        &config.agent().node_id,
        trusted_ca_text,
        clock.clone(),
    )
    .map_err(|_| CliFailure::runtime())?;
    let enrollment = if identity.active_certificate().is_none() {
        let (token, turn_rest_secret) = load_bootstrap()?;
        Some(EnrollmentRequest {
            token,
            node_id: config.agent().node_id.clone(),
            region: config.agent().region.clone(),
            failure_domain: config.agent().failure_domain.clone(),
            endpoints: config.agent().endpoints.clone(),
            max_allocations: config.agent().max_allocations,
            max_egress_bps: config.agent().max_egress_bps,
            csr_pem: String::new(),
            turn_rest_secret,
        })
    } else {
        None
    };
    let enrollment_backend: Arc<dyn RelayBackendPort> = Arc::new(
        ReqwestRelayBackend::new(config.agent().backend_url.clone(), &trusted_ca)
            .map_err(|_| CliFailure::runtime())?,
    );
    let factory: Arc<dyn RelayBackendClientFactoryPort> = Arc::new(
        ReqwestRelayBackendFactory::new(config.agent().backend_url.clone(), &trusted_ca)
            .map_err(|_| CliFailure::runtime())?,
    );
    let native_scrape = ReqwestNativeCoturnScrape::new(
        config.agent().metrics_url.clone(),
        MetricsLimits::default(),
    )
    .map_err(|_| CliFailure::config())?;
    let metrics = Arc::new(PlatformMetrics::new(native_scrape, runtime.clone()));
    let dependencies = PortableRelayAgentDeps {
        identity,
        enrollment_backend: enrollment_backend.clone(),
        initial_backend: enrollment_backend,
        factory,
        coturn: runtime.clone(),
        clock,
        sleeper: Arc::new(TokioSleeper),
        jitter: Arc::new(RandomJitter),
        state_store,
        metrics,
        probe: runtime,
    };
    let agent_config = PortableRelayAgentConfig {
        enrollment,
        endpoints: config.agent().endpoints.clone(),
        max_allocations: config.agent().max_allocations,
        max_egress_bps: config.agent().max_egress_bps,
        pressure: HostPressureSnapshot::default(),
        renewal_window: CERTIFICATE_LIFETIME_RENEWAL_WINDOW_CAP,
        backend_backoff_cap: config.agent().backend_backoff_cap,
    };
    run_agent(dependencies, agent_config)
        .await
        .map_err(map_runtime_error)
}

fn map_runtime_error(_error: RuntimeError) -> CliFailure {
    CliFailure::runtime()
}

fn validate_loaded_secret(
    bytes: Zeroizing<Vec<u8>>,
    max_bytes: usize,
    turn_secret: bool,
) -> Result<SecretString, CliFailure> {
    let value = std::str::from_utf8(&bytes).map_err(|_| CliFailure::runtime())?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty()
        || value.len() > max_bytes
        || !value.is_ascii()
        || (!turn_secret && value.len() < 40)
        || (turn_secret && !canonical_turn_secret(value))
    {
        return Err(CliFailure::runtime());
    }
    Ok(SecretString::from(value.to_owned()))
}

fn canonical_turn_secret(value: &str) -> bool {
    if value.len() != 43 {
        return false;
    }
    let decoded = match URL_SAFE_NO_PAD.decode(value) {
        Ok(decoded) => Zeroizing::new(decoded),
        Err(_) => return false,
    };
    decoded.len() == 32 && URL_SAFE_NO_PAD.encode(decoded.as_slice()) == value
}
