use std::{
    fs,
    path::{Component, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::platform::{linux, windows, CoturnTarget, PlatformExpectation, TransportCapability};

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_ENDPOINTS: usize = 4;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const LINUX_ENROLLMENT_CREDENTIAL_PATH: &str =
    "/run/credentials/mrd-relay-agent.service/enrollment-token";
const LINUX_TURN_CREDENTIAL_PATH: &str =
    "/run/credentials/mrd-relay-agent.service/turn-rest-secret";
const WINDOWS_MANAGED_LABEL: &str = "io.mrd.relay.managed=true";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("relay_agent_config_invalid")]
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsDataLayout {
    drive: u8,
    root_components: Vec<String>,
    data_root: PathBuf,
}

impl WindowsDataLayout {
    pub fn from_config_path(path: &std::path::Path) -> Result<Self, ConfigError> {
        Self::from_static_path(path, "agent.json")
    }

    fn from_trusted_ca_path(path: &std::path::Path) -> Result<Self, ConfigError> {
        Self::from_static_path(path, "trusted-ca.pem")
    }

    fn from_static_path(path: &std::path::Path, expected_leaf: &str) -> Result<Self, ConfigError> {
        let (drive, components) = windows_path_components(path).ok_or(ConfigError::Invalid)?;
        if components.len() < 3
            || !windows_component_eq(&components[components.len() - 2], "config")
            || !windows_component_eq(&components[components.len() - 1], expected_leaf)
        {
            return Err(ConfigError::Invalid);
        }
        let root_components = components[..components.len() - 2].to_vec();
        if root_components.is_empty() {
            return Err(ConfigError::Invalid);
        }
        let data_root = windows_path_from_components(drive, &root_components);
        Ok(Self {
            drive,
            root_components,
            data_root,
        })
    }

    pub fn data_root(&self) -> &std::path::Path {
        &self.data_root
    }

    fn same_root(&self, other: &Self) -> bool {
        self.drive.eq_ignore_ascii_case(&other.drive)
            && self.root_components.len() == other.root_components.len()
            && self
                .root_components
                .iter()
                .zip(&other.root_components)
                .all(|(left, right)| windows_component_eq(left, right))
    }

    pub fn matches_relative(&self, path: &std::path::Path, relative: &[&str]) -> bool {
        if relative.is_empty()
            || relative
                .iter()
                .any(|component| !valid_windows_component(component))
        {
            return false;
        }
        let Some((drive, components)) = windows_path_components(path) else {
            return false;
        };
        drive.eq_ignore_ascii_case(&self.drive)
            && components.len() == self.root_components.len() + relative.len()
            && components[..self.root_components.len()]
                .iter()
                .zip(&self.root_components)
                .all(|(actual, expected)| windows_component_eq(actual, expected))
            && components[self.root_components.len()..]
                .iter()
                .zip(relative)
                .all(|(actual, expected)| windows_component_eq(actual, expected))
    }
}

fn windows_path_components(path: &std::path::Path) -> Option<(u8, Vec<String>)> {
    let value = path.to_str()?;
    let bytes = value.as_bytes();
    if value.is_empty()
        || value.encode_utf16().count() > 32 * 1024
        || value.starts_with("\\\\")
        || bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
        || value[2..].contains(':')
        || value.contains('\0')
    {
        return None;
    }
    let components: Vec<String> = value[3..].split(['\\', '/']).map(str::to_owned).collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !valid_windows_component(component))
    {
        return None;
    }
    Some((bytes[0].to_ascii_uppercase(), components))
}

fn windows_path_from_components(drive: u8, components: &[String]) -> PathBuf {
    let mut value = String::with_capacity(
        3 + components
            .iter()
            .map(|component| component.len() + 1)
            .sum::<usize>(),
    );
    value.push(char::from(drive.to_ascii_uppercase()));
    value.push(':');
    value.push('\\');
    value.push_str(&components.join("\\"));
    PathBuf::from(value)
}

#[cfg(windows)]
fn windows_component_eq(left: &str, right: &str) -> bool {
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    let left: Vec<u16> = left.encode_utf16().collect();
    let right: Vec<u16> = right.encode_utf16().collect();
    let Ok(left_len) = i32::try_from(left.len()) else {
        return false;
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return false;
    };
    // SAFETY: both pointers remain live for the call and the explicit lengths
    // bound the non-NUL-terminated UTF-16 slices. CompareStringOrdinal is the
    // filesystem-compatible, locale-independent Windows ordinal comparison.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

#[cfg(not(windows))]
fn windows_component_eq(left: &str, right: &str) -> bool {
    left == right || (left.is_ascii() && right.is_ascii() && left.eq_ignore_ascii_case(right))
}

fn valid_windows_component(value: &str) -> bool {
    if value.is_empty()
        || value.encode_utf16().count() > 255
        || value.ends_with(['.', ' '])
        || value.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
        })
        || value.contains(':')
        || matches!(value, "." | "..")
    {
        return false;
    }
    let basename = value
        .split_once('.')
        .map_or(value, |(basename, _)| basename)
        .to_ascii_uppercase();
    !matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        && !matches!(
            basename.strip_prefix("COM"),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        )
        && !matches!(
            basename.strip_prefix("LPT"),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        )
}

pub struct AgentConfig {
    pub backend_url: Url,
    pub node_id: String,
    pub region: String,
    pub failure_domain: String,
    pub endpoints: Vec<String>,
    pub max_allocations: u32,
    pub max_egress_bps: u64,
    pub identity_path: PathBuf,
    pub runtime_state_path: PathBuf,
    pub trusted_ca_path: PathBuf,
    pub metrics_url: Url,
    pub enrollment_token: Option<SecretString>,
    pub turn_rest_secret: Option<SecretString>,
    pub heartbeat_interval: Duration,
    pub backend_backoff_cap: Duration,
}

pub struct ProductionAgentConfig {
    agent: AgentConfig,
    target_config: ProductionTargetConfig,
    platform_expectation: PlatformExpectation,
    relay_min_port: u16,
    relay_max_port: u16,
    tls_listener_port: Option<u16>,
    enrollment_token_path: PathBuf,
    turn_rest_secret_path: PathBuf,
    windows_data_layout: Option<WindowsDataLayout>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProductionTargetConfig {
    LinuxSystemd,
    WindowsService {
        agent_service_sid: String,
        broker_executable: PathBuf,
        broker_sha256: [u8; 32],
        native_wrapper: PathBuf,
        native_wrapper_sha256: [u8; 32],
        native_wrapper_signer: String,
    },
    Docker {
        agent_service_sid: String,
        broker_executable: PathBuf,
        broker_sha256: [u8; 32],
        docker_executable: PathBuf,
        canonical_image: String,
        expected_container_id_state_path: PathBuf,
    },
    Wsl2 {
        agent_service_sid: String,
        broker_executable: PathBuf,
        broker_sha256: [u8; 32],
        wsl_executable: PathBuf,
    },
}

impl ProductionTargetConfig {
    pub const fn target(&self) -> CoturnTarget {
        match self {
            Self::LinuxSystemd => CoturnTarget::LinuxSystemd,
            Self::WindowsService { .. } => CoturnTarget::WindowsService,
            Self::Docker { .. } => CoturnTarget::Docker,
            Self::Wsl2 { .. } => CoturnTarget::Wsl2,
        }
    }

    pub fn broker_identity(&self) -> Option<(&std::path::Path, [u8; 32])> {
        match self {
            Self::LinuxSystemd => None,
            Self::WindowsService {
                broker_executable,
                broker_sha256,
                ..
            }
            | Self::Docker {
                broker_executable,
                broker_sha256,
                ..
            }
            | Self::Wsl2 {
                broker_executable,
                broker_sha256,
                ..
            } => Some((broker_executable, *broker_sha256)),
        }
    }

    pub fn agent_service_sid(&self) -> Option<&str> {
        match self {
            Self::LinuxSystemd => None,
            Self::WindowsService {
                agent_service_sid, ..
            }
            | Self::Docker {
                agent_service_sid, ..
            }
            | Self::Wsl2 {
                agent_service_sid, ..
            } => Some(agent_service_sid),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigWire {
    backend_url: String,
    node_id: String,
    region: String,
    failure_domain: String,
    endpoints: Vec<String>,
    max_allocations: u32,
    max_egress_bps: u64,
    identity_path: PathBuf,
    runtime_state_path: PathBuf,
    trusted_ca_path: PathBuf,
    metrics_url: String,
    enrollment_token: Option<String>,
    turn_rest_secret: Option<String>,
    heartbeat_interval_seconds: u64,
    backend_backoff_cap_seconds: u64,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ProductionTargetKind {
    LinuxSystemd,
    WindowsService,
    Docker,
    Wsl2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionAgentConfigWire {
    backend_url: String,
    node_id: String,
    region: String,
    failure_domain: String,
    endpoints: Vec<String>,
    max_allocations: u32,
    max_egress_bps: u64,
    identity_path: PathBuf,
    runtime_state_path: PathBuf,
    trusted_ca_path: PathBuf,
    metrics_url: String,
    heartbeat_interval_seconds: u64,
    backend_backoff_cap_seconds: u64,
    target: ProductionTargetKind,
    relay_min_port: u16,
    relay_max_port: u16,
    transport_capabilities: Vec<TransportCapability>,
    tls_listener_port: Option<u16>,
    enrollment_token_path: PathBuf,
    turn_rest_secret_path: PathBuf,
    target_config: Option<ProductionTargetDetailsWire>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ProductionTargetDetailsWire {
    WindowsService {
        agent_service_sid: String,
        broker_executable: PathBuf,
        broker_sha256: String,
        native_wrapper: PathBuf,
        native_wrapper_sha256: String,
        native_wrapper_signer: String,
    },
    Docker {
        agent_service_sid: String,
        broker_executable: PathBuf,
        broker_sha256: String,
        docker_executable: PathBuf,
        canonical_image: String,
        expected_container_id_state_path: PathBuf,
        managed_label: String,
        container_read_only: bool,
        restart_policy: String,
        relay_udp_range_published: bool,
        published_ports: Vec<DockerPublishedPortWire>,
        read_only_mounts: Vec<DockerMountWire>,
    },
    Wsl2 {
        agent_service_sid: String,
        broker_executable: PathBuf,
        broker_sha256: String,
        wsl_executable: PathBuf,
        distro: String,
        system_owned: bool,
        mirrored_networking: bool,
    },
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DockerProtocol {
    Tcp,
    Udp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DockerPublishedPortWire {
    host_port: u16,
    container_port: u16,
    protocol: DockerProtocol,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DockerMountWire {
    source: PathBuf,
    destination: String,
    read_only: bool,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentConfig")
            .field("backend_url", &self.backend_url)
            .field("node_id", &self.node_id)
            .field("region", &self.region)
            .field("failure_domain", &self.failure_domain)
            .field("endpoint_count", &self.endpoints.len())
            .field("max_allocations", &self.max_allocations)
            .field("max_egress_bps", &self.max_egress_bps)
            .field("identity_path", &self.identity_path)
            .field("runtime_state_path", &self.runtime_state_path)
            .field("trusted_ca_path", &self.trusted_ca_path)
            .field("metrics_url", &self.metrics_url)
            .field("enrollment_token", &"REDACTED")
            .field("turn_rest_secret", &"REDACTED")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("backend_backoff_cap", &self.backend_backoff_cap)
            .finish()
    }
}

impl std::fmt::Debug for ProductionAgentConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionAgentConfig")
            .field("agent", &self.agent)
            .field("target", &self.target())
            .field("relay_min_port", &self.relay_min_port)
            .field("relay_max_port", &self.relay_max_port)
            .field("tls_listener_port", &self.tls_listener_port)
            .field("enrollment_token_path", &self.enrollment_token_path)
            .field("turn_rest_secret_path", &self.turn_rest_secret_path)
            .finish_non_exhaustive()
    }
}

impl ProductionAgentConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        if !safe_absolute_file(path) {
            return Err(ConfigError::Invalid);
        }
        #[cfg(target_os = "linux")]
        let encoded =
            crate::secure_store::read_linux_integrity_file(path, MAX_CONFIG_BYTES as usize)
                .map_err(|_| ConfigError::Invalid)?;
        #[cfg(not(target_os = "linux"))]
        let encoded = {
            let metadata = fs::symlink_metadata(path).map_err(|_| ConfigError::Invalid)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() == 0
                || metadata.len() > MAX_CONFIG_BYTES
            {
                return Err(ConfigError::Invalid);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
                if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
                    return Err(ConfigError::Invalid);
                }
            }
            Zeroizing::new(fs::read(path).map_err(|_| ConfigError::Invalid)?)
        };
        let config = Self::from_slice_at_path(encoded.as_slice(), path)?;
        if [
            &config.agent.identity_path,
            &config.agent.runtime_state_path,
            &config.agent.trusted_ca_path,
            &config.enrollment_token_path,
            &config.turn_rest_secret_path,
        ]
        .contains(&&path.to_path_buf())
        {
            return Err(ConfigError::Invalid);
        }
        Ok(config)
    }

    pub fn from_slice(encoded: &[u8]) -> Result<Self, ConfigError> {
        Self::from_slice_with_path(encoded, None)
    }

    pub fn from_slice_at_path(
        encoded: &[u8],
        config_path: &std::path::Path,
    ) -> Result<Self, ConfigError> {
        Self::from_slice_with_path(encoded, Some(config_path))
    }

    fn from_slice_with_path(
        encoded: &[u8],
        config_path: Option<&std::path::Path>,
    ) -> Result<Self, ConfigError> {
        if encoded.is_empty() || encoded.len() > MAX_CONFIG_BYTES as usize {
            return Err(ConfigError::Invalid);
        }
        let wire: ProductionAgentConfigWire =
            serde_json::from_slice(encoded).map_err(|_| ConfigError::Invalid)?;
        let windows_data_layout = match wire.target {
            ProductionTargetKind::LinuxSystemd => None,
            ProductionTargetKind::WindowsService
            | ProductionTargetKind::Docker
            | ProductionTargetKind::Wsl2 => {
                let trusted_ca_layout =
                    WindowsDataLayout::from_trusted_ca_path(&wire.trusted_ca_path)?;
                if let Some(config_path) = config_path {
                    let config_layout = WindowsDataLayout::from_config_path(config_path)?;
                    if !trusted_ca_layout.same_root(&config_layout) {
                        return Err(ConfigError::Invalid);
                    }
                }
                Some(trusted_ca_layout)
            }
        };
        let target_config = validate_target_details(
            wire.target,
            wire.target_config,
            &wire.endpoints,
            wire.relay_min_port,
            wire.relay_max_port,
            windows_data_layout.as_ref(),
        )?;
        let target = target_config.target();
        let platform_expectation = PlatformExpectation::new(
            wire.max_allocations,
            wire.max_egress_bps,
            wire.relay_min_port,
            wire.relay_max_port,
            wire.transport_capabilities,
            wire.endpoints.clone(),
        )
        .map_err(|_| ConfigError::Invalid)?;
        validate_tls_listener(
            &wire.endpoints,
            platform_expectation.transport_capabilities(),
            wire.tls_listener_port,
        )?;

        let agent = AgentConfig {
            backend_url: wire.backend_url.parse().map_err(|_| ConfigError::Invalid)?,
            node_id: wire.node_id,
            region: wire.region,
            failure_domain: wire.failure_domain,
            endpoints: wire.endpoints,
            max_allocations: wire.max_allocations,
            max_egress_bps: wire.max_egress_bps,
            identity_path: wire.identity_path,
            runtime_state_path: wire.runtime_state_path,
            trusted_ca_path: wire.trusted_ca_path,
            metrics_url: wire.metrics_url.parse().map_err(|_| ConfigError::Invalid)?,
            enrollment_token: None,
            turn_rest_secret: None,
            heartbeat_interval: Duration::from_secs(wire.heartbeat_interval_seconds),
            backend_backoff_cap: Duration::from_secs(wire.backend_backoff_cap_seconds),
        };
        agent.validate()?;
        if !paths_match_target(
            target,
            &agent,
            &wire.enrollment_token_path,
            &wire.turn_rest_secret_path,
            windows_data_layout.as_ref(),
        ) {
            return Err(ConfigError::Invalid);
        }
        let mut distinct_paths = std::collections::BTreeSet::new();
        if [
            &agent.identity_path,
            &agent.runtime_state_path,
            &agent.trusted_ca_path,
            &wire.enrollment_token_path,
            &wire.turn_rest_secret_path,
        ]
        .into_iter()
        .any(|path| !distinct_paths.insert(path.as_os_str().to_string_lossy().to_string()))
        {
            return Err(ConfigError::Invalid);
        }
        Ok(Self {
            agent,
            target_config,
            platform_expectation,
            relay_min_port: wire.relay_min_port,
            relay_max_port: wire.relay_max_port,
            tls_listener_port: wire.tls_listener_port,
            enrollment_token_path: wire.enrollment_token_path,
            turn_rest_secret_path: wire.turn_rest_secret_path,
            windows_data_layout,
        })
    }

    pub fn agent(&self) -> &AgentConfig {
        &self.agent
    }

    pub const fn target(&self) -> CoturnTarget {
        self.target_config.target()
    }

    pub fn target_config(&self) -> &ProductionTargetConfig {
        &self.target_config
    }

    pub fn platform_expectation(&self) -> &PlatformExpectation {
        &self.platform_expectation
    }

    pub fn enrollment_token_path(&self) -> &std::path::Path {
        &self.enrollment_token_path
    }

    pub fn turn_rest_secret_path(&self) -> &std::path::Path {
        &self.turn_rest_secret_path
    }

    pub const fn tls_listener_port(&self) -> Option<u16> {
        self.tls_listener_port
    }

    pub fn windows_data_root(&self) -> Option<&std::path::Path> {
        self.windows_data_layout
            .as_ref()
            .map(WindowsDataLayout::data_root)
    }
}

impl AgentConfig {
    /// Loads the portable agent configuration without reading credentials from
    /// command-line arguments or environment variables.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        if !safe_absolute_file(path) {
            return Err(ConfigError::Invalid);
        }
        let metadata = fs::metadata(path).map_err(|_| ConfigError::Invalid)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConfigError::Invalid);
            }
        }
        let encoded = Zeroizing::new(fs::read(path).map_err(|_| ConfigError::Invalid)?);
        let wire: AgentConfigWire =
            serde_json::from_slice(encoded.as_slice()).map_err(|_| ConfigError::Invalid)?;
        let config = Self {
            backend_url: wire.backend_url.parse().map_err(|_| ConfigError::Invalid)?,
            node_id: wire.node_id,
            region: wire.region,
            failure_domain: wire.failure_domain,
            endpoints: wire.endpoints,
            max_allocations: wire.max_allocations,
            max_egress_bps: wire.max_egress_bps,
            identity_path: wire.identity_path,
            runtime_state_path: wire.runtime_state_path,
            trusted_ca_path: wire.trusted_ca_path,
            metrics_url: wire.metrics_url.parse().map_err(|_| ConfigError::Invalid)?,
            enrollment_token: wire.enrollment_token.map(SecretString::from),
            turn_rest_secret: wire.turn_rest_secret.map(SecretString::from),
            heartbeat_interval: Duration::from_secs(wire.heartbeat_interval_seconds),
            backend_backoff_cap: Duration::from_secs(wire.backend_backoff_cap_seconds),
        };
        config.validate()?;
        if path == config.identity_path
            || path == config.runtime_state_path
            || path == config.trusted_ca_path
        {
            return Err(ConfigError::Invalid);
        }
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.backend_url.scheme() != "https"
            || self.backend_url.cannot_be_a_base()
            || !self.backend_url.username().is_empty()
            || self.backend_url.password().is_some()
            || self.backend_url.query().is_some()
            || self.backend_url.fragment().is_some()
            || !credential_safe_relay_id(&self.node_id)
            || !region_id(&self.region)
            || !relay_id(&self.failure_domain)
            || self.endpoints.is_empty()
            || self.endpoints.len() > MAX_ENDPOINTS
            || self
                .endpoints
                .iter()
                .any(|endpoint| !is_public_turn_endpoint(endpoint))
            || self.max_allocations == 0
            || self.max_egress_bps == 0
            || !safe_absolute_file(&self.identity_path)
            || !safe_absolute_file(&self.runtime_state_path)
            || !safe_absolute_file(&self.trusted_ca_path)
            || self.identity_path == self.runtime_state_path
            || self.identity_path == self.trusted_ca_path
            || self.runtime_state_path == self.trusted_ca_path
            || !loopback_metrics_url(&self.metrics_url)
            || self.heartbeat_interval != Duration::from_secs(5)
            || !(Duration::from_secs(1)..=Duration::from_secs(30))
                .contains(&self.backend_backoff_cap)
            || self.enrollment_token.as_ref().is_some_and(|token| {
                let token = token.expose_secret();
                !(40..=512).contains(&token.len()) || !token.is_ascii()
            })
            || self
                .turn_rest_secret
                .as_ref()
                .is_some_and(|secret| !valid_turn_secret(secret.expose_secret()))
        {
            return Err(ConfigError::Invalid);
        }
        Ok(())
    }
}

fn validate_target_details(
    target: ProductionTargetKind,
    details: Option<ProductionTargetDetailsWire>,
    endpoints: &[String],
    relay_min_port: u16,
    relay_max_port: u16,
    windows_data_layout: Option<&WindowsDataLayout>,
) -> Result<ProductionTargetConfig, ConfigError> {
    match (target, details) {
        (ProductionTargetKind::LinuxSystemd, None) => Ok(ProductionTargetConfig::LinuxSystemd),
        (
            ProductionTargetKind::WindowsService,
            Some(ProductionTargetDetailsWire::WindowsService {
                agent_service_sid,
                broker_executable,
                broker_sha256,
                native_wrapper,
                native_wrapper_sha256,
                native_wrapper_signer,
            }),
        ) => {
            let broker_sha256 = decode_lower_hex_32(&broker_sha256)?;
            let native_wrapper_sha256 = decode_lower_hex_32(&native_wrapper_sha256)?;
            if !windows_local_file(&broker_executable)
                || !windows_local_file(&native_wrapper)
                || broker_executable == native_wrapper
                || !valid_service_sid(&agent_service_sid)
                || !valid_signer(&native_wrapper_signer)
            {
                return Err(ConfigError::Invalid);
            }
            windows::WindowsBrokerClient::new(broker_executable.clone(), broker_sha256)
                .map_err(|_| ConfigError::Invalid)?;
            Ok(ProductionTargetConfig::WindowsService {
                agent_service_sid,
                broker_executable,
                broker_sha256,
                native_wrapper,
                native_wrapper_sha256,
                native_wrapper_signer,
            })
        }
        (
            ProductionTargetKind::Docker,
            Some(ProductionTargetDetailsWire::Docker {
                agent_service_sid,
                broker_executable,
                broker_sha256,
                docker_executable,
                canonical_image,
                expected_container_id_state_path,
                managed_label,
                container_read_only,
                restart_policy,
                relay_udp_range_published,
                published_ports,
                read_only_mounts,
            }),
        ) => {
            let broker_sha256 = decode_lower_hex_32(&broker_sha256)?;
            if !windows_local_file(&broker_executable)
                || !windows_local_file(&docker_executable)
                || !valid_service_sid(&agent_service_sid)
                || !canonical_docker_image(&canonical_image)
                || !windows_data_layout.is_some_and(|layout| {
                    layout.matches_relative(
                        &expected_container_id_state_path,
                        &["broker", "docker-identity.json"],
                    )
                })
                || managed_label != WINDOWS_MANAGED_LABEL
                || !container_read_only
                || restart_policy != "no"
                || !relay_udp_range_published
                || relay_min_port > relay_max_port
                || !docker_ports_cover_endpoints(&published_ports, endpoints)
                || !windows_data_layout
                    .is_some_and(|layout| valid_docker_mounts(&read_only_mounts, layout))
            {
                return Err(ConfigError::Invalid);
            }
            windows::WindowsBrokerClient::new(broker_executable.clone(), broker_sha256)
                .map_err(|_| ConfigError::Invalid)?;
            Ok(ProductionTargetConfig::Docker {
                agent_service_sid,
                broker_executable,
                broker_sha256,
                docker_executable,
                canonical_image,
                expected_container_id_state_path,
            })
        }
        (
            ProductionTargetKind::Wsl2,
            Some(ProductionTargetDetailsWire::Wsl2 {
                agent_service_sid,
                broker_executable,
                broker_sha256,
                wsl_executable,
                distro,
                system_owned,
                mirrored_networking,
            }),
        ) => {
            let broker_sha256 = decode_lower_hex_32(&broker_sha256)?;
            if !windows_local_file(&broker_executable)
                || !windows_local_file(&wsl_executable)
                || !valid_service_sid(&agent_service_sid)
                || distro != windows::WSL_DISTRIBUTION
                || !system_owned
                || !mirrored_networking
            {
                return Err(ConfigError::Invalid);
            }
            windows::WindowsBrokerClient::new(broker_executable.clone(), broker_sha256)
                .map_err(|_| ConfigError::Invalid)?;
            Ok(ProductionTargetConfig::Wsl2 {
                agent_service_sid,
                broker_executable,
                broker_sha256,
                wsl_executable,
            })
        }
        _ => Err(ConfigError::Invalid),
    }
}

fn validate_tls_listener(
    endpoints: &[String],
    capabilities: &[TransportCapability],
    tls_listener_port: Option<u16>,
) -> Result<(), ConfigError> {
    let turns_ports: Option<Vec<u16>> = endpoints
        .iter()
        .filter(|endpoint| endpoint.starts_with("turns:"))
        .map(|endpoint| endpoint_port(endpoint))
        .collect();
    let turns_ports = turns_ports.ok_or(ConfigError::Invalid)?;
    let has_tls_capability = capabilities.contains(&TransportCapability::TurnsTcp);
    if has_tls_capability == turns_ports.is_empty()
        || has_tls_capability != tls_listener_port.is_some()
        || turns_ports
            .iter()
            .any(|port| Some(*port) != tls_listener_port)
    {
        return Err(ConfigError::Invalid);
    }
    Ok(())
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    let authority = endpoint
        .strip_prefix("turn:")
        .or_else(|| endpoint.strip_prefix("turns:"))?
        .split('?')
        .next()?;
    authority.rsplit_once(':')?.1.parse().ok()
}

fn paths_match_target(
    target: CoturnTarget,
    agent: &AgentConfig,
    enrollment_token_path: &std::path::Path,
    turn_rest_secret_path: &std::path::Path,
    windows_data_layout: Option<&WindowsDataLayout>,
) -> bool {
    match target {
        CoturnTarget::LinuxSystemd => {
            unix_absolute_file(&agent.identity_path)
                && unix_absolute_file(&agent.runtime_state_path)
                && unix_absolute_file(&agent.trusted_ca_path)
                && enrollment_token_path == std::path::Path::new(LINUX_ENROLLMENT_CREDENTIAL_PATH)
                && turn_rest_secret_path == std::path::Path::new(LINUX_TURN_CREDENTIAL_PATH)
                && linux::LINUX_CONTROL_SOCKET.starts_with("/run/")
        }
        CoturnTarget::WindowsService | CoturnTarget::Docker | CoturnTarget::Wsl2 => {
            windows_data_layout.is_some_and(|layout| {
                layout.matches_relative(&agent.identity_path, &["state", "identity.json"])
                    && layout
                        .matches_relative(&agent.runtime_state_path, &["state", "runtime.json"])
                    && layout
                        .matches_relative(&agent.trusted_ca_path, &["config", "trusted-ca.pem"])
                    && layout.matches_relative(
                        enrollment_token_path,
                        &["secrets", "enrollment-token.dpapi"],
                    )
                    && layout.matches_relative(
                        turn_rest_secret_path,
                        &["secrets", "turn-rest-secret.dpapi"],
                    )
            })
        }
    }
}

fn unix_absolute_file(path: &std::path::Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('\0')
        && path.file_name().is_some()
        && !value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn windows_local_file(path: &std::path::Path) -> bool {
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
        && windows_path_leaf(path).is_some()
        && !value
            .split(['\\', '/'])
            .any(|component| matches!(component, "." | ".."))
}

fn windows_path_leaf(path: &std::path::Path) -> Option<&str> {
    path.to_str()?
        .split(['\\', '/'])
        .next_back()
        .filter(|component| !component.is_empty())
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

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], ConfigError> {
    if !lower_hex_exact(value, 64) || value.bytes().all(|byte| byte == b'0') {
        return Err(ConfigError::Invalid);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, ConfigError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ConfigError::Invalid),
    }
}

fn lower_hex_exact(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_docker_image(value: &str) -> bool {
    let Some((tagged, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    let last_component = tagged.rsplit('/').next().unwrap_or_default();
    !tagged.is_empty()
        && !tagged.contains('@')
        && last_component
            .split_once(':')
            .is_some_and(|(name, tag)| !name.is_empty() && !tag.is_empty())
        && tagged.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
        && lower_hex_exact(digest, 64)
}

fn docker_ports_cover_endpoints(
    published: &[DockerPublishedPortWire],
    endpoints: &[String],
) -> bool {
    if published.is_empty() || published.len() > 16 {
        return false;
    }
    let mut unique = std::collections::BTreeSet::new();
    if published.iter().any(|port| {
        port.host_port == 0
            || port.container_port == 0
            || !unique.insert((port.host_port, port.container_port, port.protocol as u8))
    }) {
        return false;
    }
    endpoints.iter().all(|endpoint| {
        let Some(port) = endpoint_port(endpoint) else {
            return false;
        };
        let protocol = if endpoint.ends_with("transport=udp") {
            DockerProtocol::Udp
        } else {
            DockerProtocol::Tcp
        };
        published.iter().any(|mapping| {
            mapping.host_port == port
                && mapping.container_port == port
                && mapping.protocol == protocol
        })
    })
}

fn valid_docker_mounts(mounts: &[DockerMountWire], layout: &WindowsDataLayout) -> bool {
    if mounts.len() != 2 {
        return false;
    }
    let mut envelope = false;
    let mut tls = false;
    for mount in mounts {
        if !mount.read_only {
            return false;
        }
        match mount.destination.as_str() {
            "/run/mrd/turnserver.conf"
                if layout.matches_relative(&mount.source, &["broker", "docker-envelope"]) =>
            {
                if std::mem::replace(&mut envelope, true) {
                    return false;
                }
            }
            "/run/mrd/tls" if layout.matches_relative(&mount.source, &["tls"]) => {
                if std::mem::replace(&mut tls, true) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    envelope && tls
}

pub(crate) fn is_public_turn_endpoint(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES || !value.is_ascii() {
        return false;
    }
    let (scheme, remainder) = if let Some(remainder) = value.strip_prefix("turn:") {
        ("turn", remainder)
    } else if let Some(remainder) = value.strip_prefix("turns:") {
        ("turns", remainder)
    } else {
        return false;
    };
    if remainder.contains(['@', '/', '#']) {
        return false;
    }
    let mut query_parts = remainder.split('?');
    let authority = query_parts.next().unwrap_or_default();
    let transport = match query_parts.next() {
        None => {
            if scheme == "turn" {
                "udp"
            } else {
                "tcp"
            }
        }
        Some("transport=udp") => "udp",
        Some("transport=tcp") => "tcp",
        Some(_) => return false,
    };
    if query_parts.next().is_some() || (scheme == "turns" && transport != "tcp") {
        return false;
    }
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((host, port)) = ipv6.split_once("]:") else {
            return false;
        };
        if !host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|address| globally_routable_ip(address.into()))
        {
            return false;
        }
        (host, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return false;
        };
        let ipv4 = host.parse::<std::net::Ipv4Addr>().ok();
        let numeric_looking = host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.');
        let lowered = host.to_ascii_lowercase();
        if ipv4.is_some_and(|address| !globally_routable_ip(address.into()))
            || (ipv4.is_none() && numeric_looking)
            || obvious_local_domain(&lowered)
            || host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return false;
        }
        (host, port)
    };
    !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0)
}

pub(crate) fn globally_routable_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => globally_routable_ipv4(address),
        std::net::IpAddr::V6(address) => globally_routable_ipv6(address),
    }
}

fn globally_routable_ipv4(address: std::net::Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    !(matches!(a, 0 | 10 | 127 | 224..=255)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0 && !matches!(d, 9 | 10))
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (18..=19).contains(&b))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn globally_routable_ipv6(address: std::net::Ipv6Addr) -> bool {
    let segments = address.segments();
    let value = u128::from(address);
    const WELL_KNOWN_NAT64: u128 = 0x0064_ff9b_0000_0000_0000_0000_0000_0000;
    if value >> 32 == WELL_KNOWN_NAT64 >> 32 {
        return globally_routable_ipv4(std::net::Ipv4Addr::from(value as u32));
    }
    let ietf_exception = (segments[1] == 0x0001
        && segments[2] == 0
        && segments[3] == 0
        && matches!(value as u64, 1..=3))
        || segments[1] == 0x0003
        || (segments[1] == 0x0004 && segments[2] == 0x0112)
        || matches!(segments[1] & 0xfff0, 0x0020 | 0x0030);
    (0x2000..=0x3fff).contains(&segments[0])
        && !(segments[0] == 0x2001 && segments[1] <= 0x01ff && !ietf_exception)
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && segments[0] != 0x2002
        && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
}

fn obvious_local_domain(host: &str) -> bool {
    !host.contains('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".localdomain")
        || host.ends_with(".lan")
        || host.ends_with(".home")
        || host.ends_with(".home.arpa")
        || host.ends_with(".internal")
        || host.ends_with(".invalid")
}

fn safe_absolute_file(path: &std::path::Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    (unix_absolute_file(path) || windows_local_file(path))
        && !value.is_empty()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn loopback_metrics_url(url: &Url) -> bool {
    let loopback = match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    loopback
        && url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn valid_turn_secret(encoded: &str) -> bool {
    if encoded.len() != 43 || !encoded.is_ascii() {
        return false;
    }
    let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
        Ok(decoded) => Zeroizing::new(decoded),
        Err(_) => return false,
    };
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded {
        return false;
    }
    let lowered = Zeroizing::new(
        decoded
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>(),
    );
    decoded
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        >= 8
        && ![b"placeholder".as_slice(), b"changeme", b"change-me"]
            .iter()
            .any(|marker| {
                lowered
                    .windows(marker.len())
                    .any(|window| window == *marker)
            })
}

fn relay_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn credential_safe_relay_id(value: &str) -> bool {
    relay_id(value) && !value.contains(':')
}

fn region_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{globally_routable_ip, is_public_turn_endpoint};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PublicIpVectors {
        schema_version: u8,
        accepted: Vec<String>,
        rejected: Vec<String>,
        accepted_mappings: Vec<serde_json::Value>,
        rejected_mappings: Vec<serde_json::Value>,
    }

    #[test]
    fn public_ip_classifier_and_turn_literals_match_the_shared_deploy_vectors() {
        let vectors: PublicIpVectors = serde_json::from_str(include_str!(
            "../../../deploy/turn/public-ip-test-vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors.schema_version, 1);
        assert!(!vectors.accepted_mappings.is_empty());
        assert!(!vectors.rejected_mappings.is_empty());
        for (expected, addresses) in [(true, vectors.accepted), (false, vectors.rejected)] {
            for address in addresses {
                let address: std::net::IpAddr = address.parse().unwrap();
                assert_eq!(
                    globally_routable_ip(address),
                    expected,
                    "classifier drifted for {address}"
                );
                let endpoint = match address {
                    std::net::IpAddr::V4(address) => {
                        format!("turn:{address}:3478?transport=udp")
                    }
                    std::net::IpAddr::V6(address) => {
                        format!("turn:[{address}]:3478?transport=udp")
                    }
                };
                assert_eq!(
                    is_public_turn_endpoint(&endpoint),
                    expected,
                    "TURN literal drifted for {address}"
                );
            }
        }
    }

    #[test]
    fn public_turn_endpoints_reject_non_global_literals_and_local_names() {
        for endpoint in [
            "turn:0.0.0.0:3478?transport=udp",
            "turn:127.0.0.1:3478?transport=udp",
            "turn:10.23.4.5:3478?transport=tcp",
            "turn:100.64.0.1:3478?transport=udp",
            "turn:169.254.10.2:3478?transport=udp",
            "turn:192.168.1.5:3478?transport=udp",
            "turn:192.0.2.1:3478?transport=udp",
            "turn:198.18.0.1:3478?transport=udp",
            "turn:224.0.0.1:3478?transport=udp",
            "turn:[::]:3478?transport=udp",
            "turn:[::1]:3478?transport=udp",
            "turn:[fc00::1]:3478?transport=udp",
            "turn:[fe80::1]:3478?transport=udp",
            "turn:[ff02::1]:3478?transport=udp",
            "turn:[2001:db8::1]:3478?transport=udp",
            "turn:[3fff::1]:3478?transport=udp",
            "turn:[::ffff:192.168.1.5]:3478?transport=udp",
            "turn:localhost:3478?transport=udp",
            "turn:relay.local:3478?transport=udp",
        ] {
            assert!(!is_public_turn_endpoint(endpoint), "accepted {endpoint}");
        }

        for endpoint in [
            "turn:8.8.8.8:3478?transport=udp",
            "turn:[2606:4700:4700::1111]:3478?transport=tcp",
            "turns:relay.example.test:5349?transport=tcp",
        ] {
            assert!(is_public_turn_endpoint(endpoint), "rejected {endpoint}");
        }
    }
}
