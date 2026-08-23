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

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_ENDPOINTS: usize = 4;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("relay_agent_config_invalid")]
    Invalid,
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
                .any(|endpoint| endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES)
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

fn safe_absolute_file(path: &std::path::Path) -> bool {
    !path.as_os_str().is_empty()
        && path.is_absolute()
        && path.file_name().is_some()
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
        && matches!(url.scheme(), "http" | "https")
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
