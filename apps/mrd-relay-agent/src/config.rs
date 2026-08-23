use std::{
    path::{Component, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_ENDPOINTS: usize = 4;

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
    pub enrollment_token: Option<SecretString>,
    pub turn_rest_secret: Option<SecretString>,
    pub heartbeat_interval: Duration,
    pub backend_backoff_cap: Duration,
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
            .field("enrollment_token", &"REDACTED")
            .field("turn_rest_secret", &"REDACTED")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("backend_backoff_cap", &self.backend_backoff_cap)
            .finish()
    }
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.backend_url.scheme() != "https"
            || self.backend_url.cannot_be_a_base()
            || !self.backend_url.username().is_empty()
            || self.backend_url.password().is_some()
            || self.backend_url.query().is_some()
            || self.backend_url.fragment().is_some()
            || !bounded_identifier(&self.node_id)
            || !bounded_identifier(&self.region)
            || !bounded_identifier(&self.failure_domain)
            || self.endpoints.is_empty()
            || self.endpoints.len() > MAX_ENDPOINTS
            || self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES)
            || self.max_allocations == 0
            || self.max_egress_bps == 0
            || self.identity_path.as_os_str().is_empty()
            || !self.identity_path.is_absolute()
            || self.identity_path.file_name().is_none()
            || self
                .identity_path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
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

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}
