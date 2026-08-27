use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{collections::BTreeMap, fmt, net::IpAddr, time::Duration};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);
const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_ATTEMPTS: usize = 3;
const MAX_TRUSTED_KEYS_JSON_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct WanSessionBackendConfig {
    base_url: Url,
    device_token: Zeroizing<String>,
    trusted_directory_keys: BTreeMap<String, Vec<u8>>,
    operation_deadline: Duration,
    max_body_bytes: usize,
    max_attempts: usize,
}

impl fmt::Debug for WanSessionBackendConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanSessionBackendConfig")
            .field("base_url", &"[REDACTED ENDPOINT]")
            .field("device_token", &"[REDACTED]")
            .field(
                "trusted_directory_key_ids",
                &self.trusted_directory_keys.keys().collect::<Vec<_>>(),
            )
            .field("operation_deadline", &self.operation_deadline)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl WanSessionBackendConfig {
    pub fn new(
        base_url: &str,
        device_token: &str,
        trusted_directory_keys: BTreeMap<String, Vec<u8>>,
        operation_deadline: Duration,
        max_body_bytes: usize,
        max_attempts: usize,
    ) -> Result<Self, WanSessionBackendConfigError> {
        let mut base_url =
            Url::parse(base_url).map_err(|_| WanSessionBackendConfigError::InvalidEndpoint)?;
        validate_endpoint(&base_url)?;
        if !base_url.path().ends_with('/') {
            let mut path = base_url.path().to_owned();
            path.push('/');
            base_url.set_path(&path);
        }
        if device_token.is_empty()
            || device_token.len() > 4_096
            || device_token.chars().any(char::is_control)
            || trusted_directory_keys.is_empty()
            || trusted_directory_keys.len() > 8
            || trusted_directory_keys.iter().any(|(key_id, key)| {
                key_id.is_empty()
                    || key_id.len() > 256
                    || key_id.chars().any(char::is_control)
                    || key.len() != 32
            })
            || operation_deadline < Duration::from_millis(50)
            || operation_deadline > Duration::from_secs(30)
            || !(1_024..=4 * 1024 * 1024).contains(&max_body_bytes)
            || !(1..=5).contains(&max_attempts)
        {
            return Err(WanSessionBackendConfigError::InvalidValue);
        }
        Ok(Self {
            base_url,
            device_token: Zeroizing::new(device_token.to_owned()),
            trusted_directory_keys,
            operation_deadline,
            max_body_bytes,
            max_attempts,
        })
    }

    pub fn from_env() -> Result<Option<Self>, WanSessionBackendConfigError> {
        let Some(base_url) = env_optional("MRD_WAN_SESSION_API_URL") else {
            return Ok(None);
        };
        let token = Zeroizing::new(env_required("MRD_SIGNAL_DEVICE_TOKEN")?);
        let encoded_keys = env_required("MRD_RELAY_DIRECTORY_TRUSTED_KEYS")?;
        if encoded_keys.len() > MAX_TRUSTED_KEYS_JSON_BYTES {
            return Err(WanSessionBackendConfigError::InvalidEnvironment(
                "MRD_RELAY_DIRECTORY_TRUSTED_KEYS",
            ));
        }
        let raw_keys: BTreeMap<String, String> =
            serde_json::from_str(&encoded_keys).map_err(|_| {
                WanSessionBackendConfigError::InvalidEnvironment("MRD_RELAY_DIRECTORY_TRUSTED_KEYS")
            })?;
        let mut trusted_keys = BTreeMap::new();
        for (key_id, encoded) in raw_keys {
            let key = STANDARD.decode(encoded.as_bytes()).map_err(|_| {
                WanSessionBackendConfigError::InvalidEnvironment("MRD_RELAY_DIRECTORY_TRUSTED_KEYS")
            })?;
            trusted_keys.insert(key_id, key);
        }
        let deadline =
            duration_ms_from_env("MRD_WAN_SESSION_DEADLINE_MS", DEFAULT_DEADLINE, 50, 30_000)?;
        let max_body_bytes = usize_from_env(
            "MRD_WAN_SESSION_MAX_BODY_BYTES",
            DEFAULT_MAX_BODY_BYTES,
            1_024,
            4 * 1024 * 1024,
        )?;
        let max_attempts =
            usize_from_env("MRD_WAN_SESSION_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS, 1, 5)?;
        Self::new(
            &base_url,
            &token,
            trusted_keys,
            deadline,
            max_body_bytes,
            max_attempts,
        )
        .map(Some)
    }

    pub(crate) fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub(crate) fn device_token(&self) -> &str {
        &self.device_token
    }

    pub(crate) fn trusted_directory_keys(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.trusted_directory_keys
    }

    pub(crate) fn operation_deadline(&self) -> Duration {
        self.operation_deadline
    }

    pub(crate) fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub(crate) fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    pub(crate) fn permits_cleartext_loopback(&self) -> bool {
        self.base_url.scheme() == "http"
    }
}

fn validate_endpoint(endpoint: &Url) -> Result<(), WanSessionBackendConfigError> {
    let secure = endpoint.scheme() == "https";
    let loopback_http = endpoint.scheme() == "http" && endpoint.host_str().is_some_and(is_loopback);
    if (!secure && !loopback_http)
        || endpoint.host_str().is_none()
        || endpoint.as_str().len() > 2_048
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(WanSessionBackendConfigError::InvalidEndpoint);
    }
    Ok(())
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn env_optional(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_required(name: &'static str) -> Result<String, WanSessionBackendConfigError> {
    env_optional(name).ok_or(WanSessionBackendConfigError::Missing(name))
}

fn duration_ms_from_env(
    name: &'static str,
    default: Duration,
    minimum: u64,
    maximum: u64,
) -> Result<Duration, WanSessionBackendConfigError> {
    let default = u64::try_from(default.as_millis()).unwrap_or(maximum);
    Ok(Duration::from_millis(u64_from_env(
        name, default, minimum, maximum,
    )?))
}

fn usize_from_env(
    name: &'static str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, WanSessionBackendConfigError> {
    let Some(raw) = env_optional(name) else {
        return Ok(default);
    };
    let value = raw
        .parse::<usize>()
        .map_err(|_| WanSessionBackendConfigError::InvalidEnvironment(name))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(WanSessionBackendConfigError::InvalidEnvironment(name));
    }
    Ok(value)
}

fn u64_from_env(
    name: &'static str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, WanSessionBackendConfigError> {
    let Some(raw) = env_optional(name) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u64>()
        .map_err(|_| WanSessionBackendConfigError::InvalidEnvironment(name))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(WanSessionBackendConfigError::InvalidEnvironment(name));
    }
    Ok(value)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WanSessionBackendConfigError {
    #[error("WAN session backend endpoint must be credential-free HTTPS")]
    InvalidEndpoint,
    #[error("WAN session backend configuration contains an invalid value")]
    InvalidValue,
    #[error("required WAN session environment variable is missing: {0}")]
    Missing(&'static str),
    #[error("WAN session environment variable is invalid: {0}")]
    InvalidEnvironment(&'static str),
}
