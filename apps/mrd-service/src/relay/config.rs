use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{collections::BTreeMap, fmt, time::Duration};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CACHE_CAPACITY: usize = 32;
const MAX_TRUSTED_KEYS_JSON_BYTES: usize = 8 * 1024;

/// Validated service configuration for relay-directory requests.
#[derive(Clone)]
pub struct RelayClientConfig {
    endpoint: Url,
    backend_device_token: Zeroizing<String>,
    trusted_keys: BTreeMap<String, Vec<u8>>,
    request_timeout: Duration,
    cache_capacity: usize,
}

impl fmt::Debug for RelayClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayClientConfig")
            .field("endpoint", &"[REDACTED HTTPS ENDPOINT]")
            .field("backend_device_token", &"[REDACTED]")
            .field(
                "trusted_key_ids",
                &self.trusted_keys.keys().collect::<Vec<_>>(),
            )
            .field("request_timeout", &self.request_timeout)
            .field("cache_capacity", &self.cache_capacity)
            .finish()
    }
}

impl Drop for RelayClientConfig {
    fn drop(&mut self) {
        for key in self.trusted_keys.values_mut() {
            key.zeroize();
        }
    }
}

impl RelayClientConfig {
    pub fn new(
        endpoint: &str,
        backend_device_token: &str,
        trusted_keys: BTreeMap<String, Vec<u8>>,
        request_timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self, RelayClientConfigError> {
        let endpoint = Url::parse(endpoint).map_err(|_| RelayClientConfigError::InvalidEndpoint)?;
        validate_endpoint(&endpoint)?;
        if backend_device_token.is_empty()
            || backend_device_token.len() > 4_096
            || backend_device_token.chars().any(char::is_control)
            || trusted_keys.is_empty()
            || trusted_keys.len() > 8
            || trusted_keys.iter().any(|(key_id, key)| {
                key_id.is_empty()
                    || key_id.len() > 256
                    || key_id.chars().any(char::is_control)
                    || key.len() != 32
            })
            || request_timeout < Duration::from_millis(100)
            || request_timeout > Duration::from_secs(30)
            || !(1..=128).contains(&cache_capacity)
        {
            return Err(RelayClientConfigError::InvalidValue);
        }
        Ok(Self {
            endpoint,
            backend_device_token: Zeroizing::new(backend_device_token.to_owned()),
            trusted_keys,
            request_timeout,
            cache_capacity,
        })
    }

    /// Load optional relay configuration. An unset directory URL disables the runtime.
    pub fn from_env() -> Result<Option<Self>, RelayClientConfigError> {
        let Some(endpoint) = env_optional("MRD_RELAY_DIRECTORY_URL") else {
            return Ok(None);
        };
        let token = Zeroizing::new(env_required("MRD_SIGNAL_DEVICE_TOKEN")?);
        let encoded_keys = env_required("MRD_RELAY_DIRECTORY_TRUSTED_KEYS")?;
        if encoded_keys.len() > MAX_TRUSTED_KEYS_JSON_BYTES {
            return Err(RelayClientConfigError::InvalidEnvironment(
                "MRD_RELAY_DIRECTORY_TRUSTED_KEYS",
            ));
        }
        let raw_keys: BTreeMap<String, String> =
            serde_json::from_str(&encoded_keys).map_err(|_| {
                RelayClientConfigError::InvalidEnvironment("MRD_RELAY_DIRECTORY_TRUSTED_KEYS")
            })?;
        let mut trusted_keys = BTreeMap::new();
        for (key_id, encoded) in raw_keys {
            let key = STANDARD.decode(encoded.as_bytes()).map_err(|_| {
                RelayClientConfigError::InvalidEnvironment("MRD_RELAY_DIRECTORY_TRUSTED_KEYS")
            })?;
            trusted_keys.insert(key_id, key);
        }
        let request_timeout = duration_ms_from_env(
            "MRD_RELAY_DIRECTORY_TIMEOUT_MS",
            DEFAULT_REQUEST_TIMEOUT,
            100,
            30_000,
        )?;
        let cache_capacity = usize_from_env(
            "MRD_RELAY_DIRECTORY_CACHE_CAPACITY",
            DEFAULT_CACHE_CAPACITY,
            1,
            128,
        )?;
        Self::new(
            &endpoint,
            &token,
            trusted_keys,
            request_timeout,
            cache_capacity,
        )
        .map(Some)
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub fn trusted_keys(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.trusted_keys
    }

    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity
    }

    pub(crate) fn backend_device_token(&self) -> &str {
        &self.backend_device_token
    }
}

fn validate_endpoint(endpoint: &Url) -> Result<(), RelayClientConfigError> {
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || endpoint.as_str().len() > 2_048
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(RelayClientConfigError::InvalidEndpoint);
    }
    Ok(())
}

fn env_optional(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_required(name: &'static str) -> Result<String, RelayClientConfigError> {
    env_optional(name).ok_or(RelayClientConfigError::Missing(name))
}

fn duration_ms_from_env(
    name: &'static str,
    default: Duration,
    minimum: u64,
    maximum: u64,
) -> Result<Duration, RelayClientConfigError> {
    Ok(Duration::from_millis(u64_from_env(
        name,
        u64::try_from(default.as_millis()).unwrap_or(maximum),
        minimum,
        maximum,
    )?))
}

fn usize_from_env(
    name: &'static str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, RelayClientConfigError> {
    let Some(raw) = env_optional(name) else {
        return Ok(default);
    };
    let value = raw
        .parse::<usize>()
        .map_err(|_| RelayClientConfigError::InvalidEnvironment(name))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(RelayClientConfigError::InvalidEnvironment(name));
    }
    Ok(value)
}

fn u64_from_env(
    name: &'static str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, RelayClientConfigError> {
    let Some(raw) = env_optional(name) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u64>()
        .map_err(|_| RelayClientConfigError::InvalidEnvironment(name))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(RelayClientConfigError::InvalidEnvironment(name));
    }
    Ok(value)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayClientConfigError {
    #[error("relay directory endpoint must be a credential-free HTTPS URL")]
    InvalidEndpoint,
    #[error("relay client configuration contains an invalid value")]
    InvalidValue,
    #[error("required relay environment variable is missing: {0}")]
    Missing(&'static str),
    #[error("relay environment variable is invalid: {0}")]
    InvalidEnvironment(&'static str),
}
