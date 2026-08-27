use super::{cache::RelayDirectoryCache, config::RelayClientConfig};
use crate::transports::webrtc::ServiceTurnRelayCredentials;
use async_trait::async_trait;
use futures_util::StreamExt as _;
use mrd_relay_control::{
    ContextVerifiedRelayDirectory, RelayDirectoryCandidate, RelayDirectoryEndpoint,
    RelayDirectoryError, RelayDirectoryTransport, SignedRelayDirectory,
    MAX_RELAY_DIRECTORY_JSON_BYTES,
};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    collections::BTreeSet,
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_RELAY_ACCESS_JSON_BYTES: usize = MAX_RELAY_DIRECTORY_JSON_BYTES + 64 * 1024;
const MAX_CREDENTIALS: usize = 8;
const MAX_URLS_PER_CREDENTIAL: usize = 4;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize)]
pub struct RelayAccessContext {
    pub session_id: String,
    pub policy_revision: u64,
    pub intended_peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh: Option<bool>,
    #[serde(skip)]
    peer_digest: String,
}

impl RelayAccessContext {
    pub fn new(
        session_id: impl Into<String>,
        policy_revision: u64,
        intended_peer_id: impl Into<String>,
    ) -> Result<Self, RelayClientError> {
        let session_id = session_id.into();
        let intended_peer_id = intended_peer_id.into();
        validate_identifier(&session_id)?;
        validate_identifier(&intended_peer_id)?;
        if policy_revision == 0 || policy_revision > i64::MAX as u64 {
            return Err(RelayClientError::InvalidContext);
        }
        let peer_digest = relay_peer_digest(&intended_peer_id)?;
        Ok(Self {
            session_id,
            policy_revision,
            intended_peer_id,
            generation: None,
            refresh: None,
            peer_digest,
        })
    }

    pub fn for_generation(
        session_id: impl Into<String>,
        policy_revision: u64,
        intended_peer_id: impl Into<String>,
        generation: u64,
    ) -> Result<Self, RelayClientError> {
        Self::with_generation(
            session_id,
            policy_revision,
            intended_peer_id,
            generation,
            None,
        )
    }

    pub fn for_refresh(
        session_id: impl Into<String>,
        policy_revision: u64,
        intended_peer_id: impl Into<String>,
        generation: u64,
    ) -> Result<Self, RelayClientError> {
        Self::with_generation(
            session_id,
            policy_revision,
            intended_peer_id,
            generation,
            Some(true),
        )
    }

    fn with_generation(
        session_id: impl Into<String>,
        policy_revision: u64,
        intended_peer_id: impl Into<String>,
        generation: u64,
        refresh: Option<bool>,
    ) -> Result<Self, RelayClientError> {
        if generation > i64::MAX as u64 {
            return Err(RelayClientError::InvalidContext);
        }
        let mut context = Self::new(session_id, policy_revision, intended_peer_id)?;
        context.generation = Some(generation);
        context.refresh = refresh;
        Ok(context)
    }

    pub fn generation(&self) -> Option<u64> {
        self.generation
    }

    pub fn is_refresh(&self) -> bool {
        self.refresh.unwrap_or(false)
    }

    pub fn intended_peer_digest(&self) -> &str {
        &self.peer_digest
    }
}

/// Compute the backend contract's domain-separated intended-peer digest.
pub fn relay_peer_digest(peer_id: &str) -> Result<String, RelayClientError> {
    validate_identifier(peer_id)?;
    let mut bytes = Vec::with_capacity(18 + peer_id.len());
    bytes.extend_from_slice(b"MRD_RELAY_PEER_V1\0");
    bytes.extend_from_slice(peer_id.as_bytes());
    let digest = digest(&SHA256, &bytes);
    let mut output = String::with_capacity(12 + 64);
    output.push_str("peer-sha256-");
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RelayBackendError {
    #[error("relay backend is unavailable")]
    Unavailable,
    #[error("relay access is unauthorized")]
    Unauthorized,
    #[error("relay backend response is invalid")]
    InvalidResponse,
}

#[async_trait]
pub trait RelayAccessBackend: Send + Sync {
    async fn fetch(
        &self,
        context: &RelayAccessContext,
    ) -> Result<Zeroizing<Vec<u8>>, RelayBackendError>;
}

pub trait RelayClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemRelayClock;

impl RelayClock for SystemRelayClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

struct ReqwestRelayAccessBackend {
    client: reqwest::Client,
    config: RelayClientConfig,
}

#[async_trait]
impl RelayAccessBackend for ReqwestRelayAccessBackend {
    async fn fetch(
        &self,
        context: &RelayAccessContext,
    ) -> Result<Zeroizing<Vec<u8>>, RelayBackendError> {
        let device_authorization =
            Zeroizing::new(format!("Bearer {}", self.config.backend_device_token()));
        let mut device_authorization =
            reqwest::header::HeaderValue::from_str(&device_authorization)
                .map_err(|_| RelayBackendError::InvalidResponse)?;
        device_authorization.set_sensitive(true);
        let response = self
            .client
            .post(self.config.endpoint().clone())
            .header("X-Rdesk-Device-Authorization", device_authorization)
            .json(context)
            .send()
            .await
            .map_err(|_| RelayBackendError::Unavailable)?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(RelayBackendError::Unauthorized);
        }
        if status.is_server_error()
            || status == reqwest::StatusCode::REQUEST_TIMEOUT
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        {
            return Err(RelayBackendError::Unavailable);
        }
        if !status.is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_RELAY_ACCESS_JSON_BYTES as u64)
        {
            return Err(RelayBackendError::InvalidResponse);
        }
        let mut body = Zeroizing::new(Vec::new());
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| RelayBackendError::Unavailable)?;
            if body.len().saturating_add(chunk.len()) > MAX_RELAY_ACCESS_JSON_BYTES {
                return Err(RelayBackendError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

pub struct RelayDirectoryClient {
    config: RelayClientConfig,
    backend: Arc<dyn RelayAccessBackend>,
    clock: Arc<dyn RelayClock>,
    cache: Mutex<RelayDirectoryCache>,
}

impl fmt::Debug for RelayDirectoryClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayDirectoryClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RelayDirectoryClient {
    pub fn new(config: RelayClientConfig) -> Result<Self, RelayClientError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.request_timeout())
            .build()
            .map_err(|_| RelayClientError::BackendUnavailable)?;
        let backend = Arc::new(ReqwestRelayAccessBackend {
            client,
            config: config.clone(),
        });
        Ok(Self::with_backend(
            config,
            backend,
            Arc::new(SystemRelayClock),
        ))
    }

    pub fn with_backend(
        config: RelayClientConfig,
        backend: Arc<dyn RelayAccessBackend>,
        clock: Arc<dyn RelayClock>,
    ) -> Self {
        let capacity = config.cache_capacity();
        Self {
            config,
            backend,
            clock,
            cache: Mutex::new(RelayDirectoryCache::new(capacity)),
        }
    }

    pub async fn access(
        &self,
        context: RelayAccessContext,
    ) -> Result<Arc<VerifiedRelayAccess>, RelayClientError> {
        let now_ms = self.clock.now_ms();
        if let Some(cached) = self.cache.lock().await.get(&context, now_ms) {
            return Ok(cached);
        }
        self.refresh(context).await
    }

    pub async fn refresh(
        &self,
        context: RelayAccessContext,
    ) -> Result<Arc<VerifiedRelayAccess>, RelayClientError> {
        match self.backend.fetch(&context).await {
            Ok(body) => match self.verify_response(&context, &body, self.clock.now_ms()) {
                Ok(access) => {
                    let access = Arc::new(access);
                    self.cache.lock().await.insert(context, Arc::clone(&access));
                    Ok(access)
                }
                Err(error) => {
                    self.cache.lock().await.remove(&context);
                    Err(error)
                }
            },
            Err(RelayBackendError::Unavailable) => self
                .cache
                .lock()
                .await
                .get(&context, self.clock.now_ms())
                .ok_or(RelayClientError::BackendUnavailable),
            Err(RelayBackendError::Unauthorized) => {
                self.cache.lock().await.remove(&context);
                Err(RelayClientError::Unauthorized)
            }
            Err(RelayBackendError::InvalidResponse) => {
                self.cache.lock().await.remove(&context);
                Err(RelayClientError::InvalidResponse)
            }
        }
    }

    pub async fn cache_len(&self) -> usize {
        self.cache.lock().await.len()
    }

    fn verify_response(
        &self,
        context: &RelayAccessContext,
        body: &[u8],
        now_ms: u64,
    ) -> Result<VerifiedRelayAccess, RelayClientError> {
        verify_relay_access_response(context, self.config.trusted_keys(), body, now_ms)
    }
}

pub(crate) fn verify_relay_access_response(
    context: &RelayAccessContext,
    trusted_keys: &BTreeMap<String, Vec<u8>>,
    body: &[u8],
    now_ms: u64,
) -> Result<VerifiedRelayAccess, RelayClientError> {
    if body.len() > MAX_RELAY_ACCESS_JSON_BYTES {
        return Err(RelayClientError::InvalidResponse);
    }
    let raw: RawRelayAccessResponse =
        serde_json::from_slice(body).map_err(|_| RelayClientError::InvalidResponse)?;
    if raw.credentials.is_empty() || raw.credentials.len() > MAX_CREDENTIALS {
        return Err(RelayClientError::CredentialBinding);
    }
    let directory_json =
        serde_json::to_vec(&raw.directory).map_err(|_| RelayClientError::InvalidResponse)?;
    let signed = SignedRelayDirectory::from_json(&directory_json)?;
    let directory = signed.verify_for_context(
        trusted_keys,
        &context.session_id,
        context.policy_revision,
        context.intended_peer_digest(),
        now_ms,
    )?;
    let credentials = verify_credentials(
        directory.payload().candidates.as_slice(),
        raw.credentials,
        now_ms,
    )?;
    Ok(VerifiedRelayAccess {
        directory,
        credentials,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayAccessResponse {
    directory: serde_json::Value,
    credentials: Vec<RawRelayCredential>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawRelayCredential {
    node_id: String,
    urls: Vec<String>,
    username: String,
    credential: String,
    expires_at_unix_seconds: u64,
}

pub struct VerifiedRelayAccess {
    directory: ContextVerifiedRelayDirectory,
    credentials: BTreeMap<String, ServiceTurnRelayCredentials>,
}

impl fmt::Debug for VerifiedRelayAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRelayAccess")
            .field("directory_id", &self.directory.payload().directory_id)
            .field("session_id", &self.directory.payload().session_id)
            .field(
                "candidate_node_ids",
                &self.credentials.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl VerifiedRelayAccess {
    pub fn directory(&self) -> &ContextVerifiedRelayDirectory {
        &self.directory
    }

    pub fn credentials_for(&self, node_id: &str) -> Option<&ServiceTurnRelayCredentials> {
        self.credentials.get(node_id)
    }

    pub fn route_evidence(
        &self,
        node_id: &str,
        generation: u64,
    ) -> Result<RelayRouteEvidence, RelayClientError> {
        let candidate = self
            .directory
            .payload()
            .candidates
            .iter()
            .find(|candidate| candidate.node_id == node_id)
            .ok_or(RelayClientError::CredentialBinding)?;
        let credential = self
            .credentials
            .get(node_id)
            .ok_or(RelayClientError::CredentialBinding)?;
        Ok(RelayRouteEvidence {
            session_id: self.directory.payload().session_id.clone(),
            directory_id: self.directory.payload().directory_id.clone(),
            node_id: node_id.to_owned(),
            region: candidate.region.clone(),
            failure_domain: candidate.failure_domain.clone(),
            generation,
            urls_digest: urls_digest(&credential.urls),
        })
    }

    pub(crate) fn is_fresh(&self, now_ms: u64) -> bool {
        let payload = self.directory.payload();
        now_ms < payload.expires_at_ms
            && payload
                .candidates
                .iter()
                .all(|candidate| now_ms < candidate.reservation.expires_at_ms)
            && self
                .credentials
                .values()
                .all(|credential| now_ms / 1_000 < credential.expires_at_unix_seconds)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RelayRouteEvidence {
    session_id: String,
    directory_id: String,
    node_id: String,
    region: String,
    failure_domain: String,
    generation: u64,
    urls_digest: [u8; 32],
}

impl fmt::Debug for RelayRouteEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayRouteEvidence")
            .field("session_id", &self.session_id)
            .field("directory_id", &self.directory_id)
            .field("node_id", &self.node_id)
            .field("region", &self.region)
            .field("failure_domain", &self.failure_domain)
            .field("generation", &self.generation)
            .field("urls_digest", &"[REDACTED]")
            .finish()
    }
}

impl RelayRouteEvidence {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn directory_id(&self) -> &str {
        &self.directory_id
    }
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn failure_domain(&self) -> &str {
        &self.failure_domain
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn urls_digest(&self) -> &[u8; 32] {
        &self.urls_digest
    }
}

fn verify_credentials(
    candidates: &[RelayDirectoryCandidate],
    raw_credentials: Vec<RawRelayCredential>,
    now_ms: u64,
) -> Result<BTreeMap<String, ServiceTurnRelayCredentials>, RelayClientError> {
    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut credentials = BTreeMap::new();
    for mut raw in raw_credentials {
        validate_identifier(&raw.node_id)?;
        if credentials.contains_key(&raw.node_id)
            || raw.urls.is_empty()
            || raw.urls.len() > MAX_URLS_PER_CREDENTIAL
            || raw.username.is_empty()
            || raw.username.len() > 512
            || raw.username.chars().any(char::is_control)
            || raw.credential.is_empty()
            || raw.credential.len() > 512
            || raw.credential.chars().any(char::is_control)
            || raw.expires_at_unix_seconds <= now_ms / 1_000
        {
            return Err(RelayClientError::CredentialBinding);
        }
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.node_id == raw.node_id)
            .ok_or(RelayClientError::CredentialBinding)?;
        let actual = raw.urls.iter().map(String::as_str).collect::<BTreeSet<_>>();
        if actual.len() != raw.urls.len() || actual.len() != candidate.endpoints.len() {
            return Err(RelayClientError::CredentialBinding);
        }
        for endpoint in &candidate.endpoints {
            let expected = Zeroizing::new(turn_url(endpoint)?);
            if !actual.contains(expected.as_str()) {
                return Err(RelayClientError::CredentialBinding);
            }
        }
        let node_id = std::mem::take(&mut raw.node_id);
        credentials.insert(
            node_id,
            ServiceTurnRelayCredentials {
                urls: std::mem::take(&mut raw.urls),
                username: std::mem::take(&mut raw.username),
                credential: std::mem::take(&mut raw.credential),
                expires_at_unix_seconds: raw.expires_at_unix_seconds,
            },
        );
    }
    if credentials.len() != candidate_ids.len()
        || !credentials
            .keys()
            .all(|node_id| candidate_ids.contains(node_id.as_str()))
    {
        return Err(RelayClientError::CredentialBinding);
    }
    Ok(credentials)
}

fn turn_url(endpoint: &RelayDirectoryEndpoint) -> Result<String, RelayClientError> {
    if endpoint.port == 0
        || endpoint.host.is_empty()
        || endpoint.host.len() > 253
        || endpoint.host.chars().any(char::is_control)
        || endpoint.host.contains(['@', '/', '?', '#', '\\'])
    {
        return Err(RelayClientError::CredentialBinding);
    }
    let host = if endpoint.host.contains(':') {
        format!("[{}]", endpoint.host)
    } else {
        endpoint.host.clone()
    };
    let (scheme, transport) = match endpoint.transport {
        RelayDirectoryTransport::Udp => ("turn", "udp"),
        RelayDirectoryTransport::Tcp => ("turn", "tcp"),
        RelayDirectoryTransport::Tls => ("turns", "tcp"),
    };
    Ok(format!(
        "{scheme}:{host}:{}?transport={transport}",
        endpoint.port
    ))
}

pub(crate) fn urls_digest(urls: &[String]) -> [u8; 32] {
    let mut urls = urls.iter().map(String::as_str).collect::<Vec<_>>();
    urls.sort();
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"MRD_RELAY_URLS_V1\0");
    for url in urls {
        bytes.extend_from_slice(&(url.len() as u32).to_be_bytes());
        bytes.extend_from_slice(url.as_bytes());
    }
    digest(&SHA256, &bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output is 32 bytes")
}

fn validate_identifier(value: &str) -> Result<(), RelayClientError> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RelayClientError::InvalidContext);
    }
    Ok(())
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RelayClientError {
    #[error("relay access context is invalid")]
    InvalidContext,
    #[error("relay backend is unavailable")]
    BackendUnavailable,
    #[error("relay access was denied or revoked")]
    Unauthorized,
    #[error("relay access response is invalid")]
    InvalidResponse,
    #[error("relay credentials do not match the verified directory")]
    CredentialBinding,
    #[error(transparent)]
    Directory(#[from] RelayDirectoryError),
}

impl RelayClientError {
    pub fn is_terminal_security(&self) -> bool {
        !matches!(self, Self::BackendUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::RawRelayCredential;

    #[test]
    fn raw_relay_credentials_zeroize_when_dropped() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<RawRelayCredential>();
    }
}
