use super::config::WanSessionBackendConfig;
use crate::{
    relay::{
        verify_relay_access_response, RelayAccessContext, RelayClientError, VerifiedRelayAccess,
    },
    transports::webrtc::ServiceTurnRelayCredentials,
};
use async_trait::async_trait;
use futures_util::StreamExt as _;
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{
    WanAccessModeV3, WanMediaProfileV3, WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
};
use reqwest::{header::HeaderValue, Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::SystemTime};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::time::{timeout_at, Instant};
use zeroize::Zeroizing;

const MAX_SESSION_ID_BYTES: usize = 36;
const MAX_DEVICE_ID_BYTES: usize = 64;
const MAX_SCOPES: usize = 32;

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct WanSessionBinding {
    session_id: SessionId,
    controller_device_id: DeviceId,
    target_device_id: DeviceId,
}

impl fmt::Debug for WanSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanSessionBinding")
            .field("session_id", &self.session_id)
            .field("controller_device_id", &self.controller_device_id)
            .field("target_device_id", &self.target_device_id)
            .finish()
    }
}

impl WanSessionBinding {
    pub fn new(
        session_id: SessionId,
        controller_device_id: DeviceId,
        target_device_id: DeviceId,
    ) -> Result<Self, WanSessionBackendError> {
        validate_identifier(&session_id.0, MAX_SESSION_ID_BYTES)?;
        validate_identifier(&controller_device_id.0, MAX_DEVICE_ID_BYTES)?;
        validate_identifier(&target_device_id.0, MAX_DEVICE_ID_BYTES)?;
        if controller_device_id == target_device_id {
            return Err(WanSessionBackendError::InvalidRequest);
        }
        Ok(Self {
            session_id,
            controller_device_id,
            target_device_id,
        })
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn controller_device_id(&self) -> &DeviceId {
        &self.controller_device_id
    }

    pub fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WanSessionApproval {
    approved_scopes: Vec<WanPermissionScopeV3>,
    approved_profile: Option<WanMediaProfileV3>,
}

impl fmt::Debug for WanSessionApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanSessionApproval")
            .field("approved_scopes", &self.approved_scopes)
            .field(
                "approved_profile",
                &self.approved_profile.as_ref().map(|_| "SET"),
            )
            .finish()
    }
}

impl WanSessionApproval {
    pub fn new(
        approved_scopes: Vec<WanPermissionScopeV3>,
        approved_profile: Option<WanMediaProfileV3>,
    ) -> Result<Self, WanSessionBackendError> {
        validate_scopes(&approved_scopes)?;
        if let Some(profile) = &approved_profile {
            validate_profile(profile)?;
        }
        Ok(Self {
            approved_scopes,
            approved_profile,
        })
    }

    pub fn approved_scopes(&self) -> &[WanPermissionScopeV3] {
        &self.approved_scopes
    }

    pub fn approved_profile(&self) -> Option<&WanMediaProfileV3> {
        self.approved_profile.as_ref()
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WanSessionStatus {
    Requested,
    Approved,
    Rejected,
    Expired,
    Closed,
    Revoked,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WanSessionRecord {
    binding: WanSessionBinding,
    request: WanSessionRequestV3,
    request_commitment: String,
    status: WanSessionStatus,
    approved_scopes: Option<Vec<WanPermissionScopeV3>>,
    approved_profile: Option<WanMediaProfileV3>,
    policy_revision: Option<u64>,
    policy_expires_at_ms: Option<u64>,
    grant_expires_at_ms: Option<u64>,
    active_relay_generation: Option<u64>,
}

impl fmt::Debug for WanSessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanSessionRecord")
            .field("binding", &self.binding)
            .field("request", &"[REDACTED]")
            .field("request_commitment", &self.request_commitment)
            .field("status", &self.status)
            .field("policy_revision", &self.policy_revision)
            .field("policy_expires_at_ms", &self.policy_expires_at_ms)
            .field("grant_expires_at_ms", &self.grant_expires_at_ms)
            .field("active_relay_generation", &self.active_relay_generation)
            .finish()
    }
}

impl WanSessionRecord {
    pub fn binding(&self) -> &WanSessionBinding {
        &self.binding
    }

    pub fn request(&self) -> &WanSessionRequestV3 {
        &self.request
    }

    pub fn request_commitment(&self) -> &str {
        &self.request_commitment
    }

    pub fn status(&self) -> WanSessionStatus {
        self.status
    }

    pub fn approved_scopes(&self) -> Option<&[WanPermissionScopeV3]> {
        self.approved_scopes.as_deref()
    }

    pub fn approved_profile(&self) -> Option<&WanMediaProfileV3> {
        self.approved_profile.as_ref()
    }

    pub fn policy_revision(&self) -> Option<u64> {
        self.policy_revision
    }

    pub fn policy_expires_at_ms(&self) -> Option<u64> {
        self.policy_expires_at_ms
    }

    pub fn grant_expires_at_ms(&self) -> Option<u64> {
        self.grant_expires_at_ms
    }

    pub fn active_relay_generation(&self) -> Option<u64> {
        self.active_relay_generation
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WanRelayAccessRequest {
    binding: WanSessionBinding,
    policy_revision: u64,
    generation: u64,
    refresh: bool,
}

impl fmt::Debug for WanRelayAccessRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanRelayAccessRequest")
            .field("binding", &self.binding)
            .field("policy_revision", &self.policy_revision)
            .field("generation", &self.generation)
            .field("refresh", &self.refresh)
            .finish()
    }
}

impl WanRelayAccessRequest {
    pub fn generation_zero(
        binding: WanSessionBinding,
        policy_revision: u64,
    ) -> Result<Self, WanSessionBackendError> {
        Self::exact_generation(binding, policy_revision, 0, false)
    }

    pub fn exact_generation(
        binding: WanSessionBinding,
        policy_revision: u64,
        generation: u64,
        refresh: bool,
    ) -> Result<Self, WanSessionBackendError> {
        if policy_revision == 0 || policy_revision > i64::MAX as u64 || generation > i64::MAX as u64
        {
            return Err(WanSessionBackendError::InvalidRequest);
        }
        Ok(Self {
            binding,
            policy_revision,
            generation,
            refresh,
        })
    }

    pub fn binding(&self) -> &WanSessionBinding {
        &self.binding
    }

    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_refresh(&self) -> bool {
        self.refresh
    }
}

pub struct WanRelayAccess {
    binding: WanSessionBinding,
    generation: u64,
    verified: Arc<VerifiedRelayAccess>,
}

impl fmt::Debug for WanRelayAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanRelayAccess")
            .field("binding", &self.binding)
            .field("generation", &self.generation)
            .field("directory_id", &self.directory_id())
            .field(
                "candidate_node_ids",
                &self
                    .verified
                    .directory()
                    .payload()
                    .candidates
                    .iter()
                    .map(|candidate| candidate.node_id.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl WanRelayAccess {
    pub fn binding(&self) -> &WanSessionBinding {
        &self.binding
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn directory_id(&self) -> &str {
        &self.verified.directory().payload().directory_id
    }

    pub fn credential_for(&self, node_id: &str) -> Option<&ServiceTurnRelayCredentials> {
        self.verified.credentials_for(node_id)
    }

    pub fn verified(&self) -> &Arc<VerifiedRelayAccess> {
        &self.verified
    }

    pub fn safe_snapshot(&self) -> WanRelayAccessSnapshot {
        WanRelayAccessSnapshot {
            session_id: self.binding.session_id.0.clone(),
            controller_device_id: self.binding.controller_device_id.0.clone(),
            target_device_id: self.binding.target_device_id.0.clone(),
            generation: self.generation,
            directory_id: self.directory_id().to_owned(),
            candidate_node_ids: self
                .verified
                .directory()
                .payload()
                .candidates
                .iter()
                .map(|candidate| candidate.node_id.clone())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WanRelayAccessSnapshot {
    pub session_id: String,
    pub controller_device_id: String,
    pub target_device_id: String,
    pub generation: u64,
    pub directory_id: String,
    pub candidate_node_ids: Vec<String>,
}

#[async_trait]
pub trait WanSessionBackend: Send + Sync {
    async fn create(
        &self,
        request: &WanSessionRequestV3,
    ) -> Result<WanSessionRecord, WanSessionBackendError>;
    async fn inspect(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError>;
    async fn approve(
        &self,
        binding: &WanSessionBinding,
        approval: &WanSessionApproval,
    ) -> Result<WanSessionRecord, WanSessionBackendError>;
    async fn reject(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError>;
    async fn close(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError>;
    async fn revoke(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError>;
    async fn access(
        &self,
        request: &WanRelayAccessRequest,
    ) -> Result<WanRelayAccess, WanSessionBackendError>;
}

pub struct HttpWanSessionBackend {
    config: WanSessionBackendConfig,
    client: reqwest::Client,
}

impl fmt::Debug for HttpWanSessionBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpWanSessionBackend")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl HttpWanSessionBackend {
    pub fn new(config: WanSessionBackendConfig) -> Result<Self, WanSessionBackendError> {
        let client = reqwest::Client::builder()
            .https_only(!config.permits_cleartext_loopback())
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.operation_deadline())
            .build()
            .map_err(|_| WanSessionBackendError::InvalidConfiguration)?;
        Ok(Self { config, client })
    }

    fn endpoint(&self, relative: &str) -> Result<Url, WanSessionBackendError> {
        self.config
            .base_url()
            .join(relative)
            .map_err(|_| WanSessionBackendError::InvalidConfiguration)
    }

    async fn execute_json<B: Serialize + ?Sized>(
        &self,
        method: Method,
        endpoint: Url,
        body: Option<&B>,
    ) -> Result<Zeroizing<Vec<u8>>, WanSessionBackendError> {
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| WanSessionBackendError::InvalidRequest)?;
        let deadline = Instant::now() + self.config.operation_deadline();
        for attempt in 1..=self.config.max_attempts() {
            let mut authorization =
                Zeroizing::new(format!("Bearer {}", self.config.device_token()));
            let mut authorization_header = HeaderValue::from_str(&authorization)
                .map_err(|_| WanSessionBackendError::InvalidConfiguration)?;
            authorization_header.set_sensitive(true);
            authorization.clear();
            let mut request = self
                .client
                .request(method.clone(), endpoint.clone())
                .header("X-Rdesk-Device-Authorization", authorization_header);
            if let Some(body) = &body {
                request = request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.clone());
            }
            let response = match timeout_at(deadline, request.send()).await {
                Err(_) => return Err(WanSessionBackendError::DeadlineExceeded),
                Ok(Err(_)) if attempt < self.config.max_attempts() => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Ok(Err(_)) => return Err(WanSessionBackendError::Unavailable),
                Ok(Ok(response)) => response,
            };
            let status = response.status();
            if is_retryable_status(status) && attempt < self.config.max_attempts() {
                tokio::task::yield_now().await;
                continue;
            }
            if !status.is_success() {
                return Err(map_status(status));
            }
            return match timeout_at(deadline, self.read_bounded(response)).await {
                Err(_) => Err(WanSessionBackendError::DeadlineExceeded),
                Ok(result) => result,
            };
        }
        Err(WanSessionBackendError::Unavailable)
    }

    async fn read_bounded(
        &self,
        response: reqwest::Response,
    ) -> Result<Zeroizing<Vec<u8>>, WanSessionBackendError> {
        if response
            .content_length()
            .is_some_and(|length| length > self.config.max_body_bytes() as u64)
        {
            return Err(WanSessionBackendError::ResponseTooLarge);
        }
        let mut body = Zeroizing::new(Vec::new());
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| WanSessionBackendError::Unavailable)?;
            if body.len().saturating_add(chunk.len()) > self.config.max_body_bytes() {
                return Err(WanSessionBackendError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn session_operation<B: Serialize + ?Sized>(
        &self,
        method: Method,
        relative: &str,
        body: Option<&B>,
        binding: &WanSessionBinding,
        expected_status: Option<WanSessionStatus>,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        let bytes = self
            .execute_json(method, self.endpoint(relative)?, body)
            .await?;
        let record = parse_record(&bytes, binding)?;
        if expected_status.is_some_and(|expected| record.status != expected) {
            return Err(WanSessionBackendError::BindingMismatch);
        }
        Ok(record)
    }
}

#[async_trait]
impl WanSessionBackend for HttpWanSessionBackend {
    async fn create(
        &self,
        request: &WanSessionRequestV3,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        request
            .validate()
            .map_err(|_| WanSessionBackendError::InvalidRequest)?;
        let binding = WanSessionBinding::new(
            request.session_id.clone(),
            request.controller_device_id.clone(),
            request.target_device_id.clone(),
        )?;
        let body = DeviceSessionCreateBody::from(request);
        let record = self
            .session_operation(Method::POST, "device-sessions", Some(&body), &binding, None)
            .await?;
        if &record.request != request {
            return Err(WanSessionBackendError::BindingMismatch);
        }
        Ok(record)
    }

    async fn inspect(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        self.session_operation::<()>(
            Method::GET,
            &format!("device-sessions/{}", binding.session_id.0),
            None,
            binding,
            None,
        )
        .await
    }

    async fn approve(
        &self,
        binding: &WanSessionBinding,
        approval: &WanSessionApproval,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        let body = DeviceSessionApprovalBody {
            approved_scopes: approval.approved_scopes.clone(),
            approved_profile: approval.approved_profile.clone(),
        };
        self.session_operation(
            Method::POST,
            &format!("device-sessions/{}/approve", binding.session_id.0),
            Some(&body),
            binding,
            Some(WanSessionStatus::Approved),
        )
        .await
    }

    async fn reject(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        self.transition(binding, "reject", WanSessionStatus::Rejected)
            .await
    }

    async fn close(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        self.transition(binding, "close", WanSessionStatus::Closed)
            .await
    }

    async fn revoke(
        &self,
        binding: &WanSessionBinding,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        self.transition(binding, "revoke", WanSessionStatus::Revoked)
            .await
    }

    async fn access(
        &self,
        request: &WanRelayAccessRequest,
    ) -> Result<WanRelayAccess, WanSessionBackendError> {
        let context = if request.refresh {
            RelayAccessContext::for_refresh(
                request.binding.session_id.0.clone(),
                request.policy_revision,
                request.binding.target_device_id.0.clone(),
                request.generation,
            )
        } else {
            RelayAccessContext::for_generation(
                request.binding.session_id.0.clone(),
                request.policy_revision,
                request.binding.target_device_id.0.clone(),
                request.generation,
            )
        }
        .map_err(map_relay_error)?;
        let body = self
            .execute_json(
                Method::POST,
                self.endpoint("relays/access")?,
                Some(&context),
            )
            .await?;
        let verified = verify_relay_access_response(
            &context,
            self.config.trusted_directory_keys(),
            &body,
            system_now_ms(),
        )
        .map_err(map_relay_error)?;
        Ok(WanRelayAccess {
            binding: request.binding.clone(),
            generation: request.generation,
            verified: Arc::new(verified),
        })
    }
}

impl HttpWanSessionBackend {
    async fn transition(
        &self,
        binding: &WanSessionBinding,
        action: &str,
        expected_status: WanSessionStatus,
    ) -> Result<WanSessionRecord, WanSessionBackendError> {
        self.session_operation(
            Method::POST,
            &format!("device-sessions/{}/{}", binding.session_id.0, action),
            Some(&EmptyBody {}),
            binding,
            Some(expected_status),
        )
        .await
    }
}

#[derive(Serialize)]
struct DeviceSessionCreateBody {
    session_id: SessionId,
    idempotency_key: [u8; 16],
    target_device_id: DeviceId,
    access_mode: WanAccessModeV3,
    requested_scopes: Vec<WanPermissionScopeV3>,
    requested_profile: Option<WanMediaProfileV3>,
    route_policy: WanRoutePolicyV3,
}

impl From<&WanSessionRequestV3> for DeviceSessionCreateBody {
    fn from(request: &WanSessionRequestV3) -> Self {
        Self {
            session_id: request.session_id.clone(),
            idempotency_key: request.idempotency_key,
            target_device_id: request.target_device_id.clone(),
            access_mode: request.access_mode,
            requested_scopes: request.requested_scopes.clone(),
            requested_profile: request.requested_profile.clone(),
            route_policy: request.route_policy,
        }
    }
}

#[derive(Serialize)]
struct DeviceSessionApprovalBody {
    approved_scopes: Vec<WanPermissionScopeV3>,
    approved_profile: Option<WanMediaProfileV3>,
}

#[derive(Serialize)]
struct EmptyBody {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeviceSessionOut {
    session_id: SessionId,
    request: WanSessionRequestV3,
    request_commitment: String,
    status: WanSessionStatus,
    approved_scopes: Option<Vec<WanPermissionScopeV3>>,
    approved_profile: Option<WanMediaProfileV3>,
    policy_revision: Option<u64>,
    policy_expires_at: Option<String>,
    grant_expires_at: Option<String>,
    active_relay_generation: Option<u64>,
}

fn parse_record(
    body: &[u8],
    expected: &WanSessionBinding,
) -> Result<WanSessionRecord, WanSessionBackendError> {
    let raw: RawDeviceSessionOut =
        serde_json::from_slice(body).map_err(|_| WanSessionBackendError::InvalidResponse)?;
    raw.request
        .validate()
        .map_err(|_| WanSessionBackendError::InvalidResponse)?;
    let binding = WanSessionBinding::new(
        raw.session_id.clone(),
        raw.request.controller_device_id.clone(),
        raw.request.target_device_id.clone(),
    )
    .map_err(|_| WanSessionBackendError::InvalidResponse)?;
    let commitment = raw
        .request
        .commitment()
        .map_err(|_| WanSessionBackendError::InvalidResponse)?;
    if &binding != expected
        || raw.request.session_id != raw.session_id
        || raw.request_commitment != commitment
        || !is_sha256_hex(&raw.request_commitment)
    {
        return Err(WanSessionBackendError::BindingMismatch);
    }
    if let Some(scopes) = &raw.approved_scopes {
        validate_scopes(scopes).map_err(|_| WanSessionBackendError::InvalidResponse)?;
        if scopes
            .iter()
            .any(|scope| !raw.request.requested_scopes.contains(scope))
        {
            return Err(WanSessionBackendError::BindingMismatch);
        }
    }
    if let Some(profile) = &raw.approved_profile {
        validate_profile(profile).map_err(|_| WanSessionBackendError::InvalidResponse)?;
    }
    if raw
        .policy_revision
        .is_some_and(|revision| revision == 0 || revision > i64::MAX as u64)
        || raw
            .active_relay_generation
            .is_some_and(|generation| generation > i64::MAX as u64)
    {
        return Err(WanSessionBackendError::InvalidResponse);
    }
    let policy_expires_at_ms = parse_timestamp(raw.policy_expires_at.as_deref())?;
    let grant_expires_at_ms = parse_timestamp(raw.grant_expires_at.as_deref())?;
    if raw.status == WanSessionStatus::Approved
        && (raw.approved_scopes.is_none()
            || raw.policy_revision.is_none()
            || policy_expires_at_ms.is_none()
            || grant_expires_at_ms.is_none()
            || raw.active_relay_generation.is_none())
    {
        return Err(WanSessionBackendError::InvalidResponse);
    }
    Ok(WanSessionRecord {
        binding,
        request: raw.request,
        request_commitment: raw.request_commitment,
        status: raw.status,
        approved_scopes: raw.approved_scopes,
        approved_profile: raw.approved_profile,
        policy_revision: raw.policy_revision,
        policy_expires_at_ms,
        grant_expires_at_ms,
        active_relay_generation: raw.active_relay_generation,
    })
}

fn parse_timestamp(value: Option<&str>) -> Result<Option<u64>, WanSessionBackendError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| WanSessionBackendError::InvalidResponse)?;
    u64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .map(Some)
        .map_err(|_| WanSessionBackendError::InvalidResponse)
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), WanSessionBackendError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(WanSessionBackendError::InvalidRequest);
    }
    Ok(())
}

fn validate_scopes(scopes: &[WanPermissionScopeV3]) -> Result<(), WanSessionBackendError> {
    if scopes.is_empty()
        || scopes.len() > MAX_SCOPES
        || scopes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(WanSessionBackendError::InvalidRequest);
    }
    Ok(())
}

fn validate_profile(profile: &WanMediaProfileV3) -> Result<(), WanSessionBackendError> {
    if profile.width == 0
        || profile.width > 16_384
        || profile.height == 0
        || profile.height > 16_384
        || profile.fps == 0
        || profile.fps > 240
        || profile.bitrate_mbps == 0
        || profile.bitrate_mbps > 1_000
        || !is_normalized_token(&profile.codec, 32)
        || profile
            .bit_depth
            .is_some_and(|value| value != 8 && value != 10)
        || [
            profile.codec_profile.as_deref(),
            profile.chroma_subsampling.as_deref(),
            profile.pixel_format.as_deref(),
            profile.color_mode.as_deref(),
            profile.color_pipeline.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| !is_normalized_token(value, 64))
    {
        return Err(WanSessionBackendError::InvalidRequest);
    }
    Ok(())
}

fn is_normalized_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'+' | b'-')
        })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn map_status(status: StatusCode) -> WanSessionBackendError {
    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            WanSessionBackendError::InvalidRequest
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => WanSessionBackendError::Unauthorized,
        StatusCode::NOT_FOUND => WanSessionBackendError::NotFound,
        StatusCode::CONFLICT => WanSessionBackendError::Conflict,
        StatusCode::PAYLOAD_TOO_LARGE => WanSessionBackendError::ResponseTooLarge,
        status if is_retryable_status(status) => WanSessionBackendError::Unavailable,
        _ => WanSessionBackendError::InvalidResponse,
    }
}

fn map_relay_error(error: RelayClientError) -> WanSessionBackendError {
    match error {
        RelayClientError::InvalidContext => WanSessionBackendError::InvalidRequest,
        RelayClientError::BackendUnavailable => WanSessionBackendError::Unavailable,
        RelayClientError::Unauthorized => WanSessionBackendError::Unauthorized,
        RelayClientError::InvalidResponse => WanSessionBackendError::InvalidResponse,
        RelayClientError::CredentialBinding | RelayClientError::Directory(_) => {
            WanSessionBackendError::BindingMismatch
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum WanSessionBackendError {
    #[error("WAN session backend configuration is invalid")]
    InvalidConfiguration,
    #[error("WAN session request is invalid")]
    InvalidRequest,
    #[error("WAN session backend is unavailable")]
    Unavailable,
    #[error("WAN session operation exceeded its deadline")]
    DeadlineExceeded,
    #[error("WAN session device is unauthorized")]
    Unauthorized,
    #[error("WAN session was not found")]
    NotFound,
    #[error("WAN session state conflicts")]
    Conflict,
    #[error("WAN session backend response is too large")]
    ResponseTooLarge,
    #[error("WAN session backend response is invalid")]
    InvalidResponse,
    #[error("WAN session backend response does not match the requested binding")]
    BindingMismatch,
}
