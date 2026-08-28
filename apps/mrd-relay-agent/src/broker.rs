use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ring::hmac;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    config::globally_routable_ip,
    platform::{
        linux::{COTURN_CERT_CREDENTIAL_PATH, COTURN_KEY_CREDENTIAL_PATH},
        BrokerRequest, CoturnTarget, PlatformError, TransportCapability, FRAME_HEADER_BYTES,
        MAX_CONTROL_OUTPUT_BYTES, RAW_TURN_SECRET_BYTES,
    },
    process::SecretBytes,
};

#[cfg(target_os = "linux")]
mod linux_runtime;

#[cfg(target_os = "linux")]
pub use linux_runtime::{run_linux_socket_activated, run_linux_wsl_broker, BrokerRuntimeError};

#[cfg(windows)]
mod windows_runtime;

#[cfg(windows)]
pub use windows_runtime::{run_windows_service, BrokerRuntimeError};

const MAX_CONFIG_BYTES: usize = 128 * 1024;
const MAX_DOCKER_STATS_RESPONSE_BYTES: usize = 1024 * 1024;
const CANONICAL_TURN_SECRET_BYTES: usize = 43;
const SECRET_PLACEHOLDER: &str = "__MRD_BROKER_SECRET_V1__";
const BASELINE_CERTIFICATE_PATH: &str = "/etc/mrd-relay-agent/tls/fullchain.pem";
const BASELINE_PRIVATE_KEY_PATH: &str = "/etc/mrd-relay-agent/tls/privkey.pem";
const REQUIRED_SINGLETON_DIRECTIVES: &[&str] = &[
    "listening-port",
    "tls-listening-port",
    "listening-ip",
    "fingerprint",
    "realm",
    "server-name",
    "use-auth-secret",
    "static-auth-secret",
    "rest-api-separator",
    "unauthorized-ratelimit",
    "unauthorized-ratelimit-rps",
    "user-quota",
    "total-quota",
    "max-bps",
    "bps-capacity",
    "min-port",
    "max-port",
    "stale-nonce",
    "max-allocate-timeout",
    "max-allocate-lifetime",
    "cert",
    "pkey",
    "no-tlsv1",
    "no-tlsv1_1",
    "no-multicast-peers",
    "no-cli",
    "no-rfc5780",
    "no-software-attribute",
    "prometheus",
    "prometheus-address",
    "prometheus-port",
    "prometheus-path",
    "drain-min-allocations",
    "simple-log",
    "log-file",
];
const REQUIRED_DENIED_PEER_RANGES: &[&str] = &[
    "0.0.0.0-0.255.255.255",
    "10.0.0.0-10.255.255.255",
    "100.64.0.0-100.127.255.255",
    "127.0.0.0-127.255.255.255",
    "169.254.0.0-169.254.255.255",
    "172.16.0.0-172.31.255.255",
    "192.0.0.0-192.0.0.255",
    "192.168.0.0-192.168.255.255",
    "198.18.0.0-198.19.255.255",
    "::1",
    "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DockerNetworkCounters {
    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
}

#[derive(Deserialize)]
struct DockerStatsBody {
    networks: BTreeMap<String, DockerNetworkStats>,
}

#[derive(Deserialize)]
struct DockerNetworkStats {
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Parse one bounded Docker Engine HTTP response and preserve the raw byte
/// counter semantics. This deliberately does not accept the human-readable,
/// rounded `docker stats` CLI output.
pub fn parse_docker_engine_stats_http(
    response: &[u8],
) -> Result<DockerNetworkCounters, PlatformError> {
    if response.is_empty() || response.len() > MAX_DOCKER_STATS_RESPONSE_BYTES {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(PlatformError::ControlFrameInvalid)?;
    let header_bytes = &response[..header_end];
    if !header_bytes.is_ascii() || header_bytes.contains(&0) {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let headers =
        std::str::from_utf8(header_bytes).map_err(|_| PlatformError::ControlFrameInvalid)?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(PlatformError::ControlFrameInvalid);
    }

    let mut content_length = None;
    let mut chunked = false;
    let mut content_type_is_json = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(PlatformError::ControlFrameInvalid)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(PlatformError::ControlFrameInvalid);
        }
        let value = value.trim_ascii();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(PlatformError::ControlFrameInvalid);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| PlatformError::ControlFrameInvalid)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(PlatformError::ControlFrameInvalid);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type_is_json {
                return Err(PlatformError::ControlFrameInvalid);
            }
            content_type_is_json = value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"));
        }
    }
    if !content_type_is_json {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let body_start = header_end
        .checked_add(4)
        .ok_or(PlatformError::ControlFrameInvalid)?;
    if content_length.is_some() == chunked {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let body = if let Some(content_length) = content_length {
        let body_end = body_start
            .checked_add(content_length)
            .ok_or(PlatformError::ControlFrameInvalid)?;
        if body_end != response.len() || content_length == 0 {
            return Err(PlatformError::ControlFrameInvalid);
        }
        response[body_start..body_end].to_vec()
    } else {
        decode_chunked_body(&response[body_start..])?
    };

    let body: DockerStatsBody =
        serde_json::from_slice(&body).map_err(|_| PlatformError::ControlFrameInvalid)?;
    if body.networks.is_empty() || body.networks.len() > 32 {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let mut total_ingress_bytes = 0_u64;
    let mut total_egress_bytes = 0_u64;
    for (name, counters) in body.networks {
        if name.is_empty() || name.len() > 64 || name.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(PlatformError::ControlFrameInvalid);
        }
        total_ingress_bytes = total_ingress_bytes
            .checked_add(counters.rx_bytes)
            .ok_or(PlatformError::ControlFrameInvalid)?;
        total_egress_bytes = total_egress_bytes
            .checked_add(counters.tx_bytes)
            .ok_or(PlatformError::ControlFrameInvalid)?;
    }
    Ok(DockerNetworkCounters {
        total_ingress_bytes,
        total_egress_bytes,
    })
}

fn decode_chunked_body(encoded: &[u8]) -> Result<Vec<u8>, PlatformError> {
    let mut cursor = 0_usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .and_then(|offset| cursor.checked_add(offset))
            .ok_or(PlatformError::ControlFrameInvalid)?;
        let size_bytes = &encoded[cursor..line_end];
        if size_bytes.is_empty()
            || size_bytes.len() > 16
            || !size_bytes.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(PlatformError::ControlFrameInvalid);
        }
        let size = usize::from_str_radix(
            std::str::from_utf8(size_bytes).map_err(|_| PlatformError::ControlFrameInvalid)?,
            16,
        )
        .map_err(|_| PlatformError::ControlFrameInvalid)?;
        cursor = line_end
            .checked_add(2)
            .ok_or(PlatformError::ControlFrameInvalid)?;
        if size == 0 {
            return if encoded.get(cursor..) == Some(b"\r\n") && !decoded.is_empty() {
                Ok(decoded)
            } else {
                Err(PlatformError::ControlFrameInvalid)
            };
        }
        let data_end = cursor
            .checked_add(size)
            .ok_or(PlatformError::ControlFrameInvalid)?;
        let chunk_end = data_end
            .checked_add(2)
            .ok_or(PlatformError::ControlFrameInvalid)?;
        if chunk_end > encoded.len() || encoded.get(data_end..chunk_end) != Some(b"\r\n") {
            return Err(PlatformError::ControlFrameInvalid);
        }
        if decoded
            .len()
            .checked_add(size)
            .is_none_or(|length| length > MAX_DOCKER_STATS_RESPONSE_BYTES)
        {
            return Err(PlatformError::ControlFrameInvalid);
        }
        decoded.extend_from_slice(&encoded[cursor..data_end]);
        cursor = chunk_end;
    }
}

/// Decode one already-bounded broker frame. Ownership is deliberate: request
/// buffers may contain the raw TURN secret and are zeroized on every return.
pub fn decode_request_frame(encoded: Zeroizing<Vec<u8>>) -> Result<BrokerRequest, PlatformError> {
    if encoded.len() < FRAME_HEADER_BYTES
        || encoded.len() > FRAME_HEADER_BYTES + 48 + RAW_TURN_SECRET_BYTES
    {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let header: [u8; FRAME_HEADER_BYTES] = encoded[..FRAME_HEADER_BYTES]
        .try_into()
        .map_err(|_| PlatformError::ControlFrameInvalid)?;
    BrokerRequest::validate_header(header)?;
    let metadata_len = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| PlatformError::ControlFrameInvalid)?,
    ) as usize;
    let secret_len = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| PlatformError::ControlFrameInvalid)?,
    ) as usize;
    let expected_len = FRAME_HEADER_BYTES
        .checked_add(metadata_len)
        .and_then(|value| value.checked_add(secret_len))
        .ok_or(PlatformError::ControlFrameInvalid)?;
    if encoded.len() != expected_len {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let metadata_end = FRAME_HEADER_BYTES + metadata_len;
    let metadata = encoded[FRAME_HEADER_BYTES..metadata_end].to_vec();
    let secret = (secret_len != 0).then(|| SecretBytes::new(encoded[metadata_end..].to_vec()));
    BrokerRequest::from_frame_parts(header, metadata, secret)
}

/// Encode exactly one JSON object response with a bounded big-endian length.
pub fn encode_response_frame(payload: &[u8]) -> Result<Vec<u8>, PlatformError> {
    if payload.is_empty() || payload.len() > MAX_CONTROL_OUTPUT_BYTES {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| PlatformError::ControlFrameInvalid)?;
    if !value.is_object() {
        return Err(PlatformError::ControlFrameInvalid);
    }
    let length = u32::try_from(payload.len()).map_err(|_| PlatformError::ControlFrameInvalid)?;
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketActivationClaim {
    pub current_pid: u32,
    pub listen_pid: u32,
    pub listen_fds: u32,
    pub first_fd: i32,
    pub fd_is_connected_unix_stream: bool,
}

pub fn validate_socket_activation(claim: &SocketActivationClaim) -> Result<(), PlatformError> {
    if claim.current_pid == 0
        || claim.listen_pid != claim.current_pid
        || claim.listen_fds != 1
        || claim.first_fd != 3
        || !claim.fd_is_connected_unix_stream
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxClientPeerClaim {
    pub peer_uid: u32,
    pub expected_agent_uid: u32,
    pub peer_pid: u32,
}

pub fn validate_linux_client_peer(claim: &LinuxClientPeerClaim) -> Result<(), PlatformError> {
    if claim.peer_pid == 0
        || claim.expected_agent_uid == 0
        || claim.peer_uid != claim.expected_agent_uid
    {
        return Err(PlatformError::PeerIdentityInvalid);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeStabilityObservation {
    pub target: CoturnTarget,
    pub generation: u64,
    pub applied_secret_version: u64,
    pub epoch: String,
    pub active: bool,
    pub draining: bool,
    pub external_restart_detected: bool,
}

/// A successful relay exchange is evidence for the committed target only when
/// the exact target identity remains live across the whole network roundtrip.
pub fn validate_probe_stability(
    before: &ProbeStabilityObservation,
    after: &ProbeStabilityObservation,
) -> Result<(), PlatformError> {
    if before.target != after.target
        || before.generation == 0
        || before.applied_secret_version == 0
        || before.epoch.is_empty()
        || before.epoch.len() > 128
        || !before.epoch.is_ascii()
        || before != after
        || !before.active
        || before.draining
        || before.external_restart_detected
    {
        return Err(PlatformError::ControlFrameInvalid);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRecoveryObservation {
    pub committed_marker_matches_desired: bool,
    pub desired_secret_and_config_match: bool,
    pub previous_invocation: Option<String>,
    pub current_invocation: Option<String>,
    pub target_active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRecoveryAction {
    RemoveJournal,
    Commit,
    RestartAndVerify,
    Rollback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsPendingRecoveryObservation {
    pub committed_marker_matches_desired: bool,
    pub active_secret_matches_desired: bool,
    pub target_config_matches_desired: bool,
    pub target_reports_desired_version: bool,
    pub previous_epoch: Option<String>,
    pub current_epoch: Option<String>,
    pub target_active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsPendingRecoveryAction {
    RemoveJournal,
    CommitDesired,
    RetryDesired,
    FailClosed,
}

/// Chooses a recovery action without guessing which secret a Windows target
/// loaded. A desired version is committed only when both the target's protected
/// version evidence and a new live target epoch agree. If the old epoch is
/// still active, replaying the idempotent desired transaction is safe. Every
/// ambiguous split-brain shape remains fail-closed with the DPAPI journal kept.
pub fn select_windows_pending_recovery(
    observation: &WindowsPendingRecoveryObservation,
) -> WindowsPendingRecoveryAction {
    if observation.committed_marker_matches_desired {
        return if observation.active_secret_matches_desired
            && observation.target_config_matches_desired
            && observation.target_reports_desired_version
            && observation.target_active
        {
            WindowsPendingRecoveryAction::RemoveJournal
        } else {
            WindowsPendingRecoveryAction::FailClosed
        };
    }

    let epoch_advanced = observation.current_epoch.is_some()
        && observation.current_epoch != observation.previous_epoch;
    if observation.target_active
        && epoch_advanced
        && observation.target_config_matches_desired
        && observation.target_reports_desired_version
    {
        return WindowsPendingRecoveryAction::CommitDesired;
    }

    let old_target_still_observed = observation.current_epoch == observation.previous_epoch;
    let fresh_target_not_started = observation.previous_epoch.is_none()
        && observation.current_epoch.is_none()
        && !observation.target_active;
    if observation.target_config_matches_desired
        && !observation.target_reports_desired_version
        && (old_target_still_observed || fresh_target_not_started)
    {
        return WindowsPendingRecoveryAction::RetryDesired;
    }

    WindowsPendingRecoveryAction::FailClosed
}

/// Select the only safe recovery path for an interrupted secret transaction.
/// File bytes alone never prove which credentials a live process loaded.
pub fn select_pending_recovery(observation: &PendingRecoveryObservation) -> PendingRecoveryAction {
    if observation.committed_marker_matches_desired && observation.desired_secret_and_config_match {
        return PendingRecoveryAction::RemoveJournal;
    }
    if !observation.desired_secret_and_config_match {
        return PendingRecoveryAction::Rollback;
    }
    let invocation_advanced = match (
        observation.previous_invocation.as_deref(),
        observation.current_invocation.as_deref(),
    ) {
        (Some(previous), Some(current)) => previous != current,
        (None, Some(_)) => true,
        _ => false,
    };
    if observation.target_active && invocation_advanced {
        PendingRecoveryAction::Commit
    } else {
        PendingRecoveryAction::RestartAndVerify
    }
}

pub struct RenderedCoturnConfig {
    bytes: Zeroizing<Vec<u8>>,
    configured_max_allocations: u32,
    configured_max_egress_bps: u64,
    relay_min_port: u16,
    relay_max_port: u16,
    transport_capabilities: Vec<TransportCapability>,
    configured_endpoints: Vec<String>,
}

impl fmt::Debug for RenderedCoturnConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedCoturnConfig")
            .field("bytes", &"REDACTED")
            .field(
                "configured_max_allocations",
                &self.configured_max_allocations,
            )
            .field("configured_max_egress_bps", &self.configured_max_egress_bps)
            .field("relay_min_port", &self.relay_min_port)
            .field("relay_max_port", &self.relay_max_port)
            .field("transport_capabilities", &self.transport_capabilities)
            .field("configured_endpoints", &self.configured_endpoints)
            .finish()
    }
}

impl RenderedCoturnConfig {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn configured_max_allocations(&self) -> u32 {
        self.configured_max_allocations
    }

    pub const fn configured_max_egress_bps(&self) -> u64 {
        self.configured_max_egress_bps
    }

    pub const fn relay_ports(&self) -> (u16, u16) {
        (self.relay_min_port, self.relay_max_port)
    }

    pub fn transport_capabilities(&self) -> &[TransportCapability] {
        &self.transport_capabilities
    }

    pub fn configured_endpoints(&self) -> &[String] {
        &self.configured_endpoints
    }
}

/// Short-lived TURN REST material for a broker-owned live allocation probe.
/// Both fields zeroize on drop and the type deliberately has no `Debug`
/// implementation because the credential is an authentication secret.
pub struct CoturnRestCredentials {
    username: Zeroizing<String>,
    credential: Zeroizing<String>,
}

impl CoturnRestCredentials {
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    pub fn credential(&self) -> &str {
        self.credential.as_str()
    }
}

/// Derive coturn's REST credential using the exact canonical base64url string
/// configured as `static-auth-secret`, rather than its decoded entropy bytes.
pub fn derive_coturn_rest_credentials(
    raw_secret: &[u8],
    username: &str,
) -> Result<CoturnRestCredentials, PlatformError> {
    if raw_secret.len() != RAW_TURN_SECRET_BYTES || username.len() > 407 || !username.is_ascii() {
        return Err(PlatformError::ConfigInvalid);
    }
    let mut components = username.split(':');
    let expiry = components.next().ok_or(PlatformError::ConfigInvalid)?;
    let scope = components.next().ok_or(PlatformError::ConfigInvalid)?;
    let nonce = components.next().ok_or(PlatformError::ConfigInvalid)?;
    let target = components.next().ok_or(PlatformError::ConfigInvalid)?;
    if components.next().is_some()
        || expiry.is_empty()
        || expiry.len() > 20
        || expiry.starts_with('0')
        || !expiry.bytes().all(|byte| byte.is_ascii_digit())
        || expiry
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .map(|value| value.to_string())
            .as_deref()
            != Some(expiry)
        || !safe_turn_username_component(scope)
        || !safe_turn_username_component(nonce)
        || !safe_turn_username_component(target)
    {
        return Err(PlatformError::ConfigInvalid);
    }

    let canonical_secret = canonical_turn_secret_bytes(raw_secret)?;
    let key = hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        canonical_secret.as_slice(),
    );
    let signature = hmac::sign(&key, username.as_bytes());
    let mut credential = Zeroizing::new(String::with_capacity(28));
    STANDARD.encode_string(signature.as_ref(), &mut credential);
    let mut owned_username = Zeroizing::new(String::with_capacity(username.len()));
    owned_username.push_str(username);
    Ok(CoturnRestCredentials {
        username: owned_username,
        credential,
    })
}

pub(crate) fn canonical_turn_secret_bytes(
    raw_secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    if raw_secret.len() != RAW_TURN_SECRET_BYTES {
        return Err(PlatformError::ConfigInvalid);
    }
    let mut encoded = Zeroizing::new(vec![0_u8; CANONICAL_TURN_SECRET_BYTES]);
    let written = URL_SAFE_NO_PAD
        .encode_slice(raw_secret, encoded.as_mut_slice())
        .map_err(|_| PlatformError::ConfigInvalid)?;
    if written != CANONICAL_TURN_SECRET_BYTES {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(encoded)
}

fn safe_turn_username_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Render the complete root-only coturn configuration from a trusted template
/// and the raw 32-byte active secret. Every security-relevant scalar must be
/// present exactly once; bytes/s are checked and converted to bits/s.
pub fn render_linux_coturn_config(
    template: &[u8],
    raw_secret: &[u8],
) -> Result<RenderedCoturnConfig, PlatformError> {
    render_coturn_config(
        template,
        raw_secret,
        COTURN_CERT_CREDENTIAL_PATH,
        COTURN_KEY_CREDENTIAL_PATH,
    )
}

/// Render a coturn configuration for a broker-owned target namespace. TLS
/// paths are literal target paths (for example a read-only Docker mount) and
/// are never inferred from ambient environment or shell-expanded input.
pub fn render_coturn_config(
    template: &[u8],
    raw_secret: &[u8],
    certificate_path: &str,
    private_key_path: &str,
) -> Result<RenderedCoturnConfig, PlatformError> {
    if template.is_empty()
        || template.len() > MAX_CONFIG_BYTES
        || raw_secret.len() != RAW_TURN_SECRET_BYTES
        || !safe_target_config_path(certificate_path)
        || !safe_target_config_path(private_key_path)
        || certificate_path == private_key_path
    {
        return Err(PlatformError::ConfigInvalid);
    }
    let template = std::str::from_utf8(template).map_err(|_| PlatformError::ConfigInvalid)?;
    // `str::lines` accepts both LF and CRLF and removes their terminators. This
    // lets the same trusted template work from ordinary Windows checkouts while
    // the directive validator below still rejects a lone or embedded carriage
    // return as non-canonical whitespace. Rendered output is always normalized
    // to LF by `append_zeroizing_config_line`.
    if !template.is_ascii()
        || template.contains('\0')
        || template.as_bytes().iter().enumerate().any(|(index, byte)| {
            *byte == b'\r' && template.as_bytes().get(index + 1) != Some(&b'\n')
        })
    {
        return Err(PlatformError::ConfigInvalid);
    }
    validate_coturn_template_semantics(template)?;
    let secret = canonical_turn_secret_bytes(raw_secret)?;

    let mut output = Zeroizing::new(Vec::with_capacity(MAX_CONFIG_BYTES));
    let mut listening_port = None;
    let mut tls_port = None;
    let mut server_name = None;
    let mut allocations = None;
    let mut capacity_bytes = None;
    let mut relay_min = None;
    let mut relay_max = None;
    let mut placeholder_count = 0_u8;
    let mut cert_count = 0_u8;
    let mut key_count = 0_u8;
    let mut no_udp = false;
    let mut no_tcp = false;
    let mut no_tls = false;

    for line in template.lines() {
        if line.len() > 4096 {
            return Err(PlatformError::ConfigInvalid);
        }
        if let Some(value) = line.strip_prefix("static-auth-secret=") {
            if value != SECRET_PLACEHOLDER || placeholder_count != 0 {
                return Err(PlatformError::ConfigInvalid);
            }
            placeholder_count = 1;
            append_zeroizing_config_line(
                &mut output,
                &[b"static-auth-secret=", secret.as_slice()],
            )?;
        } else if line.starts_with("cert=") {
            cert_count = cert_count
                .checked_add(1)
                .ok_or(PlatformError::ConfigInvalid)?;
            append_zeroizing_config_line(&mut output, &[b"cert=", certificate_path.as_bytes()])?;
        } else if line.starts_with("pkey=") {
            key_count = key_count
                .checked_add(1)
                .ok_or(PlatformError::ConfigInvalid)?;
            append_zeroizing_config_line(&mut output, &[b"pkey=", private_key_path.as_bytes()])?;
        } else {
            if !line.starts_with('#') && !line.is_empty() {
                if let Some((key, value)) = line.split_once('=') {
                    match key {
                        "listening-port" => set_once(&mut listening_port, parse_u16(value)?)?,
                        "tls-listening-port" => set_once(&mut tls_port, parse_u16(value)?)?,
                        "server-name" => {
                            if !valid_dns_name(value)
                                || server_name.replace(value.to_owned()).is_some()
                            {
                                return Err(PlatformError::ConfigInvalid);
                            }
                        }
                        "total-quota" => set_once(&mut allocations, parse_u32(value)?)?,
                        "bps-capacity" => set_once(&mut capacity_bytes, parse_u64(value)?)?,
                        "min-port" => set_once(&mut relay_min, parse_u16(value)?)?,
                        "max-port" => set_once(&mut relay_max, parse_u16(value)?)?,
                        _ => {}
                    }
                } else {
                    match line {
                        "no-udp" => no_udp = true,
                        "no-tcp" => no_tcp = true,
                        "no-tls" => no_tls = true,
                        _ => {}
                    }
                }
            }
            append_zeroizing_config_line(&mut output, &[line.as_bytes()])?;
        }
    }

    if placeholder_count != 1 || cert_count != 1 || key_count != 1 {
        return Err(PlatformError::ConfigInvalid);
    }
    let listening_port = listening_port.ok_or(PlatformError::ConfigInvalid)?;
    let tls_port = tls_port.ok_or(PlatformError::ConfigInvalid)?;
    let server_name = server_name.ok_or(PlatformError::ConfigInvalid)?;
    let configured_max_allocations = allocations
        .filter(|value| *value != 0)
        .ok_or(PlatformError::ConfigInvalid)?;
    let configured_max_egress_bps = capacity_bytes
        .filter(|value| *value != 0)
        .and_then(|value| value.checked_mul(8))
        .ok_or(PlatformError::ConfigInvalid)?;
    let relay_min_port = relay_min.ok_or(PlatformError::ConfigInvalid)?;
    let relay_max_port = relay_max.ok_or(PlatformError::ConfigInvalid)?;
    if relay_min_port > relay_max_port || listening_port == tls_port || no_udp || no_tcp || no_tls {
        return Err(PlatformError::ConfigInvalid);
    }
    let transport_capabilities = vec![
        TransportCapability::TurnUdp,
        TransportCapability::TurnTcp,
        TransportCapability::TurnsTcp,
    ];
    let configured_endpoints = vec![
        format!("turn:{server_name}:{listening_port}?transport=udp"),
        format!("turn:{server_name}:{listening_port}?transport=tcp"),
        format!("turns:{server_name}:{tls_port}?transport=tcp"),
    ];
    Ok(RenderedCoturnConfig {
        bytes: output,
        configured_max_allocations,
        configured_max_egress_bps,
        relay_min_port,
        relay_max_port,
        transport_capabilities,
        configured_endpoints,
    })
}

fn append_zeroizing_config_line(
    output: &mut Zeroizing<Vec<u8>>,
    fragments: &[&[u8]],
) -> Result<(), PlatformError> {
    let line_bytes = fragments
        .iter()
        .try_fold(1_usize, |total, fragment| total.checked_add(fragment.len()));
    line_bytes
        .and_then(|line_bytes| output.len().checked_add(line_bytes))
        .filter(|final_len| *final_len <= MAX_CONFIG_BYTES)
        .ok_or(PlatformError::ConfigInvalid)?;
    for fragment in fragments {
        output.extend_from_slice(fragment);
    }
    output.push(b'\n');
    Ok(())
}

fn validate_coturn_template_semantics(template: &str) -> Result<(), PlatformError> {
    let mut seen = BTreeMap::<&str, u8>::new();
    let mut denied_peer_ranges = BTreeSet::new();
    let mut listening_ip = None;
    let mut relay_ip = None;
    let mut external_ip = None;
    for raw_line in template.lines() {
        if raw_line.len() > 4096 {
            return Err(PlatformError::ConfigInvalid);
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line != raw_line
            || line.bytes().any(|byte| byte.is_ascii_whitespace())
            || line.contains('#')
        {
            return Err(PlatformError::ConfigInvalid);
        }
        let (key, value) = match line.split_once('=') {
            Some((key, value)) if !key.is_empty() && !value.is_empty() => (key, Some(value)),
            Some(_) => return Err(PlatformError::ConfigInvalid),
            None => (line, None),
        };
        if matches!(
            key,
            "allow-loopback-peers" | "no-auth" | "lt-cred-mech" | "verbose" | "Verbose"
        ) {
            return Err(PlatformError::ConfigInvalid);
        }

        let count = seen.entry(key).or_default();
        *count = count.checked_add(1).ok_or(PlatformError::ConfigInvalid)?;
        if key != "denied-peer-ip" && *count != 1 {
            return Err(PlatformError::ConfigInvalid);
        }

        match (key, value) {
            (
                "fingerprint"
                | "use-auth-secret"
                | "unauthorized-ratelimit"
                | "no-tlsv1"
                | "no-tlsv1_1"
                | "no-multicast-peers"
                | "no-cli"
                | "no-rfc5780"
                | "no-software-attribute"
                | "prometheus"
                | "simple-log",
                None,
            ) => {}
            ("listening-port" | "tls-listening-port" | "min-port" | "max-port", Some(value))
                if canonical_positive_u64(value).is_some_and(|value| value <= u16::MAX as u64) => {}
            ("total-quota", Some(value))
                if canonical_positive_u64(value).is_some_and(|value| value <= u32::MAX as u64) => {}
            ("bps-capacity", Some(value))
                if canonical_positive_u64(value)
                    .and_then(|value| value.checked_mul(8))
                    .is_some() => {}
            ("realm" | "server-name", Some(value)) if valid_dns_name(value) => {}
            ("relay-ip", Some(value)) if valid_single_ip(value) => relay_ip = Some(value),
            ("external-ip", Some(value)) if valid_external_ip(value) => {
                external_ip = Some(value);
            }
            ("listening-ip", Some(value)) if valid_listener_ip(value) => {
                listening_ip = value.parse::<IpAddr>().ok();
            }
            ("static-auth-secret", Some(SECRET_PLACEHOLDER))
            | ("rest-api-separator", Some(":"))
            | ("unauthorized-ratelimit-rps", Some("10"))
            | ("user-quota", Some("4"))
            | ("max-bps", Some("25000000"))
            | ("stale-nonce", Some("600"))
            | ("max-allocate-timeout", Some("15"))
            | ("max-allocate-lifetime", Some("900"))
            | ("cert", Some(BASELINE_CERTIFICATE_PATH))
            | ("pkey", Some(BASELINE_PRIVATE_KEY_PATH))
            | ("prometheus-address", Some("127.0.0.1"))
            | ("prometheus-port", Some("9641"))
            | ("prometheus-path", Some("/metrics"))
            | ("drain-min-allocations", Some("0"))
            | ("log-file", Some("stdout")) => {}
            ("denied-peer-ip", Some(value))
                if REQUIRED_DENIED_PEER_RANGES.contains(&value)
                    && denied_peer_ranges.insert(value) => {}
            _ => return Err(PlatformError::ConfigInvalid),
        }
    }

    if REQUIRED_SINGLETON_DIRECTIVES
        .iter()
        .any(|key| seen.get(key).copied() != Some(1))
        || denied_peer_ranges.len() != REQUIRED_DENIED_PEER_RANGES.len()
        || REQUIRED_DENIED_PEER_RANGES
            .iter()
            .any(|range| !denied_peer_ranges.contains(range))
        || !valid_external_relay_binding(external_ip, relay_ip, listening_ip)
    {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(())
}

fn canonical_positive_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| *parsed != 0 && parsed.to_string() == value)
}

fn valid_single_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

fn valid_listener_ip(value: &str) -> bool {
    matches!(value, "0.0.0.0" | "::")
}

fn valid_external_ip(value: &str) -> bool {
    let mut addresses = value.split('/');
    let Some(public) = addresses.next() else {
        return false;
    };
    let Ok(public) = public.parse::<IpAddr>() else {
        return false;
    };
    if !globally_routable_ip(public) {
        return false;
    }
    let private = match addresses.next() {
        Some(private) => match private.parse::<IpAddr>() {
            Ok(private) => Some(private),
            Err(_) => return false,
        },
        None => None,
    };
    addresses.next().is_none() && private.is_none_or(|private| same_ip_family(public, private))
}

fn valid_external_relay_binding(
    external: Option<&str>,
    relay: Option<&str>,
    listener: Option<IpAddr>,
) -> bool {
    let Some(listener) = listener else {
        return false;
    };
    let Some(external) = external else {
        return relay.is_none_or(valid_single_ip);
    };
    let mut addresses = external.split('/');
    let Some(public) = addresses
        .next()
        .and_then(|value| value.parse::<IpAddr>().ok())
    else {
        return false;
    };
    let private_literal = addresses.next();
    if addresses.next().is_some() {
        return false;
    }
    let relay_address = relay.and_then(|value| value.parse::<IpAddr>().ok());
    if !same_ip_family(public, listener)
        || relay.is_some() != relay_address.is_some()
        || relay_address.is_some_and(|address| !same_ip_family(public, address))
    {
        return false;
    }
    match private_literal {
        Some(private) => relay.is_some_and(|relay| relay == private),
        None => true,
    }
}

const fn same_ip_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn safe_target_config_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.is_ascii()
        && value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains(['\0', '\r', '\n'])
        && !value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), PlatformError> {
    if slot.replace(value).is_some() {
        return Err(PlatformError::ConfigInvalid);
    }
    Ok(())
}

fn parse_u16(value: &str) -> Result<u16, PlatformError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(PlatformError::ConfigInvalid)
}

fn parse_u32(value: &str) -> Result<u32, PlatformError> {
    value
        .parse::<u32>()
        .map_err(|_| PlatformError::ConfigInvalid)
}

fn parse_u64(value: &str) -> Result<u64, PlatformError> {
    value
        .parse::<u64>()
        .map_err(|_| PlatformError::ConfigInvalid)
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.contains('.')
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}
