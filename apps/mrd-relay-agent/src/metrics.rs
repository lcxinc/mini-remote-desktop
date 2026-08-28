use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    str,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use reqwest::{redirect::Policy, Client};
use thiserror::Error;
use url::{Host, Url};

#[derive(Clone, Copy, Debug)]
pub struct MetricsLimits {
    pub max_input_bytes: usize,
    pub max_lines: usize,
    pub max_line_bytes: usize,
    pub max_fields: usize,
}

impl Default for MetricsLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_lines: 256,
            max_line_bytes: 512,
            max_fields: 32,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoturnMetrics {
    pub active_allocations: u32,
    pub current_ingress_bps: u64,
    pub current_egress_bps: u64,
    pub errors_total: u64,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MetricsError {
    #[error("relay_metrics_too_large")]
    TooLarge,
    #[error("relay_metrics_invalid")]
    Invalid,
    #[error("relay_metrics_unavailable")]
    Unavailable,
    #[error("relay_metrics_config_invalid")]
    ConfigInvalid,
    #[error("relay_metrics_counter_reset")]
    CounterReset,
}

#[async_trait]
pub trait MetricsPort: Send + Sync {
    async fn collect(&self) -> Result<CoturnMetrics, MetricsError>;
}

pub struct ReqwestCoturnMetrics {
    url: Url,
    client: Client,
    limits: MetricsLimits,
}

impl ReqwestCoturnMetrics {
    pub fn new(url: Url, limits: MetricsLimits) -> Result<Self, MetricsError> {
        let client = build_metrics_client(&url, limits)?;
        Ok(Self {
            url,
            client,
            limits,
        })
    }
}

#[async_trait]
impl MetricsPort for ReqwestCoturnMetrics {
    async fn collect(&self) -> Result<CoturnMetrics, MetricsError> {
        let body = fetch_metrics_body(&self.client, &self.url, self.limits).await?;
        parse_coturn_metrics(&body, self.limits)
    }
}

fn build_metrics_client(url: &Url, limits: MetricsLimits) -> Result<Client, MetricsError> {
    let loopback = match url.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if !loopback
        // Metrics are a loopback-only plaintext endpoint. Accepting HTTPS
        // here without a separately pinned private CA would silently
        // re-enable the platform WebPKI root set outside the backend pin.
        || url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || limits.max_input_bytes == 0
        || limits.max_input_bytes > 1024 * 1024
    {
        return Err(MetricsError::ConfigInvalid);
    }
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| MetricsError::ConfigInvalid)
}

async fn fetch_metrics_body(
    client: &Client,
    url: &Url,
    limits: MetricsLimits,
) -> Result<Vec<u8>, MetricsError> {
    let mut response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| MetricsError::Unavailable)?
        .error_for_status()
        .map_err(|_| MetricsError::Unavailable)?;
    if response
        .content_length()
        .is_some_and(|length| length > limits.max_input_bytes as u64)
    {
        return Err(MetricsError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| MetricsError::Unavailable)?
    {
        if body.len().saturating_add(chunk.len()) > limits.max_input_bytes {
            return Err(MetricsError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub fn parse_coturn_metrics(
    input: &[u8],
    limits: MetricsLimits,
) -> Result<CoturnMetrics, MetricsError> {
    if input.len() > limits.max_input_bytes {
        return Err(MetricsError::TooLarge);
    }
    let text = str::from_utf8(input).map_err(|_| MetricsError::Invalid)?;
    let mut values = BTreeMap::new();
    let mut line_count = 0usize;
    for line in text.lines() {
        line_count = line_count.checked_add(1).ok_or(MetricsError::TooLarge)?;
        if line_count > limits.max_lines || line.len() > limits.max_line_bytes {
            return Err(MetricsError::TooLarge);
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or(MetricsError::Invalid)?;
        let value = fields.next().ok_or(MetricsError::Invalid)?;
        if fields.next().is_some()
            || name.contains(['{', '}'])
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || values.len() >= limits.max_fields
            || values.contains_key(name)
        {
            return Err(MetricsError::Invalid);
        }
        let parsed = value.parse::<u64>().map_err(|_| MetricsError::Invalid)?;
        values.insert(name, parsed);
    }
    let allocations = required(&values, "turn_active_allocations")?;
    Ok(CoturnMetrics {
        active_allocations: u32::try_from(allocations).map_err(|_| MetricsError::Invalid)?,
        current_ingress_bps: required(&values, "turn_current_ingress_bps")?,
        current_egress_bps: required(&values, "turn_current_egress_bps")?,
        errors_total: required(&values, "turn_errors_total")?,
    })
}

fn required(values: &BTreeMap<&str, u64>, name: &str) -> Result<u64, MetricsError> {
    values.get(name).copied().ok_or(MetricsError::Invalid)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeCoturnScrape {
    pub active_allocations: u32,
    /// Finished-session diagnostic counter. It is deliberately not a bitrate.
    pub finished_sent_bytes: u64,
    /// Finished-session diagnostic counter. It is deliberately not a bitrate.
    pub finished_received_bytes: u64,
    pub errors_total: u64,
}

#[async_trait]
pub trait NativeCoturnScrapePort: Send + Sync {
    async fn scrape(&self) -> Result<NativeCoturnScrape, MetricsError>;
}

pub struct ReqwestNativeCoturnScrape {
    url: Url,
    client: Client,
    limits: MetricsLimits,
}

impl ReqwestNativeCoturnScrape {
    pub fn new(url: Url, limits: MetricsLimits) -> Result<Self, MetricsError> {
        let client = build_metrics_client(&url, limits)?;
        Ok(Self {
            url,
            client,
            limits,
        })
    }
}

#[async_trait]
impl NativeCoturnScrapePort for ReqwestNativeCoturnScrape {
    async fn scrape(&self) -> Result<NativeCoturnScrape, MetricsError> {
        let body = fetch_metrics_body(&self.client, &self.url, self.limits).await?;
        parse_native_coturn_scrape(&body, self.limits)
    }
}

#[async_trait]
pub trait TargetTrafficPort: Send + Sync {
    async fn collect_target_traffic(
        &self,
    ) -> Result<crate::platform::PlatformTrafficSample, MetricsError>;
}

#[async_trait]
impl TargetTrafficPort for Arc<crate::platform::PlatformCoturnRuntime> {
    async fn collect_target_traffic(
        &self,
    ) -> Result<crate::platform::PlatformTrafficSample, MetricsError> {
        self.collect_metrics_sample()
            .await
            .map_err(|_| MetricsError::Unavailable)
    }
}

pub struct PlatformMetrics<S, T> {
    native_scrape: S,
    target_traffic: T,
}

impl<S, T> PlatformMetrics<S, T> {
    pub fn new(native_scrape: S, target_traffic: T) -> Self {
        Self {
            native_scrape,
            target_traffic,
        }
    }
}

#[async_trait]
impl<S, T> MetricsPort for PlatformMetrics<S, T>
where
    S: NativeCoturnScrapePort,
    T: TargetTrafficPort,
{
    async fn collect(&self) -> Result<CoturnMetrics, MetricsError> {
        let (native, traffic) = tokio::try_join!(
            self.native_scrape.scrape(),
            self.target_traffic.collect_target_traffic()
        )?;
        if traffic.generation == 0 {
            return Err(MetricsError::Invalid);
        }
        Ok(CoturnMetrics {
            active_allocations: traffic.active_allocations,
            current_ingress_bps: traffic.current_ingress_bps,
            current_egress_bps: traffic.current_egress_bps,
            errors_total: native.errors_total,
        })
    }
}

pub fn parse_native_coturn_scrape(
    input: &[u8],
    limits: MetricsLimits,
) -> Result<NativeCoturnScrape, MetricsError> {
    if input.len() > limits.max_input_bytes {
        return Err(MetricsError::TooLarge);
    }
    let text = str::from_utf8(input).map_err(|_| MetricsError::Invalid)?;
    let mut result = NativeCoturnScrape::default();
    let mut seen_series = BTreeSet::new();
    let mut declarations = BTreeSet::new();
    let mut recognized_fields = 0usize;
    let mut line_count = 0usize;
    for raw_line in text.lines() {
        line_count = line_count.checked_add(1).ok_or(MetricsError::TooLarge)?;
        if line_count > limits.max_lines || raw_line.len() > limits.max_line_bytes {
            return Err(MetricsError::TooLarge);
        }
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            validate_prometheus_comment(line, &mut declarations)?;
            continue;
        }
        let (series, value) = split_sample(line)?;
        let (name, labels) = parse_series(series)?;
        let recognized = matches!(
            name,
            "turn_total_allocations"
                | "turn_total_traffic_sentb"
                | "turn_total_traffic_rcvb"
                | "turn_packet_dropped"
                | "stun_binding_error"
                | "turn_unauthenticated_401_dropped_responses"
                | "turn_ratelimit_hash_collisions"
        );
        if !recognized {
            continue;
        }
        recognized_fields = recognized_fields
            .checked_add(1)
            .ok_or(MetricsError::TooLarge)?;
        if recognized_fields > limits.max_fields {
            return Err(MetricsError::Invalid);
        }
        validate_native_labels(name, &labels)?;
        let canonical = canonical_series(name, &labels);
        if !seen_series.insert(canonical) {
            return Err(MetricsError::Invalid);
        }
        let value = parse_nonnegative_integer_float(value)?;
        match name {
            "turn_total_allocations" => {
                let allocations = u32::try_from(value).map_err(|_| MetricsError::Invalid)?;
                result.active_allocations = result
                    .active_allocations
                    .checked_add(allocations)
                    .ok_or(MetricsError::Invalid)?;
            }
            "turn_total_traffic_sentb" => {
                result.finished_sent_bytes = result
                    .finished_sent_bytes
                    .checked_add(value)
                    .ok_or(MetricsError::Invalid)?;
            }
            "turn_total_traffic_rcvb" => {
                result.finished_received_bytes = result
                    .finished_received_bytes
                    .checked_add(value)
                    .ok_or(MetricsError::Invalid)?;
            }
            "turn_packet_dropped"
            | "stun_binding_error"
            | "turn_unauthenticated_401_dropped_responses"
            | "turn_ratelimit_hash_collisions" => {
                result.errors_total = result
                    .errors_total
                    .checked_add(value)
                    .ok_or(MetricsError::Invalid)?;
            }
            _ => unreachable!(),
        }
    }
    if !seen_series
        .iter()
        .any(|series| series.starts_with("turn_total_allocations"))
    {
        return Err(MetricsError::Invalid);
    }
    Ok(result)
}

fn validate_prometheus_comment(
    line: &str,
    declarations: &mut BTreeSet<String>,
) -> Result<(), MetricsError> {
    if line == "#" || (!line.starts_with("# HELP ") && !line.starts_with("# TYPE ")) {
        return Ok(());
    }
    let mut fields = line.split_ascii_whitespace();
    let hash = fields.next();
    let kind = fields.next();
    let metric = fields.next().ok_or(MetricsError::Invalid)?;
    if hash != Some("#") || !matches!(kind, Some("HELP" | "TYPE")) || !valid_metric_name(metric) {
        return Err(MetricsError::Invalid);
    }
    if kind == Some("TYPE") {
        let metric_type = fields.next().ok_or(MetricsError::Invalid)?;
        if !matches!(metric_type, "counter" | "gauge" | "untyped") || fields.next().is_some() {
            return Err(MetricsError::Invalid);
        }
    } else if fields.next().is_none() {
        return Err(MetricsError::Invalid);
    }
    let declaration = format!("{}:{metric}", kind.unwrap_or_default());
    if !declarations.insert(declaration) {
        return Err(MetricsError::Invalid);
    }
    Ok(())
}

fn split_sample(line: &str) -> Result<(&str, &str), MetricsError> {
    let mut fields = line.split_ascii_whitespace();
    let series = fields.next().ok_or(MetricsError::Invalid)?;
    let value = fields.next().ok_or(MetricsError::Invalid)?;
    if fields.next().is_some() {
        return Err(MetricsError::Invalid);
    }
    Ok((series, value))
}

fn parse_series(series: &str) -> Result<(&str, BTreeMap<String, String>), MetricsError> {
    let Some(open) = series.find('{') else {
        if !valid_metric_name(series) {
            return Err(MetricsError::Invalid);
        }
        return Ok((series, BTreeMap::new()));
    };
    if !series.ends_with('}') || series[..open].contains('}') {
        return Err(MetricsError::Invalid);
    }
    let name = &series[..open];
    if !valid_metric_name(name) {
        return Err(MetricsError::Invalid);
    }
    let mut labels = BTreeMap::new();
    let encoded = &series[open + 1..series.len() - 1];
    if encoded.is_empty() {
        return Err(MetricsError::Invalid);
    }
    for pair in encoded.split(',') {
        let (name, encoded_value) = pair.split_once('=').ok_or(MetricsError::Invalid)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || encoded_value.len() < 2
            || !encoded_value.starts_with('"')
            || !encoded_value.ends_with('"')
        {
            return Err(MetricsError::Invalid);
        }
        let value = &encoded_value[1..encoded_value.len() - 1];
        if value.is_empty()
            || value.len() > 64
            || !value.is_ascii()
            || value.contains(['"', '\\', '\n', '\r'])
            || labels.insert(name.to_owned(), value.to_owned()).is_some()
        {
            return Err(MetricsError::Invalid);
        }
    }
    Ok((name, labels))
}

fn valid_metric_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && (name.as_bytes()[0].is_ascii_alphabetic() || name.as_bytes()[0] == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_native_labels(
    metric: &str,
    labels: &BTreeMap<String, String>,
) -> Result<(), MetricsError> {
    if labels.len() > 4 {
        return Err(MetricsError::Invalid);
    }
    let allowed: &[&str] = match metric {
        "turn_total_allocations" => &["type"],
        "turn_total_traffic_sentb"
        | "turn_total_traffic_rcvb"
        | "turn_packet_dropped"
        | "stun_binding_error"
        | "turn_unauthenticated_401_dropped_responses"
        | "turn_ratelimit_hash_collisions" => &[],
        _ => return Err(MetricsError::Invalid),
    };
    if labels
        .keys()
        .any(|label| !allowed.contains(&label.as_str()))
    {
        return Err(MetricsError::Invalid);
    }
    if metric == "turn_total_allocations" {
        let socket_type = labels.get("type").ok_or(MetricsError::Invalid)?;
        if labels.len() != 1
            || !matches!(
                socket_type.as_str(),
                "TCP" | "SCTP" | "UDP" | "TLS/TCP" | "TLS/SCTP" | "DTLS"
            )
        {
            return Err(MetricsError::Invalid);
        }
    } else if !labels.is_empty() {
        return Err(MetricsError::Invalid);
    }
    Ok(())
}

fn canonical_series(metric: &str, labels: &BTreeMap<String, String>) -> String {
    let mut result = String::from(metric);
    for (name, value) in labels {
        result.push('\0');
        result.push_str(name);
        result.push('=');
        result.push_str(value);
    }
    result
}

fn parse_nonnegative_integer_float(value: &str) -> Result<u64, MetricsError> {
    if value.is_empty() || value.starts_with(['-', '+']) {
        return Err(MetricsError::Invalid);
    }
    let parsed = value.parse::<f64>().map_err(|_| MetricsError::Invalid)?;
    if !parsed.is_finite() || parsed < 0.0 || parsed.fract() != 0.0 || parsed > u64::MAX as f64 {
        return Err(MetricsError::Invalid);
    }
    let converted = parsed as u64;
    if converted as f64 != parsed {
        return Err(MetricsError::Invalid);
    }
    Ok(converted)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficCounterSample {
    pub generation: u64,
    pub counter_epoch: String,
    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub measurement_monotonic_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrafficRate {
    pub current_ingress_bps: u64,
    pub current_egress_bps: u64,
}

#[derive(Default)]
pub struct TrafficRateNormalizer {
    previous: Option<TrafficCounterSample>,
}

impl TrafficRateNormalizer {
    pub fn observe(
        &mut self,
        current: TrafficCounterSample,
    ) -> Result<Option<TrafficRate>, MetricsError> {
        if current.generation == 0
            || current.counter_epoch.is_empty()
            || current.counter_epoch.len() > 128
            || !current.counter_epoch.is_ascii()
            || current.measurement_monotonic_ns == 0
        {
            return Err(MetricsError::Invalid);
        }
        let Some(previous) = self.previous.replace(current.clone()) else {
            return Ok(None);
        };
        if current.generation != previous.generation
            || current.counter_epoch != previous.counter_epoch
        {
            return Ok(None);
        }
        if current.measurement_monotonic_ns <= previous.measurement_monotonic_ns
            || current.total_ingress_bytes < previous.total_ingress_bytes
            || current.total_egress_bytes < previous.total_egress_bytes
        {
            return Err(MetricsError::CounterReset);
        }
        let elapsed_ns = current
            .measurement_monotonic_ns
            .checked_sub(previous.measurement_monotonic_ns)
            .ok_or(MetricsError::CounterReset)?;
        let ingress = rate_bps(
            current
                .total_ingress_bytes
                .checked_sub(previous.total_ingress_bytes)
                .ok_or(MetricsError::CounterReset)?,
            elapsed_ns,
        )?;
        let egress = rate_bps(
            current
                .total_egress_bytes
                .checked_sub(previous.total_egress_bytes)
                .ok_or(MetricsError::CounterReset)?,
            elapsed_ns,
        )?;
        Ok(Some(TrafficRate {
            current_ingress_bps: ingress,
            current_egress_bps: egress,
        }))
    }
}

fn rate_bps(delta_bytes: u64, elapsed_ns: u64) -> Result<u64, MetricsError> {
    if elapsed_ns == 0 {
        return Err(MetricsError::CounterReset);
    }
    let bits_per_second = u128::from(delta_bytes)
        .checked_mul(8)
        .and_then(|value| value.checked_mul(1_000_000_000))
        .and_then(|value| value.checked_div(u128::from(elapsed_ns)))
        .ok_or(MetricsError::Invalid)?;
    u64::try_from(bits_per_second).map_err(|_| MetricsError::Invalid)
}
