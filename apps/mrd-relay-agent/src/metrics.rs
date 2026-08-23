use std::{collections::BTreeMap, net::IpAddr, str, time::Duration};

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
        let loopback = match url.host() {
            Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
            Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        };
        if !loopback
            || !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || limits.max_input_bytes == 0
            || limits.max_input_bytes > 1024 * 1024
        {
            return Err(MetricsError::ConfigInvalid);
        }
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| MetricsError::ConfigInvalid)?;
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
        let mut response = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .map_err(|_| MetricsError::Unavailable)?
            .error_for_status()
            .map_err(|_| MetricsError::Unavailable)?;
        if response
            .content_length()
            .is_some_and(|length| length > self.limits.max_input_bytes as u64)
        {
            return Err(MetricsError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| MetricsError::Unavailable)?
        {
            if body.len().saturating_add(chunk.len()) > self.limits.max_input_bytes {
                return Err(MetricsError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        parse_coturn_metrics(&body, self.limits)
    }
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
