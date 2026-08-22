use std::fmt;

const MAX_IDENTIFIER_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    Empty,
    TooLong { max: usize },
    InvalidCharacter { index: usize },
}

macro_rules! bounded_identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self, IdentifierError> {
                let value = value.as_ref();
                validate_identifier(value)?;
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

bounded_identifier!(RelayNodeId);
bounded_identifier!(RegionId);
bounded_identifier!(FailureDomainId);

fn validate_identifier(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(IdentifierError::TooLong {
            max: MAX_IDENTIFIER_LEN,
        });
    }
    if let Some((index, _)) = value
        .bytes()
        .enumerate()
        .find(|(_, byte)| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IdentifierError::InvalidCharacter { index });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RelayNodeState {
    Enrolling,
    Ready,
    Degraded,
    Draining,
    Unavailable,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RelayTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayEndpointError {
    EmptyHost,
    InvalidPort,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayEndpoint {
    pub transport: RelayTransport,
    pub host: String,
    pub port: u16,
}

impl RelayEndpoint {
    pub fn new(
        transport: RelayTransport,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, RelayEndpointError> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err(RelayEndpointError::EmptyHost);
        }
        if port == 0 {
            return Err(RelayEndpointError::InvalidPort);
        }
        Ok(Self {
            transport,
            host,
            port,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayNodeSnapshot {
    pub node_id: RelayNodeId,
    pub region: RegionId,
    pub failure_domain: FailureDomainId,
    pub state: RelayNodeState,
    pub lease_expires_at_ms: u64,
    pub endpoints: Vec<RelayEndpoint>,
    pub active_allocations: u32,
    pub max_allocations: u32,
    pub current_egress_bps: u64,
    pub max_egress_bps: u64,
    pub recent_failure_bps: u16,
    pub measured_rtt_ms: u32,
}
