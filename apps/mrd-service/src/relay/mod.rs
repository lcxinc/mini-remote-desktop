//! Verified relay-directory consumption and session failover orchestration.

mod cache;
mod client;
mod config;
mod executor;
mod migration;
mod responder;
mod runtime;

pub use client::{
    relay_peer_digest, RelayAccessBackend, RelayAccessContext, RelayBackendError, RelayClientError,
    RelayClock, RelayDirectoryClient, RelayRouteEvidence, SystemRelayClock, VerifiedRelayAccess,
};
pub(crate) use client::{urls_digest, verify_relay_access_response};
pub use config::{RelayClientConfig, RelayClientConfigError};
pub use executor::{ServiceRelayMigrationConfigError, ServiceRelayMigrationExecutor};
pub use migration::*;
pub use responder::{spawn_relay_migration_responder, ServiceRelayResponderTask};
pub use runtime::{install_connected_relay_session, RelaySessionInstallError};
