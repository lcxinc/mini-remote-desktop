//! Service-owned authenticated realtime signaling runtime.

mod config;
mod event_mapper;
mod runtime;

pub use config::{SignalingConfig, SignalingConfigError};
pub use event_mapper::ServiceSignalingMapper;
pub use mrd_signal_proto::relay_candidate_fingerprint;
pub use runtime::{
    spawn, spawn_from_env, InboundDisposition, OutboundRelayMigrationSignal, RelaySignalingBus,
    RelaySignalingCommand, RelaySignalingReceiveError, RelaySignalingSendError,
    RelaySignalingSubscription, SignalingConnectionState, SignalingRuntimeCore,
    SignalingRuntimeError, SignalingRuntimeSnapshot, SignalingStatus, SignalingTask,
};
