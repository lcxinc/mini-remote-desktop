use crate::RelayNodeState;

pub const RELAY_LEASE_DURATION_MS: u64 = 15_000;
const HEALTHY_HEARTBEATS_TO_RECOVER: u8 = 3;

pub fn lease_expires_at(heartbeat_at_ms: u64) -> u64 {
    heartbeat_at_ms.saturating_add(RELAY_LEASE_DURATION_MS)
}

pub fn lease_is_fresh(lease_expires_at_ms: u64, now_ms: u64) -> bool {
    now_ms < lease_expires_at_ms
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayHealthTracker {
    state: RelayNodeState,
    healthy_heartbeat_streak: u8,
}

impl RelayHealthTracker {
    pub fn new(state: RelayNodeState) -> Self {
        Self {
            state,
            healthy_heartbeat_streak: 0,
        }
    }

    pub fn state(&self) -> RelayNodeState {
        self.state
    }

    pub fn healthy_heartbeat_streak(&self) -> u8 {
        self.healthy_heartbeat_streak
    }

    pub fn record_heartbeat(&mut self, healthy: bool) -> RelayNodeState {
        if !healthy {
            self.healthy_heartbeat_streak = 0;
            self.state = match self.state {
                RelayNodeState::Enrolling => RelayNodeState::Unavailable,
                RelayNodeState::Ready => RelayNodeState::Degraded,
                state => state,
            };
            return self.state;
        }

        match self.state {
            RelayNodeState::Enrolling | RelayNodeState::Degraded | RelayNodeState::Unavailable => {
                self.healthy_heartbeat_streak = self
                    .healthy_heartbeat_streak
                    .saturating_add(1)
                    .min(HEALTHY_HEARTBEATS_TO_RECOVER);
                if self.healthy_heartbeat_streak == HEALTHY_HEARTBEATS_TO_RECOVER {
                    self.state = RelayNodeState::Ready;
                    self.healthy_heartbeat_streak = 0;
                }
            }
            RelayNodeState::Ready | RelayNodeState::Draining | RelayNodeState::Revoked => {
                self.healthy_heartbeat_streak = 0;
            }
        }
        self.state
    }
}
