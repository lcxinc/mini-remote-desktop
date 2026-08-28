use mrd_agent_ipc::MediaAccessUnit;
use std::collections::{HashMap, VecDeque};

/// Bounded hand-off from authenticated agent IPC to the service media loop.
#[derive(Debug)]
pub struct AgentMediaIngress {
    capacity: usize,
    queue: VecDeque<MediaAccessUnit>,
    dropped: u64,
    last_sequences: HashMap<String, u64>,
}

impl AgentMediaIngress {
    /// Creates a queue with an explicit backpressure limit.
    pub fn new(capacity: usize) -> Option<Self> {
        (capacity > 0).then_some(Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            dropped: 0,
            last_sequences: HashMap::new(),
        })
    }

    /// Enqueues a validated unit, rejecting invalid or over-capacity input.
    pub fn push(&mut self, unit: MediaAccessUnit) -> bool {
        if !unit.is_valid()
            || unit.sequence
                <= self
                    .last_sequences
                    .get(&unit.session_id)
                    .copied()
                    .unwrap_or(0)
            || self.queue.len() >= self.capacity
        {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.last_sequences
            .insert(unit.session_id.clone(), unit.sequence);
        self.queue.push_back(unit);
        true
    }

    /// Removes the oldest unit for the LAN sender.
    pub fn pop(&mut self) -> Option<MediaAccessUnit> {
        self.queue.pop_front()
    }

    /// Drains at most `limit` units for one sender scheduling turn.
    pub fn drain(&mut self, limit: usize) -> Vec<MediaAccessUnit> {
        let count = limit.min(self.queue.len());
        self.queue.drain(..count).collect()
    }

    /// Drains only units belonging to one logical session.
    pub fn drain_session(&mut self, session_id: &str, limit: usize) -> Vec<MediaAccessUnit> {
        let mut selected = Vec::new();
        let mut retained = VecDeque::with_capacity(self.queue.len());
        while let Some(unit) = self.queue.pop_front() {
            if unit.session_id == session_id && selected.len() < limit {
                selected.push(unit);
            } else {
                retained.push_back(unit);
            }
        }
        self.queue = retained;
        selected
    }

    /// Current queue depth.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue contains no media access units.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Number of queued units for one logical session.
    pub fn session_len(&self, session_id: &str) -> usize {
        self.queue
            .iter()
            .filter(|unit| unit.session_id == session_id)
            .count()
    }

    /// Whether authenticated media ownership has been established for a session.
    pub fn has_session(&self, session_id: &str) -> bool {
        self.last_sequences.contains_key(session_id)
    }

    /// Number of rejected units since creation.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Clears queued units when the owning agent/session is invalidated.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.last_sequences.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_agent_ipc::{AgentEventContext, MediaCodec};

    fn unit(sequence: u64) -> MediaAccessUnit {
        MediaAccessUnit {
            context: AgentEventContext {
                registration_id: [1; 16],
                registration_epoch: 1,
                windows_session_id: 1,
                desktop_epoch: 1,
                sequence,
                observed_at_ms: sequence,
            },
            resource_id: [2; 16],
            session_id: "session-1".to_string(),
            sequence,
            timestamp_us: sequence,
            codec: MediaCodec::H264,
            is_keyframe: sequence == 1,
            payload: vec![1, 2],
        }
    }

    #[test]
    fn ingress_applies_validation_and_backpressure() {
        let mut ingress = AgentMediaIngress::new(1).unwrap();
        assert!(ingress.push(unit(1)));
        assert!(!ingress.push(unit(2)));
        assert_eq!(ingress.dropped(), 1);
        assert_eq!(ingress.pop().unwrap().sequence, 1);
        assert!(!ingress.push(unit(1)));
        assert_eq!(ingress.dropped(), 2);
        assert!(!ingress.push({
            let mut invalid = unit(3);
            invalid.payload.clear();
            invalid
        }));
        assert_eq!(ingress.dropped(), 3);
        ingress.clear();
        assert_eq!(ingress.len(), 0);
        assert!(ingress.push(unit(1)));
    }

    #[test]
    fn session_drain_does_not_cross_route_units() {
        let mut ingress = AgentMediaIngress::new(4).unwrap();
        let mut second = unit(2);
        second.session_id = "session-2".to_string();
        second.sequence = 1;
        assert!(ingress.push(unit(1)));
        assert!(ingress.push(second));
        let first = ingress.drain_session("session-1", 8);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].session_id, "session-1");
        assert_eq!(ingress.pop().unwrap().session_id, "session-2");
    }

    #[test]
    fn session_len_counts_only_target_session() {
        let mut ingress = AgentMediaIngress::new(4).unwrap();
        let mut second = unit(2);
        second.session_id = "session-2".to_string();
        assert!(ingress.push(unit(1)));
        assert!(ingress.push(second));
        assert_eq!(ingress.session_len("session-1"), 1);
        assert_eq!(ingress.session_len("session-2"), 1);
    }
}
