use super::client::{RelayAccessContext, VerifiedRelayAccess};
use std::{collections::HashMap, collections::VecDeque, sync::Arc};

/// Bounded least-recently-used cache containing only context-verified directories.
pub(crate) struct RelayDirectoryCache {
    capacity: usize,
    entries: HashMap<RelayAccessContext, Arc<VerifiedRelayAccess>>,
    order: VecDeque<RelayAccessContext>,
}

impl RelayDirectoryCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    pub(crate) fn get(
        &mut self,
        context: &RelayAccessContext,
        now_ms: u64,
    ) -> Option<Arc<VerifiedRelayAccess>> {
        let access = self.entries.get(context).cloned();
        match access {
            Some(access) if access.is_fresh(now_ms) => {
                self.touch(context);
                Some(access)
            }
            Some(_) => {
                self.remove(context);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(&mut self, context: RelayAccessContext, access: Arc<VerifiedRelayAccess>) {
        self.entries.insert(context.clone(), access);
        self.touch(&context);
        while self.entries.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    pub(crate) fn remove(&mut self, context: &RelayAccessContext) {
        self.entries.remove(context);
        self.order.retain(|candidate| candidate != context);
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn touch(&mut self, context: &RelayAccessContext) {
        self.order.retain(|candidate| candidate != context);
        self.order.push_back(context.clone());
    }
}
