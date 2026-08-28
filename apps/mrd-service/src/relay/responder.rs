//! Background answer-side dispatcher for authenticated relay migration offers.

use super::{RelayFailoverCoordinator, RelayMigrationOffer};
use crate::AppState;
use std::sync::Arc;
use tokio::{sync::oneshot, task::JoinSet};

pub struct ServiceRelayResponderTask {
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for ServiceRelayResponderTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceRelayResponderTask")
            .finish_non_exhaustive()
    }
}

impl ServiceRelayResponderTask {
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.join.await;
    }
}

pub fn spawn_relay_migration_responder(
    app_state: Arc<AppState>,
    coordinator: Arc<RelayFailoverCoordinator>,
) -> ServiceRelayResponderTask {
    let mut inbound = app_state.relay_signaling.subscribe();
    let (shutdown, mut shutdown_requested) = oneshot::channel();
    let join = tokio::spawn(async move {
        let mut migrations = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_requested => break,
                result = migrations.join_next(), if !migrations.is_empty() => {
                    let _ = result;
                }
                event = inbound.recv() => {
                    let Ok(event) = event else { break };
                    let Some(offer) = RelayMigrationOffer::from_verified_event(event) else {
                        continue;
                    };
                    let coordinator = Arc::clone(&coordinator);
                    migrations.spawn(async move {
                        let _ = coordinator.accept_remote_offer(offer).await;
                    });
                }
            }
        }
        migrations.abort_all();
        while migrations.join_next().await.is_some() {}
    });
    ServiceRelayResponderTask {
        shutdown: Some(shutdown),
        join,
    }
}
