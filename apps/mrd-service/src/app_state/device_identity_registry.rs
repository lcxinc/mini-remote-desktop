use super::now_unix_ms;
use mrd_identity::DeviceIdentity;
use mrd_ipc::PairedDeviceIdentity;
use mrd_proto::DeviceId;
use mrd_store_sqlite::{
    AuditDraft, AuditRecord, AuditedTrustTransition, PersistentStore, StoreError, TrustRecord,
    TrustState,
};
use ring::rand::SystemRandom;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Pairing/trust adapter. Production trust is pinned by authenticated Ed25519 key ID.
pub struct DeviceIdentityRegistry {
    backend: DeviceIdentityBackend,
}

enum DeviceIdentityBackend {
    InMemory {
        paired_devices: Mutex<HashMap<DeviceId, PairedDeviceIdentity>>,
        machine_identity: Arc<DeviceIdentity>,
        authenticated_peers: Mutex<HashMap<String, TrustRecord>>,
    },
    Persistent {
        store: Arc<PersistentStore>,
        machine_identity: Arc<DeviceIdentity>,
        machine_epoch: u64,
    },
}

/// Current durable trust classification for a cryptographically authenticated peer key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedPeerTrust {
    Untrusted,
    Trusted,
    Suspended,
    Revoked,
    EpochMismatch,
}

impl AuthenticatedPeerTrust {
    pub fn is_controllable(self) -> bool {
        self == Self::Trusted
    }
}

#[derive(Debug)]
pub enum DeviceIdentityRegistryError {
    AuthenticatedPeerRequired,
    Store(StoreError),
}

impl std::fmt::Display for DeviceIdentityRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticatedPeerRequired => {
                formatter.write_str("an authenticated peer public key is required")
            }
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DeviceIdentityRegistryError {}

impl From<StoreError> for DeviceIdentityRegistryError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl std::fmt::Debug for DeviceIdentityRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceIdentityRegistry")
            .field(
                "backend",
                &match self.backend {
                    DeviceIdentityBackend::InMemory { .. } => "in_memory_test_fake",
                    DeviceIdentityBackend::Persistent { .. } => "persistent",
                },
            )
            .finish()
    }
}

impl Default for DeviceIdentityRegistry {
    fn default() -> Self {
        let machine_identity = DeviceIdentity::generate(&SystemRandom::new())
            .expect("test/debug machine identity generation must succeed");
        Self {
            backend: DeviceIdentityBackend::InMemory {
                paired_devices: Mutex::new(HashMap::new()),
                machine_identity: Arc::new(machine_identity),
                authenticated_peers: Mutex::new(HashMap::new()),
            },
        }
    }
}

impl DeviceIdentityRegistry {
    pub(crate) fn persistent(
        store: Arc<PersistentStore>,
        machine_identity: DeviceIdentity,
        machine_epoch: u64,
    ) -> Self {
        Self {
            backend: DeviceIdentityBackend::Persistent {
                store,
                machine_identity: Arc::new(machine_identity),
                machine_epoch,
            },
        }
    }

    pub fn machine_key_id(&self) -> Option<&str> {
        match &self.backend {
            DeviceIdentityBackend::InMemory {
                machine_identity, ..
            }
            | DeviceIdentityBackend::Persistent {
                machine_identity, ..
            } => Some(machine_identity.key_id()),
        }
    }

    pub fn machine_public_key(&self) -> Option<&[u8]> {
        match &self.backend {
            DeviceIdentityBackend::InMemory {
                machine_identity, ..
            }
            | DeviceIdentityBackend::Persistent {
                machine_identity, ..
            } => Some(machine_identity.public_key()),
        }
    }

    pub fn machine_key_epoch(&self) -> Option<u64> {
        match &self.backend {
            DeviceIdentityBackend::InMemory { .. } => Some(1),
            DeviceIdentityBackend::Persistent { machine_epoch, .. } => Some(*machine_epoch),
        }
    }

    pub(crate) fn machine_identity(&self) -> Arc<DeviceIdentity> {
        match &self.backend {
            DeviceIdentityBackend::InMemory {
                machine_identity, ..
            }
            | DeviceIdentityBackend::Persistent {
                machine_identity, ..
            } => Arc::clone(machine_identity),
        }
    }

    pub fn upsert(
        &self,
        device_id: DeviceId,
        certificate_fingerprint: Option<String>,
        trust_status: impl Into<String>,
    ) -> Result<(), DeviceIdentityRegistryError> {
        let DeviceIdentityBackend::InMemory { paired_devices, .. } = &self.backend else {
            return Err(DeviceIdentityRegistryError::AuthenticatedPeerRequired);
        };
        let mut paired_devices = paired_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let display_name = device_id.0.clone();
        let existing = paired_devices.remove(&device_id);
        let certificate_fingerprint = certificate_fingerprint.or_else(|| {
            existing
                .as_ref()
                .and_then(|identity| identity.certificate_fingerprint.clone())
        });
        paired_devices.insert(
            device_id.clone(),
            PairedDeviceIdentity {
                display_name: existing
                    .as_ref()
                    .map(|identity| identity.display_name.clone())
                    .unwrap_or(display_name),
                device_id,
                certificate_fingerprint,
                trust_status: trust_status.into(),
                last_seen_ms: Some(now_unix_ms()),
            },
        );
        Ok(())
    }

    pub fn revoke(&self, device_id: &DeviceId) -> Result<(), DeviceIdentityRegistryError> {
        let DeviceIdentityBackend::InMemory { paired_devices, .. } = &self.backend else {
            return Err(DeviceIdentityRegistryError::AuthenticatedPeerRequired);
        };
        let mut paired_devices = paired_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(identity) = paired_devices.get_mut(device_id) {
            identity.trust_status = "revoked".to_string();
            identity.last_seen_ms = Some(now_unix_ms());
        } else {
            drop(paired_devices);
            self.upsert(device_id.clone(), None, "revoked")?;
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<PairedDeviceIdentity>, DeviceIdentityRegistryError> {
        match &self.backend {
            DeviceIdentityBackend::InMemory { paired_devices, .. } => {
                let paired_devices = paired_devices
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut identities = paired_devices.values().cloned().collect::<Vec<_>>();
                identities.sort_by(|a, b| a.device_id.0.cmp(&b.device_id.0));
                Ok(identities)
            }
            DeviceIdentityBackend::Persistent { .. } => Ok(Vec::new()),
        }
    }

    pub fn approve_authenticated_peer(
        &self,
        peer_key_id: &str,
        public_key: &[u8],
        epoch: u64,
        audit: AuditDraft,
    ) -> Result<(TrustRecord, AuditRecord), DeviceIdentityRegistryError> {
        let DeviceIdentityBackend::Persistent { store, .. } = &self.backend else {
            return Err(DeviceIdentityRegistryError::AuthenticatedPeerRequired);
        };
        store
            .insert_trusted_device_with_audit(
                peer_key_id,
                public_key,
                epoch,
                TrustState::Trusted,
                audit,
            )
            .map_err(Into::into)
    }

    pub fn transition_authenticated_peer(
        &self,
        peer_key_id: &str,
        expected_revision: u64,
        next: TrustState,
        audit: AuditDraft,
    ) -> Result<AuditedTrustTransition, DeviceIdentityRegistryError> {
        let DeviceIdentityBackend::Persistent { store, .. } = &self.backend else {
            return Err(DeviceIdentityRegistryError::AuthenticatedPeerRequired);
        };
        store
            .transition_trust_with_audit(peer_key_id, expected_revision, next, audit)
            .map_err(Into::into)
    }

    pub fn trusted_records(
        &self,
        include_revoked: bool,
    ) -> Result<Vec<TrustRecord>, DeviceIdentityRegistryError> {
        let DeviceIdentityBackend::Persistent { store, .. } = &self.backend else {
            return Err(DeviceIdentityRegistryError::AuthenticatedPeerRequired);
        };
        store
            .list_trusted_devices(include_revoked)
            .map_err(Into::into)
    }

    pub fn authenticated_peer_trust(
        &self,
        peer_key_id: &str,
        public_key: &[u8],
        epoch: u64,
    ) -> Result<AuthenticatedPeerTrust, DeviceIdentityRegistryError> {
        let record = match &self.backend {
            DeviceIdentityBackend::InMemory {
                authenticated_peers,
                ..
            } => authenticated_peers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(peer_key_id)
                .cloned(),
            DeviceIdentityBackend::Persistent { store, .. } => store.trust_record(peer_key_id)?,
        };
        let Some(record) = record else {
            return Ok(AuthenticatedPeerTrust::Untrusted);
        };
        if record.public_key != public_key || record.epoch != epoch {
            return Ok(AuthenticatedPeerTrust::EpochMismatch);
        }
        Ok(match record.state {
            TrustState::Trusted => AuthenticatedPeerTrust::Trusted,
            TrustState::Suspended => AuthenticatedPeerTrust::Suspended,
            TrustState::Revoked => AuthenticatedPeerTrust::Revoked,
        })
    }

    /// Revalidate the current pinned key state when a signed protocol message
    /// does not carry a trust-store epoch. A matching untrusted key remains
    /// distinguishable from a durably suspended or revoked key.
    pub fn authenticated_peer_trust_current_key(
        &self,
        peer_key_id: &str,
        public_key: &[u8],
    ) -> Result<AuthenticatedPeerTrust, DeviceIdentityRegistryError> {
        let record = match &self.backend {
            DeviceIdentityBackend::InMemory {
                authenticated_peers,
                ..
            } => authenticated_peers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(peer_key_id)
                .cloned(),
            DeviceIdentityBackend::Persistent { store, .. } => store.trust_record(peer_key_id)?,
        };
        let Some(record) = record else {
            return Ok(AuthenticatedPeerTrust::Untrusted);
        };
        if record.public_key != public_key {
            return Ok(AuthenticatedPeerTrust::EpochMismatch);
        }
        Ok(match record.state {
            TrustState::Trusted => AuthenticatedPeerTrust::Trusted,
            TrustState::Suspended => AuthenticatedPeerTrust::Suspended,
            TrustState::Revoked => AuthenticatedPeerTrust::Revoked,
        })
    }

    #[doc(hidden)]
    #[cfg(any(test, debug_assertions))]
    pub fn trust_authenticated_peer_for_test(
        &self,
        identity: &DeviceIdentity,
        epoch: u64,
        state: TrustState,
    ) {
        let DeviceIdentityBackend::InMemory {
            authenticated_peers,
            ..
        } = &self.backend
        else {
            panic!("test trust injection requires the in-memory registry");
        };
        authenticated_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                identity.key_id().to_string(),
                TrustRecord {
                    peer_key_id: identity.key_id().to_string(),
                    public_key: identity.public_key().to_vec(),
                    epoch,
                    state,
                    revision: 1,
                    updated_at_ms: now_unix_ms(),
                },
            );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_preserves_certificate_fingerprint_and_revoke_updates_trust() {
        let device_id = DeviceId("peer-device".to_string());
        let registry = DeviceIdentityRegistry::default();

        registry
            .upsert(
                device_id.clone(),
                Some("sha256:first".to_string()),
                "trusted",
            )
            .unwrap();
        registry.upsert(device_id.clone(), None, "paired").unwrap();

        let paired = registry.list().unwrap();
        assert_eq!(paired.len(), 1);
        assert_eq!(
            paired[0].certificate_fingerprint.as_deref(),
            Some("sha256:first")
        );
        assert_eq!(paired[0].trust_status, "paired");

        registry.revoke(&device_id).unwrap();

        let revoked = registry.list().unwrap();
        assert_eq!(revoked[0].trust_status, "revoked");
        assert_eq!(
            revoked[0].certificate_fingerprint.as_deref(),
            Some("sha256:first")
        );
    }

    #[test]
    fn authenticated_trust_requires_exact_public_key_and_epoch() {
        let registry = DeviceIdentityRegistry::default();
        let peer = DeviceIdentity::generate(&SystemRandom::new()).unwrap();
        let other_peer = DeviceIdentity::generate(&SystemRandom::new()).unwrap();

        assert_eq!(
            registry
                .authenticated_peer_trust(peer.key_id(), peer.public_key(), 1)
                .unwrap(),
            AuthenticatedPeerTrust::Untrusted
        );

        registry.trust_authenticated_peer_for_test(&peer, 1, TrustState::Trusted);
        assert_eq!(
            registry
                .authenticated_peer_trust(peer.key_id(), peer.public_key(), 1)
                .unwrap(),
            AuthenticatedPeerTrust::Trusted
        );
        assert_eq!(
            registry
                .authenticated_peer_trust(peer.key_id(), peer.public_key(), 2)
                .unwrap(),
            AuthenticatedPeerTrust::EpochMismatch
        );
        assert_eq!(
            registry
                .authenticated_peer_trust(peer.key_id(), other_peer.public_key(), 1)
                .unwrap(),
            AuthenticatedPeerTrust::EpochMismatch
        );
    }

    #[test]
    fn suspended_and_revoked_authenticated_peers_are_not_controllable() {
        let registry = DeviceIdentityRegistry::default();
        let peer = DeviceIdentity::generate(&SystemRandom::new()).unwrap();

        registry.trust_authenticated_peer_for_test(&peer, 1, TrustState::Suspended);
        let suspended = registry
            .authenticated_peer_trust(peer.key_id(), peer.public_key(), 1)
            .unwrap();
        assert_eq!(suspended, AuthenticatedPeerTrust::Suspended);
        assert!(!suspended.is_controllable());

        registry.trust_authenticated_peer_for_test(&peer, 1, TrustState::Revoked);
        let revoked = registry
            .authenticated_peer_trust(peer.key_id(), peer.public_key(), 1)
            .unwrap();
        assert_eq!(revoked, AuthenticatedPeerTrust::Revoked);
        assert!(!revoked.is_controllable());
    }
}
