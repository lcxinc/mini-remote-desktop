use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mrd_relay_agent::{
    identity::load_or_create_identity,
    runtime::{RuntimeError, RuntimeStateSnapshot, RuntimeStateStorePort},
    secure_store::{
        validate_windows_static_boundary_claim, AtomicEnvelopeFile, BoundSecretStore,
        EnvelopeProtector, SecretStorePurpose, SecureIdentityStore, SecureRuntimeStateStore,
        SecureStoreError, WindowsStaticAceClaim, WindowsStaticAclClaim, WindowsStaticAncestorClaim,
        WindowsStaticBoundaryClaim, WINDOWS_ADMINISTRATORS_SID, WINDOWS_DELETE_CHILD_ACCESS,
        WINDOWS_FILE_ALL_ACCESS, WINDOWS_FILE_READ_EXECUTE, WINDOWS_FILE_WRITE_ATTRIBUTES,
        WINDOWS_FILE_WRITE_EA, WINDOWS_INHERIT_CONTAINERS_AND_OBJECTS, WINDOWS_LOCAL_SYSTEM_SID,
        WINDOWS_SYSTEM_MANAGED_CREATE_ACCESS, WINDOWS_TRUSTED_INSTALLER_SID,
    },
};
use zeroize::Zeroizing;

#[cfg(windows)]
use mrd_relay_agent::secure_store::{
    protected_service_dacl_sddl, DpapiMachineProtector, HardenedAtomicFile,
    WindowsTrustedStaticFile,
};

#[cfg(target_os = "linux")]
use mrd_relay_agent::secure_store::{
    read_linux_integrity_file, HardenedAtomicFile, LinuxPlaintextProtector, StrictCredentialFile,
};

type ProtectedEntry = (Vec<u8>, Vec<u8>);
type ProtectedEntries = BTreeMap<Vec<u8>, ProtectedEntry>;

#[derive(Default)]
struct RecordingProtector {
    entries: Mutex<ProtectedEntries>,
    last_plaintext: Mutex<Vec<u8>>,
}

impl EnvelopeProtector for RecordingProtector {
    fn seal(
        &self,
        binding: &[u8],
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        *self.last_plaintext.lock().unwrap() = plaintext.to_vec();
        let token = format!("sealed-{}", self.entries.lock().unwrap().len() + 1).into_bytes();
        self.entries
            .lock()
            .unwrap()
            .insert(token.clone(), (binding.to_vec(), plaintext.to_vec()));
        Ok(Zeroizing::new(token))
    }

    fn open(&self, binding: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        let entries = self.entries.lock().unwrap();
        let (expected_binding, plaintext) = entries.get(sealed).ok_or(SecureStoreError::Invalid)?;
        if expected_binding != binding {
            return Err(SecureStoreError::Invalid);
        }
        Ok(Zeroizing::new(plaintext.clone()))
    }
}

struct FakeAtomicFile {
    canonical_path: String,
    committed: Mutex<Option<Vec<u8>>>,
    fail_next_replace: Mutex<bool>,
}

impl FakeAtomicFile {
    fn new(canonical_path: &str) -> Self {
        Self {
            canonical_path: canonical_path.to_owned(),
            committed: Mutex::new(None),
            fail_next_replace: Mutex::new(false),
        }
    }

    fn fail_next_replace(&self) {
        *self.fail_next_replace.lock().unwrap() = true;
    }
}

impl AtomicEnvelopeFile for FakeAtomicFile {
    fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    fn read(&self, max_bytes: usize) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        let value = self.committed.lock().unwrap().clone();
        if value.as_ref().is_some_and(|bytes| bytes.len() > max_bytes) {
            return Err(SecureStoreError::Invalid);
        }
        Ok(value.map(Zeroizing::new))
    }

    fn atomic_replace(&self, value: &[u8], max_bytes: usize) -> Result<(), SecureStoreError> {
        if value.len() > max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        if std::mem::take(&mut *self.fail_next_replace.lock().unwrap()) {
            return Err(SecureStoreError::Io);
        }
        *self.committed.lock().unwrap() = Some(value.to_vec());
        Ok(())
    }

    fn enforce_strict_permissions(&self) -> Result<(), SecureStoreError> {
        Ok(())
    }
}

#[test]
fn runtime_store_seals_one_bound_whole_envelope_before_atomic_replace() {
    let protector = Arc::new(RecordingProtector::default());
    let file = Arc::new(FakeAtomicFile::new("C:\\ProgramData\\MRD\\runtime.sec"));
    let store = SecureRuntimeStateStore::new(file.clone(), protector.clone(), "node-a").unwrap();
    let state = RuntimeStateSnapshot {
        secret_version: 7,
        draining: true,
        ..RuntimeStateSnapshot::default()
    };

    store.atomic_store(&state).unwrap();

    let on_disk = file.committed.lock().unwrap().clone().unwrap();
    assert!(!on_disk
        .windows("secret_version".len())
        .any(|window| window == b"secret_version"));
    let envelope: serde_json::Value =
        serde_json::from_slice(&protector.last_plaintext.lock().unwrap()).unwrap();
    assert_eq!(
        envelope
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "canonical_path",
            "node_id",
            "payload_b64",
            "purpose",
            "schema"
        ]
    );
    assert_eq!(envelope["schema"], "mrd-relay-secure-envelope.v1");
    assert_eq!(envelope["purpose"], "runtime_state");
    assert_eq!(envelope["node_id"], "node-a");
    assert_eq!(
        envelope["canonical_path"],
        "C:\\ProgramData\\MRD\\runtime.sec"
    );
    let payload = STANDARD
        .decode(envelope["payload_b64"].as_str().unwrap())
        .unwrap();
    let decoded: RuntimeStateSnapshot = serde_json::from_slice(&payload).unwrap();
    assert_eq!(decoded.secret_version, 7);
    assert!(decoded.draining);
    assert_eq!(store.load().unwrap(), state);
}

#[test]
fn bound_secret_store_returns_zeroizing_bytes_and_seals_the_entire_blob() {
    let protector = Arc::new(RecordingProtector::default());
    let file = Arc::new(FakeAtomicFile::new(
        "C:\\ProgramData\\MRD\\bootstrap-token.sec",
    ));
    let store = BoundSecretStore::new(
        file.clone(),
        protector.clone(),
        "node-a",
        SecretStorePurpose::BootstrapEnrollmentToken,
    )
    .unwrap();

    store.atomic_replace(b"bootstrap-super-secret").unwrap();

    let on_disk = file.committed.lock().unwrap().clone().unwrap();
    assert!(!on_disk
        .windows("bootstrap-super-secret".len())
        .any(|window| window == b"bootstrap-super-secret"));
    let loaded: Zeroizing<Vec<u8>> = store.load().unwrap().unwrap();
    assert_eq!(loaded.as_slice(), b"bootstrap-super-secret");
    let envelope: serde_json::Value =
        serde_json::from_slice(&protector.last_plaintext.lock().unwrap()).unwrap();
    assert_eq!(envelope["purpose"], "bootstrap_enrollment_token");
}

#[test]
fn identity_port_seals_private_key_material_and_roundtrips_the_same_identity() {
    let protector = Arc::new(RecordingProtector::default());
    let file = Arc::new(FakeAtomicFile::new("C:\\ProgramData\\MRD\\identity.sec"));
    let store = SecureIdentityStore::new(file.clone(), protector.clone(), "node-a").unwrap();

    let first = load_or_create_identity(&store, "node-a").unwrap();
    let second = load_or_create_identity(&store, "node-a").unwrap();

    assert_eq!(first.public_key(), second.public_key());
    let on_disk = file.committed.lock().unwrap().clone().unwrap();
    assert!(!on_disk
        .windows("private_pkcs8_b64".len())
        .any(|window| window == b"private_pkcs8_b64"));
    let envelope: serde_json::Value =
        serde_json::from_slice(&protector.last_plaintext.lock().unwrap()).unwrap();
    assert_eq!(envelope["purpose"], "identity");
    let payload = STANDARD
        .decode(envelope["payload_b64"].as_str().unwrap())
        .unwrap();
    assert!(payload
        .windows("private_pkcs8_b64".len())
        .any(|window| window == b"private_pkcs8_b64"));
}

#[test]
fn failed_atomic_replace_preserves_the_previous_complete_runtime_envelope() {
    let protector = Arc::new(RecordingProtector::default());
    let file = Arc::new(FakeAtomicFile::new("C:\\ProgramData\\MRD\\runtime.sec"));
    let store = SecureRuntimeStateStore::new(file.clone(), protector, "node-a").unwrap();
    let old = RuntimeStateSnapshot {
        secret_version: 1,
        ..RuntimeStateSnapshot::default()
    };
    store.atomic_store(&old).unwrap();
    file.fail_next_replace();
    let replacement = RuntimeStateSnapshot {
        secret_version: 2,
        ..RuntimeStateSnapshot::default()
    };

    assert_eq!(store.atomic_store(&replacement), Err(RuntimeError::StateIo));
    assert_eq!(store.load().unwrap(), old);
}

#[test]
fn runtime_mutations_are_serialized_across_concurrent_writers() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let protector = Arc::new(RecordingProtector::default());
    let file = Arc::new(FakeAtomicFile::new("C:\\ProgramData\\MRD\\runtime.sec"));
    let store = Arc::new(SecureRuntimeStateStore::new(file, protector, "node-a").unwrap());
    let first_inside_mutation = Arc::new(AtomicBool::new(false));

    let first_store = store.clone();
    let first_flag = first_inside_mutation.clone();
    let first = std::thread::spawn(move || {
        first_store
            .mutate(&mut |state| {
                first_flag.store(true, Ordering::Release);
                std::thread::sleep(std::time::Duration::from_millis(75));
                state.secret_version += 1;
                Ok(())
            })
            .unwrap();
    });
    while !first_inside_mutation.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    let second_store = store.clone();
    let second = std::thread::spawn(move || {
        second_store
            .mutate(&mut |state| {
                state.secret_version += 1;
                Ok(())
            })
            .unwrap();
    });

    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(store.load().unwrap().secret_version, 2);
}

#[test]
fn wrong_node_or_path_binding_and_tampered_sealed_bytes_fail_closed() {
    let protector = Arc::new(RecordingProtector::default());
    let original_file = Arc::new(FakeAtomicFile::new("C:\\ProgramData\\MRD\\runtime.sec"));
    let original =
        SecureRuntimeStateStore::new(original_file.clone(), protector.clone(), "node-a").unwrap();
    original
        .atomic_store(&RuntimeStateSnapshot {
            secret_version: 7,
            ..RuntimeStateSnapshot::default()
        })
        .unwrap();
    let sealed = original_file.committed.lock().unwrap().clone().unwrap();

    let wrong_path_file = Arc::new(FakeAtomicFile::new(
        "C:\\ProgramData\\MRD\\other-runtime.sec",
    ));
    *wrong_path_file.committed.lock().unwrap() = Some(sealed.clone());
    let wrong_path =
        SecureRuntimeStateStore::new(wrong_path_file, protector.clone(), "node-a").unwrap();
    assert_eq!(wrong_path.load(), Err(RuntimeError::StateInvalid));

    let wrong_node_file = Arc::new(FakeAtomicFile::new("C:\\ProgramData\\MRD\\runtime.sec"));
    *wrong_node_file.committed.lock().unwrap() = Some(sealed.clone());
    let wrong_node =
        SecureRuntimeStateStore::new(wrong_node_file, protector.clone(), "node-b").unwrap();
    assert_eq!(wrong_node.load(), Err(RuntimeError::StateInvalid));

    let tampered_file = Arc::new(FakeAtomicFile::new("C:\\ProgramData\\MRD\\runtime.sec"));
    let mut tampered = sealed;
    tampered[0] ^= 0x80;
    *tampered_file.committed.lock().unwrap() = Some(tampered);
    let tampered_store = SecureRuntimeStateStore::new(tampered_file, protector, "node-a").unwrap();
    assert_eq!(tampered_store.load(), Err(RuntimeError::StateInvalid));
}

fn static_allow(sid: &str, rights: u32, inheritance: u32) -> WindowsStaticAceClaim {
    WindowsStaticAceClaim {
        sid: sid.to_owned(),
        allow: true,
        rights,
        inheritance,
    }
}

fn exact_static_acl(agent_sid: &str, directory: bool) -> WindowsStaticAclClaim {
    let inheritance = if directory {
        WINDOWS_INHERIT_CONTAINERS_AND_OBJECTS
    } else {
        0
    };
    WindowsStaticAclClaim {
        owner_sid: WINDOWS_ADMINISTRATORS_SID.to_owned(),
        dacl_protected: true,
        entries: vec![
            static_allow(
                WINDOWS_LOCAL_SYSTEM_SID,
                WINDOWS_FILE_ALL_ACCESS,
                inheritance,
            ),
            static_allow(
                WINDOWS_ADMINISTRATORS_SID,
                WINDOWS_FILE_ALL_ACCESS,
                inheritance,
            ),
            static_allow(agent_sid, WINDOWS_FILE_READ_EXECUTE, inheritance),
        ],
    }
}

#[test]
fn windows_static_ancestors_accept_standard_windows_acl_shapes() {
    const CONTAINER_INHERIT: u32 = 0x0000_0002;
    const INHERIT_ONLY: u32 = 0x0000_0008;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const DELETE: u32 = 0x0001_0000;
    const AUTHENTICATED_USERS_SID: &str = "S-1-5-11";
    const USERS_SID: &str = "S-1-5-32-545";

    let agent_sid = "S-1-5-80-1-2-3-4-5";
    let claim = WindowsStaticBoundaryClaim {
        fixed_drive: true,
        reparse_free: true,
        canonical_components_match: true,
        directory_acl: exact_static_acl(agent_sid, true),
        leaf_acl: exact_static_acl(agent_sid, false),
        ancestors: vec![
            // A stock fixed-drive root contains an Authenticated Users ACE
            // whose destructive-looking rights apply only to inheriting
            // descendants, never to the root being checked.
            WindowsStaticAncestorClaim {
                system_managed: true,
                acl: WindowsStaticAclClaim {
                    owner_sid: WINDOWS_LOCAL_SYSTEM_SID.to_owned(),
                    dacl_protected: false,
                    entries: vec![static_allow(
                        AUTHENTICATED_USERS_SID,
                        GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE,
                        WINDOWS_INHERIT_CONTAINERS_AND_OBJECTS | INHERIT_ONLY,
                    )],
                },
            },
            // ProgramData grants Users create/write rights on the current
            // directory and propagates them to child containers. Those rights
            // cannot delete or replace an already protected child.
            WindowsStaticAncestorClaim {
                system_managed: true,
                acl: WindowsStaticAclClaim {
                    owner_sid: WINDOWS_LOCAL_SYSTEM_SID.to_owned(),
                    dacl_protected: false,
                    entries: vec![static_allow(
                        USERS_SID,
                        WINDOWS_SYSTEM_MANAGED_CREATE_ACCESS
                            | WINDOWS_FILE_WRITE_ATTRIBUTES
                            | WINDOWS_FILE_WRITE_EA,
                        CONTAINER_INHERIT,
                    )],
                },
            },
            // Program Files commonly exposes generic read/execute to Users.
            WindowsStaticAncestorClaim {
                system_managed: false,
                acl: WindowsStaticAclClaim {
                    owner_sid: WINDOWS_TRUSTED_INSTALLER_SID.to_owned(),
                    dacl_protected: false,
                    entries: vec![static_allow(
                        USERS_SID,
                        GENERIC_READ | GENERIC_EXECUTE,
                        WINDOWS_INHERIT_CONTAINERS_AND_OBJECTS,
                    )],
                },
            },
        ],
    };

    assert_eq!(
        validate_windows_static_boundary_claim(&claim, agent_sid),
        Ok(())
    );
}

#[test]
fn windows_static_ancestors_reject_effective_untrusted_replacement_rights() {
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const AUTHENTICATED_USERS_SID: &str = "S-1-5-11";

    let agent_sid = "S-1-5-80-1-2-3-4-5";
    for dangerous_right in [DELETE, WINDOWS_DELETE_CHILD_ACCESS, WRITE_DAC, WRITE_OWNER] {
        let claim = WindowsStaticBoundaryClaim {
            fixed_drive: true,
            reparse_free: true,
            canonical_components_match: true,
            directory_acl: exact_static_acl(agent_sid, true),
            leaf_acl: exact_static_acl(agent_sid, false),
            ancestors: vec![WindowsStaticAncestorClaim {
                system_managed: true,
                acl: WindowsStaticAclClaim {
                    owner_sid: WINDOWS_LOCAL_SYSTEM_SID.to_owned(),
                    dacl_protected: false,
                    entries: vec![static_allow(AUTHENTICATED_USERS_SID, dangerous_right, 0)],
                },
            }],
        };

        assert_eq!(
            validate_windows_static_boundary_claim(&claim, agent_sid),
            Err(SecureStoreError::Permissions),
            "effective untrusted access mask {dangerous_right:#010x} must be rejected"
        );
    }
}

#[test]
fn windows_static_reader_policy_is_read_only_owner_bound_and_ancestor_safe() {
    let agent_sid = "S-1-5-80-1-2-3-4-5";
    let broker_sid = "S-1-5-80-6-7-8-9-10";
    let data_root = WindowsStaticAncestorClaim {
        system_managed: false,
        acl: WindowsStaticAclClaim {
            owner_sid: WINDOWS_ADMINISTRATORS_SID.to_owned(),
            dacl_protected: true,
            entries: vec![
                static_allow(WINDOWS_LOCAL_SYSTEM_SID, WINDOWS_FILE_ALL_ACCESS, 0),
                static_allow(WINDOWS_ADMINISTRATORS_SID, WINDOWS_FILE_ALL_ACCESS, 0),
                static_allow(agent_sid, WINDOWS_FILE_READ_EXECUTE, 0),
                static_allow(broker_sid, WINDOWS_FILE_READ_EXECUTE, 0),
            ],
        },
    };
    let system_program_data = WindowsStaticAncestorClaim {
        system_managed: true,
        acl: WindowsStaticAclClaim {
            owner_sid: WINDOWS_LOCAL_SYSTEM_SID.to_owned(),
            dacl_protected: false,
            entries: vec![static_allow(
                "S-1-5-11",
                WINDOWS_SYSTEM_MANAGED_CREATE_ACCESS,
                0,
            )],
        },
    };
    let secure = WindowsStaticBoundaryClaim {
        fixed_drive: true,
        reparse_free: true,
        canonical_components_match: true,
        directory_acl: exact_static_acl(agent_sid, true),
        leaf_acl: exact_static_acl(agent_sid, false),
        ancestors: vec![data_root.clone(), system_program_data],
    };
    assert!(validate_windows_static_boundary_claim(&secure, agent_sid).is_ok());

    for invalid in [
        WindowsStaticBoundaryClaim {
            fixed_drive: false,
            ..secure.clone()
        },
        WindowsStaticBoundaryClaim {
            reparse_free: false,
            ..secure.clone()
        },
        WindowsStaticBoundaryClaim {
            canonical_components_match: false,
            ..secure.clone()
        },
        WindowsStaticBoundaryClaim {
            directory_acl: WindowsStaticAclClaim {
                owner_sid: WINDOWS_LOCAL_SYSTEM_SID.to_owned(),
                ..secure.directory_acl.clone()
            },
            ..secure.clone()
        },
        WindowsStaticBoundaryClaim {
            leaf_acl: WindowsStaticAclClaim {
                entries: vec![
                    static_allow(WINDOWS_LOCAL_SYSTEM_SID, WINDOWS_FILE_ALL_ACCESS, 0),
                    static_allow(WINDOWS_ADMINISTRATORS_SID, WINDOWS_FILE_ALL_ACCESS, 0),
                    static_allow(agent_sid, WINDOWS_FILE_ALL_ACCESS, 0),
                ],
                ..secure.leaf_acl.clone()
            },
            ..secure.clone()
        },
        WindowsStaticBoundaryClaim {
            ancestors: vec![WindowsStaticAncestorClaim {
                system_managed: false,
                acl: WindowsStaticAclClaim {
                    entries: vec![static_allow("S-1-5-11", WINDOWS_FILE_ALL_ACCESS, 0)],
                    ..data_root.acl.clone()
                },
            }],
            ..secure.clone()
        },
        WindowsStaticBoundaryClaim {
            ancestors: vec![WindowsStaticAncestorClaim {
                system_managed: true,
                acl: WindowsStaticAclClaim {
                    entries: vec![static_allow("S-1-5-11", WINDOWS_FILE_ALL_ACCESS, 0)],
                    ..data_root.acl.clone()
                },
            }],
            ..secure.clone()
        },
        WindowsStaticBoundaryClaim {
            ancestors: vec![WindowsStaticAncestorClaim {
                system_managed: true,
                acl: WindowsStaticAclClaim {
                    entries: vec![static_allow("S-1-5-11", WINDOWS_DELETE_CHILD_ACCESS, 0)],
                    ..data_root.acl.clone()
                },
            }],
            ..secure.clone()
        },
    ] {
        assert_eq!(
            validate_windows_static_boundary_claim(&invalid, agent_sid),
            Err(SecureStoreError::Permissions)
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_dpapi_machine_protector_encrypts_the_whole_envelope_and_binds_entropy() {
    let protector = DpapiMachineProtector::new();
    let plaintext = br#"{"schema":"mrd-relay-secure-envelope.v1","payload_b64":"c2VjcmV0"}"#;

    let sealed = protector
        .seal(b"node-a\0runtime\0path-a", plaintext)
        .unwrap();

    assert!(!sealed
        .windows("mrd-relay-secure-envelope".len())
        .any(|window| window == b"mrd-relay-secure-envelope"));
    assert_eq!(
        protector
            .open(b"node-a\0runtime\0path-a", &sealed)
            .unwrap()
            .as_slice(),
        plaintext
    );
    assert_eq!(
        protector.open(b"node-a\0runtime\0path-b", &sealed),
        Err(SecureStoreError::Invalid)
    );
    let mut tampered = sealed.to_vec();
    let tampered_index = tampered.len() / 2;
    tampered[tampered_index] ^= 0x40;
    assert_eq!(
        protector.open(b"node-a\0runtime\0path-a", &tampered),
        Err(SecureStoreError::Invalid)
    );
}

#[cfg(windows)]
#[test]
fn windows_file_policy_rejects_remote_device_ads_and_traversal_paths_and_uses_exact_sid_acl() {
    fn assert_atomic_envelope_file<T: AtomicEnvelopeFile>() {}
    assert_atomic_envelope_file::<HardenedAtomicFile>();

    let service_sid = "S-1-5-80-1-2-3-4-5";
    assert_eq!(
        protected_service_dacl_sddl(service_sid).unwrap(),
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-1-2-3-4-5)"
    );
    assert_eq!(
        protected_service_dacl_sddl("S-1-5-19"),
        Err(SecureStoreError::Invalid)
    );

    let trusted_root = std::path::PathBuf::from(r"C:\ProgramData\MRD\RelayAgent");
    for invalid in [
        std::path::PathBuf::from(r"relative\runtime.sec"),
        std::path::PathBuf::from(r"\\server\share\runtime.sec"),
        std::path::PathBuf::from(r"\\?\C:\ProgramData\MRD\runtime.sec"),
        std::path::PathBuf::from(r"\\.\C:\ProgramData\MRD\runtime.sec"),
        std::path::PathBuf::from(r"C:\ProgramData\MRD\runtime.sec:stream"),
        std::path::PathBuf::from(r"C:\ProgramData\MRD\RelayAgent\..\runtime.sec"),
        std::path::PathBuf::from(r"C:\ProgramData\MRD\RelayAgent\NUL"),
        std::path::PathBuf::from(r"C:\ProgramData\MRD\RelayAgent\runtime.sec."),
        std::path::PathBuf::from(r"C:\ProgramData\MRD\RelayAgent\runtime.sec "),
        std::path::PathBuf::from(r"C:\ProgramData\MRD\RelayAgent\run?time.sec"),
    ] {
        assert!(matches!(
            HardenedAtomicFile::new_windows(trusted_root.clone(), invalid, service_sid),
            Err(SecureStoreError::Invalid)
        ));
    }
    assert!(matches!(
        HardenedAtomicFile::new_windows(
            std::path::PathBuf::from(r"B:\MRD\RelayAgent"),
            std::path::PathBuf::from(r"B:\MRD\RelayAgent\runtime.sec"),
            service_sid,
        ),
        Err(SecureStoreError::Invalid)
    ));
}

#[cfg(windows)]
#[test]
fn windows_static_reader_rejects_paths_outside_the_exact_config_layout_before_io() {
    let service_sid = "S-1-5-80-1-2-3-4-5";
    let data_root = std::path::PathBuf::from(r"D:\中继数据\MRD\RelayAgent");
    for invalid in [
        std::path::PathBuf::from(r"D:\中继数据\MRD\RelayAgent\agent.json"),
        std::path::PathBuf::from(r"D:\中继数据\MRD\RelayAgent\state\agent.json"),
        std::path::PathBuf::from(r"D:\中继数据\MRD\RelayAgent2\config\agent.json"),
        std::path::PathBuf::from(r"D:\中继数据\MRD\RelayAgent\config\other.pem"),
        std::path::PathBuf::from(r"D:\中继数据\MRD\RelayAgent\config\agent.json:stream"),
        std::path::PathBuf::from(r"\\server\share\config\agent.json"),
    ] {
        assert!(matches!(
            WindowsTrustedStaticFile::new_windows(data_root.clone(), invalid, service_sid),
            Err(SecureStoreError::Invalid)
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_hardened_file_is_an_atomic_0600_bound_secret_store() {
    use std::os::unix::fs::PermissionsExt as _;

    fn assert_atomic_envelope_file<T: AtomicEnvelopeFile>() {}
    assert_atomic_envelope_file::<HardenedAtomicFile>();

    let root = LinuxTestRoot::new();
    let target = root.path().join("turn-secret.sec");
    let file =
        Arc::new(HardenedAtomicFile::new_linux(root.path().to_path_buf(), target.clone()).unwrap());
    let store = BoundSecretStore::new(
        file,
        Arc::new(LinuxPlaintextProtector::new()),
        "node-linux-a",
        SecretStorePurpose::TurnRestSecret,
    )
    .unwrap();

    store.atomic_replace(b"turn-rest-secret").unwrap();

    assert_eq!(
        store.load().unwrap().unwrap().as_slice(),
        b"turn-rest-secret"
    );
    assert_eq!(
        std::fs::symlink_metadata(&target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_hardened_file_and_credential_reader_reject_links_and_loose_modes() {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let root = LinuxTestRoot::new();
    let credential = root.path().join("bootstrap-token.credential");
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&credential)
        .unwrap();
    output.write_all(b"bootstrap-token").unwrap();
    output.sync_all().unwrap();
    drop(output);

    let reader = StrictCredentialFile::new_linux(credential.clone(), 128).unwrap();
    assert_eq!(reader.read_secret().unwrap().as_slice(), b"bootstrap-token");

    let linked = root.path().join("linked-token");
    std::os::unix::fs::symlink(&credential, &linked).unwrap();
    assert!(matches!(
        StrictCredentialFile::new_linux(linked.clone(), 128),
        Err(SecureStoreError::Invalid)
    ));
    assert!(matches!(
        HardenedAtomicFile::new_linux(root.path().to_path_buf(), linked),
        Err(SecureStoreError::Invalid)
    ));

    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(reader.read_secret(), Err(SecureStoreError::Permissions));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_integrity_reader_requires_a_root_owned_nonwritable_chain_and_regular_leaf() {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let root = LinuxTestRoot::new();
    let trusted = root.path().join("trusted-ca.pem");
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&trusted)
        .unwrap();
    output.write_all(b"test-ca").unwrap();
    output.sync_all().unwrap();
    drop(output);

    assert_eq!(
        read_linux_integrity_file(&trusted, 64 * 1024)
            .unwrap()
            .as_slice(),
        b"test-ca"
    );

    std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        read_linux_integrity_file(&trusted, 64 * 1024),
        Err(SecureStoreError::Permissions)
    );
    std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o644)).unwrap();

    let linked_leaf = root.path().join("linked-ca.pem");
    std::os::unix::fs::symlink(&trusted, &linked_leaf).unwrap();
    assert_eq!(
        read_linux_integrity_file(&linked_leaf, 64 * 1024),
        Err(SecureStoreError::Invalid)
    );

    let real_parent = root.path().join("real-parent");
    std::fs::create_dir(&real_parent).unwrap();
    std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let nested = real_parent.join("ca.pem");
    std::fs::write(&nested, b"nested-ca").unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o644)).unwrap();
    let linked_parent = root.path().join("linked-parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
    assert_eq!(
        read_linux_integrity_file(&linked_parent.join("ca.pem"), 64 * 1024),
        Err(SecureStoreError::Invalid)
    );
}

#[cfg(target_os = "linux")]
struct LinuxTestRoot(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl LinuxTestRoot {
    fn new() -> Self {
        use rand::{rngs::OsRng, RngCore as _};
        use std::os::unix::fs::PermissionsExt as _;

        let parent = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .expect("Linux secure-store contract tests require an absolute HOME");
        let path = parent.join(format!(
            "secure-store-contract-{}-{:016x}",
            std::process::id(),
            OsRng.next_u64()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxTestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
