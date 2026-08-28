use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    identity::{IdentityFsPort, StoredIdentity},
    runtime::{RuntimeError, RuntimeStateSnapshot, RuntimeStateStorePort},
};

const ENVELOPE_SCHEMA: &str = "mrd-relay-secure-envelope.v1";
const MAX_NODE_ID_BYTES: usize = 128;
const MAX_BINDING_PATH_BYTES: usize = 4096;
const MAX_RUNTIME_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_RUNTIME_SEALED_BYTES: usize = 128 * 1024;
const MAX_IDENTITY_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_IDENTITY_SEALED_BYTES: usize = 512 * 1024;
const MAX_SECRET_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_SECRET_SEALED_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SecureStoreError {
    #[error("secure_store_io")]
    Io,
    #[error("secure_store_invalid")]
    Invalid,
    #[error("secure_store_permissions_invalid")]
    Permissions,
}

pub const WINDOWS_LOCAL_SYSTEM_SID: &str = "S-1-5-18";
pub const WINDOWS_ADMINISTRATORS_SID: &str = "S-1-5-32-544";
pub const WINDOWS_TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
pub const WINDOWS_FILE_ALL_ACCESS: u32 = 0x001f_01ff;
pub const WINDOWS_FILE_READ_EXECUTE: u32 = 0x0012_00a9;
pub const WINDOWS_INHERIT_CONTAINERS_AND_OBJECTS: u32 = 0x0000_0003;
pub const WINDOWS_SYSTEM_MANAGED_CREATE_ACCESS: u32 = 0x0000_0006;
const WINDOWS_DELETE_ACCESS: u32 = 0x0001_0000;
pub const WINDOWS_DELETE_CHILD_ACCESS: u32 = 0x0000_0040;
pub const WINDOWS_FILE_WRITE_EA: u32 = 0x0000_0010;
pub const WINDOWS_FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const WINDOWS_WRITE_DACL_ACCESS: u32 = 0x0004_0000;
const WINDOWS_WRITE_OWNER_ACCESS: u32 = 0x0008_0000;
const WINDOWS_GENERIC_ALL_ACCESS: u32 = 0x1000_0000;
const WINDOWS_INHERIT_ONLY: u32 = 0x0000_0008;
const WINDOWS_ANCESTOR_REPLACEMENT_ACCESS: u32 = WINDOWS_DELETE_ACCESS
    | WINDOWS_DELETE_CHILD_ACCESS
    | WINDOWS_WRITE_DACL_ACCESS
    | WINDOWS_WRITE_OWNER_ACCESS
    | WINDOWS_GENERIC_ALL_ACCESS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsStaticAceClaim {
    pub sid: String,
    pub allow: bool,
    pub rights: u32,
    pub inheritance: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsStaticAclClaim {
    pub owner_sid: String,
    pub dacl_protected: bool,
    pub entries: Vec<WindowsStaticAceClaim>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsStaticAncestorClaim {
    pub system_managed: bool,
    pub acl: WindowsStaticAclClaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsStaticBoundaryClaim {
    pub fixed_drive: bool,
    pub reparse_free: bool,
    pub canonical_components_match: bool,
    pub directory_acl: WindowsStaticAclClaim,
    pub leaf_acl: WindowsStaticAclClaim,
    pub ancestors: Vec<WindowsStaticAncestorClaim>,
}

pub fn validate_windows_static_boundary_claim(
    claim: &WindowsStaticBoundaryClaim,
    agent_service_sid: &str,
) -> Result<(), SecureStoreError> {
    if !claim.fixed_drive
        || !claim.reparse_free
        || !claim.canonical_components_match
        || !valid_windows_service_sid_text(agent_service_sid)
        || claim.ancestors.is_empty()
    {
        return Err(SecureStoreError::Permissions);
    }
    validate_windows_static_exact_acl(&claim.directory_acl, agent_service_sid, true)?;
    validate_windows_static_exact_acl(&claim.leaf_acl, agent_service_sid, false)?;
    for ancestor in &claim.ancestors {
        validate_windows_static_ancestor(ancestor)?;
    }
    Ok(())
}

fn validate_windows_static_exact_acl(
    acl: &WindowsStaticAclClaim,
    agent_service_sid: &str,
    directory: bool,
) -> Result<(), SecureStoreError> {
    if acl.owner_sid != WINDOWS_ADMINISTRATORS_SID || !acl.dacl_protected {
        return Err(SecureStoreError::Permissions);
    }
    let inheritance = if directory {
        WINDOWS_INHERIT_CONTAINERS_AND_OBJECTS
    } else {
        0
    };
    let expected = [
        (WINDOWS_LOCAL_SYSTEM_SID, WINDOWS_FILE_ALL_ACCESS),
        (WINDOWS_ADMINISTRATORS_SID, WINDOWS_FILE_ALL_ACCESS),
        (agent_service_sid, WINDOWS_FILE_READ_EXECUTE),
    ];
    if acl.entries.len() != expected.len() {
        return Err(SecureStoreError::Permissions);
    }
    for (sid, rights) in expected {
        let mut matches = acl.entries.iter().filter(|entry| entry.sid == sid);
        let Some(entry) = matches.next() else {
            return Err(SecureStoreError::Permissions);
        };
        if matches.next().is_some()
            || !entry.allow
            || entry.rights != rights
            || entry.inheritance != inheritance
        {
            return Err(SecureStoreError::Permissions);
        }
    }
    Ok(())
}

fn validate_windows_static_ancestor(
    ancestor: &WindowsStaticAncestorClaim,
) -> Result<(), SecureStoreError> {
    if !matches!(
        ancestor.acl.owner_sid.as_str(),
        WINDOWS_LOCAL_SYSTEM_SID | WINDOWS_ADMINISTRATORS_SID | WINDOWS_TRUSTED_INSTALLER_SID
    ) {
        return Err(SecureStoreError::Permissions);
    }
    for entry in ancestor.acl.entries.iter().filter(|entry| entry.allow) {
        // An inherit-only ACE cannot mutate this ancestor. If it becomes
        // effective on a real descendant, that descendant's own DACL is read
        // and checked separately while walking the canonical path.
        if entry.inheritance & WINDOWS_INHERIT_ONLY != 0 {
            continue;
        }
        let trusted = matches!(
            entry.sid.as_str(),
            WINDOWS_LOCAL_SYSTEM_SID | WINDOWS_ADMINISTRATORS_SID | WINDOWS_TRUSTED_INSTALLER_SID
        );
        if trusted {
            continue;
        }
        // Creating siblings and changing ordinary directory metadata do not
        // permit replacement of an existing protected child. DELETE on this
        // object, DELETE_CHILD, WRITE_DAC, WRITE_OWNER, and GENERIC_ALL do.
        if entry.rights & WINDOWS_ANCESTOR_REPLACEMENT_ACCESS != 0 {
            return Err(SecureStoreError::Permissions);
        }
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod windows_static_ancestor_tests {
    use super::*;

    #[test]
    fn installed_windows_root_and_program_data_acl_are_ancestor_safe() {
        let roots = windows_system_managed_roots()
            .expect("the Windows fixed-drive root and ProgramData must be discoverable");
        assert_eq!(roots.len(), 2);

        for path in roots {
            let claim = WindowsStaticAncestorClaim {
                system_managed: true,
                acl: windows_acl_claim_from_path(&path)
                    .unwrap_or_else(|error| panic!("failed to read ACL for {path:?}: {error}")),
            };
            assert_eq!(
                validate_windows_static_ancestor(&claim),
                Ok(()),
                "standard Windows ancestor ACL must be accepted: {path:?}"
            );
        }
    }
}

fn valid_windows_service_sid_text(value: &str) -> bool {
    let Some(components) = value.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let mut count = 0usize;
    for component in components.split('-') {
        if component.is_empty()
            || component.len() > 10
            || !component.bytes().all(|byte| byte.is_ascii_digit())
            || component.parse::<u32>().is_err()
        {
            return false;
        }
        count += 1;
    }
    count == 5
}

pub trait EnvelopeProtector: Send + Sync {
    fn seal(
        &self,
        binding: &[u8],
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError>;

    fn open(&self, binding: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError>;
}

pub trait AtomicEnvelopeFile: Send + Sync {
    fn canonical_path(&self) -> &str;
    fn read(&self, max_bytes: usize) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError>;
    fn atomic_replace(&self, value: &[u8], max_bytes: usize) -> Result<(), SecureStoreError>;
    fn enforce_strict_permissions(&self) -> Result<(), SecureStoreError>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EnvelopePurpose {
    Identity,
    RuntimeState,
    BootstrapEnrollmentToken,
    TurnRestSecret,
    BrokerActiveTurnSecret,
    BrokerControlState,
    BrokerControlJournal,
}

impl EnvelopePurpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::RuntimeState => "runtime_state",
            Self::BootstrapEnrollmentToken => "bootstrap_enrollment_token",
            Self::TurnRestSecret => "turn_rest_secret",
            Self::BrokerActiveTurnSecret => "broker_active_turn_secret",
            Self::BrokerControlState => "broker_control_state",
            Self::BrokerControlJournal => "broker_control_journal",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundEnvelope {
    canonical_path: String,
    node_id: String,
    payload_b64: String,
    purpose: EnvelopePurpose,
    schema: String,
}

impl Drop for BoundEnvelope {
    fn drop(&mut self) {
        self.canonical_path.zeroize();
        self.node_id.zeroize();
        self.payload_b64.zeroize();
        self.schema.zeroize();
    }
}

struct BoundEnvelopeStore<F, P> {
    file: Arc<F>,
    protector: Arc<P>,
    node_id: String,
    purpose: EnvelopePurpose,
    binding: Zeroizing<Vec<u8>>,
    max_payload_bytes: usize,
    max_sealed_bytes: usize,
}

impl<F, P> BoundEnvelopeStore<F, P>
where
    F: AtomicEnvelopeFile,
    P: EnvelopeProtector,
{
    fn new(
        file: Arc<F>,
        protector: Arc<P>,
        node_id: &str,
        purpose: EnvelopePurpose,
        max_payload_bytes: usize,
        max_sealed_bytes: usize,
    ) -> Result<Self, SecureStoreError> {
        let path = file.canonical_path();
        if !valid_node_id(node_id)
            || path.is_empty()
            || path.len() > MAX_BINDING_PATH_BYTES
            || path.contains('\0')
            || max_payload_bytes == 0
            || max_sealed_bytes < max_payload_bytes
        {
            return Err(SecureStoreError::Invalid);
        }
        let binding = Zeroizing::new(binding_bytes(purpose, node_id, path));
        Ok(Self {
            file,
            protector,
            node_id: node_id.to_owned(),
            purpose,
            binding,
            max_payload_bytes,
            max_sealed_bytes,
        })
    }

    fn load_payload(&self) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        self.file.enforce_strict_permissions()?;
        let Some(sealed) = self.file.read(self.max_sealed_bytes)? else {
            return Ok(None);
        };
        let plaintext = self.protector.open(&self.binding, &sealed)?;
        if plaintext.len() > self.max_sealed_bytes {
            return Err(SecureStoreError::Invalid);
        }
        let envelope: BoundEnvelope =
            serde_json::from_slice(&plaintext).map_err(|_| SecureStoreError::Invalid)?;
        if envelope.schema != ENVELOPE_SCHEMA
            || envelope.purpose != self.purpose
            || envelope.node_id != self.node_id
            || envelope.canonical_path != self.file.canonical_path()
        {
            return Err(SecureStoreError::Invalid);
        }
        let payload = Zeroizing::new(
            STANDARD
                .decode(envelope.payload_b64.as_bytes())
                .map_err(|_| SecureStoreError::Invalid)?,
        );
        if payload.len() > self.max_payload_bytes
            || STANDARD.encode(payload.as_slice()) != envelope.payload_b64
        {
            return Err(SecureStoreError::Invalid);
        }
        Ok(Some(payload))
    }

    fn store_payload(&self, payload: &[u8]) -> Result<(), SecureStoreError> {
        if payload.len() > self.max_payload_bytes {
            return Err(SecureStoreError::Invalid);
        }
        let envelope = BoundEnvelope {
            canonical_path: self.file.canonical_path().to_owned(),
            node_id: self.node_id.clone(),
            payload_b64: STANDARD.encode(payload),
            purpose: self.purpose,
            schema: ENVELOPE_SCHEMA.to_owned(),
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| SecureStoreError::Invalid)?);
        if plaintext.len() > self.max_sealed_bytes {
            return Err(SecureStoreError::Invalid);
        }
        let sealed = self.protector.seal(&self.binding, &plaintext)?;
        self.file.atomic_replace(&sealed, self.max_sealed_bytes)?;
        self.file.enforce_strict_permissions()
    }
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_ID_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn binding_bytes(purpose: EnvelopePurpose, node_id: &str, path: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(
        ENVELOPE_SCHEMA.len() + purpose.as_str().len() + node_id.len() + path.len() + 4,
    );
    result.extend_from_slice(ENVELOPE_SCHEMA.as_bytes());
    result.push(0);
    result.extend_from_slice(purpose.as_str().as_bytes());
    result.push(0);
    result.extend_from_slice(node_id.as_bytes());
    result.push(0);
    result.extend_from_slice(path.as_bytes());
    result
}

pub struct SecureRuntimeStateStore<F, P> {
    inner: BoundEnvelopeStore<F, P>,
    mutation_lock: std::sync::Mutex<()>,
}

pub struct SecureIdentityStore<F, P> {
    inner: BoundEnvelopeStore<F, P>,
}

impl<F, P> SecureIdentityStore<F, P>
where
    F: AtomicEnvelopeFile,
    P: EnvelopeProtector,
{
    pub fn new(file: Arc<F>, protector: Arc<P>, node_id: &str) -> Result<Self, RuntimeError> {
        BoundEnvelopeStore::new(
            file,
            protector,
            node_id,
            EnvelopePurpose::Identity,
            MAX_IDENTITY_PAYLOAD_BYTES,
            MAX_IDENTITY_SEALED_BYTES,
        )
        .map(|inner| Self { inner })
        .map_err(identity_error)
    }
}

impl<F, P> IdentityFsPort for SecureIdentityStore<F, P>
where
    F: AtomicEnvelopeFile,
    P: EnvelopeProtector,
{
    fn load(&self) -> Result<Option<StoredIdentity>, RuntimeError> {
        let Some(payload) = self.inner.load_payload().map_err(identity_error)? else {
            return Ok(None);
        };
        serde_json::from_slice(&payload)
            .map(Some)
            .map_err(|_| RuntimeError::IdentityInvalid)
    }

    fn atomic_replace(&self, identity: &StoredIdentity) -> Result<(), RuntimeError> {
        let payload = Zeroizing::new(
            serde_json::to_vec(identity).map_err(|_| RuntimeError::IdentityInvalid)?,
        );
        self.inner.store_payload(&payload).map_err(identity_error)
    }

    fn enforce_strict_permissions(&self) -> Result<(), RuntimeError> {
        self.inner
            .file
            .enforce_strict_permissions()
            .map_err(identity_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretStorePurpose {
    BootstrapEnrollmentToken,
    TurnRestSecret,
    BrokerActiveTurnSecret,
    BrokerControlState,
    BrokerControlJournal,
}

impl SecretStorePurpose {
    const fn envelope_purpose(self) -> EnvelopePurpose {
        match self {
            Self::BootstrapEnrollmentToken => EnvelopePurpose::BootstrapEnrollmentToken,
            Self::TurnRestSecret => EnvelopePurpose::TurnRestSecret,
            Self::BrokerActiveTurnSecret => EnvelopePurpose::BrokerActiveTurnSecret,
            Self::BrokerControlState => EnvelopePurpose::BrokerControlState,
            Self::BrokerControlJournal => EnvelopePurpose::BrokerControlJournal,
        }
    }
}

pub struct BoundSecretStore<F, P> {
    inner: BoundEnvelopeStore<F, P>,
}

impl<F, P> BoundSecretStore<F, P>
where
    F: AtomicEnvelopeFile,
    P: EnvelopeProtector,
{
    pub fn new(
        file: Arc<F>,
        protector: Arc<P>,
        node_id: &str,
        purpose: SecretStorePurpose,
    ) -> Result<Self, SecureStoreError> {
        BoundEnvelopeStore::new(
            file,
            protector,
            node_id,
            purpose.envelope_purpose(),
            MAX_SECRET_PAYLOAD_BYTES,
            MAX_SECRET_SEALED_BYTES,
        )
        .map(|inner| Self { inner })
    }

    pub fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        self.inner.load_payload()
    }

    pub fn atomic_replace(&self, secret: &[u8]) -> Result<(), SecureStoreError> {
        if secret.is_empty() {
            return Err(SecureStoreError::Invalid);
        }
        self.inner.store_payload(secret)
    }
}

impl<F, P> SecureRuntimeStateStore<F, P>
where
    F: AtomicEnvelopeFile,
    P: EnvelopeProtector,
{
    pub fn new(file: Arc<F>, protector: Arc<P>, node_id: &str) -> Result<Self, RuntimeError> {
        BoundEnvelopeStore::new(
            file,
            protector,
            node_id,
            EnvelopePurpose::RuntimeState,
            MAX_RUNTIME_PAYLOAD_BYTES,
            MAX_RUNTIME_SEALED_BYTES,
        )
        .map(|inner| Self {
            inner,
            mutation_lock: std::sync::Mutex::new(()),
        })
        .map_err(runtime_error)
    }

    fn load_unlocked(&self) -> Result<RuntimeStateSnapshot, RuntimeError> {
        let Some(payload) = self.inner.load_payload().map_err(runtime_error)? else {
            return Ok(RuntimeStateSnapshot::default());
        };
        serde_json::from_slice(&payload).map_err(|_| RuntimeError::StateInvalid)
    }

    fn atomic_store_unlocked(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError> {
        let payload =
            Zeroizing::new(serde_json::to_vec(state).map_err(|_| RuntimeError::StateInvalid)?);
        self.inner.store_payload(&payload).map_err(runtime_error)
    }
}

impl<F, P> RuntimeStateStorePort for SecureRuntimeStateStore<F, P>
where
    F: AtomicEnvelopeFile,
    P: EnvelopeProtector,
{
    fn load(&self) -> Result<RuntimeStateSnapshot, RuntimeError> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| RuntimeError::StateIo)?;
        self.load_unlocked()
    }

    fn atomic_store(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| RuntimeError::StateIo)?;
        self.atomic_store_unlocked(state)
    }

    fn mutate(
        &self,
        mutation: &mut dyn FnMut(&mut RuntimeStateSnapshot) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| RuntimeError::StateIo)?;
        let mut state = self.load_unlocked()?;
        mutation(&mut state)?;
        self.atomic_store_unlocked(&state)
    }
}

fn runtime_error(error: SecureStoreError) -> RuntimeError {
    match error {
        SecureStoreError::Io => RuntimeError::StateIo,
        SecureStoreError::Invalid | SecureStoreError::Permissions => RuntimeError::StateInvalid,
    }
}

fn identity_error(error: SecureStoreError) -> RuntimeError {
    match error {
        SecureStoreError::Io => RuntimeError::IdentityIo,
        SecureStoreError::Invalid => RuntimeError::IdentityInvalid,
        SecureStoreError::Permissions => RuntimeError::IdentityPermissions,
    }
}

#[cfg(windows)]
pub struct DpapiMachineProtector;

#[cfg(windows)]
impl DpapiMachineProtector {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(windows)]
impl Default for DpapiMachineProtector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl EnvelopeProtector for DpapiMachineProtector {
    fn seal(
        &self,
        binding: &[u8],
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        dpapi_protect(binding, plaintext)
    }

    fn open(&self, binding: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        dpapi_unprotect(binding, sealed)
    }
}

#[cfg(windows)]
fn dpapi_protect(binding: &[u8], plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    use sha2::{Digest as _, Sha256};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if plaintext.is_empty() || plaintext.len() > 1024 * 1024 {
        return Err(SecureStoreError::Invalid);
    }
    let mut entropy = Zeroizing::new(Sha256::digest(binding).to_vec());
    let input_len = u32::try_from(plaintext.len()).map_err(|_| SecureStoreError::Invalid)?;
    let entropy_len = u32::try_from(entropy.len()).map_err(|_| SecureStoreError::Invalid)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_len,
        pbData: entropy.as_mut_ptr(),
    };
    let mut output = LocalCryptBlob::empty();
    // SAFETY: input and entropy point to live buffers of the declared sizes;
    // output is initialized for CryptProtectData to allocate with LocalAlloc.
    let protected = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy_blob,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.blob,
        )
    };
    if protected == 0 {
        return Err(SecureStoreError::Io);
    }
    output.copy_bounded(1024 * 1024)
}

#[cfg(windows)]
fn dpapi_unprotect(binding: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    use sha2::{Digest as _, Sha256};
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if sealed.is_empty() || sealed.len() > 1024 * 1024 {
        return Err(SecureStoreError::Invalid);
    }
    let mut entropy = Zeroizing::new(Sha256::digest(binding).to_vec());
    let input_len = u32::try_from(sealed.len()).map_err(|_| SecureStoreError::Invalid)?;
    let entropy_len = u32::try_from(entropy.len()).map_err(|_| SecureStoreError::Invalid)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: sealed.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_len,
        pbData: entropy.as_mut_ptr(),
    };
    let mut output = LocalCryptBlob::empty();
    // SAFETY: input and entropy point to live buffers of the declared sizes;
    // no description is requested, and output is initialized for LocalAlloc.
    let unprotected = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy_blob,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.blob,
        )
    };
    if unprotected == 0 {
        return Err(SecureStoreError::Invalid);
    }
    output.copy_bounded(1024 * 1024)
}

#[cfg(windows)]
struct LocalCryptBlob {
    blob: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
}

#[cfg(windows)]
impl LocalCryptBlob {
    const fn empty() -> Self {
        Self {
            blob: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            },
        }
    }

    fn copy_bounded(&self, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        let length = self.blob.cbData as usize;
        if self.blob.pbData.is_null() || length == 0 || length > max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        // SAFETY: a successful DPAPI call returns a LocalAlloc buffer containing
        // exactly cbData bytes and keeps it valid until LocalFree in Drop.
        let source = unsafe { std::slice::from_raw_parts(self.blob.pbData, length) };
        Ok(Zeroizing::new(source.to_vec()))
    }
}

#[cfg(windows)]
impl Drop for LocalCryptBlob {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        if self.blob.pbData.is_null() {
            return;
        }
        for offset in 0..self.blob.cbData as usize {
            // SAFETY: the DPAPI output buffer remains live and writable until
            // LocalFree. Volatile writes prevent eliding the plaintext wipe.
            unsafe { std::ptr::write_volatile(self.blob.pbData.add(offset), 0) };
        }
        // SAFETY: DPAPI allocated this exact pointer with LocalAlloc.
        unsafe {
            let _ = LocalFree(self.blob.pbData.cast());
        }
        self.blob.pbData = std::ptr::null_mut();
        self.blob.cbData = 0;
    }
}

#[cfg(windows)]
pub fn protected_service_dacl_sddl(service_sid: &str) -> Result<String, SecureStoreError> {
    if !valid_service_sid(service_sid) {
        return Err(SecureStoreError::Invalid);
    }
    Ok(format!(
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{service_sid})"
    ))
}

#[cfg(windows)]
fn valid_service_sid(value: &str) -> bool {
    let Some(components) = value.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let mut count = 0usize;
    for component in components.split('-') {
        if component.is_empty()
            || component.len() > 10
            || !component.bytes().all(|byte| byte.is_ascii_digit())
            || component.parse::<u32>().is_err()
        {
            return false;
        }
        count += 1;
    }
    count == 5
}

pub struct HardenedAtomicFile {
    path: std::path::PathBuf,
    canonical_path: String,
    #[cfg(any(windows, target_os = "linux"))]
    trusted_root: std::path::PathBuf,
    #[cfg(windows)]
    service_sid: String,
}

/// Read-only integrity boundary for installed Windows configuration and trust
/// anchors. Unlike [`HardenedAtomicFile`], this type never grants the agent a
/// mutation capability and requires the installed RX-only service SID ACL.
#[cfg(windows)]
pub struct WindowsTrustedStaticFile {
    data_root: std::path::PathBuf,
    static_directory: std::path::PathBuf,
    path: std::path::PathBuf,
    service_sid: String,
}

#[cfg(windows)]
impl WindowsTrustedStaticFile {
    pub fn new_windows(
        data_root: std::path::PathBuf,
        path: std::path::PathBuf,
        service_sid: &str,
    ) -> Result<Self, SecureStoreError> {
        if !valid_windows_local_path(&data_root)
            || !valid_windows_local_path(&path)
            || !valid_service_sid(service_sid)
            || !windows_static_path_matches_layout(&data_root, &path)
        {
            return Err(SecureStoreError::Invalid);
        }
        let static_directory = path
            .parent()
            .ok_or(SecureStoreError::Invalid)?
            .to_path_buf();
        let reader = Self {
            data_root,
            static_directory,
            path,
            service_sid: service_sid.to_owned(),
        };
        reader.verify_windows_boundary()?;
        Ok(reader)
    }

    pub fn read(&self, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        use std::io::Read as _;
        use std::os::windows::{
            fs::{MetadataExt as _, OpenOptionsExt as _},
            io::AsRawHandle as _,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };

        if max_bytes == 0 {
            return Err(SecureStoreError::Invalid);
        }
        self.verify_windows_boundary()?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.path)
            .map_err(|_| SecureStoreError::Io)?;
        let metadata = file.metadata().map_err(|_| SecureStoreError::Io)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() == 0
            || metadata.len() > max_bytes as u64
        {
            return Err(SecureStoreError::Invalid);
        }
        let handle_claim = windows_acl_claim_from_handle(file.as_raw_handle().cast())?;
        validate_windows_static_exact_acl(&handle_claim, &self.service_sid, false)?;

        let mut bytes = Zeroizing::new(Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(max_bytes)
                .min(max_bytes),
        ));
        (&file)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| SecureStoreError::Io)?;
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        self.verify_windows_boundary()?;
        Ok(bytes)
    }

    fn verify_windows_boundary(&self) -> Result<(), SecureStoreError> {
        verify_windows_fixed_drive(&self.data_root)?;
        reject_windows_reparse_chain(&self.path)?;

        let canonical_root =
            std::fs::canonicalize(&self.data_root).map_err(|_| SecureStoreError::Io)?;
        let canonical_directory =
            std::fs::canonicalize(&self.static_directory).map_err(|_| SecureStoreError::Io)?;
        let canonical_path = std::fs::canonicalize(&self.path).map_err(|_| SecureStoreError::Io)?;
        let leaf = self.path.file_name().ok_or(SecureStoreError::Invalid)?;
        if !canonical_root.is_dir()
            || !canonical_directory.is_dir()
            || !canonical_path.is_file()
            || !windows_paths_equal_ordinal(&canonical_root.join("config"), &canonical_directory)
            || !windows_paths_equal_ordinal(&canonical_directory.join(leaf), &canonical_path)
        {
            return Err(SecureStoreError::Invalid);
        }

        let directory_acl = windows_acl_claim_from_path(&canonical_directory)?;
        let leaf_acl = windows_acl_claim_from_path(&canonical_path)?;
        let system_managed = windows_system_managed_roots()?;
        let mut ancestors = Vec::new();
        let mut current = Some(canonical_root.as_path());
        while let Some(path) = current {
            if ancestors.len() >= 64 {
                return Err(SecureStoreError::Invalid);
            }
            ancestors.push(WindowsStaticAncestorClaim {
                system_managed: system_managed
                    .iter()
                    .any(|managed| windows_paths_equal_ordinal(managed, path)),
                acl: windows_acl_claim_from_path(path)?,
            });
            current = path.parent();
        }
        validate_windows_static_boundary_claim(
            &WindowsStaticBoundaryClaim {
                fixed_drive: true,
                reparse_free: true,
                canonical_components_match: true,
                directory_acl,
                leaf_acl,
                ancestors,
            },
            &self.service_sid,
        )
    }
}

#[cfg(windows)]
impl HardenedAtomicFile {
    pub fn new_windows(
        trusted_root: std::path::PathBuf,
        path: std::path::PathBuf,
        service_sid: &str,
    ) -> Result<Self, SecureStoreError> {
        if !valid_windows_local_path(&trusted_root)
            || !valid_windows_local_path(&path)
            || !valid_service_sid(service_sid)
            || path.parent() != Some(trusted_root.as_path())
        {
            return Err(SecureStoreError::Invalid);
        }
        verify_windows_fixed_drive(&trusted_root)?;
        reject_windows_reparse_chain(&trusted_root)?;
        let canonical_root =
            std::fs::canonicalize(&trusted_root).map_err(|_| SecureStoreError::Io)?;
        if !canonical_root.is_dir() {
            return Err(SecureStoreError::Invalid);
        }
        verify_windows_exact_dacl(&canonical_root, service_sid)?;
        let file_name = path.file_name().ok_or(SecureStoreError::Invalid)?;
        let canonical_target = canonical_root.join(file_name);
        if let Some(metadata) = windows_optional_metadata(&canonical_target)? {
            reject_windows_reparse(&canonical_target)?;
            if !metadata.is_file() {
                return Err(SecureStoreError::Invalid);
            }
            verify_windows_exact_dacl(&canonical_target, service_sid)?;
        }
        let canonical_path = canonical_target
            .to_str()
            .filter(|value| !value.is_empty() && value.len() <= MAX_BINDING_PATH_BYTES)
            .ok_or(SecureStoreError::Invalid)?
            .to_owned();
        Ok(Self {
            path: canonical_target,
            canonical_path,
            trusted_root: canonical_root,
            service_sid: service_sid.to_owned(),
        })
    }
}

#[cfg(windows)]
impl AtomicEnvelopeFile for HardenedAtomicFile {
    fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    fn read(&self, max_bytes: usize) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        use std::io::Read as _;
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        if max_bytes == 0 {
            return Err(SecureStoreError::Invalid);
        }
        self.verify_windows_boundary()?;
        if windows_optional_metadata(&self.path)?.is_none() {
            return Ok(None);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.path)
            .map_err(|_| SecureStoreError::Io)?;
        let metadata = file.metadata().map_err(|_| SecureStoreError::Io)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > max_bytes as u64
        {
            return Err(SecureStoreError::Invalid);
        }
        let limit = u64::try_from(max_bytes)
            .map_err(|_| SecureStoreError::Invalid)?
            .saturating_add(1);
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(max_bytes)
                .min(max_bytes),
        ));
        file.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| SecureStoreError::Io)?;
        if bytes.len() > max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        Ok(Some(bytes))
    }

    fn atomic_replace(&self, value: &[u8], max_bytes: usize) -> Result<(), SecureStoreError> {
        use std::io::Write as _;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        if value.is_empty() || max_bytes == 0 || value.len() > max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        self.verify_windows_boundary()?;
        let (temp_path, mut temp_file) = self.create_windows_temp()?;
        let write_result = (|| {
            set_windows_exact_dacl(&temp_path, &self.service_sid)?;
            temp_file
                .write_all(value)
                .map_err(|_| SecureStoreError::Io)?;
            temp_file.sync_all().map_err(|_| SecureStoreError::Io)?;
            Ok(())
        })();
        drop(temp_file);
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temp_path);
            return Err(error);
        }
        let verified = reject_windows_reparse(&temp_path)
            .and_then(|()| verify_windows_exact_dacl(&temp_path, &self.service_sid));
        if let Err(error) = verified {
            let _ = std::fs::remove_file(&temp_path);
            return Err(error);
        }

        let from = match windows_wide_path(&temp_path) {
            Ok(value) => value,
            Err(error) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(error);
            }
        };
        let to = match windows_wide_path(&self.path) {
            Ok(value) => value,
            Err(error) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(error);
            }
        };
        // SAFETY: both paths are live, NUL-terminated UTF-16 buffers. The
        // temporary source is a same-directory create_new regular file.
        let moved = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            let _ = std::fs::remove_file(&temp_path);
            return Err(SecureStoreError::Io);
        }
        self.verify_windows_boundary()
    }

    fn enforce_strict_permissions(&self) -> Result<(), SecureStoreError> {
        self.verify_windows_boundary()
    }
}

#[cfg(windows)]
impl HardenedAtomicFile {
    fn verify_windows_boundary(&self) -> Result<(), SecureStoreError> {
        verify_windows_fixed_drive(&self.trusted_root)?;
        reject_windows_reparse_chain(&self.trusted_root)?;
        verify_windows_exact_dacl(&self.trusted_root, &self.service_sid)?;
        if let Some(metadata) = windows_optional_metadata(&self.path)? {
            reject_windows_reparse(&self.path)?;
            if !metadata.is_file() {
                return Err(SecureStoreError::Invalid);
            }
            verify_windows_exact_dacl(&self.path, &self.service_sid)?;
        }
        Ok(())
    }

    fn create_windows_temp(&self) -> Result<(std::path::PathBuf, std::fs::File), SecureStoreError> {
        use rand::{rngs::OsRng, RngCore as _};
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        };

        let file_name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(SecureStoreError::Invalid)?;
        for _ in 0..32 {
            let candidate = self
                .trusted_root
                .join(format!(".{file_name}.{:016x}.tmp", OsRng.next_u64()));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
                .open(&candidate)
            {
                Ok(file) => return Ok((candidate, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(SecureStoreError::Io),
            }
        }
        Err(SecureStoreError::Io)
    }
}

#[cfg(windows)]
fn set_windows_exact_dacl(
    path: &std::path::Path,
    service_sid: &str,
) -> Result<(), SecureStoreError> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        },
    };

    let sddl = protected_service_dacl_sddl(service_sid)?;
    let sddl_wide = windows_wide_string(&sddl)?;
    let mut descriptor = LocalSecurityDescriptor::empty();
    // SAFETY: sddl_wide is a live NUL-terminated buffer and descriptor is a
    // valid out-pointer receiving LocalAlloc storage.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor.pointer,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.pointer.is_null() {
        return Err(SecureStoreError::Io);
    }
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    // SAFETY: descriptor owns a valid security descriptor returned above and
    // all remaining arguments are initialized out-pointers.
    let got_dacl = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.pointer,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if got_dacl == 0 || dacl_present == 0 || dacl.is_null() {
        return Err(SecureStoreError::Io);
    }
    let mut path_wide = windows_wide_path(path)?;
    // SAFETY: path_wide is a writable NUL-terminated buffer, dacl remains
    // owned by descriptor for the duration of this call, and no owner/SACL is
    // requested.
    let result = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(SecureStoreError::Io);
    }
    verify_windows_exact_dacl(path, service_sid)
}

#[cfg(windows)]
fn verify_windows_exact_dacl(
    path: &std::path::Path,
    service_sid: &str,
) -> Result<(), SecureStoreError> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
            GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        },
    };

    let path_wide = windows_wide_path(path)?;
    let mut descriptor = LocalSecurityDescriptor::empty();
    // SAFETY: path_wide is a live NUL-terminated buffer; unused out-pointers
    // are null and descriptor receives LocalAlloc storage on success.
    let result = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor.pointer,
        )
    };
    if result != ERROR_SUCCESS || descriptor.pointer.is_null() {
        return Err(SecureStoreError::Io);
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor points to the live descriptor returned above and both
    // output scalars are initialized.
    let got_control =
        unsafe { GetSecurityDescriptorControl(descriptor.pointer, &mut control, &mut revision) };
    if got_control == 0 || control & SE_DACL_PROTECTED == 0 {
        return Err(SecureStoreError::Permissions);
    }
    let actual = windows_descriptor_dacl_sddl(descriptor.pointer)?;
    let expected_descriptor =
        windows_descriptor_from_sddl(&protected_service_dacl_sddl(service_sid)?)?;
    let expected = windows_descriptor_dacl_sddl(expected_descriptor.pointer)?;
    if actual != expected {
        return Err(SecureStoreError::Permissions);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_descriptor_from_sddl(sddl: &str) -> Result<LocalSecurityDescriptor, SecureStoreError> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    let wide = windows_wide_string(sddl)?;
    let mut descriptor = LocalSecurityDescriptor::empty();
    // SAFETY: wide is live and NUL-terminated and descriptor is a valid
    // out-pointer receiving LocalAlloc storage.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor.pointer,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.pointer.is_null() {
        return Err(SecureStoreError::Io);
    }
    Ok(descriptor)
}

#[cfg(windows)]
fn windows_descriptor_dacl_sddl(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<String, SecureStoreError> {
    use windows_sys::Win32::Security::{
        Authorization::{ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1},
        DACL_SECURITY_INFORMATION,
    };

    let mut string = LocalWideString::empty();
    let mut length = 0u32;
    // SAFETY: descriptor is valid for this call and string is a valid
    // out-pointer receiving LocalAlloc UTF-16 storage.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut string.pointer,
            &mut length,
        )
    };
    if converted == 0 || string.pointer.is_null() || length == 0 || length > 16 * 1024 {
        return Err(SecureStoreError::Io);
    }
    // SAFETY: the conversion API returned length UTF-16 code units in the
    // LocalAlloc buffer. Strip the optional terminal NUL before decoding.
    let units = unsafe { std::slice::from_raw_parts(string.pointer, length as usize) };
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    String::from_utf16(&units[..end]).map_err(|_| SecureStoreError::Invalid)
}

#[cfg(windows)]
fn windows_wide_string(value: &str) -> Result<Vec<u16>, SecureStoreError> {
    if value.is_empty() || value.contains('\0') || value.len() > MAX_BINDING_PATH_BYTES * 2 {
        return Err(SecureStoreError::Invalid);
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

#[cfg(windows)]
fn windows_wide_path(path: &std::path::Path) -> Result<Vec<u16>, SecureStoreError> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.len() > 32 * 1024 || wide.contains(&0) {
        return Err(SecureStoreError::Invalid);
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
struct LocalSecurityDescriptor {
    pointer: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl LocalSecurityDescriptor {
    const fn empty() -> Self {
        Self {
            pointer: std::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        if !self.pointer.is_null() {
            // SAFETY: the security descriptor was allocated by an SDDL or
            // security-info API documented to require LocalFree.
            unsafe {
                let _ = LocalFree(self.pointer.cast());
            }
            self.pointer = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
struct LocalWideString {
    pointer: windows_sys::core::PWSTR,
}

#[cfg(windows)]
impl LocalWideString {
    const fn empty() -> Self {
        Self {
            pointer: std::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
impl Drop for LocalWideString {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        if !self.pointer.is_null() {
            // SAFETY: the SDDL conversion API allocated this pointer with
            // LocalAlloc and transfers ownership to the caller.
            unsafe {
                let _ = LocalFree(self.pointer.cast());
            }
            self.pointer = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
struct LocalExplicitAccessList {
    pointer: *mut windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W,
}

#[cfg(windows)]
impl LocalExplicitAccessList {
    const fn empty() -> Self {
        Self {
            pointer: std::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
impl Drop for LocalExplicitAccessList {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        if !self.pointer.is_null() {
            // SAFETY: GetExplicitEntriesFromAclW returned one LocalAlloc block
            // and transferred ownership to the caller.
            unsafe {
                let _ = LocalFree(self.pointer.cast());
            }
            self.pointer = std::ptr::null_mut();
        }
    }
}

/// Linux relies on a trusted local directory and exact 0600 files for
/// confidentiality. This protector adds domain-separated integrity and keeps
/// the entire bound envelope as the single atomic file payload.
#[cfg(target_os = "linux")]
pub struct LinuxPlaintextProtector;

#[cfg(target_os = "linux")]
impl LinuxPlaintextProtector {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
impl Default for LinuxPlaintextProtector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl EnvelopeProtector for LinuxPlaintextProtector {
    fn seal(
        &self,
        binding: &[u8],
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        const MAGIC: &[u8] = b"MRD-LINUX-ENVELOPE-V1\0";
        const MAX_PROTECTED_BYTES: usize = 1024 * 1024;

        if binding.is_empty()
            || binding.len() > MAX_BINDING_PATH_BYTES + MAX_NODE_ID_BYTES + 256
            || plaintext.is_empty()
            || plaintext.len() > MAX_PROTECTED_BYTES
        {
            return Err(SecureStoreError::Invalid);
        }
        let digest = linux_envelope_digest(binding, plaintext);
        let mut sealed = Zeroizing::new(Vec::with_capacity(
            MAGIC.len() + digest.len() + plaintext.len(),
        ));
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&digest);
        sealed.extend_from_slice(plaintext);
        Ok(sealed)
    }

    fn open(&self, binding: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        const MAGIC: &[u8] = b"MRD-LINUX-ENVELOPE-V1\0";
        const DIGEST_BYTES: usize = 32;
        const MAX_PROTECTED_BYTES: usize = 1024 * 1024;

        if binding.is_empty()
            || binding.len() > MAX_BINDING_PATH_BYTES + MAX_NODE_ID_BYTES + 256
            || sealed.len() <= MAGIC.len() + DIGEST_BYTES
            || sealed.len() > MAX_PROTECTED_BYTES + MAGIC.len() + DIGEST_BYTES
            || !sealed.starts_with(MAGIC)
        {
            return Err(SecureStoreError::Invalid);
        }
        let digest_end = MAGIC.len() + DIGEST_BYTES;
        let plaintext = &sealed[digest_end..];
        let expected = linux_envelope_digest(binding, plaintext);
        if sealed[MAGIC.len()..digest_end] != expected {
            return Err(SecureStoreError::Invalid);
        }
        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

#[cfg(target_os = "linux")]
fn linux_envelope_digest(binding: &[u8], plaintext: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"mrd-relay-linux-envelope-integrity-v1\0");
    digest.update((binding.len() as u64).to_be_bytes());
    digest.update(binding);
    digest.update(plaintext);
    digest.finalize().into()
}

#[cfg(target_os = "linux")]
impl HardenedAtomicFile {
    pub fn new_linux(
        trusted_root: std::path::PathBuf,
        path: std::path::PathBuf,
    ) -> Result<Self, SecureStoreError> {
        if !valid_linux_absolute_path(&trusted_root)
            || !valid_linux_absolute_path(&path)
            || path.parent() != Some(trusted_root.as_path())
        {
            return Err(SecureStoreError::Invalid);
        }
        verify_linux_directory_chain(&trusted_root, true)?;
        let canonical_root =
            std::fs::canonicalize(&trusted_root).map_err(|_| SecureStoreError::Io)?;
        verify_linux_directory_chain(&canonical_root, true)?;
        verify_linux_local_filesystem(&canonical_root)?;

        let file_name = path.file_name().ok_or(SecureStoreError::Invalid)?;
        let canonical_target = canonical_root.join(file_name);
        if let Some(metadata) = linux_optional_metadata(&canonical_target)? {
            verify_linux_state_metadata(&canonical_target, &metadata)?;
        }
        let canonical_path = canonical_target
            .to_str()
            .filter(|value| !value.is_empty() && value.len() <= MAX_BINDING_PATH_BYTES)
            .ok_or(SecureStoreError::Invalid)?
            .to_owned();
        Ok(Self {
            path: canonical_target,
            canonical_path,
            trusted_root: canonical_root,
        })
    }

    fn verify_linux_boundary(&self) -> Result<(), SecureStoreError> {
        verify_linux_directory_chain(&self.trusted_root, true)?;
        verify_linux_local_filesystem(&self.trusted_root)?;
        if let Some(metadata) = linux_optional_metadata(&self.path)? {
            verify_linux_state_metadata(&self.path, &metadata)?;
        }
        Ok(())
    }

    fn create_linux_temp(&self) -> Result<(std::path::PathBuf, std::fs::File), SecureStoreError> {
        use rand::{rngs::OsRng, RngCore as _};
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let file_name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(SecureStoreError::Invalid)?;
        for _ in 0..32 {
            let candidate = self
                .trusted_root
                .join(format!(".{file_name}.{:016x}.tmp", OsRng.next_u64()));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&candidate)
            {
                Ok(file) => {
                    // SAFETY: file owns a live descriptor. fchmod applies to
                    // that descriptor, not to a raceable path.
                    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                        drop(file);
                        let _ = std::fs::remove_file(&candidate);
                        return Err(SecureStoreError::Io);
                    }
                    let verified = file
                        .metadata()
                        .map_err(|_| SecureStoreError::Io)
                        .and_then(|metadata| verify_linux_state_metadata(&candidate, &metadata));
                    if let Err(error) = verified {
                        drop(file);
                        let _ = std::fs::remove_file(&candidate);
                        return Err(error);
                    }
                    return Ok((candidate, file));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(SecureStoreError::Io),
            }
        }
        Err(SecureStoreError::Io)
    }
}

#[cfg(target_os = "linux")]
impl AtomicEnvelopeFile for HardenedAtomicFile {
    fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    fn read(&self, max_bytes: usize) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        if max_bytes == 0 {
            return Err(SecureStoreError::Invalid);
        }
        self.verify_linux_boundary()?;
        if linux_optional_metadata(&self.path)?.is_none() {
            return Ok(None);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|_| SecureStoreError::Io)?;
        let metadata = file.metadata().map_err(|_| SecureStoreError::Io)?;
        verify_linux_state_metadata(&self.path, &metadata)?;
        if metadata.len() > max_bytes as u64 {
            return Err(SecureStoreError::Invalid);
        }
        let limit = u64::try_from(max_bytes)
            .map_err(|_| SecureStoreError::Invalid)?
            .saturating_add(1);
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(max_bytes)
                .min(max_bytes),
        ));
        file.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| SecureStoreError::Io)?;
        if bytes.len() > max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        Ok(Some(bytes))
    }

    fn atomic_replace(&self, value: &[u8], max_bytes: usize) -> Result<(), SecureStoreError> {
        use std::io::Write as _;

        if value.is_empty() || max_bytes == 0 || value.len() > max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        self.verify_linux_boundary()?;
        let (temp_path, mut temp_file) = self.create_linux_temp()?;
        let write_result = (|| {
            temp_file
                .write_all(value)
                .map_err(|_| SecureStoreError::Io)?;
            temp_file.sync_all().map_err(|_| SecureStoreError::Io)
        })();
        drop(temp_file);
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temp_path);
            return Err(error);
        }
        let verified = std::fs::symlink_metadata(&temp_path)
            .map_err(|_| SecureStoreError::Io)
            .and_then(|metadata| verify_linux_state_metadata(&temp_path, &metadata));
        if let Err(error) = verified {
            let _ = std::fs::remove_file(&temp_path);
            return Err(error);
        }
        std::fs::rename(&temp_path, &self.path).map_err(|_| {
            let _ = std::fs::remove_file(&temp_path);
            SecureStoreError::Io
        })?;
        self.verify_linux_boundary()?;
        sync_linux_directory(&self.trusted_root)
    }

    fn enforce_strict_permissions(&self) -> Result<(), SecureStoreError> {
        self.verify_linux_boundary()
    }
}

/// Read-only source for systemd credentials or installer-provisioned 0400/0600
/// bootstrap material. The type deliberately has no `Debug` implementation.
#[cfg(target_os = "linux")]
pub struct StrictCredentialFile {
    path: std::path::PathBuf,
    max_bytes: usize,
}

#[cfg(target_os = "linux")]
impl StrictCredentialFile {
    pub fn new_linux(path: std::path::PathBuf, max_bytes: usize) -> Result<Self, SecureStoreError> {
        if !valid_linux_absolute_path(&path)
            || max_bytes == 0
            || max_bytes > MAX_SECRET_PAYLOAD_BYTES
        {
            return Err(SecureStoreError::Invalid);
        }
        verify_linux_credential_path(&path)?;
        let canonical_path = std::fs::canonicalize(&path).map_err(|_| SecureStoreError::Io)?;
        verify_linux_credential_path(&canonical_path)?;
        Ok(Self {
            path: canonical_path,
            max_bytes,
        })
    }

    pub fn read_secret(&self) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        verify_linux_credential_path(&self.path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|_| SecureStoreError::Io)?;
        let metadata = file.metadata().map_err(|_| SecureStoreError::Io)?;
        verify_linux_credential_metadata(&self.path, &metadata)?;
        if metadata.len() > self.max_bytes as u64 {
            return Err(SecureStoreError::Invalid);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(self.max_bytes)
                .min(self.max_bytes),
        ));
        file.take((self.max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| SecureStoreError::Io)?;
        if bytes.is_empty() || bytes.len() > self.max_bytes {
            return Err(SecureStoreError::Invalid);
        }
        Ok(bytes)
    }
}

/// Reads a non-secret integrity root such as the production agent config or
/// pinned backend CA. The leaf and every ancestor are root-owned and cannot be
/// replaced by the unprivileged agent; the opened descriptor is then checked
/// again before any bytes are accepted.
#[cfg(target_os = "linux")]
pub fn read_linux_integrity_file(
    path: &std::path::Path,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    use std::io::Read as _;
    use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _};

    if !valid_linux_absolute_path(path) || max_bytes == 0 || max_bytes > 1024 * 1024 {
        return Err(SecureStoreError::Invalid);
    }
    let parent = path.parent().ok_or(SecureStoreError::Invalid)?;
    verify_linux_root_owned_directory_chain(parent)?;
    let path_metadata = std::fs::symlink_metadata(path).map_err(|_| SecureStoreError::Io)?;
    verify_linux_integrity_metadata(&path_metadata)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| SecureStoreError::Io)?;
    let metadata = file.metadata().map_err(|_| SecureStoreError::Io)?;
    verify_linux_integrity_metadata(&metadata)?;
    verify_linux_local_file_descriptor(file.as_raw_fd())?;
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(SecureStoreError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(max_bytes)
            .min(max_bytes),
    ));
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| SecureStoreError::Io)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(SecureStoreError::Invalid);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn verify_linux_root_owned_directory_chain(path: &std::path::Path) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;

    if !path.is_absolute() {
        return Err(SecureStoreError::Invalid);
    }
    let mut current = std::path::PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => return Err(SecureStoreError::Invalid),
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| SecureStoreError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SecureStoreError::Invalid);
        }
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(SecureStoreError::Permissions);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_linux_integrity_metadata(metadata: &std::fs::Metadata) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(SecureStoreError::Invalid);
    }
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(SecureStoreError::Permissions);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_linux_local_file_descriptor(fd: std::os::fd::RawFd) -> Result<(), SecureStoreError> {
    const REMOTE_OR_USER_MOUNT_TYPES: &[libc::__fsword_t] = &[
        0x0000_517b_u64 as libc::__fsword_t,
        0x0000_564c_u64 as libc::__fsword_t,
        0x0000_6969_u64 as libc::__fsword_t,
        0x0102_1997_u64 as libc::__fsword_t,
        0x00c3_6400_u64 as libc::__fsword_t,
        0x5346_414f_u64 as libc::__fsword_t,
        0x6573_5546_u64 as libc::__fsword_t,
        0x7375_7245_u64 as libc::__fsword_t,
        0xfe53_4d42_u64 as libc::__fsword_t,
        0xff53_4d42_u64 as libc::__fsword_t,
    ];
    // SAFETY: zero initializes a valid statfs output value and fd belongs to
    // the live File retained by the caller for this check.
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut stats) } != 0 {
        return Err(SecureStoreError::Io);
    }
    if REMOTE_OR_USER_MOUNT_TYPES.contains(&stats.f_type) {
        return Err(SecureStoreError::Permissions);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn valid_linux_absolute_path(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    let bytes = path.as_os_str().as_bytes();
    path.is_absolute()
        && path.file_name().is_some()
        && !bytes.is_empty()
        && bytes.len() <= MAX_BINDING_PATH_BYTES
        && !bytes.contains(&0)
        && path.to_str().is_some()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
}

#[cfg(target_os = "linux")]
fn verify_linux_directory_chain(
    path: &std::path::Path,
    strict_final: bool,
) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;

    if !path.is_absolute() {
        return Err(SecureStoreError::Invalid);
    }
    let effective_uid = unsafe { libc::geteuid() };
    let mut current = std::path::PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => return Err(SecureStoreError::Invalid),
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| SecureStoreError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SecureStoreError::Invalid);
        }
        let mode = metadata.mode() & 0o7777;
        if (metadata.uid() != 0 && metadata.uid() != effective_uid) || mode & 0o022 != 0 {
            return Err(SecureStoreError::Permissions);
        }
        if strict_final && current == path && mode != 0o700 {
            return Err(SecureStoreError::Permissions);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_optional_metadata(
    path: &std::path::Path,
) -> Result<Option<std::fs::Metadata>, SecureStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SecureStoreError::Io),
    }
}

#[cfg(target_os = "linux")]
fn verify_linux_state_metadata(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(SecureStoreError::Invalid);
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(SecureStoreError::Permissions);
    }
    if metadata.mode() & 0o7777 != 0o600 {
        return Err(SecureStoreError::Permissions);
    }
    verify_linux_local_filesystem(path)
}

#[cfg(target_os = "linux")]
fn verify_linux_credential_path(path: &std::path::Path) -> Result<(), SecureStoreError> {
    let parent = path.parent().ok_or(SecureStoreError::Invalid)?;
    verify_linux_directory_chain(parent, false)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| SecureStoreError::Io)?;
    verify_linux_credential_metadata(path, &metadata)
}

#[cfg(target_os = "linux")]
fn verify_linux_credential_metadata(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(SecureStoreError::Invalid);
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(SecureStoreError::Permissions);
    }
    let mode = metadata.mode() & 0o7777;
    if !matches!(mode, 0o400 | 0o600) {
        return Err(SecureStoreError::Permissions);
    }
    verify_linux_local_filesystem(path)
}

#[cfg(target_os = "linux")]
fn verify_linux_local_filesystem(path: &std::path::Path) -> Result<(), SecureStoreError> {
    use std::os::unix::ffi::OsStrExt as _;

    const REMOTE_OR_USER_MOUNT_TYPES: &[libc::__fsword_t] = &[
        0x0000_517b_u64 as libc::__fsword_t, // SMB
        0x0000_564c_u64 as libc::__fsword_t, // NCP
        0x0000_6969_u64 as libc::__fsword_t, // NFS
        0x0102_1997_u64 as libc::__fsword_t, // 9P / WSL DrvFs transport
        0x00c3_6400_u64 as libc::__fsword_t, // Ceph
        0x5346_414f_u64 as libc::__fsword_t, // AFS
        0x6573_5546_u64 as libc::__fsword_t, // FUSE
        0x7375_7245_u64 as libc::__fsword_t, // Coda
        0xfe53_4d42_u64 as libc::__fsword_t, // SMB2
        0xff53_4d42_u64 as libc::__fsword_t, // CIFS
    ];
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SecureStoreError::Invalid)?;
    // SAFETY: zero is a valid initial representation for statfs and the path
    // buffer remains live and NUL-terminated for the call.
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stats) } != 0 {
        return Err(SecureStoreError::Io);
    }
    if REMOTE_OR_USER_MOUNT_TYPES.contains(&stats.f_type) {
        return Err(SecureStoreError::Permissions);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_linux_directory(path: &std::path::Path) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| SecureStoreError::Io)?;
    directory.sync_all().map_err(|_| SecureStoreError::Io)
}

#[cfg(windows)]
fn windows_static_path_matches_layout(data_root: &std::path::Path, path: &std::path::Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !windows_ordinal_equal(file_name, "agent.json")
        && !windows_ordinal_equal(file_name, "trusted-ca.pem")
    {
        return false;
    }
    windows_paths_equal_ordinal(&data_root.join("config").join(file_name), path)
}

#[cfg(windows)]
fn windows_paths_equal_ordinal(left: &std::path::Path, right: &std::path::Path) -> bool {
    let Some((left_drive, left_components)) = windows_path_identity(left) else {
        return false;
    };
    let Some((right_drive, right_components)) = windows_path_identity(right) else {
        return false;
    };
    left_drive.eq_ignore_ascii_case(&right_drive)
        && left_components.len() == right_components.len()
        && left_components
            .iter()
            .zip(right_components)
            .all(|(left, right)| windows_ordinal_equal(left, &right))
}

#[cfg(windows)]
fn windows_path_identity(path: &std::path::Path) -> Option<(u8, Vec<String>)> {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    let drive = match components.next()? {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return None,
        },
        _ => return None,
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return None;
    }
    let mut normal = Vec::new();
    for component in components {
        match component {
            Component::Normal(value) => {
                normal.push(value.to_str()?.to_owned());
            }
            _ => return None,
        }
    }
    Some((drive, normal))
}

#[cfg(windows)]
fn windows_ordinal_equal(left: &str, right: &str) -> bool {
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    let left: Vec<u16> = left.encode_utf16().collect();
    let right: Vec<u16> = right.encode_utf16().collect();
    let Ok(left_len) = i32::try_from(left.len()) else {
        return false;
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return false;
    };
    // SAFETY: the explicit lengths bound both live UTF-16 slices. Ordinal
    // comparison avoids locale-sensitive path identity decisions.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

#[cfg(windows)]
fn windows_system_managed_roots() -> Result<Vec<std::path::PathBuf>, SecureStoreError> {
    use windows_sys::Win32::{
        Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK},
        Storage::FileSystem::GetVolumePathNameW,
        System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED},
        UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
    };

    // Known Folder APIs document COM initialization. An already initialized
    // thread with a different apartment is still safe for this API, but must
    // not be uninitialized by us.
    let initialized = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
    let uninitialize = match initialized {
        S_OK | S_FALSE => true,
        RPC_E_CHANGED_MODE => false,
        _ => return Err(SecureStoreError::Io),
    };
    let mut pointer = std::ptr::null_mut();
    // SAFETY: pointer is a valid out-parameter. The API returns a
    // CoTaskMemAlloc UTF-16 string which is freed below on every success path.
    let result = unsafe {
        SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut pointer)
    };
    let decoded = if result < 0 || pointer.is_null() {
        Err(SecureStoreError::Io)
    } else {
        unsafe { windows_bounded_wide_to_string(pointer, 32 * 1024) }
    };
    if !pointer.is_null() {
        // SAFETY: SHGetKnownFolderPath transferred this exact allocation even
        // if it subsequently reported an error.
        unsafe { CoTaskMemFree(pointer.cast()) };
    }
    if uninitialize {
        // SAFETY: this thread received S_OK/S_FALSE from CoInitializeEx above.
        unsafe { CoUninitialize() };
    }
    let path = std::path::PathBuf::from(decoded?);
    let program_data = std::fs::canonicalize(path).map_err(|_| SecureStoreError::Io)?;
    let program_data_wide = windows_wide_path(&program_data)?;
    let mut volume_root = vec![0u16; 32 * 1024];
    // SAFETY: both buffers are live and sized as specified; the input is
    // NUL-terminated and the output size is supplied in UTF-16 units.
    if unsafe {
        GetVolumePathNameW(
            program_data_wide.as_ptr(),
            volume_root.as_mut_ptr(),
            volume_root.len() as u32,
        )
    } == 0
    {
        return Err(SecureStoreError::Io);
    }
    let volume_root = std::path::PathBuf::from(unsafe {
        windows_bounded_wide_to_string(volume_root.as_ptr(), volume_root.len())?
    });
    let volume_root = std::fs::canonicalize(volume_root).map_err(|_| SecureStoreError::Io)?;
    Ok(vec![program_data, volume_root])
}

#[cfg(windows)]
fn windows_acl_claim_from_path(
    path: &std::path::Path,
) -> Result<WindowsStaticAclClaim, SecureStoreError> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
            ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID,
        },
    };

    let path = windows_wide_path(path)?;
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = LocalSecurityDescriptor::empty();
    // SAFETY: path is live and NUL-terminated; all output pointers are valid
    // and the descriptor owner is released with LocalFree.
    let result = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor.pointer,
        )
    };
    if result != ERROR_SUCCESS || descriptor.pointer.is_null() || owner.is_null() || dacl.is_null()
    {
        return Err(SecureStoreError::Permissions);
    }
    windows_acl_claim_from_parts(descriptor.pointer, owner, dacl)
}

#[cfg(windows)]
fn windows_acl_claim_from_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<WindowsStaticAclClaim, SecureStoreError> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID,
        },
    };

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = LocalSecurityDescriptor::empty();
    // SAFETY: handle is owned by the live File and all output pointers are
    // valid for the duration of the call.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor.pointer,
        )
    };
    if result != ERROR_SUCCESS || descriptor.pointer.is_null() || owner.is_null() || dacl.is_null()
    {
        return Err(SecureStoreError::Permissions);
    }
    windows_acl_claim_from_parts(descriptor.pointer, owner, dacl)
}

#[cfg(windows)]
fn windows_acl_claim_from_parts(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    owner: windows_sys::Win32::Security::PSID,
    dacl: *mut windows_sys::Win32::Security::ACL,
) -> Result<WindowsStaticAclClaim, SecureStoreError> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{
            Authorization::{
                GetExplicitEntriesFromAclW, DENY_ACCESS, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE,
                TRUSTEE_IS_SID,
            },
            GetSecurityDescriptorControl, IsValidSid, SE_DACL_PROTECTED,
        },
    };

    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor is live for this call and both scalar out-pointers
    // are initialized.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(SecureStoreError::Io);
    }
    let mut count = 0u32;
    let mut list = LocalExplicitAccessList::empty();
    // SAFETY: dacl is owned by descriptor; list receives a LocalAlloc array.
    let result = unsafe { GetExplicitEntriesFromAclW(dacl, &mut count, &mut list.pointer) };
    if result != ERROR_SUCCESS || count > 512 || (count != 0 && list.pointer.is_null()) {
        return Err(SecureStoreError::Permissions);
    }
    let entries = if count == 0 {
        &[][..]
    } else {
        // SAFETY: the API returned count EXPLICIT_ACCESS_W entries in list.
        unsafe { std::slice::from_raw_parts(list.pointer, count as usize) }
    };
    let mut claims = Vec::with_capacity(entries.len());
    for entry in entries {
        // SAFETY: the trustee pointer belongs to the live ACL/descriptor and
        // is checked for null before any conversion.
        let valid_sid = !entry.Trustee.ptstrName.is_null()
            && unsafe { IsValidSid(entry.Trustee.ptstrName.cast()) } != 0;
        if entry.Trustee.TrusteeForm != TRUSTEE_IS_SID
            || entry.Trustee.MultipleTrusteeOperation != NO_MULTIPLE_TRUSTEE
            || !entry.Trustee.pMultipleTrustee.is_null()
            || !valid_sid
        {
            return Err(SecureStoreError::Permissions);
        }
        let allow = match entry.grfAccessMode {
            GRANT_ACCESS => true,
            DENY_ACCESS => false,
            _ => return Err(SecureStoreError::Permissions),
        };
        claims.push(WindowsStaticAceClaim {
            sid: windows_sid_to_string(entry.Trustee.ptstrName.cast())?,
            allow,
            rights: entry.grfAccessPermissions,
            inheritance: entry.grfInheritance,
        });
    }
    Ok(WindowsStaticAclClaim {
        owner_sid: windows_sid_to_string(owner)?,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        entries: claims,
    })
}

#[cfg(windows)]
fn windows_sid_to_string(
    sid: windows_sys::Win32::Security::PSID,
) -> Result<String, SecureStoreError> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut string = LocalWideString::empty();
    // SAFETY: sid is supplied by a live security descriptor and string is a
    // valid LocalAlloc out-pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut string.pointer) } == 0 || string.pointer.is_null()
    {
        return Err(SecureStoreError::Permissions);
    }
    unsafe { windows_bounded_wide_to_string(string.pointer, 256) }
}

#[cfg(windows)]
unsafe fn windows_bounded_wide_to_string(
    pointer: *const u16,
    max_units: usize,
) -> Result<String, SecureStoreError> {
    if pointer.is_null() || max_units == 0 {
        return Err(SecureStoreError::Invalid);
    }
    for length in 0..max_units {
        // SAFETY: Win32 guarantees a NUL-terminated result; the explicit bound
        // prevents an unbounded scan if that contract is violated.
        if unsafe { *pointer.add(length) } == 0 {
            // SAFETY: all preceding units are within the same returned string.
            let units = unsafe { std::slice::from_raw_parts(pointer, length) };
            return String::from_utf16(units).map_err(|_| SecureStoreError::Invalid);
        }
    }
    Err(SecureStoreError::Invalid)
}

#[cfg(windows)]
fn valid_windows_local_path(path: &std::path::Path) -> bool {
    use std::path::Component;

    let Some(value) = path.to_str() else {
        return false;
    };
    let bytes = value.as_bytes();
    if value.is_empty()
        || value.len() > MAX_BINDING_PATH_BYTES
        || value.contains('\0')
        || value.starts_with("\\\\")
        || bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
        || value[2..].contains(':')
        || path.file_name().is_none()
    {
        return false;
    }
    path.components().all(|component| match component {
        Component::Prefix(_) | Component::RootDir => true,
        Component::Normal(value) => value.to_str().is_some_and(valid_windows_path_component),
        Component::CurDir | Component::ParentDir => false,
    })
}

#[cfg(windows)]
fn valid_windows_path_component(value: &str) -> bool {
    if value.is_empty()
        || value.encode_utf16().count() > 255
        || value.ends_with(['.', ' '])
        || value.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
        })
    {
        return false;
    }
    let basename = value
        .split_once('.')
        .map_or(value, |(basename, _)| basename)
        .to_ascii_uppercase();
    !matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        && !matches!(
            basename.strip_prefix("COM"),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        )
        && !matches!(
            basename.strip_prefix("LPT"),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        )
}

#[cfg(windows)]
fn verify_windows_fixed_drive(path: &std::path::Path) -> Result<(), SecureStoreError> {
    use std::path::{Component, Prefix};
    use windows_sys::Win32::{
        Storage::FileSystem::GetDriveTypeW, System::WindowsProgramming::DRIVE_FIXED,
    };

    let drive = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return Err(SecureStoreError::Invalid),
        },
        _ => return Err(SecureStoreError::Invalid),
    };
    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: root is a live NUL-terminated `X:\` UTF-16 buffer.
    if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
        return Err(SecureStoreError::Invalid);
    }
    Ok(())
}

#[cfg(windows)]
fn reject_windows_reparse_chain(path: &std::path::Path) -> Result<(), SecureStoreError> {
    use std::path::Component;

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        reject_windows_reparse(&current)?;
    }
    Ok(())
}

#[cfg(windows)]
fn reject_windows_reparse(path: &std::path::Path) -> Result<(), SecureStoreError> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = std::fs::symlink_metadata(path).map_err(|_| SecureStoreError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SecureStoreError::Invalid);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_optional_metadata(
    path: &std::path::Path,
) -> Result<Option<std::fs::Metadata>, SecureStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SecureStoreError::Io),
    }
}
