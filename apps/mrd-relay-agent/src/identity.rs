use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ED25519};
use ring::{
    rand::{SecureRandom as _, SystemRandom},
    signature,
    signature::KeyPair as _,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use x509_parser::{
    certification_request::X509CertificationRequest, extensions::GeneralName,
    parse_x509_certificate, pem::parse_x509_pem, prelude::FromDer,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    backend::{
        serialize_renewal_body, sign_relay_request, BackendError, EnrollmentRequest,
        EnrollmentStatus, HeartbeatPayload, NodeCertificate, PickupRequest, RelayBackendPort,
        RenewalRequest, RequestAuthentication, SignedHeartbeat,
    },
    runtime::RuntimeError,
};

const MAX_IDENTITY_FILE_BYTES: u64 = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    node_id: String,
    private_pkcs8_b64: String,
    public_key_b64: String,
    csr_pem: String,
    certificate: Option<StoredCertificate>,
    #[serde(default)]
    pending_enrollment: Option<StoredEnrollment>,
    #[serde(default)]
    pending_renewal: Option<StoredRenewal>,
    #[serde(default)]
    request_sequence: u64,
    #[serde(default)]
    boot_id_b64: String,
}

impl std::fmt::Debug for StoredIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredIdentity")
            .field("node_id", &self.node_id)
            .field("private_pkcs8_b64", &"REDACTED")
            .field("public_key_b64", &self.public_key_b64)
            .field("csr_pem", &"REDACTED")
            .field("certificate", &self.certificate)
            .field("pending_enrollment", &self.pending_enrollment)
            .field("pending_renewal", &self.pending_renewal)
            .finish()
    }
}

impl Drop for StoredIdentity {
    fn drop(&mut self) {
        self.private_pkcs8_b64.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredCertificate {
    certificate_pem: String,
    ca_certificate_pem: String,
    expires_at_unix_seconds: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredEnrollment {
    enrollment_id: String,
    receipt: String,
}

impl std::fmt::Debug for StoredEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredEnrollment")
            .field("enrollment_id", &self.enrollment_id)
            .field("receipt", &"REDACTED")
            .finish()
    }
}

impl Drop for StoredEnrollment {
    fn drop(&mut self) {
        self.receipt.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredRenewal {
    renewal_id: String,
    private_pkcs8_b64: String,
    public_key_b64: String,
    csr_pem: String,
    boot_id_b64: String,
    certificate: Option<StoredCertificate>,
}

impl std::fmt::Debug for StoredRenewal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRenewal")
            .field("renewal_id", &self.renewal_id)
            .field("private_pkcs8_b64", &"REDACTED")
            .field("public_key_b64", &self.public_key_b64)
            .field("csr_pem", &"REDACTED")
            .field("boot_id_b64", &self.boot_id_b64)
            .field("certificate", &self.certificate)
            .finish()
    }
}

impl Drop for StoredRenewal {
    fn drop(&mut self) {
        self.private_pkcs8_b64.zeroize();
    }
}

pub trait IdentityFsPort: Send + Sync {
    fn load(&self) -> Result<Option<StoredIdentity>, RuntimeError>;
    fn atomic_replace(&self, identity: &StoredIdentity) -> Result<(), RuntimeError>;
    fn enforce_strict_permissions(&self) -> Result<(), RuntimeError>;
}

pub struct StdIdentityFs {
    path: PathBuf,
}

impl StdIdentityFs {
    pub fn new(path: PathBuf) -> Result<Self, RuntimeError> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(RuntimeError::IdentityInvalid);
        }
        Ok(Self { path })
    }

    fn temporary_path(&self) -> PathBuf {
        self.path.with_extension(format!(
            "tmp-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }
}

impl IdentityFsPort for StdIdentityFs {
    fn load(&self) -> Result<Option<StoredIdentity>, RuntimeError> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RuntimeError::IdentityIo),
        };
        if !metadata.is_file() || metadata.len() > MAX_IDENTITY_FILE_BYTES {
            return Err(RuntimeError::IdentityInvalid);
        }
        let bytes = Zeroizing::new(fs::read(&self.path).map_err(|_| RuntimeError::IdentityIo)?);
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| RuntimeError::IdentityInvalid)
    }

    fn atomic_replace(&self, identity: &StoredIdentity) -> Result<(), RuntimeError> {
        let parent = self.path.parent().ok_or(RuntimeError::IdentityInvalid)?;
        fs::create_dir_all(parent).map_err(|_| RuntimeError::IdentityIo)?;
        let temporary = self.temporary_path();
        let bytes = Zeroizing::new(
            serde_json::to_vec(identity).map_err(|_| RuntimeError::IdentityInvalid)?,
        );
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| RuntimeError::IdentityIo)?;
        let write_result = (|| {
            file.write_all(&bytes)
                .map_err(|_| RuntimeError::IdentityIo)?;
            file.sync_all().map_err(|_| RuntimeError::IdentityIo)?;
            atomic_replace_path(&temporary, &self.path)?;
            sync_parent(parent)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    fn enforce_strict_permissions(&self) -> Result<(), RuntimeError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.path).map_err(|_| RuntimeError::IdentityIo)?;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(RuntimeError::IdentityPermissions);
            }
        }
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace_path(from: &Path, to: &Path) -> Result<(), RuntimeError> {
    fs::rename(from, to).map_err(|_| RuntimeError::IdentityIo)
}

#[cfg(windows)]
fn atomic_replace_path(from: &Path, to: &Path) -> Result<(), RuntimeError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers are NUL-terminated and live through the call.
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(RuntimeError::IdentityIo)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), RuntimeError> {
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| RuntimeError::IdentityIo)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

pub struct RelayIdentity {
    stored: StoredIdentity,
}

impl std::fmt::Debug for RelayIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayIdentity")
            .field("node_id", &self.stored.node_id)
            .field("public_key", &self.stored.public_key_b64)
            .field("private_key", &"REDACTED")
            .finish()
    }
}

impl RelayIdentity {
    pub fn public_key(&self) -> Vec<u8> {
        STANDARD
            .decode(&self.stored.public_key_b64)
            .unwrap_or_default()
    }

    pub fn csr_pem(&self) -> &str {
        &self.stored.csr_pem
    }

    pub(crate) fn private_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
        STANDARD
            .decode(&self.stored.private_pkcs8_b64)
            .map(Zeroizing::new)
            .map_err(|_| RuntimeError::IdentityInvalid)
    }

    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        timestamp: i64,
        sequence: u64,
        body: &[u8],
    ) -> Result<String, RuntimeError> {
        sign_relay_request(
            &self.private_pkcs8()?,
            method,
            path,
            &self.stored.node_id,
            timestamp,
            sequence,
            body,
        )
        .map_err(RuntimeError::Backend)
    }
}

pub fn load_or_create_identity(
    fs: &dyn IdentityFsPort,
    node_id: &str,
) -> Result<RelayIdentity, RuntimeError> {
    let stored = match fs.load()? {
        Some(stored) => {
            validate_stored_identity(&stored, node_id)?;
            stored
        }
        None => {
            let stored = generate_identity(node_id)?;
            fs.atomic_replace(&stored)?;
            stored
        }
    };
    fs.enforce_strict_permissions()?;
    Ok(RelayIdentity { stored })
}

fn generate_identity(node_id: &str) -> Result<StoredIdentity, RuntimeError> {
    if node_id.is_empty() || node_id.len() > 128 || !node_id.is_ascii() {
        return Err(RuntimeError::IdentityInvalid);
    }
    let generated = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| RuntimeError::IdentityInvalid)?;
    let key = signature::Ed25519KeyPair::from_pkcs8(generated.as_ref())
        .map_err(|_| RuntimeError::IdentityInvalid)?;
    let pkcs8 = PrivatePkcs8KeyDer::from(generated.as_ref().to_vec());
    let rcgen_key = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
        .map_err(|_| RuntimeError::IdentityInvalid)?;
    let mut params = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, node_id);
    params.distinguished_name = distinguished_name;
    params.subject_alt_names = vec![SanType::URI(
        format!("urn:mrd:relay:{node_id}")
            .try_into()
            .map_err(|_| RuntimeError::IdentityInvalid)?,
    )];
    let csr = params
        .serialize_request(&rcgen_key)
        .map_err(|_| RuntimeError::IdentityInvalid)?;
    let mut boot_id = [0u8; 16];
    SystemRandom::new()
        .fill(&mut boot_id)
        .map_err(|_| RuntimeError::IdentityInvalid)?;
    Ok(StoredIdentity {
        node_id: node_id.to_owned(),
        private_pkcs8_b64: STANDARD.encode(generated.as_ref()),
        public_key_b64: STANDARD.encode(key.public_key().as_ref()),
        csr_pem: csr.pem().map_err(|_| RuntimeError::IdentityInvalid)?,
        certificate: None,
        pending_enrollment: None,
        pending_renewal: None,
        request_sequence: 0,
        boot_id_b64: STANDARD.encode(boot_id),
    })
}

fn validate_stored_identity(stored: &StoredIdentity, node_id: &str) -> Result<(), RuntimeError> {
    if stored.node_id != node_id
        || stored.csr_pem.len() > 16_384
        || STANDARD
            .decode(&stored.boot_id_b64)
            .map_or(true, |boot_id| boot_id.len() != 16)
    {
        return Err(RuntimeError::IdentityInvalid);
    }
    let private = Zeroizing::new(
        STANDARD
            .decode(&stored.private_pkcs8_b64)
            .map_err(|_| RuntimeError::IdentityInvalid)?,
    );
    let key = signature::Ed25519KeyPair::from_pkcs8(&private)
        .map_err(|_| RuntimeError::IdentityInvalid)?;
    if STANDARD.encode(key.public_key().as_ref()) != stored.public_key_b64 {
        return Err(RuntimeError::IdentityInvalid);
    }
    let (remainder, csr_pem) =
        parse_x509_pem(stored.csr_pem.as_bytes()).map_err(|_| RuntimeError::IdentityInvalid)?;
    if !remainder.iter().all(u8::is_ascii_whitespace) {
        return Err(RuntimeError::IdentityInvalid);
    }
    let (remainder, csr) = X509CertificationRequest::from_der(&csr_pem.contents)
        .map_err(|_| RuntimeError::IdentityInvalid)?;
    if !remainder.is_empty()
        || csr.verify_signature().is_err()
        || csr
            .certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .as_ref()
            != key.public_key().as_ref()
    {
        return Err(RuntimeError::IdentityInvalid);
    }
    Ok(())
}

pub struct CertificateState<F: IdentityFsPort> {
    fs: Arc<F>,
    identity: RelayIdentity,
    pending_delivery: Option<NodeCertificate>,
}

impl<F: IdentityFsPort> CertificateState<F> {
    pub fn new(fs: Arc<F>, node_id: &str) -> Result<Self, RuntimeError> {
        Ok(Self {
            identity: load_or_create_identity(fs.as_ref(), node_id)?,
            fs,
            pending_delivery: None,
        })
    }

    pub fn active_certificate(&self) -> Option<NodeCertificate> {
        self.identity
            .stored
            .certificate
            .as_ref()
            .map(|stored| NodeCertificate {
                certificate_pem: stored.certificate_pem.clone(),
                ca_certificate_pem: stored.ca_certificate_pem.clone(),
                expires_at_unix_seconds: stored.expires_at_unix_seconds,
            })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.identity.public_key()
    }

    pub fn sign_heartbeat(
        &mut self,
        timestamp: i64,
        payload: HeartbeatPayload,
    ) -> Result<SignedHeartbeat, RuntimeError> {
        if self.identity.stored.certificate.is_none() {
            return Err(RuntimeError::EnrollmentMissing);
        }
        payload.validate().map_err(RuntimeError::Backend)?;
        let body = serde_json::to_vec(&payload)
            .map_err(|_| RuntimeError::Backend(BackendError::ProtocolInvalid))?;
        let mut proposed = self.identity.stored.clone();
        proposed.request_sequence = proposed
            .request_sequence
            .checked_add(1)
            .ok_or(RuntimeError::IdentityInvalid)?;
        let sequence = proposed.request_sequence;
        let node_id = proposed.node_id.clone();
        let path = format!("/api/v1/relays/{node_id}/heartbeat");
        let signature_b64 = self
            .identity
            .sign_request("POST", &path, timestamp, sequence, &body)?;
        // Persist the consumed sequence before releasing the signed request, so
        // a crash cannot replay it on the next boot.
        self.fs.atomic_replace(&proposed)?;
        self.identity.stored = proposed;
        Ok(SignedHeartbeat {
            node_id,
            timestamp,
            sequence,
            body,
            signature_b64,
        })
    }

    pub async fn enroll(
        &mut self,
        backend: &dyn RelayBackendPort,
        mut request: EnrollmentRequest,
    ) -> Result<(), RuntimeError> {
        request.csr_pem = self.identity.csr_pem().to_owned();
        match backend
            .enroll(request)
            .await
            .map_err(RuntimeError::Backend)?
        {
            EnrollmentStatus::Pending {
                enrollment_id,
                receipt,
            } => {
                self.identity.stored.pending_enrollment = Some(StoredEnrollment {
                    enrollment_id,
                    receipt: receipt.expose_secret().to_owned(),
                });
                self.fs.atomic_replace(&self.identity.stored)?;
            }
        }
        Ok(())
    }

    pub async fn pickup(&mut self, backend: &dyn RelayBackendPort) -> Result<bool, RuntimeError> {
        if let Some(certificate) = self.pending_delivery.clone() {
            self.install_certificate(certificate)?;
            self.pending_delivery = None;
            return Ok(true);
        }
        let pending = self
            .identity
            .stored
            .pending_enrollment
            .clone()
            .ok_or(RuntimeError::EnrollmentMissing)?;
        let certificate = backend
            .pickup(PickupRequest {
                enrollment_id: pending.enrollment_id.clone(),
                node_id: self.identity.stored.node_id.clone(),
                receipt: SecretString::from(pending.receipt.clone()),
            })
            .await
            .map_err(RuntimeError::Backend)?;
        let Some(certificate) = certificate else {
            return Ok(false);
        };
        self.pending_delivery = Some(certificate.clone());
        if let Err(error) = self.install_certificate(certificate) {
            if error == RuntimeError::CertificateInvalid {
                self.pending_delivery = None;
            }
            return Err(error);
        }
        self.pending_delivery = None;
        Ok(true)
    }

    pub async fn renew(
        &mut self,
        backend: &dyn RelayBackendPort,
        renewal_id: &str,
        timestamp: i64,
    ) -> Result<(), RuntimeError> {
        if let Some(pending) = self.identity.stored.pending_renewal.clone() {
            if pending.renewal_id != renewal_id {
                return Err(RuntimeError::RenewalConflict);
            }
            if pending.certificate.is_some() {
                return self.promote_pending_renewal();
            }
        } else {
            let proposed = generate_identity(&self.identity.stored.node_id)?;
            self.identity.stored.pending_renewal = Some(StoredRenewal {
                renewal_id: renewal_id.to_owned(),
                private_pkcs8_b64: proposed.private_pkcs8_b64.clone(),
                public_key_b64: proposed.public_key_b64.clone(),
                csr_pem: proposed.csr_pem.clone(),
                boot_id_b64: proposed.boot_id_b64.clone(),
                certificate: None,
            });
            // Persist the candidate key before contacting the backend. A crash
            // can then retry the same idempotency id and exact CSR.
            self.fs.atomic_replace(&self.identity.stored)?;
        }
        let pending = self
            .identity
            .stored
            .pending_renewal
            .clone()
            .ok_or(RuntimeError::RenewalConflict)?;
        self.identity.stored.request_sequence = self
            .identity
            .stored
            .request_sequence
            .checked_add(1)
            .ok_or(RuntimeError::IdentityInvalid)?;
        self.fs.atomic_replace(&self.identity.stored)?;
        let request_sequence = self.identity.stored.request_sequence;
        let node_id = self.identity.stored.node_id.clone();
        let path = format!("/api/v1/relays/{node_id}/renew");
        let body =
            serialize_renewal_body(renewal_id, &pending.csr_pem).map_err(RuntimeError::Backend)?;
        let private = self.identity.private_pkcs8()?;
        let authentication = RequestAuthentication {
            timestamp,
            sequence: request_sequence,
            signature_b64: sign_relay_request(
                &private,
                "POST",
                &path,
                &node_id,
                timestamp,
                request_sequence,
                &body,
            )
            .map_err(RuntimeError::Backend)?,
        };
        let certificate = backend
            .renew(RenewalRequest {
                node_id,
                renewal_id: renewal_id.to_owned(),
                csr_pem: pending.csr_pem.clone(),
                authentication,
            })
            .await
            .map_err(RuntimeError::Backend)?;
        let expected_public_key = STANDARD
            .decode(&pending.public_key_b64)
            .map_err(|_| RuntimeError::IdentityInvalid)?;
        validate_node_certificate(
            &certificate,
            &self.identity.stored.node_id,
            &expected_public_key,
        )?;
        self.identity
            .stored
            .pending_renewal
            .as_mut()
            .ok_or(RuntimeError::RenewalConflict)?
            .certificate = Some(certificate.into());
        self.fs.atomic_replace(&self.identity.stored)?;
        self.promote_pending_renewal()
    }

    fn install_certificate(&mut self, certificate: NodeCertificate) -> Result<(), RuntimeError> {
        validate_node_certificate(
            &certificate,
            &self.identity.stored.node_id,
            &self.identity.public_key(),
        )?;
        let mut proposed = self.identity.stored.clone();
        proposed.certificate = Some(certificate.into());
        proposed.pending_enrollment = None;
        self.fs.atomic_replace(&proposed)?;
        self.identity.stored = proposed;
        Ok(())
    }

    fn promote_pending_renewal(&mut self) -> Result<(), RuntimeError> {
        let pending = self
            .identity
            .stored
            .pending_renewal
            .clone()
            .ok_or(RuntimeError::RenewalConflict)?;
        let certificate = pending
            .certificate
            .clone()
            .ok_or(RuntimeError::RenewalConflict)?;
        let promoted = StoredIdentity {
            node_id: self.identity.stored.node_id.clone(),
            private_pkcs8_b64: pending.private_pkcs8_b64.clone(),
            public_key_b64: pending.public_key_b64.clone(),
            csr_pem: pending.csr_pem.clone(),
            certificate: Some(certificate),
            pending_enrollment: None,
            pending_renewal: None,
            request_sequence: 0,
            boot_id_b64: pending.boot_id_b64.clone(),
        };
        self.fs.atomic_replace(&promoted)?;
        self.identity.stored = promoted;
        Ok(())
    }
}

fn validate_node_certificate(
    certificate: &NodeCertificate,
    node_id: &str,
    expected_public_key: &[u8],
) -> Result<(), RuntimeError> {
    if certificate.expires_at_unix_seconds <= 0
        || certificate.certificate_pem.len() > 64 * 1024
        || certificate.ca_certificate_pem.len() > 64 * 1024
    {
        return Err(RuntimeError::CertificateInvalid);
    }
    let (leaf_pem_remainder, leaf_pem) = parse_x509_pem(certificate.certificate_pem.as_bytes())
        .map_err(|_| RuntimeError::CertificateInvalid)?;
    let (leaf_remainder, leaf) =
        parse_x509_certificate(&leaf_pem.contents).map_err(|_| RuntimeError::CertificateInvalid)?;
    let (ca_pem_remainder, ca_pem) = parse_x509_pem(certificate.ca_certificate_pem.as_bytes())
        .map_err(|_| RuntimeError::CertificateInvalid)?;
    let (ca_remainder, ca) =
        parse_x509_certificate(&ca_pem.contents).map_err(|_| RuntimeError::CertificateInvalid)?;
    if !leaf_pem_remainder.iter().all(u8::is_ascii_whitespace)
        || !leaf_remainder.is_empty()
        || !ca_pem_remainder.iter().all(u8::is_ascii_whitespace)
        || !ca_remainder.is_empty()
        || leaf.public_key().subject_public_key.data.as_ref() != expected_public_key
        || leaf.issuer() != ca.subject()
        || leaf.verify_signature(Some(ca.public_key())).is_err()
        || ca
            .basic_constraints()
            .ok()
            .flatten()
            .is_none_or(|constraints| !constraints.value.ca)
    {
        return Err(RuntimeError::CertificateInvalid);
    }
    let expected_uri = format!("urn:mrd:relay:{node_id}");
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| RuntimeError::CertificateInvalid)?
        .ok_or(RuntimeError::CertificateInvalid)?;
    if !san
        .value
        .general_names
        .iter()
        .any(|name| matches!(name, GeneralName::URI(uri) if *uri == expected_uri))
    {
        return Err(RuntimeError::CertificateInvalid);
    }
    Ok(())
}

impl From<NodeCertificate> for StoredCertificate {
    fn from(value: NodeCertificate) -> Self {
        Self {
            certificate_pem: value.certificate_pem,
            ca_certificate_pem: value.ca_certificate_pem,
            expires_at_unix_seconds: value.expires_at_unix_seconds,
        }
    }
}

impl From<BackendError> for RuntimeError {
    fn from(value: BackendError) -> Self {
        RuntimeError::Backend(value)
    }
}
