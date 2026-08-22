from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import Request
from pydantic import SecretStr


_REQUEST_CONTEXT = b"MRD_RELAY_REQUEST_V1\x00"
_HEADER_INTEGER = re.compile(r"^(0|[1-9][0-9]{0,18})$")
_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


class RelayAuthError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class RelayAuthHeaders:
    node_id: str
    certificate_fingerprint: str
    timestamp: int
    sequence: int
    signature: bytes


@dataclass(frozen=True)
class IssuedRelayCertificate:
    certificate_pem: str
    ca_certificate_pem: str
    fingerprint: str
    expires_at: datetime


def require_trusted_proxy(request: Request, configured_allowlist: str) -> None:
    """Trust proxy metadata only when the direct ASGI peer is explicitly allowed.

    Entries may be exact IPv4/IPv6 addresses or explicit CIDRs. Forwarding
    headers are rejected because they are attacker-controlled at this boundary.
    """

    if any(
        name == b"forwarded"
        or name.startswith(b"x-forwarded-")
        or name in {b"x-real-ip", b"x-client-ip"}
        for name, _ in request.scope.get("headers", ())
    ):
        _auth_error("relay_proxy_required", 403, "trusted mTLS proxy required")
    peer = request.client.host if request.client is not None else ""
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        _auth_error("relay_proxy_required", 403, "trusted mTLS proxy required")
    if isinstance(peer_ip, ipaddress.IPv6Address) and peer_ip.ipv4_mapped is not None:
        peer_ip = peer_ip.ipv4_mapped
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw_entry in configured_allowlist.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # A malformed security setting never broadens the trust boundary.
            continue
    if not networks or not any(
        peer_ip.version == network.version and peer_ip in network
        for network in networks
    ):
        _auth_error("relay_proxy_required", 403, "trusted mTLS proxy required")
    if request.headers.get("x-rdesk-client-tls", "").lower() != "verified":
        _auth_error("relay_proxy_required", 403, "trusted mTLS proxy required")


def parse_relay_auth_headers(request: Request) -> RelayAuthHeaders:
    node_id = _bounded_header(request, "x-relay-node-id", 128)
    if _NODE_ID.fullmatch(node_id) is None:
        _auth_error("relay_signature_invalid", 401, "relay request signature invalid")
    fingerprint = canonical_certificate_fingerprint(
        _bounded_header(request, "x-rdesk-client-cert-sha256", 128)
    )
    if fingerprint is None:
        _auth_error("relay_certificate_invalid", 401, "relay certificate invalid")
    timestamp_raw = _bounded_header(request, "x-relay-timestamp", 20)
    sequence_raw = _bounded_header(request, "x-relay-sequence", 20)
    if (
        _HEADER_INTEGER.fullmatch(timestamp_raw) is None
        or _HEADER_INTEGER.fullmatch(sequence_raw) is None
    ):
        _auth_error("relay_signature_invalid", 401, "relay request signature invalid")
    signature_raw = _bounded_header(request, "x-relay-signature", 128)
    try:
        signature = base64.b64decode(signature_raw, validate=True)
    except (ValueError, TypeError):
        _auth_error("relay_signature_invalid", 401, "relay request signature invalid")
    if len(signature) != 64:
        _auth_error("relay_signature_invalid", 401, "relay request signature invalid")
    return RelayAuthHeaders(
        node_id=node_id,
        certificate_fingerprint=fingerprint,
        timestamp=int(timestamp_raw),
        sequence=int(sequence_raw),
        signature=signature,
    )


def verify_request_signature(
    *,
    request: Request,
    headers: RelayAuthHeaders,
    raw_body: bytes,
    signing_public_key: bytes,
    now: datetime,
    max_clock_skew_seconds: int,
) -> None:
    if request.url.query:
        _auth_error("relay_signature_invalid", 401, "relay request signature invalid")
    if not 1 <= max_clock_skew_seconds <= 300:
        _auth_error("relay_signature_invalid", 401, "relay request signature invalid")
    if abs(int(now.timestamp()) - headers.timestamp) > max_clock_skew_seconds:
        _auth_error("relay_clock_stale", 400, "relay request timestamp is stale")
    canonical = canonical_relay_request(
        method=request.method,
        path=request.url.path,
        node_id=headers.node_id,
        timestamp=headers.timestamp,
        sequence=headers.sequence,
        raw_body=raw_body,
    )
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(signing_public_key).verify(
            headers.signature, canonical
        )
    except (ValueError, InvalidSignature):
        _auth_error("relay_signature_invalid", 401, "relay request signature invalid")


def canonical_relay_request(
    *,
    method: str,
    path: str,
    node_id: str,
    timestamp: int,
    sequence: int,
    raw_body: bytes,
) -> bytes:
    """Encode signed input without delimiter ambiguity.

    The domain separator is followed by six unsigned 32-bit big-endian length
    prefixed fields: uppercase HTTP method, normalized ASGI path (query forbidden),
    node ID, decimal timestamp, decimal sequence, and the raw 32-byte SHA-256 body
    digest.  No forwarded URL or reconstructed JSON participates in signing.
    """

    fields = (
        method.upper().encode("ascii"),
        path.encode("ascii"),
        node_id.encode("ascii"),
        str(timestamp).encode("ascii"),
        str(sequence).encode("ascii"),
        hashlib.sha256(raw_body).digest(),
    )
    encoded = bytearray(_REQUEST_CONTEXT)
    for field in fields:
        encoded.extend(len(field).to_bytes(4, "big"))
        encoded.extend(field)
    return bytes(encoded)


def validate_relay_csr(csr_pem: str, node_id: str) -> tuple[bytes, bytes]:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        public_key = csr.public_key()
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError("relay signing key must be Ed25519")
        public_key.verify(csr.signature, csr.tbs_certrequest_bytes)
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        san = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
        _auth_error("relay_enrollment_invalid", 400, "relay enrollment invalid")
    if (
        len(common_names) != 1
        or common_names[0].value != node_id
        or uris != [f"urn:mrd:relay:{node_id}"]
    ):
        _auth_error("relay_enrollment_invalid", 400, "relay enrollment invalid")
    raw_public_key = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    canonical_csr = csr.public_bytes(serialization.Encoding.PEM)
    return canonical_csr, raw_public_key


def issue_relay_certificate(
    *,
    csr_pem: bytes,
    node_id: str,
    ca_certificate_pem: str,
    ca_private_key_pem: str | SecretStr,
    ca_private_key_password: str | SecretStr = "",
    now: datetime,
    validity_seconds: int,
) -> IssuedRelayCertificate:
    private_key_pem = (
        ca_private_key_pem.get_secret_value()
        if isinstance(ca_private_key_pem, SecretStr)
        else ca_private_key_pem
    )
    private_key_password = (
        ca_private_key_password.get_secret_value()
        if isinstance(ca_private_key_password, SecretStr)
        else ca_private_key_password
    )
    if not ca_certificate_pem or not private_key_pem:
        _auth_error("relay_ca_unavailable", 503, "relay certificate authority unavailable")
    if not 300 <= validity_seconds <= 86_400:
        _auth_error("relay_ca_unavailable", 503, "relay certificate authority unavailable")
    try:
        ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem.encode())
        ca_private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=(private_key_password.encode() if private_key_password else None),
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        if not isinstance(
            ca_private_key,
            (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey),
        ):
            raise ValueError("unsupported CA key")
        if isinstance(ca_private_key, rsa.RSAPrivateKey) and ca_private_key.key_size < 3072:
            raise ValueError("RSA CA key is too small")
        if isinstance(ca_private_key, ec.EllipticCurvePrivateKey) and not isinstance(
            ca_private_key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
        ):
            raise ValueError("unsupported CA curve")
        if ca_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != ca_certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ):
            raise ValueError("CA key mismatch")
        constraints = ca_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not constraints.ca:
            raise ValueError("certificate is not a CA")
        try:
            key_usage = ca_certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
        except x509.ExtensionNotFound:
            key_usage = None
        if key_usage is not None and not key_usage.key_cert_sign:
            raise ValueError("CA certificate cannot sign certificates")
        ca_not_before = _certificate_time(
            ca_certificate, "not_valid_before_utc", "not_valid_before"
        )
        ca_not_after = _certificate_time(
            ca_certificate, "not_valid_after_utc", "not_valid_after"
        )
        if not ca_not_before <= now <= ca_not_after:
            raise ValueError("CA certificate is outside its validity window")
    except (ValueError, TypeError, UnsupportedAlgorithm, x509.ExtensionNotFound):
        _auth_error("relay_ca_unavailable", 503, "relay certificate authority unavailable")

    expires_at = now + timedelta(seconds=validity_seconds)
    leaf_not_before = max(now - timedelta(minutes=1), ca_not_before)
    if expires_at > ca_not_after:
        _auth_error("relay_ca_unavailable", 503, "relay certificate authority unavailable")
    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MRD relay node"),
                    x509.NameAttribute(NameOID.COMMON_NAME, node_id),
                ]
            )
        )
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(leaf_not_before)
        .not_valid_after(expires_at)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:mrd:relay:{node_id}")]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    algorithm: hashes.HashAlgorithm | None = (
        None if isinstance(ca_private_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    )
    certificate = certificate_builder.sign(ca_private_key, algorithm)
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    return IssuedRelayCertificate(
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode(),
        ca_certificate_pem=ca_certificate.public_bytes(serialization.Encoding.PEM).decode(),
        fingerprint="sha256:" + hashlib.sha256(certificate_der).hexdigest(),
        expires_at=expires_at,
    )


def canonical_certificate_fingerprint(value: str) -> str | None:
    normalized = value.strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    normalized = normalized.replace(":", "")
    if _FINGERPRINT.fullmatch(normalized) is None:
        return None
    return "sha256:" + normalized


def _certificate_time(
    certificate: x509.Certificate, aware_name: str, legacy_name: str
) -> datetime:
    value = getattr(certificate, aware_name, None)
    if value is None:
        value = getattr(certificate, legacy_name)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _bounded_header(request: Request, name: str, maximum: int) -> str:
    values = request.headers.getlist(name)
    value = values[0] if len(values) == 1 else None
    if (
        value is None
        or not value
        or "," in value
        or len(value) > maximum
        or not value.isascii()
    ):
        code = (
            "relay_certificate_invalid"
            if name == "x-rdesk-client-cert-sha256"
            else "relay_signature_invalid"
        )
        _auth_error(code, 401, "relay authentication invalid")
    return value


def _auth_error(code: str, status_code: int, message: str) -> None:
    raise RelayAuthError(code, status_code, message)
