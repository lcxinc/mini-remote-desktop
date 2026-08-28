import base64
import json
from pathlib import Path

from app.services.relay_signing import (
    Ed25519RelayDirectorySigner,
    SignedRelayDirectoryOut,
    canonical_directory_bytes,
    verify_signed_directory,
)


FIXTURES = Path(__file__).parents[3] / "tests" / "relay" / "fixtures"
EXPECTED_HEX = (
    "4d52445f52454c41595f4449524543544f52595f563100010000000000000011"
    "000000176469726563746f72792d32303236303832322d303030310000019dbd"
    "742a000000019dbd749f300000000d73657373696f6e2d616c7068610000001c"
    "706565722d7368613235362d3031323334353637383961626364656600000002"
    "0000000d72656c61792d61702d73672d610000000e61702d736f757468656173"
    "742d310000000f61702d736f757468656173742d316100000002010000001374"
    "75726e2d612e6578616d706c652e746573740d9603000000137475726e2d612e"
    "6578616d706c652e7465737414e5000000070100000010707265666572726564"
    "2d726567696f6e0000000d7265736572766174696f6e2d610000019dbd747820"
    "0000000d72656c61792d65752d64652d620000000c65752d63656e7472616c2d"
    "310000000d65752d63656e7472616c2d31620000000102000000137475726e2d"
    "622e6578616d706c652e746573740d960000000302000000156661696c757265"
    "2d646f6d61696e2d6261636b75700000000d7265736572766174696f6e2d6200"
    "00019dbd748ba8"
)
EXPECTED_SIGNATURE = (
    "fcl/7IoMHEYef8sMbbIDpIZaP94zvLqK7PXO7baEmL4cEqQN+y8KxjRHo3TxLAZWXzaxSYXfY/sMQMnEjr2HBQ=="
)


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_python_canonical_bytes_and_signature_exactly_match_rust_golden_vector():
    document = fixture("directory-v1.json")
    directory = SignedRelayDirectoryOut.model_validate(document["directory"])
    canonical = canonical_directory_bytes(directory.payload)
    assert canonical.hex() == EXPECTED_HEX
    assert directory.signature_b64 == EXPECTED_SIGNATURE
    public_key = base64.b64decode(document["test_only_public_key_b64"], validate=True)
    assert verify_signed_directory(directory, public_key=public_key)

    signer = Ed25519RelayDirectorySigner(
        key_id="directory-test-key-v1", private_key_seed=bytes([0x42]) * 32
    )
    assert signer.sign(directory.payload).signature_b64 == EXPECTED_SIGNATURE


def test_tampered_vector_and_noncanonical_order_fail_closed():
    valid_document = fixture("directory-v1.json")
    tampered_document = fixture("directory-v1-tampered.json")
    public_key = base64.b64decode(valid_document["test_only_public_key_b64"], validate=True)
    tampered = SignedRelayDirectoryOut.model_validate(tampered_document["directory"])
    assert not verify_signed_directory(tampered, public_key=public_key)

    reordered = SignedRelayDirectoryOut.model_validate(valid_document["directory"])
    reordered.payload.candidates.reverse()
    try:
        canonical_directory_bytes(reordered.payload)
    except ValueError as error:
        assert "canonical" in str(error).lower()
    else:
        raise AssertionError("noncanonical candidate order must be rejected")
