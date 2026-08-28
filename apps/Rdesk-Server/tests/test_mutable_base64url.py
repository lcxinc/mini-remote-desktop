from __future__ import annotations

import base64
import random

import pytest

from app.core.mutable_base64url import (
    decode_canonical_base64url,
    encode_unpadded_base64url,
    zeroize,
)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        (b"", b""),
        (b"f", b"Zg"),
        (b"fo", b"Zm8"),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg"),
        (b"fooba", b"Zm9vYmE"),
        (b"foobar", b"Zm9vYmFy"),
        (b"\xfb\xff", b"-_8"),
    ],
)
def test_mutable_base64url_matches_rfc_vectors(
    raw: bytes, canonical: bytes
) -> None:
    source = bytearray(raw)
    encoded = encode_unpadded_base64url(memoryview(source))
    decoded = decode_canonical_base64url(
        memoryview(encoded), expected_length=len(source)
    )
    try:
        assert encoded == canonical
        assert decoded == source
    finally:
        zeroize(decoded)
        zeroize(encoded)
        zeroize(source)
    assert not any(decoded)
    assert not any(encoded)
    assert not any(source)


def test_mutable_base64url_matches_real_stdlib_for_random_vectors() -> None:
    rng = random.Random(0x5E_C2_E7)
    for length in range(130):
        source = bytearray(rng.randrange(256) for _ in range(length))
        expected = base64.urlsafe_b64encode(source).rstrip(b"=")
        encoded = encode_unpadded_base64url(memoryview(source))
        decoded = decode_canonical_base64url(
            encoded.decode("ascii"), expected_length=length
        )
        try:
            assert bytes(encoded) == expected
            assert decoded == source
        finally:
            zeroize(decoded)
            zeroize(encoded)
            zeroize(source)


@pytest.mark.parametrize(
    "value",
    [
        "A",  # impossible unpadded length
        "AA=",
        "AA==",
        "A+",
        "A/",
        "A A",
        "A\nA",
        "é",
        "A" * 42 + "B",  # non-zero unused low bits
        memoryview(b"A\x80"),
    ],
)
def test_mutable_base64url_rejects_invalid_or_noncanonical_input(
    value: str | memoryview,
) -> None:
    with pytest.raises(ValueError, match="canonical base64url"):
        decode_canonical_base64url(value, expected_length=32)


def test_mutable_base64url_clears_partial_output_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core import mutable_base64url

    allocated: list[bytearray] = []

    def tracked_buffer() -> bytearray:
        value = bytearray()
        allocated.append(value)
        return value

    monkeypatch.setattr(mutable_base64url, "_new_buffer", tracked_buffer)
    with pytest.raises(ValueError, match="canonical base64url"):
        decode_canonical_base64url("Zm9vYmFy$", expected_length=32)
    assert allocated
    assert all(not any(owner) for owner in allocated)
