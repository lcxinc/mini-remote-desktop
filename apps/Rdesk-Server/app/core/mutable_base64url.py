from __future__ import annotations

from collections.abc import Iterator


_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_DECODE = [-1] * 128
for _index, _character in enumerate(_ALPHABET):
    _DECODE[_character] = _index


def _new_buffer() -> bytearray:
    return bytearray()


def zeroize(value: bytearray) -> None:
    """Clear one application-owned mutable buffer in place."""

    for index in range(len(value)):
        value[index] = 0


def _symbols(value: str | bytes | bytearray | memoryview) -> Iterator[int]:
    if isinstance(value, str):
        for character in value:
            codepoint = ord(character)
            if codepoint >= 128:
                raise ValueError("value must be canonical base64url")
            yield codepoint
        return

    try:
        view = memoryview(value).cast("B")
    except (TypeError, ValueError):
        raise ValueError("value must be canonical base64url") from None
    try:
        yield from view
    finally:
        view.release()


def decode_canonical_base64url(
    value: str | bytes | bytearray | memoryview,
    *,
    expected_length: int | None = None,
) -> bytearray:
    """Decode strict, unpadded base64url directly into a mutable owner.

    Padding, the standard ``+/`` alphabet, whitespace, non-ASCII input,
    impossible lengths, and non-zero unused bits are rejected.  A partially
    populated owner is wiped before validation errors escape.
    """

    decoded = _new_buffer()
    accumulator = 0
    available_bits = 0
    symbol_count = 0
    try:
        for character in _symbols(value):
            if character >= 128 or _DECODE[character] < 0:
                raise ValueError("value must be canonical base64url")
            symbol_count += 1
            accumulator = (accumulator << 6) | _DECODE[character]
            available_bits += 6
            if available_bits >= 8:
                available_bits -= 8
                decoded.append((accumulator >> available_bits) & 0xFF)
                accumulator &= (1 << available_bits) - 1

        canonical_length = (len(decoded) * 8 + 5) // 6
        if (
            symbol_count != canonical_length
            or accumulator != 0
            or (expected_length is not None and len(decoded) != expected_length)
        ):
            raise ValueError("value must be canonical base64url")
        return decoded
    except (TypeError, ValueError):
        zeroize(decoded)
        raise ValueError("value must be canonical base64url") from None


def encode_unpadded_base64url(
    value: bytes | bytearray | memoryview,
) -> bytearray:
    """Encode a bytes-like value directly into a mutable unpadded owner."""

    encoded = _new_buffer()
    accumulator = 0
    available_bits = 0
    try:
        try:
            view = memoryview(value).cast("B")
        except (TypeError, ValueError):
            raise ValueError("value must be bytes-like") from None
        try:
            for byte in view:
                accumulator = (accumulator << 8) | byte
                available_bits += 8
                while available_bits >= 6:
                    available_bits -= 6
                    encoded.append(_ALPHABET[(accumulator >> available_bits) & 0x3F])
                    accumulator &= (1 << available_bits) - 1
            if available_bits:
                encoded.append(_ALPHABET[(accumulator << (6 - available_bits)) & 0x3F])
        finally:
            view.release()
        return encoded
    except (TypeError, ValueError):
        zeroize(encoded)
        raise
