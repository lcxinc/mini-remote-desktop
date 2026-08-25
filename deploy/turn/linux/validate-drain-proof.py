#!/usr/bin/python3
"""Strict parser for challenge-bound, local drain proof evidence."""

import hashlib
import json
import pathlib
import re
import sys


KEYS = {
    "schema_version",
    "scope",
    "target",
    "generation",
    "applied_secret_version",
    "draining",
    "active_allocations",
    "drain_completed",
    "challenge_sha256",
    "proof_sha256",
}


class DuplicateKey(ValueError):
    pass


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(key)
        result[key] = value
    return result


def validate_text(text: str, challenge: str, expected_target: str):
    if not re.fullmatch(r"[0-9a-f]{64}", challenge) or set(challenge) == {"0"}:
        raise ValueError("challenge")
    if len(text.encode("utf-8")) > 8192 or "\r" in text:
        raise ValueError("framing")
    if text.endswith("\n"):
        text = text[:-1]
    if not text or "\n" in text:
        raise ValueError("framing")
    value = json.loads(text, object_pairs_hook=no_duplicates)
    if type(value) is not dict or set(value) != KEYS:
        raise ValueError("schema")
    if (
        value["schema_version"] != 1
        or value["scope"] != "local"
        or value["target"] != expected_target
        or type(value["generation"]) is not int
        or value["generation"] <= 0
        or type(value["applied_secret_version"]) is not int
        or value["applied_secret_version"] <= 0
        or value["draining"] is not True
        or type(value["active_allocations"]) is not int
        or value["active_allocations"] != 0
        or value["drain_completed"] is not True
        or value["challenge_sha256"]
        != hashlib.sha256(bytes.fromhex(challenge)).hexdigest()
        or type(value["proof_sha256"]) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", value["proof_sha256"])
    ):
        raise ValueError("evidence")
    return value["target"], value["generation"], value["applied_secret_version"]


def self_test() -> bool:
    challenge = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    good = {
        "schema_version": 1,
        "scope": "local",
        "target": "linux-systemd",
        "generation": 7,
        "applied_secret_version": 3,
        "draining": True,
        "active_allocations": 0,
        "drain_completed": True,
        "challenge_sha256": hashlib.sha256(bytes.fromhex(challenge)).hexdigest(),
        "proof_sha256": "a" * 64,
    }
    encoded = json.dumps(good, separators=(",", ":")) + "\n"
    if validate_text(encoded, challenge, "linux-systemd") != ("linux-systemd", 7, 3):
        return False
    invalid = [
        encoded[:-2] + ',"secret":"rejected"}\n',
        encoded.replace('"active_allocations":0', '"active_allocations":1'),
        encoded.replace('"generation":7', '"generation":0'),
        encoded.replace(good["challenge_sha256"], "0" * 64),
        encoded.replace('"generation":7', '"generation":7,"generation":7'),
    ]
    for candidate in invalid:
        try:
            validate_text(candidate, challenge, "linux-systemd")
        except (DuplicateKey, json.JSONDecodeError, UnicodeError, ValueError):
            continue
        return False
    return True


if len(sys.argv) == 2 and sys.argv[1] == "self-test":
    raise SystemExit(0 if self_test() else 1)
if len(sys.argv) == 5 and sys.argv[1] == "validate":
    path = pathlib.Path(sys.argv[2])
    with path.open("rb") as source:
        encoded = source.read(8193)
    if len(encoded) > 8192:
        raise SystemExit(1)
    try:
        result = validate_text(encoded.decode("utf-8"), sys.argv[3], sys.argv[4])
    except (DuplicateKey, json.JSONDecodeError, UnicodeError, ValueError):
        raise SystemExit(1)
    print("\t".join(str(item) for item in result))
    raise SystemExit(0)
raise SystemExit(64)
