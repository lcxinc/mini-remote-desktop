#!/usr/bin/python3
"""Closed public address classifier used by the Linux relay installer."""

import ipaddress
import json
import pathlib
import sys
from typing import Optional


def globally_routable(address: ipaddress._BaseAddress) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        a, b, c, d = address.packed
        return not (
            a in (0, 10, 127)
            or a >= 224
            or (a == 100 and 64 <= b <= 127)
            or (a == 169 and b == 254)
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 0 and c == 0 and d not in (9, 10))
            or (a == 192 and b == 0 and c == 2)
            or (a == 192 and b == 88 and c == 99)
            or (a == 192 and b == 168)
            or (a == 198 and b in (18, 19))
            or (a == 198 and b == 51 and c == 100)
            or (a == 203 and b == 0 and c == 113)
        )

    value = int(address)
    well_known_nat64 = int(ipaddress.IPv6Address("64:ff9b::"))
    if value >> 32 == well_known_nat64 >> 32:
        return globally_routable(ipaddress.IPv4Address(value & 0xFFFFFFFF))
    first = value >> 112
    second = (value >> 96) & 0xFFFF
    third = (value >> 80) & 0xFFFF
    fourth = (value >> 64) & 0xFFFF
    low_64 = value & 0xFFFFFFFFFFFFFFFF
    ietf_exception = (
        (second == 0x0001 and third == 0 and fourth == 0 and low_64 in (1, 2, 3))
        or second == 0x0003
        or (second == 0x0004 and third == 0x0112)
        or second & 0xFFF0 in (0x0020, 0x0030)
    )
    return (
        0x2000 <= first <= 0x3FFF
        and not (first == 0x2001 and second <= 0x01FF and not ietf_exception)
        and not (first == 0x2001 and second == 0x0DB8)
        and first != 0x2002
        and not (first == 0x3FFF and second & 0xF000 == 0)
    )


def parse_global(value: str) -> bool:
    try:
        return globally_routable(ipaddress.ip_address(value))
    except ValueError:
        return False


def validate_mapping(external: str, relay: str) -> bool:
    parts = external.split("/")
    if len(parts) not in (1, 2) or any(not item for item in parts):
        return False
    try:
        public_address = ipaddress.ip_address(parts[0])
        if not globally_routable(public_address):
            return False
        private_address = ipaddress.ip_address(parts[1]) if len(parts) == 2 else None
        relay_address = ipaddress.ip_address(relay) if relay else None
    except ValueError:
        return False
    if private_address is not None and private_address.version != public_address.version:
        return False
    if relay_address is not None and relay_address.version != public_address.version:
        return False
    if private_address is not None:
        # coturn's PUBLIC/PRIVATE mapping and relay-ip form one deployment
        # identity.  Require the operator's literal PRIVATE value rather than
        # accepting an alternative IPv6 spelling of the same address.
        return relay_address is not None and relay == parts[1]
    return True


def expected_listener(external: str, relay: str) -> Optional[str]:
    if not validate_mapping(external, relay):
        return None
    public_address = ipaddress.ip_address(external.split("/", 1)[0])
    return "0.0.0.0" if public_address.version == 4 else "::"


def self_test(vector_path: pathlib.Path) -> bool:
    raw = json.loads(vector_path.read_text(encoding="utf-8"))
    if set(raw) != {
        "schema_version",
        "accepted",
        "rejected",
        "accepted_mappings",
        "rejected_mappings",
    } or raw["schema_version"] != 1:
        return False
    for collection in (raw["accepted_mappings"], raw["rejected_mappings"]):
        if not isinstance(collection, list) or any(
            not isinstance(item, dict)
            or set(item) != {"external_ip", "relay_ip"}
            or not isinstance(item["external_ip"], str)
            or not isinstance(item["relay_ip"], str)
            for item in collection
        ):
            return False
    return (
        all(parse_global(value) for value in raw["accepted"])
        and not any(parse_global(value) for value in raw["rejected"])
        and all(
            validate_mapping(item["external_ip"], item["relay_ip"])
            for item in raw["accepted_mappings"]
        )
        and not any(
            validate_mapping(item["external_ip"], item["relay_ip"])
            for item in raw["rejected_mappings"]
        )
        and expected_listener("198.20.0.10/10.0.0.10", "10.0.0.10") == "0.0.0.0"
        and expected_listener("2606:4700:4700::1111/fd00::10", "fd00::10") == "::"
        and expected_listener("198.20.0.10/fd00::10", "fd00::10") is None
    )


if len(sys.argv) == 4 and sys.argv[1] == "check":
    raise SystemExit(0 if validate_mapping(sys.argv[2], sys.argv[3]) else 1)
if len(sys.argv) == 3 and sys.argv[1] == "self-test":
    raise SystemExit(0 if self_test(pathlib.Path(sys.argv[2])) else 1)
if len(sys.argv) == 4 and sys.argv[1] == "listener":
    listener = expected_listener(sys.argv[2], sys.argv[3])
    if listener is None:
        raise SystemExit(1)
    print(listener)
    raise SystemExit(0)
raise SystemExit(64)
