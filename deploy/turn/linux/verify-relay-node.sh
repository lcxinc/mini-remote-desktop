#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly default_config=/etc/mrd-relay-agent/agent.json
readonly enrollment_source=/etc/mrd-relay-agent/secrets/enrollment-token
readonly turn_secret_source=/etc/mrd-relay-agent/secrets/turn-rest-secret
readonly trusted_ca_source=/etc/mrd-relay-agent/secrets/trusted-ca.pem
readonly rendered_config=/etc/mrd-relay-agent/secrets/turnserver.generated.conf
readonly firewall_config=/etc/mrd-relay-agent/firewall.conf
readonly nft_policy=/etc/nftables.d/mrd-relay.nft

config=$default_config
self_test=false
drained=false
expected_target=
expected_generation=
expected_secret_version=
evidence_python=/usr/bin/python3

fail() {
  printf '%s\n' "${1:-relay_verify_failed}" >&2
  exit 1
}

usage() {
  printf '%s\n' 'usage: verify-relay-node.sh [--config ABSOLUTE_PATH] [--drained --expected-target linux-systemd --expected-generation N --expected-secret-version N] [--self-test]' >&2
  exit 64
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --config)
      [[ "$#" -ge 2 ]] || usage
      config=$2
      shift 2
      ;;
    --self-test)
      self_test=true
      shift
      ;;
    --drained)
      drained=true
      shift
      ;;
    --expected-target)
      [[ "$#" -ge 2 ]] || usage
      expected_target=$2
      shift 2
      ;;
    --expected-generation)
      [[ "$#" -ge 2 ]] || usage
      expected_generation=$2
      shift 2
      ;;
    --expected-secret-version)
      [[ "$#" -ge 2 ]] || usage
      expected_secret_version=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

validate_evidence() {
  local evidence_path=$1
  local challenge=$2
  local expected_target=$3
  "$evidence_python" - "$evidence_path" "$challenge" "$expected_target" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
challenge = sys.argv[2]
expected_target = sys.argv[3]
raw = path.read_bytes()
if not raw or len(raw) > 8192 or raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
    raise SystemExit("relay_verify_preflight_framing_invalid")
try:
    value = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit("relay_verify_preflight_json_invalid")
expected_keys = {
    "schema_version", "scope", "target", "generation", "applied_secret_version",
    "challenge_sha256", "listener_reachable", "credential_authenticated",
    "allocation_created", "permission_created", "packets_sent", "packets_received",
    "bytes_sent", "bytes_received", "local_candidate_kind", "remote_candidate_kind",
    "proof_sha256",
}
if not isinstance(value, dict) or set(value) != expected_keys:
    raise SystemExit("relay_verify_preflight_schema_invalid")
if not re.fullmatch(r"[0-9a-f]{64}", challenge):
    raise SystemExit("relay_verify_challenge_invalid")
expected_challenge_sha256 = hashlib.sha256(bytes.fromhex(challenge)).hexdigest()
if value["schema_version"] != 1 or value["scope"] != "local" or value["target"] != expected_target:
    raise SystemExit("relay_verify_preflight_identity_invalid")
if value["challenge_sha256"] != expected_challenge_sha256:
    raise SystemExit("relay_verify_preflight_challenge_mismatch")
for field in ("generation", "applied_secret_version"):
    if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] <= 0:
        raise SystemExit("relay_verify_preflight_generation_invalid")
for field in (
    "listener_reachable", "credential_authenticated", "allocation_created", "permission_created"
):
    if value[field] is not True:
        raise SystemExit("relay_verify_preflight_stage_failed")
for field in ("packets_sent", "packets_received", "bytes_sent", "bytes_received"):
    if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] <= 0:
        raise SystemExit("relay_verify_preflight_traffic_invalid")
if value["local_candidate_kind"] != "relay" or value["remote_candidate_kind"] != "relay":
    raise SystemExit("relay_verify_preflight_candidate_invalid")
if not isinstance(value["proof_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["proof_sha256"]):
    raise SystemExit("relay_verify_preflight_proof_invalid")
PY
}

validate_drained_fence() {
  local actual=$1
  local target=$2
  local generation=$3
  local secret_version=$4
  [[ "$target" == linux-systemd ]] || return 1
  [[ "$generation" =~ ^[1-9][0-9]*$ && "$secret_version" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$actual" =~ ^linux-systemd$'\t'[1-9][0-9]*$'\t'[1-9][0-9]*$ ]] || return 1
  [[ "$actual" == "$target"$'\t'"$generation"$'\t'"$secret_version" ]]
}

self_test() {
  local temporary_dir challenge challenge_hash proof
  temporary_dir="$(/usr/bin/mktemp -d)"
  challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  challenge_hash=630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd
  proof=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local good="$temporary_dir/good.json"
  local extra="$temporary_dir/extra.json"
  local stale="$temporary_dir/stale.json"
  local zero="$temporary_dir/zero.json"
  printf '%s\n' "{\"schema_version\":1,\"scope\":\"local\",\"target\":\"linux-systemd\",\"generation\":7,\"applied_secret_version\":3,\"challenge_sha256\":\"$challenge_hash\",\"listener_reachable\":true,\"credential_authenticated\":true,\"allocation_created\":true,\"permission_created\":true,\"packets_sent\":2,\"packets_received\":2,\"bytes_sent\":64,\"bytes_received\":64,\"local_candidate_kind\":\"relay\",\"remote_candidate_kind\":\"relay\",\"proof_sha256\":\"$proof\"}" > "$good"
  "$evidence_python" - "$good" "$extra" "$stale" "$zero" <<'PY'
import json
import pathlib
import sys

good = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
extra = dict(good)
extra["credential"] = "must-be-rejected"
stale = dict(good)
stale["challenge_sha256"] = "0" * 64
zero = dict(good)
zero["generation"] = 0
for path, value in zip(sys.argv[2:], (extra, stale, zero)):
    pathlib.Path(path).write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  validate_evidence "$good" "$challenge" linux-systemd || fail relay_verify_self_test_good_rejected
  if validate_evidence "$extra" "$challenge" linux-systemd >/dev/null 2>&1; then
    fail relay_verify_self_test_extra_key_accepted
  fi
  if validate_evidence "$stale" "$challenge" linux-systemd >/dev/null 2>&1; then
    fail relay_verify_self_test_stale_challenge_accepted
  fi
  if validate_evidence "$zero" "$challenge" linux-systemd >/dev/null 2>&1; then
    fail relay_verify_self_test_zero_generation_accepted
  fi
  validate_drained_fence $'linux-systemd\t7\t3' linux-systemd 7 3 \
    || fail relay_verify_self_test_drained_fence_good_rejected
  if validate_drained_fence $'linux-systemd\t8\t3' linux-systemd 7 3; then
    fail relay_verify_self_test_drained_fence_mismatch_accepted
  fi
  if validate_drained_fence $'linux-systemd\t7\t3\textra' linux-systemd 7 3; then
    fail relay_verify_self_test_drained_fence_extra_field_accepted
  fi
  /usr/bin/rm -f -- "$good" "$extra" "$stale" "$zero"
  /usr/bin/rmdir -- "$temporary_dir"
  printf '%s\n' relay_verify_self_test_passed
}

if [[ "$self_test" == true ]]; then
  if [[ -n "${MRD_RELAY_TEST_PYTHON:-}" ]]; then
    [[ "$MRD_RELAY_TEST_PYTHON" == /* && -x "$MRD_RELAY_TEST_PYTHON" ]] \
      || fail relay_verify_self_test_python_invalid
    evidence_python=$MRD_RELAY_TEST_PYTHON
  fi
  self_test
  exit 0
fi

if [[ "$drained" == true ]]; then
  [[ "$expected_target" == linux-systemd ]] || usage
  [[ "$expected_generation" =~ ^[1-9][0-9]*$ ]] || usage
  [[ "$expected_secret_version" =~ ^[1-9][0-9]*$ ]] || usage
elif [[ -n "$expected_target" || -n "$expected_generation" || -n "$expected_secret_version" ]]; then
  usage
fi

[[ "${EUID}" -eq 0 ]] || fail relay_verify_requires_root
[[ "$config" == /* && -f "$config" && ! -L "$config" ]] || fail relay_verify_invalid_config
[[ "$(/usr/bin/realpath -e -- "$config")" == "$config" ]] || fail relay_verify_noncanonical_config

assert_trusted_ancestors() {
  local current=$1
  while [[ "$current" != / ]]; do
    [[ ! -L "$current" ]] || fail relay_verify_symlink_ancestor_rejected
    [[ "$(/usr/bin/stat -c '%u' -- "$current")" == 0 ]] || fail relay_verify_owner_invalid
    local mode
    mode="$(/usr/bin/stat -c '%a' -- "$current")"
    (( (8#$mode & 0022) == 0 )) || fail relay_verify_mode_invalid
    current="${current%/*}"
    [[ -n "$current" ]] || current=/
  done
}

for private_file in \
  "$config" "$enrollment_source" "$turn_secret_source" "$trusted_ca_source" "$rendered_config" \
  /etc/mrd-relay-agent/tls/fullchain.pem /etc/mrd-relay-agent/tls/privkey.pem \
  "$firewall_config"; do
  assert_trusted_ancestors "$private_file"
  [[ -f "$private_file" && ! -L "$private_file" ]] || fail relay_verify_private_file_missing
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- "$private_file")" == root:root:600 ]] \
    || fail relay_verify_private_file_mode_invalid
done
[[ "$(/usr/bin/stat -c '%s' -- "$turn_secret_source")" == 43 ]] \
  || fail relay_verify_turn_secret_size_invalid

/usr/bin/python3 - "$config" "$rendered_config" "$firewall_config" "$nft_policy" <<'PY'
import ipaddress
import json
import pathlib
import re
import sys

agent = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if "enrollment_token" in agent or "turn_rest_secret" in agent:
    raise SystemExit("relay_verify_inline_secret_rejected")
if agent.get("enrollment_token_path") != "/run/credentials/mrd-relay-agent.service/enrollment-token":
    raise SystemExit("relay_verify_enrollment_credential_path_invalid")
if agent.get("turn_rest_secret_path") != "/run/credentials/mrd-relay-agent.service/turn-rest-secret":
    raise SystemExit("relay_verify_turn_credential_path_invalid")
if agent.get("trusted_ca_path") != "/run/credentials/mrd-relay-agent.service/trusted-ca":
    raise SystemExit("relay_verify_trusted_ca_credential_path_invalid")
max_allocations = agent.get("max_allocations")
max_egress_bps = agent.get("max_egress_bps")
if isinstance(max_allocations, bool) or not isinstance(max_allocations, int) or not 1 <= max_allocations <= 100:
    raise SystemExit("relay_verify_max_allocations_invalid")
if isinstance(max_egress_bps, bool) or not isinstance(max_egress_bps, int) or max_egress_bps <= 0 or max_egress_bps % 8:
    raise SystemExit("relay_verify_max_egress_bps_invalid")

def exact_pairs(path):
    result = {}
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        key, separator, value = raw.partition("=")
        if not separator:
            value = ""
        if key in result and key != "denied-peer-ip":
            raise SystemExit("relay_verify_coturn_duplicate")
        result[key] = value
    return result

coturn = exact_pairs(sys.argv[2])
try:
    total_quota = int(coturn["total-quota"])
    bps_capacity = int(coturn["bps-capacity"])
    max_bps = int(coturn["max-bps"])
    min_port = int(coturn["min-port"])
    max_port = int(coturn["max-port"])
    tls_port = int(coturn["tls-listening-port"])
except (KeyError, ValueError):
    raise SystemExit("relay_verify_coturn_capacity_invalid")
if total_quota != max_allocations or bps_capacity * 8 != max_egress_bps:
    raise SystemExit("relay_verify_capacity_mismatch")
if not 0 < max_bps <= bps_capacity or (min_port, max_port) != (49160, 49260):
    raise SystemExit("relay_verify_coturn_limits_invalid")
if "unauthorized-ratelimit" not in coturn or coturn.get("unauthorized-ratelimit-rps") != "10":
    raise SystemExit("relay_verify_unauthorized_ratelimit_invalid")
if total_quota > max_port - min_port:
    raise SystemExit("relay_verify_relay_range_exhausted")
try:
    public_address = ipaddress.ip_address(coturn["external-ip"].split("/", 1)[0])
except (KeyError, ValueError):
    raise SystemExit("relay_verify_external_ip_invalid")
expected_listener = "0.0.0.0" if public_address.version == 4 else "::"
if coturn.get("listening-ip") != expected_listener:
    raise SystemExit("relay_verify_listener_family_mismatch")
endpoint_pattern = re.compile(
    r"^(?:turn|turns):(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):"
    r"[0-9]{1,5}(?:\?transport=(?:udp|tcp))?$"
)
for endpoint in agent.get("endpoints", []):
    if not isinstance(endpoint, str):
        raise SystemExit("relay_verify_endpoint_invalid")
    match = endpoint_pattern.fullmatch(endpoint)
    if match is None:
        raise SystemExit("relay_verify_endpoint_invalid")
    endpoint_host = match.group(1).strip("[]")
    try:
        endpoint_address = ipaddress.ip_address(endpoint_host)
    except ValueError:
        continue
    if endpoint_address.version != public_address.version:
        raise SystemExit("relay_verify_endpoint_listener_family_mismatch")

firewall = exact_pairs(sys.argv[3])
if set(firewall) != {"backend", "tls_port", "min_port", "max_port", "firewalld_zone"}:
    raise SystemExit("relay_verify_firewall_schema_invalid")
if firewall["backend"] not in {"nftables", "firewalld", "ufw"}:
    raise SystemExit("relay_verify_firewall_backend_unknown")
if (firewall["tls_port"], firewall["min_port"], firewall["max_port"]) != (
    str(tls_port), str(min_port), str(max_port)
):
    raise SystemExit("relay_verify_firewall_capacity_mismatch")
if firewall["backend"] == "nftables":
    policy = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8")
    required = ("udp dport 3478 accept", f"tcp dport {{ 3478, {tls_port} }} accept", "th dport 49160-49260 accept")
    if any(item not in policy for item in required):
        raise SystemExit("relay_verify_mrd-relay.nft_invalid")
PY

[[ "$(/usr/bin/systemctl show mrd-coturn.service --property=Restart --value)" == no ]] \
  || fail relay_verify_coturn_restart_policy_invalid
[[ "$(/usr/bin/systemctl show mrd-coturn.service --property=Type --value)" == simple ]] \
  || fail relay_verify_coturn_type_invalid
[[ "$(/usr/bin/systemctl show mrd-coturn.service --property=IPAccounting --value)" == yes ]] \
  || fail relay_verify_coturn_ip_accounting_invalid
[[ "$(/usr/bin/systemctl show mrd-relay-agent.service --property=StartLimitBurst --value)" == 3 ]] \
  || fail relay_verify_agent_restart_budget_invalid
[[ "$(/usr/bin/systemctl show mrd-relay-coturn-control.socket --property=SocketGroup --value)" == mrd-relay ]] \
  || fail relay_verify_control_socket_group_invalid
/usr/bin/systemctl is-active --quiet mrd-relay-coturn-control.socket \
  || fail relay_verify_control_socket_inactive
/usr/bin/systemctl is-enabled --quiet mrd-relay-firewall.service \
  || fail relay_verify_firewall_disabled
[[ "$(/usr/bin/systemctl show mrd-relay-firewall.service --property=Type --value)" == oneshot ]] \
  || fail relay_verify_firewall_type_invalid
[[ "$(/usr/bin/systemctl show mrd-relay-firewall.service --property=RemainAfterExit --value)" == no ]] \
  || fail relay_verify_firewall_residency_invalid
/usr/local/libexec/mrd-relay-firewall verify || fail relay_verify_firewall_rules_invalid
/usr/bin/systemctl is-active --quiet mrd-relay-agent.service || fail relay_verify_agent_inactive

version_output="$(/usr/bin/turnserver --version 2>&1)" || fail relay_verify_coturn_version_unavailable
version="$(printf '%s\n' "$version_output" | /usr/bin/grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | /usr/bin/head -n 1)"
[[ -n "$version" ]] || fail relay_verify_coturn_version_invalid
if ! /usr/bin/sort -V -C <(printf '%s\n' 4.17.2 "$version"); then
  fail relay_verify_coturn_version_too_old
fi
help_output="$(/usr/bin/turnserver --help 2>&1 || true)"
printf '%s\n' "$help_output" | /usr/bin/grep -q -- '--prometheus-address' \
  || fail relay_verify_coturn_prometheus_build_missing
unset version_output version help_output

evidence_file=
cleanup() {
  if [[ -n "${evidence_file:-}" && -e "$evidence_file" ]]; then
    /usr/bin/rm -f -- "$evidence_file"
  fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# These transient commands are static validation and a read_only_probe through
# the broker. They do not enter run mode and have no_state_mutation access to
# identity, runtime, or sequence state.
credential_properties=(
  --property="LoadCredential=agent-config:$config"
  --property="LoadCredential=enrollment-token:$enrollment_source"
  --property="LoadCredential=turn-rest-secret:$turn_secret_source"
  --property="LoadCredential=trusted-ca:$trusted_ca_source"
)
/usr/bin/systemd-run --quiet --wait --collect --uid=mrd-relay --gid=mrd-relay \
  --property=Type=exec --property=NoNewPrivileges=yes "${credential_properties[@]}" \
  /usr/local/bin/mrd-relay-agent validate --config %d/agent-config >/dev/null \
  || fail relay_verify_static_validation_failed

if [[ "$drained" == true ]]; then
  if /usr/bin/systemctl is-active --quiet mrd-coturn.service; then
    fail relay_verify_drained_coturn_still_active
  fi
  drained_fence="$(/usr/local/libexec/mrd-relay-drain-proof --config "$config")" \
    || fail relay_verify_drained_control_proof_failed
  validate_drained_fence "$drained_fence" "$expected_target" \
    "$expected_generation" "$expected_secret_version" \
    || fail relay_verify_drained_fence_mismatch
  printf '%s\n' "relay_verify_drained_passed target=$expected_target generation=$expected_generation applied_secret_version=$expected_secret_version"
  exit 0
else
  /usr/bin/systemctl is-active --quiet mrd-coturn.service || fail relay_verify_coturn_inactive
fi

challenge="$(/usr/bin/openssl rand -hex 32)"
[[ "$challenge" =~ ^[0-9a-f]{64}$ ]] || fail relay_verify_challenge_generation_failed
evidence_file="$(/usr/bin/mktemp --tmpdir=/run .mrd-relay-preflight.XXXXXX)"
/usr/bin/systemd-run --quiet --wait --pipe --collect --uid=mrd-relay --gid=mrd-relay \
  --property=Type=exec --property=NoNewPrivileges=yes "${credential_properties[@]}" \
  /usr/local/bin/mrd-relay-agent preflight --config %d/agent-config --challenge "$challenge" \
  > "$evidence_file" || fail relay_verify_live_preflight_failed

validate_evidence "$evidence_file" "$challenge" linux-systemd \
  || fail relay_verify_preflight_evidence_invalid
printf '%s\n' relay_verify_passed
