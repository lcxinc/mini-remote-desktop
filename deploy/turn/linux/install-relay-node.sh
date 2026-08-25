#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly deploy_dir="$(cd -- "$script_dir/.." && pwd -P)"
readonly turn_config="$deploy_dir/turnserver.conf.example"
readonly config_root=/etc/mrd-relay-agent
readonly secret_dir=/etc/mrd-relay-agent/secrets
readonly tls_dir=/etc/mrd-relay-agent/tls
readonly coturn_dir=/etc/mrd-relay-agent/coturn
readonly backup_root=/var/backups/mrd-relay-agent
readonly nft_destination=/etc/nftables.d/mrd-relay.nft
readonly firewall_config=/etc/mrd-relay-agent/firewall.conf
readonly ufw_profile=/etc/ufw/applications.d/mrd-relay
readonly low_port_dropin=/etc/systemd/system/mrd-coturn.service.d/10-low-port.conf
readonly public_ip_vectors="$deploy_dir/public-ip-test-vectors.json"
readonly public_ip_validator="$script_dir/validate-public-ip.py"

agent_binary=
coturn_helper_binary=
agent_config=
enrollment_token_file=
turn_secret_file=
trusted_ca=
tls_cert=
tls_key=
realm=
server_name=
external_ip=
relay_ip=
tls_port=5349
firewall_backend=
firewalld_zone=public
firewall_was_active=false
coturn_was_active=false
agent_was_active=false
socket_was_active=false
agent_was_enabled=false
socket_was_enabled=false
firewall_was_enabled=false
coturn_was_enabled=false
existing_install=false
existing_firewall_backend=
first_drain_proof=
second_drain_proof=
transaction_started=false
transaction_committed=false
filesystem_mutation_started=false
agent_stop_attempted=false
socket_stop_attempted=false
coturn_stop_attempted=false
firewall_policy_remove_attempted=false
base_temporary=
firewall_temporary=
ufw_temporary=
dropin_temporary=

fail() {
  printf '%s\n' "${1:-relay_install_failed}" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage: install-relay-node.sh --agent-binary PATH --coturn-helper-binary PATH' \
    '       --agent-config PATH --enrollment-token-file PATH --turn-secret-file PATH --trusted-ca PATH' \
    '       --tls-cert PATH --tls-key PATH' \
    '       --realm DNS_NAME --server-name DNS_NAME --external-ip PUBLIC[/PRIVATE]' \
    '       --firewall-backend nftables|firewalld|ufw' \
    '       [--firewalld-zone ZONE] [--relay-ip IP] [--tls-port 5349|443]' >&2
  exit 64
}

parse_system_uid_range_text() {
  local input=$1 key value extra
  local minimum= maximum= minimum_count=0 maximum_count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%%#*}
    IFS=$' \t' read -r key value extra <<< "$line"
    case "${key:-}" in
      '') continue ;;
      SYS_UID_MIN)
        [[ -z "${extra:-}" && "$value" =~ ^[0-9]+$ ]] || return 1
        minimum=$value
        minimum_count=$((minimum_count + 1))
        ;;
      SYS_UID_MAX)
        [[ -z "${extra:-}" && "$value" =~ ^[0-9]+$ ]] || return 1
        maximum=$value
        maximum_count=$((maximum_count + 1))
        ;;
    esac
  done <<< "$input"
  [[ "$minimum_count" -eq 1 && "$maximum_count" -eq 1 ]] || return 1
  (( minimum > 0 && minimum <= maximum && maximum < 4294967295 )) || return 1
  printf '%s\t%s\n' "$minimum" "$maximum"
}

read_system_uid_range() {
  local login_defs=/etc/login.defs content
  [[ -f "$login_defs" && ! -L "$login_defs" ]] || fail relay_install_system_uid_range_invalid
  [[ "$(/usr/bin/stat -c '%u' -- "$login_defs")" == 0 ]] \
    || fail relay_install_system_uid_range_invalid
  local mode
  mode="$(/usr/bin/stat -c '%a' -- "$login_defs")"
  (( (8#$mode & 0022) == 0 )) || fail relay_install_system_uid_range_invalid
  [[ "$(/usr/bin/stat -c '%s' -- "$login_defs")" -le 65536 ]] \
    || fail relay_install_system_uid_range_invalid
  content="$(/usr/bin/head -c 65537 -- "$login_defs")"
  parse_system_uid_range_text "$content" || fail relay_install_system_uid_range_invalid
}

validate_service_identity_fixture() {
  local expected_name=$1 expected_home=$2 range=$3 passwd_line=$4 shadow_line=$5
  local group_line=$6 primary_gid=$7 all_gids=$8
  local minimum maximum
  IFS=$'\t' read -r minimum maximum <<< "$range"
  [[ "$minimum" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ ]] || return 1
  [[ "$passwd_line" =~ ^([^:]*:){6}[^:]*$ ]] || return 1
  [[ "$shadow_line" =~ ^([^:]*:){8}[^:]*$ ]] || return 1
  [[ "$group_line" =~ ^([^:]*:){3}[^:]*$ ]] || return 1
  local user passwd uid gid gecos home shell
  local shadow_user shadow_password shadow_rest
  local group group_password group_gid group_members
  IFS=: read -r user passwd uid gid gecos home shell <<< "$passwd_line"
  IFS=: read -r shadow_user shadow_password shadow_rest <<< "$shadow_line"
  IFS=: read -r group group_password group_gid group_members <<< "$group_line"
  [[ "$user" == "$expected_name" && "$passwd" == x ]] || return 1
  [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ && "$uid" -ne 0 ]] || return 1
  (( uid >= minimum && uid <= maximum )) || return 1
  [[ "$home" == "$expected_home" && "$shell" == /usr/sbin/nologin ]] || return 1
  [[ "$shadow_user" == "$expected_name" && "$shadow_password" =~ ^[!*] ]] || return 2
  [[ "$group" == "$expected_name" && "$group_password" == x && "$group_gid" == "$gid" ]] \
    || return 1
  [[ -z "$group_members" ]] || return 3
  [[ "$primary_gid" == "$gid" && "$all_gids" == "$gid" ]] || return 4
}

assert_service_identity() {
  local name=$1 expected_home=$2 range=$3
  local passwd_line shadow_line group_line primary_gid all_gids status
  passwd_line="$(/usr/bin/getent passwd "$name")" || fail relay_install_service_identity_passwd_missing
  shadow_line="$(/usr/bin/getent shadow "$name")" || fail relay_install_service_identity_shadow_missing
  group_line="$(/usr/bin/getent group "$name")" || fail relay_install_service_identity_group_missing
  [[ "$passwd_line" != *$'\n'* && "$shadow_line" != *$'\n'* && "$group_line" != *$'\n'* ]] \
    || fail relay_install_service_identity_ambiguous
  primary_gid="$(/usr/bin/id -g "$name")" || fail relay_install_service_identity_primary_group_invalid
  all_gids="$(/usr/bin/id -G "$name")" || fail relay_install_service_identity_supplementary_group_invalid
  if validate_service_identity_fixture "$name" "$expected_home" "$range" \
      "$passwd_line" "$shadow_line" "$group_line" "$primary_gid" "$all_gids"; then
    return 0
  else
    status=$?
  fi
  case "$status" in
    2) fail relay_install_service_identity_password_unlocked ;;
    3) fail relay_install_service_identity_group_members_invalid ;;
    4) fail relay_install_service_identity_supplementary_group_invalid ;;
    *) fail relay_install_service_identity_invalid ;;
  esac
}

assert_service_identity_or_absent() {
  local name=$1 expected_home=$2 range=$3
  if /usr/bin/getent passwd "$name" >/dev/null; then
    assert_service_identity "$name" "$expected_home" "$range"
    return
  fi
  if /usr/bin/getent group "$name" >/dev/null || /usr/bin/getent shadow "$name" >/dev/null; then
    fail relay_install_service_identity_partial_collision
  fi
}

self_test_service_identity_contract() {
  local range
  range="$(parse_system_uid_range_text $'SYS_UID_MIN 100\nSYS_UID_MAX 999\n')" \
    || fail relay_install_self_test_uid_range_rejected
  local passwd_line='mrd-relay:x:995:995::/nonexistent:/usr/sbin/nologin'
  local shadow_line='mrd-relay:!:1:0:99999:7:::'
  local group_line='mrd-relay:x:995:'
  validate_service_identity_fixture mrd-relay /nonexistent "$range" \
    "$passwd_line" "$shadow_line" "$group_line" 995 995 \
    || fail relay_install_self_test_service_identity_rejected
  if validate_service_identity_fixture mrd-relay /nonexistent "$range" \
      "$passwd_line" 'mrd-relay:x:1:0:99999:7:::' "$group_line" 995 995; then
    fail relay_install_self_test_unlocked_identity_accepted
  fi
  if validate_service_identity_fixture mrd-relay /nonexistent "$range" \
      "$passwd_line" "$shadow_line" 'mrd-relay:x:995:other' 995 995; then
    fail relay_install_self_test_group_member_accepted
  fi
  if validate_service_identity_fixture mrd-relay /nonexistent "$range" \
      "$passwd_line" "$shadow_line" "$group_line" 995 '995 996'; then
    fail relay_install_self_test_supplementary_group_accepted
  fi
  if parse_system_uid_range_text $'SYS_UID_MIN 100\nSYS_UID_MIN 101\nSYS_UID_MAX 999\n' >/dev/null; then
    fail relay_install_self_test_ambiguous_uid_range_accepted
  fi
}

if [[ "$#" -eq 1 && "$1" == --self-test ]]; then
  self_test_service_identity_contract
  self_test_python="${MRD_RELAY_TEST_PYTHON:-/usr/bin/python3}"
  "$self_test_python" "$public_ip_validator" self-test "$public_ip_vectors" \
    || fail relay_install_self_test_public_ip_classifier_invalid
  [[ "$("$self_test_python" "$public_ip_validator" listener \
      198.20.0.10/10.0.0.10 10.0.0.10)" == 0.0.0.0 ]] \
    || fail relay_install_listener_self_test_ipv4_mismatch
  [[ "$("$self_test_python" "$public_ip_validator" listener \
      2606:4700:4700::1111/fd00::10 fd00::10)" == :: ]] \
    || fail relay_install_listener_self_test_ipv6_mismatch
  MRD_RELAY_TEST_PYTHON="$self_test_python" \
    MRD_RELAY_TEST_VALIDATOR="$script_dir/validate-drain-proof.py" \
    "$script_dir/mrd-relay-drain-proof" --self-test \
    || fail relay_install_self_test_drain_proof_invalid
  aligned_bits=1000000000
  misaligned_bits=1000000001
  (( aligned_bits % 8 == 0 )) || fail relay_install_self_test_aligned_rejected
  aligned_bytes=$((aligned_bits / 8))
  [[ "$aligned_bytes" == 125000000 ]] || fail relay_install_self_test_unit_conversion_invalid
  if (( misaligned_bits % 8 == 0 )); then fail relay_install_self_test_misaligned_accepted; fi
  canonical_secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  [[ "${#canonical_secret}" -eq 43 && "$canonical_secret" =~ ^[A-Za-z0-9_-]{43}$ ]] \
    || fail relay_install_self_test_canonical_secret_rejected
  if [[ "${canonical_secret}A" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
    fail relay_install_self_test_oversized_secret_accepted
  fi
  printf '%s\n' relay_install_self_test_passed
  exit 0
fi

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --agent-binary|--coturn-helper-binary|--agent-config|--enrollment-token-file|--turn-secret-file|--trusted-ca|--tls-cert|--tls-key|--realm|--server-name|--external-ip|--relay-ip|--tls-port|--firewall-backend|--firewalld-zone)
      [[ "$#" -ge 2 ]] || usage
      case "$1" in
        --agent-binary) agent_binary=$2 ;;
        --coturn-helper-binary) coturn_helper_binary=$2 ;;
        --agent-config) agent_config=$2 ;;
        --enrollment-token-file) enrollment_token_file=$2 ;;
        --turn-secret-file) turn_secret_file=$2 ;;
        --trusted-ca) trusted_ca=$2 ;;
        --tls-cert) tls_cert=$2 ;;
        --tls-key) tls_key=$2 ;;
        --realm) realm=$2 ;;
        --server-name) server_name=$2 ;;
        --external-ip) external_ip=$2 ;;
        --relay-ip) relay_ip=$2 ;;
        --tls-port) tls_port=$2 ;;
        --firewall-backend) firewall_backend=$2 ;;
        --firewalld-zone) firewalld_zone=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || fail relay_install_requires_root
[[ "$tls_port" == 5349 || "$tls_port" == 443 ]] || fail relay_install_invalid_tls_port
[[ "$firewall_backend" =~ ^(nftables|firewalld|ufw)$ ]] || fail relay_install_firewall_backend_unknown
[[ "$firewalld_zone" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || fail relay_install_firewall_zone_invalid
[[ "$realm" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || fail relay_install_invalid_realm
[[ "$server_name" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || fail relay_install_invalid_server_name

require_source() {
  local path=$1
  [[ "$path" == /* && -f "$path" && ! -L "$path" ]] || fail relay_install_invalid_source
  local canonical
  canonical="$(/usr/bin/realpath -e -- "$path")" || fail relay_install_invalid_source
  [[ "$canonical" == "$path" ]] || fail relay_install_noncanonical_source
}

assert_trusted_ancestors() {
  local current=$1
  while [[ "$current" != / ]]; do
    if [[ -e "$current" ]]; then
      [[ ! -L "$current" ]] || fail relay_install_symlink_ancestor_rejected
      [[ "$(/usr/bin/stat -c '%u' -- "$current")" == 0 ]] || fail relay_install_owner_invalid
      local mode
      mode="$(/usr/bin/stat -c '%a' -- "$current")"
      (( (8#$mode & 0022) == 0 )) || fail relay_install_mode_invalid
    fi
    current="${current%/*}"
    [[ -n "$current" ]] || current=/
  done
}

for source in \
  "$agent_binary" "$coturn_helper_binary" "$agent_config" "$turn_config" \
  "$enrollment_token_file" "$turn_secret_file" "$trusted_ca" "$tls_cert" "$tls_key" "$script_dir/mrd-relay.nft" \
  "$script_dir/mrd-relay-firewall" "$public_ip_vectors" "$public_ip_validator"; do
  require_source "$source"
  assert_trusted_ancestors "$source"
done
for source in "$script_dir/mrd-relay-drain-proof" "$script_dir/validate-drain-proof.py"; do
  require_source "$source"
  assert_trusted_ancestors "$source"
done
for private_source in "$enrollment_token_file" "$turn_secret_file" "$tls_key"; do
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- "$private_source")" == root:root:600 ]] \
    || fail relay_install_private_source_mode_invalid
done

for executable in \
  /usr/bin/systemctl /usr/bin/systemd-tmpfiles /usr/bin/turnserver /usr/bin/ss \
  /usr/bin/install /usr/bin/mv /usr/bin/cp /usr/bin/stat /usr/bin/python3 \
  /usr/bin/openssl /usr/bin/flock /usr/bin/readlink /usr/bin/sha256sum /usr/sbin/runuser \
  /usr/bin/getent /usr/bin/id /usr/bin/head /usr/sbin/useradd; do
  [[ -x "$executable" ]] || fail relay_install_dependency_missing
done
system_uid_range="$(read_system_uid_range)" || fail relay_install_system_uid_range_invalid
assert_service_identity_or_absent mrd-relay /nonexistent "$system_uid_range"
assert_service_identity_or_absent mrd-coturn /nonexistent "$system_uid_range"
[[ -x /usr/bin/flock ]] || fail relay_install_deploy_lock_unavailable
exec 8> /run/lock/mrd-relay-deploy.lock
/usr/bin/flock --exclusive --nonblock 8 || fail relay_install_deploy_lock_busy
assert_service_identity_or_absent mrd-relay /nonexistent "$system_uid_range"
assert_service_identity_or_absent mrd-coturn /nonexistent "$system_uid_range"
case "$firewall_backend" in
  nftables) [[ -x /usr/sbin/nft ]] || fail relay_install_firewall_backend_unavailable ;;
  firewalld)
    [[ -x /usr/bin/firewall-cmd ]] || fail relay_install_firewall_backend_unavailable
    [[ "$(/usr/bin/firewall-cmd --state 2>/dev/null)" == running ]] \
      || fail relay_install_firewall_backend_unavailable
    ;;
  ufw)
    [[ -x /usr/sbin/ufw ]] || fail relay_install_firewall_backend_unavailable
    /usr/sbin/ufw status | /usr/bin/grep -q '^Status: active$' \
      || fail relay_install_firewall_backend_unavailable
    ;;
  *) fail relay_install_firewall_backend_unknown ;;
esac

/usr/bin/python3 "$public_ip_validator" check "$external_ip" "$relay_ip" \
  || fail relay_install_invalid_ip
listener_ip="$(/usr/bin/python3 "$public_ip_validator" listener "$external_ip" "$relay_ip")" \
  || fail relay_install_invalid_ip
[[ "$listener_ip" == 0.0.0.0 || "$listener_ip" == :: ]] \
  || fail relay_install_listener_ip_invalid

# The repository baseline is code-reviewed input. Reject drift, duplicates,
# unsafe flags, and active placeholders before rendering any operator values.
/usr/bin/python3 - "$turn_config" "$agent_config" "$external_ip" >/dev/null <<'PY' || fail relay_install_config_invalid
import ipaddress
import json
import pathlib
import re
import sys

baseline = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
allowed = {
    "listening-port", "tls-listening-port", "listening-ip", "fingerprint",
    "realm", "server-name", "use-auth-secret", "static-auth-secret",
    "rest-api-separator", "unauthorized-ratelimit", "unauthorized-ratelimit-rps",
    "user-quota", "total-quota", "max-bps",
    "bps-capacity", "min-port", "max-port", "stale-nonce",
    "max-allocate-timeout", "max-allocate-lifetime", "cert", "pkey",
    "no-tlsv1", "no-tlsv1_1", "denied-peer-ip", "no-multicast-peers",
    "no-cli", "no-rfc5780", "no-software-attribute", "prometheus",
    "prometheus-address", "prometheus-port", "prometheus-path",
    "drain-min-allocations", "simple-log", "log-file",
}
repeatable = {"denied-peer-ip"}
seen = {}
for raw in baseline.splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    key = line.split("=", 1)[0]
    if key not in allowed:
        raise SystemExit("relay_install_config_unknown")
    seen[key] = seen.get(key, 0) + 1
    if seen[key] > 1 and key not in repeatable:
        raise SystemExit("relay_install_config_duplicate")
    if "CHANGE_ME" in line and key not in {"realm", "server-name", "static-auth-secret"}:
        raise SystemExit("relay_install_config_placeholder")
for required in allowed - repeatable:
    if seen.get(required) != 1:
        raise SystemExit("relay_install_config_missing")
for forbidden in ("allow-loopback-peers", "no-auth", "lt-cred-mech", "verbose"):
    if forbidden in seen:
        raise SystemExit("relay_install_config_forbidden")
config = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if config.get("enrollment_token") is not None or config.get("turn_rest_secret") is not None:
    raise SystemExit("relay_install_config_inline_secret")
max_allocations = config.get("max_allocations")
max_egress_bps = config.get("max_egress_bps")
if isinstance(max_allocations, bool) or not isinstance(max_allocations, int) or not 1 <= max_allocations <= 100:
    raise SystemExit("relay_install_config_capacity_invalid")
if isinstance(max_egress_bps, bool) or not isinstance(max_egress_bps, int) or max_egress_bps <= 0:
    raise SystemExit("relay_install_config_bandwidth_invalid")
if max_egress_bps % 8 != 0:
    raise SystemExit("relay_install_bandwidth_not_byte_aligned")
public_address = ipaddress.ip_address(sys.argv[3].split("/", 1)[0])
endpoint_pattern = re.compile(
    r"^(?:turn|turns):(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):"
    r"[0-9]{1,5}(?:\?transport=(?:udp|tcp))?$"
)
for endpoint in config.get("endpoints", []):
    if not isinstance(endpoint, str):
        raise SystemExit("relay_install_endpoint_invalid")
    match = endpoint_pattern.fullmatch(endpoint)
    if match is None:
        raise SystemExit("relay_install_endpoint_invalid")
    endpoint_host = match.group(1).strip("[]")
    try:
        endpoint_address = ipaddress.ip_address(endpoint_host)
    except ValueError:
        continue
    if endpoint_address.version != public_address.version:
        raise SystemExit("relay_install_endpoint_listener_family_mismatch")
print(max_allocations)
print(max_egress_bps)
PY
mapfile -t capacity_values < <(/usr/bin/python3 - "$agent_config" "$turn_config" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(value["max_allocations"])
print(value["max_egress_bps"])
for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    if line.startswith("max-bps="):
        print(line.split("=", 1)[1])
        break
PY
)
[[ "${#capacity_values[@]}" -eq 3 ]] || fail relay_install_config_capacity_invalid
max_allocations=${capacity_values[0]}
max_egress_bps=${capacity_values[1]}
coturn_capacity_bps=$((max_egress_bps / 8))
coturn_per_allocation_bps=${capacity_values[2]}
(( coturn_per_allocation_bps > 0 && coturn_per_allocation_bps <= coturn_capacity_bps )) \
  || fail relay_install_per_allocation_bandwidth_invalid

version_output="$(/usr/bin/turnserver --version 2>&1)" || fail relay_install_coturn_version_unavailable
version="$(printf '%s\n' "$version_output" | /usr/bin/grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | /usr/bin/head -n 1)"
[[ -n "$version" ]] || fail relay_install_coturn_version_invalid
if ! /usr/bin/sort -V -C <(printf '%s\n' 4.17.2 "$version"); then
  fail relay_install_coturn_version_too_old
fi
help_output="$(/usr/bin/turnserver --help 2>&1 || true)"
printf '%s\n' "$help_output" | /usr/bin/grep -q -- '--prometheus-address' \
  || fail relay_install_coturn_prometheus_build_missing
unset version_output help_output

[[ "$(/usr/bin/stat -c '%s' -- "$turn_secret_file")" == 43 ]] || fail relay_install_secret_size_invalid
secret="$(/usr/bin/head -c 513 -- "$turn_secret_file")"
[[ "$secret" =~ ^[A-Za-z0-9_-]{43}$ ]] || fail relay_install_invalid_turn_secret
unset secret
/usr/bin/python3 - "$enrollment_token_file" <<'PY' || fail relay_install_enrollment_token_invalid
import pathlib
import sys

value = pathlib.Path(sys.argv[1]).read_bytes()
if not 40 <= len(value) <= 512 or not value.isascii() or any(byte < 0x21 or byte > 0x7e for byte in value):
    raise SystemExit(1)
PY

/usr/bin/openssl x509 -in "$tls_cert" -noout -checkend 86400 >/dev/null \
  || fail relay_install_tls_certificate_invalid
cert_key_hash="$(/usr/bin/openssl x509 -in "$tls_cert" -pubkey -noout \
  | /usr/bin/openssl pkey -pubin -outform DER 2>/dev/null | /usr/bin/sha256sum)"
private_key_hash="$(/usr/bin/openssl pkey -in "$tls_key" -pubout -outform DER 2>/dev/null \
  | /usr/bin/sha256sum)"
[[ "${cert_key_hash%% *}" == "${private_key_hash%% *}" ]] || fail relay_install_tls_key_mismatch
unset cert_key_hash private_key_hash

if [[ "$tls_port" == 443 ]]; then
  listeners="$(/usr/bin/ss -H -ltnp 'sport = :443')"
  if [[ -n "$listeners" ]]; then
    owned_pid="$(/usr/bin/systemctl show mrd-coturn.service --property=MainPID --value 2>/dev/null || true)"
    [[ "$owned_pid" =~ ^[1-9][0-9]*$ ]] || fail relay_install_tls_443_conflict
    while IFS= read -r listener; do
      [[ "$listener" == *"pid=$owned_pid,"* ]] || fail relay_install_tls_443_conflict
    done <<< "$listeners"
  fi
  unset listeners owned_pid
fi

if [[ -e /etc/systemd/system/mrd-relay-agent.service ||
      -e /etc/mrd-relay-agent/agent.json ||
      -e /usr/local/bin/mrd-relay-agent ]]; then
  existing_install=true
  for existing_path in \
    /etc/systemd/system/mrd-relay-agent.service \
    /etc/mrd-relay-agent/agent.json \
    /usr/local/bin/mrd-relay-agent \
    /usr/local/libexec/mrd-relay-firewall \
    /usr/local/libexec/mrd-relay-drain-proof \
    /usr/local/libexec/mrd-validate-drain-proof \
    "$firewall_config"; do
    [[ -f "$existing_path" && ! -L "$existing_path" ]] \
      || fail relay_install_existing_install_incomplete
    assert_trusted_ancestors "$existing_path"
  done
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- /usr/local/bin/mrd-relay-agent)" == root:root:755 ]] \
    || fail relay_install_existing_agent_mode_invalid
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- /usr/local/libexec/mrd-relay-drain-proof)" == root:root:755 ]] \
    || fail relay_install_existing_drain_helper_mode_invalid
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- /usr/local/libexec/mrd-validate-drain-proof)" == root:root:755 ]] \
    || fail relay_install_existing_drain_validator_mode_invalid
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- /usr/local/libexec/mrd-relay-firewall)" == root:root:755 \
    && "$(/usr/bin/stat -c '%U:%G:%a' -- "$firewall_config")" == root:root:600 ]] \
    || fail relay_install_existing_firewall_files_invalid
  mapfile -t existing_firewall_backends < <(
    /usr/bin/awk -F= '$1 == "backend" { print $2 }' "$firewall_config"
  )
  [[ "${#existing_firewall_backends[@]}" -eq 1 \
    && "${existing_firewall_backends[0]}" =~ ^(nftables|firewalld|ufw)$ ]] \
    || fail relay_install_existing_firewall_config_invalid
  existing_firewall_backend=${existing_firewall_backends[0]}
  unset existing_firewall_backends
  assert_service_identity mrd-relay /nonexistent "$system_uid_range"
  assert_service_identity mrd-coturn /nonexistent "$system_uid_range"
  first_drain_proof="$(/usr/local/libexec/mrd-relay-drain-proof --config /etc/mrd-relay-agent/agent.json)" \
    || fail relay_install_first_drain_proof_failed
fi

if [[ "$firewall_backend" == ufw ]]; then
  ufw_status="$(/usr/sbin/ufw status)" || fail relay_install_firewall_backend_unavailable
  ufw_named_rule_present=false
  if /usr/bin/grep -Fq -- MRD-Relay <<< "$ufw_status"; then
    ufw_named_rule_present=true
  fi
  if [[ "$existing_install" != true || "$existing_firewall_backend" != ufw ]]; then
    [[ ! -e "$ufw_profile" && ! -e /var/lib/mrd-coturn/ufw-added.rule \
      && "$ufw_named_rule_present" != true ]] \
      || fail relay_install_ufw_name_collision
  else
    [[ -f "$ufw_profile" && ! -L "$ufw_profile" \
      && -f /var/lib/mrd-coturn/ufw-added.rule \
      && ! -L /var/lib/mrd-coturn/ufw-added.rule \
      && "$(/usr/bin/stat -c '%U:%G:%a' -- /var/lib/mrd-coturn/ufw-added.rule)" == root:root:600 \
      && "$(/usr/bin/cat -- /var/lib/mrd-coturn/ufw-added.rule)" == $'schema_version=2\nrule=MRD-Relay\nstate=owned' ]] \
      || fail relay_install_existing_ufw_ownership_invalid
  fi
  unset ufw_status ufw_named_rule_present
fi
if [[ "$existing_install" == true ]]; then
  /usr/local/libexec/mrd-relay-firewall verify \
    || fail relay_install_existing_firewall_ownership_invalid
fi

for trusted_path in \
  /etc /etc/systemd /etc/systemd/system /usr/local /usr/local/bin /usr/local/libexec \
  /usr/lib /usr/lib/tmpfiles.d /usr/share /usr/share/doc /var /var/lib \
  "${config_root%/*}" "${backup_root%/*}" "${low_port_dropin%/*}"; do
  assert_trusted_ancestors "$trusted_path"
done
for managed_path in "$config_root" "$backup_root" /var/lib/mrd-coturn \
  /usr/share/doc/mrd-relay-agent; do
  assert_trusted_ancestors "$managed_path"
done
if [[ -e /var/lib/mrd-relay-agent ]]; then
  [[ -d /var/lib/mrd-relay-agent && ! -L /var/lib/mrd-relay-agent ]] \
    || fail relay_install_state_directory_invalid
fi

if ! /usr/bin/getent passwd mrd-relay >/dev/null; then
  /usr/sbin/useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin mrd-relay
fi
if ! /usr/bin/getent passwd mrd-coturn >/dev/null; then
  /usr/sbin/useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin mrd-coturn
fi
assert_service_identity mrd-relay /nonexistent "$system_uid_range"
assert_service_identity mrd-coturn /nonexistent "$system_uid_range"

/usr/bin/install -d -o root -g root -m 0700 "$config_root" "$secret_dir" "$tls_dir" "$coturn_dir"
/usr/bin/install -d -o root -g root -m 0700 "$backup_root"
case "$firewall_backend" in
  nftables) /usr/bin/install -d -o root -g root -m 0755 /etc/nftables.d ;;
  ufw) /usr/bin/install -d -o root -g root -m 0755 /etc/ufw/applications.d ;;
esac
/usr/bin/install -d -o mrd-relay -g mrd-relay -m 0700 /var/lib/mrd-relay-agent
/usr/bin/install -d -o root -g root -m 0700 /var/lib/mrd-coturn
for trusted_path in \
  "$config_root" "$secret_dir" "$tls_dir" "$coturn_dir" "$backup_root" \
  /usr/local/bin /usr/local/libexec /etc/systemd/system /usr/lib/tmpfiles.d \
  /var/lib /var/lib/mrd-coturn; do
  assert_trusted_ancestors "$trusted_path"
done
case "$firewall_backend" in
  nftables) assert_trusted_ancestors /etc/nftables.d ;;
  ufw) assert_trusted_ancestors /etc/ufw/applications.d ;;
esac

backup_dir="$backup_root/install-$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)-$$"
/usr/bin/install -d -o root -g root -m 0700 "$backup_dir"
printf '%s\n' "relay_install_recovery_checkpoint path=$backup_dir"

backup_existing() {
  local destination=$1
  local name=$2
  if [[ -e "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] || fail relay_install_unsafe_existing_file
    /usr/bin/cp --preserve=mode,ownership,timestamps -- "$destination" "$backup_dir/$name"
  fi
}

backup_existing /usr/local/bin/mrd-relay-agent mrd-relay-agent
backup_existing /usr/local/libexec/mrd-relay-coturn-control mrd-relay-coturn-control
backup_existing /usr/local/libexec/mrd-relay-firewall mrd-relay-firewall
backup_existing /usr/local/libexec/mrd-coturn-render-config mrd-coturn-render-config
backup_existing /usr/local/libexec/mrd-verify-relay-node mrd-verify-relay-node
backup_existing /usr/local/libexec/mrd-relay-drain-proof mrd-relay-drain-proof
backup_existing /usr/local/libexec/mrd-validate-drain-proof mrd-validate-drain-proof
backup_existing "$config_root/agent.json" agent.json
backup_existing "$secret_dir/enrollment-token" enrollment-token
backup_existing "$secret_dir/turn-rest-secret" turn-rest-secret
backup_existing "$secret_dir/trusted-ca.pem" trusted-ca.pem
backup_existing "$secret_dir/turnserver.generated.conf" turnserver.generated.conf
backup_existing "$tls_dir/fullchain.pem" fullchain.pem
backup_existing "$tls_dir/privkey.pem" privkey.pem
backup_existing "$coturn_dir/turnserver.conf.base" turnserver.conf.base
backup_existing "$firewall_config" firewall.conf
backup_existing /var/lib/mrd-coturn/firewalld-added.rules firewalld-added.rules
backup_existing /var/lib/mrd-coturn/ufw-added.rule ufw-added.rule
backup_existing /var/lib/mrd-coturn/control-state.json control-state.json
backup_existing /var/lib/mrd-coturn/control-journal.json control-journal.json
backup_existing /var/lib/mrd-coturn/control-previous-secret control-previous-secret
backup_existing /var/lib/mrd-coturn/control-previous-config control-previous-config
backup_existing "$nft_destination" mrd-relay.nft
backup_existing "$ufw_profile" ufw-mrd-relay
backup_existing "$low_port_dropin" 10-low-port.conf
backup_existing /etc/systemd/system/mrd-relay-agent.service mrd-relay-agent.service
backup_existing /etc/systemd/system/mrd-coturn.service mrd-coturn.service
backup_existing /etc/systemd/system/mrd-relay-coturn-control.socket mrd-relay-coturn-control.socket
backup_existing /etc/systemd/system/mrd-relay-coturn-control@.service mrd-relay-coturn-control@.service
backup_existing /etc/systemd/system/mrd-relay-firewall.service mrd-relay-firewall.service
backup_existing /usr/lib/tmpfiles.d/mrd-relay-coturn-control.conf mrd-relay-coturn-control.conf
backup_existing /usr/share/doc/mrd-relay-agent/README.md README.md

if /usr/bin/systemctl is-active --quiet mrd-relay-agent.service; then agent_was_active=true; fi
if /usr/bin/systemctl is-active --quiet mrd-relay-coturn-control.socket; then socket_was_active=true; fi
if /usr/bin/systemctl is-active --quiet mrd-relay-firewall.service; then firewall_was_active=true; fi
if /usr/bin/systemctl is-active --quiet mrd-coturn.service; then coturn_was_active=true; fi
if /usr/bin/systemctl is-enabled --quiet mrd-relay-agent.service; then agent_was_enabled=true; fi
if /usr/bin/systemctl is-enabled --quiet mrd-relay-coturn-control.socket; then socket_was_enabled=true; fi
if /usr/bin/systemctl is-enabled --quiet mrd-relay-firewall.service; then firewall_was_enabled=true; fi
if /usr/bin/systemctl is-enabled --quiet mrd-coturn.service; then coturn_was_enabled=true; fi

assert_same_drain_fence() {
  local first=$1
  local second=$2
  [[ "$first" =~ ^linux-systemd$'\t'[1-9][0-9]*$'\t'[1-9][0-9]*$ ]] \
    || fail relay_install_first_drain_fence_invalid
  [[ "$second" == "$first" ]] || fail relay_install_drain_fence_changed
}

checkpoint_drained_broker_state() {
  local path
  path=/var/lib/mrd-coturn/control-state.json
  [[ -f "$path" && ! -L "$path" ]] || fail relay_install_drained_control_state_missing
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- "$path")" == root:root:600 ]] \
    || fail relay_install_drained_control_state_mode_invalid
  backup_existing "$path" control-state.json
  for path in \
    /var/lib/mrd-coturn/control-journal.json \
    /var/lib/mrd-coturn/control-previous-secret \
    /var/lib/mrd-coturn/control-previous-config; do
    if [[ -e "$path" ]]; then
      [[ -f "$path" && ! -L "$path" ]] || fail relay_install_drained_broker_artifact_invalid
      [[ "$(/usr/bin/stat -c '%U:%G:%a' -- "$path")" == root:root:600 ]] \
        || fail relay_install_drained_broker_artifact_mode_invalid
      backup_existing "$path" "${path##*/}"
    else
      /usr/bin/rm -f -- "$backup_dir/${path##*/}"
    fi
  done
}

restore_or_remove() {
  local destination=$1
  local name=$2
  if [[ -f "$backup_dir/$name" && ! -L "$backup_dir/$name" ]]; then
    /usr/bin/cp --preserve=mode,ownership,timestamps -- "$backup_dir/$name" "$destination"
  else
    /usr/bin/rm -f -- "$destination"
  fi
}

cleanup_temporaries() {
  local temporary
  for temporary in \
    "${base_temporary:-}" "${firewall_temporary:-}" \
    "${ufw_temporary:-}" "${dropin_temporary:-}"; do
    if [[ -n "$temporary" && -f "$temporary" && ! -L "$temporary" ]]; then
      /usr/bin/rm -f -- "$temporary"
    fi
  done
}

rollback_install() {
  set +e
  if [[ "$filesystem_mutation_started" != true ]]; then
    local early_rollback_failed=false
    # Before the first file replacement there is nothing to restore.  Only
    # undo service transitions which this invocation may have completed.  In
    # particular, never stop a still-live drained coturn merely because the
    # second drain fence failed.
    if [[ "$firewall_policy_remove_attempted" == true ]]; then
      /usr/bin/systemctl start mrd-relay-firewall.service \
        || early_rollback_failed=true
      /usr/local/libexec/mrd-relay-firewall verify \
        || early_rollback_failed=true
    fi
    if [[ "$socket_stop_attempted" == true && "$socket_was_active" == true ]] \
      && ! /usr/bin/systemctl is-active --quiet mrd-relay-coturn-control.socket; then
      /usr/bin/systemctl start mrd-relay-coturn-control.socket \
        || early_rollback_failed=true
      /usr/bin/systemctl is-active --quiet mrd-relay-coturn-control.socket \
        || early_rollback_failed=true
    fi
    if [[ "$coturn_stop_attempted" == true && "$coturn_was_active" == true ]] \
      && ! /usr/bin/systemctl is-active --quiet mrd-coturn.service; then
      # Once a drained coturn has stopped, only the restored broker/agent may
      # create its next generation.  Do not bypass the drain journal here.
      printf '%s\n' relay_install_rollback_coturn_left_for_broker >&2
    fi
    if [[ "$agent_stop_attempted" == true && "$agent_was_active" == true ]] \
      && ! /usr/bin/systemctl is-active --quiet mrd-relay-agent.service; then
      /usr/bin/systemctl start mrd-relay-agent.service \
        || early_rollback_failed=true
      /usr/bin/systemctl is-active --quiet mrd-relay-agent.service \
        || early_rollback_failed=true
    fi
    set -e
    if [[ "$early_rollback_failed" == true ]]; then
      printf '%s\n' relay_install_early_rollback_failed >&2
      return 1
    fi
    return
  fi
  local rollback_failed=false
  local firewall_cleanup_succeeded=true
  /usr/bin/systemctl stop mrd-relay-agent.service
  /usr/bin/systemctl stop mrd-relay-firewall.service
  /usr/bin/systemctl stop mrd-relay-coturn-control.socket
  /usr/bin/systemctl stop mrd-coturn.service
  if [[ -x /usr/local/libexec/mrd-relay-firewall ]]; then
    if ! /usr/local/libexec/mrd-relay-firewall remove; then
      # Keep the current helper, configuration, profile and provenance intact
      # when cleanup/read-back fails.  Overwriting any of them here could
      # orphan still-open rules and make a later operator recovery unsafe.
      firewall_cleanup_succeeded=false
      rollback_failed=true
      printf '%s\n' relay_install_rollback_firewall_cleanup_failed >&2
    fi
  fi
  while IFS='|' read -r destination name; do
    if [[ "$firewall_cleanup_succeeded" != true ]]; then
      case "$name" in
        mrd-relay-firewall|firewall.conf|firewalld-added.rules|ufw-added.rule|\
        mrd-relay.nft|ufw-mrd-relay|mrd-relay-firewall.service)
          continue
          ;;
      esac
    fi
    restore_or_remove "$destination" "$name"
  done <<'ROLLBACK_FILES'
/usr/local/bin/mrd-relay-agent|mrd-relay-agent
/usr/local/libexec/mrd-relay-coturn-control|mrd-relay-coturn-control
/usr/local/libexec/mrd-relay-firewall|mrd-relay-firewall
/usr/local/libexec/mrd-coturn-render-config|mrd-coturn-render-config
/usr/local/libexec/mrd-verify-relay-node|mrd-verify-relay-node
/usr/local/libexec/mrd-relay-drain-proof|mrd-relay-drain-proof
/usr/local/libexec/mrd-validate-drain-proof|mrd-validate-drain-proof
/etc/mrd-relay-agent/agent.json|agent.json
/etc/mrd-relay-agent/secrets/enrollment-token|enrollment-token
/etc/mrd-relay-agent/secrets/turn-rest-secret|turn-rest-secret
/etc/mrd-relay-agent/secrets/trusted-ca.pem|trusted-ca.pem
/etc/mrd-relay-agent/secrets/turnserver.generated.conf|turnserver.generated.conf
/etc/mrd-relay-agent/tls/fullchain.pem|fullchain.pem
/etc/mrd-relay-agent/tls/privkey.pem|privkey.pem
/etc/mrd-relay-agent/coturn/turnserver.conf.base|turnserver.conf.base
/etc/mrd-relay-agent/firewall.conf|firewall.conf
/var/lib/mrd-coturn/firewalld-added.rules|firewalld-added.rules
/var/lib/mrd-coturn/ufw-added.rule|ufw-added.rule
/var/lib/mrd-coturn/control-state.json|control-state.json
/var/lib/mrd-coturn/control-journal.json|control-journal.json
/var/lib/mrd-coturn/control-previous-secret|control-previous-secret
/var/lib/mrd-coturn/control-previous-config|control-previous-config
/etc/nftables.d/mrd-relay.nft|mrd-relay.nft
/etc/ufw/applications.d/mrd-relay|ufw-mrd-relay
/etc/systemd/system/mrd-coturn.service.d/10-low-port.conf|10-low-port.conf
/etc/systemd/system/mrd-relay-agent.service|mrd-relay-agent.service
/etc/systemd/system/mrd-coturn.service|mrd-coturn.service
/etc/systemd/system/mrd-relay-coturn-control.socket|mrd-relay-coturn-control.socket
/etc/systemd/system/mrd-relay-coturn-control@.service|mrd-relay-coturn-control@.service
/etc/systemd/system/mrd-relay-firewall.service|mrd-relay-firewall.service
/usr/lib/tmpfiles.d/mrd-relay-coturn-control.conf|mrd-relay-coturn-control.conf
/usr/share/doc/mrd-relay-agent/README.md|README.md
ROLLBACK_FILES
  /usr/bin/systemctl daemon-reload
  if [[ "$socket_was_enabled" == true ]]; then
    /usr/bin/systemctl enable mrd-relay-coturn-control.socket
  else
    /usr/bin/systemctl disable mrd-relay-coturn-control.socket
  fi
  if [[ "$firewall_cleanup_succeeded" == true ]]; then
    if [[ "$firewall_was_enabled" == true ]]; then
      /usr/bin/systemctl enable mrd-relay-firewall.service
    else
      /usr/bin/systemctl disable mrd-relay-firewall.service
    fi
  fi
  if [[ "$agent_was_enabled" == true ]]; then
    /usr/bin/systemctl enable mrd-relay-agent.service
  else
    /usr/bin/systemctl disable mrd-relay-agent.service
  fi
  if [[ "$coturn_was_enabled" == true ]]; then
    /usr/bin/systemctl enable mrd-coturn.service
  else
    /usr/bin/systemctl disable mrd-coturn.service
  fi
  if [[ "$socket_was_active" == true ]]; then /usr/bin/systemctl start mrd-relay-coturn-control.socket; fi
  if [[ "$firewall_cleanup_succeeded" == true \
    && ( "$firewall_was_active" == true || "$firewall_policy_remove_attempted" == true ) ]]; then
    /usr/bin/systemctl start mrd-relay-firewall.service
    /usr/local/libexec/mrd-relay-firewall verify
  fi
  # Never bypass the restored broker journal/control-state.  The restored agent
  # and broker decide whether a new coturn invocation is safe.
  if [[ "$coturn_was_active" == true ]]; then
    printf '%s\n' relay_install_rollback_coturn_left_for_broker >&2
  fi
  if [[ "$agent_was_active" == true ]]; then /usr/bin/systemctl start mrd-relay-agent.service; fi
  set -e
  if [[ "$rollback_failed" == true ]]; then
    return 1
  fi
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  cleanup_temporaries
  if [[ "$transaction_started" == true && "$transaction_committed" != true ]]; then
    printf '%s\n' relay_install_transaction_rollback >&2
    if ! rollback_install; then
      status=1
    fi
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' HUP INT TERM
transaction_started=true

if [[ "$existing_install" == true ]]; then
  agent_stop_attempted=true
  /usr/bin/systemctl stop mrd-relay-agent.service || fail relay_install_existing_agent_stop_failed
  second_drain_proof="$(/usr/local/libexec/mrd-relay-drain-proof --config /etc/mrd-relay-agent/agent.json)" \
    || fail relay_install_second_drain_proof_failed
  assert_same_drain_fence "$first_drain_proof" "$second_drain_proof"
  socket_stop_attempted=true
  /usr/bin/systemctl stop mrd-relay-coturn-control.socket || fail relay_install_existing_socket_stop_failed
  mapfile -t existing_control_instances < <(
    /usr/bin/systemctl list-units --all --plain --no-legend 'mrd-relay-coturn-control@*.service' \
      | /usr/bin/awk '{print $1}'
  )
  for unit in "${existing_control_instances[@]}"; do
    [[ "$unit" =~ ^mrd-relay-coturn-control@[A-Za-z0-9_.:@-]+\.service$ ]] \
      || fail relay_install_control_instance_invalid
    /usr/bin/systemctl stop "$unit" || fail relay_install_control_instance_stop_failed
  done
  checkpoint_drained_broker_state
  coturn_stop_attempted=true
  /usr/bin/systemctl stop mrd-coturn.service || fail relay_install_existing_coturn_stop_failed
fi
if [[ "$existing_install" == true ]]; then
  /usr/local/libexec/mrd-relay-firewall verify \
    || fail relay_install_existing_firewall_ownership_invalid
  firewall_policy_remove_attempted=true
  /usr/bin/systemctl stop mrd-relay-firewall.service \
    || fail relay_install_existing_firewall_remove_failed
  /usr/local/libexec/mrd-relay-firewall remove \
    || fail relay_install_existing_firewall_remove_failed
fi

filesystem_mutation_started=true
/usr/bin/install -o root -g root -m 0755 "$agent_binary" /usr/local/bin/mrd-relay-agent
/usr/bin/install -o root -g root -m 0755 "$coturn_helper_binary" /usr/local/libexec/mrd-relay-coturn-control
/usr/bin/install -o root -g root -m 0755 "$script_dir/mrd-coturn-render-config" /usr/local/libexec/mrd-coturn-render-config
/usr/bin/install -o root -g root -m 0755 "$script_dir/mrd-relay-firewall" /usr/local/libexec/mrd-relay-firewall
/usr/bin/install -o root -g root -m 0755 "$script_dir/verify-relay-node.sh" /usr/local/libexec/mrd-verify-relay-node
/usr/bin/install -o root -g root -m 0755 "$script_dir/mrd-relay-drain-proof" /usr/local/libexec/mrd-relay-drain-proof
/usr/bin/install -o root -g root -m 0755 "$script_dir/validate-drain-proof.py" /usr/local/libexec/mrd-validate-drain-proof
agent_config_temporary="$(/usr/bin/mktemp --tmpdir="$config_root" .agent.json.XXXXXX)"
/usr/bin/python3 - "$agent_config" "$agent_config_temporary" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
value = json.loads(source.read_text(encoding="utf-8"))
value.pop("enrollment_token", None)
value.pop("turn_rest_secret", None)
value["enrollment_token_path"] = "/run/credentials/mrd-relay-agent.service/enrollment-token"
value["turn_rest_secret_path"] = "/run/credentials/mrd-relay-agent.service/turn-rest-secret"
value["trusted_ca_path"] = "/run/credentials/mrd-relay-agent.service/trusted-ca"
destination.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
/usr/bin/chown root:root "$agent_config_temporary"
/usr/bin/chmod 0600 "$agent_config_temporary"
/usr/bin/mv -fT -- "$agent_config_temporary" "$config_root/agent.json"
/usr/local/bin/mrd-relay-agent validate --config "$config_root/agent.json" \
  || fail relay_install_agent_config_validation_failed
/usr/bin/install -o root -g root -m 0600 "$enrollment_token_file" "$secret_dir/enrollment-token"
/usr/bin/install -o root -g root -m 0600 "$turn_secret_file" "$secret_dir/turn-rest-secret"
/usr/bin/install -o root -g root -m 0600 "$trusted_ca" "$secret_dir/trusted-ca.pem"
/usr/bin/install -o root -g root -m 0600 "$tls_cert" "$tls_dir/fullchain.pem"
/usr/bin/install -o root -g root -m 0600 "$tls_key" "$tls_dir/privkey.pem"

base_temporary="$(/usr/bin/mktemp --tmpdir="$coturn_dir" .turnserver.conf.base.XXXXXX)"
tls_line_count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    listening-ip=*) printf 'listening-ip=%s\n' "$listener_ip" >> "$base_temporary" ;;
    tls-listening-port=*)
      printf 'tls-listening-port=%s\n' "$tls_port" >> "$base_temporary"
      tls_line_count=$((tls_line_count + 1))
      ;;
    realm=CHANGE_ME_RELAY_REALM) printf 'realm=%s\n' "$realm" >> "$base_temporary" ;;
    server-name=CHANGE_ME_RELAY_FQDN) printf 'server-name=%s\n' "$server_name" >> "$base_temporary" ;;
    static-auth-secret=CHANGE_ME_WITH_43_CHAR_BASE64URL_SECRET)
      printf '%s\n' 'static-auth-secret=__MRD_BROKER_SECRET_V1__' >> "$base_temporary"
      ;;
    '# relay-ip=CHANGE_ME_PRIVATE_OR_PUBLIC_IP')
      if [[ -n "$relay_ip" ]]; then printf 'relay-ip=%s\n' "$relay_ip" >> "$base_temporary"; fi
      ;;
    '# external-ip=CHANGE_ME_PUBLIC_IP/CHANGE_ME_PRIVATE_IP')
      printf 'external-ip=%s\n' "$external_ip" >> "$base_temporary"
      ;;
    total-quota=*) printf 'total-quota=%s\n' "$max_allocations" >> "$base_temporary" ;;
    bps-capacity=*) printf 'bps-capacity=%s\n' "$coturn_capacity_bps" >> "$base_temporary" ;;
    *) printf '%s\n' "$line" >> "$base_temporary" ;;
  esac
done < "$turn_config"
[[ "$tls_line_count" -eq 1 ]] || fail relay_install_tls_setting_invalid
if /usr/bin/grep -Ev '^[[:space:]]*(#|$)' "$base_temporary" | /usr/bin/grep -q CHANGE_ME; then
  fail relay_install_config_placeholder
fi
/usr/bin/chown root:root "$base_temporary"
/usr/bin/chmod 0600 "$base_temporary"
/usr/bin/mv -fT -- "$base_temporary" "$coturn_dir/turnserver.conf.base"
base_temporary=

/usr/local/libexec/mrd-coturn-render-config "$secret_dir/turn-rest-secret"
for private_file in \
  "$config_root/agent.json" "$secret_dir/turn-rest-secret" \
  "$secret_dir/enrollment-token" \
  "$secret_dir/trusted-ca.pem" \
  "$secret_dir/turnserver.generated.conf" "$tls_dir/fullchain.pem" "$tls_dir/privkey.pem" \
  "$coturn_dir/turnserver.conf.base"; do
  [[ "$(/usr/bin/stat -c '%U:%G:%a' -- "$private_file")" == root:root:600 ]] \
    || fail relay_install_private_file_mode_invalid
done

firewall_config_temporary="$(/usr/bin/mktemp --tmpdir="$config_root" .firewall.conf.XXXXXX)"
printf '%s\n' \
  "backend=$firewall_backend" \
  "tls_port=$tls_port" \
  'min_port=49160' \
  'max_port=49260' \
  "firewalld_zone=$firewalld_zone" > "$firewall_config_temporary"
/usr/bin/chown root:root "$firewall_config_temporary"
/usr/bin/chmod 0600 "$firewall_config_temporary"
/usr/bin/mv -fT -- "$firewall_config_temporary" "$firewall_config"

case "$firewall_backend" in
  nftables)
    firewall_temporary="$(/usr/bin/mktemp --tmpdir=/etc/nftables.d .mrd-relay.nft.XXXXXX)"
    /usr/bin/sed "s/CHANGE_ME_TLS_PORT/$tls_port/g" "$script_dir/mrd-relay.nft" > "$firewall_temporary"
    /usr/sbin/nft --check --file "$firewall_temporary" || fail relay_install_firewall_policy_invalid
    /usr/bin/chown root:root "$firewall_temporary"
    /usr/bin/chmod 0644 "$firewall_temporary"
    /usr/bin/mv -fT -- "$firewall_temporary" "$nft_destination"
    ;;
  firewalld)
    : # mrd-relay-firewall records only the rules it adds, so removal is reversible.
    ;;
  ufw)
    ufw_temporary="$(/usr/bin/mktemp --tmpdir=/etc/ufw/applications.d .mrd-relay.XXXXXX)"
    printf '%s\n' \
      '[MRD-Relay]' \
      'title=MRD TURN relay' \
      'description=Managed MRD TURN listeners and restricted relay range' \
      "ports=3478/tcp|3478/udp|$tls_port/tcp|49160:49260/tcp|49160:49260/udp" \
      > "$ufw_temporary"
    /usr/bin/chown root:root "$ufw_temporary"
    /usr/bin/chmod 0644 "$ufw_temporary"
    /usr/bin/mv -fT -- "$ufw_temporary" "$ufw_profile"
    ;;
  *) fail relay_install_firewall_backend_unknown ;;
esac

if [[ "$tls_port" == 443 ]]; then
  /usr/bin/install -d -o root -g root -m 0755 "${low_port_dropin%/*}"
  dropin_temporary="$(/usr/bin/mktemp --tmpdir="${low_port_dropin%/*}" .10-low-port.XXXXXX)"
  printf '%s\n' '[Service]' 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' \
    'AmbientCapabilities=CAP_NET_BIND_SERVICE' > "$dropin_temporary"
  /usr/bin/chown root:root "$dropin_temporary"
  /usr/bin/chmod 0644 "$dropin_temporary"
  /usr/bin/mv -fT -- "$dropin_temporary" "$low_port_dropin"
elif [[ -f "$low_port_dropin" && ! -L "$low_port_dropin" ]]; then
  /usr/bin/rm -f -- "$low_port_dropin"
fi

/usr/bin/install -o root -g root -m 0644 "$script_dir/mrd-relay-agent.service" /etc/systemd/system/mrd-relay-agent.service
/usr/bin/install -o root -g root -m 0644 "$script_dir/mrd-coturn.service" /etc/systemd/system/mrd-coturn.service
/usr/bin/install -o root -g root -m 0644 "$script_dir/mrd-relay-coturn-control.socket" /etc/systemd/system/mrd-relay-coturn-control.socket
/usr/bin/install -o root -g root -m 0644 "$script_dir/mrd-relay-coturn-control@.service" /etc/systemd/system/mrd-relay-coturn-control@.service
/usr/bin/install -o root -g root -m 0644 "$script_dir/mrd-relay-coturn-control.tmpfiles" /usr/lib/tmpfiles.d/mrd-relay-coturn-control.conf
/usr/bin/install -o root -g root -m 0644 "$script_dir/mrd-relay-firewall.service" /etc/systemd/system/mrd-relay-firewall.service
/usr/bin/install -d -o root -g root -m 0755 /usr/share/doc/mrd-relay-agent
/usr/bin/install -o root -g root -m 0644 "$deploy_dir/README.md" /usr/share/doc/mrd-relay-agent/README.md

/usr/bin/systemd-analyze verify \
  /etc/systemd/system/mrd-coturn.service \
  /etc/systemd/system/mrd-relay-coturn-control.socket \
  /etc/systemd/system/mrd-relay-coturn-control@.service \
  /etc/systemd/system/mrd-relay-firewall.service \
  /etc/systemd/system/mrd-relay-agent.service
/usr/bin/systemctl daemon-reload
/usr/bin/systemd-tmpfiles --create /usr/lib/tmpfiles.d/mrd-relay-coturn-control.conf
/usr/bin/systemctl enable --now mrd-relay-coturn-control.socket
if ! /usr/bin/systemctl enable --now mrd-relay-firewall.service; then
  fail relay_install_firewall_apply_failed
fi
/usr/local/libexec/mrd-relay-firewall verify || fail relay_install_firewall_verify_failed
/usr/bin/systemctl enable --now mrd-relay-agent.service

running_agent_pid="$(/usr/bin/systemctl show mrd-relay-agent.service --property=MainPID --value)"
[[ "$running_agent_pid" =~ ^[1-9][0-9]*$ ]] || fail relay_install_agent_main_pid_invalid
[[ "$(/usr/bin/readlink -f -- "/proc/$running_agent_pid/exe")" == /usr/local/bin/mrd-relay-agent ]] \
  || fail relay_install_agent_old_process_detected
installed_agent_hash="$(/usr/bin/sha256sum -- /usr/local/bin/mrd-relay-agent)"
running_agent_hash="$(/usr/bin/sha256sum -- "/proc/$running_agent_pid/exe")"
[[ "${installed_agent_hash%% *}" == "${running_agent_hash%% *}" ]] \
  || fail relay_install_agent_running_hash_mismatch
unset installed_agent_hash running_agent_hash running_agent_pid

# Enrollment and bootstrap apply-secret(1) are broker-owned. Fresh installs
# require the allocation/permission/relayed-packet preflight. Upgrades must
# remain drained: verify static state plus a fresh broker-authenticated zero-
# allocation proof bound to the pre-mutation generation/version fence.
verify_arguments=(--config "$config_root/agent.json")
if [[ "$existing_install" == true ]]; then
  IFS=$'\t' read -r expected_drain_target expected_drain_generation \
    expected_drain_secret_version unexpected_drain_field <<< "$second_drain_proof"
  [[ -z "${unexpected_drain_field:-}" && "$expected_drain_target" == linux-systemd \
    && "$expected_drain_generation" =~ ^[1-9][0-9]*$ \
    && "$expected_drain_secret_version" =~ ^[1-9][0-9]*$ ]] \
    || fail relay_install_drained_fence_parse_failed
  verify_arguments=(
    --drained
    --expected-target "$expected_drain_target"
    --expected-generation "$expected_drain_generation"
    --expected-secret-version "$expected_drain_secret_version"
    --config "$config_root/agent.json"
  )
fi
verified=false
for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if /usr/local/libexec/mrd-verify-relay-node "${verify_arguments[@]}"; then
    verified=true
    break
  fi
  /usr/bin/sleep 5
done
if [[ "$verified" != true ]]; then
  if [[ "$existing_install" == true ]]; then
    fail relay_install_drained_verification_failed
  fi
  fail relay_install_local_preflight_failed
fi

transaction_committed=true
if [[ "$existing_install" == true ]]; then
  printf '%s\n' "relay_install_complete_drained recovery_backup=$backup_dir"
else
  printf '%s\n' "relay_install_complete recovery_backup=$backup_dir"
fi
