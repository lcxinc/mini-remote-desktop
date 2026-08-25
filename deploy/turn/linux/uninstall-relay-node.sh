#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

archive_root=/var/backups/mrd-relay-agent/removals
agent_was_active=false
agent_stop_attempted=false
drain_fence_confirmed=false

fail() {
  printf '%s\n' "${1:-relay_uninstall_failed}" >&2
  exit 1
}

path_is_equal_or_descendant() {
  local candidate=$1 root=$2
  [[ "$candidate" == "$root" || "$candidate" == "$root/"* ]]
}

paths_intersect() {
  local first=$1 second=$2
  path_is_equal_or_descendant "$first" "$second" || \
    path_is_equal_or_descendant "$second" "$first"
}

assert_archive_root_isolated() {
  local candidate=$1 managed
  local -a managed_roots=(
    /etc/mrd-relay-agent
    /var/lib/mrd-relay-agent
    /var/lib/mrd-coturn
    /usr/local/bin
    /usr/local/libexec
    /etc/systemd/system
    /usr/lib/tmpfiles.d
    /etc/nftables.d
    /etc/ufw/applications.d
    /usr/share/doc/mrd-relay-agent
  )
  for managed in "${managed_roots[@]}"; do
    if paths_intersect "$candidate" "$managed"; then
      fail relay_uninstall_archive_root_overlaps_managed_path
    fi
  done
}

self_test_archive_root_isolation() {
  assert_archive_root_isolated /var/backups/mrd-relay-agent/removals
  if (assert_archive_root_isolated /etc/mrd-relay-agent/removals) 2>/dev/null; then
    fail relay_uninstall_self_test_self_archive_accepted
  fi
  if (assert_archive_root_isolated /etc) 2>/dev/null; then
    fail relay_uninstall_self_test_managed_descendant_accepted
  fi
  if (assert_archive_root_isolated /var/lib/mrd-coturn) 2>/dev/null; then
    fail relay_uninstall_self_test_equal_managed_root_accepted
  fi
  assert_archive_root_isolated /usr/local/libexec-backup \
    || fail relay_uninstall_self_test_component_prefix_rejected

  local script_source
  script_source="$(<"${BASH_SOURCE[0]}")"
  [[ "$script_source" == *'agent_stop_attempted=true'* ]] \
    || fail relay_uninstall_self_test_agent_stop_not_journaled
  [[ "$script_source" == *'drain_fence_confirmed=true'* ]] \
    || fail relay_uninstall_self_test_drain_fence_not_committed
  [[ "$script_source" == *'relay_uninstall_early_agent_restore_failed'* ]] \
    || fail relay_uninstall_self_test_early_agent_restore_missing
}

if [[ "$#" -eq 1 && "$1" == --self-test ]]; then
  self_test_archive_root_isolation
  printf '%s\n' relay_uninstall_self_test_passed
  exit 0
elif [[ "$#" -eq 2 && "$1" == --archive-root ]]; then
  archive_root=$2
elif [[ "$#" -ne 0 ]]; then
  printf '%s\n' 'usage: uninstall-relay-node.sh [--archive-root ABSOLUTE_PATH] [--self-test]' >&2
  exit 64
fi

[[ "${EUID}" -eq 0 ]] || fail relay_uninstall_requires_root
[[ -x /usr/bin/flock ]] || fail relay_uninstall_deploy_lock_unavailable
exec 8> /run/lock/mrd-relay-deploy.lock
/usr/bin/flock --exclusive --nonblock 8 || fail relay_uninstall_deploy_lock_busy
[[ "$archive_root" == /* && "$archive_root" != / && ! -L "$archive_root" ]] \
  || fail relay_uninstall_invalid_archive_root
canonical_archive_root="$(/usr/bin/realpath -m -- "$archive_root")" \
  || fail relay_uninstall_invalid_archive_root
[[ "$canonical_archive_root" == "$archive_root" ]] || fail relay_uninstall_symlink_ancestor_rejected
assert_archive_root_isolated "$canonical_archive_root"

assert_trusted_ancestors() {
  local current=$1
  while [[ "$current" != / ]]; do
    if [[ -e "$current" ]]; then
      [[ ! -L "$current" ]] || fail relay_uninstall_symlink_ancestor_rejected
      [[ "$(/usr/bin/stat -c '%u' -- "$current")" == 0 ]] \
        || fail relay_uninstall_owner_invalid
      local mode
      mode="$(/usr/bin/stat -c '%a' -- "$current")"
      (( (8#$mode & 0022) == 0 )) || fail relay_uninstall_mode_invalid
    fi
    current="${current%/*}"
    [[ -n "$current" ]] || current=/
  done
}
assert_trusted_ancestors "$archive_root"

for installed_path in \
  /usr/local/bin/mrd-relay-agent \
  /usr/local/libexec/mrd-relay-drain-proof \
  /usr/local/libexec/mrd-validate-drain-proof \
  /etc/mrd-relay-agent/agent.json; do
  [[ -f "$installed_path" && ! -L "$installed_path" ]] \
    || fail relay_uninstall_drain_proof_dependency_missing
  assert_trusted_ancestors "$installed_path"
done
[[ "$(/usr/bin/stat -c '%U:%G:%a' -- /usr/local/libexec/mrd-relay-drain-proof)" == root:root:755 ]] \
  || fail relay_uninstall_drain_proof_helper_mode_invalid
[[ "$(/usr/bin/stat -c '%U:%G:%a' -- /usr/local/libexec/mrd-validate-drain-proof)" == root:root:755 ]] \
  || fail relay_uninstall_drain_proof_validator_mode_invalid
first_drain_proof="$(/usr/local/libexec/mrd-relay-drain-proof --config /etc/mrd-relay-agent/agent.json)" \
  || fail relay_uninstall_first_drain_proof_failed

assert_same_drain_fence() {
  local first=$1
  local second=$2
  [[ "$first" =~ ^linux-systemd$'\t'[1-9][0-9]*$'\t'[1-9][0-9]*$ ]] \
    || fail relay_uninstall_first_drain_fence_invalid
  [[ "$second" == "$first" ]] || fail relay_uninstall_drain_fence_changed
}

restore_early_agent_state_on_exit() {
  local status=$?
  trap - EXIT
  if [[ "$status" -ne 0 && "$agent_stop_attempted" == true \
    && "$drain_fence_confirmed" != true && "$agent_was_active" == true ]]; then
    if ! /usr/bin/systemctl is-active --quiet mrd-relay-agent.service; then
      /usr/bin/systemctl start mrd-relay-agent.service \
        || printf '%s\n' relay_uninstall_early_agent_restore_failed >&2
    fi
  fi
  exit "$status"
}
trap restore_early_agent_state_on_exit EXIT

/usr/bin/install -d -o root -g root -m 0700 "$archive_root"
archive_dir="$archive_root/uninstall-$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)-$$"
[[ ! -e "$archive_dir" ]] || fail relay_uninstall_archive_exists
/usr/bin/install -d -o root -g root -m 0700 "$archive_dir"

if /usr/bin/systemctl is-active --quiet mrd-relay-agent.service; then
  agent_was_active=true
fi
agent_stop_attempted=true
/usr/bin/systemctl stop mrd-relay-agent.service \
  || fail relay_uninstall_agent_stop_failed
second_drain_proof="$(/usr/local/libexec/mrd-relay-drain-proof --config /etc/mrd-relay-agent/agent.json)" \
  || fail relay_uninstall_second_drain_proof_failed
assert_same_drain_fence "$first_drain_proof" "$second_drain_proof"
drain_fence_confirmed=true
/usr/bin/systemctl disable mrd-relay-agent.service 2>/dev/null || true
/usr/bin/systemctl disable --now mrd-relay-coturn-control.socket 2>/dev/null || true
mapfile -t control_instances < <(
  /usr/bin/systemctl list-units --all --plain --no-legend 'mrd-relay-coturn-control@*.service' \
    | /usr/bin/awk '{print $1}'
)
for unit in "${control_instances[@]}"; do
  [[ "$unit" =~ ^mrd-relay-coturn-control@[A-Za-z0-9_.:@-]+\.service$ ]] \
    || fail relay_uninstall_control_instance_invalid
  /usr/bin/systemctl stop "$unit"
done
/usr/bin/systemctl stop mrd-coturn.service || fail relay_uninstall_coturn_stop_failed
/usr/local/libexec/mrd-relay-firewall verify || fail relay_uninstall_firewall_ownership_invalid
/usr/bin/systemctl stop mrd-relay-firewall.service || fail relay_uninstall_firewall_stop_failed
/usr/local/libexec/mrd-relay-firewall remove || fail relay_uninstall_firewall_remove_failed
/usr/bin/systemctl disable mrd-relay-firewall.service || fail relay_uninstall_firewall_disable_failed

archive_path() {
  local source=$1
  local name=$2
  if [[ -e "$source" ]]; then
    [[ ! -L "$source" ]] || fail relay_uninstall_reparse_target_rejected
    /usr/bin/mv -- "$source" "$archive_dir/$name"
  fi
}

archive_path /etc/mrd-relay-agent etc-mrd-relay-agent
archive_path /var/lib/mrd-relay-agent var-lib-mrd-relay-agent
archive_path /var/lib/mrd-coturn var-lib-mrd-coturn
archive_path /usr/local/bin/mrd-relay-agent mrd-relay-agent
archive_path /usr/local/libexec/mrd-relay-coturn-control mrd-relay-coturn-control
archive_path /usr/local/libexec/mrd-coturn-render-config mrd-coturn-render-config
archive_path /usr/local/libexec/mrd-relay-firewall mrd-relay-firewall
archive_path /usr/local/libexec/mrd-verify-relay-node mrd-verify-relay-node
archive_path /usr/local/libexec/mrd-relay-drain-proof mrd-relay-drain-proof
archive_path /usr/local/libexec/mrd-validate-drain-proof mrd-validate-drain-proof
archive_path /etc/systemd/system/mrd-relay-agent.service mrd-relay-agent.service
archive_path /etc/systemd/system/mrd-coturn.service mrd-coturn.service
archive_path /etc/systemd/system/mrd-relay-coturn-control.socket mrd-relay-coturn-control.socket
archive_path /etc/systemd/system/mrd-relay-coturn-control@.service mrd-relay-coturn-control@.service
archive_path /etc/systemd/system/mrd-relay-firewall.service mrd-relay-firewall.service
archive_path /etc/systemd/system/mrd-coturn.service.d/10-low-port.conf 10-low-port.conf
archive_path /usr/lib/tmpfiles.d/mrd-relay-coturn-control.conf mrd-relay-coturn-control.conf
archive_path /etc/nftables.d/mrd-relay.nft mrd-relay.nft
archive_path /etc/ufw/applications.d/mrd-relay ufw-mrd-relay
archive_path /usr/share/doc/mrd-relay-agent mrd-relay-documentation

/usr/bin/systemctl daemon-reload
if [[ -d /run/mrd-relay-coturn-control && ! -L /run/mrd-relay-coturn-control ]]; then
  /usr/bin/rmdir -- /run/mrd-relay-coturn-control 2>/dev/null || true
fi

printf '%s\n' "relay_uninstall_archived recovery_path=$archive_dir"
