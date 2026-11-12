#!/usr/bin/env bash
# The recovery disk: where merod --recovery-dir writes backups sealed to the key
# of whoever upgrades each app (core `calimero_node::recovery_disk`).
#
# What fails quietly without this test:
#   * the disk is found by "the one blank disk" fallback, which can be the data
#     disk, so backups land on it (or the data disk is formatted as a backup);
#   * a disk holding another filesystem is formatted, losing someone's backups;
#   * the disk is mounted with exec, or merod never learns the path;
#   * a job node, which holds no app data, mounts one;
#   * it is mounted inside the data disk or over a system path.
#
# Usage: scripts/ci/tests/calimero-init-recovery-disk-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"
body="$(cat "$TEMPLATE")"
start=$(grep -nF '# --- The recovery disk' <<<"$body" | head -1 | cut -d: -f1)
end=$(grep -nF '# --- TLS material for traefik' <<<"$body" | head -1 | cut -d: -f1)
[[ -n "$start" && -n "$end" ]] || fail "could not locate the recovery disk block"
block="$(sed -n "${start},${end}p" <<<"$body")"
code="$(grep -vE '^[[:space:]]*#' <<<"$block")"

grep -qF 'RECOVERY_DEVICE="/dev/disk/by-id/google-recovery"' <<<"$code" \
  || fail "the recovery disk must be addressed by its by-id link (deviceName \"recovery\")"
grep -qE 'nvme|/dev/sd|DATA_DEVICE' <<<"$code" \
  && fail "the recovery block must not probe devices or touch the data disk's device"
grep -qF 'mount -t ext4 -o nosuid,nodev,noexec' <<<"$code" \
  || fail "the recovery disk must be mounted nosuid,nodev,noexec"
grep -qF '!= ext4 ]]' <<<"$code" \
  || fail "a disk holding another filesystem must be refused, never formatted"
grep -qF 'lsblk -nro NAME' <<<"$code" \
  || fail "a disk with partitions must not count as blank"
grep -qF 'MEROD_RECOVERY_DIR=' <<<"$code" \
  || fail "merod must learn the path (MEROD_RECOVERY_DIR in merod.env)"
grep -qF 'JOB_NODE:-}" != true' <<<"$code" \
  || fail "a job node must refuse recovery-dir"
grep -qF '"$DATA_MOUNT"|"$DATA_MOUNT"/*' <<<"$code" \
  || fail "the mount point must not be inside the data disk"

# It runs after the data disk is settled, so that disk's own checks see it first.
data_check=$(grep -nF 'keeps node state only on an encrypted data disk' <<<"$body" | head -1 | cut -d: -f1)
(( data_check < start )) || fail "the recovery block must come after the data disk checks"

# The env file it appends to is written (truncated) before it, every boot.
env_write=$(grep -nF '} > /etc/calimero/merod.env' <<<"$body" | head -1 | cut -d: -f1)
(( env_write < start )) || fail "merod.env must be written before the recovery block appends to it"

echo "OK: calimero-init mounts the recovery disk safely and hands merod its path"
