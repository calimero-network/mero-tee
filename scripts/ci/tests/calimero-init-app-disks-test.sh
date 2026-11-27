#!/usr/bin/env bash
# The recovery and backup disks: where merod --recovery-dir writes backups
# sealed to the key of whoever upgrades each app (core
# `calimero_node::recovery_disk`), and merod --backup-dir writes app snapshots
# sealed under the cluster key (core `calimero_node::backup`).
#
# What fails quietly without this test:
#   * a disk is found by "the one blank disk" fallback, which can be the data
#     disk, so backups land on it (or the data disk is formatted as a backup);
#   * a disk holding another filesystem is formatted, losing someone's backups;
#   * a disk is mounted with exec, or merod never learns the path;
#   * a job node, which holds no app data, mounts one;
#   * it is mounted inside the data disk or over a system path.
#
# Usage: scripts/ci/tests/calimero-init-app-disks-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"
body="$(cat "$TEMPLATE")"
start=$(grep -nF '# --- The recovery and backup disks' <<<"$body" | head -1 | cut -d: -f1 || true)
end=$(grep -nF '# --- merod 1.0: storage key' <<<"$body" | head -1 | cut -d: -f1 || true)
[[ -n "$start" && -n "$end" ]] || fail "could not locate the recovery and backup disks block"
block="$(sed -n "${start},${end}p" <<<"$body")"
code="$(grep -vE '^[[:space:]]*#' <<<"$block")"
fn="$(sed -n '/^mount_app_disk() {$/,/^}$/p' <<<"$code")"
[[ -n "$fn" ]] || fail "the disks must be mounted by one function, mount_app_disk"

grep -qF 'device="/dev/disk/by-id/google-$name"' <<<"$fn" \
  || fail "a disk must be addressed by its by-id link (its deviceName)"
grep -qE 'nvme|/dev/sd|DATA_DEVICE' <<<"$code" \
  && fail "the disks block must not probe devices or touch the data disk's device"
grep -qF 'mount -t ext4 -o nosuid,nodev,noexec' <<<"$fn" \
  || fail "a disk must be mounted nosuid,nodev,noexec"
grep -qF '!= ext4 ]]' <<<"$fn" \
  || fail "a disk holding another filesystem must be refused, never formatted"
grep -qF 'lsblk -nro NAME' <<<"$fn" \
  || fail "a disk with partitions must not count as blank"
grep -qF 'JOB_NODE:-}" != true' <<<"$fn" \
  || fail "a job node must refuse a disk"
grep -qF '"$DATA_MOUNT"|"$DATA_MOUNT"/*' <<<"$fn" \
  || fail "the mount point must not be inside the data disk"

# Each disk: its metadata key, its deviceName, and the variable merod reads.
for disk in recovery:RECOVERY backup:BACKUP; do
  name="${disk%%:*}" var="${disk##*:}"
  grep -qF "${var}_DIR=\"\$(get_meta ${name}-dir | tr -d '\\r\\n')\"" <<<"$code" \
    || fail "the $name disk must be driven by '${name}-dir' metadata"
  grep -qE "^  mount_app_disk ${name} \"\\\$${var}_DIR\" " <<<"$code" \
    || fail "the $name disk must be mounted by mount_app_disk as deviceName '$name'"
  grep -qF "MEROD_${var}_DIR=" <<<"$code" \
    || fail "merod must learn the $name path (MEROD_${var}_DIR in merod.env)"
done

# Both on one mount point would put the backups on the recovery disk.
grep -qF '[[ "$BACKUP_DIR" != "$RECOVERY_DIR" ]]' <<<"$code" \
  || fail "backup-dir and recovery-dir must be refused when they are the same"

# It runs after the data disk is settled, so that disk's own checks see it first.
data_check=$(grep -nF 'keeps node state only on an encrypted data disk' <<<"$body" | head -1 | cut -d: -f1)
(( data_check < start )) || fail "the disks block must come after the data disk checks"

# The env file it appends to is written (truncated) before it, every boot.
env_write=$(grep -nF '} > /etc/calimero/merod.env' <<<"$body" | head -1 | cut -d: -f1)
(( env_write < start )) || fail "merod.env must be written before the disks block appends to it"

echo "OK: calimero-init mounts the recovery and backup disks safely and hands merod their paths"
