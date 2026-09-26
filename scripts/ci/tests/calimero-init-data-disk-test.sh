#!/usr/bin/env bash
# The data disk must be mounted before merod initialises into it.
#
# Every node is created with a separate data disk and nothing mounted it:
# `merod` initialised into `/mnt/data/calimero`, a directory on the ~19 GB root
# filesystem, while the console advertised 200 GB. When root fills it takes
# merod, traefik, mero-auth, vector and vmagent with it, on a machine with no
# shell to recover from.
#
# The logic could not live in a GCP startup script: `merod-lockdown` blocks
# those on `locked-read-only` (R5), and nothing attached one anyway. So it is in
# `calimero-init`, and this checks the four states it has to tell apart.
#
# What fails quietly without this test:
#   * mounting over a pre-existing `/mnt/data` on an upgraded node, hiding its
#     state so merod initialises a FRESH identity -- peer id, account, keys;
#   * reformatting a disk that already holds the node's state;
#   * a disk that is present but will not mount being silently ignored, so the
#     node writes to root and nobody learns until root is full;
#   * probing `/dev/nvme0n2` instead of the stable by-id path.
#
# Usage: scripts/ci/tests/calimero-init-data-disk-test.sh
# Single quotes throughout the greps below are deliberate: they are the LITERAL
# strings to find in the template, `$DATA_MOUNT` and all. Expanding them would
# search for the value of a variable this script does not have.
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

body="$(cat "$TEMPLATE")"
# Comments stripped for the negative checks below. The template EXPLAINS why it
# does not probe /dev/nvme0n2, and matching that prose would fail the very file
# that gets it right.
code="$(grep -vE '^[[:space:]]*#' <<<"$body")"

# --- the device is addressed stably ----------------------------------------
grep -qF '/dev/disk/by-id/google-data' <<<"$body" \
  || fail "the data disk must be addressed by its GCP deviceName
       (/dev/disk/by-id/google-data), not by probing an NVMe enumeration order.
       mdma attaches it as device_name=\"data\"; the by-id path is stable and
       /dev/nvme0n2 is not."
grep -qE '/dev/nvme0n2|/dev/sdb' <<<"$code" \
  && fail "device-name probing reintroduced; use the by-id path"

# --- it runs BEFORE anything writes into the mount point --------------------
mount_line=$(grep -nF 'mountpoint -q "$DATA_MOUNT"' <<<"$body" | head -1 | cut -d: -f1)
home_line=$(grep -nF 'mkdir -p "$CALIMERO_HOME"' <<<"$body" | head -1 | cut -d: -f1)
tls_line=$(grep -nF 'TLS_DIR="/mnt/data/tls"' <<<"$body" | head -1 | cut -d: -f1)
[[ -n "$mount_line" && -n "$home_line" && -n "$tls_line" ]] \
  || fail "could not locate the mount block, CALIMERO_HOME or TLS_DIR; this test slices on them"
(( mount_line < home_line )) \
  || fail "the mount runs at line ${mount_line}, after CALIMERO_HOME is created at ${home_line}:
       merod would initialise onto the root filesystem and the mount would then
       hide it"
(( mount_line < tls_line )) \
  || fail "the mount runs after the TLS key directory is set (${tls_line}); the
       node's TLS identity would land on root"

# --- a pre-existing /mnt/data is never mounted over -------------------------
grep -qF 'ls -A "$DATA_MOUNT"' <<<"$body" \
  || fail "nothing checks whether /mnt/data already holds data. On a node that
       predates this change its state IS there, on root; mounting the empty disk
       over it hides that state and merod initialises a fresh identity."

# --- the disk is never reformatted once it holds state ----------------------
# Gated on `blkid -p` (a probe of the device itself, not the cache) reporting
# its explicit "nothing found" status. The behaviour -- including the encrypted
# path and every signature that must NOT be formatted -- is executed in
# calimero-init-disk-encryption-test.sh; this only pins the shape.
grep -qF 'blkid -p -o export' <<<"$body" \
  || fail "mkfs must be gated on the device having NO filesystem; an
       unconditional mkfs on a later boot is a wipe"
grep -qF 'if [[ "$DATA_SIG_RC" == 2 ]]; then' <<<"$body" \
  || fail "formatting must key on blkid's explicit no-signature status (2); a
       probe that failed is not a blank disk"

# --- a present-but-unmountable disk is fatal, not ignored -------------------
awk '/could not be mounted at/,/^fi$/' <<<"$body" | grep -qF 'exit 1' \
  || fail "a data disk that exists and will not mount must stop the boot.
       Continuing writes the node's state to root and nobody learns until root
       is full -- which is the bug this fixes. calimero-init's journal ships, so
       a node that stops here can say why."

# --- it survives a reboot ---------------------------------------------------
grep -qF '/etc/fstab' <<<"$body" || fail "the mount is not persisted to /etc/fstab"
grep -qF 'nofail' <<<"$body" \
  || fail "the fstab entry must be nofail: without it a missing disk drops the
       boot into emergency mode, which on a shell-less machine is
       indistinguishable from a brick"

echo "PASS: the data disk is mounted before use, never reformatted, and never mounted over existing state"
