#!/usr/bin/env bash
# agent-init extends RTMR3 with `calimero-rtmr3-v2:agent:<profile>:<root_hash>`,
# and an unextended RTMR3 stops a locked-read-only boot.
#
# The role string is the whole difference between an agent quote and a node
# quote in RTMR3: mero-kms releases an agent key only to a quote matching its
# agent policy entry, and that entry's RTMR3 is this extend. A typo here
# ("agnet", the KMS's "kms", a node's "node") builds an image whose RTMR3
# matches no entry, or the wrong one. So this EXECUTES the RTMR3 block against
# a fake sysfs file and checks the 48 bytes written are SHA-384 of exactly that
# string. What it pins:
#
#   * the extend is SHA-384("calimero-rtmr3-v2:agent:<profile>:<root_hash>")
#     with the root hash from the kernel command line, and nothing else
#   * the image role in the template is "agent"
#   * locked-read-only: no writable RTMR3, or a failed write -> the boot stops
#   * the debug profiles: the same -> a warning, the boot goes on
#   * the RTMR3 block runs before metadata is read or the disk is touched
#
# Usage: scripts/ci/tests/agent-init-rtmr3-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/mero-agent/templates/agent-init.sh.j2"
KMS_TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/mero-kms/templates/kms-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"
command -v openssl >/dev/null || fail "openssl is required"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

grep -qxF 'IMAGE_ROLE="agent"' "$TEMPLATE" || fail 'agent-init must set IMAGE_ROLE="agent"'
grep -qxF 'IMAGE_PROFILE="{{ lockdown_profile }}"' "$TEMPLATE" || fail "agent-init must take its profile from the build"

# The extend line is the KMS's, byte for byte, so the two images name
# themselves the same way and differ only in the role.
extend_line="printf 'calimero-rtmr3-v2:%s:%s:%s' \"\$IMAGE_ROLE\" \"\$IMAGE_PROFILE\" \"\$ROOT_HASH\" \\"
grep -qF -- "$extend_line" "$TEMPLATE" || fail "the RTMR3 extend string changed shape"
grep -qF -- "$extend_line" "$KMS_TEMPLATE" || fail "kms-init's RTMR3 extend changed; keep agent-init's in step"

line_of() { grep -nF -- "$1" "$TEMPLATE" | head -1 | cut -d: -f1; }
rtmr3_line="$(line_of '# --- RTMR3')"
for later in 'KMS_URL="$(get_meta kms-url' '# --- The data disk' 'get_meta logs-endpoint'; do
  at="$(line_of "$later")"
  [[ -n "$at" ]] || fail "could not find '$later'"
  (( rtmr3_line < at )) || fail "'$later' runs before RTMR3 is extended"
done

block="$(awk '/^# --- RTMR3/{on=1} /^# --- Observability/{exit} on{print}' "$TEMPLATE")"
[[ -n "$block" ]] || fail "could not find '# --- RTMR3' .. '# --- Observability'"

ROOT_HASH="5f2d0c1e9a8b7c6d5e4f30211203f4e5d6c7b8a9908172635445362718090a1b"

# run NAME PROFILE SYSFS(writable|readonly|absent) [SYSFS_DIR]
run() {
  local name="$1" profile="$2" sysfs="$3" dir="${4:-measurements}"
  local T="$WORK/$name"
  mkdir -p "$T/bin" "$T/sys/$dir"
  printf 'BOOT_IMAGE=/vmlinuz root=/dev/dm-0 calimero.role=agent calimero.root_hash=%s quiet\n' "$ROOT_HASH" >"$T/cmdline"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$T/bin/modprobe"
  chmod +x "$T/bin/modprobe"
  case "$sysfs" in
    writable) : >"$T/sys/$dir/rtmr3:sha384" ;;
    readonly) : >"$T/sys/$dir/rtmr3:sha384"; chmod 0444 "$T/sys/$dir/rtmr3:sha384" ;;
    absent) ;;
  esac
  local body
  body="$(sed \
    -e "s@/sys/class/misc/tdx_guest@$T/sys@g" \
    -e "s@/proc/cmdline@$T/cmdline@g" \
    <<<"$block")"
  cat >"$T/run.sh" <<RUN
set -euo pipefail
PATH="$T/bin:\$PATH"
IMAGE_PROFILE="$profile"
IMAGE_ROLE="agent"
log() { echo "\$*" >>"$T/log"; }
fatal() { log "ERROR: \$*"; exit 1; }
$body
RUN
  set +e
  bash "$T/run.sh" >/dev/null 2>&1
  echo $? >"$T/rc"
  set -e
}

expected_hex() {
  printf 'calimero-rtmr3-v2:%s:%s:%s' "$1" "$2" "$ROOT_HASH" | openssl dgst -sha384 -binary | od -An -tx1 | tr -d ' \n'
}
written_hex() { od -An -tx1 "$WORK/$1/sys/${2:-measurements}/rtmr3:sha384" | tr -d ' \n'; }
rc() { cat "$WORK/$1/rc"; }

# --- the extend --------------------------------------------------------------
run locked locked-read-only writable
[[ "$(rc locked)" == 0 ]] || fail "a writable RTMR3 must be extended (rc=$(rc locked)): $(cat "$WORK/locked/log")"
[[ "$(written_hex locked)" == "$(expected_hex agent locked-read-only)" ]] \
  || fail "RTMR3 was extended with something other than SHA-384('calimero-rtmr3-v2:agent:locked-read-only:<root_hash>')"
[[ "$(written_hex locked)" != "$(expected_hex node locked-read-only)" ]] || fail "the agent extends as a node"
[[ "$(written_hex locked)" != "$(expected_hex kms locked-read-only)" ]] || fail "the agent extends as the KMS"
[[ "$(wc -c <"$WORK/locked/sys/measurements/rtmr3:sha384" | tr -d ' ')" == 48 ]] || fail "the extend must be exactly 48 bytes"

# Older kernels expose the register under mr/.
run older-kernel debug writable mr
[[ "$(rc older-kernel)" == 0 ]] || fail "the mr/ sysfs path must be used where measurements/ is absent"
[[ "$(written_hex older-kernel mr)" == "$(expected_hex agent debug)" ]] || fail "the extend under mr/ is wrong"

# --- no RTMR3: fatal when locked, a warning otherwise ------------------------
run locked-absent locked-read-only absent
[[ "$(rc locked-absent)" != 0 ]] || fail "locked-read-only must stop when RTMR3 cannot be extended"
grep -qF 'RTMR3 not extended' "$WORK/locked-absent/log" || fail "the refusal must say RTMR3 was not extended"

if [[ "$(id -u)" != 0 ]]; then
  run locked-readonly locked-read-only readonly
  [[ "$(rc locked-readonly)" != 0 ]] || fail "locked-read-only must stop when RTMR3 is not writable"
fi

run debug-absent debug-read-only absent
[[ "$(rc debug-absent)" == 0 ]] || fail "a debug profile must boot on without RTMR3"
grep -qF 'WARN: RTMR3 not extended' "$WORK/debug-absent/log" || fail "a debug profile must warn that RTMR3 was not extended"

echo "agent-init RTMR3: OK"
