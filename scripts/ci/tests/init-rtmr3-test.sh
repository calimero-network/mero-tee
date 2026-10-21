#!/usr/bin/env bash
# calimero-init (node), kms-init, agent-init and inference-init extend RTMR3 with
# SHA-384("calimero-rtmr3-v3:<role>:<profile>:<roothash>"), <roothash> being the
# dm-verity root hash on the kernel command line, and an unextended RTMR3 stops
# a locked-read-only boot.
#
# RTMR3 is what a KMS policy entry pins for each role: a node, a KMS and an
# agent quote differ there and nowhere else the image controls at runtime. A
# typo in the role or the format string builds an image whose RTMR3 matches no
# entry, or the wrong one. So this EXECUTES each template's RTMR3 block against
# a fake sysfs file and a fake /proc/cmdline, and checks the 48 bytes written
# are SHA-384 of exactly that string. What it pins:
#
#   * the three templates carry the same block, byte for byte, between the
#     `# rtmr3-v3 begin` and `# rtmr3-v3 end` markers;
#   * each template sets its own role (node, kms, agent) and takes its profile
#     from the build;
#   * the extend is SHA-384("calimero-rtmr3-v3:<role>:<profile>:<roothash>")
#     with `roothash=` from the command line -- not `calimero.root_hash=`;
#   * locked-read-only: no roothash=, no writable RTMR3, or a failed write
#     stops the boot; the debug profiles warn and go on;
#   * the block runs before the script reads instance metadata.
#
# Usage: scripts/ci/tests/init-rtmr3-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLES="${REPO_ROOT}/mero-tee/ansible/roles"
declare -A TEMPLATES=(
  [node]="${ROLES}/merotee/templates/calimero-init.sh.j2"
  [kms]="${ROLES}/mero-kms/templates/kms-init.sh.j2"
  [agent]="${ROLES}/mero-agent/templates/agent-init.sh.j2"
  [inference]="${ROLES}/mero-inference/templates/inference-init.sh.j2"
)

fail() { echo "FAIL: $*" >&2; exit 1; }
command -v openssl >/dev/null || fail "openssl is required"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

block_of() { awk '/^# rtmr3-v3 begin/{on=1} on{print} /^# rtmr3-v3 end/{exit}' "$1"; }

reference=""
for role in node kms agent inference; do
  template="${TEMPLATES[$role]}"
  [[ -r "$template" ]] || fail "cannot read ${template}"
  grep -qxF "IMAGE_ROLE=\"${role}\"" "$template" || fail "$(basename "$template") must set IMAGE_ROLE=\"${role}\""
  grep -qxF 'IMAGE_PROFILE="{{ lockdown_profile }}"' "$template" \
    || fail "$(basename "$template") must take its profile from the build"
  block="$(block_of "$template")"
  [[ "$block" == *"# rtmr3-v3 end"* ]] || fail "$(basename "$template") has no complete rtmr3-v3 block"
  if [[ -z "$reference" ]]; then
    reference="$block"
  elif [[ "$block" != "$reference" ]]; then
    fail "$(basename "$template")'s RTMR3 block differs from calimero-init's; keep them in step"
  fi
  grep -q 'calimero-rtmr3-v2' "$template" && fail "$(basename "$template") still extends the v2 string"

  # Before any instance metadata is read: a boot that stops later still has
  # its image named in RTMR3.
  begin="$(grep -n '^# rtmr3-v3 begin' "$template" | cut -d: -f1)"
  first_meta="$(grep -nE 'get_meta [a-z"$]' "$template" | grep -v '^[0-9]*:get_meta()' | head -1 | cut -d: -f1)"
  [[ -n "$first_meta" ]] || fail "$(basename "$template"): no metadata read found"
  (( begin < first_meta )) || fail "$(basename "$template") reads metadata (line $first_meta) before extending RTMR3"
done

ROOT_HASH="5f2d0c1e9a8b7c6d5e4f30211203f4e5d6c7b8a9908172635445362718090a1b"
OLD_HASH="0000000000000000000000000000000000000000000000000000000000000001"

# run NAME ROLE PROFILE SYSFS(writable|readonly|absent) CMDLINE [SYSFS_DIR]
run() {
  local name="$1" role="$2" profile="$3" sysfs="$4" cmdline="$5" dir="${6:-measurements}"
  local T="$WORK/$name"
  mkdir -p "$T/bin" "$T/sys/$dir"
  printf '%s\n' "$cmdline" >"$T/cmdline"
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
    <<<"$(block_of "${TEMPLATES[$role]}")")"
  cat >"$T/run.sh" <<RUN
set -euo pipefail
PATH="$T/bin:\$PATH"
IMAGE_PROFILE="$profile"
IMAGE_ROLE="$role"
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
  printf 'calimero-rtmr3-v3:%s:%s:%s' "$1" "$2" "$3" | openssl dgst -sha384 -binary | od -An -tx1 | tr -d ' \n'
}
written_hex() { od -An -tx1 "$WORK/$1/sys/${2:-measurements}/rtmr3:sha384" | tr -d ' \n'; }
rc() { cat "$WORK/$1/rc"; }

# Both hashes on the line, as on a Packer image: only roothash= counts.
SEALED="BOOT_IMAGE=/vmlinuz root=/dev/mapper/root ro roothash=${ROOT_HASH} calimero.root_hash=${OLD_HASH} quiet"
UNSEALED="BOOT_IMAGE=/vmlinuz root=/dev/sda1 calimero.root_hash=${OLD_HASH} quiet"

for role in node kms agent inference; do
  # --- the extend ------------------------------------------------------------
  run "$role-locked" "$role" locked-read-only writable "$SEALED"
  [[ "$(rc "$role-locked")" == 0 ]] || fail "$role: a writable RTMR3 must be extended: $(cat "$WORK/$role-locked/log")"
  [[ "$(written_hex "$role-locked")" == "$(expected_hex "$role" locked-read-only "$ROOT_HASH")" ]] \
    || fail "$role: RTMR3 was extended with something other than SHA-384('calimero-rtmr3-v3:$role:locked-read-only:<roothash>')"
  for other in node kms agent inference; do
    [[ "$other" == "$role" ]] && continue
    [[ "$(written_hex "$role-locked")" != "$(expected_hex "$other" locked-read-only "$ROOT_HASH")" ]] \
      || fail "$role extends as $other"
  done
  [[ "$(written_hex "$role-locked")" != "$(expected_hex "$role" locked-read-only "$OLD_HASH")" ]] \
    || fail "$role: the extend used calimero.root_hash instead of the verity roothash"
  [[ "$(wc -c <"$WORK/$role-locked/sys/measurements/rtmr3:sha384" | tr -d ' ')" == 48 ]] \
    || fail "$role: the extend must be exactly 48 bytes"

  # roothash= last on the line, and older kernels' mr/ path.
  run "$role-older" "$role" debug writable "quiet calimero.role=$role roothash=${ROOT_HASH}" mr
  [[ "$(rc "$role-older")" == 0 ]] || fail "$role: the mr/ sysfs path must be used where measurements/ is absent"
  [[ "$(written_hex "$role-older" mr)" == "$(expected_hex "$role" debug "$ROOT_HASH")" ]] \
    || fail "$role: the extend under mr/ (roothash= last on the line) is wrong"

  # --- not extended: fatal when locked, a warning otherwise --------------------
  run "$role-unsealed" "$role" locked-read-only writable "$UNSEALED"
  [[ "$(rc "$role-unsealed")" != 0 ]] || fail "$role: locked-read-only must stop without a roothash="
  grep -qF 'no dm-verity roothash=' "$WORK/$role-unsealed/log" || fail "$role: the refusal must name the missing roothash="
  [[ ! -s "$WORK/$role-unsealed/sys/measurements/rtmr3:sha384" ]] || fail "$role: nothing may be extended without a roothash="

  run "$role-absent" "$role" locked-read-only absent "$SEALED"
  [[ "$(rc "$role-absent")" != 0 ]] || fail "$role: locked-read-only must stop when RTMR3 cannot be extended"
  grep -qF 'RTMR3 not extended' "$WORK/$role-absent/log" || fail "$role: the refusal must say RTMR3 was not extended"

  if [[ "$(id -u)" != 0 ]]; then
    run "$role-readonly" "$role" locked-read-only readonly "$SEALED"
    [[ "$(rc "$role-readonly")" != 0 ]] || fail "$role: locked-read-only must stop when RTMR3 is not writable"
  fi

  run "$role-debug" "$role" debug-read-only absent "$UNSEALED"
  [[ "$(rc "$role-debug")" == 0 ]] || fail "$role: a debug profile must boot on without RTMR3"
  grep -qF 'WARN: RTMR3 not extended' "$WORK/$role-debug/log" || fail "$role: a debug profile must warn that RTMR3 was not extended"
done

echo "init RTMR3 (v3, node/kms/agent/inference): OK"
