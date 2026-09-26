#!/usr/bin/env bash
# The TDX KMS policy a release publishes must be one merod pins correctly.
#
# `kms-tdx-attestation-policy.<profile>.json` is what a node verifies its TDX
# cluster KMS against (core#4085). Two fields decide how merod reads it, and a
# mistake in either fails every node, or worse, passes the wrong KMS:
#
#   * `kms.backend` must be "tdx", or merod treats the file as a dstack policy
#     and demands a compose hash no TDX KMS has;
#   * `kms_allowed_event_payload` must be absent, since merod refuses a tdx
#     policy that names a compose hash.
#
# The writer also refuses inputs that would publish a policy pinning the wrong
# thing: more than one measurement, a missing node allowlist, and a KMS whose
# RTMR3 (which carries the image role) equals a node image's.
#
# Usage: scripts/ci/tests/kms-tdx-policy-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRITER="${REPO_ROOT}/scripts/release/kms-tdx/write-tdx-policy.sh"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

hex() { local out=""; for _ in $(seq 1 96); do out+="$1"; done; printf '%s' "${out}"; }
K_MRTD="$(hex a)"; K_R0="$(hex b)"; K_R1="$(hex c)"; K_R2="$(hex d)"; K_R3="$(hex e)"
N_R3="$(hex f)"

export TAG=2.3.80 COMMIT=abc RUN_ID=1 RUN_ATTEMPT=1 REPOSITORY=calimero-network/mero-tee \
  WORKFLOW="Release mero-kms" REF=master \
  DEFAULT_BINDING_HEX=00 DEFAULT_BINDING_B64=AA==

measurements() {  # <rtmr3> [extra mrtd]
  jq -n --arg m "${K_MRTD}" --arg r0 "${K_R0}" --arg r1 "${K_R1}" --arg r2 "${K_R2}" \
    --arg r3 "$1" --arg extra "${2:-}" '{policy: {
      allowed_tcb_statuses: ["uptodate","outofdate"],
      allowed_mrtd: ([$m] + (if $extra == "" then [] else [$extra] end)),
      allowed_rtmr0: [$r0], allowed_rtmr1: [$r1], allowed_rtmr2: [$r2], allowed_rtmr3: [$r3]}}'
}
jq -n --arg r3 "${N_R3}" --arg x "$(hex 1)" '{profiles: {
  "locked-read-only": {allowed_tcb_statuses: ["uptodate"], allowed_mrtd: [$x],
    allowed_rtmr0: [$x], allowed_rtmr1: [$x], allowed_rtmr2: [$x], allowed_rtmr3: [$r3]}}}' \
  > "${SB}/published-mrtds.json"
echo '{"name":"merotee-kms-locked-read-only-2-3-80","project":"cloud-486420","family":"merotee-kms-locked-read-only"}' \
  > "${SB}/image.json"

measurements "${K_R3}" > "${SB}/m.json"
bash "${WRITER}" locked-read-only "${SB}/m.json" "${SB}/published-mrtds.json" "${SB}/image.json" "${SB}/out.json" \
  || fail "the writer refused a valid measurement"

check() { jq -e "$1" "${SB}/out.json" >/dev/null || fail "$2: $(jq -c "${3:-.}" "${SB}/out.json")"; echo "ok   $2"; }
check '.kms.backend == "tdx"' "kms.backend is tdx" '.kms'
check '.policy | has("kms_allowed_event_payload") | not' "no compose hash is named" '.policy'
check '.role == "kms" and .profile == "locked-read-only" and .tag == "2.3.80"' "role, profile and tag" '{role,profile,tag}'
jq -e --arg m "${K_MRTD}" --arg r3 "${K_R3}" \
  '.policy.kms_allowed_mrtd == [$m] and .policy.kms_allowed_rtmr3 == [$r3]
   and .policy.kms_allowed_tcb_statuses == ["uptodate","outofdate"]' "${SB}/out.json" >/dev/null \
  || fail "KMS registers not copied: $(jq -c .policy "${SB}/out.json")"
echo "ok   the KMS's own registers are pinned"
jq -e --arg r3 "${N_R3}" '.policy.node_allowed_rtmr3 == [$r3] and .policy.node_allowed_tcb_statuses == ["uptodate"]' \
  "${SB}/out.json" >/dev/null || fail "node allowlist not copied"
echo "ok   the node allowlist it serves is carried beside them"
check '.image.name == "merotee-kms-locked-read-only-2-3-80" and .image.project == "cloud-486420"' \
  "the image the measurements belong to is named" '.image'

refuses() {  # <label> <args...>
  local label="$1"; shift
  if bash "${WRITER}" "$@" "${SB}/refused.json" 2>/dev/null; then
    fail "the writer accepted ${label}"
  fi
  echo "ok   refuses ${label}"
}
measurements "${K_R3}" "$(hex 9)" > "${SB}/two.json"
refuses "two measurements for one image" locked-read-only "${SB}/two.json" "${SB}/published-mrtds.json" "${SB}/image.json"
jq '.policy.allowed_rtmr1 = ["xyz"]' "${SB}/m.json" > "${SB}/bad.json"
refuses "a register that is not 96 hex" locked-read-only "${SB}/bad.json" "${SB}/published-mrtds.json" "${SB}/image.json"
refuses "a profile with no node allowlist" debug "${SB}/m.json" "${SB}/published-mrtds.json" "${SB}/image.json"
refuses "an unknown profile" production "${SB}/m.json" "${SB}/published-mrtds.json" "${SB}/image.json"
measurements "${N_R3}" > "${SB}/same.json"
refuses "a KMS measuring a node image's RTMR3" locked-read-only "${SB}/same.json" "${SB}/published-mrtds.json" "${SB}/image.json"
echo '{"name":""}' > "${SB}/noimage.json"
refuses "a policy that names no image" locked-read-only "${SB}/m.json" "${SB}/published-mrtds.json" "${SB}/noimage.json"

echo "== TDX KMS policy is one merod pins by its registers =="
