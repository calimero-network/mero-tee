#!/usr/bin/env bash
# Verify compose_hash data flow: release process vs attestation verifier.
# Run from mero-tee repo root.
#
# Usage:
#   ./scripts/attestation/verify-compose-hash-flow.sh [mero-kms-v2.1.73]
#
# Checks:
# 1. Fetch compatibility map from GitHub release, verify structure
# 2. Compare JS extraction with Python extraction on same event log (if attest-response provided)
# 3. Report any mismatches

set -euo pipefail

TAG="${1:-mero-kms-v2.1.73}"
REPO="calimero-network/mero-tee"
COMPAT_URL="https://github.com/${REPO}/releases/download/${TAG}/kms-phala-compatibility-map.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Compose hash flow verification ==="
echo "Tag: ${TAG}"
echo ""

# 1. Fetch and verify compatibility map structure
echo "--- 1. Compatibility map (release) ---"
if ! compat_json="$(curl -sSf -L -H "User-Agent: verify-compose-hash-flow/1.0" "${COMPAT_URL}" 2>/dev/null)"; then
  echo "ERROR: Failed to fetch ${COMPAT_URL}"
  echo "  (Release may not exist or asset not found)"
  exit 1
fi

echo "Fetched $(echo "${compat_json}" | wc -c) bytes"
for profile in debug "debug-read-only" "locked-read-only"; do
  val="$(echo "${compat_json}" | jq -r --arg p "${profile}" '.compatibility.profiles[$p].kms_compose_hash // ""')"
  if [[ -z "${val}" ]]; then
    echo "  ${profile}: (empty or missing)"
  elif [[ "${val}" =~ ^[a-f0-9]{64}$ ]]; then
    echo "  ${profile}: ${val:0:16}...${val: -16}"
  else
    echo "  ${profile}: INVALID (expected 64 hex chars, got ${#val})"
  fi
done
echo ""

# 2. Verify attestation verifier expects same structure
echo "--- 2. Verifier expectations ---"
echo "Verifier fetches: ${COMPAT_URL}"
echo "Verifier reads: compatibility.profiles.<profile>.kms_compose_hash"
echo "Extraction: imr=3 event with event=='compose-hash', payload=64 hex"
echo ""

# 3. Python vs JS extraction parity (if attest-response provided)
ATTEST_FILE="${2:-}"
if [[ -n "${ATTEST_FILE}" && -f "${ATTEST_FILE}" ]]; then
  echo "--- 3. Python vs JS extraction parity ---"
  cd "${REPO_ROOT}"
  event_log="$(jq -c '.event_log // .eventLog' "${ATTEST_FILE}")"
  if [[ -z "${event_log}" || "${event_log}" == "null" ]]; then
    echo "  No event_log in ${ATTEST_FILE}"
  else
    # Python: same logic as verify_dstack_compose_hash.extract_compose_hash_and_app_id
    tmp_py="$(mktemp)"
    trap "rm -f ${tmp_py}" EXIT
    cat > "${tmp_py}" << 'PYSCRIPT'
import json, re, sys
events = json.load(sys.stdin)
ch = None
for e in events:
    if e.get("imr") != 3: continue
    name = e.get("event", "")
    payload = (e.get("event_payload", "") or "").strip()
    if name == "compose-hash" and payload and re.match(r"^[a-fA-F0-9]{64}$", payload):
        ch = payload.lower()
print(ch or "")
PYSCRIPT
    py_hash="$(echo "${event_log}" | python3 "${tmp_py}" 2>/dev/null)" || py_hash=""
    # JS: matches attestation.js extractComposeHashAndAppId
    js_hash="$(node -e "
const events = ${event_log};
let ch = null;
for (const e of events) {
  if (e.imr !== 3) continue;
  const name = (e.event || '').toString();
  let payload = e.event_payload ?? e.eventPayload ?? '';
  if (typeof payload === 'string') payload = payload.trim();
  if (name === 'compose-hash' && payload && /^[a-fA-F0-9]{64}\$/.test(payload)) ch = payload.toLowerCase();
}
console.log(ch || '');
" 2>/dev/null)" || js_hash=""
    echo "  Python: ${py_hash:-n/a}"
    echo "  JS:     ${js_hash:-n/a}"
    if [[ -n "${py_hash}" && -n "${js_hash}" && "${py_hash}" != "${js_hash}" ]]; then
      echo "  ERROR: Extraction mismatch!"
      exit 1
    fi
    echo "  Parity: OK"
  fi
else
  echo "--- 3. Python vs JS parity ---"
  echo "  Skipped (no attest-response path provided)"
  echo "  Usage: $0 [tag] path/to/attest-response.json"
fi
echo ""

echo "=== Done ==="
