#!/usr/bin/env bash
# Download attestation artifact from a failed run and show boot/merod diagnostics.
# Requires: gh auth login or GH_TOKEN / GITHUB_TOKEN
# Usage: ./scripts/fetch-and-analyze-failed-attestation.sh [run_id] [profile] [out_dir] [run_attempt]
#   run_attempt defaults to 1 (use 2, 3, ... for retried runs)
set -euo pipefail

RUN_ID="${1:-23000679833}"
PROFILE="${2:-debug-read-only}"
OUT_DIR="${3:-${HOME}/Desktop/mero-tee-artifacts-${RUN_ID}}"
RUN_ATTEMPT="${4:-1}"
ARTIFACT_NAME="gcp-tdx-attestation-${PROFILE}-${RUN_ID}-${RUN_ATTEMPT}"

if ! command -v gh &>/dev/null; then
  echo "gh CLI required. Install: brew install gh && gh auth login"
  exit 1
fi

if [[ -z "${GH_TOKEN:-}" && -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Note: GH_TOKEN or GITHUB_TOKEN not set. Run: gh auth login"
fi

mkdir -p "${OUT_DIR}"
echo "Downloading artifact ${ARTIFACT_NAME} from run ${RUN_ID} to ${OUT_DIR}..."
gh run download "${RUN_ID}" --repo calimero-network/mero-tee --name "${ARTIFACT_NAME}" -D "${OUT_DIR}" || {
  echo "Failed. Try: gh run download ${RUN_ID} --repo calimero-network/mero-tee"
  echo "Or list artifacts: gh run view ${RUN_ID} --repo calimero-network/mero-tee"
  exit 1
}

SERIAL_LOG="${OUT_DIR}/serial-port-1.log"
if [[ ! -f "${SERIAL_LOG}" ]]; then
  echo "Warning: ${SERIAL_LOG} not found. Listing downloaded files:"
  ls -la "${OUT_DIR}" 2>/dev/null || true
  exit 1
fi

echo ""
echo "=== First 200 lines of serial-port-1 (boot + calimero-init) ==="
head -200 "${SERIAL_LOG}" 2>/dev/null || true

echo ""
echo "=== Lines matching panic|exhausted|calimero-init|merod|ERROR|failed|WARN ==="
grep -E -i "panic|exhausted|calimero-init|merod|ERROR|failed|WARN" "${SERIAL_LOG}" 2>/dev/null || true

echo ""
echo "=== Last 150 lines of serial-port-1 (most recent) ==="
tail -150 "${SERIAL_LOG}" 2>/dev/null || true

echo ""
echo "Artifacts saved to ${OUT_DIR}"
