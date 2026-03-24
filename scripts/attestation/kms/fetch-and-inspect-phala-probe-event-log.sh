#!/usr/bin/env bash
# Download attestation artifacts from a KMS Phala probe run and inspect event_log for compose_hash debugging.
#
# Usage:
#   ./scripts/attestation/kms/fetch-and-inspect-phala-probe-event-log.sh [run_id] [version] [profile] [out_dir]
#
# Examples:
#   # From release workflow run (e.g. 2.1.72 release): download kms-probe-2.1.72-debug
#   ./scripts/attestation/kms/fetch-and-inspect-phala-probe-event-log.sh 12345678 2.1.72 debug
#
#   # From staging probe run directly: download kms-staging-probe-{run_id}-{attempt}
#   ./scripts/attestation/kms/fetch-and-inspect-phala-probe-event-log.sh 12345678 "" "" ./phala-probe-inspect
#
# When version and profile are empty, assumes run_id is a staging probe run and looks for
# artifact kms-staging-probe-{run_id}-*.
#
# Requires: gh CLI, jq

set -euo pipefail

REPO="${GITHUB_REPOSITORY:-calimero-network/mero-tee}"
RUN_ID="${1:-}"
VERSION="${2:-}"
PROFILE="${3:-debug}"
OUT_DIR="${4:-${HOME}/Desktop/phala-probe-inspect-${RUN_ID}}"

if [[ -z "${RUN_ID}" ]]; then
  echo "Usage: $0 <run_id> [version] [profile] [out_dir]"
  echo ""
  echo "  run_id   - GitHub Actions run ID (release workflow or staging probe)"
  echo "  version  - e.g. 2.1.72 (required when artifact is kms-probe-{version}-{profile})"
  echo "  profile  - debug | debug-read-only | locked-read-only (default: debug)"
  echo "  out_dir  - output directory (default: ~/Desktop/phala-probe-inspect-{run_id})"
  echo ""
  echo "Find run IDs: gh run list --repo calimero-network/mero-tee --workflow 'Release mero-kms'"
  echo ""
  echo "Examples:"
  echo "  $0 12345678 2.1.72 debug          # release workflow run"
  echo "  $0 12345678 '' '' ./out           # staging probe run (artifact: kms-staging-probe-*)"
  exit 1
fi

if ! command -v gh &>/dev/null; then
  echo "gh CLI required. Install: brew install gh && gh auth login"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "jq required. Install: brew install jq"
  exit 1
fi

mkdir -p "${OUT_DIR}"
echo "Fetching artifacts from run ${RUN_ID} (repo: ${REPO})..."
echo ""

if [[ -n "${VERSION}" ]]; then
  ARTIFACT_NAME="kms-probe-${VERSION}-${PROFILE}"
  echo "Downloading artifact: ${ARTIFACT_NAME}"
  if ! gh run download "${RUN_ID}" --repo "${REPO}" --name "${ARTIFACT_NAME}" -D "${OUT_DIR}"; then
    echo "::error::Artifact ${ARTIFACT_NAME} not found. Check run_id and version."
    echo "List artifacts: gh run view ${RUN_ID} --repo ${REPO}"
    exit 1
  fi
else
  ARTIFACT_NAME="kms-staging-probe-${RUN_ID}"
  echo "Downloading artifact matching: kms-staging-probe-*"
  if ! gh run download "${RUN_ID}" --repo "${REPO}" --name "kms-staging-probe-${RUN_ID}-1" -D "${OUT_DIR}"; then
    # Try without attempt suffix
    ARTIFACT=$(gh api "repos/${REPO}/actions/runs/${RUN_ID}/artifacts" \
      --jq '.artifacts | map(select(.expired == false and (.name | startswith("kms-staging-probe-")))) | sort_by(.created_at) | reverse | .[0].name // ""')
    if [[ -z "${ARTIFACT}" ]]; then
      echo "::error::No kms-staging-probe-* artifact found for run ${RUN_ID}"
      exit 1
    fi
    gh run download "${RUN_ID}" --repo "${REPO}" --name "${ARTIFACT}" -D "${OUT_DIR}"
  fi
fi

# Resolve paths: artifact may extract to nested dir (e.g. kms-probe-2.1.72-debug/ or kms-staging-probe-123-1/)
ATTEST_FILE=""
LOG_FILE=""
for f in "${OUT_DIR}"/attest-response.json "${OUT_DIR}"/*/attest-response.json; do
  if [[ -f "${f}" ]]; then
    ATTEST_FILE="${f}"
    break
  fi
done
for f in "${OUT_DIR}"/verify-compose-hash.log "${OUT_DIR}"/*/verify-compose-hash.log; do
  if [[ -f "${f}" ]]; then
    LOG_FILE="${f}"
    break
  fi
done

echo "=== verify-compose-hash.log ==="
if [[ -n "${LOG_FILE}" && -f "${LOG_FILE}" ]]; then
  cat "${LOG_FILE}"
else
  echo "(not found)"
fi

echo ""
echo "=== event_log from attest-response.json ==="
if [[ -n "${ATTEST_FILE}" && -f "${ATTEST_FILE}" ]]; then
  EVENT_LOG=$(jq -r '.event_log // .eventLog // empty' "${ATTEST_FILE}")
  if [[ -z "${EVENT_LOG}" ]]; then
    echo "No event_log or eventLog key found."
    echo "Top-level keys: $(jq -r 'keys | join(", ")' "${ATTEST_FILE}" 2>/dev/null || echo "n/a")"
  else
    if [[ "${EVENT_LOG}" == "["* ]]; then
      echo "${EVENT_LOG}" | jq '.' 2>/dev/null || echo "${EVENT_LOG}"
      echo ""
      echo "Event count: $(echo "${EVENT_LOG}" | jq 'length' 2>/dev/null || echo "n/a")"
      echo "Events with imr==3: $(echo "${EVENT_LOG}" | jq '[.[] | select(.imr == 3)] | length' 2>/dev/null || echo "n/a")"
      echo "Event names (imr==3): $(echo "${EVENT_LOG}" | jq '[.[] | select(.imr == 3) | .event] | unique' 2>/dev/null || echo "n/a")"
    else
      echo "(event_log may be string; parsing...)"
      echo "${EVENT_LOG}" | jq '.' 2>/dev/null || echo "${EVENT_LOG}"
    fi
  fi
else
  echo "(attest-response.json not found)"
fi

echo ""
echo "Artifacts saved to ${OUT_DIR}"
echo ""
echo "To compare with our verifier expectations, see: scripts/attestation/kms/verify_dstack_compose_hash.py"
echo "  - Expects: imr: 3, event: \"compose-hash\", payload: 64-char hex"
echo "  - Digest: sha384(event_type:event:payload) → 96-char hex"
