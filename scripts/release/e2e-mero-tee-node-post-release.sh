#!/usr/bin/env bash
# Post-release: boot a fresh GCP TDX VM per node profile (debug, debug-read-only,
# locked-read-only), collect measurement-policy-candidates + node-client-verification,
# and assert probe measurements are covered by published-mrtds.json from the same
# GitHub release (subset checks; RTMR3 excluded from strict allowlist gate — same as
# post-release-kms-node-e2e).
#
# Does NOT require mero-kms release assets or KMS staging probes (unlike
# scripts/release/../post-release-kms-node-e2e.yaml). Does NOT run the debug→locked
# KMS runtime negative probe (that stays in the KMS-node workflow).
#
# Required env:
#   GH_TOKEN, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT
#   E2E_TEE_TAG              e.g. mero-tee-v2.3.20
#   E2E_RELEASE_VERSION      e.g. 2.3.20 (for naming)
#   E2E_PROBE_WORKFLOW_REF   branch or tag for gh workflow run --ref
#   E2E_PROBE_EXPECTED_SHA   commit SHA child workflows must use
# Optional:
#   DEFAULT_NODE_VM_MACHINE_TYPE  (default c3-standard-4)

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT required}"
: "${E2E_TEE_TAG:?E2E_TEE_TAG required}"
: "${E2E_RELEASE_VERSION:?E2E_RELEASE_VERSION required}"
: "${E2E_PROBE_WORKFLOW_REF:?E2E_PROBE_WORKFLOW_REF required}"
: "${E2E_PROBE_EXPECTED_SHA:?E2E_PROBE_EXPECTED_SHA required}"

export GH_TOKEN

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

wait_for_release_tag() {
  local tag="$1"
  local attempts="${2:-36}"
  local delay_secs="${3:-10}"
  local attempt
  for attempt in $(seq 1 "${attempts}"); do
    echo "[mero-tee-node-e2e] release poll ${attempt}/${attempts} for ${tag}..."
    if gh release view "${tag}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
      echo "[mero-tee-node-e2e] OK: found release ${tag}"
      return 0
    fi
    sleep "${delay_secs}"
  done
  echo "::error::Timed out waiting for GitHub release '${tag}'."
  return 1
}

wait_for_workflow_run() {
  local run_id="$1"
  local timeout_secs="$2"
  local label="$3"
  local repo="$4"
  local deadline=$(( $(date +%s) + timeout_secs ))
  local last_status=""
  local last_conclusion=""
  local last_heartbeat=0

  while (( $(date +%s) < deadline )); do
    local state
    state="$(gh run view "${run_id}" \
      --repo "${repo}" \
      --json status,conclusion,url \
      --jq '[.status, (.conclusion // ""), .url] | @tsv' 2>/dev/null || true)"
    if [[ -z "${state}" ]]; then
      sleep 10
      continue
    fi

    local status conclusion run_url
    IFS=$'\t' read -r status conclusion run_url <<< "${state}"
    if [[ "${status}" != "${last_status}" || "${conclusion}" != "${last_conclusion}" ]]; then
      echo "[mero-tee-node-e2e] ${label}: status=${status:-unknown} conclusion=${conclusion:-n/a} run=${run_url}"
      last_status="${status}"
      last_conclusion="${conclusion}"
    fi

    if [[ "${status}" == "completed" ]]; then
      [[ "${conclusion}" == "success" ]] && return 0
      return 1
    fi

    local now sec_left
    now="$(date +%s)"
    sec_left=$(( deadline - now ))
    if (( now - last_heartbeat >= 60 )); then
      echo "[mero-tee-node-e2e] ${label}: still running (status=${status:-unknown}, ~${sec_left}s left) run=${run_url}"
      last_heartbeat="${now}"
    fi
    sleep 10
  done

  echo "::error::Timed out after ${timeout_secs}s waiting for ${label} (run ${run_id})."
  return 1
}

if ! wait_for_release_tag "${E2E_TEE_TAG}" 36 10; then
  exit 1
fi

mkdir -p e2e/node e2e/node-probe
gh release download "${E2E_TEE_TAG}" \
  --repo "${GITHUB_REPOSITORY}" \
  --pattern "published-mrtds.json" \
  --dir e2e/node
gh release download "${E2E_TEE_TAG}" \
  --repo "${GITHUB_REPOSITORY}" \
  --pattern "release-provenance.json" \
  --dir e2e/node

node_release_provenance="e2e/node/release-provenance.json"
node_published_policy="e2e/node/published-mrtds.json"
if [[ ! -f "${node_release_provenance}" || ! -f "${node_published_policy}" ]]; then
  echo "::error::Missing release-provenance.json or published-mrtds.json from ${E2E_TEE_TAG}"
  exit 1
fi

version_slug="${E2E_RELEASE_VERSION//./-}"
node_vm_machine_type="${DEFAULT_NODE_VM_MACHINE_TYPE:-c3-standard-4}"
node_probe_run_urls=()

for profile in debug debug-read-only locked-read-only; do
  node_image_name="$(jq -r --arg profile "${profile}" '.profiles[$profile].image.name // empty' "${node_release_provenance}")"
  node_image_project="$(jq -r --arg profile "${profile}" '.profiles[$profile].image.project // empty' "${node_release_provenance}")"
  node_zone="$(jq -r --arg profile "${profile}" '.profiles[$profile].attestation_context.zone // empty' "${node_release_provenance}")"
  node_admin_port="$(python3 - "${node_release_provenance}" "${profile}" <<'PY'
import json
import pathlib
import sys
import urllib.parse

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
profile = sys.argv[2]
base_url = (
    payload.get("profiles", {})
    .get(profile, {})
    .get("attestation_context", {})
    .get("base_url", "")
)
if not base_url:
    print("80")
    raise SystemExit(0)
parsed = urllib.parse.urlparse(base_url)
if parsed.port:
    print(str(parsed.port))
elif parsed.scheme == "https":
    print("443")
else:
    print("80")
PY
  )"

  if [[ -z "${node_image_name}" || -z "${node_image_project}" || -z "${node_zone}" ]]; then
    echo "::error::Node release provenance missing image metadata for profile '${profile}'"
    exit 1
  fi

  node_probe_label="mero-tee-e2e-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${profile}"
  expected_node_title="Node GCP staging probe (${node_probe_label})"
  node_deployment_name="tdx-e2e-${version_slug}-${profile}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
  node_dispatch_started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  gh workflow run "node-image-gcp-staging-probe.yaml" \
    --repo "${GITHUB_REPOSITORY}" \
    --ref "${E2E_PROBE_WORKFLOW_REF}" \
    -f probe_label="${node_probe_label}" \
    -f deployment_name="${node_deployment_name}" \
    -f profile="${profile}" \
    -f image_name="${node_image_name}" \
    -f image_project="${node_image_project}" \
    -f vm_project="${node_image_project}" \
    -f vm_zone="${node_zone}" \
    -f vm_machine_type="${node_vm_machine_type}" \
    -f admin_api_port="${node_admin_port}"

  node_probe_run_id=""
  for attempt in $(seq 1 90); do
    echo "[mero-tee-node-e2e] resolving node-image-gcp-staging-probe run id (attempt ${attempt}/90, profile=${profile})..."
    node_probe_run_id="$(gh run list \
      --repo "${GITHUB_REPOSITORY}" \
      --workflow "node-image-gcp-staging-probe.yaml" \
      --event workflow_dispatch \
      --limit 10 \
      --json databaseId,createdAt,displayTitle \
      --jq '[.[] | select(.createdAt >= "'"${node_dispatch_started_at}"'" and .displayTitle == "'"${expected_node_title}"'")] | sort_by(.createdAt) | reverse | .[0].databaseId // empty' 2>/dev/null || true)"
    if [[ -z "${node_probe_run_id}" ]]; then
      node_probe_run_id="$(gh run list \
        --repo "${GITHUB_REPOSITORY}" \
        --workflow "node-image-gcp-staging-probe.yaml" \
        --event workflow_dispatch \
        --limit 10 \
        --json databaseId,createdAt \
        --jq '[.[] | select(.createdAt >= "'"${node_dispatch_started_at}"'")] | sort_by(.createdAt) | reverse | .[0].databaseId // empty' 2>/dev/null || true)"
    fi
    if [[ -n "${node_probe_run_id}" ]]; then
      break
    fi
    sleep 10
  done

  if [[ -z "${node_probe_run_id}" ]]; then
    echo "::error::Could not resolve node-image-gcp-staging-probe workflow run ID for profile '${profile}'"
    exit 1
  fi

  node_probe_run_head_sha="$(gh run view "${node_probe_run_id}" --repo "${GITHUB_REPOSITORY}" --json headSha --jq '.headSha // empty')"
  if [[ -z "${node_probe_run_head_sha}" ]]; then
    echo "::error::Could not read head SHA for node probe run ${node_probe_run_id}"
    exit 1
  fi
  if [[ "${node_probe_run_head_sha}" != "${E2E_PROBE_EXPECTED_SHA}" ]]; then
    echo "::error::Node probe run ${node_probe_run_id} used unexpected head SHA ${node_probe_run_head_sha}; expected ${E2E_PROBE_EXPECTED_SHA}."
    exit 1
  fi

  node_probe_run_url="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${node_probe_run_id}"
  if ! wait_for_workflow_run "${node_probe_run_id}" 2700 "Node probe profile=${profile}" "${GITHUB_REPOSITORY}"; then
    echo "::error::Timed out or failed while waiting for node probe run ${node_probe_run_id} (${node_probe_run_url})"
    exit 1
  fi
  node_probe_run_urls+=("${node_probe_run_url}")

  node_artifact_name="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${node_probe_run_id}/artifacts" \
    --jq '.artifacts | map(select(.expired == false and (.name | startswith("node-gcp-staging-probe-")))) | sort_by(.created_at) | reverse | .[0].name // ""')"
  if [[ -z "${node_artifact_name}" ]]; then
    echo "::error::No non-expired node probe artifact found for run ${node_probe_run_id}"
    exit 1
  fi

  node_probe_dir="e2e/node-probe/${profile}"
  mkdir -p "${node_probe_dir}"
  gh run download "${node_probe_run_id}" \
    --repo "${GITHUB_REPOSITORY}" \
    --name "${node_artifact_name}" \
    --dir "${node_probe_dir}"

  node_probe_candidates_file="$(python3 - "${node_probe_dir}" <<'PY'
import pathlib
import sys
base = pathlib.Path(sys.argv[1])
matches = sorted(base.rglob("measurement-policy-candidates.json"))
print(matches[0] if matches else "")
PY
  )"
  if [[ -z "${node_probe_candidates_file}" ]]; then
    echo "::error::Could not locate measurement-policy-candidates.json for node profile '${profile}'"
    exit 1
  fi

  cp "${node_probe_candidates_file}" "e2e/node/measurement-policy-candidates-${profile}.json"

  node_client_verification_file="$(python3 - "${node_probe_dir}" <<'PY'
import pathlib
import sys
base = pathlib.Path(sys.argv[1])
matches = sorted(base.rglob("node-client-verification.json"))
print(matches[0] if matches else "")
PY
  )"
  if [[ -z "${node_client_verification_file}" ]]; then
    echo "::error::Could not locate node-client-verification.json for node profile '${profile}'"
    exit 1
  fi
  cp "${node_client_verification_file}" "e2e/node/node-client-verification-${profile}.json"

  python3 - "${profile}" "${node_probe_candidates_file}" "${node_published_policy}" <<'PY'
import json
import pathlib
import sys

profile = sys.argv[1]
probe_file = pathlib.Path(sys.argv[2])
published_file = pathlib.Path(sys.argv[3])


def normalize(values):
    out = []
    for value in values:
        if isinstance(value, str):
            candidate = value.strip().lower().removeprefix("0x")
            if candidate:
                out.append(candidate)
    return out


probe_payload = json.loads(probe_file.read_text(encoding="utf-8"))
probe_policy = probe_payload.get("policy", {})
published_payload = json.loads(published_file.read_text(encoding="utf-8"))
published_profile = published_payload.get("profiles", {}).get(profile, {})

keys = [
    "allowed_tcb_statuses",
    "allowed_mrtd",
    "allowed_rtmr0",
    "allowed_rtmr1",
    "allowed_rtmr2",
]
for key in keys:
    probe_values = normalize(probe_policy.get(key, []))
    published_values = normalize(published_profile.get(key, []))
    if not probe_values:
        raise SystemExit(f"[mero-tee-node-e2e] ERROR: missing node probe values for {profile}.{key}")
    if not published_values:
        raise SystemExit(f"[mero-tee-node-e2e] ERROR: missing published node policy values for {profile}.{key}")
    if not set(probe_values).issubset(set(published_values)):
        raise SystemExit(
            "[mero-tee-node-e2e] ERROR: node probe values are not covered by published policy "
            f"for profile={profile} key={key}"
        )
print(f"[mero-tee-node-e2e] OK: probed node measurements match published policy for profile={profile}")
PY

  python3 - "${profile}" "${node_client_verification_file}" <<'PY'
import json
import pathlib
import sys

profile = sys.argv[1]
verification_file = pathlib.Path(sys.argv[2])
payload = json.loads(verification_file.read_text(encoding="utf-8"))
checks = payload.get("checks", {})


def assert_true(path: str, value):
    if value is not True:
        raise SystemExit(
            f"[mero-tee-node-e2e] ERROR: node client verification check failed for profile={profile}: {path} expected true, got {value!r}"
        )


assert_true("checks.positive.passed", checks.get("positive", {}).get("passed"))
assert_true("checks.wrong_nonce.rejected", checks.get("wrong_nonce", {}).get("rejected"))
assert_true("checks.tampered_quote.rejected", checks.get("tampered_quote", {}).get("rejected"))
assert_true(
    "checks.wrong_expected_application_hash.rejected",
    checks.get("wrong_expected_application_hash", {}).get("rejected"),
)
print(
    "[mero-tee-node-e2e] OK: node client-side anti-fake verification checks passed "
    f"for profile={profile}"
)
PY

done

echo "[mero-tee-node-e2e] All profiles passed."
printf '%s\n' "${node_probe_run_urls[@]}"
