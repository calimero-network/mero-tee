#!/usr/bin/env bash
set -euo pipefail

# Dispatch and wait for the KMS staging probe workflow.
# Inputs: IMAGE_REF, PROFILE, RELEASE_VERSION, PROBE_LABEL, GH_TOKEN context.
# Optional: KMS_POLICY_VERSION - when set, probe runs with MERO_KMS_VERSION to test policy fetch.
# Output (GITHUB_OUTPUT): run_id of the completed probe run.

if [[ -z "${IMAGE_REF:-}" || -z "${PROFILE:-}" || -z "${RELEASE_VERSION:-}" || -z "${PROBE_LABEL:-}" ]]; then
  echo "::error::IMAGE_REF, PROFILE, RELEASE_VERSION, and PROBE_LABEL are required"
  exit 1
fi

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo "::error::GITHUB_OUTPUT is required"
  exit 1
fi

wait_for_workflow_run() {
  local run_id="$1"
  local timeout_secs="$2"
  local label="$3"
  local repo="$4"
  local deadline=$(( $(date +%s) + timeout_secs ))
  local last_status=""
  local last_conclusion=""

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
      echo "[release-kms-probe] ${label}: status=${status:-unknown} conclusion=${conclusion:-n/a} run=${run_url}"
      last_status="${status}"
      last_conclusion="${conclusion}"
    fi

    if [[ "${status}" == "completed" ]]; then
      [[ "${conclusion}" == "success" ]] && return 0
      return 1
    fi
    sleep 10
  done

  echo "::error::Timed out after ${timeout_secs}s waiting for ${label} (run ${run_id})."
  return 1
}

# Use canonical names matching MDMA/production for compose_hash consistency
deployment_name="calimero-kms-${PROFILE}"
max_probe_attempts=2
run_id=""

for probe_attempt in $(seq 1 "${max_probe_attempts}"); do
  probe_label="${PROBE_LABEL}-try${probe_attempt}"
  dispatch_started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  expected_display_title="KMS staging probe (${probe_label})"

  probe_inputs=(-f kms_image="${IMAGE_REF}" -f kms_tag="pinned" -f probe_label="${probe_label}" -f deployment_name="${deployment_name}")
  if [[ -n "${KMS_POLICY_VERSION:-}" ]]; then
    probe_inputs+=(-f kms_policy_version="${KMS_POLICY_VERSION}")
  fi
  gh workflow run "kms-phala-staging-probe.yaml" \
    --repo "${GITHUB_REPOSITORY}" \
    --ref master \
    "${probe_inputs[@]}"

  if [[ -z "${run_id}" ]]; then
    run_id=""
    for _ in $(seq 1 90); do
      run_id="$(gh run list \
        --repo "${GITHUB_REPOSITORY}" \
        --workflow "kms-phala-staging-probe.yaml" \
        --event workflow_dispatch \
        --branch master \
        --limit 20 \
        --json databaseId,createdAt,displayTitle \
        --jq '[.[] | select(.createdAt >= "'"${dispatch_started_at}"'" and .displayTitle == "'"${expected_display_title}"'")] | sort_by(.createdAt) | reverse | .[0].databaseId // empty' 2>/dev/null || true)"
      if [[ -z "${run_id}" ]]; then
        run_id="$(gh run list \
          --repo "${GITHUB_REPOSITORY}" \
          --workflow "kms-phala-staging-probe.yaml" \
          --event workflow_dispatch \
          --branch master \
          --limit 20 \
          --json databaseId,createdAt \
          --jq '[.[] | select(.createdAt >= "'"${dispatch_started_at}"'")] | sort_by(.createdAt) | reverse | .[0].databaseId // empty' 2>/dev/null || true)"
      fi
      if [[ -n "${run_id}" ]]; then
        break
      fi
      sleep 10
    done
  fi

  if [[ -z "${run_id}" ]]; then
    if [[ "${probe_attempt}" -lt "${max_probe_attempts}" ]]; then
      echo "::warning::Could not find dispatched probe run on attempt ${probe_attempt}; retrying..."
      continue
    fi
    echo "::error::Could not find dispatched probe run"
    exit 1
  fi

  echo "Waiting for probe run ${run_id} (attempt ${probe_attempt}/${max_probe_attempts})..."
  if wait_for_workflow_run "${run_id}" 2700 "release profile=${PROFILE} attempt=${probe_attempt}" "${GITHUB_REPOSITORY}"; then
    echo "run_id=${run_id}" >> "${GITHUB_OUTPUT}"
    break
  fi

  if [[ "${probe_attempt}" -lt "${max_probe_attempts}" ]]; then
    echo "::warning::Probe run ${run_id} failed on attempt ${probe_attempt}; retrying once..."
    run_id=""
    continue
  fi

  echo "::error::Timed out or failed while waiting for probe run ${run_id}"
  exit 1
done

if [[ -z "${run_id}" ]]; then
  echo "::error::No successful staging probe run found after retries."
  exit 1
fi
