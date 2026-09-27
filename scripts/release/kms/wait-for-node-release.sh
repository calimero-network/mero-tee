#!/usr/bin/env bash
set -euo pipefail

# Wait for the same-version node release (Release mero-tee) and fetch its
# published-mrtds.json into node-policy/. The KMS image bakes that node
# allowlist and the KMS policy republishes it, so Release mero-kms cannot run
# ahead of it. Fails fast when no same-commit node release is running.
# Inputs: GH_TOKEN, VERSION, NODE_TAG, EVENT_NAME, GITHUB_SHA,
# GITHUB_REPOSITORY, GITHUB_EVENT_PATH (push events).

for var in VERSION NODE_TAG EVENT_NAME GITHUB_SHA GITHUB_REPOSITORY; do
  if [[ -z "${!var:-}" ]]; then
    echo "::error::${var} is required"
    exit 1
  fi
done

source scripts/ci/logging.sh
mkdir -p node-policy

node_release_workflow_state="unknown"
last_logged_node_release_workflow_state=""
refresh_node_release_workflow_state() {
  local state
  state="$(gh run list \
    --repo "${GITHUB_REPOSITORY}" \
    --workflow "Release mero-tee" \
    --commit "${GITHUB_SHA}" \
    --json status,conclusion \
    --limit 1 \
    --jq 'if length == 0 then "none" else (.[0].status + ":" + (.[0].conclusion // "none")) end' \
    2>/dev/null || true)"
  if [[ -z "${state}" ]]; then
    state="query-error"
  fi
  node_release_workflow_state="${state}"
}

versions_manifest_changed="unknown"
if [[ "${EVENT_NAME}" == "push" && -f "${GITHUB_EVENT_PATH:-}" ]]; then
  if jq -e '
    [ .commits[]? | (.added // []) + (.modified // []) + (.removed // []) ]
    | flatten
    | any(. == "mero-tee/versions.json")
  ' "${GITHUB_EVENT_PATH}" >/dev/null 2>&1; then
    versions_manifest_changed="true"
  else
    versions_manifest_changed="false"
  fi
  refresh_node_release_workflow_state
  ci_info "Detected versions manifest changed: ${versions_manifest_changed}"
  ci_info "Release mero-tee workflow state for commit ${GITHUB_SHA}: ${node_release_workflow_state}"
fi

ci_group_start "Node release polling"
for attempt in $(seq 1 60); do
  if gh release view "${NODE_TAG}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
    if gh release download "${NODE_TAG}" --repo "${GITHUB_REPOSITORY}" \
      --pattern "published-mrtds.json" --dir node-policy 2>/dev/null; then
      ci_ok "Fetched node policy from ${NODE_TAG}"
      ci_result "release-kms-node-release-wait" "success" "NODE_POLICY_READY" "attempt=${attempt}" "node_tag=${NODE_TAG}"
      break
    fi
  fi

  if [[ "${EVENT_NAME}" == "push" ]]; then
    refresh_node_release_workflow_state
    ci_log_transition "Release mero-tee workflow state" "${node_release_workflow_state}" "${last_logged_node_release_workflow_state}" "${attempt}" 5
    last_logged_node_release_workflow_state="${node_release_workflow_state}"
    case "${node_release_workflow_state}" in
      completed:failure|completed:cancelled|completed:timed_out|completed:action_required|completed:startup_failure|completed:stale)
        ci_fail "NODE_RELEASE_FAILED" "Same-commit 'Release mero-tee' run ended as ${node_release_workflow_state} before publishing ${NODE_TAG}."
        ci_next "Fix/re-run node release first, then rerun this workflow."
        exit 1
        ;;
    esac
  fi

  if [[ "${attempt}" -eq 1 && "${versions_manifest_changed}" == "false" ]]; then
    case "${node_release_workflow_state}" in
      queued:*|in_progress:*|pending:*|requested:*|waiting:*)
        ci_info "Release mero-tee is currently ${node_release_workflow_state}; continuing to wait for ${NODE_TAG}."
        ;;
      *)
        ci_fail "NODE_RELEASE_MISSING" "Node release ${NODE_TAG} is missing and this push did not modify mero-tee/versions.json."
        ci_fail "NODE_POLICY_REQUIRED" "Release mero-kms cannot proceed without ${NODE_TAG}/published-mrtds.json."
        ci_fail "NODE_RELEASE_NOT_ACTIVE" "No active same-commit 'Release mero-tee' workflow was detected (state=${node_release_workflow_state})."
        ci_next "Run the 'Release mero-tee' workflow for imageVersion ${VERSION}, then rerun this workflow."
        exit 1
        ;;
    esac
  fi
  if [[ "${attempt}" -eq 60 ]]; then
    ci_fail "NODE_RELEASE_TIMEOUT" "Timed out waiting for node release ${NODE_TAG} with published-mrtds.json"
    exit 1
  fi
  if [[ "${attempt}" -eq 1 || $(( attempt % 5 )) -eq 0 ]]; then
    ci_info "Waiting for node release ${NODE_TAG} (attempt ${attempt}/60)"
  fi
  sleep 30
done
ci_group_end
