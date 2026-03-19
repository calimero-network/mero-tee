#!/usr/bin/env bash
set -euo pipefail

source scripts/ci/logging.sh

required_env=(
  ARTIFACTS_DIR
  INSTANCE_NAME
  VM_PROJECT
  VM_ZONE
  KMS_PROBE_URL
  KMS_PROBE_EXPECTED_OUTCOME
  KMS_PROBE_EXPECTED_CODES
)
for env_name in "${required_env[@]}"; do
  if [[ -z "${!env_name+x}" ]]; then
    ci_fail "MISSING_REQUIRED_ENV" "${env_name} is not set."
    exit 1
  fi
done

if [[ -z "${KMS_PROBE_URL}" ]]; then
  ci_fail "KMS_PROBE_URL_REQUIRED" "kms_probe_url must be set when kms_probe_expected_outcome is not 'skip'."
  exit 1
fi

case "${KMS_PROBE_EXPECTED_OUTCOME}" in
  success|failure) ;;
  *)
    ci_fail "INVALID_EXPECTED_OUTCOME" "kms_probe_expected_outcome must be one of: skip, success, failure."
    exit 1
    ;;
esac

probe_stdout="${ARTIFACTS_DIR}/node-kms-probe-ssh-stdout.log"
probe_stderr="${ARTIFACTS_DIR}/node-kms-probe-ssh-stderr.log"
probe_json="${ARTIFACTS_DIR}/node-kms-probe-raw.json"
parsed_json="false"
ssh_exit_code=255

ci_group_start "Node->KMS runtime probe attempts"
for attempt in $(seq 1 12); do
  set +e
  gcloud compute ssh "${INSTANCE_NAME}" \
    --project "${VM_PROJECT}" \
    --zone "${VM_ZONE}" \
    --quiet \
    --ssh-flag="-o ConnectTimeout=10" \
    --ssh-flag="-o ServerAliveInterval=30" \
    --command "set -euo pipefail; /usr/local/bin/merod --home /mnt/data/calimero --node default kms probe --kms-url '${KMS_PROBE_URL}' --json" \
    > "${probe_stdout}" \
    2> "${probe_stderr}"
  ssh_exit_code=$?
  set -e

  if python3 - "${probe_stdout}" "${probe_json}" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
end = text.rfind("}")
if end == -1:
    raise SystemExit(1)

depth = 0
start = None
for idx in range(end, -1, -1):
    ch = text[idx]
    if ch == "}":
        depth += 1
    elif ch == "{":
        depth -= 1
        if depth == 0:
            start = idx
            break

if start is None:
    raise SystemExit(1)

payload = json.loads(text[start : end + 1])
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
  then
    parsed_json="true"
    ci_ok "Parsed node->KMS probe JSON output at attempt ${attempt}"
    break
  fi
  ci_log_transition "node->KMS probe parse status" "non-json" "non-json" "${attempt}" 3
  if [[ "${attempt}" -lt 12 ]]; then
    sleep 10
  fi
done
ci_group_end

if [[ "${parsed_json}" != "true" ]]; then
  if [[ "${KMS_PROBE_EXPECTED_OUTCOME}" != "failure" ]]; then
    ci_fail "KMS_PROBE_PARSE_FAILED" "Unable to parse node KMS probe JSON output."
    echo "::group::node-kms-probe-ssh-stdout (last 120 lines)"
    tail -120 "${probe_stdout}" || true
    echo "::endgroup::"
    echo "::group::node-kms-probe-ssh-stderr (last 120 lines)"
    tail -120 "${probe_stderr}" || true
    echo "::endgroup::"
    exit 1
  fi

  # merod can emit non-JSON terminal errors for rejection paths.
  # Preserve strict failure semantics by converting known errors into a structured fallback.
  fallback_code="MEROD_KMS_PROBE_NO_JSON"
  if [[ -f "${probe_stderr}" ]] && grep -qi "TEE is not configured in this node" "${probe_stderr}"; then
    fallback_code="MEROD_TEE_NOT_CONFIGURED"
  fi
  fallback_error="$(python3 - "${probe_stderr}" "${probe_stdout}" <<'PY'
import pathlib
import sys

for candidate in sys.argv[1:]:
    path = pathlib.Path(candidate)
    if not path.exists():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if line:
            print(line[:512])
            raise SystemExit(0)
print("Node->KMS probe did not return JSON output")
PY
  )"
  jq -n \
    --arg code "${fallback_code}" \
    --arg error "${fallback_error}" \
    '{
      ok: false,
      code: $code,
      error: $error
    }' > "${probe_json}"
  ci_warn "Node->KMS probe did not return JSON; using fallback code ${fallback_code}."
fi

probe_ok="$(jq -r '.ok' "${probe_json}")"
probe_code="$(jq -r '.code // ""' "${probe_json}")"
outcome_matches="false"
if [[ "${KMS_PROBE_EXPECTED_OUTCOME}" == "success" ]]; then
  if [[ "${probe_ok}" == "true" ]]; then
    outcome_matches="true"
  fi
else
  if [[ "${probe_ok}" == "false" ]]; then
    outcome_matches="true"
  fi
fi

expected_code_matches="true"
if [[ -n "${KMS_PROBE_EXPECTED_CODES}" ]]; then
  expected_code_matches="false"
  IFS=',' read -r -a expected_codes <<< "${KMS_PROBE_EXPECTED_CODES}"
  for expected_code in "${expected_codes[@]}"; do
    normalized_expected_code="${expected_code//[[:space:]]/}"
    if [[ -n "${normalized_expected_code}" && "${probe_code}" == "${normalized_expected_code}" ]]; then
      expected_code_matches="true"
      break
    fi
  done
fi

jq -n \
  --arg kms_url "${KMS_PROBE_URL}" \
  --arg expected_outcome "${KMS_PROBE_EXPECTED_OUTCOME}" \
  --arg expected_codes "${KMS_PROBE_EXPECTED_CODES}" \
  --argjson ssh_exit_code "${ssh_exit_code}" \
  --argjson outcome_matches "${outcome_matches}" \
  --argjson expected_code_matches "${expected_code_matches}" \
  --slurpfile probe "${probe_json}" \
  '{
    schema_version: 1,
    kms_url: $kms_url,
    expected_outcome: $expected_outcome,
    expected_codes: (
      $expected_codes
      | split(",")
      | map(gsub("^\\s+|\\s+$"; ""))
      | map(select(length > 0))
    ),
    ssh_exit_code: $ssh_exit_code,
    probe: $probe[0],
    checks: {
      outcome_matches: $outcome_matches,
      expected_code_matches: $expected_code_matches
    }
  }' > "${ARTIFACTS_DIR}/node-kms-probe-result.json"

if [[ "${outcome_matches}" != "true" || "${expected_code_matches}" != "true" ]]; then
  ci_fail "KMS_PROBE_EXPECTATION_MISMATCH" "Node->KMS probe expectation mismatch."
  jq -c '{
    kms_url,
    expected_outcome,
    expected_codes,
    ssh_exit_code,
    probe: (.probe | {ok, code, error}),
    checks
  }' "${ARTIFACTS_DIR}/node-kms-probe-result.json" || true
  echo "::group::node-kms-probe-ssh-stdout (last 120 lines)"
  tail -120 "${probe_stdout}" || true
  echo "::endgroup::"
  echo "::group::node-kms-probe-ssh-stderr (last 120 lines)"
  tail -120 "${probe_stderr}" || true
  echo "::endgroup::"
  exit 1
fi

ci_result "node-image-gcp-runtime-probe" "success" "EXPECTATIONS_MATCHED" "ssh_exit_code=${ssh_exit_code}" "probe_code=${probe_code:-none}"
