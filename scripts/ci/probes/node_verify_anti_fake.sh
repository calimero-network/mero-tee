#!/usr/bin/env bash
set -euo pipefail

source scripts/ci/logging.sh

# Anti-fake TEE attestation probe.
#
# This probe no longer relies on a node HTTP attestation endpoint. Instead it
# SSHes into the staging node and invokes the merod `tee probe` CLI
# subcommand, mirroring node_runtime_kms_probe.sh. The
# subcommand runs the positive + negative attestation checks in-process and
# reports a TeeProbeResult JSON document:
#
#   {
#     "outcome": "success" | "failure",   # mirrors the process exit code
#     "is_mock": <bool>,                    # true when the quote is a mock quote
#     "checks": {
#       "positive":       { "passed": <bool>, ... },
#       "wrong_nonce":    { "passed": <bool>, ... },
#       "tampered_quote": { "passed": <bool>, ... }
#     }
#   }
#
# The probe fails unless the node returns real-hardware assurance: a successful
# outcome, a non-mock quote, and all three attestation checks passing.

required_env=(
  ARTIFACTS_DIR
  INSTANCE_NAME
  VM_PROJECT
  VM_ZONE
)
for env_name in "${required_env[@]}"; do
  if [[ -z "${!env_name+x}" ]]; then
    ci_fail "MISSING_REQUIRED_ENV" "${env_name} is not set."
    exit 1
  fi
done

probe_stdout="${ARTIFACTS_DIR}/node-anti-fake-ssh-stdout.log"
probe_stderr="${ARTIFACTS_DIR}/node-anti-fake-ssh-stderr.log"
probe_json="${ARTIFACTS_DIR}/node-anti-fake-probe-raw.json"
parsed_json="false"
ssh_exit_code=255

ci_group_start "Node anti-fake TEE probe attempts"
for attempt in $(seq 1 12); do
  set +e
  gcloud compute ssh "${INSTANCE_NAME}" \
    --project "${VM_PROJECT}" \
    --zone "${VM_ZONE}" \
    --quiet \
    --ssh-flag="-o ConnectTimeout=10" \
    --ssh-flag="-o ServerAliveInterval=30" \
    --command "set -euo pipefail; /usr/local/bin/merod --home /mnt/data/calimero --node default tee probe --json" \
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
    ci_ok "Parsed node anti-fake TEE probe JSON output at attempt ${attempt}"
    break
  fi
  ci_log_transition "node anti-fake probe parse status" "non-json" "non-json" "${attempt}" 3
  if [[ "${attempt}" -lt 12 ]]; then
    sleep 10
  fi
done
ci_group_end

if [[ "${parsed_json}" != "true" ]]; then
  # No parseable TeeProbeResult JSON was retrieved. Distinguish a pure SSH
  # transport failure (gcloud ssh could never connect -> exit 255) from a
  # node that answered but emitted a non-JSON terminal error (e.g. the
  # "TEE is not configured in this node" path emits no JSON and exits nonzero).
  echo "::group::node-anti-fake-ssh-stdout (last 120 lines)"
  ci_tail_bounded "${probe_stdout}" 120
  echo "::endgroup::"
  echo "::group::node-anti-fake-ssh-stderr (last 120 lines)"
  ci_tail_bounded "${probe_stderr}" 120
  echo "::endgroup::"
  if [[ "${ssh_exit_code}" -eq 255 ]]; then
    ci_fail "VERIFY_TEE_PROBE_SSH" "Unable to reach node over SSH to run merod tee probe (ssh_exit_code=${ssh_exit_code})."
  else
    ci_fail "VERIFY_TEE_PROBE_PARSE" "Node did not return parseable TeeProbeResult JSON from merod tee probe (ssh_exit_code=${ssh_exit_code})."
  fi
  exit 1
fi

# Structural validation: every field we assert on must be present and correctly
# typed. A malformed payload is a parse-tier failure, not a policy failure.
if ! jq -e '
    (.outcome | type == "string")
    and (.is_mock | type == "boolean")
    and (.checks | type == "object")
    and (.checks.positive.passed | type == "boolean")
    and (.checks.wrong_nonce.passed | type == "boolean")
    and (.checks.tampered_quote.passed | type == "boolean")
  ' "${probe_json}" >/dev/null 2>&1; then
  ci_fail "VERIFY_TEE_PROBE_PARSE" "TeeProbeResult JSON is missing required fields or has unexpected types."
  jq -c '.' "${probe_json}" 2>/dev/null || true
  exit 1
fi

outcome="$(jq -r '.outcome' "${probe_json}")"
is_mock="$(jq -r 'if .is_mock then "true" else "false" end' "${probe_json}")"
positive_passed="$(jq -r 'if .checks.positive.passed then "true" else "false" end' "${probe_json}")"
wrong_nonce_passed="$(jq -r 'if .checks.wrong_nonce.passed then "true" else "false" end' "${probe_json}")"
tampered_passed="$(jq -r 'if .checks.tampered_quote.passed then "true" else "false" end' "${probe_json}")"

# Persist a compact verification summary alongside the raw probe payload.
jq -n \
  --argjson ssh_exit_code "${ssh_exit_code}" \
  --arg outcome "${outcome}" \
  --argjson is_mock "${is_mock}" \
  --argjson positive_passed "${positive_passed}" \
  --argjson wrong_nonce_passed "${wrong_nonce_passed}" \
  --argjson tampered_passed "${tampered_passed}" \
  --slurpfile probe "${probe_json}" \
  '{
    schema_version: 2,
    transport: "ssh+merod-tee-probe",
    ssh_exit_code: $ssh_exit_code,
    outcome: $outcome,
    is_mock: $is_mock,
    probe: $probe[0],
    checks: {
      positive: {passed: $positive_passed},
      wrong_nonce: {passed: $wrong_nonce_passed},
      tampered_quote: {passed: $tampered_passed}
    }
  }' > "${ARTIFACTS_DIR}/node-client-verification.json"

# A mock quote must never count as real-hardware assurance.
if [[ "${is_mock}" != "false" ]]; then
  ci_fail "VERIFY_TEE_PROBE_IS_MOCK" "Node reported a mock quote (is_mock=true); mock attestation is not real-hardware assurance."
  exit 1
fi

if [[ "${positive_passed}" != "true" ]]; then
  ci_fail "VERIFY_TEE_PROBE_POSITIVE" "Positive attestation check did not pass."
  exit 1
fi

if [[ "${wrong_nonce_passed}" != "true" ]]; then
  ci_fail "VERIFY_TEE_PROBE_WRONG_NONCE" "Wrong-nonce negative check did not pass (a mismatched nonce was not rejected)."
  exit 1
fi

if [[ "${tampered_passed}" != "true" ]]; then
  ci_fail "VERIFY_TEE_PROBE_TAMPERED" "Tampered-quote negative check did not pass (a tampered quote was not rejected)."
  exit 1
fi

if [[ "${outcome}" != "success" ]]; then
  ci_fail "VERIFY_TEE_PROBE_OUTCOME" "merod tee probe reported outcome=${outcome} (expected success)."
  exit 1
fi

ci_result "node-image-gcp-anti-fake" "success" "ALL_TEE_PROBE_CHECKS_PASSED" "outcome=${outcome}" "is_mock=${is_mock}" "ssh_exit_code=${ssh_exit_code}"
