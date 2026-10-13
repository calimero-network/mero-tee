#!/usr/bin/env bash
# Boot one confidential H100 VM, serve a pinned model on it and measure it.
#
# What a GPU TD serving agents (docs/design/private-agents.md, "The model")
# can carry is a measurement, not an estimate: this starts a3-highgpu-1g with
# TDX, has gpu-probe-startup.sh install the driver and vLLM, fetch the files
# MODEL_FILES pins (refusing any that differ), serve the model on loopback and
# run load_probe.py, then reads the report off the serial console. The VM
# opens no port; it is always deleted, and --max-run-duration deletes it even
# if this script is killed first.
#
# Env: VM_PROJECT, VM_ZONES (comma list, tried in order), PROVISIONING
# (SPOT|FLEX_START), CONFIDENTIAL (true|false), DRIVER, VLLM_VERSION (empty =
# latest), MAX_MODEL_LEN, LEVELS, MODEL_FILES, PROBE_NAME, OUT_DIR,
# WAIT_TIMEOUT_MINUTES.
set -euo pipefail

: "${VM_PROJECT:?}" "${VM_ZONES:?}" "${PROVISIONING:?}" "${CONFIDENTIAL:?}" "${DRIVER:?}"
: "${MAX_MODEL_LEN:?}" "${LEVELS:?}" "${MODEL_FILES:?}" "${PROBE_NAME:?}" "${OUT_DIR:?}"
: "${WAIT_TIMEOUT_MINUTES:?}"
VLLM_VERSION="${VLLM_VERSION:-}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "${OUT_DIR}"
vm="${PROBE_NAME}"
zone=""

cleanup() {
  local rc=$?
  if [[ -n "${zone}" ]]; then
    gcloud compute instances get-serial-port-output "${vm}" --project "${VM_PROJECT}" \
      --zone "${zone}" >"${OUT_DIR}/serial.log" 2>/dev/null || true
    gcloud compute instances delete "${vm}" --project "${VM_PROJECT}" --zone "${zone}" \
      --delete-disks=all --quiet || true
  fi
  exit "${rc}"
}
trap cleanup EXIT

create_args=(
  --project "${VM_PROJECT}"
  --machine-type a3-highgpu-1g
  --maintenance-policy TERMINATE
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud
  --boot-disk-size 400GB --boot-disk-type pd-ssd
  --no-service-account --no-scopes
  --provisioning-model "${PROVISIONING}"
  --instance-termination-action DELETE
  --max-run-duration 3h
  --metadata "probe-driver=${DRIVER},probe-vllm-version=${VLLM_VERSION},probe-max-model-len=${MAX_MODEL_LEN},probe-levels=${LEVELS//,/;}"
  --metadata-from-file "startup-script=${here}/gpu-probe-startup.sh,probe-files=${MODEL_FILES},probe-load=${here}/load_probe.py"
)
[[ "${CONFIDENTIAL}" == "true" ]] && create_args+=(--confidential-compute-type TDX)
[[ "${PROVISIONING}" == "FLEX_START" ]] && create_args+=(--reservation-affinity none --request-valid-for-duration 30m)

IFS=',' read -r -a zones <<<"${VM_ZONES}"
for z in "${zones[@]}"; do
  echo "Creating ${vm} in ${z} (${PROVISIONING}, confidential=${CONFIDENTIAL})"
  if gcloud compute instances create "${vm}" --zone "${z}" "${create_args[@]}" 2>"${OUT_DIR}/create-${z}.err"; then
    zone="${z}"
    break
  fi
  echo "::warning::no VM in ${z}: $(tail -n 3 "${OUT_DIR}/create-${z}.err" | tr '\n' ' ')"
done
[[ -n "${zone}" ]] || { echo "::error::no zone in ${VM_ZONES} could start a3-highgpu-1g"; exit 1; }
echo "zone=${zone}" >"${OUT_DIR}/placement"

deadline=$(( $(date +%s) + WAIT_TIMEOUT_MINUTES * 60 ))
seen=0
while :; do
  if ! gcloud compute instances get-serial-port-output "${vm}" --project "${VM_PROJECT}" \
      --zone "${zone}" >"${OUT_DIR}/serial.log" 2>/dev/null; then
    status="$(gcloud compute instances describe "${vm}" --project "${VM_PROJECT}" --zone "${zone}" \
      --format='value(status)' 2>/dev/null || echo GONE)"
    [[ "${status}" == "RUNNING" || "${status}" == "STAGING" || "${status}" == "PROVISIONING" ]] \
      || { echo "::error::the VM is ${status} (preempted or deleted)"; exit 1; }
  fi
  mapfile -t progress < <(grep -a 'GPU-PROBE \(STAGE\|FAILED\|LOG\)' "${OUT_DIR}/serial.log" | awk '!x[$0]++' || true)
  for line in "${progress[@]:seen}"; do echo "${line}"; done
  seen=${#progress[@]}
  if grep -aq 'GPU-PROBE FAILED' "${OUT_DIR}/serial.log"; then
    echo "::error::$(grep -a 'GPU-PROBE FAILED' "${OUT_DIR}/serial.log" | head -n 1)"
    exit 1
  fi
  if grep -aq 'GPU-PROBE RESULT-END' "${OUT_DIR}/serial.log"; then
    sed -n '/GPU-PROBE RESULT-BEGIN/,/GPU-PROBE RESULT-END/p' "${OUT_DIR}/serial.log" \
      | grep -a 'GPU-PROBE B64 ' | sed 's/.*GPU-PROBE B64 //' | tr -d '\r' \
      | base64 -d >"${OUT_DIR}/report.json"
    jq . "${OUT_DIR}/report.json"
    exit 0
  fi
  (( $(date +%s) < deadline )) || { echo "::error::no report within ${WAIT_TIMEOUT_MINUTES} minutes"; exit 1; }
  sleep 30
done
