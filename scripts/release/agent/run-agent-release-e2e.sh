#!/usr/bin/env bash
set -euo pipefail

# The private agent end to end, on a release (docs/design/private-agents.md):
#
#   1. boots a one-replica KMS cluster from the release's KMS image;
#   2. boots the release's agent image with a blank data disk, pointed at it.
#      agent-init's `merod kms disk-key` verifies that KMS against the release's
#      signed policy, and the KMS releases a key only because the agent's quote
#      matches its AGENT entry (under the mero-agent/ prefix). The gate starts
#      only once the disk is open, so a gate answering proves the whole chain;
#   3. verifies the gate's quote against the release's signed agent policy and,
#      as an owner would, claims the agent with a throwaway key made here and
#      provisions a secret through mero-agent-provision; a second key is refused;
#   4. resets the agent VM: the gate must come back with the SAME signing key
#      and the SAME owner, both on the encrypted disk, so the disk was reopened
#      with the same KMS key rather than reformatted; the owner provisions
#      again and the second key is still refused.
#
# Creates and always deletes its own VMs, disk and firewall rule.
#
# Required env:
#   VERSION                the release (X.Y.Z)
#   PROFILE                the profile to run
#   IMAGE_PROJECT          where the release images live
#   PROBE_NAME             lowercase prefix for VMs, firewall rule and tag
#   VM_PROJECT, VM_ZONE, VM_MACHINE_TYPE
#   AGENT_POLICY           the release's agent allowlist for PROFILE (verified)
#   PROVISION_BIN          a built mero-agent-provision
#   OUT_DIR
# Optional env:
#   KMS_PORT (8080), GATE_PORT (8090), WAIT_TIMEOUT_MINUTES (25)

for var in VERSION PROFILE IMAGE_PROJECT PROBE_NAME VM_PROJECT VM_ZONE VM_MACHINE_TYPE \
  AGENT_POLICY PROVISION_BIN OUT_DIR; do
  if [[ -z "${!var:-}" ]]; then
    echo "::error::${var} is required"
    exit 1
  fi
done
KMS_PORT="${KMS_PORT:-8080}"
GATE_PORT="${GATE_PORT:-8090}"
WAIT_TIMEOUT_MINUTES="${WAIT_TIMEOUT_MINUTES:-25}"
mkdir -p "${OUT_DIR}"

kms_image="merotee-kms-${PROFILE}-${VERSION//./-}"
agent_image="merotee-agent-${PROFILE}-${VERSION//./-}"
kms_vm="${PROBE_NAME}-kms"
agent_vm="${PROBE_NAME}-agent"
firewall="${PROBE_NAME}"
created_vms=()
firewall_created="false"

cleanup() {
  local rc=$?
  if (( rc != 0 )); then
    for vm in "${created_vms[@]}"; do
      echo "::group::serial output of ${vm}"
      gcloud compute instances get-serial-port-output "${vm}" \
        --project "${VM_PROJECT}" --zone "${VM_ZONE}" 2>/dev/null | tail -300 || true
      echo "::endgroup::"
    done
  fi
  for vm in "${created_vms[@]}"; do
    gcloud compute instances delete "${vm}" \
      --project "${VM_PROJECT}" --zone "${VM_ZONE}" --delete-disks=all --quiet || true
  done
  if [[ "${firewall_created}" == "true" ]]; then
    gcloud compute firewall-rules delete "${firewall}" --project "${VM_PROJECT}" --quiet || true
  fi
  exit "${rc}"
}
trap cleanup EXIT

# The runner reaches the KMS's /health and the gate; the agent reaches the KMS
# over the VPC.
runner_ip="$(curl -fsS https://api.ipify.org)"
gcloud compute firewall-rules create "${firewall}" \
  --project "${VM_PROJECT}" --network default --direction INGRESS \
  --action ALLOW --rules "tcp:${KMS_PORT},tcp:${GATE_PORT}" \
  --source-ranges "${runner_ip}/32,10.0.0.0/8" \
  --target-tags "${PROBE_NAME}" \
  --description "mero-agent release e2e ${GITHUB_RUN_ID:-local}"
firewall_created="true"

create_vm() {
  local name="$1" image="$2" metadata="$3"
  shift 3
  created_vms+=("${name}")
  gcloud compute instances create "${name}" \
    --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
    --machine-type "${VM_MACHINE_TYPE}" \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --min-cpu-platform "Intel Sapphire Rapids" \
    --no-service-account --no-scopes \
    --image "${image}" --image-project "${IMAGE_PROJECT}" \
    --metadata "${metadata}" \
    --tags "${PROBE_NAME}" "$@"
}

vm_ip() {
  gcloud compute instances describe "$1" --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
    --format="value(networkInterfaces[0].$2)"
}

wait_for() { # label url jq-filter
  local label="$1" url="$2" filter="$3"
  local deadline=$(( $(date +%s) + WAIT_TIMEOUT_MINUTES * 60 ))
  until curl -fsS --max-time 5 "${url}" 2>/dev/null | jq -e "${filter}" >/dev/null 2>&1; do
    if (( $(date +%s) >= deadline )); then
      echo "::error::${label} never answered ${url}"
      exit 1
    fi
    sleep 10
  done
  echo "${label} is up: $(curl -fsS --max-time 5 "${url}")"
}

# --- 1. the release's KMS ------------------------------------------------------
create_vm "${kms_vm}" "${kms_image}" "kms-bootstrap=true"
kms_ip="$(vm_ip "${kms_vm}" 'accessConfigs[0].natIP')"
kms_internal="$(vm_ip "${kms_vm}" 'networkIP')"
wait_for "the KMS" "http://${kms_ip}:${KMS_PORT}/health" '.clusterRootReady == true'

# --- 2. the release's agent, on a blank disk --------------------------------------
create_vm "${agent_vm}" "${agent_image}" \
  "kms-url=http://${kms_internal}:${KMS_PORT},tee-release-version=${VERSION},relay-url=https://relay.invalid" \
  --create-disk "name=${agent_vm}-data,size=10GB,type=pd-balanced,device-name=data,auto-delete=yes"
agent_ip="$(vm_ip "${agent_vm}" 'accessConfigs[0].natIP')"
gate="http://${agent_ip}:${GATE_PORT}"
wait_for "the agent gate (its disk opened with an agent key)" "${gate}/health" '.status == "ok"'

# --- 3. verify, claim, provision -------------------------------------------------
keys="$(mktemp -d)"
"${PROVISION_BIN}" keygen --out "${keys}/owner.key" >"${OUT_DIR}/owner.pub"
"${PROVISION_BIN}" keygen --out "${keys}/other.key" >/dev/null
owner="$(cat "${OUT_DIR}/owner.pub")"
"${PROVISION_BIN}" attest --gate "${gate}" --policy "${AGENT_POLICY}" | tee "${OUT_DIR}/attest-1.json"
jq -e '.ownerPublicKey == null' "${OUT_DIR}/attest-1.json" >/dev/null \
  || { echo "::error::a fresh agent on a blank disk is already claimed"; exit 1; }

provision() { # key label
  printf '{"secrets":{"E2E_SECRET":"e2e-%s-%s"}}' "${GITHUB_RUN_ID:-local}" "$2" >"${OUT_DIR}/e2e-secrets.json"
  local rc=0
  "${PROVISION_BIN}" provision --gate "${gate}" --policy "${AGENT_POLICY}" \
    --key "$1" --secrets "${OUT_DIR}/e2e-secrets.json" || rc=$?
  rm -f "${OUT_DIR}/e2e-secrets.json"
  return "${rc}"
}
refused() { # label
  if provision "${keys}/other.key" foreign >"${OUT_DIR}/foreign-$1.json" 2>"${OUT_DIR}/foreign-$1.err"; then
    echo "::error::a second key provisioned a claimed agent ($1)"; exit 1
  fi
  grep -q "not yours" "${OUT_DIR}/foreign-$1.err" \
    || { echo "::error::a second key failed for the wrong reason ($1): $(cat "${OUT_DIR}/foreign-$1.err")"; exit 1; }
}

provision "${keys}/owner.key" claim | tee "${OUT_DIR}/provision.json"
jq -e --arg owner "${owner}" '.written == ["E2E_SECRET"] and .claimed == true and .ownerPublicKey == $owner' \
  "${OUT_DIR}/provision.json" >/dev/null \
  || { echo "::error::the gate did not write the secret under a claim"; exit 1; }
refused before-reset

# --- 4. reboot: the same disk, the same key -----------------------------------
gcloud compute instances reset "${agent_vm}" --project "${VM_PROJECT}" --zone "${VM_ZONE}"
sleep 30
wait_for "the agent gate after a reset" "${gate}/health" '.status == "ok"'
"${PROVISION_BIN}" attest --gate "${gate}" --policy "${AGENT_POLICY}" | tee "${OUT_DIR}/attest-2.json"
before="$(jq -r '.signingPublicKey' "${OUT_DIR}/attest-1.json")"
after="$(jq -r '.signingPublicKey' "${OUT_DIR}/attest-2.json")"
[[ -n "${before}" && "${before}" == "${after}" ]] \
  || { echo "::error::the signing key changed across a reset (${before} -> ${after}): the disk was not reopened"; exit 1; }
jq -e --arg owner "${owner}" '.ownerPublicKey == $owner' "${OUT_DIR}/attest-2.json" >/dev/null \
  || { echo "::error::the claim did not survive a reset"; exit 1; }
refused after-reset
provision "${keys}/owner.key" again | tee "${OUT_DIR}/provision-2.json"
jq -e '.written == ["E2E_SECRET"] and .claimed == false' "${OUT_DIR}/provision-2.json" >/dev/null \
  || { echo "::error::the owner could not provision again after a reset"; exit 1; }
rm -rf "${keys}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Private agent end to end (${PROFILE}, ${VERSION})"
    echo "- KMS \`${kms_image}\` released the agent's disk key; the gate verified against the signed agent policy."
    echo "- A throwaway owner key \`${owner}\` claimed the agent and provisioned a secret sealed to the TD; a second key was refused."
    echo "- After a reset the disk reopened: signing key \`${before}\` and the owner unchanged; the owner provisioned again and the second key was still refused."
  } >> "${GITHUB_STEP_SUMMARY}"
fi
echo "Agent end to end: OK"
