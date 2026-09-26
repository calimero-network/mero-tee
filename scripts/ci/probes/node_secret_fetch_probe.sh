#!/usr/bin/env bash
# Real-cloud check that a node fetches its log credential from Secret Manager.
#
# fetch_secret.sh's `gcp` provider is the one path a staging probe never
# exercised: probe VMs are created with no service account, exactly as mdma
# creates nodes, and a node with no cloud identity cannot read Secret Manager
# by design. The unit test (scripts/ci/tests/fetch-secret-rest-test.sh) covers
# the request and the decode against stubs. This covers the part stubs cannot:
# the real metadata server, the real Secret Manager API, and the real image,
# which on locked-read-only has snapd masked. That is why the provider had to
# stop using `gcloud` (mero-tee#339).
#
# A locked-read-only node has no shell and no serial console, so the result is
# observed from outside. The node's `logs-endpoint` points at a throwaway
# receiver VM (log_auth_receiver.py), and the receiver reports on ITS serial
# console whether each push carried the token stored in the secret.
#
#   setup    create a one-off secret holding a random token, grant the probe
#            service account read access to that secret only, and start the
#            receiver. Writes secret_name, receiver_name, receiver_fw_rule and
#            receiver_ip to $GITHUB_OUTPUT.
#   verify   poll the receiver's serial console until it records an
#            authenticated push, or fail after VERIFY_TIMEOUT_SECONDS.
#   cleanup  delete the receiver, its firewall rule and the secret. Best
#            effort, so it is safe to run after a partial setup.
#
# Prerequisites: repo variable GCP_PROBE_SECRET_SA names an existing service
# account that needs no project roles, because this grants it access to one
# secret. The workflow's own identity needs to create and delete secrets and
# set their IAM policy, and `iam.serviceAccounts.actAs` on that account.
set -euo pipefail

source scripts/ci/logging.sh

MODE="${1:-}"
RECEIVER_PORT=9200

require_env() {
  local name
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      ci_fail "MISSING_REQUIRED_ENV" "${name} is not set."
      exit 1
    fi
  done
}

names() {
  require_env VM_PROJECT VM_ZONE RUN_SUFFIX
  SECRET_NAME="tee-e2e-obs-${RUN_SUFFIX}"
  RECEIVER_NAME="tee-e2e-rcv-${RUN_SUFFIX}"
  RECEIVER_TAG="tee-e2e-rcv-${RUN_SUFFIX}"
  RECEIVER_FW_RULE="tee-e2e-rcv-${RUN_SUFFIX}"
}

setup() {
  require_env PROBE_SERVICE_ACCOUNT VM_NETWORK VM_SUBNETWORK NODE_TAG GITHUB_OUTPUT
  names

  # The token lives only in this function. The receiver gets its SHA-256, and
  # nothing but the secret itself ever holds the value.
  local token want startup
  token="$(openssl rand -hex 32)"
  echo "::add-mask::${token}"
  want="$(printf '%s' "${token}" | sha256sum | awk '{print $1}')"

  printf '%s' "${token}" | gcloud secrets create "${SECRET_NAME}" \
    --project "${VM_PROJECT}" \
    --replication-policy automatic \
    --labels purpose=tee-e2e \
    --data-file=-
  unset token
  gcloud secrets add-iam-policy-binding "${SECRET_NAME}" \
    --project "${VM_PROJECT}" \
    --member "serviceAccount:${PROBE_SERVICE_ACCOUNT}" \
    --role roles/secretmanager.secretAccessor >/dev/null
  ci_info "Secret ${SECRET_NAME} readable by ${PROBE_SERVICE_ACCOUNT} only"

  # Vector pushes from the node's tag to the receiver's; nothing else reaches it.
  gcloud compute firewall-rules create "${RECEIVER_FW_RULE}" \
    --project "${VM_PROJECT}" \
    --network "${VM_NETWORK}" \
    --direction INGRESS \
    --priority 1000 \
    --action ALLOW \
    --rules "tcp:${RECEIVER_PORT}" \
    --source-tags "${NODE_TAG}" \
    --target-tags "${RECEIVER_TAG}" \
    --description "Temporary node log-auth receiver for run ${RUN_SUFFIX}"

  startup="$(mktemp)"
  {
    echo '#!/bin/bash'
    echo "cat > /opt/log_auth_receiver.py <<'PY'"
    cat scripts/ci/probes/log_auth_receiver.py
    echo 'PY'
    echo "exec env WANT_SHA256=${want} PROBE_PORT=${RECEIVER_PORT} python3 /opt/log_auth_receiver.py"
  } > "${startup}"

  # Plain Debian, not a TEE image: the receiver is test scaffolding. No service
  # account and no external address, since it only listens inside the VPC.
  gcloud compute instances create "${RECEIVER_NAME}" \
    --project "${VM_PROJECT}" \
    --zone "${VM_ZONE}" \
    --machine-type e2-small \
    --image-family debian-12 \
    --image-project debian-cloud \
    --no-service-account \
    --no-scopes \
    --subnet "${VM_SUBNETWORK}" \
    --no-address \
    --tags "${RECEIVER_TAG}" \
    --metadata-from-file "startup-script=${startup}"
  rm -f "${startup}"

  local receiver_ip
  receiver_ip="$(gcloud compute instances describe "${RECEIVER_NAME}" \
    --project "${VM_PROJECT}" \
    --zone "${VM_ZONE}" \
    --format='value(networkInterfaces[0].networkIP)')"
  if [[ -z "${receiver_ip}" ]]; then
    ci_fail "RECEIVER_NO_IP" "Receiver ${RECEIVER_NAME} has no internal IP."
    exit 1
  fi

  # IAM changes can take a minute to reach Secret Manager, and fetch_secret.sh
  # reads the secret once, early in the node's boot. A binding that has not
  # arrived yet would read as a failed fetch, so wait before the node exists.
  ci_info "Waiting 60s for the secret's IAM binding to propagate"
  sleep 60

  {
    echo "secret_name=${SECRET_NAME}"
    echo "receiver_name=${RECEIVER_NAME}"
    echo "receiver_fw_rule=${RECEIVER_FW_RULE}"
    echo "receiver_ip=${receiver_ip}"
  } >> "${GITHUB_OUTPUT}"
  ci_ok "Receiver ${RECEIVER_NAME} at ${receiver_ip}:${RECEIVER_PORT}"
}

verify() {
  require_env ARTIFACTS_DIR
  names
  local timeout="${VERIFY_TIMEOUT_SECONDS:-600}" deadline serial counts
  local ok=0 mismatch=0 none=0
  serial="${ARTIFACTS_DIR}/log-auth-receiver-serial.log"
  deadline=$(( $(date +%s) + timeout ))

  while :; do
    gcloud compute instances get-serial-port-output "${RECEIVER_NAME}" \
      --project "${VM_PROJECT}" \
      --zone "${VM_ZONE}" \
      --port 1 > "${serial}" 2>/dev/null || true
    counts="$(grep -oE 'PROBE_AUTH_(OK|MISMATCH|NONE)' "${serial}" | sort | uniq -c || true)"
    ok="$(awk '$2 == "PROBE_AUTH_OK" {print $1}' <<< "${counts}")"
    mismatch="$(awk '$2 == "PROBE_AUTH_MISMATCH" {print $1}' <<< "${counts}")"
    none="$(awk '$2 == "PROBE_AUTH_NONE" {print $1}' <<< "${counts}")"
    ok="${ok:-0}" mismatch="${mismatch:-0}" none="${none:-0}"
    if (( ok > 0 )) || (( $(date +%s) >= deadline )); then
      break
    fi
    ci_info "Receiver: ${ok} authenticated, ${mismatch} wrong token, ${none} unauthenticated pushes so far"
    sleep 15
  done

  jq -n --argjson ok "${ok}" --argjson mismatch "${mismatch}" --argjson none "${none}" \
    --arg secret "${SECRET_NAME}" --arg receiver "${RECEIVER_NAME}" \
    '{secret: $secret, receiver: $receiver, pushes: {authenticated: $ok, wrong_token: $mismatch, unauthenticated: $none}, passed: ($ok > 0)}' \
    > "${ARTIFACTS_DIR}/node-secret-fetch-result.json"

  if (( ok > 0 )); then
    ci_ok "Node pushed logs with the token from Secret Manager (${ok} authenticated pushes)"
    return 0
  fi
  if (( none > 0 )); then
    ci_fail "SECRET_FETCH_FAILED" "Node pushed ${none} times with no credential: fetch_secret.sh gcp did not get the secret on this image."
  elif (( mismatch > 0 )); then
    ci_fail "SECRET_FETCH_WRONG_TOKEN" "Node pushed ${mismatch} times with a token that is not the one in ${SECRET_NAME}."
  elif ! grep -q PROBE_RECEIVER_READY "${serial}"; then
    ci_fail "RECEIVER_NOT_READY" "The receiver never started; see ${serial}."
  else
    ci_fail "NO_LOG_PUSHES" "The receiver got no pushes in ${timeout}s: vector did not start, or could not reach ${RECEIVER_NAME}."
  fi
  exit 1
}

cleanup() {
  names
  gcloud compute instances delete "${RECEIVER_NAME}" \
    --project "${VM_PROJECT}" --zone "${VM_ZONE}" --quiet || true
  gcloud compute firewall-rules delete "${RECEIVER_FW_RULE}" \
    --project "${VM_PROJECT}" --quiet || true
  gcloud secrets delete "${SECRET_NAME}" \
    --project "${VM_PROJECT}" --quiet || true
}

case "${MODE}" in
  setup) setup ;;
  verify) verify ;;
  cleanup) cleanup ;;
  *)
    echo "Usage: $0 setup|verify|cleanup" >&2
    exit 2
    ;;
esac
