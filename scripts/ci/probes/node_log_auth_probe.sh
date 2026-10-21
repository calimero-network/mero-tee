#!/usr/bin/env bash
# Real-cloud check that a node ships its logs with the credential mdma gives it.
#
# mdma stamps the fleet's observability token into instance metadata as
# `observability-token` when it creates a node. calimero-init writes it to
# /etc/vector/provided_token, and vector presents it on every push through
# fetch_secret.sh's `provided` provider. If any link in that chain breaks, the
# sink rejects every write, and nothing on the node's side ever hears about it.
# A locked-read-only node also has no shell to ask. So the chain was only ever
# checked by looking for a node's logs after it went live.
#
# This checks it from outside. The node boots with a random per-run token in
# `observability-token` and its `logs-endpoint` pointed at a throwaway receiver
# VM (log_auth_receiver.py). The receiver reports on ITS serial console whether
# each push carried that token. It needs no cloud identity and no setup, because
# the token travels the same way mdma sends it.
#
#   setup    generate the token, start the receiver, and write the token to
#            $TOKEN_FILE (mode 0600) for the node VM step. Writes
#            receiver_name and receiver_ip to $GITHUB_OUTPUT.
#   verify   poll the receiver's serial console until it records an
#            authenticated push, or fail after VERIFY_TIMEOUT_SECONDS.
#   cleanup  delete the receiver and its firewall rule. Best effort, so it is
#            safe to run after a partial setup.
#
# Callers: the staging probe's opt-in `log_auth_check`; the debug and
# debug-read-only profiles of the node release (release-node-image-gcp.yaml),
# where a node that does not ship its logs stops the release before anything
# is published; and the same profiles of the KMS release (release-kms.yaml),
# for its KMS and agent images, whose probes take the two keys through
# log_auth_metadata.sh. Not locked-read-only: it ships only over https (see
# setup).
set -euo pipefail

source scripts/ci/logging.sh
source scripts/ci/gcp_create_instance.sh

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

# The receiver VM, its network tag and its firewall rule share one name,
# ${RECEIVER_PREFIX}-${RUN_SUFFIX}. The staging probe keeps the default. The
# release passes `tee-attest-rcv`, so that its cleanup sweep, which matches the
# release's own `tee-attest-` names, also finds a receiver a cancelled run left.
# The KMS release passes `kms-attest-rcv` and `agent-attest-rcv`, which that
# sweep's stale patterns also match.
names() {
  require_env VM_PROJECT VM_ZONE RUN_SUFFIX
  local name="${RECEIVER_PREFIX:-tee-e2e-rcv}-${RUN_SUFFIX}"
  if [[ ! "${name}" =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]]; then
    ci_fail "BAD_RECEIVER_NAME" "Receiver name '${name}' is not a valid GCE resource name (lowercase, at most 63 characters)."
    exit 1
  fi
  RECEIVER_NAME="${name}"
  RECEIVER_TAG="${name}"
  RECEIVER_FW_RULE="${name}"
}

setup() {
  # The receiver speaks plain http: vector cannot trust a CA handed to it in
  # metadata, so an https receiver would need a publicly trusted certificate.
  # configure_vector.sh lets only the debug profiles ship over plain http (the
  # push carries the bearer token and every log line), so on locked-read-only
  # vector never starts against this receiver and verify could only time out.
  # IMAGE_PROFILE is optional; when given, refuse such a profile up front.
  case "${IMAGE_PROFILE:-}" in
    "" | debug | debug-read-only) ;;
    *)
      ci_fail "LOG_AUTH_UNSUPPORTED_PROFILE" "Profile '${IMAGE_PROFILE}' ships logs only to an https endpoint (configure_vector.sh), so it cannot push to the plain-http receiver. Run the log-auth check on debug or debug-read-only; they share vector's role, config and token chain."
      exit 1
      ;;
  esac
  require_env VM_NETWORK NODE_TAG TOKEN_FILE GITHUB_OUTPUT
  names

  # The receiver goes where the VM it listens for is. The node release and the
  # staging probe place their node on VM_SUBNETWORK. The KMS and agent probes
  # (release-kms.yaml) give theirs neither a network nor a subnet, so it lands
  # on the `default` network's subnet in the zone's region; they leave
  # VM_SUBNETWORK empty, and the receiver gets the same with --network.
  local placement=(--subnet "${VM_SUBNETWORK:-}")
  if [[ -z "${VM_SUBNETWORK:-}" ]]; then
    placement=(--network "${VM_NETWORK}")
  fi

  # A throwaway token, valid for no real sink. It goes to the node through
  # instance metadata, as mdma's does, and the file hands it to the step that
  # creates the node: a step output carrying a masked value is dropped. The
  # receiver gets only its SHA-256.
  local token want startup
  token="$(openssl rand -hex 32)"
  echo "::add-mask::${token}"
  want="$(printf '%s' "${token}" | sha256sum | awk '{print $1}')"
  ( umask 077; printf '%s' "${token}" > "${TOKEN_FILE}" )
  unset token

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
  # The release runs this for every profile, so a transient GCP error here
  # would fail a release. gcp_create_instance retries those under the same
  # name, so cleanup and the release sweep still find the receiver.
  gcp_create_instance "${RECEIVER_NAME}" "${VM_PROJECT}" "${VM_ZONE}" \
    --machine-type e2-small \
    --image-family debian-12 \
    --image-project debian-cloud \
    --no-service-account \
    --no-scopes \
    "${placement[@]}" \
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

  {
    echo "receiver_name=${RECEIVER_NAME}"
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
    --arg receiver "${RECEIVER_NAME}" \
    '{receiver: $receiver, pushes: {authenticated: $ok, wrong_token: $mismatch, unauthenticated: $none}, passed: ($ok > 0)}' \
    > "${ARTIFACTS_DIR}/node-log-auth-result.json"

  if (( ok > 0 )); then
    ci_ok "Node pushed logs with the token from its metadata (${ok} authenticated pushes)"
    return 0
  fi
  if (( none > 0 )); then
    ci_fail "LOG_PUSH_UNAUTHENTICATED" "Node pushed ${none} times with no credential: the observability-token never reached vector."
  elif (( mismatch > 0 )); then
    ci_fail "LOG_PUSH_WRONG_TOKEN" "Node pushed ${mismatch} times with a token that is not the one in its metadata."
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
