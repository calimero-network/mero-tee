#!/bin/bash
# Fleet HA sidecar: polls MDMA for group assignments and drives merod via localhost admin API.
# Runs as a systemd service alongside merod on ReadOnly TEE fleet nodes.
#
# Config (from GCP instance metadata):
#   fleet-mdma-url:    MDMA Manager URL (e.g. https://manager.cloud.calimero.network)
#   fleet-auth-token:  Shared secret for X-Fleet-Token header
#
# The MDMA URL is baked into the measured image (MRTD). TLS is always verified.
set -euo pipefail

LOG="/var/log/fleet-sidecar.log"
STATE_FILE="/var/lib/calimero/fleet-assignments.json"
MEROD_ADMIN="http://localhost:2428/admin-api"
POLL_INTERVAL=1
METADATA_URL="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
METADATA_HEADER="Metadata-Flavor: Google"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG"; }

get_meta() {
  curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/${1}" 2>/dev/null || true
}

mkdir -p "$(dirname "$STATE_FILE")"
[[ -f "$STATE_FILE" ]] || echo '[]' > "$STATE_FILE"

MDMA_URL=$(get_meta "fleet-mdma-url")
FLEET_TOKEN=$(get_meta "fleet-auth-token")

if [[ -z "${MDMA_URL:-}" ]]; then
  log "ERROR: fleet-mdma-url metadata not set. Fleet sidecar cannot start."
  exit 1
fi

log "Fleet sidecar starting (mdma=$MDMA_URL poll=${POLL_INTERVAL}s)"

wait_for_merod() {
  log "Waiting for merod admin API..."
  local attempts=0
  while ! curl -sf "${MEROD_ADMIN}/health" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if (( attempts % 30 == 0 )); then
      log "Still waiting for merod (attempt $attempts)..."
    fi
    sleep 1
  done
  log "merod admin API is ready"
}

get_peer_id() {
  local info
  info=$(curl -sf "${MEROD_ADMIN}/tee/info" 2>/dev/null || true)
  if [[ -n "$info" ]]; then
    echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('peer_id',''))" 2>/dev/null || true
  fi
}

get_measurements() {
  local info
  info=$(curl -sf "${MEROD_ADMIN}/tee/info" 2>/dev/null || true)
  if [[ -n "$info" ]]; then
    echo "$info" | python3 -c "
import sys, json
d = json.load(sys.stdin).get('data', {})
print(json.dumps({
  'mrtd': d.get('mrtd', ''),
  'rtmr0': d.get('rtmr0', ''),
  'rtmr1': d.get('rtmr1', ''),
  'rtmr2': d.get('rtmr2', ''),
  'rtmr3': d.get('rtmr3', ''),
  'tcb_status': d.get('tcb_status', '')
}))
" 2>/dev/null || echo '{}'
  else
    echo '{}'
  fi
}

poll_mdma() {
  local peer_id="$1"
  local measurements="$2"
  local payload
  payload=$(python3 -c "
import json
m = json.loads('''$measurements''')
m['peer_id'] = '$peer_id'
print(json.dumps(m))
")

  local headers=(-H "Content-Type: application/json")
  [[ -n "${FLEET_TOKEN:-}" ]] && headers+=(-H "X-Fleet-Token: ${FLEET_TOKEN}")

  curl -sf --max-time 10 "${headers[@]}" \
    -d "$payload" \
    "${MDMA_URL}/api/fleet/should-join" 2>/dev/null || echo '{"assignments":[]}'
}

confirm_assignment() {
  local peer_id="$1"
  local group_id="$2"

  local headers=(-H "Content-Type: application/json")
  [[ -n "${FLEET_TOKEN:-}" ]] && headers+=(-H "X-Fleet-Token: ${FLEET_TOKEN}")

  curl -sf --max-time 10 "${headers[@]}" \
    -d "{\"peer_id\":\"$peer_id\",\"group_id\":\"$group_id\"}" \
    "${MDMA_URL}/api/fleet/confirm" 2>/dev/null || true
}

join_group() {
  local group_id="$1"
  log "Joining group $group_id via merod admin API..."

  local result
  result=$(curl -sf --max-time 30 \
    -H "Content-Type: application/json" \
    -d "{\"group_id\":\"$group_id\"}" \
    "${MEROD_ADMIN}/tee/fleet-join" 2>&1) || true

  if [[ -n "$result" ]]; then
    log "fleet-join response: $result"
    return 0
  else
    log "WARN: fleet-join endpoint not available (core upgrade needed)"
    return 1
  fi
}

load_current_assignments() {
  cat "$STATE_FILE" 2>/dev/null || echo '[]'
}

save_current_assignments() {
  echo "$1" > "$STATE_FILE"
}

# --- Main loop ---

wait_for_merod

PEER_ID=$(get_peer_id)
if [[ -z "$PEER_ID" ]]; then
  log "Could not get peer_id, retrying in 5s..."
  sleep 5
  PEER_ID=$(get_peer_id)
fi

if [[ -z "$PEER_ID" ]]; then
  log "ERROR: Could not get peer_id from merod after retry."
  exit 1
fi

log "Fleet node peer_id: $PEER_ID"

MEASUREMENTS=$(get_measurements)
log "Node measurements: $MEASUREMENTS"

while true; do
  response=$(poll_mdma "$PEER_ID" "$MEASUREMENTS")

  new_assignments=$(echo "$response" | python3 -c "
import sys, json
try:
  data = json.load(sys.stdin)
  assignments = data.get('assignments', [])
  if not assignments and data.get('join'):
    assignments = [{'group_id': data['group_id']}]
  print(json.dumps(sorted([a['group_id'] for a in assignments])))
except:
  print('[]')
" 2>/dev/null || echo '[]')

  current=$(load_current_assignments)

  to_join=$(python3 -c "
import json
new = set(json.loads('''$new_assignments'''))
cur = set(json.loads('''$current'''))
print(json.dumps(list(new - cur)))
" 2>/dev/null || echo '[]')

  for group_id in $(echo "$to_join" | python3 -c "import sys,json; [print(g) for g in json.loads(sys.stdin.read())]" 2>/dev/null); do
    if join_group "$group_id"; then
      confirm_assignment "$PEER_ID" "$group_id"
      log "Joined and confirmed group $group_id"
    fi
  done

  save_current_assignments "$new_assignments"

  sleep "$POLL_INTERVAL"
done
