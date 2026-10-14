#!/usr/bin/env bash
# The agent image's /usr/local/bin/mero-agent when it runs mero-bot
# (calimero-network/mero-bot, baked at /opt/mero-bot with Node at /opt/node).
#
# One runs per slot (mero-agent@<n>.service, as user mero-agent-<n>): an agent
# TD hosts several owners' agents, each in its own slot. It waits until its
# slot's owner has provisioned the agent's secrets through mero-agent-gate.
# Then it runs mero-bot headless, on that owner's Hyperfeed, with model calls
# only to attested providers (--attested-only). It restarts mero-bot when the
# owner provisions again; the gate stops it before a release erases the slot.
#
# Secrets (files in the slot's secrets directory, by NAME):
#   MERO_AGENTS_JSON      required: mero-bot's agents.json. Every agent a turn
#                         can reach must be attested ("attest": "near").
#   CALIMERO_NODE_URL     required: the owner's node.
#   CALIMERO_AUTH_TOKEN   the node login, with CALIMERO_REFRESH_TOKEN; or
#   CALIMERO_USERNAME     with CALIMERO_PASSWORD.
#   NEAR_AI_API_KEY       the key a NEAR profile names in apiKeyEnv. Normally the
#                         operator's (mdma pays for the agent's model calls):
#                         the gate writes it to the slot's operator/ directory,
#                         and the owner's own, if provisioned, wins.
#   HYPERFEED_CONTEXT     optional: pins the feed.
# Any other name is ignored: only these reach mero-bot's environment.
#
# Environment: MERO_AGENT_DATA_DIR (from /run/mero-agent/agent.env, written by
# agent-init) and MERO_AGENT_SLOT (the unit's instance). The slot's secrets are
# in $MERO_AGENT_DATA_DIR/agents/<slot>/secrets and its state beside them;
# MERO_AGENT_SECRETS_DIR and MERO_AGENT_STATE_DIR override both, for tests.
set -euo pipefail

if [[ -z "${MERO_AGENT_SECRETS_DIR:-}" || -z "${MERO_AGENT_STATE_DIR:-}" ]]; then
  SLOT="${MERO_AGENT_SLOT:?}"
  [[ "$SLOT" =~ ^[1-9][0-9]*$ ]] || { echo "mero-agent: bad slot '$SLOT'" >&2; exit 1; }
  SLOT_DIR="${MERO_AGENT_DATA_DIR:?}/agents/$SLOT"
fi
SECRETS="${MERO_AGENT_SECRETS_DIR:-$SLOT_DIR/secrets}"
OPERATOR="${MERO_AGENT_OPERATOR_DIR:-${SLOT_DIR:+$SLOT_DIR/operator}}"
STATE="${MERO_AGENT_STATE_DIR:-$SLOT_DIR/state}"
BOT="${MERO_BOT_DIR:-/opt/mero-bot}"
NODE="${MERO_BOT_NODE:-/opt/node/bin/node}"
POLL_SECONDS="${MERO_BOT_POLL_SECONDS:-10}"

ENV_SECRETS=(
  CALIMERO_NODE_URL
  CALIMERO_AUTH_TOKEN
  CALIMERO_REFRESH_TOKEN
  CALIMERO_USERNAME
  CALIMERO_PASSWORD
  NEAR_AI_API_KEY
  HYPERFEED_CONTEXT
)

log() { echo "mero-agent: $*"; }

secret() { [[ -s "$SECRETS/$1" ]]; }

provisioned() {
  secret MERO_AGENTS_JSON && secret CALIMERO_NODE_URL \
    && { secret CALIMERO_AUTH_TOKEN || { secret CALIMERO_USERNAME && secret CALIMERO_PASSWORD; }; }
}

# What changes when the owner or the operator provisions again: each secret's
# name, size and mtime.
fingerprint() {
  find "$SECRETS" ${OPERATOR:+"$OPERATOR"} -maxdepth 1 -type f -printf '%h/%f %s %T@\n' 2>/dev/null | sort
}

if ! provisioned; then
  log "waiting for the owner to provision MERO_AGENTS_JSON, CALIMERO_NODE_URL and a node login"
  until provisioned; do sleep "$POLL_SECONDS"; done
fi
seen="$(fingerprint)"

home="$STATE/home"
install -d -m 0700 "$home/.mero" "$STATE/work"
install -m 0600 "$SECRETS/MERO_AGENTS_JSON" "$home/.mero/agents.json"
# mero-mcp from the bundle: nothing is fetched at run time.
printf '{"mcpServers":{"mero-mcp":{"command":"%s","args":["%s/node_modules/@calimero-network/mero-mcp/dist/index.js"]}}}\n' \
  "$NODE" "$BOT" >"$home/.mero/mcp.json"
chmod 0600 "$home/.mero/mcp.json"

node_dir="$(dirname "$NODE")"
cd "$STATE/work"
# Only what mero-bot needs, set in a subshell's environment: never in an argv,
# where any process in the TD could read it from /proc.
(
  while read -r name; do unset "$name"; done < <(compgen -e)
  export HOME="$home" PATH="$node_dir:/usr/bin:/bin"
  export MERO_BOT_STATE_DIR="$STATE/mero-bot" CALIMERO_MCP_STATE_DIR="$STATE/mcp"
  for name in "${ENV_SECRETS[@]}"; do
    if secret "$name"; then
      export "$name=$(<"$SECRETS/$name")"
    elif [[ "$name" == NEAR_AI_API_KEY && -n "$OPERATOR" && -s "$OPERATOR/$name" ]]; then
      export "$name=$(<"$OPERATOR/$name")"
    fi
  done
  exec "$NODE" "$BOT/dist/cli.js" --headless --fixed-code --attested-only
) &
bot=$!
trap 'kill -TERM "$bot" 2>/dev/null; wait "$bot"; exit 0' TERM INT

while kill -0 "$bot" 2>/dev/null; do
  sleep "$POLL_SECONDS" &
  wait $! || true
  if [[ "$(fingerprint)" != "$seen" ]]; then
    log "secrets changed: restarting mero-bot"
    kill -TERM "$bot" 2>/dev/null || true
    wait "$bot" || true
    # Non-zero: systemd (Restart=on-failure) starts the agent again with the new secrets.
    exit 75
  fi
done
wait "$bot"
