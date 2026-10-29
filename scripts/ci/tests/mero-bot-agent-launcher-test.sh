#!/usr/bin/env bash
# The agent image's mero-bot launcher (scripts/agent/mero-bot-agent.sh), run
# against a stand-in for Node that records how it was started and then waits.
# What it pins:
#
#   * it finds its slot's secrets and state from MERO_AGENT_DATA_DIR and
#     MERO_AGENT_SLOT, and refuses a slot that is not a number
#   * on a node (CALIMERO_NODE_URL provisioned), nothing starts until
#     MERO_AGENTS_JSON and a node login are provisioned too
#   * as an account of its own (no node), MERO_AGENTS_JSON is enough: the
#     account's root is the slot's signing key, its account and the
#     invitations provisioned as MERO_INVITATION.* are in the slot's state, and
#     mero-mcp acts as the same account; a new invitation restarts it
#   * mero-bot runs headless, with --fixed-code and --attested-only
#   * its environment is HOME, PATH, its state dirs and the allowlisted secrets:
#     no other secret (NODE_OPTIONS included) and nothing from the launcher's
#     own environment
#   * no secret value is ever in an argv
#   * agents.json is the provisioned one; mcp.json starts the bundle's mero-mcp
#   * NEAR_AI_API_KEY comes from the operator's operator/ unless the owner set one
#   * provisioning again, by the owner or the operator, stops mero-bot and exits
#     non-zero (systemd restarts it)
#   * SIGTERM stops mero-bot and exits 0
#
# Usage: scripts/ci/tests/mero-bot-agent-launcher-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LAUNCHER="${ROOT}/scripts/agent/mero-bot-agent.sh"
WORK="$(mktemp -d)"
trap 'pkill -P $$ 2>/dev/null || true; rm -rf "${WORK:?}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# Stand-in for /opt/node/bin/node: records its argv and environment, then waits.
# Slot 3's directory, as agent-init makes it; the launcher derives it.
SLOT_DIR="${WORK}/data/agents/3"
mkdir -p "${WORK}/node/bin" "${WORK}/bot/dist" "${SLOT_DIR}/secrets" "${SLOT_DIR}/operator" "${SLOT_DIR}/state"
cat >"${WORK}/node/bin/node" <<EOF
#!/usr/bin/env bash
echo "\$\$" >"${WORK}/pid"
printf '%s\n' "\$@" >"${WORK}/argv"
# PWD, SHLVL and _ are set by bash for this stand-in itself, not by the launcher.
env | sed 's/=.*//' | grep -vxE 'PWD|OLDPWD|SHLVL|_' | sort >"${WORK}/env-names.tmp"
env >"${WORK}/env"
# env-names is what the test waits for, so it lands last, whole: env is
# already this run's when the test reads it.
mv "${WORK}/env-names.tmp" "${WORK}/env-names"
trap 'echo stopped >"${WORK}/stopped"; exit 0' TERM
while :; do sleep 0.1; done
EOF
chmod +x "${WORK}/node/bin/node"

export MERO_AGENT_DATA_DIR="${WORK}/data"
export MERO_BOT_DIR="${WORK}/bot" MERO_BOT_NODE="${WORK}/node/bin/node" MERO_BOT_POLL_SECONDS=0.2
export LAUNCHER_HOST_SECRET=must-not-leak

# Waits up to 10s for a file the stand-in writes.
wait_file() {
  local i
  for ((i = 0; i < 100; i++)); do
    if [[ -s "$1" ]]; then return 0; fi
    sleep 0.1
  done
  fail "timed out waiting for $1"
}

secret() { printf '%s' "$2" >"${SLOT_DIR}/secrets/$1"; }
operator_secret() { printf '%s' "$2" >"${SLOT_DIR}/operator/$1"; }

# --- Its slot -----------------------------------------------------------------
for bad in "" "0" "../1" "1/../2" "x"; do
  if MERO_AGENT_SLOT="$bad" bash "${LAUNCHER}" >"${WORK}/bad-slot.log" 2>&1; then
    fail "the launcher ran with slot '${bad}'"
  fi
done
export MERO_AGENT_SLOT=3

# --- Waits for provisioning ---------------------------------------------------
bash "${LAUNCHER}" >"${WORK}/log" 2>&1 &
launcher=$!
sleep 1
[[ ! -e "${WORK}/argv" ]] || fail "mero-bot started before anything was provisioned"
grep -q "waiting for the owner" "${WORK}/log" || fail "no waiting line: $(cat "${WORK}/log")"

secret CALIMERO_NODE_URL "https://node.example"
operator_secret NEAR_AI_API_KEY "near-operator-value"
operator_secret MERO_INFERENCE_API_KEY "inference-operator-value"
# Only the operator's own names: anything else in operator/ never reaches mero-bot.
operator_secret HYPERFEED_CONTEXT "operator-picked-feed"
sleep 0.5
[[ ! -e "${WORK}/argv" ]] || fail "mero-bot started with no agents.json or node login"
secret CALIMERO_AUTH_TOKEN "auth-secret-value"
secret NODE_OPTIONS "--require /tmp/evil.js"
secret UNRELATED "unrelated-secret-value"
secret MERO_AGENTS_JSON '{"agents":{"near":{"runtime":"openai","attest":"near","model":"m"}},"default":"near"}'
wait_file "${WORK}/env-names"

# --- How it started -------------------------------------------------------------
expected_argv="${WORK}/bot/dist/cli.js
--headless
--fixed-code
--attested-only"
[[ "$(cat "${WORK}/argv")" == "${expected_argv}" ]] || fail "argv: $(cat "${WORK}/argv")"

expected_env="CALIMERO_AUTH_TOKEN
CALIMERO_MCP_STATE_DIR
CALIMERO_NODE_URL
HOME
MERO_BOT_STATE_DIR
MERO_INFERENCE_API_KEY
NEAR_AI_API_KEY
PATH"
[[ "$(cat "${WORK}/env-names")" == "${expected_env}" ]] || fail "environment: $(tr '\n' ' ' <"${WORK}/env-names")"
grep -qx "NEAR_AI_API_KEY=near-operator-value" "${WORK}/env" || fail "NEAR_AI_API_KEY not taken from the operator's"
grep -qx "MERO_INFERENCE_API_KEY=inference-operator-value" "${WORK}/env" || fail "MERO_INFERENCE_API_KEY not taken from the operator's"
grep -qx "HOME=${SLOT_DIR}/state/home" "${WORK}/env" || fail "HOME is not on the state dir"

for pid in "$(cat "${WORK}/pid")" "${launcher}"; do
  if tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -qE 'secret-value'; then
    fail "a secret is in the argv of pid ${pid}"
  fi
done

cmp -s "${SLOT_DIR}/secrets/MERO_AGENTS_JSON" "${SLOT_DIR}/state/home/.mero/agents.json" || fail "agents.json is not the provisioned one"
jq -e --arg node "${WORK}/node/bin/node" --arg mcp "${WORK}/bot/node_modules/@calimero-network/mero-mcp/dist/index.js" \
  '.mcpServers["mero-mcp"] == {command: $node, args: [$mcp]}' "${SLOT_DIR}/state/home/.mero/mcp.json" >/dev/null \
  || fail "mcp.json: $(cat "${SLOT_DIR}/state/home/.mero/mcp.json")"

# --- Provisioning again restarts it -----------------------------------------------
# The operator's new NEAR key is a new secret too.
operator_secret NEAR_AI_API_KEY "near-rotated-value"
set +e
wait "${launcher}"
code=$?
set -e
[[ ${code} -eq 75 ]] || fail "after new secrets the launcher exited ${code}, not 75"
[[ -e "${WORK}/stopped" ]] || fail "mero-bot was not stopped before the launcher exited"
grep -q "secrets changed" "${WORK}/log" || fail "no restart line: $(cat "${WORK}/log")"

# --- SIGTERM stops it cleanly -------------------------------------------------------
rm -f "${WORK}/argv" "${WORK}/env-names" "${WORK}/env" "${WORK}/stopped"
bash "${LAUNCHER}" >"${WORK}/log" 2>&1 &
launcher=$!
wait_file "${WORK}/env-names"
grep -qx "NEAR_AI_API_KEY=near-rotated-value" "${WORK}/env" || fail "the restarted mero-bot did not get the operator's new key"
# The owner's own key, if it sets one, wins over the operator's.
secret NEAR_AI_API_KEY "near-owner-value"
set +e
wait "${launcher}"
code=$?
set -e
[[ ${code} -eq 75 ]] || fail "after the owner's key the launcher exited ${code}, not 75"
rm -f "${WORK}/argv" "${WORK}/env-names" "${WORK}/env" "${WORK}/stopped"
bash "${LAUNCHER}" >"${WORK}/log" 2>&1 &
launcher=$!
wait_file "${WORK}/env-names"
grep -qx "NEAR_AI_API_KEY=near-owner-value" "${WORK}/env" || fail "the owner's NEAR key did not win over the operator's"
kill -TERM "${launcher}"
set +e
wait "${launcher}"
code=$?
set -e
[[ ${code} -eq 0 ]] || fail "SIGTERM: the launcher exited ${code}, not 0"
[[ -e "${WORK}/stopped" ]] || fail "SIGTERM did not reach mero-bot"

# --- As an account of its own ---------------------------------------------------------
SLOT_DIR="${WORK}/data/agents/4"
mkdir -p "${SLOT_DIR}/secrets" "${SLOT_DIR}/operator" "${SLOT_DIR}/state" "${SLOT_DIR}/keys"
export MERO_AGENT_SLOT=4
rm -f "${WORK}/argv" "${WORK}/env-names" "${WORK}/env" "${WORK}/stopped"
secret MERO_AGENTS_JSON '{"agents":{"near":{"runtime":"openai","attest":"near","model":"m"}},"default":"near"}'
secret MERO_INVITATION.feed '{"namespaceId":"aa","invitation":{}}'
secret MERO_INVITATION_NOT '{"not":"an invitation by name"}'
bash "${LAUNCHER}" >"${WORK}/log" 2>&1 &
launcher=$!
wait_file "${WORK}/env-names"
expected_env="CALIMERO_MCP_STATE_DIR
HOME
MERO_BOT_ACCOUNT_DIR
MERO_BOT_ACCOUNT_ROOT_FILE
MERO_BOT_INVITATIONS_DIR
MERO_BOT_STATE_DIR
PATH"
[[ "$(cat "${WORK}/env-names")" == "${expected_env}" ]] || fail "account environment: $(tr '\n' ' ' <"${WORK}/env-names")"
grep -qx "MERO_BOT_ACCOUNT_ROOT_FILE=${SLOT_DIR}/keys/signing.ed25519" "${WORK}/env" || fail "the account root is not the slot's signing key"
grep -qx "MERO_BOT_ACCOUNT_DIR=${SLOT_DIR}/state/account" "${WORK}/env" || fail "the account is not in the slot's state"
[[ "$(ls "${SLOT_DIR}/state/invitations")" == "MERO_INVITATION.feed" ]] || fail "invitations: $(ls "${SLOT_DIR}/state/invitations")"
cmp -s "${SLOT_DIR}/secrets/MERO_INVITATION.feed" "${SLOT_DIR}/state/invitations/MERO_INVITATION.feed" || fail "the invitation was not copied as provisioned"
jq -e --arg dir "${SLOT_DIR}/state/account" '.mcpServers["mero-mcp"].env == {CALIMERO_ACCOUNT_DIR: $dir}' \
  "${SLOT_DIR}/state/home/.mero/mcp.json" >/dev/null || fail "mero-mcp does not act as the account: $(cat "${SLOT_DIR}/state/home/.mero/mcp.json")"
# A new invitation restarts it, to join.
secret MERO_INVITATION.team '{"namespaceId":"bb","invitation":{}}'
set +e
wait "${launcher}"
code=$?
set -e
[[ ${code} -eq 75 ]] || fail "after a new invitation the launcher exited ${code}, not 75"

echo "OK: the mero-bot launcher waits for provisioning, passes only its secrets, and restarts on new ones"
