#!/usr/bin/env bash
# An agent TD hosts several owners' agents, one per slot (mero-tee#467,
# mero-agent-gate's slots.rs). This slices the agent-environment block out of
# agent-init.sh.j2 and runs it against stub install / chown / chmod, recording
# every call, then checks the role's units statically. What it pins:
#
#   * slot n's directory, keys and secrets: root:mero-agent-<n> 0750, so only
#     the gate and slot n's group read them; its state: mero-agent-<n> 0700
#   * the data disk and agents/ are 0711: every slot's user passes through to
#     its own slot and lists no other
#   * the agents' environment names the data disk, not one slot's secrets
#   * slot n's operator/ (the operator's NEAR key) is root:mero-agent-<n> 0750;
#     the operator key the gate reads is written only when metadata names one
#   * slot n's unit runs as mero-agent-<n>, writes only its own state, sees no
#     other process, and has a memory limit; the gate stops it by that name
#
# Usage: scripts/ci/tests/agent-init-slots-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="${REPO_ROOT}/mero-tee/ansible/roles/mero-agent"
TEMPLATE="${ROLE}/templates/agent-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- slice the code under test out of the template --------------------------
block_src="$(awk '/^# --- Agent environment/{on=1} /^log "Agent environment/{exit} on{print}' "$TEMPLATE")"
[[ -n "$block_src" ]] || fail "could not find the '# --- Agent environment' block"
grep -qF 'agents/' <<<"$block_src" || fail "the sliced block does not make the slots it is meant to test"
grep -qF '{{' <<<"$block_src" && fail "the sliced block holds Jinja; this test runs it unrendered"
grep -qF 'AGENT_USER_PREFIX="{{ mero_agent_user_prefix }}"' "$TEMPLATE" \
  || fail "agent-init must take the slot users' prefix from the role"
grep -qF 'AGENT_SLOTS="{{ mero_agent_slots }}"' "$TEMPLATE" \
  || fail "agent-init must take the slot count from the role"

# --- stubs: record, do not touch ownership ------------------------------------
BIN="$WORK/bin"
mkdir -p "$BIN"
for tool in install chown chmod; do
  cat >"$BIN/$tool" <<STUB
#!/usr/bin/env bash
echo "$tool \$*" >>"$WORK/calls"
if [[ "$tool" == install ]]; then
  for arg in "\$@"; do [[ "\$arg" == /* ]] && mkdir -p "\$arg"; done
fi
exit 0
STUB
  chmod +x "$BIN/$tool"
done

DATA="$WORK/mnt/agent"
mkdir -p "$DATA" "$WORK/run"
cat >"$WORK/run.sh" <<EOF
set -euo pipefail
PATH="$BIN:\$PATH"
DATA_MOUNT="$DATA"
LOG_DIR="$WORK/run"
RELAY_URL="https://relay.example"
OPERATOR_KEY="\${OPERATOR_KEY:-}"
IMAGE_PROFILE="debug"
AGENT_USER_PREFIX="mero-agent-"
AGENT_SLOTS=3
$block_src
EOF
bash "$WORK/run.sh" || fail "the agent-environment block failed"
[[ -e "$WORK/run/operator.x25519" ]] && fail "wrote an operator key though metadata named none"
calls="$(cat "$WORK/calls")"

expect() { grep -qxF -- "$1" <<<"$calls" || fail "missing: $1"$'\n'"calls:"$'\n'"$calls"; }
expect "chown root:root $DATA"
expect "chmod 0711 $DATA"
expect "install -d -o root -g root -m 0711 $DATA/agents"
for slot in 1 2 3; do
  dir="$DATA/agents/$slot"
  expect "install -d -o root -g mero-agent-$slot -m 0750 $dir $dir/keys $dir/secrets $dir/operator"
  expect "install -d -o mero-agent-$slot -g mero-agent-$slot -m 0700 $dir/state"
done
grep -q "agents/4" <<<"$calls" && fail "made a slot past AGENT_SLOTS"
grep -qE 'mero-agent[^-]' <<<"$calls" && fail "a slot was given the old single agent user"

env_file="$WORK/run/agent.env"
grep -qxF "MERO_AGENT_DATA_DIR=$DATA" "$env_file" || fail "agent.env does not name the data disk: $(cat "$env_file")"
grep -qE 'SECRETS_DIR|STATE_DIR|SIGNING_KEY' "$env_file" \
  && fail "agent.env must not name one slot's secrets, state or key: every slot reads it"

# --- the operator key ----------------------------------------------------------
key="AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
OPERATOR_KEY="$key" bash "$WORK/run.sh" || fail "the agent-environment block failed with an operator key"
[[ "$(cat "$WORK/run/operator.x25519")" == "$key" ]] || fail "the operator key file is not the metadata's key"
[[ "$(stat -c %a "$WORK/run/operator.x25519")" == 600 ]] || fail "the operator key file must be root-only"
grep -qF 'fatal "operator-key is not 32 bytes of base64"' "$TEMPLATE" \
  || fail "agent-init must refuse an operator key that is not 32 bytes"
grep -qxF 'GATE_OPERATOR_KEY_FILE=/run/mero-agent/operator.x25519' "${ROLE}/templates/gate.env.j2" \
  || fail "the gate must read the operator key where agent-init writes it"

# --- the units, statically ----------------------------------------------------
tasks="${ROLE}/tasks/main.yml"
unit="$(awk '/dest: \/etc\/systemd\/system\/mero-agent@.service/{exit} /name: Install mero-agent@.service/{on=1} on{print}' "$tasks")"
[[ -n "$unit" ]] || fail "the role installs no mero-agent@.service"
for line in \
  'User={{ mero_agent_user_prefix }}%i' \
  'Group={{ mero_agent_user_prefix }}%i' \
  'Environment=MERO_AGENT_SLOT=%i' \
  'ReadWritePaths=/mnt/agent/agents/%i/state' \
  'ProtectSystem=strict' \
  'ProtectProc=invisible' \
  'NoNewPrivileges=yes' \
  'CapabilityBoundingSet=' \
  'MemoryMax={{ mero_agent_memory_max }}'; do
  grep -qF -- "$line" <<<"$unit" || fail "mero-agent@.service lacks '$line'"
done
[[ "$(grep -c 'ReadWritePaths=' <<<"$unit")" == 1 ]] || fail "slot units may write their own state and nothing else"
grep -qF 'mero-agent.service' "$tasks" && fail "the single-agent unit is still installed"
grep -qxF 'GATE_SLOT_UNIT=mero-agent@{slot}.service' "${ROLE}/templates/gate.env.j2" \
  || fail "the gate must stop and start slot units by the name the role installs"
grep -qxF 'GATE_SLOT_GROUP_PREFIX={{ mero_agent_user_prefix }}' "${ROLE}/templates/gate.env.j2" \
  || fail "the gate must share slot n's files with the group the role makes for it"

echo "agent-init slots: OK"
