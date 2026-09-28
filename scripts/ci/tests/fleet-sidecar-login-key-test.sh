#!/usr/bin/env bash
# Behavioural test: the sidecar records the node key device-key login needs,
# and restarts mero-auth only when that key changes.
#
# mero-auth's `account_proof` provider needs this node's device signing key,
# which only merod knows (`GET /admin-api/identity`, `publicKey`).
# `reconcile_login_node_key` reads it, records it for `mero-auth-start`, and
# restarts mero-auth so the provider comes up. It must:
#
#   * do nothing on a non-relay image;
#   * do nothing while merod has no key (404), and not invent one;
#   * record a key and restart mero-auth once;
#   * NOT restart again for the same key: a restart drops forwardAuth for every
#     caller on the node;
#   * record and restart again when merod's key changes;
#   * not restart for a key recorded before mero-auth's current run began,
#     which `mero-auth-start` has already read.
#
# Usage: scripts/ci/tests/fleet-sidecar-login-key-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/etc/calimero/device-key-login@${SB}/device-key-login@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

# merod's identity route: answers with ${SB}/identity.json, or 404 without it.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  if [[ "${a}" == */admin-api/identity ]]; then
    [[ -f "${SB}/identity.json" ]] || exit 22
    cat "${SB}/identity.json"
    exit 0
  fi
done
exit 7
STUB
# systemctl: records restarts; mero-auth's current run began at ${SB}/started-at.
cat > "${SB}/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  restart) echo "$2" >> "${SB}/restarts"; date +%s > "${SB}/started-at" ;;
  show)
    [[ -f "${SB}/started-at" ]] || { echo ""; exit 0; }
    date -d "@$(cat "${SB}/started-at")" ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${SB}/bin/curl" "${SB}/bin/systemctl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
restarts() { [[ -f "${SB}/restarts" ]] && wc -l < "${SB}/restarts" | tr -d ' ' || echo 0; }
identity() { printf '{"data":{"accountId":"aa","publicKey":"%s"}}' "$1" > "${SB}/identity.json"; }
# Each call re-checks immediately: the clocks are the loop's business, not this test's.
# shellcheck disable=SC2034  # read by reconcile_login_node_key, sourced above
pass() { LOGIN_NODE_KEY_NEXT_CHECK=0; reconcile_login_node_key; }

# shellcheck disable=SC2034  # read by the sourced functions
SERVER_PORT=2428
LOGIN_NODE_KEY_ACTIVE=""
KEY_A="$(printf 'a%.0s' {1..64})"
KEY_B="$(printf 'b%.0s' {1..64})"

# --- a non-relay image does nothing ----------------------------------------
identity "${KEY_A}"
pass
[[ ! -e "${LOGIN_NODE_KEY_FILE}" && "$(restarts)" == 0 ]] || fail "a non-relay image must record nothing and restart nothing"

# From here on, a relay image.
touch "${SB}/device-key-login"

# --- merod has no key yet ---------------------------------------------------
rm -f "${SB}/identity.json"
pass
[[ ! -e "${LOGIN_NODE_KEY_FILE}" && "$(restarts)" == 0 ]] || fail "no key must be invented while merod answers 404"

# A key that is not 64 hex is not one either.
identity "not-a-key"
pass
[[ ! -e "${LOGIN_NODE_KEY_FILE}" && "$(restarts)" == 0 ]] || fail "a malformed publicKey must not be recorded"

# --- merod names a key: recorded, mero-auth restarted once ------------------
identity "${KEY_A}"
pass
[[ "$(cat "${LOGIN_NODE_KEY_FILE}")" == "${KEY_A}" ]] || fail "the key must be recorded"
[[ "$(restarts)" == 1 ]] || fail "mero-auth must restart once to pick the key up"
[[ "$(stat -c %a "${LOGIN_NODE_KEY_FILE}")" == 600 ]] || fail "the key file must be written 0600"

# --- the same key again: no restart -----------------------------------------
pass
pass
[[ "$(restarts)" == 1 ]] || fail "an unchanged key must not restart mero-auth"

# --- merod re-keys: recorded and restarted -----------------------------------
identity "${KEY_B}"
pass
[[ "$(cat "${LOGIN_NODE_KEY_FILE}")" == "${KEY_B}" ]] || fail "a changed key must be recorded"
[[ "$(restarts)" == 2 ]] || fail "a changed key must restart mero-auth"

# --- a fresh sidecar, key recorded before mero-auth started ------------------
# The next boot: the file is already there and mero-auth-start read it.
LOGIN_NODE_KEY_ACTIVE=""
touch -d "@$(( $(date +%s) - 120 ))" "${LOGIN_NODE_KEY_FILE}"
date +%s > "${SB}/started-at"
pass
[[ "$(restarts)" == 2 ]] || fail "a key mero-auth already started with must not restart it"
[[ "${LOGIN_NODE_KEY_ACTIVE}" == "${KEY_B}" ]] || fail "the sidecar must learn which key mero-auth runs with"

# --- a fresh sidecar, key recorded AFTER mero-auth started --------------------
# The last sidecar wrote the file and died before the restart went through.
LOGIN_NODE_KEY_ACTIVE=""
echo "$(( $(date +%s) - 120 ))" > "${SB}/started-at"
touch "${LOGIN_NODE_KEY_FILE}"
pass
[[ "$(restarts)" == 3 ]] || fail "a key mero-auth has not read must restart it"

echo "OK: the sidecar records merod's node key and restarts mero-auth only on change"
