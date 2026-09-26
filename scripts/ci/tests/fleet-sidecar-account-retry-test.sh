#!/usr/bin/env bash
# Behavioural test: a node whose account is not readable at boot still becomes
# a relay once it is.
#
# `EXECUTOR_ACCOUNT` used to be read exactly once, at sidecar startup, on the
# reasoning that the account is fixed for the life of the node. The value is —
# its AVAILABILITY is not. The unit is `After=merod.service`, and `After`
# ORDERS a start, it does not wait for merod to be READY, so on a boot where
# `meroctl account show` had not come up yet the variable stayed empty for the
# life of the process.
#
# `reconcile_registration` returns immediately without an account, so such a
# node never registered. Everything downstream hangs off that registration: no
# NodeCertificate row, so the dispatcher published no A record and ordered no
# certificate, so the name resolved NXDOMAIN and mdma never advertised the node
# as a relay. It replicated and polled the whole time, looking healthy, and no
# log on either side said why — which is what made this cost two rounds of
# guessing to find rather than one grep.
#
# Usage: scripts/ci/tests/fleet-sidecar-account-retry-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

# `meroctl account show` answers only once ${SB}/account-ready exists — exactly
# the boot race: the binary is there, merod behind it is not yet serving.
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  if [[ "${a}" == "account" ]]; then
    [[ -f "${SB}/account-ready" ]] || { echo "error: node is not running" >&2; exit 1; }
    echo "${SB}" >> /dev/null
    echo '{"data":{"accountId":"AABBCC"}}'
    exit 0
  fi
done
exit 1
STUB
chmod +x "${SB}/bin/meroctl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

# The globals the main loop sets up before entering its cycle.
# shellcheck disable=SC2034  # read by reconcile_executor_account, sourced above
SIDECAR_STARTED_AT=$(date +%s)
# shellcheck disable=SC2034  # ditto
LAST_ACCOUNT_ATTEMPT=0
# shellcheck disable=SC2034  # ditto; 0 so the retry never waits on wall clock
ACCOUNT_RETRY_INTERVAL=0
EXECUTOR_ACCOUNT=$(get_executor_account || true)

# --- the boot race ---------------------------------------------------------
[[ -z "${EXECUTOR_ACCOUNT}" ]] \
  || fail "precondition: the account must be unreadable before merod is ready"

reconcile_executor_account
[[ -z "${EXECUTOR_ACCOUNT}" ]] \
  || fail "an account that is still unreadable must not be invented"

# A node with no account must not register a half-identity: there is nothing to
# bind, and recording one would have to be replaced.
: > "${SB}/register-log"
reconcile_registration "12D3KooWAccountRetryPeer" "${EXECUTOR_ACCOUNT}" "https://relay-01.test" 2428
[[ ! -s "${SB}/register-log" ]] || fail "a node with no account must not register"

# --- merod comes up --------------------------------------------------------
# THE REGRESSION. Before the fix this stayed empty forever, and every
# consequence below followed from that one unread value.
touch "${SB}/account-ready"
reconcile_executor_account
[[ "${EXECUTOR_ACCOUNT}" == "aabbcc" ]] \
  || fail "the account must be picked up once merod answers, got '${EXECUTOR_ACCOUNT}'"

grep -q "readable after" "${SB}/fleet.log" \
  || fail "recovering from the boot race must say so in the log"

# --- and it stops costing anything -----------------------------------------
# Once known, the account is fixed for the life of the node: re-reading it on a
# 1 Hz loop would fork `meroctl` forever for a value that cannot change.
before="$(wc -c < "${SB}/fleet.log")"
reconcile_executor_account
reconcile_executor_account
[[ "${EXECUTOR_ACCOUNT}" == "aabbcc" ]] || fail "a known account must not be re-read"
[[ "$(wc -c < "${SB}/fleet.log")" == "${before}" ]] \
  || fail "a known account must produce no further log traffic"

echo "PASS: fleet sidecar executor-account retry"
