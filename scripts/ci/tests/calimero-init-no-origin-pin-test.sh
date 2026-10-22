#!/usr/bin/env bash
# A relay pins no browser origin in merod's `server.cors.allowed_origins`.
#
# merod admits browser pages from any origin on a node that takes callers'
# identity from the proxy (`server.proxy_identity=true`): the proxy, not the
# page's origin, says who the caller is. `allowed_origins` is also merod's CORS
# allow-list, so image 2.3.109, which listed the relay's own origin for the
# origin guard, had every hosted app refused by the browser. calimero-init must
# write no such list.
#
# config.toml lives on the data disk and `merod config` only sets keys, so a
# node that first booted on 2.3.109 still carries the line. calimero-init drops
# it, and this runs the real `drop_allowed_origins`, extracted from the
# template, against the shapes it has to tell apart.
#
# Usage: scripts/ci/tests/calimero-init-no-origin-pin-test.sh
# The greps below match literal template text, `$(...)` included.
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INIT="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# Comments stripped: the template EXPLAINS why no origin is listed, and matching
# that prose would fail the very file that gets it right.
code="$(grep -vE '^[[:space:]]*#' "${INIT}")"
grep -q 'server.cors.allowed_origins=' <<<"${code}" \
  && fail "calimero-init still writes server.cors.allowed_origins"
grep -q 'relay_origin\|RELAY_ORIGIN' <<<"${code}" \
  && fail "calimero-init still derives a relay origin"
grep -q "'server.proxy_identity=true'" <<<"${code}" \
  || fail "calimero-init no longer sets server.proxy_identity, which is what admits any origin"
grep -q 'drop_allowed_origins "$NODE_CONFIG"' <<<"${code}" \
  || fail "calimero-init does not drop a persisted allowed_origins from config.toml"

sed -n '/^drop_allowed_origins() {$/,/^}$/p' "${INIT}" > "${SB}/fn.sh"
grep -q '^drop_allowed_origins() {$' "${SB}/fn.sh" || fail "no drop_allowed_origins in calimero-init"

# A 2.3.109 config.toml: `merod init` wrote [server.cors] with its default, then
# `merod config` appended the list. Another table's `allowed_origins` is not ours.
pinned="${SB}/pinned.toml"
printf '%s\n' \
  '[identity]' \
  'peer_id = "12D3KooWSelf"' \
  '' \
  '[server]' \
  'proxy_identity = true' \
  '' \
  '[server.cors]' \
  'allow_private_network = true' \
  'allowed_origins = ["https://node-1.relay.calimero.network"]' \
  '' \
  '[server.admin]' \
  'delegated_access = true' \
  '' \
  '[other]' \
  'allowed_origins = ["https://keep.example"]' \
  > "${pinned}"
chmod 600 "${pinned}"
# shellcheck source=/dev/null
(source "${SB}/fn.sh"; drop_allowed_origins "${pinned}") || fail "drop_allowed_origins failed on a pinned config"
grep -q 'node-1.relay.calimero.network' "${pinned}" && fail "the relay origin is still listed"
grep -q '^allow_private_network = true$' "${pinned}" || fail "[server.cors] lost allow_private_network"
grep -q '^\[server.cors\]$' "${pinned}" || fail "[server.cors] header is gone"
grep -q '^allowed_origins = \["https://keep.example"\]$' "${pinned}" || fail "another table's allowed_origins was dropped"
grep -q '^proxy_identity = true$' "${pinned}" || fail "proxy_identity was dropped"
grep -q '^delegated_access = true$' "${pinned}" || fail "delegated_access was dropped"
grep -q '^peer_id = "12D3KooWSelf"$' "${pinned}" || fail "the identity was dropped"
mode="$(stat -c '%a' "${pinned}" 2>/dev/null || stat -f '%Lp' "${pinned}")"
[[ "${mode}" == "600" ]] || fail "config.toml mode changed to ${mode}, want 600"
ls "${SB}"/pinned.toml.* >/dev/null 2>&1 && fail "a temp file was left beside config.toml"

# [server.cors] as the last table: the range runs to the end of the file.
last="${SB}/last.toml"
printf '%s\n' '[server]' 'proxy_identity = true' '' '[server.cors]' 'allowed_origins = ["https://node.example"]' > "${last}"
# shellcheck source=/dev/null
(source "${SB}/fn.sh"; drop_allowed_origins "${last}") || fail "drop_allowed_origins failed with [server.cors] last"
grep -q 'allowed_origins' "${last}" && fail "the list survived with [server.cors] last"
grep -q '^\[server.cors\]$' "${last}" || fail "[server.cors] header is gone when last"

# Nothing listed: the file is not rewritten at all.
clean="${SB}/clean.toml"
printf '%s\n' '[server]' 'proxy_identity = true' '' '[server.cors]' 'allow_private_network = true' > "${clean}"
cp "${clean}" "${SB}/clean.want"
touch -t 200001010000 "${clean}"
mtime() { stat -c '%Y' "$1" 2>/dev/null || stat -f '%m' "$1"; }
before="$(mtime "${clean}")"
# shellcheck source=/dev/null
(source "${SB}/fn.sh"; drop_allowed_origins "${clean}") || fail "drop_allowed_origins failed on a clean config"
cmp -s "${clean}" "${SB}/clean.want" || fail "a clean config was changed"
[[ "$(mtime "${clean}")" == "${before}" ]] || fail "a clean config was rewritten"

# --- app hosts ----------------------------------------------------------------
# With a relay URL, merod serves each app on `<app id>.<host>` and takes the
# proxy's word for the caller there. Without one there is no host to name.
grep -q 'RELAY_URL=$(get_meta "relay-url"' <<<"${code}" || fail "calimero-init does not read relay-url"
sed -n '/^relay_host() {$/,/^}$/p;/^configure_app_host() {$/,/^}$/p' "${INIT}" > "${SB}/app.sh"
grep -q '^configure_app_host() {$' "${SB}/app.sh" || fail "no configure_app_host in calimero-init"
grep -q '^configure_app_host$' <<<"${code}" || fail "calimero-init never calls configure_app_host"

mkdir -p "${SB}/bin"
cat > "${SB}/bin/merod" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${SB}/merod.calls"
[[ -z "${MEROD_REFUSES:-}" ]] || exit 1
[[ -z "${MEROD_REFUSES_ONLY:-}" || "$*" != *"${MEROD_REFUSES_ONLY}"* ]]
STUB
chmod +x "${SB}/bin/merod"
export SB
run_app_host() (
  # shellcheck source=/dev/null
  source "${SB}/app.sh"
  # Called by the sourced function, not by this script.
  # shellcheck disable=SC2317,SC2329
  log() { echo "$*" >> "${SB}/log"; }
  export BIN_DIR="${SB}/bin" CALIMERO_HOME=/h CALIMERO_NODE=n RELAY_URL="$1"
  configure_app_host
)

: > "${SB}/merod.calls"; : > "${SB}/log"
run_app_host "https://relay-07.relay.calimero.test" || fail "configure_app_host failed with a relay url"
grep -qF 'server.apps.base_domain="relay-07.relay.calimero.test"' "${SB}/merod.calls" || fail "base_domain not set to the relay host"
grep -qF 'server.apps.trust_proxy=true' "${SB}/merod.calls" || fail "trust_proxy not set"
# One key per call: a merod that knows only base_domain refuses a call naming both.
[[ "$(grep -c 'server.apps' "${SB}/merod.calls")" == "2" ]] || fail "each server.apps key needs its own merod call"
! grep 'base_domain' "${SB}/merod.calls" | grep -q 'trust_proxy' || fail "base_domain and trust_proxy share a merod call"

: > "${SB}/merod.calls"
run_app_host "" || fail "configure_app_host failed with no relay url"
[[ ! -s "${SB}/merod.calls" ]] || fail "merod was configured with no relay url"

# A merod that refuses a key: warn, never abort the boot.
: > "${SB}/merod.calls"; : > "${SB}/log"
MEROD_REFUSES=1 run_app_host "https://relay-07.relay.calimero.test" || fail "a merod refusing the keys aborted the boot"
grep -q 'WARN' "${SB}/log" || fail "a refused key must be warned about"

# A merod that serves files but predates trust_proxy: base_domain still lands.
: > "${SB}/merod.calls"; : > "${SB}/log"
MEROD_REFUSES_ONLY=trust_proxy run_app_host "https://relay-07.relay.calimero.test" || fail "a merod without trust_proxy aborted the boot"
grep -qF 'server.apps.base_domain=' "${SB}/merod.calls" || fail "base_domain must be set before trust_proxy is tried"
[[ "$(grep -c WARN "${SB}/log")" == "1" ]] || fail "only the refused trust_proxy call may warn"

echo "OK: calimero-init pins no browser origin and drops the one 2.3.109 wrote"
