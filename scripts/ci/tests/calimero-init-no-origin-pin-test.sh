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

echo "OK: calimero-init pins no browser origin and drops the one 2.3.109 wrote"
