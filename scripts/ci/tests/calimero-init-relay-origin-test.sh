#!/usr/bin/env bash
# A relay lists only its own origin in merod's `server.cors.allowed_origins`.
#
# merod in proxy auth mode serves a browser only pages whose host it recognises,
# because under DNS rebinding a page sends its own name as both Origin and Host.
# A relay's dashboard is served under its relay host name, so calimero-init lists
# that origin. `relay-url` is instance metadata, which the host sets: only an
# `https://` URL on a plain DNS name yields an origin, and nothing else from it
# reaches the TOML value `merod config` writes.
#
# Runs calimero-init's real `relay_origin`, extracted from the template.
#
# Usage: scripts/ci/tests/calimero-init-relay-origin-test.sh
# The greps below match literal template text, `$(...)` included.
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INIT="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

sed -n '/^relay_origin() {$/,/^}$/p' "${INIT}" > "${SB}/fn.sh"
grep -q '^relay_origin() {$' "${SB}/fn.sh" || fail "no relay_origin in calimero-init"
grep -q 'RELAY_ORIGIN=$(relay_origin "$RELAY_URL")' "${INIT}" \
  || fail "calimero-init does not derive the origin through relay_origin"
grep -q '"server.cors.allowed_origins=\[\\"${RELAY_ORIGIN}\\"\]"' "${INIT}" \
  || fail "calimero-init does not list RELAY_ORIGIN in server.cors.allowed_origins"

# relay-url in, origin out. Empty means nothing is listed.
CASES=(
  "https://node-1.relay.calimero.network|https://node-1.relay.calimero.network"
  "https://Node-1.Relay.Example/contexts?x=1|https://node-1.relay.example"
  "https://node.example:8443/|https://node.example:8443"
  "http://node.example|"
  "https://node|"
  "https://evil..example|"
  "https://-bad.example|"
  "https://node.example\"];x=[\"|"
  "https://node.example\$(id)|"
  "https://user@node.example|"
  "javascript:alert(1)|"
  "|"
)

for case in "${CASES[@]}"; do
  value="${case%%|*}"
  want="${case#*|}"
  # shellcheck source=/dev/null
  got=$(source "${SB}/fn.sh"; relay_origin "${value}")
  [[ "${got}" == "${want}" ]] || fail "relay-url '${value}': got '${got}', want '${want}'"
done

echo "OK: calimero-init lists only an https relay origin on a DNS name"
