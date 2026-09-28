#!/usr/bin/env bash
# Port values read from instance metadata must be ports.
#
# `server-port` and `swarm-port` are instance metadata, which the host sets.
# calimero-init hands them to `merod init`, and the fleet sidecar puts
# `server-port` into its loopback attest URL. Anything but a decimal number from
# 1 to 65535 falls back to the default.
#
# Runs the real functions: calimero-init's `metadata_port`, extracted from the
# template, and the sidecar's `get_server_port` from its function half, each
# against a stubbed metadata value.
#
# Usage: scripts/ci/tests/metadata-port-test.sh
# The greps below match literal template text, `$(...)` included.
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INIT="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"
SIDECAR="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

fail() { echo "FAIL: $*" >&2; exit 1; }

# Values in, what each function must answer. `@` and `/` would move the host
# or path of a URL built from the value.
CASES=(
  "2428:2428"
  "8080:8080"
  "65535:65535"
  "02428:2428"
  ":DEFAULT"
  "0:DEFAULT"
  "65536:DEFAULT"
  "123456:DEFAULT"
  "-1:DEFAULT"
  "2428 :DEFAULT"
  "1@evil.example:DEFAULT"
  "2428/../x:DEFAULT"
  "\$(id):DEFAULT"
)

# --- calimero-init: metadata_port ------------------------------------------
sed -n '/^metadata_port() {$/,/^}$/p' "${INIT}" > "${SB}/init-fn.sh"
grep -q '^metadata_port() {$' "${SB}/init-fn.sh" || fail "no metadata_port in calimero-init"
grep -q 'SERVER_PORT=$(metadata_port "server-port" 2428)' "${INIT}" \
  || fail "calimero-init does not read server-port through metadata_port"
grep -q 'SWARM_PORT=$(metadata_port "swarm-port" 2528)' "${INIT}" \
  || fail "calimero-init does not read swarm-port through metadata_port"

for case in "${CASES[@]}"; do
  value="${case%:*}"
  want="${case##*:}"
  [[ "${want}" == "DEFAULT" ]] && want=2428
  got=$(VALUE="${value}" bash -c '
    log() { echo "$*"; }  # as the real one does: stdout too
    get_meta() { printf "%s" "${VALUE}"; }
    source "$1"
    metadata_port server-port 2428
  ' _ "${SB}/init-fn.sh")
  [[ "${got}" == "${want}" ]] \
    || fail "calimero-init: server-port '${value}' gave '${got}', expected '${want}'"
done

# --- fleet sidecar: get_server_port ----------------------------------------
sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${SIDECAR}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

mkdir -p "${SB}/bin"
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  if [[ "${a}" == *metadata.google.internal*server-port* ]]; then
    printf '%s' "$(cat "${SB}/server-port")"
    exit 0
  fi
done
exit 1
STUB
chmod +x "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

for case in "${CASES[@]}"; do
  value="${case%:*}"
  want="${case##*:}"
  [[ "${want}" == "DEFAULT" ]] && want=2428
  printf '%s' "${value}" > "${SB}/server-port"
  got=$(get_server_port)
  [[ "${got}" == "${want}" ]] \
    || fail "fleet sidecar: server-port '${value}' gave '${got}', expected '${want}'"
done

echo "PASS: port metadata is a port or the default"
