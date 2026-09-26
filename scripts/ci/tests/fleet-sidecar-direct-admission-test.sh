#!/usr/bin/env bash
# Direct TEE admission: the sidecar tells mdma where it can be dialed, and asks
# the peers mdma names for admission instead of relying on the broadcast alone.
#
# A fleet node used to be admitted only by announcing its attestation on the
# namespace's gossip topic and waiting for an admin or admitted TEE to hear it.
# When the only such peer is an owner's laptop behind a relay, that mesh may
# never form, and the node polls happily while never being admitted. Core's
# `fleet-join --admitter-addr` asks named peers over a stream instead.
#
# What fails quietly without this test:
#   * reporting merod's external addresses verbatim -- they usually lack
#     `/p2p/<peer id>`, and core cannot dial an address that names no peer;
#   * treating a relay-circuit address as already complete because it contains
#     `/p2p/` -- it names the RELAY's peer, not ours;
#   * passing one group's admitters to another group's join;
#   * passing `--admitter-addr` to a meroctl that predates it, which fails EVERY
#     fleet-join on an unknown flag -- strictly worse than broadcast-only.
#
# Usage: scripts/ci/tests/fleet-sidecar-direct-admission-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/var/log/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/var/lib/calimero/@${SB}/@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

PEER="12D3KooWSelfPeer"
RELAY="12D3KooWRelayPeer"

# meroctl stub: `network status` from a fixture, `tee fleet-join --help` with or
# without the flag depending on ${SB}/old, and `tee fleet-join` records argv.
cat > "${SB}/bin/meroctl" <<STUB
#!/usr/bin/env bash
args="\$*"
case "\${args}" in
  *"network status"*)
    cat <<JSON
{"localPeerId":"${PEER}","listenAddrs":["/ip4/0.0.0.0/udp/2528/quic-v1"],"externalAddrs":["/ip4/34.178.148.140/udp/2528/quic-v1","/ip4/34.178.148.140/tcp/2528/p2p/${PEER}","/ip4/9.9.9.9/udp/4001/quic-v1/p2p/${RELAY}/p2p-circuit"]}
JSON
    ;;
  *"fleet-join --help"*)
    if [[ -f "\${SB}/old" ]]; then echo "Usage: meroctl tee fleet-join <GROUP_ID>"; else echo "Usage: meroctl tee fleet-join [--admitter-addr <MULTIADDR>] <GROUP_ID>"; fi
    ;;
  *"fleet-join"*)
    printf '%s\n' "\$@" > "\${SB}/join_argv"
    echo '{"data":{"admitted":true}}'
    ;;
  *) exit 1 ;;
esac
STUB
chmod +x "${SB}/bin/meroctl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"
# shellcheck disable=SC2034  # read by the sourced sidecar functions
MEROCTL="meroctl"

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- swarm addresses end in OUR peer id -------------------------------------
got="$(read_swarm_addrs)"
want="[\"/ip4/34.178.148.140/udp/2528/quic-v1/p2p/${PEER}\", \"/ip4/34.178.148.140/tcp/2528/p2p/${PEER}\", \"/ip4/9.9.9.9/udp/4001/quic-v1/p2p/${RELAY}/p2p-circuit/p2p/${PEER}\"]"
[[ "$got" == "$want" ]] || fail "swarm addresses: got ${got}, want ${want}"

# Cached in a file, so the 1 Hz poll does not run meroctl every second.
[[ "$(cached_swarm_addrs)" == "$want" ]] || fail "cached_swarm_addrs must return the same list"
[[ -f "${SB}/fleet-swarm-addrs.json" ]] || fail "the swarm-address cache must be a file"

# --- the join passes THIS group's admitters, in order -----------------------
RESPONSE='{"assignments":[
  {"group_id":"aa","admitter_addrs":["/ip4/1.1.1.1/tcp/2528/p2p/12D3KooWFleet","/ip4/2.2.2.2/tcp/1/p2p/12D3KooWOwner"]},
  {"group_id":"bb","admitter_addrs":["/ip4/3.3.3.3/tcp/1/p2p/12D3KooWOther"]}
]}'
join_group "aa" "$RESPONSE" >/dev/null 2>&1 || fail "join_group must succeed against the stub"
expected="tee
fleet-join
aa
--admitter-addr
/ip4/1.1.1.1/tcp/2528/p2p/12D3KooWFleet
--admitter-addr
/ip4/2.2.2.2/tcp/1/p2p/12D3KooWOwner"
tail -n +3 "${SB}/join_argv" > "${SB}/join_tail"
[[ "$(cat "${SB}/join_tail")" == "$expected" ]] \
  || fail "fleet-join argv: $(cat "${SB}/join_tail")"
grep -q "12D3KooWOther" "${SB}/join_argv" && fail "another group's admitter must not be passed"

# --- no response: the join still happens, by broadcast ----------------------
join_group "aa" >/dev/null 2>&1 || fail "join_group without a response must still join"
grep -q -- "--admitter-addr" "${SB}/join_argv" && fail "no response means no admitter flags"

# --- an older meroctl never sees the flag -----------------------------------
touch "${SB}/old"
# shellcheck disable=SC2034  # the sourced probe caches its answer here
FLEET_JOIN_TAKES_ADMITTERS=""
join_group "aa" "$RESPONSE" >/dev/null 2>&1 || fail "join_group must still succeed on an older meroctl"
grep -q -- "--admitter-addr" "${SB}/join_argv" \
  && fail "--admitter-addr must not be passed to a meroctl that lacks it"
grep -q "broadcast-only" "${SB}/fleet.log" || fail "an older meroctl must be noted in the log"

echo "PASS: fleet-sidecar direct admission"
