#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's account-recovery-envelope writer.
#
# This is the writer `PUT /api/fleet/recovery-envelope` never had (mdma#223).
# Without it, holding a root key recovers the ACCOUNT but not the LIST of
# namespaces it belongs to, and those namespaces stay permanently unaddressable.
# Every way this can be wrong is silent until someone's last device dies:
#
#   * write for members with no cloud login and the relay hands mdma the full
#     membership roster of every namespace it serves — undoing the property the
#     inventory half protects by reporting counts and never rosters — while
#     storing envelopes nobody can ever fetch;
#   * write a PARTIAL list at a higher version and it destroys a good one just
#     as effectively as a stale copy, with a valid version number on it;
#   * let the version reset across a restart and mdma answers 409 forever, so
#     the envelope silently stops tracking reality;
#   * compare CIPHERTEXTS to detect change and every pass looks like a change,
#     because sealing mints a fresh ephemeral key each call — burning a version
#     per pass and rewriting mdma forever for data that never moved.
#
# None of that is reachable from the release probes (they need a live TDX node,
# an MDMA, a linked cloud account and a namespace admin), so this renders the
# template, sources the function half, and drives it against stubbed `meroctl`
# and `curl` — the same shape as fleet-sidecar-inventory-test.sh.
#
# Usage: scripts/ci/tests/fleet-sidecar-recovery-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin"

if [[ ! -r "${TEMPLATE}" ]]; then
  echo "FAIL: cannot read ${TEMPLATE}" >&2
  exit 1
fi
sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/var/log/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/var/lib/calimero/@${SB}/@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"

if ! grep -q '^# --- Main loop ---$' "${SB}/rendered.sh"; then
  echo "FAIL: the sidecar template no longer has a '# --- Main loop ---' marker" >&2
  exit 1
fi
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

if grep -q '{{\|{%' "${SB}/functions.sh"; then
  echo "FAIL: unsubstituted Jinja left in the rendered sidecar:" >&2
  grep -n '{{\|{%' "${SB}/functions.sh" >&2
  exit 1
fi

# --- stubs -----------------------------------------------------------------
# `meroctl`, answering from flat fixture files:
#   ${SB}/subgroups  "<parent>=<child>,<child>"
#   ${SB}/members    "<group>=<account>,<account>"  (absent => the read FAILS)
#   ${SB}/contexts   "<group>=<ctx>,<ctx>"          (ERR => the read fails)
# and `account seal-to <group> <account>`, which reads the plaintext on stdin.
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
lookup() { grep -E "^${2}=" "${SB}/${1}" 2>/dev/null | tail -1 | cut -d= -f2-; }
emit_list() {
  local raw="$1" field="$2" tmpl="$3" out="" item
  if [[ -n "${raw}" ]]; then
    IFS=',' read -ra items <<< "${raw}"
    for item in "${items[@]}"; do
      [[ -n "${out}" ]] && out+=","
      out+="${tmpl//@@/${item}}"
    done
  fi
  printf '{"%s":[%s]}\n' "${field}" "${out}"
}
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[i]}" in
    subgroups)
      emit_list "$(lookup subgroups "${args[i + 1]}")" subgroups '{"groupId":"@@"}'
      exit 0 ;;
    seal-to)
      # Read (and record) the plaintext, then emit an envelope whose bytes are
      # DIFFERENT every call — real sealing mints a fresh ephemeral key, so a
      # writer that compares ciphertexts would see a change on every pass.
      plaintext="$(cat)"
      printf '%s\n' "${plaintext}" >> "${SB}/sealed-plaintexts"
      nonce="$(( RANDOM * RANDOM ))$(date +%s%N)"
      printf '{"accountRootEpoch":3,"ephemeralPublicKey":"eph%s","nonce":"n%s","ciphertext":"ct%s"}\n' \
        "${nonce}" "${nonce}" "${nonce}"
      exit 0 ;;
    contexts)
      raw="$(lookup contexts "${args[i + 2]}")"
      [[ "${raw}" == "ERR" ]] && exit 1
      emit_list "${raw}" data '{"contextId":"@@"}'
      exit 0 ;;
    list)
      if [[ "${args[i - 1]}" == "members" ]]; then
        raw="$(lookup members "${args[i + 1]}")"
        [[ -z "${raw}" ]] && exit 1
        emit_list "${raw}" members '{"identity":"@@","role":"member"}'
        exit 0
      fi ;;
  esac
done
exit 1
STUB

# `curl`: GET /linked-accounts answers from ${SB}/linked; PUT /recovery-envelope
# appends its body to ${SB}/put-log, or fails while ${SB}/put-fails exists.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body=""
prev=""
url=""
for a in "$@"; do
  [[ "${prev}" == "-d" ]] && body="${a}"
  [[ "${a}" == https://* ]] && url="${a}"
  prev="${a}"
done
case "${url}" in
  *linked-accounts*)
    [[ -f "${SB}/linked-fails" ]] && exit 22
    printf '{"accounts":[%s],"count":0}\n' "$(cat "${SB}/linked" 2>/dev/null)"
    exit 0 ;;
  *recovery-envelope*)
    [[ -f "${SB}/put-fails" ]] && exit 22
    printf '%s\n' "${body}" >> "${SB}/put-log"
    echo '{"status":"ok"}'
    exit 0 ;;
esac
exit 1
STUB

chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

: > "${SB}/subgroups"
: > "${SB}/members"
: > "${SB}/contexts"
: > "${SB}/put-log"
: > "${SB}/sealed-plaintexts"
: > "${SB}/linked"

fail() { echo "FAIL: $*" >&2; exit 1; }
puts() { awk 'NF{n++} END{print n+0}' "${SB}/put-log"; }
reset_state() { rm -f "${SB}/fleet-recovery.json"; : > "${SB}/put-log"; : > "${SB}/sealed-plaintexts"; }
field() { python3 -c "
import json, sys
print(json.loads(sys.stdin.read().strip().split(chr(10))[int(sys.argv[1])])[sys.argv[2]])
" "$1" "$2" < "${SB}/put-log"; }

NS="ns01"
CONFIRMED='["ns01"]'

# --- only linked accounts are written for ----------------------------------
# The decision this endpoint exists for: a member with no cloud login could
# never fetch an envelope, so writing one stores an unreadable payload AND
# discloses that the account exists.
reset_state
echo "${NS}=alice,bob,carol" > "${SB}/members"
echo "${NS}=ctx1" > "${SB}/contexts"
printf '"alice","carol"' > "${SB}/linked"
reconcile_recovery "peer1" "${CONFIRMED}" false

[[ "$(puts)" == "2" ]] || fail "expected one envelope per LINKED member, got $(puts)"
grep -q '"account_id": *"alice"' "${SB}/put-log" || fail "alice is linked and should have an envelope"
grep -q '"account_id": *"carol"' "${SB}/put-log" || fail "carol is linked and should have an envelope"
grep -q 'bob' "${SB}/put-log" && fail "bob has no cloud login; his membership must not reach mdma"
grep -q '"namespace_id": *"ns01"' "${SB}/put-log" || fail "the envelope must name its namespace (mdma#228)"

# --- the sealed payload is the plaintext, and carries the namespace ---------
grep -q '"namespace_id":"ns01"' "${SB}/sealed-plaintexts" \
  || fail "the sealed body should repeat the namespace so it is interpretable alone"
grep -q '"v":1' "${SB}/sealed-plaintexts" || fail "the sealed body should be versioned"

# --- an unchanged list is not rewritten ------------------------------------
# The ciphertext differs on every seal, so this only passes if change detection
# hashes the PLAINTEXT.
: > "${SB}/put-log"
reconcile_recovery "peer1" "${CONFIRMED}" false
[[ "$(puts)" == "0" ]] || fail "nothing changed, so nothing should be rewritten (got $(puts) writes)"

# --- a changed list is rewritten, at a higher version ----------------------
: > "${SB}/put-log"
echo "${NS}=ctx1,ctx2" > "${SB}/contexts"
reconcile_recovery "peer1" "${CONFIRMED}" false
[[ "$(puts)" == "2" ]] || fail "a changed context list should be rewritten, got $(puts)"
[[ "$(field 0 version)" == "2" ]] || fail "version should advance to 2, got $(field 0 version)"

# --- the version survives a restart ---------------------------------------
# In memory it would reset to 1 and mdma would answer 409 forever, leaving the
# envelope frozen at whatever it last accepted.
: > "${SB}/put-log"
unset -f load_recovery save_recovery 2>/dev/null || true
# shellcheck source=/dev/null
source "${SB}/functions.sh"          # a "restart": functions reloaded, state file kept
echo "${NS}=ctx1,ctx2,ctx3" > "${SB}/contexts"
reconcile_recovery "peer1" "${CONFIRMED}" false
[[ "$(field 0 version)" == "3" ]] || fail "version must continue across a restart, got $(field 0 version)"

# --- an incomplete walk writes NOTHING ------------------------------------
# A shorter list at a higher version is the same data loss as a clobber.
reset_state
echo "${NS}=alice" > "${SB}/members"
echo "${NS}=ERR" > "${SB}/contexts"
reconcile_recovery "peer1" "${CONFIRMED}" false
[[ "$(puts)" == "0" ]] || fail "an incomplete read must write nothing, got $(puts) writes"

# --- a rejected PUT is not recorded, so it retries -------------------------
reset_state
echo "${NS}=alice" > "${SB}/members"
echo "${NS}=ctx1" > "${SB}/contexts"
touch "${SB}/put-fails"
reconcile_recovery "peer1" "${CONFIRMED}" false
rm -f "${SB}/put-fails"
reconcile_recovery "peer1" "${CONFIRMED}" false
[[ "$(puts)" == "1" ]] || fail "a failed PUT must be retried, not recorded as done (got $(puts))"
[[ "$(field 0 version)" == "1" ]] || fail "a failed write must not burn a version, got $(field 0 version)"

# --- no linked accounts means no writes, not a fallback -------------------
reset_state
printf '' > "${SB}/linked"
echo "${NS}=alice,bob" > "${SB}/members"
reconcile_recovery "peer1" "${CONFIRMED}" false
[[ "$(puts)" == "0" ]] || fail "with no cloud logins there is no reader; writing for everyone is the bug"

# --- mdma being unreachable writes nothing --------------------------------
reset_state
printf '"alice"' > "${SB}/linked"
touch "${SB}/linked-fails"
reconcile_recovery "peer1" "${CONFIRMED}" false
rm -f "${SB}/linked-fails"
[[ "$(puts)" == "0" ]] || fail "an unreadable linked-account list must not fall back to writing for all"

echo "PASS: fleet sidecar recovery-envelope behaviour"
