#!/usr/bin/env bash
# An agent's data disk is encrypted with a key the KMS releases only to an
# attested agent image, is never reformatted, and is the only place agent state
# lives (docs/design/private-agents.md).
#
# Modeled on calimero-init-disk-encryption-test.sh, and like it this EXECUTES
# the logic: it slices the release-pinning and data-disk blocks out of
# agent-init.sh.j2 and runs them against stub merod / cryptsetup / blkid /
# mount / mkfs, recording every call. What it pins:
#
#   * blank disk         -> disk-key --create-identity (with MERO_TEE_VERSION,
#                           MERO_TEE_MIN_VERSION, MERO_TEE_PROFILE exported),
#                           luksFormat LUKS2 + hmac-sha256 integrity, token
#                           imported and read back, open, mkfs on the MAPPER,
#                           mount at /mnt/agent, no fstab
#   * existing LUKS disk -> identity from the token, disk-key without
#                           --create-identity, open, mount; never luksFormat/mkfs
#   * a plain ext4 disk  -> refused: an agent never keeps host-writable state
#   * any other signature, a partition table, or a failed probe -> refuse
#   * LUKS without our token, an opened volume with no ext4, a key that does not
#     open it (a disk from an earlier release) -> refuse, never format
#   * the KMS unreachable -> refuse, and the disk is not formatted
#   * no data disk at all -> refuse (unlike a node, nowhere else to keep state)
#   * tee-release-version below the image -> refuse before any key is fetched
#   * the key file never outlives the script, and is written only to the tmpfs
#
# Usage: scripts/ci/tests/agent-init-data-disk-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/mero-agent/templates/agent-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- slice the code under test out of the template --------------------------
block_src="$(awk '/^# --- Release pinning/{on=1} /^# --- Agent environment/{exit} on{print}' "$TEMPLATE")"
[[ -n "$block_src" ]] || fail "could not find '# --- Release pinning' .. '# --- Agent environment'"
grep -qF 'luksFormat' <<<"$block_src" || fail "the sliced block does not contain the format it is meant to test"
grep -qF '{{' <<<"$block_src" && fail "the sliced block holds Jinja; this test runs it unrendered"

# --- ordering, statically ---------------------------------------------------
line_of() { grep -nF -- "$1" "$TEMPLATE" | head -1 | cut -d: -f1; }
rtmr3_line="$(line_of '# --- RTMR3')"
pin_line="$(line_of '# --- Release pinning')"
disk_line="$(line_of '# --- The data disk')"
env_line="$(line_of '# --- Agent environment')"
(( rtmr3_line < pin_line && pin_line < disk_line && disk_line < env_line )) \
  || fail "agent-init must extend RTMR3, pin the release, open the disk, then write the agent's environment, in that order"
grep -qE '^[^#]*/etc/fstab' <<<"$block_src" && fail "the agent disk must not be written to fstab: fstab cannot unlock it"

# --- stubs ------------------------------------------------------------------
BIN="$WORK/bin"
mkdir -p "$BIN"

cat >"$BIN/merod" <<'STUB'
#!/usr/bin/env bash
echo "merod $*" >>"$T/calls"
[[ "$1 $2" == "kms disk-key" ]] || exit 0
shift 2
identity="" key_out="" create=no
while (( $# )); do
  case "$1" in
    --identity) identity="$2"; shift ;;
    --key-out) key_out="$2"; shift ;;
    --create-identity) create=yes ;;
  esac
  shift
done
printf 'MERO_TEE_VERSION=%s MERO_TEE_MIN_VERSION=%s MERO_TEE_PROFILE=%s\n' \
  "${MERO_TEE_VERSION:-}" "${MERO_TEE_MIN_VERSION:-}" "${MERO_TEE_PROFILE:-}" >>"$T/disk-key-env"
[[ -n "${MERO_TEE_VERSION:-}" ]] || { echo "no release" >&2; exit 1; }
[[ "$(dirname "$key_out")" == "$T/run/mero-agent-disk" && -e "$T/state/keydir-mounted" ]] \
  || { echo "key-out $key_out is not on the tmpfs" >&2; exit 1; }
[[ ! -e "$key_out" ]] || { echo "key-out exists" >&2; exit 1; }
[[ "$(cat "$T/state/kms")" == up ]] || { echo "kms unreachable" >&2; exit 1; }
if [[ ! -e "$identity" ]]; then
  [[ "$create" == yes ]] || { echo "no identity" >&2; exit 1; }
  printf 'fresh-identity-bytes' >"$identity"
fi
( umask 077; printf 'key-for:%s' "$(cat "$identity")" >"$key_out" )
STUB

cat >"$BIN/cryptsetup" <<'STUB'
#!/usr/bin/env bash
echo "cryptsetup $*" >>"$T/calls"
last="${*: -1}"
keyfile_arg() { local prev=""; for a in "$@"; do [[ "$prev" == --key-file ]] && echo "$a"; prev="$a"; done; }
case "$1" in
  luksFormat)
    kf="$(keyfile_arg "$@")"
    [[ -s "$kf" ]] || { echo "no key file" >&2; exit 1; }
    cp "$kf" "$T/state/luks-key"
    echo luks >"$T/state/device"
    rm -f "$T/state/tokens"
    ;;
  token)
    [[ "$2" == import ]] || exit 1
    cat >>"$T/state/tokens"
    echo >>"$T/state/tokens"
    ;;
  luksDump)
    [[ "$(cat "$T/state/device")" == luks ]] || exit 1
    python3 - "$T/state/tokens" <<'PY'
import json, os, sys
tokens = {}
if os.path.exists(sys.argv[1]):
    for i, line in enumerate(l for l in open(sys.argv[1]) if l.strip()):
        tokens[str(i)] = json.loads(line)
print(json.dumps({"keyslots": {}, "tokens": tokens}))
PY
    ;;
  open)
    kf="$(keyfile_arg "$@")"
    cmp -s "$kf" "$T/state/luks-key" || { echo "No key available with this passphrase." >&2; exit 2; }
    mkdir -p "$T/dev/mapper"
    : >"$T/dev/mapper/$last"
    ;;
  status)
    printf '/dev/mapper/%s is active.\n  type:    LUKS2\n  integrity: hmac(sha256)\n' "$last"
    ;;
  *) exit 1 ;;
esac
STUB

cat >"$BIN/blkid" <<'STUB'
#!/usr/bin/env bash
echo "blkid $*" >>"$T/calls"
last="${*: -1}"
[[ "$1" == -p ]] || exit 4
if [[ "$last" == "$T/dev/mapper/"* ]]; then
  [[ -s "$T/state/mapperfs" ]] || exit 2
  echo "TYPE=$(cat "$T/state/mapperfs")"
  exit 0
fi
case "$(cat "$T/state/device")" in
  blank) exit 2 ;;
  luks) echo "TYPE=crypto_LUKS" ;;
  ext4) echo "TYPE=ext4" ;;
  ntfs) echo "TYPE=ntfs" ;;
  ptable) echo "PTTYPE=gpt" ;;
  error) exit 4 ;;
esac
STUB

cat >"$BIN/mount" <<'STUB'
#!/usr/bin/env bash
echo "mount $*" >>"$T/calls"
last="${*: -1}" src="${*: -2:1}"
if [[ "$last" == "$T/run/mero-agent-disk" ]]; then touch "$T/state/keydir-mounted"; exit 0; fi
if [[ "$last" == "$T/mnt/agent" ]]; then
  echo "$src" >"$T/state/mounted-source"
  [[ "$*" == *"-t tmpfs"* ]] && echo tmpfs >"$T/state/mnt-fstype"
  exit 0
fi
exit 32
STUB

cat >"$BIN/umount" <<'STUB'
#!/usr/bin/env bash
echo "umount $*" >>"$T/calls"
[[ "${*: -1}" == "$T/run/mero-agent-disk" ]] && rm -f "$T/state/keydir-mounted"
exit 0
STUB

cat >"$BIN/mountpoint" <<'STUB'
#!/usr/bin/env bash
last="${*: -1}"
[[ "$last" == "$T/run/mero-agent-disk" ]] && { [[ -e "$T/state/keydir-mounted" ]]; exit; }
[[ "$last" == "$T/mnt/agent" ]] && { [[ -e "$T/state/mounted-source" ]]; exit; }
exit 1
STUB

cat >"$BIN/findmnt" <<'STUB'
#!/usr/bin/env bash
last="${*: -1}"
if [[ "$last" == "$T/run/mero-agent-disk"* ]]; then
  [[ -e "$T/state/keydir-mounted" ]] && echo tmpfs || echo ext4
  exit 0
fi
if [[ "$*" == *SOURCE* ]]; then cat "$T/state/mounted-source" 2>/dev/null; exit 0; fi
if [[ "$*" == *FSTYPE* && "$last" == "$T/mnt/agent" ]]; then cat "$T/state/mnt-fstype" 2>/dev/null; exit 0; fi
exit 1
STUB

cat >"$BIN/mkfs.ext4" <<'STUB'
#!/usr/bin/env bash
echo "mkfs.ext4 $*" >>"$T/calls"
last="${*: -1}"
if [[ "$last" == "$T/dev/mapper/"* ]]; then echo ext4 >"$T/state/mapperfs"; else echo ext4 >"$T/state/device"; fi
STUB

printf '#!/usr/bin/env bash\nexit 0\n' >"$BIN/modprobe"
printf '#!/usr/bin/env bash\nexit 0\n' >"$BIN/lsblk"
printf '#!/usr/bin/env bash\nexit 0\n' >"$BIN/sleep"
chmod +x "$BIN"/*

for tool in merod cryptsetup blkid mount umount mountpoint findmnt mkfs.ext4 modprobe lsblk sleep; do
  [[ "$(PATH="$BIN:$PATH" command -v "$tool")" == "$BIN/$tool" ]] || fail "stub $tool does not shadow the real one"
done

# --- one scenario -----------------------------------------------------------
#   run_disk NAME RELEASE DEVICE_STATE [KMS_STATE] [DEVICE_PRESENT] [EPHEMERAL]
run_disk() {
  local name="$1" release="$2" device="$3" kms="${4:-up}" present="${5:-yes}" ephemeral="${6:-false}"
  local T="$WORK/$name"
  mkdir -p "$T/state" "$T/dev" "$T/mnt/agent" "$T/run"
  [[ "$present" == yes ]] && : >"$T/dev/google-data"
  echo "$device" >"$T/state/device"
  echo "$kms" >"$T/state/kms"
  echo "2.3.112" >"$T/min-version"
  : >"$T/calls"

  local block
  block="$(sed \
    -e "s@/dev/disk/by-id/google-data@$T/dev/google-data@g" \
    -e "s@/dev/mapper/@$T/dev/mapper/@g" \
    -e "s@/run/mero-agent-disk@$T/run/mero-agent-disk@g" \
    -e "s@DATA_MOUNT=\"/mnt/agent\"@DATA_MOUNT=\"$T/mnt/agent\"@" \
    -e "s@/etc/mero-agent/min-tee-release-version@$T/min-version@g" \
    -e 's@-b "\$DATA_DEVICE"@-e "$DATA_DEVICE"@g' \
    -e 's@-b "\$DATA_MAPPER"@-e "$DATA_MAPPER"@g' \
    <<<"$block_src")"
  if grep -nE '/dev/disk/by-id|"/run/mero-agent-disk|"/mnt/agent"|"/dev/mapper|"/etc/mero-agent' <<<"$block" | grep -v '^[0-9]*:[[:space:]]*#'; then
    fail "$name: the sliced block still points at a real system path"
  fi

  cat >"$T/run.sh" <<RUN
set -euo pipefail
export T="$T"
PATH="$BIN:\$PATH"
LOG="$T/log"
log() { echo "\$*" >>"\$LOG"; }
fatal() { log "ERROR: \$*"; exit 1; }
BIN_DIR="$BIN"
IMAGE_PROFILE="locked-read-only"
KMS_URL="https://kms.example:8080"
TEE_RELEASE_VERSION="$release"
DISK_KEY_ATTEMPTS=2
DISK_KEY_RETRY_DELAY=0
DATA_DEVICE_WAIT_SECS=0
EPHEMERAL_STORE="$ephemeral"
$block
RUN
  rerun "$name"
}

rerun() {
  local T="$WORK/$1"
  : >"$T/calls"; : >"$T/log"
  set +e
  bash "$T/run.sh" >/dev/null 2>&1
  echo $? >"$T/rc"
  set -e
}

T_() { echo "$WORK/$1"; }
rc() { cat "$WORK/$1/rc"; }
called() { grep -qE -- "$2" "$WORK/$1/calls"; }
logged() { grep -qF -- "$2" "$WORK/$1/log" 2>/dev/null; }
no_key_left() {
  local d="$WORK/$1/run/mero-agent-disk"
  [[ ! -d "$d" ]] || [[ -z "$(ls -A "$d")" ]] || fail "$1: the data-disk key or identity was left in $d: $(ls -A "$d")"
  [[ ! -e "$WORK/$1/state/keydir-mounted" ]] || fail "$1: the key tmpfs was left mounted"
}
never_formatted() {
  called "$1" '^cryptsetup luksFormat' && fail "$1: luksFormat ran on a disk that must not be formatted"
  called "$1" '^mkfs.ext4' && fail "$1: mkfs ran on a disk that must not be formatted"
  return 0
}
never_mounted() {
  [[ ! -e "$WORK/$1/state/mounted-source" ]] || fail "$1: /mnt/agent was mounted from $(cat "$WORK/$1/state/mounted-source")"
}
existing_luks() { # a disk formatted earlier under identity $2 ($3: the key that opens it), not open now
  local D="$WORK/$1"
  echo luks >"$D/state/device"
  rm -f "$D/state/mapperfs" "$D/state/mounted-source" "$D/dev/mapper/mero-agent-data"
  printf 'key-for:%s' "${3:-$2}" >"$D/state/luks-key"
  python3 -c 'import base64,json,sys; print(json.dumps({"type":"calimero-kms-identity","keyslots":[],"identity_b64":base64.b64encode(sys.argv[1].encode()).decode()}))' "$2" >"$D/state/tokens"
}

# --- 1. first boot: blank disk -> encrypted ---------------------------------
run_disk fresh 2.3.112 blank
F="$(T_ fresh)"
[[ "$(rc fresh)" == 0 ]] || fail "a blank disk should be encrypted and mounted (rc=$(rc fresh)); log: $(cat "$F/log")"
called fresh '^merod kms disk-key .*--create-identity' || fail "the first boot must mint the disk identity"
fmt="$(grep '^cryptsetup luksFormat' "$F/calls")"
for want in '--type luks2' '--cipher aes-xts-plain64' '--key-size 512' '--integrity hmac-sha256' \
            '--pbkdf pbkdf2' '--pbkdf-force-iterations 1000' '--batch-mode' '--key-file '; do
  grep -qF -- "$want" <<<"$fmt" || fail "luksFormat is missing '$want': $fmt"
done
grep -qF -- '--integrity-no-wipe' <<<"$fmt" && fail "luksFormat must not skip the integrity wipe"
python3 - "$(head -1 "$F/state/tokens")" <<'PY' || fail "the imported LUKS2 token is not the identity token"
import base64, json, sys
t = json.loads(sys.argv[1])
assert t["type"] == "calimero-kms-identity", t
assert base64.b64decode(t["identity_b64"]) == b"fresh-identity-bytes", t
assert t["kms_release"] == "2.3.112", t
PY
called fresh "^mkfs.ext4 .*$F/dev/mapper/mero-agent-data\$" || fail "the filesystem must be made on the dm-crypt mapper"
called fresh "^mkfs.ext4 .*google-data\$" && fail "mkfs ran on the raw device, under the encryption"
token_at="$(grep -n '^cryptsetup token import' "$F/calls" | cut -d: -f1)"
mkfs_at="$(grep -n '^mkfs.ext4' "$F/calls" | cut -d: -f1)"
(( token_at < mkfs_at )) || fail "the identity token must be stored before any data goes on the volume"
[[ "$(cat "$F/state/mounted-source")" == "$F/dev/mapper/mero-agent-data" ]] || fail "/mnt/agent is not mounted from the mapper"
grep -q 'MERO_TEE_VERSION=2.3.112 MERO_TEE_MIN_VERSION=2.3.112 MERO_TEE_PROFILE=locked-read-only' "$F/disk-key-env" \
  || fail "disk-key did not see the pinned release and profile: $(cat "$F/disk-key-env")"
logged fresh "LUKS2 dm-crypt mapping with integrity" || fail "the boot-time disk check did not run"
no_key_left fresh

# --- 2. a later boot: the same disk is reopened, never reformatted ----------
# A reboot: nothing is mounted and no mapping is open.
rm -f "$F/state/mounted-source" "$F/dev/mapper/mero-agent-data"
rerun fresh
[[ "$(rc fresh)" == 0 ]] || fail "the disk formatted on the first boot should reopen (rc=$(rc fresh)); log: $(cat "$F/log")"
never_formatted fresh
called fresh '^merod kms disk-key .*--create-identity' && fail "a later boot must present the disk's identity, never mint one"
called fresh '^cryptsetup open' || fail "the existing disk was not opened"
no_key_left fresh

# --- 3. a plain ext4 disk: refused, not mounted -----------------------------
run_disk plain 2.3.112 ext4
[[ "$(rc plain)" != 0 ]] || fail "an agent must refuse a plain (host-writable) data disk"
never_formatted plain
never_mounted plain

# --- 4. anything else: refuse, touch nothing --------------------------------
for sig in ntfs ptable error; do
  run_disk "foreign-$sig" 2.3.112 "$sig"
  [[ "$(rc "foreign-$sig")" != 0 ]] || fail "a disk holding '$sig' must stop the boot"
  never_formatted "foreign-$sig"
  never_mounted "foreign-$sig"
  no_key_left "foreign-$sig"
done

# --- 5. LUKS but not ours; a volume with no ext4; a key that does not open --
run_disk luks-no-token 2.3.112 luks
[[ "$(rc luks-no-token)" != 0 ]] || fail "a LUKS disk without our identity token must stop the boot"
never_formatted luks-no-token

run_disk luks-blank-volume 2.3.112 luks
existing_luks luks-blank-volume existing-identity
rerun luks-blank-volume
[[ "$(rc luks-blank-volume)" != 0 ]] || fail "an opened volume with no ext4 must stop the boot, not be formatted"
never_formatted luks-blank-volume
no_key_left luks-blank-volume

# A disk from an earlier release: the new release's KMS root derives another key.
run_disk earlier-release 2.3.112 luks
existing_luks earlier-release existing-identity other-root
echo ext4 >"$(T_ earlier-release)/state/mapperfs"
rerun earlier-release
[[ "$(rc earlier-release)" != 0 ]] || fail "a disk the KMS key does not open must stop the boot"
never_formatted earlier-release
logged earlier-release "earlier release" || fail "a disk that will not open must say a new release cannot reopen it"
no_key_left earlier-release

# --- 6. the KMS is unreachable: refuse, nothing formatted -------------------
run_disk kms-down 2.3.112 blank down
[[ "$(rc kms-down)" != 0 ]] || fail "no disk key must stop the boot"
never_formatted kms-down
logged kms-down "agent policy" || fail "a failed key fetch must point at the KMS's agent policy"
no_key_left kms-down

# --- 7. no data disk at all --------------------------------------------------
run_disk no-disk 2.3.112 blank up no
[[ "$(rc no-disk)" != 0 ]] || fail "an agent with no data disk must stop the boot: it has nowhere else to keep state"
called no-disk '^merod' && fail "no key may be fetched without a disk"
never_mounted no-disk

# --- 8. a release older than the image: refused before any key --------------
run_disk downgrade 2.3.111 blank
[[ "$(rc downgrade)" != 0 ]] || fail "tee-release-version older than the image must be refused"
called downgrade '^merod' && fail "a downgraded release must be refused before disk-key runs"
never_formatted downgrade
run_disk prerelease 2.3.112-rc.1 blank
[[ "$(rc prerelease)" != 0 ]] || fail "a pre-release of the image's own version is older than it"
run_disk newer 2.3.113 blank
[[ "$(rc newer)" == 0 ]] || fail "a newer release must be accepted (rc=$(rc newer)); log: $(cat "$(T_ newer)/log")"

# --- 9. ephemeral-store: TD memory, no KMS, the disk untouched ---------------
run_disk ephemeral "" blank down yes true
[[ "$(rc ephemeral)" == 0 ]] || fail "ephemeral-store must boot without a KMS (rc=$(rc ephemeral)); log: $(cat "$(T_ ephemeral)/log")"
[[ "$(cat "$(T_ ephemeral)/state/mnt-fstype")" == tmpfs ]] || fail "ephemeral-store must mount a tmpfs at /mnt/agent"
called ephemeral '^merod' && fail "ephemeral-store must not ask the KMS for anything"
called ephemeral '^cryptsetup' && fail "ephemeral-store must not touch the data disk"
never_formatted ephemeral
logged ephemeral "tmpfs in TD memory" || fail "the boot-time check must confirm the tmpfs"

echo "agent-init data disk: OK"
