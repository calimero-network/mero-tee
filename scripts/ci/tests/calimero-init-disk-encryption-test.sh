#!/usr/bin/env bash
# The data disk is encrypted (LUKS2 with integrity) with a key from the KMS, a
# disk holding anything is never reformatted, and tee-release-version cannot
# name a release older than the image.
#
# TDX protects the VM's memory, not its disks. merod's store has its own KMS
# key, but the data disk also holds config.toml, the node's TLS private key,
# mero-auth's database and the fleet sidecar's token -- all readable from a
# snapshot of a plain disk. So calimero-init formats a blank data disk as LUKS2
# keyed by `merod kms disk-key`, keeps the disk-unlock identity in a LUKS2
# token, and reopens it on every boot.
#
# Like the store-encryption test this EXECUTES the logic: it slices the
# data-disk block and the release-pinning block out of the template and runs
# them against stub merod / cryptsetup / blkid / mount / mkfs, recording every
# call. What it pins:
#
#   * blank disk + KMS      -> disk-key --create-identity, luksFormat LUKS2 +
#                              hmac-sha256 integrity, identity token imported and
#                              read back, open, mkfs on the MAPPER, mount, no fstab
#   * existing LUKS disk    -> identity exported from the token, disk-key without
#                              --create-identity, open, mount; never luksFormat/mkfs
#   * plain ext4 disk       -> mounted as before + loud WARN; never reformatted
#   * any other signature, a partition table, or a failed probe -> refuse, touch nothing
#   * LUKS without our token, or an opened volume with no ext4 -> refuse, no mkfs
#   * locked-read-only with no KMS / a merod without disk-key -> refuse, no format
#   * debug profile with no KMS -> plain ext4 + WARN (the old behaviour)
#   * a KMS URL with no release -> refuse on every profile
#   * the KMS unreachable   -> refuse, and the disk is not formatted
#   * the key file never outlives the script, and is written only to the tmpfs
#   * tee-release-version below the baked floor -> refuse; merod.env carries
#     MERO_TEE_MIN_VERSION, and MERO_TEE_PROFILE (the image's profile) on
#     every profile
#
# Usage: scripts/ci/tests/calimero-init-disk-encryption-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- slice the code under test out of the template --------------------------
disk_block="$(awk '/^# --- The data disk ---/{on=1} /^# --- Fleet state off the boot disk ---/{exit} on{print}' "$TEMPLATE")"
pin_block="$(awk '/^# --- Release pinning/{on=1} /^# Extra `merod init` arguments/{exit} on{print}' "$TEMPLATE")"
[[ -n "$disk_block" ]] || fail "could not find the data-disk block ('# --- The data disk ---' .. '# --- Fleet state off the boot disk ---')"
[[ -n "$pin_block" ]] || fail "could not find the release-pinning block ('# --- Release pinning' .. '# Extra \`merod init\` arguments')"
grep -qF 'luksFormat' <<<"$disk_block" || fail "the sliced disk block does not contain the format it is meant to test"
grep -qF 'MERO_TEE_MIN_VERSION' <<<"$pin_block" || fail "the sliced pinning block does not write MERO_TEE_MIN_VERSION"

# --- ordering, statically ---------------------------------------------------
# The release must be exported before the disk key is fetched (disk-key refuses
# without it), and the disk must be open before merod init writes the node.
line_of() { grep -nF -- "$1" "$TEMPLATE" | head -1 | cut -d: -f1; }
export_line="$(line_of 'export MERO_TEE_VERSION="$SANITIZED_TEE_RELEASE_VERSION"')"
disk_line="$(line_of '# --- The data disk ---')"
init_line="$(line_of '  init_node')"
[[ -n "$export_line" && -n "$disk_line" && -n "$init_line" ]] || fail "could not locate the export, the disk block or init_node"
(( export_line < disk_line )) || fail "MERO_TEE_VERSION is exported after the data disk is unlocked; disk-key would run unverified"
(( disk_line < init_line )) || fail "the data disk is unlocked after merod init"
grep -qE '^[^#]*/etc/fstab' <<<"$(awk '/^format_encrypted_data_disk\(\)/,/^}$/' "$TEMPLATE")" \
  && fail "the encrypted path must not write /etc/fstab: fstab cannot unlock it"

# --- stubs ------------------------------------------------------------------
# One set, driven by $T (the case directory) and files under $T/state.
BIN="$WORK/bin"
mkdir -p "$BIN"

cat >"$BIN/merod" <<'STUB'
#!/usr/bin/env bash
echo "merod $*" >>"$T/calls"
if [[ "$*" == "kms disk-key --help" ]]; then
  [[ "$(cat "$T/state/merod_disk_key")" == yes ]] || { echo "error: unrecognized subcommand 'kms'" >&2; exit 2; }
  echo "      --key-out <PATH>"
  exit 0
fi
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
# The real command refuses a key path off tmpfs; this one refuses anything but
# the mounted key dir.
[[ "$(dirname "$key_out")" == "$T/run/calimero-disk" && -e "$T/state/keydir-mounted" ]] \
  || { echo "key-out $key_out is not on the tmpfs" >&2; exit 1; }
[[ ! -e "$key_out" ]] || { echo "key-out exists" >&2; exit 1; }
[[ "$(cat "$T/state/kms")" == up ]] || { echo "kms unreachable" >&2; exit 1; }
if [[ ! -e "$identity" ]]; then
  [[ "$create" == yes ]] || { echo "no identity" >&2; exit 1; }
  printf 'fresh-identity-bytes' >"$identity"
fi
( umask 077; printf 'key-for:%s' "$(cat "$identity")" >"$key_out" )
echo "$key_out" >>"$T/key-paths"
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
    [[ "$(cat "$T/state/device")" == luks ]] || exit 1
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
    printf '/dev/mapper/%s is active.\n  type:    LUKS2\n  cipher:  aes-xts-plain64\n  integrity: hmac(sha256)\n' "$last"
    ;;
  *) exit 1 ;;
esac
STUB

cat >"$BIN/blkid" <<'STUB'
#!/usr/bin/env bash
echo "blkid $*" >>"$T/calls"
last="${*: -1}"
if [[ "$*" == *"-s UUID"* ]]; then echo "1111-2222"; exit 0; fi
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
if [[ "$last" == "$T/run/calimero-disk" ]]; then touch "$T/state/keydir-mounted"; exit 0; fi
if [[ "$last" == "$T/mnt/data" ]]; then echo "$src" >"$T/state/mounted-source"; exit 0; fi
exit 32
STUB

cat >"$BIN/umount" <<'STUB'
#!/usr/bin/env bash
echo "umount $*" >>"$T/calls"
[[ "${*: -1}" == "$T/run/calimero-disk" ]] && rm -f "$T/state/keydir-mounted"
exit 0
STUB

cat >"$BIN/mountpoint" <<'STUB'
#!/usr/bin/env bash
last="${*: -1}"
[[ "$last" == "$T/run/calimero-disk" ]] && { [[ -e "$T/state/keydir-mounted" ]]; exit; }
[[ "$last" == "$T/mnt/data" ]] && { [[ -e "$T/state/mounted-source" ]]; exit; }
exit 1
STUB

cat >"$BIN/findmnt" <<'STUB'
#!/usr/bin/env bash
last="${*: -1}"
if [[ "$last" == "$T/run/calimero-disk"* ]]; then
  [[ -e "$T/state/keydir-mounted" ]] && echo tmpfs || echo ext4
  exit 0
fi
if [[ "$*" == *SOURCE* ]]; then cat "$T/state/mounted-source" 2>/dev/null; exit 0; fi
echo ext4
STUB

cat >"$BIN/mkfs.ext4" <<'STUB'
#!/usr/bin/env bash
echo "mkfs.ext4 $*" >>"$T/calls"
last="${*: -1}"
if [[ "$last" == "$T/dev/mapper/"* ]]; then echo ext4 >"$T/state/mapperfs"; else echo ext4 >"$T/state/device"; fi
STUB

printf '#!/usr/bin/env bash\nexit 0\n' >"$BIN/modprobe"
chmod +x "$BIN"/*

# Every stub must shadow the real tool: these are block-device and mount
# operations, and this test must never reach the machine running it.
for tool in merod cryptsetup blkid mount umount mountpoint findmnt mkfs.ext4 modprobe; do
  [[ "$(PATH="$BIN:$PATH" command -v "$tool")" == "$BIN/$tool" ]] || fail "stub $tool does not shadow the real one"
done

# --- one scenario -----------------------------------------------------------
#   run_disk NAME PROFILE KMS_URL RELEASE MEROD_DISK_KEY DEVICE_STATE [KMS_STATE]
run_disk() {
  local name="$1" profile="$2" kms_url="$3" release="$4" merod_dk="$5" device="$6" kms="${7:-up}"
  local T="$WORK/$name"
  mkdir -p "$T/state" "$T/dev" "$T/mnt/data" "$T/run" "$T/home"
  : >"$T/dev/google-data"
  : >"$T/fstab"
  echo "$device" >"$T/state/device"
  echo "$merod_dk" >"$T/state/merod_disk_key"
  echo "$kms" >"$T/state/kms"
  : >"$T/calls"

  local block
  block="$(sed \
    -e "s@/dev/disk/by-id/google-data@$T/dev/google-data@g" \
    -e "s@/dev/mapper/@$T/dev/mapper/@g" \
    -e "s@/run/calimero-disk@$T/run/calimero-disk@g" \
    -e "s@DATA_MOUNT=\"/mnt/data\"@DATA_MOUNT=\"$T/mnt/data\"@" \
    -e "s@/etc/fstab@$T/fstab@g" \
    -e 's@-b "\$DATA_DEVICE"@-e "$DATA_DEVICE"@g' \
    -e 's@-b "\$DATA_MAPPER"@-e "$DATA_MAPPER"@g' \
    <<<"$disk_block")"
  if grep -nE '/dev/disk/by-id|"/run/calimero-disk|"/mnt/data"|[^/]/etc/fstab|"/dev/mapper' <<<"$block" | grep -v '^[0-9]*:[[:space:]]*#'; then
    fail "$name: the sliced disk block still points at a real system path"
  fi

  cat >"$T/run.sh" <<RUN
set -euo pipefail
export T="$T"
PATH="$BIN:\$PATH"
LOG="$T/log"
log() { echo "\$*" >>"\$LOG"; }
fatal() { log "ERROR: \$*"; exit 1; }
BIN_DIR="$BIN"
CALIMERO_HOME="$T/mnt/data/calimero"
IMAGE_PROFILE="$profile"
EPHEMERAL_STORE=""
KMS_PHALA_URL="$kms_url"
TEE_RELEASE_VERSION="$release"
SANITIZED_TEE_RELEASE_VERSION="$release"
DISK_KEY_ATTEMPTS=2
DISK_KEY_RETRY_DELAY=0
if [[ -n "$release" ]]; then export MERO_TEE_VERSION="$release" MERO_TEE_MIN_VERSION=2.3.70 MERO_TEE_PROFILE=locked-read-only; fi
$block
RUN
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
  local d="$WORK/$1/run/calimero-disk"
  [[ ! -d "$d" ]] || [[ -z "$(ls -A "$d")" ]] || fail "$1: the data-disk key or identity was left in $d: $(ls -A "$d")"
  [[ ! -e "$WORK/$1/state/keydir-mounted" ]] || fail "$1: the key tmpfs was left mounted"
}
never_formatted() {
  called "$1" '^cryptsetup luksFormat' && fail "$1: luksFormat ran on a disk that must not be formatted"
  called "$1" '^mkfs.ext4' && fail "$1: mkfs ran on a disk that must not be formatted"
  return 0
}

URL="https://kms.example:8080/"

# --- 1. first boot: blank disk, KMS, release -> encrypted -------------------
run_disk fresh locked-read-only "$URL" 2.3.70 yes blank
[[ "$(rc fresh)" == 0 ]] || fail "a blank disk with a KMS should be encrypted and mounted (rc=$(rc fresh)); log: $(cat "$(T_ fresh)/log")"
called fresh '^merod kms disk-key .*--create-identity' || fail "the first boot must mint the disk identity (--create-identity)"
fmt="$(grep '^cryptsetup luksFormat' "$(T_ fresh)/calls")"
for want in '--type luks2' '--cipher aes-xts-plain64' '--key-size 512' '--integrity hmac-sha256' \
            '--pbkdf pbkdf2' '--pbkdf-force-iterations 1000' '--batch-mode' '--key-file '; do
  grep -qF -- "$want" <<<"$fmt" || fail "luksFormat is missing '$want': $fmt"
done
grep -qF -- '--integrity-no-wipe' <<<"$fmt" && fail "luksFormat must not skip the integrity wipe (see the template)"
grep -qF -- "$(T_ fresh)/dev/google-data" <<<"$fmt" || fail "luksFormat did not target the data disk"
token="$(head -1 "$(T_ fresh)/state/tokens")"
python3 - "$token" <<'PY' || fail "the imported LUKS2 token is not a calimero-kms-identity token holding the identity: $token"
import base64, json, sys
t = json.loads(sys.argv[1])
assert t["type"] == "calimero-kms-identity", t
assert t["keyslots"] == [], t
assert base64.b64decode(t["identity_b64"]) == b"fresh-identity-bytes", t
assert t["kms_release"] == "2.3.70", t
PY
called fresh '^cryptsetup open --type luks2 --key-file ' || fail "the new volume was not opened"
called fresh "^mkfs.ext4 .*$(T_ fresh)/dev/mapper/calimero-data\$" || fail "the filesystem must be made on the dm-crypt mapper"
called fresh "^mkfs.ext4 .*google-data\$" && fail "mkfs ran on the raw device, under the encryption"
token_at="$(grep -n '^cryptsetup token import' "$(T_ fresh)/calls" | cut -d: -f1)"
mkfs_at="$(grep -n '^mkfs.ext4' "$(T_ fresh)/calls" | cut -d: -f1)"
(( token_at < mkfs_at )) || fail "the identity token must be stored before any data goes on the volume"
[[ "$(cat "$(T_ fresh)/state/mounted-source")" == "$(T_ fresh)/dev/mapper/calimero-data" ]] \
  || fail "/mnt/data is not mounted from the mapper"
[[ ! -s "$(T_ fresh)/fstab" ]] || fail "the encrypted disk was written to fstab: $(cat "$(T_ fresh)/fstab")"
grep -q 'MERO_TEE_VERSION=2.3.70 MERO_TEE_MIN_VERSION=2.3.70 MERO_TEE_PROFILE=locked-read-only' "$(T_ fresh)/disk-key-env" \
  || fail "disk-key did not see MERO_TEE_VERSION/MIN_VERSION/PROFILE: $(cat "$(T_ fresh)/disk-key-env")"
logged fresh "LUKS2 dm-crypt mapping with integrity" || fail "the boot-time disk check did not run"
no_key_left fresh

# --- 2. a later boot: existing LUKS disk -> reopened, never reformatted -----
run_disk existing locked-read-only "$URL" 2.3.70 yes luks
E="$(T_ existing)"
printf 'key-for:existing-identity' >"$E/state/luks-key"
python3 -c 'import base64,json,sys; print(json.dumps({"type":"calimero-kms-identity","keyslots":[],"identity_b64":base64.b64encode(b"existing-identity").decode()}))' >"$E/state/tokens"
echo ext4 >"$E/state/mapperfs"
rm -f "$E/state/mounted-source"
# Re-run now that the disk looks like one this node formatted earlier.
: >"$E/calls"; : >"$E/log"
set +e; bash "$E/run.sh" >/dev/null 2>&1; echo $? >"$E/rc"; set -e
[[ "$(rc existing)" == 0 ]] || fail "an existing encrypted disk should open (rc=$(rc existing)); log: $(cat "$E/log")"
never_formatted existing
called existing '^merod kms disk-key' || fail "the key was not fetched for an existing disk"
called existing '^merod kms disk-key .*--create-identity' && fail "an existing disk must present its own identity, never mint one"
called existing '^cryptsetup open' || fail "the existing disk was not opened"
[[ "$(cat "$E/state/mounted-source")" == "$E/dev/mapper/calimero-data" ]] || fail "the existing disk was not mounted from the mapper"
no_key_left existing

# --- 3. a plain ext4 disk ---------------------------------------------------
# On locked-read-only a plain disk is refused: host-written state can carry a
# node identity the host also holds. Never formatted, never mounted.
run_disk plain-locked locked-read-only "$URL" 2.3.70 yes ext4
[[ "$(rc plain-locked)" != 0 ]] || fail "locked-read-only must refuse a plain (host-writable) data disk"
never_formatted plain-locked
logged plain-locked "host-writable" || fail "the refusal must say why"

# A debug profile keeps the old behaviour: mounted as before, with a warning.
run_disk legacy debug-read-only "$URL" 2.3.70 yes ext4
[[ "$(rc legacy)" == 0 ]] || fail "a debug profile's plain ext4 disk must keep working (rc=$(rc legacy))"
never_formatted legacy
called legacy '^merod kms disk-key' && fail "a plain disk needs no disk key"
[[ "$(cat "$(T_ legacy)/state/mounted-source")" == "$(T_ legacy)/dev/google-data" ]] || fail "the plain disk was not mounted"
logged legacy "UNENCRYPTED" || fail "a plain data disk must warn that it is unencrypted"
grep -q 'nofail' "$(T_ legacy)/fstab" || fail "a plain disk keeps its fstab entry as before"

# --- 4. anything else: refuse, touch nothing --------------------------------
for sig in ntfs ptable error; do
  run_disk "foreign-$sig" locked-read-only "$URL" 2.3.70 yes "$sig"
  [[ "$(rc "foreign-$sig")" != 0 ]] || fail "a disk holding '$sig' must stop the boot"
  never_formatted "foreign-$sig"
  called "foreign-$sig" '^mount .*google-data' && fail "a disk holding '$sig' was mounted"
  no_key_left "foreign-$sig"
done

# --- 5. LUKS but not ours / an opened volume with no filesystem -------------
run_disk luks-no-token locked-read-only "$URL" 2.3.70 yes luks
[[ "$(rc luks-no-token)" != 0 ]] || fail "a LUKS disk without our identity token must stop the boot"
never_formatted luks-no-token
logged luks-no-token "recreate the node" || fail "a LUKS disk without a token must say what to do"

run_disk luks-blank-volume locked-read-only "$URL" 2.3.70 yes luks
B="$(T_ luks-blank-volume)"
printf 'key-for:existing-identity' >"$B/state/luks-key"
python3 -c 'import base64,json; print(json.dumps({"type":"calimero-kms-identity","keyslots":[],"identity_b64":base64.b64encode(b"existing-identity").decode()}))' >"$B/state/tokens"
: >"$B/calls"; : >"$B/log"
set +e; bash "$B/run.sh" >/dev/null 2>&1; echo $? >"$B/rc"; set -e
[[ "$(rc luks-blank-volume)" != 0 ]] || fail "an opened volume with no ext4 must stop the boot, not be formatted"
never_formatted luks-blank-volume
no_key_left luks-blank-volume

run_disk luks-wrong-key locked-read-only "$URL" 2.3.70 yes luks
W="$(T_ luks-wrong-key)"
printf 'key-for:someone-else' >"$W/state/luks-key"
python3 -c 'import base64,json; print(json.dumps({"type":"calimero-kms-identity","keyslots":[],"identity_b64":base64.b64encode(b"existing-identity").decode()}))' >"$W/state/tokens"
: >"$W/calls"; : >"$W/log"
set +e; bash "$W/run.sh" >/dev/null 2>&1; echo $? >"$W/rc"; set -e
[[ "$(rc luks-wrong-key)" != 0 ]] || fail "a disk the KMS key does not open must stop the boot"
never_formatted luks-wrong-key
no_key_left luks-wrong-key

# --- 6. the decision for a blank disk, profile by profile -------------------
run_disk locked-no-kms locked-read-only "" 2.3.70 yes blank
[[ "$(rc locked-no-kms)" != 0 ]] || fail "locked-read-only must refuse to create a data disk without a KMS"
never_formatted locked-no-kms

run_disk locked-old-merod locked-read-only "$URL" 2.3.70 no blank
[[ "$(rc locked-old-merod)" != 0 ]] || fail "locked-read-only must refuse when merod has no 'kms disk-key'"
never_formatted locked-old-merod

run_disk debug-no-kms debug-read-only "" "" yes blank
[[ "$(rc debug-no-kms)" == 0 ]] || fail "a debug profile without a KMS keeps the old plain disk (rc=$(rc debug-no-kms))"
called debug-no-kms '^cryptsetup luksFormat' && fail "luksFormat ran with no KMS"
called debug-no-kms "^mkfs.ext4 .*google-data\$" || fail "the plain debug disk was not formatted"
logged debug-no-kms "UNENCRYPTED" || fail "a plain debug disk must say so"

run_disk debug-old-merod debug "$URL" 2.3.70 no blank
[[ "$(rc debug-old-merod)" == 0 ]] || fail "a debug profile on a merod without disk-key keeps a plain disk"
called debug-old-merod '^cryptsetup luksFormat' && fail "luksFormat ran without a disk key"
logged debug-old-merod "UNENCRYPTED" || fail "a plain debug disk must say so"

for profile in locked-read-only debug; do
  run_disk "no-release-$profile" "$profile" "$URL" "" yes blank
  [[ "$(rc "no-release-$profile")" != 0 ]] || fail "a KMS without tee-release-version must be refused on $profile"
  never_formatted "no-release-$profile"
done

run_disk kms-down locked-read-only "$URL" 2.3.70 yes blank down
[[ "$(rc kms-down)" != 0 ]] || fail "an unreachable KMS must stop the boot"
never_formatted kms-down
[[ "$(grep -c '^merod kms disk-key --kms-url' "$(T_ kms-down)/calls")" == 2 ]] || fail "the key fetch was not retried"
no_key_left kms-down

run_disk luks-kms-down locked-read-only "$URL" 2.3.70 yes luks down
L="$(T_ luks-kms-down)"
python3 -c 'import base64,json; print(json.dumps({"type":"calimero-kms-identity","keyslots":[],"identity_b64":base64.b64encode(b"existing-identity").decode()}))' >"$L/state/tokens"
: >"$L/calls"; : >"$L/log"
set +e; bash "$L/run.sh" >/dev/null 2>&1; echo $? >"$L/rc"; set -e
[[ "$(rc luks-kms-down)" != 0 ]] || fail "an existing disk whose key cannot be fetched must stop the boot"
never_formatted luks-kms-down

# --- 7. release pinning -----------------------------------------------------
#   run_pin NAME PROFILE RELEASE FLOOR
run_pin() {
  local name="$1" profile="$2" release="$3" floor="$4"
  local P="$WORK/pin-$name"
  mkdir -p "$P"
  [[ -n "$floor" ]] && printf '%s\n' "$floor" >"$P/min-tee-release-version"
  local block
  block="$(sed -e "s@/etc/calimero/min-tee-release-version@$P/min-tee-release-version@g" \
               -e "s@/etc/calimero/merod.env@$P/merod.env@g" <<<"$pin_block")"
  grep -q '/etc/calimero/' <<<"$block" && fail "the sliced pinning block still writes under /etc/calimero"
  cat >"$P/run.sh" <<RUN
set -euo pipefail
log() { echo "\$*" >>"$P/log"; }
fatal() { log "ERROR: \$*"; exit 1; }
IMAGE_PROFILE="$profile"
TEE_RELEASE_VERSION="$release"
$block
{ env | grep '^MERO_TEE_' || true; } | sort >"$P/exported"
RUN
  set +e
  bash "$P/run.sh" >/dev/null 2>&1
  echo $? >"$P/rc"
  set -e
}
prc() { cat "$WORK/pin-$1/rc"; }
penv() { cat "$WORK/pin-$1/merod.env" 2>/dev/null; }

run_pin equal locked-read-only 2.3.70 2.3.70
[[ "$(prc equal)" == 0 ]] || fail "a release equal to the image floor must be accepted"
penv equal | grep -qx 'MERO_TEE_VERSION="2.3.70"' || fail "merod.env lacks MERO_TEE_VERSION: $(penv equal)"
penv equal | grep -qx 'MERO_TEE_MIN_VERSION="2.3.70"' || fail "merod.env lacks MERO_TEE_MIN_VERSION: $(penv equal)"
penv equal | grep -qx 'MERO_TEE_PROFILE="locked-read-only"' || fail "merod.env lacks MERO_TEE_PROFILE on locked-read-only: $(penv equal)"
grep -qx 'MERO_TEE_MIN_VERSION=2.3.70' "$WORK/pin-equal/exported" || fail "MERO_TEE_MIN_VERSION is not exported for disk-key / init"
grep -qx 'MERO_TEE_PROFILE=locked-read-only' "$WORK/pin-equal/exported" || fail "MERO_TEE_PROFILE is not exported for disk-key / init"

run_pin newer locked-read-only 2.3.71 2.3.70
[[ "$(prc newer)" == 0 ]] || fail "a newer release must be accepted"
run_pin newer-minor locked-read-only 2.10.1 2.3.70
[[ "$(prc newer-minor)" == 0 ]] || fail "2.10.1 is newer than 2.3.70 (numeric, not lexical, comparison)"
run_pin tagged locked-read-only mero-kms-v2.3.72 2.3.70
[[ "$(prc tagged)" == 0 ]] || fail "a mero-kms-v-prefixed release must compare by its version"

run_pin older locked-read-only 2.3.69 2.3.70
[[ "$(prc older)" != 0 ]] || fail "a release older than the image must be refused (downgrade)"
[[ -z "$(penv older)" ]] || fail "merod.env was written for a refused downgrade"
run_pin older-lexical locked-read-only 2.3.9 2.3.70
[[ "$(prc older-lexical)" != 0 ]] || fail "2.3.9 is older than 2.3.70"
run_pin prerelease locked-read-only 2.3.70-rc.1 2.3.70
[[ "$(prc prerelease)" != 0 ]] || fail "2.3.70-rc.1 is older than 2.3.70 (semver), and must be refused"

run_pin debug-profile debug-read-only 2.3.70 2.3.70
[[ "$(prc debug-profile)" == 0 ]] || fail "a debug profile at the floor must be accepted"
penv debug-profile | grep -qx 'MERO_TEE_PROFILE="debug-read-only"' \
  || fail "a debug-read-only node must pin its own policy profile, not the locked one: $(penv debug-profile)"
grep -qx 'MERO_TEE_PROFILE=debug-read-only' "$WORK/pin-debug-profile/exported" \
  || fail "MERO_TEE_PROFILE is not exported for disk-key / init on debug-read-only"
penv debug-profile | grep -qx 'MERO_TEE_MIN_VERSION="2.3.70"' || fail "the floor applies on every profile"
run_pin debug debug 2.3.70 2.3.70
[[ "$(prc debug)" == 0 ]] || fail "the debug profile at the floor must be accepted"
penv debug | grep -qx 'MERO_TEE_PROFILE="debug"' \
  || fail "a debug node must pin its own policy profile: $(penv debug)"

run_pin no-floor locked-read-only 2.3.1 ""
[[ "$(prc no-floor)" == 0 ]] || fail "an image without a baked floor falls back to merod's own checks"
penv no-floor | grep -q 'MERO_TEE_MIN_VERSION' && fail "no floor file, yet MERO_TEE_MIN_VERSION was written"

run_pin no-release locked-read-only "" 2.3.70
[[ "$(prc no-release)" == 0 ]] || fail "no tee-release-version is decided later, by the disk and store checks"
[[ ! -e "$WORK/pin-no-release/merod.env" ]] || fail "merod.env must be absent without a release"

echo "PASS: the data disk is LUKS2-encrypted from the KMS, never reformatted once it holds anything, and the release cannot be downgraded below the image"
