#!/usr/bin/env bash
# New nodes get a KMS-encrypted store, and locked-read-only never creates a
# plaintext one.
#
# TDX protects the VM's memory, not its disks. merod's store holds the node's
# signing identity -- the key it was admitted under as a ReadOnlyTee -- and its
# account root, so a plaintext store on the host-readable data disk means a
# disk snapshot is a copy of an admitted fleet member. The store is therefore
# encrypted with a key mero-kms-phala releases only to an attested TD, and it
# has to be encrypted from `merod init` onwards: init is what writes those keys,
# and a store written in plaintext cannot later be opened encrypted.
#
# Unlike the data-disk test this one EXECUTES the decision: it slices the
# storage-encryption block (and `init_node`) out of the template, runs it
# against a stub merod, and checks what `merod init` was called with -- or that
# it was not called at all -- for every combination that matters:
#
#   * a KMS URL and a release   -> init --kms-url, MERO_TEE_VERSION exported
#   * a KMS URL, no release     -> refuse (the KMS could not be verified)
#   * no KMS URL, locked        -> refuse; on debug profiles, plaintext + WARN
#   * a merod without the flag  -> refuse on locked; plaintext + WARN on debug
#   * an existing encrypted node -> no init; refuse on locked with no release
#   * an existing plaintext node -> no init, keeps running, WARNs
#   * a half-initialised home   -> init retried (keyed on config.toml)
#   * no KMS, store on tmpfs    -> init without one (memory only, all profiles);
#     refused on locked when swap is active
#
# Usage: scripts/ci/tests/calimero-init-store-encryption-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- slice the code under test out of the template --------------------------
init_fn="$(awk '/^INIT_EXTRA_ARGS=\(\)$/,/^}$/' "$TEMPLATE")"
# The block runs from NODE_CONFIG to the end of the init decision (its first
# top-level `fi`). `fatal` and the MERO_TEE_VERSION export live earlier in the
# script (the data disk needs both first), so the harness provides them -- and
# checks below that the template still exports the release before init.
decision="$(awk '/^NODE_CONFIG="\$CALIMERO_HOME\/\$CALIMERO_NODE\/config.toml"$/{on=1} on{print} on && /^fi$/{n++} on && n==1{exit}' "$TEMPLATE")"
[[ -n "$init_fn" ]] || fail "could not find init_node / INIT_EXTRA_ARGS in the template; this test slices on them"
[[ -n "$decision" ]] || fail "could not find the storage-encryption block (NODE_CONFIG=...) in the template"
grep -qF 'merod_can_encrypt_at_init' <<<"$decision" \
  || fail "the sliced block does not contain the decision it is meant to test"
grep -qF 'init_node' <<<"$decision" \
  || fail "the sliced block does not reach init_node; the slice boundary moved"
# `merod init --kms-url` verifies the KMS against MERO_TEE_VERSION, so the
# template must export it (from the sanitized metadata value) before init runs.
export_line=$(grep -nF 'export MERO_TEE_VERSION="$SANITIZED_TEE_RELEASE_VERSION"' "$TEMPLATE" | head -1 | cut -d: -f1)
node_config_line=$(grep -nF 'NODE_CONFIG="$CALIMERO_HOME/$CALIMERO_NODE/config.toml"' "$TEMPLATE" | head -1 | cut -d: -f1)
if [[ -z "$export_line" || -z "$node_config_line" ]] || (( export_line > node_config_line )); then
  fail "calimero-init must export MERO_TEE_VERSION before the storage-encryption decision"
fi

# One scenario: metadata + profile + node-home state in, exit code and the
# stub's record of `merod init` out.
run_case() {
  local name="$1" profile="$2" kms_url="$3" release="$4" merod_kms="$5" home_state="$6"
  # Where the node home lives, and what `swapon` reports. Defaults: a disk, no swap.
  local store_fs="${7:-ext4}" swap="${8:-}"
  local dir="$WORK/$name"
  mkdir -p "$dir/bin" "$dir/home"

  # Stub merod: `init --help` advertises --kms-url only when asked to, and
  # `init` records its arguments and the release it saw.
  cat >"$dir/bin/merod" <<STUB
#!/usr/bin/env bash
if [[ " \$* " == *" --help "* ]]; then
  echo "Usage: merod init [OPTIONS]"
  [[ "$merod_kms" == yes ]] && echo "      --kms-url <URL>"
  exit 0
fi
[[ " \$* " == *" init "* ]] || exit 0
printf '%s\n' "\$*" >"$dir/init-args"
printf '%s\n' "\${MERO_TEE_VERSION:-}" >"$dir/init-release"
STUB
  chmod +x "$dir/bin/merod"
  printf '#!/usr/bin/env bash\necho %s\n' "$store_fs" >"$dir/bin/findmnt"
  printf '#!/usr/bin/env bash\n[[ -n "%s" ]] && echo "%s"\nexit 0\n' "$swap" "$swap" >"$dir/bin/swapon"
  chmod +x "$dir/bin/findmnt" "$dir/bin/swapon"

  case "$home_state" in
    fresh) ;;
    half) mkdir -p "$dir/home/default" ;;
    encrypted) mkdir -p "$dir/home/default"
               printf '[identity]\n\n[tee.kms.phala]\nurl = "https://kms/"\n' >"$dir/home/default/config.toml" ;;
    plaintext) mkdir -p "$dir/home/default"
               printf '[identity]\n' >"$dir/home/default/config.toml" ;;
  esac

  cat >"$dir/run.sh" <<RUN
set -euo pipefail
log() { echo "\$*" >>"$dir/log"; }
fatal() { log "ERROR: \$*"; exit 1; }
if [[ -n "$release" ]]; then export MERO_TEE_VERSION="$release"; fi
PATH="$dir/bin:\$PATH"
BIN_DIR="$dir/bin"
CALIMERO_HOME="$dir/home"
CALIMERO_NODE="default"
IMAGE_PROFILE="$profile"
MEROD_MODE="read-only"
SERVER_PORT=2428
SWARM_PORT=2528
KMS_PHALA_URL="$kms_url"
TEE_RELEASE_VERSION="$release"
SANITIZED_TEE_RELEASE_VERSION="$release"
$init_fn
$decision
RUN
  set +e
  bash "$dir/run.sh" >/dev/null 2>&1
  echo $? >"$dir/rc"
  set -e
}

rc() { cat "$WORK/$1/rc"; }
init_ran() { [[ -f "$WORK/$1/init-args" ]]; }
init_args() { cat "$WORK/$1/init-args"; }
logged() { grep -qF "$2" "$WORK/$1/log" 2>/dev/null; }

URL="https://kms.example:8080/"

# --- a new node with a KMS and a release: encrypted from the first write ----
run_case encrypt locked-read-only "$URL" 2.3.70 yes fresh
[[ "$(rc encrypt)" == 0 ]] || fail "a fresh node with kms-phala-url and a release should initialise (rc=$(rc encrypt))"
init_ran encrypt || fail "merod init was not run for a fresh node"
init_args encrypt | grep -qF -- "--kms-url $URL" \
  || fail "merod init was not given --kms-url: $(init_args encrypt)"
[[ "$(cat "$WORK/encrypt/init-release")" == 2.3.70 ]] \
  || fail "MERO_TEE_VERSION was not exported to merod init; it cannot verify the KMS without it"

# --- a KMS with no release to verify it against: refuse ---------------------
run_case no-release locked-read-only "$URL" "" yes fresh
[[ "$(rc no-release)" != 0 ]] || fail "a KMS URL without tee-release-version must stop the boot"
init_ran no-release && fail "merod init ran with an unverifiable KMS"

# --- no KMS on locked: refuse; on debug profiles: plaintext, loudly ---------
run_case locked-no-kms locked-read-only "" 2.3.70 yes fresh
[[ "$(rc locked-no-kms)" != 0 ]] || fail "locked-read-only must refuse to create a node without kms-phala-url"
init_ran locked-no-kms && fail "locked-read-only created a plaintext node"

run_case debug-no-kms debug-read-only "" 2.3.70 yes fresh
[[ "$(rc debug-no-kms)" == 0 ]] || fail "a debug profile without a KMS should still initialise"
init_ran debug-no-kms || fail "merod init was not run on a debug profile without a KMS"
init_args debug-no-kms | grep -qF -- '--kms-url' && fail "--kms-url passed with no KMS URL"
logged debug-no-kms "UNENCRYPTED" || fail "a plaintext debug node must say so in the log"

# --- a merod that cannot encrypt at init ------------------------------------
run_case locked-old-merod locked-read-only "$URL" 2.3.70 no fresh
[[ "$(rc locked-old-merod)" != 0 ]] || fail "locked-read-only must refuse when merod has no init --kms-url"
init_ran locked-old-merod && fail "locked-read-only created a plaintext node on a merod that cannot encrypt"

run_case debug-old-merod debug "$URL" 2.3.70 no fresh
[[ "$(rc debug-old-merod)" == 0 ]] || fail "a debug profile on an old merod should still initialise"
init_args debug-old-merod | grep -qF -- '--kms-url' && fail "--kms-url passed to a merod that does not have it"
logged debug-old-merod "UNENCRYPTED" || fail "a plaintext debug node must say so in the log"

# --- a store held only in memory (the release measurement VM) --------------
run_case memory-only locked-read-only "" "" yes fresh tmpfs
[[ "$(rc memory-only)" == 0 ]] || fail "locked-read-only on a tmpfs with no swap should initialise without a KMS (rc=$(rc memory-only))"
init_ran memory-only || fail "merod init was not run for a memory-only node"
init_args memory-only | grep -q -- '--kms-url' && fail "a memory-only node with no KMS URL passed --kms-url"
logged memory-only "TDX-encrypted memory" || fail "a memory-only node must say where its store is"

run_case memory-swap locked-read-only "" "" yes fresh tmpfs "/dev/sdb partition 4G 0B -2"
[[ "$(rc memory-swap)" != 0 ]] || fail "a tmpfs that can page out to swap is not memory-only; locked-read-only must refuse"
init_ran memory-swap && fail "locked-read-only created a store that swap could write to disk"

run_case memory-with-kms locked-read-only "$URL" 2.3.70 yes fresh tmpfs
init_args memory-with-kms | grep -qF -- "--kms-url $URL" \
  || fail "a memory-only node that is given a KMS must still use it"

# --- existing nodes are never re-initialised --------------------------------
run_case existing-encrypted locked-read-only "$URL" 2.3.70 yes encrypted
[[ "$(rc existing-encrypted)" == 0 ]] || fail "an existing encrypted node should boot"
init_ran existing-encrypted && fail "merod init re-ran over an existing node"

run_case encrypted-no-release locked-read-only "$URL" "" yes encrypted
[[ "$(rc encrypted-no-release)" != 0 ]] \
  || fail "an encrypted locked node with no tee-release-version must not start: merod would take its key from an unverified KMS"

run_case existing-plaintext locked-read-only "$URL" 2.3.70 yes plaintext
[[ "$(rc existing-plaintext)" == 0 ]] || fail "a pre-existing plaintext node must keep running"
init_ran existing-plaintext && fail "merod init re-ran over an existing plaintext node"
logged existing-plaintext "must be treated as exposed" \
  || fail "a pre-existing plaintext node must warn that its keys are exposed"

# --- a half-finished init is retried, not mistaken for a node ---------------
run_case half locked-read-only "$URL" 2.3.70 yes half
[[ "$(rc half)" == 0 ]] || fail "a node home without config.toml should be initialised"
init_ran half || fail "a node home left without config.toml (failed KMS fetch) was not re-initialised"

echo "PASS: new nodes are KMS-encrypted from init, locked-read-only never creates a plaintext store"
