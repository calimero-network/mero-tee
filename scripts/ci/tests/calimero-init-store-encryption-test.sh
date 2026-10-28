#!/usr/bin/env bash
# merod 1.0 is configured from instance metadata, with its storage key from
# mero-kms only, and locked-read-only never boots a node without one.
#
# In TDX mode merod 1.0 takes its storage key K_r only from mero-kms
# (`--kms-url` + `--kms-identity`); `--storage-key[-file]` is refused without
# `--dev`, which this image never passes. So calimero-init must hand `merod
# init` the KMS and the cluster settings mdma stamps as instance metadata, check
# every value before it becomes the node's identity for good, and pass nothing
# that would weaken TDX mode or fix governance from the host.
#
# Like the data-disk test this one EXECUTES the decision: it slices the block
# (and `init_node`) out of the template, runs it against a stub merod and stub
# metadata, and checks what `merod init` was called with, or that it was not
# called at all:
#
#   * KMS, release, node-id, public-url, cluster -> init with the KMS identity
#     on the data disk and each metadata key as merod's own flag
#   * a KMS URL, no release                     -> refuse
#   * no KMS: locked with a disk store          -> refuse; memory-only or debug
#                                                  -> boot, merod not started
#   * a merod that is not 1.0                    -> refuse, on every profile
#   * no node-id / public-url; no cluster on locked -> refuse
#   * a value that is not the shape merod takes  -> refuse
#   * governance, --dev, storage keys, the ops token in the clear -> never passed
#   * an existing node                           -> no init, merod started
#   * v1 state on the disk                       -> warned about, left alone
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
decision="$(awk '/^NODE_CONFIG="\$CALIMERO_HOME\/\$CALIMERO_NODE\/config.toml"$/{on=1} /^# TLS material for traefik\.$/{exit} on{print}' "$TEMPLATE")"
[[ -n "$init_fn" ]] || fail "could not find init_node / INIT_EXTRA_ARGS in the template; this test slices on them"
[[ -n "$decision" ]] || fail "could not find the merod block (NODE_CONFIG=... up to the TLS material) in the template"
grep -qF 'merod_is_1_0' <<<"$decision" || fail "the sliced block does not contain the decision it is meant to test"
grep -qF '  init_node' <<<"$decision" || fail "the sliced block does not reach init_node; the slice boundary moved"
# merod verifies the KMS against MERO_TEE_VERSION, so the template must export
# it (from the sanitized metadata value) before the decision runs.
export_line=$(grep -nF 'export MERO_TEE_VERSION="$SANITIZED_TEE_RELEASE_VERSION"' "$TEMPLATE" | head -1 | cut -d: -f1)
node_config_line=$(grep -nF 'NODE_CONFIG="$CALIMERO_HOME/$CALIMERO_NODE/config.toml"' "$TEMPLATE" | head -1 | cut -d: -f1)
if [[ -z "$export_line" || -z "$node_config_line" ]] || (( export_line > node_config_line )); then
  fail "calimero-init must export MERO_TEE_VERSION before the merod decision"
fi
grep -q '^CALIMERO_HOME="/mnt/data/merod"$' "$TEMPLATE" \
  || fail "merod 1.0's home must be /mnt/data/merod, apart from v1's /mnt/data/calimero"

URL="https://kms.example:8080/"
PUBLIC="https://n1.eu1.example.com/"
SHA="$(printf 'ops' | sha256sum | awk '{print $1}')"

# run_case NAME PROFILE KMS_URL RELEASE MEROD(1.0|v1) HOME(fresh|existing|v1) STORE_FS [KEY=VALUE...]
# Each KEY=VALUE is one instance metadata item.
run_case() {
  local name="$1" profile="$2" kms_url="$3" release="$4" merod="$5" home_state="$6" store_fs="$7"
  shift 7
  local dir="$WORK/$name"
  mkdir -p "$dir/bin" "$dir/mnt/data/merod" "$dir/meta"
  local kv
  for kv in "$@"; do [[ -n "$kv" ]] && printf '%s' "${kv#*=}" >"$dir/meta/${kv%%=*}"; done

  cat >"$dir/bin/merod" <<STUB
#!/usr/bin/env bash
if [[ " \$* " == *" --help "* ]]; then
  echo "Usage: merod init [OPTIONS]"
  echo "      --kms-url <URL>"
  if [[ "$merod" == 1.0 ]]; then
    echo "      --node-id <N>"
    echo "      --kms-identity <FILE>"
  fi
  exit 0
fi
[[ " \$* " == *" init "* ]] || exit 0
printf '%s\n' "\$@" >"$dir/init-args"
printf '%s\n' "\${MERO_TEE_VERSION:-}" >"$dir/init-release"
STUB
  chmod +x "$dir/bin/merod"
  printf '#!/usr/bin/env bash\necho %s\n' "$store_fs" >"$dir/bin/findmnt"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$dir/bin/swapon"
  chmod +x "$dir/bin/findmnt" "$dir/bin/swapon"

  case "$home_state" in
    fresh) ;;
    existing) mkdir -p "$dir/mnt/data/merod/default"
              printf 'node-id = 1\nkms-url = "%s"\n' "$URL" >"$dir/mnt/data/merod/default/config.toml" ;;
    v1) mkdir -p "$dir/mnt/data/calimero/default"
        printf '[identity]\n' >"$dir/mnt/data/calimero/default/config.toml" ;;
  esac

  local block
  block="${decision//\"\/mnt\/data\/calimero\"/\"$dir\/mnt\/data\/calimero\"}"
  cat >"$dir/run.sh" <<RUN
set -euo pipefail
log() { echo "\$*" >>"$dir/log"; }
fatal() { log "ERROR: \$*"; exit 1; }
get_meta() { cat "$dir/meta/\$1" 2>/dev/null || true; }
if [[ -n "$release" ]]; then export MERO_TEE_VERSION="$release"; fi
PATH="$dir/bin:\$PATH"
BIN_DIR="$dir/bin"
CALIMERO_HOME="$dir/mnt/data/merod"
CALIMERO_NODE="default"
IMAGE_PROFILE="$profile"
KMS_URL="$kms_url"
TEE_RELEASE_VERSION="$release"
SANITIZED_TEE_RELEASE_VERSION="$release"
$init_fn
$block
echo "\$MEROD_READY" >"$dir/ready"
RUN
  set +e
  bash "$dir/run.sh" >/dev/null 2>&1
  echo $? >"$dir/rc"
  set -e
}

rc() { cat "$WORK/$1/rc"; }
ready() { cat "$WORK/$1/ready" 2>/dev/null || echo unset; }
init_ran() { [[ -f "$WORK/$1/init-args" ]]; }
# The argument after FLAG in merod init's argv, or nothing.
arg() { awk -v f="$2" 'p{print; exit} $0==f{p=1}' "$WORK/$1/init-args" 2>/dev/null; }
has_flag() { grep -qx -- "$2" "$WORK/$1/init-args" 2>/dev/null; }
logged() { grep -qF "$2" "$WORK/$1/log" 2>/dev/null; }

BASE=(node-id=1 "public-url=$PUBLIC" cluster=eu1)

# --- a new node: the KMS, its identity on the data disk, the cluster --------
run_case full locked-read-only "$URL" 2.3.70 1.0 fresh ext4 "${BASE[@]}" \
  "peers=1=https://n1.eu1.example.com/,2=https://n2.eu1.example.com/" bootstrap=true \
  rp-id=example.com "origins=https://app.example.com,https://cloud.example.com" \
  "ops-token-sha256=$SHA" "registry-url=https://registry.example.com/" apps-domain=apps.example.com \
  peer-profiles=locked-read-only peer-min-release=2.3.120 replicas=3 \
  release-approvals=operator app-upgrades=operator outbound-approvals=operator \
  dev=true storage-key=00 storage-key-file=/x ops-token=plain allow-unsigned-bundles=true listen=0.0.0.0:1
[[ "$(rc full)" == 0 ]] || fail "a new node with a KMS, a release and its cluster metadata should initialise (rc=$(rc full)): $(cat "$WORK/full/log")"
init_ran full || fail "merod init was not run for a new node"
[[ "$(arg full --kms-url)" == "$URL" ]] || fail "merod init was not given --kms-url"
[[ "$(arg full --kms-identity)" == "$WORK/full/mnt/data/merod/kms-identity" ]] \
  || fail "the KMS identity must live in merod's home on the data disk, got '$(arg full --kms-identity)'"
[[ "$(cat "$WORK/full/init-release")" == 2.3.70 ]] || fail "MERO_TEE_VERSION was not exported to merod init"
for kv in node-id=1 "public-url=$PUBLIC" cluster=eu1 \
          "peers=1=https://n1.eu1.example.com/,2=https://n2.eu1.example.com/" bootstrap=true \
          rp-id=example.com "origins=https://app.example.com,https://cloud.example.com" \
          "ops-token-sha256=$SHA" "registry-url=https://registry.example.com/" apps-domain=apps.example.com \
          peer-profiles=locked-read-only peer-min-release=2.3.120 replicas=3; do
  [[ "$(arg full "--${kv%%=*}")" == "${kv#*=}" ]] || fail "metadata ${kv%%=*} did not reach merod init as --${kv%%=*} ${kv#*=}"
done
for flag in --release-approvals --app-upgrades --outbound-approvals --dev --storage-key --storage-key-file \
            --ops-token --allow-unsigned-bundles --listen --data-dir --metrics-listen; do
  has_flag full "$flag" && fail "merod init was given $flag from instance metadata"
done
[[ "$(ready full)" == true ]] || fail "a node that initialised must be started"

# Only the keys that are set reach merod init.
run_case minimal debug "$URL" 2.3.70 1.0 fresh ext4 node-id=7 "public-url=$PUBLIC"
[[ "$(rc minimal)" == 0 ]] || fail "a debug node with node-id and public-url should initialise: $(cat "$WORK/minimal/log")"
[[ "$(wc -l <"$WORK/minimal/init-args")" == 13 ]] \
  || fail "unset metadata reached merod init: $(tr '\n' ' ' <"$WORK/minimal/init-args")"

# --- a KMS with no release to verify it against: refuse ---------------------
run_case no-release locked-read-only "$URL" "" 1.0 fresh ext4 "${BASE[@]}"
[[ "$(rc no-release)" != 0 ]] || fail "a KMS URL without tee-release-version must stop the boot"
init_ran no-release && fail "merod init ran with an unverifiable KMS"

# --- no KMS -------------------------------------------------------------------
run_case locked-no-kms locked-read-only "" 2.3.70 1.0 fresh ext4 "${BASE[@]}"
[[ "$(rc locked-no-kms)" != 0 ]] || fail "locked-read-only with its store on a disk must refuse to boot without kms-url"
init_ran locked-no-kms && fail "merod init ran without a KMS"

run_case memory-only locked-read-only "" "" 1.0 fresh tmpfs "${BASE[@]}"
[[ "$(rc memory-only)" == 0 ]] || fail "a memory-only node without a KMS (the measurement VM) must still boot"
init_ran memory-only && fail "merod init ran without a KMS on a memory-only node"
[[ "$(ready memory-only)" == false ]] || fail "merod must not be started without a storage key source"
logged memory-only "NOT started" || fail "a node that does not start merod must say so"

run_case debug-no-kms debug-read-only "" 2.3.70 1.0 fresh ext4 "${BASE[@]}"
[[ "$(rc debug-no-kms)" == 0 ]] || fail "a debug node without a KMS should boot (without merod)"
[[ "$(ready debug-no-kms)" == false ]] || fail "merod 1.0 cannot run without a KMS in TDX mode; it must not be started"

# --- a merod that is not 1.0 ---------------------------------------------------
run_case old-merod debug "$URL" 2.3.70 v1 fresh ext4 "${BASE[@]}"
[[ "$(rc old-merod)" != 0 ]] || fail "an image whose merod is not 1.0 must refuse, on every profile"
init_ran old-merod && fail "merod init ran on a merod that is not 1.0"

# --- required metadata ---------------------------------------------------------
run_case no-node-id locked-read-only "$URL" 2.3.70 1.0 fresh ext4 "public-url=$PUBLIC" cluster=eu1
[[ "$(rc no-node-id)" != 0 ]] || fail "a node without node-id metadata must not initialise"
run_case no-public-url locked-read-only "$URL" 2.3.70 1.0 fresh ext4 node-id=1 cluster=eu1
[[ "$(rc no-public-url)" != 0 ]] || fail "a node without public-url metadata must not initialise"
run_case no-cluster locked-read-only "$URL" 2.3.70 1.0 fresh ext4 node-id=1 "public-url=$PUBLIC"
[[ "$(rc no-cluster)" != 0 ]] || fail "locked-read-only must not take merod's default cluster (dev)"
init_ran no-cluster && fail "merod init ran on locked-read-only without a cluster"

# --- values that are not what merod takes -------------------------------------
n=0
for bad in "node-id=1; reboot" "node-id=-1" "public-url=javascript:alert(1)" "public-url=https://a b/" \
           "cluster=eu 1" "peers=1=https://n1/,two=https://n2/" "bootstrap=yes" \
           "ops-token-sha256=abc" "origins=https://a.example,ftp://b" "replicas=three" \
           "peer-profiles=Locked" "rp-id=-bad-.example"; do
  key="${bad%%=*}"
  args=("${BASE[@]}")
  args=("${args[@]/#${key}=*/}")
  n=$((n + 1))
  run_case "bad-$n" locked-read-only "$URL" 2.3.70 1.0 fresh ext4 "${args[@]}" "$bad"
  last="$WORK/bad-$n"
  [[ "$(cat "$last/rc")" != 0 ]] || fail "metadata '$bad' was accepted"
  [[ -f "$last/init-args" ]] && fail "merod init ran with metadata '$bad'"
done

# --- an existing node is never re-initialised ---------------------------------
run_case existing locked-read-only "$URL" 2.3.70 1.0 existing ext4 node-id=9 "public-url=$PUBLIC" cluster=eu1
[[ "$(rc existing)" == 0 ]] || fail "an existing node should boot"
init_ran existing && fail "merod init re-ran over an existing node"
[[ "$(ready existing)" == true ]] || fail "an existing node must be started"

run_case existing-no-release locked-read-only "$URL" "" 1.0 existing ext4
[[ "$(rc existing-no-release)" != 0 ]] || fail "an existing node with no tee-release-version must not start"

# --- v1 state on the disk is left alone ----------------------------------------
run_case v1-state locked-read-only "$URL" 2.3.70 1.0 v1 ext4 "${BASE[@]}"
[[ "$(rc v1-state)" == 0 ]] || fail "a disk holding v1 state should still get a merod 1.0 node"
logged v1-state "v1 node's state" || fail "v1 state on the disk must be reported"
[[ -f "$WORK/v1-state/mnt/data/calimero/default/config.toml" ]] || fail "v1 state was touched"

echo "PASS: merod 1.0 is configured from checked metadata with its storage key from mero-kms, and never without one on locked-read-only"
