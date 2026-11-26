#!/usr/bin/env bash
# calimero-init asks merod's `--help` which flags it takes, under `set -o
# pipefail`, and the answer must not depend on how fast merod writes.
#
# `merod ... --help | grep -q FLAG` is wrong under pipefail: `grep -q` exits at
# the first match, merod is still writing the rest of its help, its next write
# gets SIGPIPE (or EPIPE), and the pipeline fails although the flag is listed.
# A merod that takes a governance flag then stops the first boot with "this
# image's merod does not take --app-upgrades". On a loaded machine it made
# calimero-init-store-encryption-test.sh flaky, whose stub merod writes its help
# with many separate `echo`s.
#
# This test makes the race certain: the stub merod lists every flag first and
# then writes a megabyte more, far past what a pipe holds, so a pipeline that
# stops reading early always kills it. It slices each help probe out of the
# template and runs it under `set -euo pipefail`:
#
#   * the flag listed, then more help          -> true
#   * a help that does not list the flag       -> false
#   * the flag listed, but merod exits nonzero -> false
#
# It also checks that no `| grep -q` on a merod pipeline is left in the template.
#
# Usage: scripts/ci/tests/calimero-init-help-probe-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# fn NAME: the shell function NAME, sliced out of the template.
fn() {
  local body
  body="$(awk -v start="^$1\\\\(\\\\) \\\\{$" '$0 ~ start {on=1} on {print} on && /^}$/ {exit}' "$TEMPLATE")"
  [[ -n "$body" ]] || fail "could not find $1() in the template; this test slices on it"
  printf '%s\n' "$body"
}

# The stub merod. MODE long: every flag, then a megabyte of help, written line
# by line. absent: the same help without the flags. fails: the flags, then exit 2.
mkdir -p "$WORK/bin"
cat >"$WORK/bin/merod" <<'STUB'
#!/usr/bin/env bash
[[ " $* " == *" --help "* ]] || exit 0
echo "Usage: merod [OPTIONS] <COMMAND>"
if [[ "$MODE" != absent ]]; then
  echo "      --kms-identity <FILE>"
  echo "      --node-id <N>"
  echo "      --app-upgrades <APP_UPGRADES>"
  echo "      --attestation-verifier-url <URL>"
  echo "      --key-out <PATH>"
  echo "      --serve <ADDR>"
fi
[[ "$MODE" != fails ]] || exit 2
for ((i = 0; i < 16000; i++)); do
  echo "      --filler-$i <VALUE>  help text that a real merod prints after the flags"
done
STUB
chmod +x "$WORK/bin/merod"

# probe MODE CALL: the exit status of CALL (a probe and its arguments) against
# the stub merod in MODE.
probe() {
  local mode="$1" call="$2" name code
  name="${call%% *}"
  code="$(fn "$name")" || exit 1
  if [[ "$name" == merod_can_unlock_disk ]]; then
    code="$(fn disk_key_help)
$code" || exit 1
  fi
  cat >"$WORK/run.sh" <<RUN
set -euo pipefail
BIN_DIR="$WORK/bin"
$code
$call
RUN
  set +e
  MODE="$mode" bash "$WORK/run.sh" >/dev/null 2>&1
  local rc=$?
  set -e
  return "$rc"
}

CALLS=(
  "merod_init_takes --app-upgrades"
  "merod_init_takes --attestation-verifier-url"
  "merod_is_1_0"
  "merod_can_unlock_disk"
  "merod_can_attest"
)
for call in "${CALLS[@]}"; do
  probe long "$call" || fail "$call: false for a merod whose help lists the flag and goes on (the help pipeline died of SIGPIPE under pipefail)"
  probe absent "$call" && fail "$call: true for a merod whose help does not list the flag"
  probe fails "$call" && fail "$call: true for a merod whose --help exits nonzero"
done

# No merod help is piped into `grep -q` anywhere in the template.
# shellcheck disable=SC2016
if grep -nE '"\$BIN_DIR/merod".*\|[[:space:]]*grep[[:space:]]+-[a-zA-Z]*q' "$TEMPLATE"; then
  fail "the template pipes merod's help into grep -q; read it whole first (help=\"\$(...)\"; grep -q -- FLAG <<<\"\$help\")"
fi

echo "PASS: calimero-init's merod help probes answer the same however merod writes its help"
