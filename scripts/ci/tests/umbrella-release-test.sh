#!/usr/bin/env bash
# The umbrella release VERSION (scripts/release/upsert-umbrella-release.sh),
# against a fake `gh` that keeps the repository's releases in files:
#
#   * it is created published, never as a draft (a draft has no tag, so the
#     other release workflow could not see it and made a second release)
#   * losing the create race to the other workflow is success
#   * drafts named VERSION, left by that race, are deleted
#   * it becomes Latest once mero-kms-vVERSION and mero-tee-vVERSION are both
#     published, and only if no higher umbrella version is published
#
# Usage: scripts/ci/tests/umbrella-release-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/release/upsert-umbrella-release.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
# published: one tag per line; drafts: "<id> <name>" per line; calls: what ran.
set -euo pipefail
S="${FAKE_GH_STATE:?}"
echo "$*" >>"$S/calls"
case "$1 $2" in
  "release view")
    if grep -qx "$3" "$S/published"; then echo false; else exit 1; fi ;;
  "release create")
    # The other workflow wins the race: its release exists, ours fails.
    if [[ -f "$S/lose_race" ]]; then echo "$3" >>"$S/published"; exit 1; fi
    for a in "$@"; do [[ "$a" == --draft* ]] && { echo "draft created" >>"$S/violations"; }; done
    echo "$3" >>"$S/published" ;;
  "release list")
    cat "$S/published" ;;
  "release edit")
    echo "$3" >"$S/latest" ;;
  "api --paginate")
    name="$(sed -n 's/.*\.name == "\([^"]*\)".*/\1/p' <<<"$*")"
    awk -v n="$name" '$2 == n { print $1 }' "$S/drafts" ;;
  "api -X")
    echo "${4##*/}" >>"$S/deleted" ;;
  *) echo "fake gh: unexpected $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$WORK/bin/gh"

run() { # version
  PATH="$WORK/bin:$PATH" FAKE_GH_STATE="$S" VERSION="$1" TARGET_COMMIT=abc GITHUB_REPOSITORY=o/r \
    bash "$SCRIPT" >"$S/out" 2>&1 || fail "the script failed for $1: $(cat "$S/out")"
}

fresh() {
  S="$WORK/state-$1"
  mkdir -p "$S"
  : >"$S/published"
  : >"$S/drafts"
}

# Both components published, no umbrella yet: created published, made Latest.
fresh created
printf '2.3.129\nmero-kms-v2.3.130\nmero-tee-v2.3.130\n' >"$S/published"
run 2.3.130
grep -qx 2.3.130 "$S/published" || fail "the umbrella was not created"
[[ ! -f "$S/violations" ]] || fail "the umbrella was created as a draft"
[[ "$(cat "$S/latest" 2>/dev/null)" == 2.3.130 ]] || fail "2.3.130 was not made Latest: $(cat "$S/out")"

# Only one component published so far: umbrella yes, Latest not yet.
fresh half
printf 'mero-kms-v2.3.131\n' >"$S/published"
run 2.3.131
grep -qx 2.3.131 "$S/published" || fail "the umbrella was not created"
[[ ! -f "$S/latest" ]] || fail "Latest moved before both components were published"

# The other workflow created it first; its leftover draft is deleted.
fresh race
printf 'mero-kms-v2.3.130\nmero-tee-v2.3.130\n' >"$S/published"
printf '427871982 2.3.130\n415005027 2.3.119\n' >"$S/drafts"
touch "$S/lose_race"
run 2.3.130
[[ "$(cat "$S/deleted" 2>/dev/null)" == 427871982 ]] || fail "deleted $(cat "$S/deleted" 2>/dev/null || echo nothing), wanted only the 2.3.130 draft"
[[ "$(cat "$S/latest" 2>/dev/null)" == 2.3.130 ]] || fail "2.3.130 was not made Latest after losing the race"

# A rerun of an older version never takes Latest back.
fresh older
printf '2.3.130\nmero-kms-v2.3.128\nmero-tee-v2.3.128\n' >"$S/published"
run 2.3.128
[[ ! -f "$S/latest" ]] || fail "an older version took Latest"
grep -q "2.3.130 is newer" "$S/out" || fail "no reason given: $(cat "$S/out")"

echo "PASS: the umbrella release is published, de-duplicated and Latest"
