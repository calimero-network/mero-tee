#!/usr/bin/env bash
# A log line must say which image the node runs.
#
# `locked-read-only` is production. The debug profiles are rebuilt freely and
# their certificates come from Let's Encrypt staging, so they are not publicly
# trusted. Without this field a line from a throwaway debug node reads exactly
# like one from production, and the only way to tell them apart is to
# cross-reference `nodes.image_profile` in mdma's database -- the kind of lookup
# nobody does before believing a graph.
#
# The partial config carries a `__IMAGE_PROFILE__` placeholder because Vector's
# VRL cannot read a file. `configure_vector.sh` substitutes it from
# `/etc/calimero/image-profile`, which the playbook writes at build time and the
# measured root hash covers -- so a node cannot misreport it.
#
# What fails quietly without this test:
#   * the placeholder shipping UNSUBSTITUTED, so every node reports the literal
#     string `__IMAGE_PROFILE__`;
#   * a missing profile file blanking the field rather than saying `unknown`;
#   * the field being set but left out of `VL-Stream-Fields`, so VictoriaLogs
#     does not index it and it cannot be queried.
#
# Usage: scripts/ci/tests/vector-image-profile-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="${REPO_ROOT}/mero-tee/ansible/roles/vector/files/configure_vector.sh"
PARTIAL="${REPO_ROOT}/mero-tee/ansible/roles/merotee/files/vector-partial-merod.yaml"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
mkdir -p "${SB}/bin" "${SB}/vector" "${SB}/calimero"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$SRC" ]]     || fail "cannot read ${SRC}"
[[ -r "$PARTIAL" ]] || fail "cannot read ${PARTIAL}"

grep -q '__IMAGE_PROFILE__' "$PARTIAL" \
  || fail "the partial config no longer carries the __IMAGE_PROFILE__ placeholder;
       either the field was dropped or it was hardcoded to one profile"

sed -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/calimero@${SB}/calimero@g" \
    "$SRC" > "${SB}/configure.sh"
chmod +x "${SB}/configure.sh"
cp "$PARTIAL" "${SB}/vector/vector_partial.yaml"

cat > "${SB}/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "${SB}/bin/systemctl"
PATH="${SB}/bin:${PATH}"
export PATH

run() { # <profile-file-contents-or-empty>
  rm -f "${SB}/vector/vector.yaml"
  if [[ -n "${1:-}" ]]; then printf '%s\n' "$1" > "${SB}/calimero/image-profile"
  else rm -f "${SB}/calimero/image-profile"; fi
  "${SB}/configure.sh" "${SB}/vector/vector_partial.yaml" \
    "https://victoria-lb.test/insert/elasticsearch" false gcp "" >"${SB}/out" 2>&1 \
    || { cat "${SB}/out" >&2; fail "configure_vector.sh exited non-zero"; }
  [[ -s "${SB}/vector/vector.yaml" ]] || fail "no vector.yaml was generated"
}

run "locked-read-only"
grep -q '\.instance_profile = "locked-read-only"' "${SB}/vector/vector.yaml" \
  || fail "the profile was not substituted into the transform:
$(grep -n 'instance_profile' "${SB}/vector/vector.yaml" || echo '       (field absent entirely)')"
grep -q '__IMAGE_PROFILE__' "${SB}/vector/vector.yaml" \
  && fail "an unsubstituted __IMAGE_PROFILE__ placeholder shipped in the final config"

run "debug-read-only"
grep -q '\.instance_profile = "debug-read-only"' "${SB}/vector/vector.yaml" \
  || fail "the debug profile was not substituted"

# Missing file must say `unknown`, not blank -- an empty value silently drops
# the dimension for that node while every other node still reports one.
run ""
grep -q '\.instance_profile = "unknown"' "${SB}/vector/vector.yaml" \
  || fail "a missing /etc/calimero/image-profile must yield \"unknown\", not an empty value:
$(grep -n 'instance_profile' "${SB}/vector/vector.yaml" || true)"

# Set but unindexed is the same as absent, from a query's point of view.
grep -q 'VL-Stream-Fields:.*instance_profile' "${SB}/vector/vector.yaml" \
  || fail "instance_profile is not in VL-Stream-Fields, so VictoriaLogs will not
       index it and it cannot be queried:
$(grep -n 'VL-Stream-Fields' "${SB}/vector/vector.yaml")"

echo "PASS: vector stamps instance_profile and indexes it"
