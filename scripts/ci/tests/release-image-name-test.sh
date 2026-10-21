#!/usr/bin/env bash
# scripts/release/mkosi/release-image-name.sh names the release images. The
# rest of the release finds them by names it builds itself:
# resolve-image-vm-parameters.sh (node), release-kms.yaml's probe and record
# steps (kms, agent, inference), and mdma's dispatcher by the same prefixes. Check that
# the names agree, release and dev, for every role and profile.
#
# Usage: scripts/ci/tests/release-image-name-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tool="${REPO_ROOT}/scripts/release/mkosi/release-image-name.sh"
fail() { echo "FAIL: $*"; exit 1; }
get() { sed -n "s/^$1=//p"; }

version=2.3.119
v="${version//./-}"
for profile in locked-read-only debug-read-only debug; do
  for suffix in "" -d12-1; do
    dev=""; [[ -n "${suffix}" ]] && dev="-dev"
    out="$("${tool}" node "${profile}" "${version}" "${suffix}")"
    # resolve-image-vm-parameters.sh's image_name.
    [[ "$(get name <<< "${out}")" == "merotee-ubuntu-questing-25-10-${profile}-${v}${suffix}" ]] || fail "node name: ${out}"
    [[ "$(get family <<< "${out}")" == "merotee-ubuntu-questing-${profile}${dev}" ]] || fail "node family: ${out}"
    for role in kms agent inference; do
      out="$("${tool}" "${role}" "${profile}" "${version}" "${suffix}")"
      # release-kms.yaml: "merotee-${role}-${PROFILE}-${VERSION//./-}".
      [[ "$(get name <<< "${out}")" == "merotee-${role}-${profile}-${v}${suffix}" ]] || fail "${role} name: ${out}"
      [[ "$(get family <<< "${out}")" == "merotee-${role}-${profile}${dev}" ]] || fail "${role} family: ${out}"
    done
  done
done

# The longest names still fit GCE's 63 characters, and an unknown role or
# profile is refused rather than named.
"${tool}" node debug-read-only 2.3.119 -d9999-99 >/dev/null || fail "the longest dev name was refused"
if "${tool}" node debug-read-only 22.333.4444 -d999-99 >/dev/null 2>&1; then fail "a name over 63 characters was given"; fi
if "${tool}" node staging "${version}" >/dev/null 2>&1; then fail "an unknown profile was named"; fi
if "${tool}" gpu debug "${version}" >/dev/null 2>&1; then fail "an unknown role was named"; fi

echo "PASS: release image names"
