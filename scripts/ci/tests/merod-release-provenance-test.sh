#!/usr/bin/env bash
# release-provenance.json names the merod the release's images run
# ({version, sha256}), so mdma pins it on a cluster without an operator
# hashing the binary by hand. The values come from the probe VMs' release
# attestations. This pins, without any cloud:
#
#   * the three profiles' claims agreeing on the version versions.json pins
#     give {version, sha256}, the digest lowercased
#   * a missing attestation, a claim with no digest, another version than
#     versions.json, or profiles that disagree fail the release
#
# Usage: scripts/ci/tests/merod-release-provenance-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/release/node-image-gcp/merod-from-release-attestations.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SHA="$(printf 'AB%.0s' {1..32})"
echo '{"merodVersion": "1.0.0-rc.2"}' >"$WORK/versions.json"

claims() { # version sha [profile version sha]
  for p in debug debug-read-only locked-read-only; do
    jq -n --arg v "$1" --arg s "$2" '{nonce: "00", claim: {merodVersion: $v, merodSha256: $s, teeProfile: "x"}}' \
      >"$WORK/release-attestation-$p.json"
  done
}

claims 1.0.0-rc.2 "$SHA"
out="$(bash "$SCRIPT" "$WORK" "$WORK/versions.json")"
[[ "$(jq -r .version <<<"$out")" == "1.0.0-rc.2" ]] || fail "version: $out"
[[ "$(jq -r .sha256 <<<"$out")" == "$(tr '[:upper:]' '[:lower:]' <<<"$SHA")" ]] || fail "sha256: $out"

refused() { # label
  if bash "$SCRIPT" "$WORK" "$WORK/versions.json" >/dev/null 2>"$WORK/err"; then
    fail "$1 was accepted"
  fi
}

claims 1.0.0-rc.2 "$SHA"
rm "$WORK/release-attestation-locked-read-only.json"
refused "a missing attestation"

claims 1.0.0-rc.2 ""
refused "a claim with no digest"

claims 1.0.0-rc.1 "$SHA"
refused "another merod than versions.json"
grep -q "versions.json pins 1.0.0-rc.2" "$WORK/err" || fail "the version error does not name the pin: $(cat "$WORK/err")"

claims 1.0.0-rc.2 "$SHA"
jq '.claim.merodSha256 = "'"$(printf 'cd%.0s' {1..32})"'"' "$WORK/release-attestation-debug.json" >"$WORK/t"
mv "$WORK/t" "$WORK/release-attestation-debug.json"
refused "profiles that disagree"

echo "PASS: release-provenance.json names the attested merod"
