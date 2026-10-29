#!/usr/bin/env bash
# Print the merod every profile of this release runs, as {version, sha256}, for
# release-provenance.json.
#
# Each profile's probe VM answered GET /attestation/release with a TDX quote
# whose report data binds the release claim (node_release_attestation.sh and
# node_anti_fake_http.py check that), and the claim names merod's version and
# the SHA-256 of the merod executable it runs. Every profile bakes the same
# merod, so the three claims must agree, and on the version versions.json
# pinned. Consumers (mdma) pin these two values on a cluster and refuse a node
# whose release attestation names another merod.
#
# Usage: merod-from-release-attestations.sh ARTIFACTS_DIR VERSIONS_JSON
set -euo pipefail

artifacts_dir="${1:?artifacts dir}"
versions_json="${2:?versions.json}"

pinned="$(jq -er '.merodVersion' "${versions_json}")"
merod=""
for profile in debug debug-read-only locked-read-only; do
  file="${artifacts_dir}/release-attestation-${profile}.json"
  if [[ ! -f "${file}" ]]; then
    echo "Missing ${file}: the ${profile} probe kept no release attestation" >&2
    exit 1
  fi
  claim="$(jq -c '{version: .claim.merodVersion, sha256: (.claim.merodSha256 // "" | ascii_downcase)}' "${file}")"
  if ! jq -e '(.version | type == "string" and length > 0) and (.sha256 | test("^[0-9a-f]{64}$"))' <<<"${claim}" >/dev/null; then
    echo "The ${profile} release attestation names no merod version and SHA-256: ${claim}" >&2
    exit 1
  fi
  if [[ "$(jq -r .version <<<"${claim}")" != "${pinned}" ]]; then
    echo "The ${profile} image runs merod $(jq -r .version <<<"${claim}"), but versions.json pins ${pinned}" >&2
    exit 1
  fi
  if [[ -n "${merod}" && "${claim}" != "${merod}" ]]; then
    echo "The profiles run different merods: ${merod} and ${claim} (${profile})" >&2
    exit 1
  fi
  merod="${claim}"
done
echo "${merod}"
