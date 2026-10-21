#!/usr/bin/env bash
set -euo pipefail

# Extract one profile's node allowlist from a verified published-mrtds.json, and
# refuse anything that is not exactly what the KMS policy expects.
# Usage: extract-node-allowlist.sh <published-mrtds.json> <profile> <out.json>
#        extract-node-allowlist.sh --check <allowlist.json>
#
# --check holds a file already in the six-field shape (the agent allowlist
# Release mero-kms stages) to the same rules, and writes nothing.
#
# Each value is written verbatim into the measured kms.env, one `KEY=a,b,c`
# line per field. A signature says who wrote the file, not that it is
# well-formed, so the shape is checked here too: a newline in a value would add
# a line of its own to kms.env (say `ENFORCE_MEASUREMENT_POLICY=false`), and a
# comma would add an entry the release never measured.
#
# * measurements (MRTD, RTMR0-3): exactly 96 hex characters each, anchored to
#   the whole string (`\A`/`\z`): `$` also matches before a trailing newline;
# * TCB statuses: Intel's names, any case, `Revoked` never;
# * every field present, non-empty and at most MAX_ENTRIES long.
# The mero-kms role asserts the same shapes where kms.env is rendered.

MAX_ENTRIES=32
RULES="every MRTD/RTMR must be 96 hex characters, every TCB status a known non-revoked one, each list 1-${MAX_ENTRIES} long"

well_formed() {
  jq -e --argjson max "${MAX_ENTRIES}" '
    def entries: type == "array" and length > 0 and length <= $max and all(.[]; type == "string");
    type == "object"
    and ([.allowed_mrtd, .allowed_rtmr0, .allowed_rtmr1, .allowed_rtmr2, .allowed_rtmr3]
         | all(entries and all(.[]; test("\\A[0-9A-Fa-f]{96}\\z"))))
    and (.allowed_tcb_statuses | entries and all(.[]; ascii_downcase | IN(
          "uptodate", "swhardeningneeded", "configurationneeded",
          "configurationandswhardeningneeded", "outofdate", "outofdateconfigurationneeded")))
  ' "$1" >/dev/null 2>&1
}

if [[ "${1:-}" == "--check" ]]; then
  file="${2:?usage: extract-node-allowlist.sh --check <allowlist.json>}"
  if ! well_formed "${file}"; then
    echo "::error::${file} is not a well-formed allowlist: ${RULES}"
    exit 1
  fi
  exit 0
fi

src="${1:?usage: extract-node-allowlist.sh <published-mrtds.json> <profile> <out.json>}"
profile="${2:?profile is required}"
out="${3:?output path is required}"

jq --arg p "${profile}" '.profiles[$p] | {
    allowed_tcb_statuses, allowed_mrtd,
    allowed_rtmr0, allowed_rtmr1, allowed_rtmr2, allowed_rtmr3
  }' "${src}" > "${out}.tmp"

if ! well_formed "${out}.tmp"; then
  rm -f "${out}.tmp"
  echo "::error::${src} has no well-formed ${profile} node allowlist: ${RULES}"
  exit 1
fi
mv "${out}.tmp" "${out}"
