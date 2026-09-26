#!/usr/bin/env bash
# Write the signed-policy JSON merod pins a TDX cluster KMS by
# (`kms-tdx-attestation-policy.<profile>.json`).
#
# It sits beside the Phala policy (`kms-phala-attestation-policy.<profile>.json`)
# in the same KMS release, and uses the same layout so the same parser reads
# both, with two differences merod keys on (core#4085):
#
#   * `kms.backend` is "tdx": merod pins the KMS by all five registers, and
#   * there is no `kms_allowed_event_payload`: a TDX KMS has no dstack event log
#     and no compose file, and merod refuses a `tdx` policy that names one.
#
# `image` names the GCP image the measurements belong to, so a deployer (mdma)
# boots exactly the image this policy pins.
#
# Usage: write-tdx-policy.sh <profile> <measurements.json> <published-mrtds.json> <image.json> <out.json>
#   measurements.json  extract_tdx_policy_candidates.py output for the KMS image
#   published-mrtds.json  the matching node release's node allowlists
#   image.json         {"name": ..., "project": ..., "family": ...}
# Env: TAG, COMMIT, RUN_ID, RUN_ATTEMPT, REPOSITORY, WORKFLOW, REF,
#      DEFAULT_BINDING_HEX, DEFAULT_BINDING_B64
set -euo pipefail

[[ $# -eq 5 ]] || { echo "usage: $0 <profile> <measurements.json> <published-mrtds.json> <image.json> <out.json>" >&2; exit 2; }
profile="$1" measurements="$2" node_policy="$3" image="$4" out="$5"

for name in TAG COMMIT RUN_ID RUN_ATTEMPT REPOSITORY WORKFLOW REF DEFAULT_BINDING_HEX DEFAULT_BINDING_B64; do
  [[ -n "${!name:-}" ]] || { echo "::error::${name} is not set" >&2; exit 1; }
done
case "${profile}" in
  debug|debug-read-only|locked-read-only) ;;
  *) echo "::error::unknown profile '${profile}'" >&2; exit 1 ;;
esac

# Exactly one 96-hex value per register: one image, one measurement.
jq -e '
  .policy as $p
  | ($p.allowed_tcb_statuses | type == "array" and length > 0)
  and all(["allowed_mrtd","allowed_rtmr0","allowed_rtmr1","allowed_rtmr2","allowed_rtmr3"][];
          ($p[.] | type == "array" and length == 1 and (.[0] | test("^[0-9a-f]{96}$"))))
' "${measurements}" >/dev/null \
  || { echo "::error::${measurements} is not one complete measurement of a KMS image" >&2; exit 1; }

jq -e --arg p "${profile}" '
  .profiles[$p] as $n
  | $n != null
  and all(["allowed_tcb_statuses","allowed_mrtd","allowed_rtmr0","allowed_rtmr1","allowed_rtmr2","allowed_rtmr3"][];
          ($n[.] | type == "array" and length > 0))
' "${node_policy}" >/dev/null \
  || { echo "::error::${node_policy} has no complete ${profile} node allowlist" >&2; exit 1; }

jq -e '(.name | type == "string" and length > 0) and (.project | type == "string" and length > 0)' \
  "${image}" >/dev/null \
  || { echo "::error::${image} does not name an image and its project" >&2; exit 1; }

# RTMR3 carries the role (`calimero-rtmr3-v2:kms:...` vs `...:node:...`), so a
# KMS whose RTMR3 equals a node's is a mislabelled build, not a KMS.
kms_rtmr3="$(jq -r '.policy.allowed_rtmr3[0]' "${measurements}")"
if jq -e --arg p "${profile}" --arg r "${kms_rtmr3}" '.profiles[$p].allowed_rtmr3 | index($r)' \
    "${node_policy}" >/dev/null; then
  echo "::error::the ${profile} KMS measures the same RTMR3 as a node image" >&2
  exit 1
fi

jq -n \
  --arg profile "${profile}" \
  --arg tag "${TAG}" \
  --arg commit "${COMMIT}" \
  --arg run_id "${RUN_ID}" \
  --arg run_attempt "${RUN_ATTEMPT}" \
  --arg repository "${REPOSITORY}" \
  --arg workflow "${WORKFLOW}" \
  --arg ref "${REF}" \
  --arg default_binding_hex "${DEFAULT_BINDING_HEX}" \
  --arg default_binding_b64 "${DEFAULT_BINDING_B64}" \
  --slurpfile m "${measurements}" \
  --slurpfile n "${node_policy}" \
  --slurpfile i "${image}" \
  '($m[0].policy) as $k
  | ($n[0].profiles[$profile]) as $node
  | {
      schema_version: 1,
      role: "kms",
      profile: $profile,
      tag: $tag,
      commit_sha: $commit,
      workflow_run_id: $run_id,
      workflow_run_attempt: $run_attempt,
      generated_at: (now | todate),
      source: { repository: $repository, workflow: $workflow, ref: $ref },
      measurement_markers: {
        kms_role: "calimero.role=kms",
        node_role: "calimero.role=node",
        node_profile_key: "calimero.profile",
        node_root_hash_key: "calimero.root_hash"
      },
      kms: {
        backend: "tdx",
        provider: "mero-kms",
        attest_endpoint: "/attest",
        report_data_layout: {
          bytes_0_31: "nonce",
          bytes_32_63: "binding_or_default_domain_separator"
        },
        default_binding_hex: $default_binding_hex,
        default_binding_b64: $default_binding_b64
      },
      image: { name: $i[0].name, project: $i[0].project, family: ($i[0].family // null) },
      policy: {
        kms_allowed_tcb_statuses: $k.allowed_tcb_statuses,
        kms_allowed_mrtd: $k.allowed_mrtd,
        kms_allowed_rtmr0: $k.allowed_rtmr0,
        kms_allowed_rtmr1: $k.allowed_rtmr1,
        kms_allowed_rtmr2: $k.allowed_rtmr2,
        kms_allowed_rtmr3: $k.allowed_rtmr3,
        node_allowed_tcb_statuses: $node.allowed_tcb_statuses,
        node_allowed_mrtd: $node.allowed_mrtd,
        node_allowed_rtmr0: $node.allowed_rtmr0,
        node_allowed_rtmr1: $node.allowed_rtmr1,
        node_allowed_rtmr2: $node.allowed_rtmr2,
        node_allowed_rtmr3: $node.allowed_rtmr3
      },
      merod_config_path: "tee.kms.phala.attestation"
    }' > "${out}"
