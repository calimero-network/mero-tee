#!/usr/bin/env bash
# Fetch a merod 1.0 node's release attestation and write it in the shapes the
# attestation scripts read.
#
# The release and staging probe VMs get no kms-url, so merod 1.0 does not run
# there (it takes its storage key from mero-kms only); calimero-init serves
# `merod attest --serve` on merod's port instead, behind traefik. It answers
# `GET /attestation/release?nonce=<64 hex>` with a fresh TDX quote whose report
# data is `nonce || SHA-256(release claim)` (core crates/client/src/attest/
# release.rs), needing no key, store or running node. v1's `/admin-api/health`,
# `/admin-api/tee/info` and `/admin-api/tee/attest` do not exist in merod 1.0.
#
# Usage: node_release_attestation.sh BASE_URL ARTIFACTS_DIR TIMEOUT_SECONDS
#
# Writes to ARTIFACTS_DIR:
#   release-attestation.json  the node's answer, as is
#   release-attestation-wait.json  the poll record (wait_for_http.py)
#   tee-attest-request.json   {nonce}
#   tee-attest-response.json  the answer plus `quoteB64` (= `quote`), the field
#                             verify_tdx_quote_ita.py, extract_tdx_policy_candidates.py
#                             and compute_rtmr.py read
#   tee-info.json             {data: {mrtd}, claim}: the MRTD the node read from
#                             its own quote, which verify_tdx_quote_ita.py checks
#                             against the verified one
# Exits 2 when the endpoint never answered 200 (the caller dumps the serial
# console), 1 when it answered something that is not a release attestation of
# real hardware for this nonce.
set -euo pipefail

base_url="${1:?base url}"
artifacts_dir="${2:?artifacts dir}"
timeout_seconds="${3:?timeout seconds}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

nonce="$(openssl rand -hex 32)"
jq -n --arg nonce "${nonce}" '{nonce: $nonce}' > "${artifacts_dir}/tee-attest-request.json"

if ! python3 "${script_dir}/../polling/wait_for_http.py" \
  --url "${base_url}/attestation/release?nonce=${nonce}" \
  --timeout-seconds "${timeout_seconds}" \
  --interval-seconds 5 \
  --request-timeout-seconds 10 \
  --expected-status 200 \
  --output-body "${artifacts_dir}/release-attestation.json" \
  --output-json "${artifacts_dir}/release-attestation-wait.json" \
  --heartbeat-interval 12 \
  --label "/attestation/release" \
  --verbosity "${CI_LOG_VERBOSITY:-compact}"; then
  exit 2
fi

envelope="${artifacts_dir}/release-attestation.json"
if ! jq -e . "${envelope}" >/dev/null 2>&1; then
  echo "::error::/attestation/release answered 200 with something that is not JSON"
  exit 1
fi
# The quote must be over our nonce, from real hardware, with the registers the
# node read from it (null only for a --dev merod's mock quote).
if ! jq -e --arg nonce "${nonce}" \
  '.nonce == $nonce and .mock == false and (.quote | type == "string" and length > 0) and (.measurements.mrtd | type == "string")' \
  "${envelope}" >/dev/null; then
  echo "::error::/attestation/release did not return a real-hardware quote over this nonce: $(jq -c '{nonce, mock, format, measurements}' "${envelope}")"
  exit 1
fi

jq '. + {quoteB64: .quote}' "${envelope}" > "${artifacts_dir}/tee-attest-response.json"
jq '{data: {mrtd: .measurements.mrtd}, claim: .claim}' "${envelope}" > "${artifacts_dir}/tee-info.json"
echo "Fetched /attestation/release (HTTP 200): merod $(jq -r '.claim.merodVersion' "${envelope}"), profile $(jq -r '.claim.teeProfile // "unset"' "${envelope}"), mrtd $(jq -r '.measurements.mrtd[:24]' "${envelope}")…"
