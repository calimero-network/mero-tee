#!/usr/bin/env bash
set -euo pipefail

source scripts/ci/logging.sh

if [[ -z "${ARTIFACTS_DIR:-}" || -z "${BASE_URL:-}" ]]; then
  ci_fail "MISSING_REQUIRED_ENV" "ARTIFACTS_DIR and BASE_URL are required."
  exit 1
fi

verify_endpoint="${BASE_URL}/admin-api/tee/verify-quote"

summarize_verify_quote_response() {
  local response_file="$1"
  jq -c '{ok, code, error, data: {quoteVerified, nonceVerified, applicationHashVerified}}' \
    "${response_file}" 2>/dev/null || true
}

quote_b64="$(jq -r '.data.quoteB64 // empty' "${ARTIFACTS_DIR}/tee-attest-response.json")"
nonce_hex="$(jq -r '.nonce // empty' "${ARTIFACTS_DIR}/tee-attest-request.json")"
if [[ -z "${quote_b64}" || -z "${nonce_hex}" ]]; then
  ci_fail "MISSING_QUOTE_OR_NONCE" "Missing quote or nonce in collected node attestation artifacts."
  exit 1
fi

jq -n \
  --arg quoteB64 "${quote_b64}" \
  --arg nonce "${nonce_hex}" \
  '{quoteB64: $quoteB64, nonce: $nonce}' \
  > "${ARTIFACTS_DIR}/tee-verify-quote-positive-request.json"
positive_status="$(curl -sS --max-time 20 \
  -o "${ARTIFACTS_DIR}/tee-verify-quote-positive-response.json" \
  -w "%{http_code}" \
  -X POST "${verify_endpoint}" \
  -H "Content-Type: application/json" \
  -d @"${ARTIFACTS_DIR}/tee-verify-quote-positive-request.json" || true)"
if [[ "${positive_status}" != "200" ]]; then
  ci_fail "VERIFY_QUOTE_POSITIVE_HTTP" "Positive /verify-quote check failed (HTTP ${positive_status})."
  exit 1
fi
if ! jq -e '.data.quoteVerified == true and .data.nonceVerified == true' \
  "${ARTIFACTS_DIR}/tee-verify-quote-positive-response.json" >/dev/null 2>&1; then
  ci_fail "VERIFY_QUOTE_POSITIVE_INVARIANT" "Positive /verify-quote check did not return quoteVerified=true and nonceVerified=true."
  summarize_verify_quote_response "${ARTIFACTS_DIR}/tee-verify-quote-positive-response.json"
  exit 1
fi
positive_passed="true"

wrong_nonce_hex="$(python3 -c 'import sys; n=sys.argv[1].strip().lower(); assert len(n)==64, "nonce must be 64 hex chars"; flip=("0" if n[0]!="0" else "1"); print(flip + n[1:])' "${nonce_hex}")"
jq -n \
  --arg quoteB64 "${quote_b64}" \
  --arg nonce "${wrong_nonce_hex}" \
  '{quoteB64: $quoteB64, nonce: $nonce}' \
  > "${ARTIFACTS_DIR}/tee-verify-quote-wrong-nonce-request.json"
wrong_nonce_status="$(curl -sS --max-time 20 \
  -o "${ARTIFACTS_DIR}/tee-verify-quote-wrong-nonce-response.json" \
  -w "%{http_code}" \
  -X POST "${verify_endpoint}" \
  -H "Content-Type: application/json" \
  -d @"${ARTIFACTS_DIR}/tee-verify-quote-wrong-nonce-request.json" || true)"
wrong_nonce_rejected="false"
if [[ "${wrong_nonce_status}" != "200" ]]; then
  wrong_nonce_rejected="true"
elif jq -e '.data.nonceVerified == false or .data.quoteVerified == false' \
  "${ARTIFACTS_DIR}/tee-verify-quote-wrong-nonce-response.json" >/dev/null 2>&1; then
  wrong_nonce_rejected="true"
fi
if [[ "${wrong_nonce_rejected}" != "true" ]]; then
  ci_fail "VERIFY_QUOTE_WRONG_NONCE_ACCEPTED" "Wrong nonce was not rejected by /verify-quote."
  summarize_verify_quote_response "${ARTIFACTS_DIR}/tee-verify-quote-wrong-nonce-response.json"
  exit 1
fi

tampered_quote_b64="$(python3 -c 'import base64,sys; raw=base64.b64decode(sys.argv[1], validate=False); assert len(raw)>0, "empty quote bytes"; b=bytearray(raw); b[0]^=0x01; print(base64.b64encode(bytes(b)).decode("ascii"))' "${quote_b64}")"
jq -n \
  --arg quoteB64 "${tampered_quote_b64}" \
  --arg nonce "${nonce_hex}" \
  '{quoteB64: $quoteB64, nonce: $nonce}' \
  > "${ARTIFACTS_DIR}/tee-verify-quote-tampered-quote-request.json"
tampered_quote_status="$(curl -sS --max-time 20 \
  -o "${ARTIFACTS_DIR}/tee-verify-quote-tampered-quote-response.json" \
  -w "%{http_code}" \
  -X POST "${verify_endpoint}" \
  -H "Content-Type: application/json" \
  -d @"${ARTIFACTS_DIR}/tee-verify-quote-tampered-quote-request.json" || true)"
tampered_quote_rejected="false"
if [[ "${tampered_quote_status}" != "200" ]]; then
  tampered_quote_rejected="true"
elif jq -e '.data.quoteVerified == false' \
  "${ARTIFACTS_DIR}/tee-verify-quote-tampered-quote-response.json" >/dev/null 2>&1; then
  tampered_quote_rejected="true"
fi
if [[ "${tampered_quote_rejected}" != "true" ]]; then
  ci_fail "VERIFY_QUOTE_TAMPERED_ACCEPTED" "Tampered quote was not rejected by /verify-quote."
  summarize_verify_quote_response "${ARTIFACTS_DIR}/tee-verify-quote-tampered-quote-response.json"
  exit 1
fi

wrong_app_hash_hex="$(openssl rand -hex 32)"
jq -n \
  --arg quoteB64 "${quote_b64}" \
  --arg nonce "${nonce_hex}" \
  --arg expectedApplicationHash "${wrong_app_hash_hex}" \
  '{quoteB64: $quoteB64, nonce: $nonce, expectedApplicationHash: $expectedApplicationHash}' \
  > "${ARTIFACTS_DIR}/tee-verify-quote-wrong-app-hash-request.json"
wrong_app_hash_status="$(curl -sS --max-time 20 \
  -o "${ARTIFACTS_DIR}/tee-verify-quote-wrong-app-hash-response.json" \
  -w "%{http_code}" \
  -X POST "${verify_endpoint}" \
  -H "Content-Type: application/json" \
  -d @"${ARTIFACTS_DIR}/tee-verify-quote-wrong-app-hash-request.json" || true)"
wrong_app_hash_rejected="false"
if [[ "${wrong_app_hash_status}" != "200" ]]; then
  wrong_app_hash_rejected="true"
elif jq -e '.data.applicationHashVerified == false or .data.quoteVerified == false' \
  "${ARTIFACTS_DIR}/tee-verify-quote-wrong-app-hash-response.json" >/dev/null 2>&1; then
  wrong_app_hash_rejected="true"
fi
if [[ "${wrong_app_hash_rejected}" != "true" ]]; then
  ci_fail "VERIFY_QUOTE_APP_HASH_ACCEPTED" "Wrong expected application hash was not rejected by /verify-quote."
  summarize_verify_quote_response "${ARTIFACTS_DIR}/tee-verify-quote-wrong-app-hash-response.json"
  exit 1
fi

jq -n \
  --arg endpoint "${verify_endpoint}" \
  --arg positive_status "${positive_status}" \
  --arg wrong_nonce_status "${wrong_nonce_status}" \
  --arg tampered_quote_status "${tampered_quote_status}" \
  --arg wrong_app_hash_status "${wrong_app_hash_status}" \
  --argjson positive_passed "${positive_passed}" \
  --argjson wrong_nonce_rejected "${wrong_nonce_rejected}" \
  --argjson tampered_quote_rejected "${tampered_quote_rejected}" \
  --argjson wrong_app_hash_rejected "${wrong_app_hash_rejected}" \
  '{
    schema_version: 1,
    verify_quote_endpoint: $endpoint,
    checks: {
      positive: {http_status: $positive_status, passed: $positive_passed},
      wrong_nonce: {http_status: $wrong_nonce_status, rejected: $wrong_nonce_rejected},
      tampered_quote: {http_status: $tampered_quote_status, rejected: $tampered_quote_rejected},
      wrong_expected_application_hash: {http_status: $wrong_app_hash_status, rejected: $wrong_app_hash_rejected}
    }
  }' > "${ARTIFACTS_DIR}/node-client-verification.json"

ci_result "node-image-gcp-anti-fake" "success" "ALL_NEGATIVE_CHECKS_REJECTED" "endpoint=${verify_endpoint}"
