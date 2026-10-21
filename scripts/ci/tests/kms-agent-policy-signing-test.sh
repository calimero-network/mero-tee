#!/usr/bin/env bash
#
# The release signs each agent and inference allowlist
# (kms-{agent,inference}-attestation-policy.<profile>.json)
# and then verifies every signature it made. Signing writes `<asset>.bundle.json`
# beside each asset, and that name matches the allowlists' glob too, so the
# 2.3.114 release verified the bundles as if they were assets, found no
# `.bundle.json.pem`, and published nothing. This runs both scripts against a
# stub cosign and fails if either treats a sidecar as an asset.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

mkdir -p "${work}/bin" "${work}/artifacts" "${work}/release-assets"
cat >"${work}/bin/cosign" <<'COSIGN'
#!/usr/bin/env bash
# sign-blob writes the three sidecars; verify-blob needs the .pem and .sig it names.
set -euo pipefail
cmd="$1"; shift
asset="${@: -1}"
case "${cmd}" in
  sign-blob)
    while [[ $# -gt 1 ]]; do
      case "$1" in
        --output-signature) echo sig >"$2"; shift 2 ;;
        --output-certificate) echo pem >"$2"; shift 2 ;;
        --bundle) echo '{"verificationMaterial":{"tlogEntries":[{"logIndex":"1","integratedTime":"1","logId":{"keyId":"k"}}]}}' >"$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    echo "${asset}" >>"${COSIGN_SIGNED_LOG}" ;;
  verify-blob)
    while [[ $# -gt 1 ]]; do
      case "$1" in
        --certificate | --signature)
          [[ -f "$2" ]] || { echo "Error: open $2: no such file or directory" >&2; exit 1; }
          shift 2 ;;
        *) shift ;;
      esac
    done
    echo "${asset}" >>"${COSIGN_VERIFIED_LOG}" ;;
  *) echo "stub cosign: unexpected ${cmd}" >&2; exit 2 ;;
esac
COSIGN
chmod +x "${work}/bin/cosign"

cd "${work}"
echo bin >artifacts/mero-kms_2.3.114_x86_64.tar.gz
for f in kms-checksums.txt kms-release-manifest.json kms-attestation-policy.json \
  kms-attestation-policy.debug.json kms-attestation-policy.debug-read-only.json \
  kms-attestation-policy.locked-read-only.json kms-binaries-sbom.spdx.json \
  kms-trust-bundle.tar.gz kms-compatibility-map.json; do
  echo '{}' >"release-assets/${f}"
done
profiles=(debug debug-read-only locked-read-only)
for p in "${profiles[@]}"; do
  echo '{"role":"agent"}' >"release-assets/kms-agent-attestation-policy.${p}.json"
  echo '{"role":"inference"}' >"release-assets/kms-inference-attestation-policy.${p}.json"
done

export PATH="${work}/bin:${PATH}" COSIGN_SIGNED_LOG="${work}/signed" COSIGN_VERIFIED_LOG="${work}/verified"
export PREP_VERSION=2.3.114 GH_RUN_ID=1 GH_RUN_ATTEMPT=1
export GH_REPOSITORY=calimero-network/mero-tee COSIGN_CERTIFICATE_OIDC_ISSUER=https://token.actions.githubusercontent.com

bash "${ROOT}/scripts/release/kms/sign-release-assets.sh" >/dev/null
# A second signing pass (a retried step) must not sign the sidecars of the first.
bash "${ROOT}/scripts/release/kms/sign-release-assets.sh" >/dev/null
bash "${ROOT}/scripts/release/kms/verify-generated-signatures.sh"

failures=0
for log in signed verified; do
  if grep -E '\.(bundle\.json|sig|pem)$' "${log}" >/dev/null; then
    echo "FAIL: ${log} a sidecar as an asset:"; grep -E '\.(bundle\.json|sig|pem)$' "${log}"
    failures=$((failures + 1))
  fi
  for p in "${profiles[@]}"; do
    grep -qx "release-assets/kms-agent-attestation-policy.${p}.json" "${log}" \
      || { echo "FAIL: the ${p} agent allowlist was not ${log}"; failures=$((failures + 1)); }
    grep -qx "release-assets/kms-inference-attestation-policy.${p}.json" "${log}" \
      || { echo "FAIL: the ${p} inference allowlist was not ${log}"; failures=$((failures + 1)); }
  done
done
[[ -s release-assets/kms-agent-attestation-policy.locked-read-only.json.bundle.json ]] \
  || { echo "FAIL: no bundle for the locked-read-only agent allowlist"; failures=$((failures + 1)); }

if [[ ${failures} -gt 0 ]]; then
  echo "kms-agent-policy-signing-test: ${failures} failure(s)"
  exit 1
fi
echo "kms-agent-policy-signing-test: ok"
