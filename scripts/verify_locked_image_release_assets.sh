#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <X.Y.Z>"
  exit 1
fi

signed_assets=(
  "mrtd-debug.json"
  "mrtd-debug-read-only.json"
  "mrtd-locked-read-only.json"
  "published-mrtds.json"
  "merod-locked-image-policy.json"
  "release-provenance.json"
  "attestation-artifacts.tar.gz"
  "locked-image-checksums.txt"
)

required_assets=("${signed_assets[@]}")
for asset in "${signed_assets[@]}"; do
  required_assets+=("${asset}.sig")
  required_assets+=("${asset}.pem")
done

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required"
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required"
  exit 1
fi
if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required"
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

echo "Inspecting release ${tag}..."
release_json=""
for attempt in $(seq 1 10); do
  release_json="$(gh release view "${tag}" --json tagName,targetCommitish,assets 2>/dev/null || true)"
  if [[ -n "${release_json}" ]]; then
    missing_asset=""
    for asset in "${required_assets[@]}"; do
      if ! jq -e --arg asset "${asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
        missing_asset="${asset}"
        break
      fi
    done
    if [[ -z "${missing_asset}" ]]; then
      break
    fi
  fi

  if [[ "${attempt}" -eq 10 ]]; then
    echo "Release asset set did not stabilize in time. Last missing asset: ${missing_asset:-unknown}"
    exit 1
  fi
  sleep 6
done

for pattern in "${required_assets[@]}"; do
  for attempt in $(seq 1 5); do
    if gh release download "${tag}" --pattern "${pattern}" --dir "${tmp_dir}" >/dev/null 2>&1; then
      break
    fi
    if [[ "${attempt}" -eq 5 ]]; then
      echo "Failed to download required asset ${pattern}"
      exit 1
    fi
    sleep 3
  done
done

for required in \
  "mrtd-debug.json" \
  "mrtd-debug-read-only.json" \
  "mrtd-locked-read-only.json" \
  "published-mrtds.json" \
  "merod-locked-image-policy.json" \
  "release-provenance.json" \
  "attestation-artifacts.tar.gz"; do
  if ! awk -v req="${required}" '
    {
      # Handle optional CRLF artifacts safely when reading from downloaded assets.
      gsub(/\r$/, "", $2)
      if ($2 == req) {
        found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  ' "${tmp_dir}/locked-image-checksums.txt" >/dev/null 2>&1; then
    echo "Checksums file missing entry for ${required}"
    exit 1
  fi
done

jq -e --arg tag "${tag}" '
  .tag == $tag and
  (.profiles.debug.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["debug-read-only"].mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["locked-read-only"].mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$"))
' "${tmp_dir}/published-mrtds.json" >/dev/null

jq -e --arg tag "${tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.profiles.debug.allowed_mrtd | type == "array" and length > 0) and
  (.profiles.debug.allowed_rtmr0 | type == "array") and
  (.profiles.debug.allowed_rtmr1 | type == "array") and
  (.profiles.debug.allowed_rtmr2 | type == "array") and
  (.profiles.debug.allowed_rtmr3 | type == "array") and
  (.profiles["debug-read-only"].allowed_mrtd | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_rtmr0 | type == "array") and
  (.profiles["debug-read-only"].allowed_rtmr1 | type == "array") and
  (.profiles["debug-read-only"].allowed_rtmr2 | type == "array") and
  (.profiles["debug-read-only"].allowed_rtmr3 | type == "array") and
  (.profiles["locked-read-only"].allowed_mrtd | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_rtmr0 | type == "array") and
  (.profiles["locked-read-only"].allowed_rtmr1 | type == "array") and
  (.profiles["locked-read-only"].allowed_rtmr2 | type == "array") and
  (.profiles["locked-read-only"].allowed_rtmr3 | type == "array")
' "${tmp_dir}/merod-locked-image-policy.json" >/dev/null

jq -e --arg tag "${tag}" '
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.profiles.debug.image.name | type == "string" and length > 0) and
  (.profiles["debug-read-only"].image.name | type == "string" and length > 0) and
  (.profiles["locked-read-only"].image.name | type == "string" and length > 0) and
  (.profiles.debug.external_verification.status == "performed") and
  (.profiles["debug-read-only"].external_verification.status == "performed") and
  (.profiles["locked-read-only"].external_verification.status == "performed") and
  (.profiles.debug.external_verification.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["debug-read-only"].external_verification.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["locked-read-only"].external_verification.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.mrtds.profiles.debug.mrtd == .profiles.debug.external_verification.mrtd) and
  (.mrtds.profiles["debug-read-only"].mrtd == .profiles["debug-read-only"].external_verification.mrtd) and
  (.mrtds.profiles["locked-read-only"].mrtd == .profiles["locked-read-only"].external_verification.mrtd) and
  (.measurement_policy.tag == $tag)
' "${tmp_dir}/release-provenance.json" >/dev/null

repo="${COSIGN_REPOSITORY:-}"
if [[ -z "${repo}" ]]; then
  repo="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi

cert_identity_regex="${COSIGN_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repo}/.github/workflows/gcp_locked_image_build.yaml@refs/heads/master$}"
cert_oidc_issuer="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

for asset in "${signed_assets[@]}"; do
  cosign verify-blob \
    --certificate "${tmp_dir}/${asset}.pem" \
    --signature "${tmp_dir}/${asset}.sig" \
    --certificate-identity-regexp "${cert_identity_regex}" \
    --certificate-oidc-issuer "${cert_oidc_issuer}" \
    "${tmp_dir}/${asset}" >/dev/null
done

echo "Release ${tag} asset set, provenance checks, and Sigstore signature verification passed."
