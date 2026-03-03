#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <X.Y.Z>"
  exit 1
fi

required_assets=(
  "mrtd-debug.json"
  "mrtd-debug-read-only.json"
  "mrtd-locked-read-only.json"
  "published-mrtds.json"
  "release-provenance.json"
  "attestation-artifacts.tar.gz"
)

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required"
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required"
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

for pattern in "published-mrtds.json" "release-provenance.json"; do
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

jq -e --arg tag "${tag}" '
  .tag == $tag and
  (.profiles.debug.mrtd | type == "string") and
  (.profiles["debug-read-only"].mrtd | type == "string") and
  (.profiles["locked-read-only"].mrtd | type == "string")
' "${tmp_dir}/published-mrtds.json" >/dev/null

jq -e --arg tag "${tag}" '
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.profiles.debug.image.name | type == "string" and length > 0) and
  (.profiles["debug-read-only"].image.name | type == "string" and length > 0) and
  (.profiles["locked-read-only"].image.name | type == "string" and length > 0) and
  (.mrtds.profiles.debug.mrtd == .profiles.debug.external_verification.mrtd) and
  (.mrtds.profiles["debug-read-only"].mrtd == .profiles["debug-read-only"].external_verification.mrtd) and
  (.mrtds.profiles["locked-read-only"].mrtd == .profiles["locked-read-only"].external_verification.mrtd)
' "${tmp_dir}/release-provenance.json" >/dev/null

echo "Release ${tag} asset set and provenance checks passed."
