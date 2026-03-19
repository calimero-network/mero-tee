#!/usr/bin/env bash
# Compare compose YAML produced by release probe vs MDMA for the same inputs.
# Run from mero-tee root. Usage: ./scripts/attestation/compare-compose-probe-vs-mdma.sh [version] [port]
# Default: version=2.1.85, port=8080

set -euo pipefail

VERSION="${1:-2.1.85}"
PORT="${2:-8080}"
IMAGE="ghcr.io/calimero-network/mero-kms-phala:mero-kms-v${VERSION}"

# Both probe and MDMA use scripts/phala/kms-compose-template.yaml (single source of truth).
probe_compose() {
  sed -e "s|__IMAGE_REF__|${IMAGE}|g" \
      -e "s|__SERVICE_PORT__|${PORT}|g" \
      scripts/phala/kms-compose-template.yaml
}

mdma_compose() {
  sed -e "s|__IMAGE_REF__|${IMAGE}|g" \
      -e "s|__SERVICE_PORT__|${PORT}|g" \
      scripts/phala/kms-compose-template.yaml
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

probe_file="${tmp_dir}/probe-compose.yaml"
mdma_file="${tmp_dir}/mdma-compose.yaml"

probe_compose > "${probe_file}"
mdma_compose > "${mdma_file}"

echo "=== Probe compose (${probe_file}) ==="
cat "${probe_file}"
echo ""
echo "=== MDMA compose (${mdma_file}) ==="
cat "${mdma_file}"
echo ""
echo "=== Diff (probe vs MDMA) ==="
if diff -u "${probe_file}" "${mdma_file}"; then
  echo "(no diff - identical)"
else
  echo ""
  echo "=== Hex dump first 200 bytes ==="
  echo "Probe:"
  xxd "${probe_file}" | head -15
  echo "MDMA:"
  xxd "${mdma_file}" | head -15
fi
