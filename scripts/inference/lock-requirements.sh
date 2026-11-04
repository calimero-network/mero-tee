#!/usr/bin/env bash
# Lock what the inference image runs: mero-tee/inference/requirements.in ->
# requirements.lock, every distribution pinned by version and SHA-256, for the
# image's own Python and platform (build.sh installs it with uv, wheels only).
#
#   scripts/inference/lock-requirements.sh
#
# Run it after changing requirements.in (a vLLM bump, say), and commit both.
# The image's Python is Ubuntu's python3 from the archive snapshot in
# mero-tee/mkosi-image/mkosi.conf; python-version names its minor version.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dir="${repo}/mero-tee/inference"
uv pip compile "${dir}/requirements.in" \
  --python-version "$(tr -d '[:space:]' <"${dir}/python-version")" \
  --python-platform x86_64-manylinux_2_39 \
  --only-binary :all: \
  --generate-hashes \
  --no-header \
  --index-url https://pypi.org/simple \
  -o "${dir}/requirements.lock"
echo "locked $(grep -c '==' "${dir}/requirements.lock") distributions in ${dir}/requirements.lock"
