#!/usr/bin/env bash
# Install the inference image's Python packages (vLLM and its dependencies)
# into an image tree, for the image's own Python: exactly
# mero-tee/inference/requirements.lock, wheels only, every one checked against
# its SHA-256. mero-tee/mkosi-image/build.sh runs it for ROLE=inference.
#
#   scripts/inference/install-runtime.sh TREE SITE_PACKAGES
#
# No bytecode is written (the root is read-only; Python compiles in memory),
# and uv's cache stays out of the tree. UV_CACHE_DIR may point at a download
# cache shared between builds.
set -euo pipefail
tree="${1:?tree}" site="${2:?site-packages path in the image}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dir="${repo}/mero-tee/inference"
target="${tree}${site}"
mkdir -p "${target}"
uv pip install \
  --target "${target}" \
  --python-version "$(tr -d '[:space:]' <"${dir}/python-version")" \
  --python-platform x86_64-manylinux_2_39 \
  --require-hashes --no-deps --only-binary :all: --no-compile \
  --index-url https://pypi.org/simple \
  --link-mode copy \
  -r "${dir}/requirements.lock"
# uv records itself as the installer and, for some, where it came from; both
# the same on every build, but nothing in the image reads them.
find "${target}" -maxdepth 2 -name direct_url.json -delete
echo "installed $(find "${target}" -maxdepth 1 -name '*.dist-info' | wc -l) distributions into ${site} ($(du -sh "${target}" | cut -f1))"
