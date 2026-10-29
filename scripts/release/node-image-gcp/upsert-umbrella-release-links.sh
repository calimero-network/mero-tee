#!/usr/bin/env bash
# The umbrella release VERSION: see scripts/release/upsert-umbrella-release.sh,
# which Release mero-kms and Release mero-tee share.
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/../upsert-umbrella-release.sh"
