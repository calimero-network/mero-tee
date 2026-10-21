#!/usr/bin/env bash
# The model-sha256 to set for an inference host: the digest the TD computes
# over a model's files (docs/design/private-inference.md, "Weights digest").
#
#   hf download <owner/name> --revision <40-hex commit> --local-dir DIR
#   scripts/inference/model-digest.sh DIR
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 "${repo}/mero-tee/ansible/roles/mero-inference/files/inference_model.py" digest "${1:?model directory}"
