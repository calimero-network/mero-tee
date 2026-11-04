#!/usr/bin/env bash
# Tools build-image.sh needs on a GitHub runner, next to mkosi itself
# (systemd/mkosi action): the role renderer's Python modules, sgdisk to move
# the backup GPT header, erofs-utils to unpack the root for the ownership
# check, zstandard to read the initrd (0.25.0: Ubuntu 24.04's
# python3-zstandard may stop after the initrd's first frame).
set -euo pipefail
sudo apt-get update -q >/dev/null
sudo apt-get install -y -q python3-jinja2 python3-yaml gdisk erofs-utils >/dev/null
sudo python3 -m pip install --quiet --break-system-packages zstandard==0.25.0
# uv installs the inference image's hash-locked wheels (scripts/inference/install-runtime.sh).
sudo python3 -m pip install --quiet --break-system-packages uv==0.11.32
