#!/usr/bin/env bash
#
# Rewrite mero-tee/build-inputs.lock.json from mero-tee/versions.json.
#
# The image build fetches every binary it bakes with `get_url: checksum:` from
# that lock (mero-tee/group_vars/all.yml), so moving a version in versions.json
# needs a matching lock entry or the build stops. This writes one: for each
# pinned component it reads the checksum file its publisher ships beside the
# release and records the sha256 of the exact archive the build downloads.
#
# The lock change is reviewed like code. The pin is what was published when
# this ran: an asset replaced upstream afterwards fails the build rather than
# being baked into an image.
#
#   scripts/release/pin-build-inputs.sh             # rewrite the lock
#   scripts/release/pin-build-inputs.sh --check     # exit 1 if it would change
#   scripts/release/pin-build-inputs.sh --download  # also hash each archive
#
# Run from the repository root (or pass --root). Needs curl and python3.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="write"
DOWNLOAD="false"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --download) DOWNLOAD="true"; shift ;;
    --root) ROOT="$2"; shift 2 ;;
    *) echo "usage: $0 [--check] [--download] [--root DIR]" >&2; exit 2 ;;
  esac
done

command -v curl >/dev/null || { echo "FATAL: curl is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "FATAL: python3 is required" >&2; exit 1; }

python3 - "$ROOT" "$MODE" "$DOWNLOAD" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

root, mode, download = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3] == "true"
versions_path = root / "mero-tee/versions.json"
lock_path = root / "mero-tee/build-inputs.lock.json"
versions = json.loads(versions_path.read_text())

# Each component: the versions.json key, where its release lives, the checksum
# file published with it, and the archives the build downloads (x86_64 only:
# Intel TDX is the only target).
COMPONENTS = {
    "merod": {
        "key": "merodVersion",
        "base": "https://github.com/calimero-network/core/releases/download/{v}",
        "sums": "SHA256SUMS",
        "assets": [
            "merod_x86_64-unknown-linux-gnu.tar.gz",
            "meroctl_x86_64-unknown-linux-gnu.tar.gz",
            "mero-auth_x86_64-unknown-linux-gnu.tar.gz",
        ],
    },
    "traefik": {
        "key": "traefikVersion",
        "base": "https://github.com/traefik/traefik/releases/download/v{v}",
        "sums": "traefik_v{v}_checksums.txt",
        "assets": ["traefik_v{v}_linux_amd64.tar.gz"],
    },
    "nodeExporter": {
        "key": "nodeExporterVersion",
        "base": "https://github.com/prometheus/node_exporter/releases/download/v{v}",
        "sums": "sha256sums.txt",
        "assets": ["node_exporter-{v}.linux-amd64.tar.gz"],
    },
    "vmagent": {
        "key": "vmagentVersion",
        "base": "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v{v}",
        "sums": "vmutils-linux-amd64-v{v}_checksums.txt",
        "assets": ["vmutils-linux-amd64-v{v}.tar.gz"],
    },
    "vector": {
        "key": "vectorVersion",
        "base": "https://github.com/vectordotdev/vector/releases/download/v{v}",
        "sums": "vector-{v}-SHA256SUMS",
        "assets": ["vector-{v}-x86_64-unknown-linux-gnu.tar.gz"],
    },
}


def fetch(url):
    out = subprocess.run(
        ["curl", "-fsSL", "--retry", "5", "--retry-delay", "2", "--retry-all-errors", url],
        check=False, capture_output=True,
    )
    if out.returncode != 0:
        sys.exit(f"FATAL: could not fetch {url}: {out.stderr.decode().strip()}")
    return out.stdout


def parse_sums(text):
    table = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            table[parts[-1].lstrip("*").removeprefix("./")] = parts[0].lower()
    return table


lock = {}
for name, c in COMPONENTS.items():
    version = versions.get(c["key"], "")
    if not version:
        sys.exit(f"FATAL: {versions_path} has no {c['key']}")
    base = c["base"].format(v=version)
    sums = parse_sums(fetch(f"{base}/{c['sums'].format(v=version)}").decode())
    pinned = {}
    for asset in (a.format(v=version) for a in c["assets"]):
        digest = sums.get(asset)
        if not digest:
            sys.exit(f"FATAL: {asset} is not listed in {base}/{c['sums'].format(v=version)}")
        if download:
            actual = hashlib.sha256(fetch(f"{base}/{asset}")).hexdigest()
            if actual != digest:
                sys.exit(f"FATAL: {asset} hashes to {actual}, but its checksum file says {digest}")
        pinned[asset] = digest
    lock[name] = {"version": version, "sha256": pinned}
    print(f"{name} {version}: {len(pinned)} archive(s) pinned")

rendered = json.dumps(lock, indent=2) + "\n"
current = lock_path.read_text() if lock_path.exists() else ""
if mode == "check":
    if rendered != current:
        sys.exit(f"FAIL: {lock_path} is stale; run scripts/release/pin-build-inputs.sh")
    print(f"OK: {lock_path} matches what is published")
elif rendered != current:
    lock_path.write_text(rendered)
    print(f"wrote {lock_path}")
else:
    print(f"{lock_path} already current")
PY
