#!/usr/bin/env bash
#
# Everything the image build downloads is pinned by sha256.
#
# An image's measurement vouches for whatever was baked into it. A binary
# fetched by version alone is whatever the release host serves at build time,
# and `curl ... | bash` is whatever the installer host serves; neither is
# something a reviewer ever saw. So:
#
#   * mero-tee/build-inputs.lock.json pins, for the version versions.json
#     names, every component the build fetches, each with a 64-hex sha256
#     (mero-bot only once versions.json names meroBotVersion);
#   * every `get_url` in the image's Ansible carries `checksum:`, taken from
#     that lock;
#   * no `unarchive` fetches a URL itself (it cannot check a digest), and no
#     task pipes a download into a shell or calls curl or wget.
#
# Offline: it checks the lock against versions.json, not against the
# publishers. scripts/release/pin-build-inputs.sh --check does that.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

python3 - "$ROOT" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
versions = json.loads((root / "mero-tee/versions.json").read_text())
lock = json.loads((root / "mero-tee/build-inputs.lock.json").read_text())
failures = []

KEYS = {
    "merod": "merodVersion",
    "traefik": "traefikVersion",
    "nodeExporter": "nodeExporterVersion",
    "vmagent": "vmagentVersion",
    "vector": "vectorVersion",
    "node": "nodeVersion",
    "meroBot": "meroBotVersion",
}
# Pinned only once versions.json names a version: the agent image's mero-bot.
OPTIONAL = {"meroBot"}
for name, key in KEYS.items():
    entry = lock.get(name)
    if not entry and name in OPTIONAL and not versions.get(key):
        continue
    if not entry:
        failures.append(f"build-inputs.lock.json pins no {name}")
        continue
    if entry.get("version") != versions.get(key):
        failures.append(
            f"build-inputs.lock.json pins {name} {entry.get('version')} but versions.json "
            f"{key} is {versions.get(key)}; run scripts/release/pin-build-inputs.sh"
        )
    digests = entry.get("sha256") or {}
    if not digests:
        failures.append(f"build-inputs.lock.json pins no archive for {name}")
    for asset, digest in digests.items():
        if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
            failures.append(f"{name}: {asset} has no sha256 ({digest!r})")
for extra in sorted(set(lock) - set(KEYS)):
    failures.append(f"build-inputs.lock.json pins {extra}, which no versions.json key names")

group_vars = root / "mero-tee/group_vars/all.yml"
if "build-inputs.lock.json" not in group_vars.read_text():
    failures.append(f"{group_vars.relative_to(root)} must load build-inputs.lock.json as build_inputs")

# Split a task file into its tasks: each starts at a top-level `- name:`.
def tasks(text):
    text = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    return [t for t in re.split(r"(?m)^- ", text) if t.strip()]

sources = sorted((root / "mero-tee/ansible/roles").glob("*/tasks/*.yml"))
sources += sorted((root / "mero-tee").glob("playbook*.yml"))
for path in sources:
    rel = path.relative_to(root)
    for task in tasks(path.read_text()):
        title = re.search(r"name:\s*(.*)", task)
        title = title.group(1).strip() if title else "(unnamed task)"
        if re.search(r"(?m)^\s*(ansible\.builtin\.)?get_url:", task):
            if not re.search(r"(?m)^\s*checksum:\s*\"?sha256:\{\{\s*build_inputs\.", task):
                failures.append(f"{rel}: '{title}' downloads without a sha256 from build_inputs")
        if re.search(r"(?m)^\s*(ansible\.builtin\.)?unarchive:", task) and re.search(
            r"(?m)^\s*src:\s*\"?https?://", task
        ):
            failures.append(f"{rel}: '{title}' unarchives a URL directly; get_url it with a checksum first")
        if re.search(r"\b(curl|wget)\b", task) and re.search(r"(?m)^\s*(ansible\.builtin\.)?(shell|command|raw):", task):
            failures.append(f"{rel}: '{title}' downloads with curl/wget in a shell; use get_url with a checksum")

if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)
pinned = sum(len(e["sha256"]) for e in lock.values())
print(f"OK: {pinned} build inputs pinned by sha256, every download checked against them")
PY
