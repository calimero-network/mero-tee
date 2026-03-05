#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

python3 - <<'PY'
import hashlib
import json
import pathlib
import sys
import tomllib


def fail(message: str) -> None:
    print(f"[release-version-sync] ERROR: {message}")
    sys.exit(1)


root = pathlib.Path(".")

cargo_toml_path = root / "mero-kms/Cargo.toml"
cargo_lock_path = root / "Cargo.lock"
versions_json_path = root / "mero-tee/versions.json"
policy_index_path = root / "policies/index.json"

try:
    cargo_toml = tomllib.loads(cargo_toml_path.read_text())
except Exception as exc:
    fail(f"Could not parse {cargo_toml_path}: {exc}")

kms_version = cargo_toml.get("package", {}).get("version")
if not isinstance(kms_version, str) or not kms_version:
    fail("Missing mero-kms/Cargo.toml package.version")

try:
    versions_json = json.loads(versions_json_path.read_text())
except Exception as exc:
    fail(f"Could not parse {versions_json_path}: {exc}")

image_version = versions_json.get("imageVersion")
if not isinstance(image_version, str) or not image_version:
    fail("Missing mero-tee/versions.json imageVersion")

if kms_version != image_version:
    fail(
        "KMS and merod versions must be bumped together: "
        f"mero-kms/Cargo.toml has {kms_version}, versions.json has {image_version}"
    )

try:
    cargo_lock = tomllib.loads(cargo_lock_path.read_text())
except Exception as exc:
    fail(f"Could not parse {cargo_lock_path}: {exc}")

lock_versions = [
    pkg.get("version")
    for pkg in cargo_lock.get("package", [])
    if pkg.get("name") == "mero-kms-phala"
]
if not lock_versions:
    fail("Cargo.lock has no package entry for mero-kms-phala")
if len(lock_versions) != 1:
    fail(f"Expected exactly one mero-kms-phala entry in Cargo.lock, found {len(lock_versions)}")
if lock_versions[0] != kms_version:
    fail(
        "Cargo.lock mero-kms-phala version mismatch: "
        f"{lock_versions[0]} != {kms_version}"
    )

try:
    policy_index = json.loads(policy_index_path.read_text())
except Exception as exc:
    fail(f"Could not parse {policy_index_path}: {exc}")

releases = policy_index.get("releases")
if not isinstance(releases, list):
    fail("policies/index.json must contain a releases array")

entry = next((item for item in releases if item.get("version") == kms_version), None)
if entry is None:
    fail(f"policies/index.json missing releases entry for version {kms_version}")

if entry.get("kms_tag") != kms_version:
    fail(
        "kms_tag must match version exactly: "
        f"{entry.get('kms_tag')} != {kms_version}"
    )

expected_merod_tag = f"node-image-gcp-v{kms_version}"
if entry.get("node_image_tag") != expected_merod_tag:
    fail(
        "node_image_tag must be node-image-gcp-v<version>: "
        f"{entry.get('node_image_tag')}"
    )

expected_kms_policy_file = f"policies/kms-phala/{kms_version}.json"
expected_node_image_policy_file = f"policies/node-image-gcp/{kms_version}.json"

if entry.get("kms_policy_file") != expected_kms_policy_file:
    fail(
        f"kms_policy_file must be {expected_kms_policy_file}, got {entry.get('kms_policy_file')}"
    )
if entry.get("node_image_policy_file") != expected_node_image_policy_file:
    fail(
        f"node_image_policy_file must be {expected_node_image_policy_file}, got {entry.get('node_image_policy_file')}"
    )

kms_policy_file = root / expected_kms_policy_file
node_image_policy_file = root / expected_node_image_policy_file
if not kms_policy_file.exists():
    fail(f"Missing KMS policy file: {kms_policy_file}")
if not node_image_policy_file.exists():
    fail(f"Missing merod policy file: {node_image_policy_file}")


def sha256_hex(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


kms_sha = sha256_hex(kms_policy_file)
merod_sha = sha256_hex(node_image_policy_file)

if entry.get("kms_policy_sha256") != kms_sha:
    fail("kms_policy_sha256 does not match file contents")
if entry.get("node_image_policy_sha256") != merod_sha:
    fail("node_image_policy_sha256 does not match file contents")

try:
    kms_policy = json.loads(kms_policy_file.read_text())
    merod_policy = json.loads(node_image_policy_file.read_text())
except Exception as exc:
    fail(f"Failed to parse policy files as JSON: {exc}")

if kms_policy.get("release_tag") != kms_version:
    fail("KMS policy release_tag does not match version")
if merod_policy.get("release_tag") != kms_version:
    fail("merod policy release_tag does not match version")

print(
    "[release-version-sync] OK: "
    f"kms={kms_version}, merod={image_version}, "
    f"index.node_image_tag={entry.get('node_image_tag')}"
)
PY
