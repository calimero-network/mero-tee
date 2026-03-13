#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

python3 - <<'PY'
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

print(
    "[release-version-sync] OK: "
    f"kms={kms_version}, merod={image_version}"
)
PY
