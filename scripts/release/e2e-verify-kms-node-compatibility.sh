#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/release/e2e-verify-kms-node-compatibility.sh <node-artifacts-dir> <kms-release-assets-dir> <kms-probe-candidates-json>

Example:
  scripts/release/e2e-verify-kms-node-compatibility.sh artifacts e2e/kms-release e2e/kms-probe/kms-policy-candidates.json
EOF
}

node_artifacts_dir="${1:-}"
kms_release_assets_dir="${2:-}"
kms_probe_candidates_json="${3:-}"

if [[ -z "${node_artifacts_dir}" || -z "${kms_release_assets_dir}" || -z "${kms_probe_candidates_json}" ]]; then
  usage
  exit 1
fi

required_commands=(python3)
for cmd in "${required_commands[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "${cmd} is required"
    exit 1
  fi
done

python3 - "${node_artifacts_dir}" "${kms_release_assets_dir}" "${kms_probe_candidates_json}" <<'PY'
import json
import pathlib
import sys
from typing import Dict, List


def fail(message: str) -> None:
    print(f"[e2e-kms-node] ERROR: {message}")
    sys.exit(1)


def load_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Could not parse JSON {path}: {exc}")


def normalize(values: List[str]) -> List[str]:
    normalized = []
    for value in values:
        if not isinstance(value, str):
            continue
        normalized.append(value.strip().lower().removeprefix("0x"))
    return [value for value in normalized if value]


def kms_measurement_values(policy: dict, key: str) -> List[str]:
    return normalize(policy.get(f"kms_{key}", policy.get(key, [])))


node_dir = pathlib.Path(sys.argv[1])
kms_dir = pathlib.Path(sys.argv[2])
kms_probe_path = pathlib.Path(sys.argv[3])

profiles = ["debug", "debug-read-only", "locked-read-only"]
measurement_keys = [
    "allowed_mrtd",
    "allowed_rtmr0",
    "allowed_rtmr1",
    "allowed_rtmr2",
]

node_candidates: Dict[str, dict] = {}
for profile in profiles:
    path = node_dir / f"measurement-policy-candidates-{profile}.json"
    if not path.exists():
        fail(f"Missing node attestation artifact: {path}")
    payload = load_json(path)
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        fail(f"Node candidate policy missing in {path}")
    node_candidates[profile] = policy

kms_policies: Dict[str, dict] = {}
for profile in profiles:
    path = kms_dir / f"kms-phala-attestation-policy.{profile}.json"
    if not path.exists():
        fail(f"Missing KMS profile policy asset: {path}")
    payload = load_json(path)
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        fail(f"KMS policy missing in {path}")
    kms_policies[profile] = policy

kms_probe = load_json(kms_probe_path)
kms_probe_policy = kms_probe.get("policy")
if not isinstance(kms_probe_policy, dict):
    fail(f"KMS probe policy missing in {kms_probe_path}")

# 0) KMS profile policies must not collapse to identical KMS measurements.
for left_profile, right_profile in [
    ("debug", "debug-read-only"),
    ("debug", "locked-read-only"),
    ("debug-read-only", "locked-read-only"),
]:
    left_policy = kms_policies[left_profile]
    right_policy = kms_policies[right_profile]
    identical = True
    for key in measurement_keys:
        if kms_measurement_values(left_policy, key) != kms_measurement_values(right_policy, key):
            identical = False
            break
    if identical:
        fail(
            "KMS profile policies have identical MRTD/RTMR allowlists, expected profile separation: "
            f"{left_profile} vs {right_profile}"
        )

print("[e2e-kms-node] OK: KMS profile measurement allowlists are distinct")

# 1) Deployed KMS measurement must match published release policy.
locked_policy = kms_policies["locked-read-only"]
for key in ["allowed_tcb_statuses", *measurement_keys]:
    probe_values = normalize(kms_probe_policy.get(key, []))
    published_values = normalize(locked_policy.get(f"kms_{key}", locked_policy.get(key, [])))
    if not probe_values:
        fail(f"KMS probe candidates missing values for {key}")
    if not published_values:
        fail(f"Published KMS locked policy missing values for kms_{key}")
    if not set(probe_values).issubset(set(published_values)):
        fail(
            f"Deployed KMS measurements do not match published locked policy for {key}. "
            f"probe={probe_values} published={published_values}"
        )

print("[e2e-kms-node] OK: deployed KMS measurement candidates match published KMS policy")


def policy_allows_node(node_profile: str, kms_profile: str) -> bool:
    node_policy = node_candidates[node_profile]
    kms_policy = kms_policies[kms_profile]

    node_tcb_values = normalize(node_policy.get("allowed_tcb_statuses", []))
    allowed_tcb = normalize(
        kms_policy.get("node_allowed_tcb_statuses", kms_policy.get("allowed_tcb_statuses", []))
    )
    if not node_tcb_values or not allowed_tcb:
        return False
    if not set(node_tcb_values).issubset(set(allowed_tcb)):
        return False

    for key in measurement_keys:
        node_values = normalize(node_policy.get(key, []))
        allowed_values = normalize(kms_policy.get(f"node_{key}", kms_policy.get(key, [])))
        if not node_values or not allowed_values:
            return False
        if not set(node_values).issubset(set(allowed_values)):
            return False
    return True


# 2) Compatibility matrix: only matching profile is allowed.
results: Dict[str, Dict[str, bool]] = {}
for node_profile in profiles:
    row: Dict[str, bool] = {}
    for kms_profile in profiles:
        allowed = policy_allows_node(node_profile, kms_profile)
        row[kms_profile] = allowed
        expected = node_profile == kms_profile
        if allowed != expected:
            relation = "allowed" if allowed else "rejected"
            fail(
                "Profile compatibility mismatch: "
                f"node={node_profile} vs kms={kms_profile} was {relation}, expected "
                f"{'allowed' if expected else 'rejected'}"
            )
    results[node_profile] = row

print("[e2e-kms-node] Compatibility matrix (node profile -> KMS profile):")
for node_profile in profiles:
    row = " ".join(
        f"{kms_profile}={'ALLOW' if results[node_profile][kms_profile] else 'DENY'}"
        for kms_profile in profiles
    )
    print(f"  {node_profile}: {row}")

print("[e2e-kms-node] OK: profile allow/deny matrix is strict and correct")
PY
