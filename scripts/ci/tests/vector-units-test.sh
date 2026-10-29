#!/usr/bin/env bash
# Every systemd service the merotee role installs ships its journal.
#
# A locked node has no shell, so a unit missing from vector-partial-merod.yaml's
# `include_units` is a subsystem nobody can debug. calimero-tls-cert.service was
# missing: a node stuck on its self-signed placeholder certificate said why only
# on the node itself.
#
# Usage: scripts/ci/tests/vector-units-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="${REPO_ROOT}/mero-tee/ansible/roles/merotee"
PARTIAL="${ROLE}/files/vector-partial-merod.yaml"

fail() { echo "FAIL: $*" >&2; exit 1; }

units="$(grep -ho '/etc/systemd/system/[A-Za-z0-9@._-]*\.service' "${ROLE}"/tasks/*.yml | xargs -n1 basename | sort -u)"
[[ -n "$units" ]] || fail "found no systemd services in ${ROLE}/tasks"

missing=()
for unit in $units; do
  grep -qF "\"${unit}\"" "$PARTIAL" || missing+=("$unit")
done
(( ${#missing[@]} == 0 )) || fail "not in include_units of ${PARTIAL#"${REPO_ROOT}"/}: ${missing[*]}"

echo "PASS: every merotee service ships its journal ($(echo "$units" | wc -l | tr -d ' ') units)"
