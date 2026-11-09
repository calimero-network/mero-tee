#!/usr/bin/env bash
# scripts/release/mkosi/build_timing.py summarises a timestamped mkosi build
# log. Check, on a synthetic log:
#   - each "‣" heading's phase runs until the next heading (the last to the
#     end), and they are listed longest first;
#   - the longest silence names the lines on both sides of it;
#   - a log that crosses midnight still counts forward;
#   - a log with no timestamps says so and does not fail the build.
#
# Usage: scripts/ci/tests/build-timing-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="${REPO_ROOT}/scripts/release/mkosi/build_timing.py"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() { echo "FAIL: $*"; exit 1; }

cat > "${work}/build.log" <<'LOG'
23:50:00 ‣ Building tools image
23:50:01 Get:1 http://snapshot.ubuntu.com/ubuntu noble/main amd64 bash
23:52:00 ‣  Installing Ubuntu
23:52:05 Get:2 http://snapshot.ubuntu.com/ubuntu noble/main amd64 systemd
00:09:05 Fetched 412 MB in 17min
00:09:10 ‣  Generating erofs root
00:10:10 ‣  Building UKI
00:10:40 done
LOG

out="$(python3 "${TOOL}" "${work}/build.log")"
echo "${out}"

grep -q "build timing:  20m40s over 8 lines" <<< "${out}" || fail "total should be 20m40s across midnight"
# Installing Ubuntu: 23:52:00 -> 00:09:10 = 17m10s, the longest phase, listed first.
first_phase="$(grep -A1 "mkosi phases" <<< "${out}" | tail -1)"
grep -q " 17m10s  Installing Ubuntu" <<< "${first_phase}" || fail "Installing Ubuntu should be first at 17m10s: ${first_phase}"
grep -q "  2m00s  Building tools image" <<< "${out}" || fail "tools image phase should be 2m00s"
grep -q "  0m30s  Building UKI" <<< "${out}" || fail "the last phase should run to the end of the log"
# The 17-minute silence names both sides.
grep -A1 " 17m00s  Get:2" <<< "${out}" | grep -q -- "-> Fetched 412 MB" || fail "the longest silence should name the lines around it"

printf 'no stamps here\n' > "${work}/plain.log"
python3 "${TOOL}" "${work}/plain.log" | grep -q "no timestamped lines" || fail "an unstamped log should say so"

echo "PASS: build-timing"
