#!/usr/bin/env bash
# scripts/attestation/shared/uki_probe_evidence.py turns the UKI probe image's
# serial console into evidence, and checks the firmware measured the EFI binary
# the build produced. Build a synthetic PE, a CCEL log whose RTMR1 boot
# application event carries that PE's Authenticode hash, its quote, and a serial
# log that interleaves the payload with console noise. Then check:
#   - the Authenticode hash equals the value LIEF computes for the same bytes
#     (pinned below), so the tool's hash is not only checked against itself;
#   - extract reassembles the payloads, and refuses one that was corrupted;
#   - report finds the PE in RTMR1 and the replay matches the quote, and fails
#     for a PE the firmware did not measure.
#
# Usage: scripts/ci/tests/uki-probe-evidence-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="${REPO_ROOT}/scripts/attestation/shared/uki_probe_evidence.py"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() { echo "FAIL: $*"; exit 1; }

python3 - "${work}" "${REPO_ROOT}/scripts/attestation/shared" <<'PY'
import base64, hashlib, struct, sys

work, shared = sys.argv[1], sys.argv[2]
sys.path.insert(0, shared)
from uki_probe_evidence import authenticode_sha384

# lief.PE.parse(...).authentihash(lief.PE.ALGORITHMS.SHA_384) of pe(b"\x90").
LIEF_SHA384 = "b33684942f3ce94d5f2d0c772a838f3ffe0427d699885b7c1b0e0803bc46fedd85ad1cf5575ac17c0d0858c807143e39"

def pe(fill):
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<HBB", opt, 0, 0x20B, 0, 0)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x10000000)
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)
    struct.pack_into("<I", opt, 56, 0x2000)
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<I", opt, 64, 0x12345678)
    struct.pack_into("<H", opt, 68, 10)
    struct.pack_into("<I", opt, 108, 16)
    section = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + section
    return headers.ljust(0x200, b"\0") + fill * 0x200

measured, other = pe(b"\x90"), pe(b"\xcc")
assert authenticode_sha384(measured).hex() == LIEF_SHA384, authenticode_sha384(measured).hex()
open(f"{work}/measured.efi", "wb").write(measured)
open(f"{work}/other.efi", "wb").write(other)

spec = b"Spec ID Event03\x00" + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, 1) + struct.pack("<HH", 0x000C, 48) + b"\x00"
raw = struct.pack("<II", 0, 3) + bytes(20) + struct.pack("<I", len(spec)) + spec
registers = [bytes(48)] * 4
for mr, kind, digest, data in (
    (1, 0x00000004, hashlib.sha384(b"\0" * 4).digest(), b"\0" * 4),
    (2, 0x80000003, authenticode_sha384(measured), b"device path"),
    (3, 0x0000000D, hashlib.sha384(b"console=ttyS0").digest(), b"console=ttyS0"),
):
    raw += struct.pack("<IIIH", mr, kind, 1, 0x000C) + digest + struct.pack("<I", len(data)) + data
    registers[mr - 1] = hashlib.sha384(registers[mr - 1] + digest).digest()
raw += b"\xff" * 64
quote = bytearray(48 + 584)
for i, value in enumerate(registers):
    quote[48 + 328 + 48 * i : 48 + 328 + 48 * (i + 1)] = value

def emit(label, data):
    encoded = base64.b64encode(data).decode()
    lines = [f"MEROEV {label} {encoded[i:i + 64]}" for i in range(0, len(encoded), 64)]
    lines.insert(1, "[   12.345678] systemd[1]: Started some unit.")
    return lines + [f"MEROEV {label}-sha256 {hashlib.sha256(data).hexdigest()}"]

serial = ["Booting the probe", *emit("ccel", raw), "[  OK  ] Reached target multi-user", *emit("quote", bytes(quote)), "MEROEV done ok"]
open(f"{work}/serial.log", "w").write("\r\n".join(serial) + "\r\n")
corrupted = list(serial)
corrupted[1] = corrupted[1][:-1] + ("A" if corrupted[1][-1] != "A" else "B")
open(f"{work}/corrupted.log", "w").write("\n".join(corrupted) + "\n")
PY

python3 "${TOOL}" extract "${work}/serial.log" "${work}/out" >/dev/null || fail "extract refused a whole serial log"
for file in ccel.bin quote.bin evidence.json; do
  [[ -s "${work}/out/${file}" ]] || fail "extract wrote no ${file}"
done

if python3 "${TOOL}" extract "${work}/corrupted.log" "${work}/bad" 2>/dev/null; then
  fail "extract accepted a payload that does not match its checksum"
fi

reported="$(python3 "${TOOL}" report "${work}/out/evidence.json" --efi "${work}/measured.efi")" \
  || fail "report failed for the PE the log measured: ${reported}"
grep -q 'measured.efi.*measured as event #1 in RTMR1' <<< "${reported}" || fail "the PE is not found in RTMR1: ${reported}"
[[ "$(grep -c '| matches |' <<< "${reported}")" == "4" ]] || fail "the replay does not match all four RTMRs: ${reported}"

if reported="$(python3 "${TOOL}" report "${work}/out/evidence.json" --efi "${work}/other.efi")"; then
  fail "report passed for a PE the firmware never measured"
fi
grep -q 'other.efi.*not among the measured boot applications' <<< "${reported}" || fail "the unmeasured PE is not named: ${reported}"

echo "PASS: uki probe evidence"
