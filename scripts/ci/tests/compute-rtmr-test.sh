#!/usr/bin/env bash
# scripts/attestation/shared/compute_rtmr.py computes a UKI image's RTMR1 and
# RTMR2 from its disk image and UKI, before boot. Build a synthetic GPT disk
# and a PE with UKI sections (in a file order unlike systemd-stub's), then check:
#   - the fixed RTMR1 events and the section-name events equal the digests a
#     GCP TDX VM measured (uki-tdx-probe runs 38766487553 and 38766492178),
#     so the calculator is not only checked against itself;
#   - sections are measured in systemd-stub's order, as name then contents,
#     at their in-memory size (zero-filled past the raw data);
#   - the GPT event counts and carries only the entries in use;
#   - compare passes for a log that matches and fails for one that does not.
#
# Usage: scripts/ci/tests/compute-rtmr-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="${REPO_ROOT}/scripts/attestation/shared/compute_rtmr.py"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() { echo "FAIL: $*"; exit 1; }

python3 - "${work}" "${REPO_ROOT}/scripts/attestation/shared" <<'PY'
import base64, hashlib, json, struct, sys

work, shared = sys.argv[1], sys.argv[2]
sys.path.insert(0, shared)
from compute_rtmr import gpt_event, pe_sections

# Measured on GCP TDX (first 24 hex digits of each SHA-384).
MEASURED = {
    "Calling EFI Application from Boot Option": "77a0dab2312b4e1e57a84d86",
    "separator": "394341b7182cd227c5c6b07e",
    "Exit Boot Services Invocation": "214b0bef1379756011344877",
    "Exit Boot Services Returned with Success": "0a2e01c85deae718a530ad8c",
    ".linux": "2fdc8531577607d99031d70f",
    ".osrel": "1d6077a2797911c374edbc61",
    ".cmdline": "93c4536618d5be4a74e2cb9c",
    ".initrd": "1bcd2ed729fb9dc7b1a168ab",
    ".uname": "16b48d924b98bdfe9d5c9798",
    ".sbat": "52a957bc706ceae8f202046a",
}
json.dump(MEASURED, open(f"{work}/measured.json", "w"))

# A PE whose sections are in a file order unlike the stub's, one of them with
# VirtualSize past its raw data.
sections = [  # name, contents, virtual size
    (b".sbat", b"sbat,1\n", 7),
    (b".uname", b"7.0.0", 5),
    (b".initrd", b"initrd", 6),
    (b".cmdline", b"console=ttyS0", 13),
    (b".osrel", b"ID=ubuntu\n", 16),  # 6 zero bytes past the raw data
    (b".linux", b"kernel", 6),
    (b".text", b"\x90" * 16, 16),  # not a UKI section: never measured
]
dos = bytearray(0x80)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x80)
coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 240, 0x22)
opt = bytearray(240)
struct.pack_into("<H", opt, 0, 0x20B)
struct.pack_into("<I", opt, 60, 0x400)
struct.pack_into("<I", opt, 108, 16)
table, body, offset = b"", b"", 0x400
for name, data, vsize in sections:
    raw = data.ljust(0x200, b"\0")
    table += struct.pack("<8sIIIIIIHHI", name, vsize, 0x1000 + offset, len(raw), offset, 0, 0, 0, 0, 0x40000040)
    body += raw
    offset += len(raw)
pe = (bytes(dos) + b"PE\0\0" + coff + bytes(opt) + table).ljust(0x400, b"\0") + body
# pe_sections reports VirtualSize bytes: the file's padding past VirtualSize is
# not measured, and a VirtualSize past the raw size would be zero-filled.
assert pe_sections(pe)[".osrel"] == b"ID=ubuntu\n" + bytes(6), pe_sections(pe)[".osrel"]
assert ".text" in pe_sections(pe)
open(f"{work}/uki.efi", "wb").write(pe)

# A GPT disk: entries 0 and 2 in use, 1 empty.
entry_size, count = 128, 128
entries = bytearray(entry_size * count)
for slot, (type_guid, part_guid) in ((0, (b"\x11" * 16, b"\x21" * 16)), (2, (b"\x12" * 16, b"\x22" * 16))):
    struct.pack_into("<16s16sQQQ", entries, slot * entry_size, type_guid, part_guid, 2048 + slot, 4096 + slot, 0)
header = bytearray(92)
header[0:8] = b"EFI PART"
struct.pack_into("<IIII", header, 8, 0x10000, 92, 0, 0)
struct.pack_into("<QQQQ", header, 24, 1, 131071, 34, 131038)
header[56:72] = b"\x33" * 16
struct.pack_into("<QII", header, 72, 2, count, entry_size)
disk = bytearray(64 * 1024 * 1024 // 64)
disk[512 : 512 + 92] = header
disk[1024 : 1024 + len(entries)] = entries
open(f"{work}/disk.raw", "wb").write(disk)
event = gpt_event(f"{work}/disk.raw")
assert event == bytes(header) + struct.pack("<Q", 2) + entries[0:128] + entries[256:384], "GPT event"
PY

computed="$(python3 "${TOOL}" compute --disk "${work}/disk.raw" --uki "${work}/uki.efi" --out "${work}/computed.json")" \
  || fail "compute failed: ${computed}"

python3 - "${work}" <<'PY' || fail "a computed event differs from what GCP measured"
import json, sys
work = sys.argv[1]
measured = json.load(open(f"{work}/measured.json"))
computed = json.load(open(f"{work}/computed.json"))["events"]
rtmr1 = [e["digest"][:24] for e in computed["RTMR1"]]
assert rtmr1[0] == measured["Calling EFI Application from Boot Option"]
assert rtmr1[1] == measured["separator"]
assert rtmr1[4] == measured["Exit Boot Services Invocation"]
assert rtmr1[5] == measured["Exit Boot Services Returned with Success"]
rtmr2 = computed["RTMR2"]
order = [e["what"].split()[-1] for e in rtmr2[0::2]]
assert order == [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"], order
for e in rtmr2[0::2]:
    name = e["what"].split()[-1]
    assert e["digest"][:24] == measured[name], name
PY

# A log replaying to the computed registers passes compare; one that does not fails.
python3 - "${work}" "${REPO_ROOT}/scripts/attestation/shared" <<'PY'
import base64, hashlib, json, struct, sys
work, shared = sys.argv[1], sys.argv[2]
computed = json.load(open(f"{work}/computed.json"))
spec = b"Spec ID Event03\x00" + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, 1) + struct.pack("<HH", 0x000C, 48) + b"\x00"
def build(tamper):
    raw = struct.pack("<II", 0, 3) + bytes(20) + struct.pack("<I", len(spec)) + spec
    registers = [bytes(48)] * 4
    for mr, register in ((2, "RTMR1"), (3, "RTMR2")):
        for i, e in enumerate(computed["events"][register]):
            digest = bytes.fromhex(e["digest"])
            if tamper and register == "RTMR2" and i == 7:
                digest = hashlib.sha384(b"another initrd").digest()
            raw += struct.pack("<IIIH", mr, 0x0D, 1, 0x000C) + digest + struct.pack("<I", 4) + b"data"
            registers[mr - 1] = hashlib.sha384(registers[mr - 1] + digest).digest()
    raw += b"\xff" * 64
    quote = bytearray(48 + 584)
    for i, value in enumerate(registers):
        quote[48 + 328 + 48 * i : 48 + 328 + 48 * (i + 1)] = value
    return {"quoteB64": base64.b64encode(bytes(quote)).decode(), "eventLogB64": base64.b64encode(raw).decode()}
json.dump(build(False), open(f"{work}/good.json", "w"))
json.dump(build(True), open(f"{work}/bad.json", "w"))
PY

python3 "${TOOL}" compare "${work}/computed.json" "${work}/good.json" >/dev/null \
  || fail "compare refused a log that replays to the computed registers"
if out="$(python3 "${TOOL}" compare "${work}/computed.json" "${work}/bad.json")"; then
  fail "compare passed a log with a different initrd"
fi
grep -q 'section .initrd.*\*\*differs\*\*' <<< "${out}" || fail "compare does not name the differing event: ${out}"

echo "PASS: compute rtmr"
