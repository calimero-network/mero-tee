#!/usr/bin/env python3
"""Compute a UKI image's RTMR1 and RTMR2 (and RTMR3) from its build output, before it boots.

On a GCP TDX VM booting a unified kernel image directly (no shim, no boot
menu), the CCEL event log shows these two registers depend only on the disk
image and the UKI:

  RTMR1  "Calling EFI Application from Boot Option"   EV_EFI_ACTION
         separator (four zero bytes)                   EV_SEPARATOR
         the disk's GPT, as UEFI measures it          EV_EFI_GPT_EVENT
         the UKI's Authenticode SHA-384               EV_EFI_BOOT_SERVICES_APPLICATION
         "Exit Boot Services Invocation"               EV_EFI_ACTION
         "Exit Boot Services Returned with Success"    EV_EFI_ACTION
  RTMR2  for each UKI section systemd-stub measures, in its order:
         the section name with its NUL, then the section's contents

RTMR0 is Google's firmware and the machine shape, and does not come from the
image. RTMR3 is what the booted system extends: the init scripts extend it
once, with SHA-384("calimero-rtmr3-v3:<role>:<profile>:<roothash>"), roothash
being the dm-verity root hash on the UKI's command line. Given --role and
--profile, RTMR3 is computed too.

  compute_rtmr.py compute --disk DISK --uki UKI [--role ROLE --profile PROFILE]
                          [--out COMPUTED_JSON]
      Print the expected events and registers; write them as JSON.
  compute_rtmr.py compare COMPUTED_JSON EVIDENCE_JSON
      Compare them, event by event, with a booted TD's replayed CCEL log and
      its quote (evidence.json from uki_probe_evidence.py: quoteB64 and
      eventLogB64; without eventLogB64, the registers only). Prints Markdown;
      exits 1 on any difference.
"""

import argparse
import base64
import hashlib
import json
import struct
import sys

from tdx_event_log import EVENT_TYPES, describe, parse, quote_rtmrs
from uki_probe_evidence import authenticode_sha384

SECTOR = 512
GPT_HEADER_SIZE = 92  # sizeof(EFI_PARTITION_TABLE_HEADER), packed
# The order systemd-stub measures UKI sections in (its unified_sections[]),
# every one but .pcrsig, which holds the signature over the others.
STUB_SECTIONS = (
    ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb",
    ".uname", ".sbat", ".pcrpkey", ".profile", ".dtbauto", ".hwids", ".efifw",
)
MR_INDEX = {"RTMR1": 2, "RTMR2": 3}
RTMR3_FORMAT = "calimero-rtmr3-v3:{role}:{profile}:{roothash}"


def sha384(data):
    return hashlib.sha384(data).digest()


def gpt_event(disk):
    """UEFI_GPT_DATA, as the firmware builds it: the primary GPT header, the
    count of used entries (UINT64), then each entry whose type GUID is set."""
    with open(disk, "rb") as f:
        f.seek(SECTOR)
        header = f.read(GPT_HEADER_SIZE)
        if header[:8] != b"EFI PART":
            raise ValueError(f"{disk}: no GPT header at LBA 1")
        entries_lba, count, entry_size = struct.unpack_from("<QII", header, 72)
        f.seek(entries_lba * SECTOR)
        table = f.read(count * entry_size)
    used = [table[i * entry_size : (i + 1) * entry_size] for i in range(count)]
    used = [e for e in used if e[:16] != bytes(16)]
    return header + struct.pack("<Q", len(used)) + b"".join(used)


def pe_sections(pe):
    """{name: in-memory bytes} for each PE section: VirtualSize bytes, the
    raw data zero-filled past SizeOfRawData, as the loader maps them."""
    (pe_offset,) = struct.unpack_from("<I", pe, 0x3C)
    coff = pe_offset + 4
    (count,) = struct.unpack_from("<H", pe, coff + 2)
    (optional_size,) = struct.unpack_from("<H", pe, coff + 16)
    table = coff + 20 + optional_size
    sections = {}
    for i in range(count):
        raw_name, virtual_size, _, raw_size, raw_pointer = struct.unpack_from("<8sIIII", pe, table + 40 * i)
        data = pe[raw_pointer : raw_pointer + min(virtual_size, raw_size)]
        sections[raw_name.rstrip(b"\0").decode()] = data + bytes(max(0, virtual_size - raw_size))
    return sections


def compute(args):
    with open(args.uki, "rb") as f:
        uki = f.read()
    events = {
        "RTMR1": [
            ("action: Calling EFI Application from Boot Option", sha384(b"Calling EFI Application from Boot Option")),
            ("separator", sha384(bytes(4))),
            ("GPT of " + args.disk.rsplit("/", 1)[-1], sha384(gpt_event(args.disk))),
            ("UKI Authenticode", authenticode_sha384(uki)),
            ("action: Exit Boot Services Invocation", sha384(b"Exit Boot Services Invocation")),
            ("action: Exit Boot Services Returned with Success", sha384(b"Exit Boot Services Returned with Success")),
        ],
        "RTMR2": [],
    }
    sections = pe_sections(uki)
    for name in STUB_SECTIONS:
        if name in sections:
            events["RTMR2"].append((f"section name {name}", sha384(name.encode() + b"\0")))
            events["RTMR2"].append((f"section {name} ({len(sections[name])} bytes)", sha384(sections[name])))

    if args.role or args.profile:
        if not (args.role and args.profile):
            raise SystemExit("--role and --profile go together")
        cmdline = sections.get(".cmdline", b"").rstrip(b"\0").decode().split()
        roothash = [w.split("=", 1)[1] for w in cmdline if w.startswith("roothash=")]
        if len(roothash) != 1 or len(roothash[0]) != 64:
            raise SystemExit(f"the UKI's command line has no single roothash=: {' '.join(cmdline)}")
        event = RTMR3_FORMAT.format(role=args.role, profile=args.profile, roothash=roothash[0])
        events["RTMR3"] = [(event, sha384(event.encode()))]

    result = {"events": {}, "registers": {}}
    for register, items in events.items():
        value = bytes(48)
        for what, digest in items:
            value = sha384(value + digest)
        result["events"][register] = [{"what": what, "digest": digest.hex()} for what, digest in items]
        result["registers"][register] = value.hex()
        print(f"{register} {value.hex()}")
        for what, digest in items:
            print(f"  {digest.hex()[:24]}  {what}")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)
    return 0


def compare(args):
    with open(args.computed) as f:
        computed = json.load(f)
    with open(args.evidence) as f:
        encoded_log = json.load(f).get("eventLogB64")
    # Without the event log (a node whose merod predates core#4591 returns only
    # the quote) only the registers are compared.
    log = list(parse(base64.b64decode(encoded_log))) if encoded_log else None
    quoted = quote_rtmrs(args.evidence)
    ok = True

    print("## Computed from the build vs measured on the TD\n")
    print("| Register | Computed before boot | Quote | |")
    print("| --- | --- | --- | --- |")
    # RTMR3's one event is extended from user space, so it is in no firmware
    # event log; it is compared as a register only.
    for register in [r for r in ("RTMR1", "RTMR2", "RTMR3") if r in computed["registers"]]:
        same = computed["registers"][register] == quoted[register]
        ok &= same
        print(f"| {register} | `{computed['registers'][register][:24]}…` | `{quoted[register][:24]}…` | {'matches' if same else '**differs**'} |")

    if log is None:
        print("\nNo event log in the evidence: compared the registers only.")
        return 0 if ok else 1

    for register in ("RTMR1", "RTMR2"):
        measured = [e for e in log if e["mr"] == MR_INDEX[register] and e["type"] != 0x00000003]
        expected = computed["events"][register]
        print(f"\n### {register} event by event\n")
        print("| # | Computed | Measured | Measured event | |")
        print("| --- | --- | --- | --- | --- |")
        for i in range(max(len(expected), len(measured))):
            mine = expected[i] if i < len(expected) else None
            theirs = measured[i] if i < len(measured) else None
            same = bool(mine and theirs and mine["digest"] == theirs["digest"].hex())
            ok &= same
            name = EVENT_TYPES.get(theirs["type"], hex(theirs["type"])) if theirs else "(none)"
            seen = f"{name} {describe(theirs['type'], theirs['data'])[:60]}" if theirs else ""
            print(
                f"| {i} | {mine['what'] + ' `' + mine['digest'][:16] + '…`' if mine else '(none)'} "
                f"| `{theirs['digest'].hex()[:16] + '…' if theirs else ''}` | {seen.replace('|', '/')} "
                f"| {'matches' if same else '**differs**'} |"
            )
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    compute_parser = sub.add_parser("compute")
    compute_parser.add_argument("--disk", required=True)
    compute_parser.add_argument("--uki", required=True)
    compute_parser.add_argument("--out")
    compute_parser.add_argument("--role", help="node, kms, agent or inference: also compute RTMR3 (the image event)")
    compute_parser.add_argument("--profile", help="the image profile, with --role")
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("computed")
    compare_parser.add_argument("evidence")
    args = parser.parse_args()
    return compute(args) if args.command == "compute" else compare(args)


if __name__ == "__main__":
    sys.exit(main())
