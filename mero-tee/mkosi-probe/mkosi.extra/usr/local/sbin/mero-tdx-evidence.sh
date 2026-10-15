#!/usr/bin/env bash
# Print this TD's CCEL event log and a TDX quote on the serial console, where
# `gcloud compute instances get-serial-port-output` reads them without any
# network. Each payload goes out as `MEROEV <label> <base64 chunk>` lines and a
# closing `MEROEV <label>-sha256 <hex>`: the console also carries the kernel's
# and systemd's lines, and the checksum is what says a payload arrived whole.
# scripts/attestation/shared/uki_probe_evidence.py reads them back.
set -uo pipefail
# A hangup on the console must not cut a payload short.
trap '' HUP

work=/run/mero-evidence
mkdir -p "$work"

emit() {
  local label="$1" file="$2"
  base64 -w 64 "$file" | sed "s/^/MEROEV ${label} /"
  echo "MEROEV ${label}-sha256 $(sha256sum "$file" | cut -c1-64)"
}

problem() {
  echo "MEROEV error $(tr ' ' '_' <<< "$*")"
}

echo "MEROEV kernel $(uname -r)"

if [[ -r /sys/firmware/acpi/tables/data/CCEL ]]; then
  cat /sys/firmware/acpi/tables/data/CCEL > "$work/ccel.bin"
  emit ccel "$work/ccel.bin"
else
  problem "no CCEL event log at /sys/firmware/acpi/tables/data/CCEL"
fi

# A quote through configfs-tsm. The report data is 64 zero bytes: the quote is
# read for its registers, not to prove freshness to anyone.
modprobe tdx_guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
report=/sys/kernel/config/tsm/report/mero-probe
if mkdir -p "$report" && head -c 64 /dev/zero > "$report/inblob" && cat "$report/outblob" > "$work/quote.bin" \
  && [[ -s "$work/quote.bin" ]]; then
  emit quote "$work/quote.bin"
else
  problem "no quote from configfs-tsm at $report"
fi

echo "MEROEV done ok"
