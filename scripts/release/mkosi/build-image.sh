#!/usr/bin/env bash
# Build one mkosi image (mero-tee/mkosi-image) for a role and profile, check it,
# package it for GCE and compute what it will measure.
#
# Required env:
#   ROLE, PROFILE        what to build (see mero-tee/mkosi-image/build.sh)
#   MKOSI_OUT            mkosi's output directory
#   EVIDENCE_DIR         where the evidence goes
# Optional env:
#   SERIAL_CONSOLE=true  diagnostic build: kernel and journal on ttyS0 (changes RTMR2)
#   MERO_KMS_BINARY, KMS_NODE_POLICY_FILE, KMS_AGENT_POLICY_FILE,
#   MERO_AGENT_GATE_BINARY, MERO_AGENT_BINARY, MERO_BOT_BUNDLE,
#   MERO_INFERENCE_GATE_BINARY                                   build.sh's inputs
#
# Output:
#   MKOSI_OUT/merotee-ROLE.tar.gz  the disk as GCE imports it (create-gce-image.sh)
#   EVIDENCE_DIR/                  the UKI, mkosi's and the renderer's manifests,
#     cmdline.txt, computed.json (RTMR1-3 before boot, for compute_rtmr.py
#     compare against the image's quote), root.digest and initrd.digest
#     (scripts/image/image_digest.py, to diff against another build), and
#     mkosi-build.log, the build's output with each line's UTC time.
#   On stdout, last: how long each mkosi phase took (build_timing.py).
#
# Needs root through sudo, mkosi v26, and install-tools.sh's tools.
set -euo pipefail

for var in ROLE PROFILE MKOSI_OUT EVIDENCE_DIR; do
  [[ -n "${!var:-}" ]] || { echo "::error::${var} is required"; exit 1; }
done
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "${EVIDENCE_DIR}" "${MKOSI_OUT}"

extra=()
if [[ "${SERIAL_CONSOLE:-false}" == "true" ]]; then
  # Appended to the image's command line. The journal goes to the console
  # too, so the init script's own log is in the serial output.
  extra=(--kernel-command-line="console=ttyS0,115200 systemd.journald.forward_to_console=1")
fi

# As root. Run as an unprivileged user, mkosi's user namespace maps every other
# id to root, and the image came out with every file root's: /etc/shadow not
# group shadow, dbus's launch helper not group messagebus,
# /var/lib/systemd/network not systemd-network's.
#
# Each line goes out with the UTC time it was printed, and the log is kept in
# the evidence (mkosi-build.log): the build has taken from 5 to 23 minutes for
# the same inputs, and build_timing.py (at the end of this script) says which
# stretch it was.
build_log="${EVIDENCE_DIR}/mkosi-build.log"
sudo --preserve-env=PROFILE,ROLE,MERO_KMS_BINARY,KMS_NODE_POLICY_FILE,KMS_AGENT_POLICY_FILE,MERO_AGENT_GATE_BINARY,MERO_AGENT_BINARY,MERO_BOT_BUNDLE,MERO_INFERENCE_GATE_BINARY,DOWNLOAD_CACHE \
  env "PATH=${PATH}" "${repo}/mero-tee/mkosi-image/build.sh" "${MKOSI_OUT}" -- "${extra[@]}" 2>&1 \
  | perl -MPOSIX -ne 'BEGIN { $| = 1 } print strftime("%H:%M:%S ", gmtime), $_' \
  | tee "${build_log}"
sudo chown -R "$(id -u):$(id -g)" "${MKOSI_OUT}"
ls -la "${MKOSI_OUT}"
efi="${EVIDENCE_DIR}/merotee-${ROLE}.efi"
cp "${MKOSI_OUT}/merotee-${ROLE}.efi" "${MKOSI_OUT}/merotee-${ROLE}.manifest" \
   "${MKOSI_OUT}/merotee-${ROLE}.rendered.json" "${EVIDENCE_DIR}/"
sha256sum "${efi}" | tee "${EVIDENCE_DIR}/uki.sha256"

# What RTMR2 measures: the dm-verity root hash (and so the whole root), role
# and profile, and on locked-read-only no console (lockdown R2).
python3 - "${efi}" "${repo}" <<'PY' | tee "${EVIDENCE_DIR}/cmdline.txt"
import os, re, sys
sys.path.insert(0, f"{sys.argv[2]}/scripts/attestation/shared")
from compute_rtmr import pe_sections
cmdline = pe_sections(open(sys.argv[1], "rb").read())[".cmdline"].rstrip(b"\0").decode().split()
print(" ".join(cmdline))
problems = []
if not any(re.fullmatch(r"roothash=[0-9a-f]{64}", w) for w in cmdline):
    problems.append("no roothash=")
profile = os.environ["PROFILE"]
for want in (f"calimero.role={os.environ['ROLE']}", f"calimero.profile={profile}", "systemd.volatile=overlay"):
    if want not in cmdline:
        problems.append(f"no {want}")
console = any(w.startswith("console=") for w in cmdline)
if profile == "locked-read-only" and console and os.environ.get("SERIAL_CONSOLE") != "true":
    problems.append("console= is set")
if profile != "locked-read-only" and not console:
    problems.append(f"no console= on {profile}")
if problems:
    sys.exit("UKI command line: " + "; ".join(problems))
PY

# GCE imports a raw disk named disk.raw, a whole number of GiB, in a sparse
# oldgnu tarball. Growing the file leaves the backup GPT header short of the
# end, so it is moved there.
cp --sparse=always "${MKOSI_OUT}/merotee-${ROLE}.raw" "${MKOSI_OUT}/disk.raw"
truncate -s %1G "${MKOSI_OUT}/disk.raw"
sgdisk --move-second-header "${MKOSI_OUT}/disk.raw" >/dev/null
tar --format=oldgnu -Sczf "${MKOSI_OUT}/merotee-${ROLE}.tar.gz" -C "${MKOSI_OUT}" disk.raw
ls -la "${MKOSI_OUT}/merotee-${ROLE}.tar.gz"

# RTMR1 (the GPT and the UKI's Authenticode hash), RTMR2 (the UKI's sections)
# and RTMR3 (the init script's v3 event, naming the roothash) before boot.
python3 "${repo}/scripts/attestation/shared/compute_rtmr.py" compute \
  --disk "${MKOSI_OUT}/disk.raw" --uki "${efi}" \
  --role "${ROLE}" --profile "${PROFILE}" --out "${EVIDENCE_DIR}/computed.json"

# Ownership, and per-directory digests of the root and the initrd so two
# builds that should match can be diffed down to the file.
scratch="$(mktemp -d)"
python3 - "${MKOSI_OUT}/merotee-${ROLE}.raw" "${scratch}/root.erofs" <<'PY'
import struct, sys, uuid
disk = open(sys.argv[1], "rb"); disk.seek(512)
lba, count, size = struct.unpack_from("<QII", disk.read(92), 72)
disk.seek(lba * 512)
root = uuid.UUID("4f68bce3-e8cd-4db1-96e7-fbcaf984b709")  # x86-64 root
for _ in range(count):
    entry = disk.read(size)
    if uuid.UUID(bytes_le=entry[:16]) == root:
        first, last = struct.unpack_from("<QQ", entry, 32)
        disk.seek(first * 512)
        open(sys.argv[2], "wb").write(disk.read((last - first + 1) * 512))
        break
else:
    sys.exit("no root partition")
PY
sudo fsck.erofs --extract="${scratch}/root" "${scratch}/root.erofs" >/dev/null
# The packages own files as shadow, utmp, mail...: a root with no file owned by
# anyone but root lost its ownership in the build.
if [[ -z "$(sudo find "${scratch}/root" \( ! -uid 0 -o ! -gid 0 \) -print -quit)" ]]; then
  sudo rm -rf "${scratch}"
  echo "::error::every file in the root is owned by root:root; the build lost the packages' ownership"
  exit 1
fi
# Thousands of lines each: into the evidence only, not the step's log (where
# they pushed the mkosi build out of the API's log tail).
sudo python3 "${repo}/scripts/image/image_digest.py" root "${scratch}/root" \
  --files-under /etc --files-under /var --files-under /usr/lib/dbus-1.0 | tee "${EVIDENCE_DIR}/root.digest" >/dev/null
python3 "${repo}/scripts/image/image_digest.py" uki "${efi}" --files-under /etc > "${EVIDENCE_DIR}/initrd.digest"
for digest in root initrd; do
  echo "${digest}.digest: $(wc -l < "${EVIDENCE_DIR}/${digest}.digest") lines, sha256 $(sha256sum "${EVIDENCE_DIR}/${digest}.digest" | cut -c1-16)"
done
sudo rm -rf "${scratch}"

# Last, so it is in the last lines of the step's log.
python3 "${repo}/scripts/release/mkosi/build_timing.py" "${build_log}"
