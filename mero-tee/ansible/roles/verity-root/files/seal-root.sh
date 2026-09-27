#!/usr/bin/env bash
# Seal the image's root filesystem behind dm-verity (mero-tee#334). The LAST step
# of an image build, run once as root.
#
# Before this, the image measured `calimero.root_hash` as a cmdline string only.
# Nothing re-hashed the files at boot, so an offline edit of the boot disk kept
# the measurements. Now:
#
# 1. The running root is copied into a read-only EROFS filesystem, written to a
#    new partition (`calimero-root`) in the free space after the base image's
#    partitions.
# 2. `veritysetup format` writes its hash tree to a second new partition
#    (`calimero-verity`) and prints one root hash.
# 3. The root hash goes on the kernel cmdline, which GCP TDX measures into
#    RTMR2. At boot the initrd (dracut's systemd-veritysetup) opens the root
#    through dm-verity: every block read is checked against the hash tree, so a
#    changed byte is a read error, never different code. `systemd.volatile=overlay`
#    puts a tmpfs over it, so /etc and /var are writable in RAM and nothing is
#    written back.
#
# The base image's own root partition stays on the disk, unused by the booted
# system: GRUB still reads the kernel, initrd and grub.cfg from it, and all three
# are measured (RTMR1, RTMR2). Changing them changes the measurements.
#
# Usage: seal-root.sh [--remove-user NAME]
#
# SEAL_SYSROOT (default /) seals a root mounted elsewhere. It exists for the
# test in scripts/ci/tests/seal-root-test.sh, which runs this against a disk
# image on a loop device.
#   --remove-user  Delete this user first (the Packer build user on the locked
#                  profile). Done here, in the same root process, because it has
#                  to happen before the root is copied and nothing can run as
#                  that user after it is gone.
set -euo pipefail

SYSROOT="${SEAL_SYSROOT:-/}"
SYSROOT="${SYSROOT%/}"
ROOT_DIR="${SYSROOT:-/}"
ROOT_LABEL="calimero-root"
VERITY_LABEL="calimero-verity"
DRACUT_CONF="${SYSROOT}/etc/dracut.conf.d/90-calimero-verity.conf"
GRUB_DROPIN="${SYSROOT}/etc/default/grub.d/70-calimero-verity.cfg"
FSTAB="${SYSROOT}/etc/fstab"
# The hash tree is about 1/127 of the data it covers (4 KiB blocks, SHA-256).
# Reserve 1/64 plus a fixed margin for the superblock and tree levels.
VERITY_MARGIN_MIB=32

log() { echo "[seal-root] $*"; }
die() {
  echo "[seal-root] ERROR: $*" >&2
  exit 1
}

remove_user=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-user)
      remove_user="${2:?--remove-user needs a name}"
      shift 2
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || die "must run as root"
for tool in mkfs.erofs veritysetup sgdisk partprobe blkid dracut update-grub findmnt lsblk; do
  command -v "$tool" >/dev/null || die "missing tool: $tool"
done

if [[ -n "$remove_user" ]]; then
  userdel --force --remove "$remove_user" || true
  if getent passwd "$remove_user" >/dev/null; then
    die "user $remove_user must be removed before the root is sealed"
  fi
  log "Removed user $remove_user"
fi

# --- The disk and its free space -------------------------------------------
root_source="$(findmnt -no SOURCE "$ROOT_DIR")"
disk="/dev/$(lsblk -no PKNAME "$root_source" | head -n1)"
[[ -b "$disk" ]] || die "could not find the disk holding $ROOT_DIR ($root_source)"
log "Root is $root_source on $disk"
lsblk -o NAME,SIZE,TYPE,FSTYPE,PARTLABEL,MOUNTPOINT "$disk"

# The partition of $disk labelled $1. blkid probes the disk itself, so this
# works without udev's by-partlabel links.
partition_labelled() {
  blkid -c /dev/null -t "PARTLABEL=$1" -o device | grep "^${disk}" | head -n1 || true
}

if [[ -n "$(partition_labelled "$ROOT_LABEL")" ]]; then
  die "$disk already has a $ROOT_LABEL partition; a root is sealed once"
fi

# The base image's backup GPT header sits at the end of the base image, not of
# this larger disk (growpart is off for the build), so the space past it is
# invisible until the header moves to the real end.
sgdisk --move-second-header "$disk" >/dev/null
partprobe "$disk"

sector_bytes="$(blockdev --getss "$disk")"
# Largest free extent, in sectors (sgdisk reports the first/last usable ones).
mapfile -t free_extent < <(
  sgdisk --first-aligned-in-largest --end-of-largest "$disk" 2>/dev/null | tail -n2
)
free_start="${free_extent[0]:-}"
free_end="${free_extent[1]:-}"
[[ "$free_start" =~ ^[0-9]+$ && "$free_end" =~ ^[0-9]+$ ]] || die "could not read free space on $disk"
free_mib=$(( (free_end - free_start + 1) * sector_bytes / 1024 / 1024 ))
log "Largest free extent: ${free_mib} MiB"

used_mib=$(( $(du -sxm "$ROOT_DIR" | awk '{print $1}') ))
log "Root content: about ${used_mib} MiB"

verity_mib=$(( free_mib / 64 + VERITY_MARGIN_MIB ))
data_mib=$(( free_mib - verity_mib - 8 ))
# EROFS is compressed, but plan for none so a poorly compressing root still fits.
if (( data_mib < used_mib + 256 )); then
  die "not enough free space after the base partitions: ${free_mib} MiB free, root needs about $(( used_mib + 256 + verity_mib )) MiB. Was growpart left on during the build?"
fi

# --- Initrd: open the root through dm-verity --------------------------------
mkdir -p "$(dirname "$DRACUT_CONF")" "$(dirname "$GRUB_DROPIN")"
cat > "$DRACUT_CONF" <<'EOF'
# Written by seal-root.sh: the root is an EROFS filesystem behind dm-verity,
# opened by systemd-veritysetup from the roothash= on the kernel cmdline, with a
# tmpfs overlay on top (systemd.volatile=overlay).
add_dracutmodules+=" systemd systemd-veritysetup "
add_drivers+=" erofs dm-verity overlay "
EOF
dracut --force --regenerate-all
log "Regenerated initrd(s) with systemd-veritysetup"

# --- New partitions ---------------------------------------------------------
sgdisk --new="0:0:+${data_mib}M" --change-name="0:${ROOT_LABEL}" \
  --typecode="0:8300" "$disk"
sgdisk --new="0:0:+${verity_mib}M" --change-name="0:${VERITY_LABEL}" \
  --typecode="0:8300" "$disk"
partprobe "$disk"
udevadm settle 2>/dev/null || true
root_part="$(partition_labelled "$ROOT_LABEL")"
verity_part="$(partition_labelled "$VERITY_LABEL")"
[[ -b "$root_part" && -b "$verity_part" ]] || die "new partitions did not appear"
log "Data partition $root_part, hash partition $verity_part"

# --- The root, as the booted system will see it ------------------------------
# The base root stays mounted and in use by this build session, so the copy is
# made from it directly. What it must not carry: other filesystems, this build's
# temporary and log files, and fstab entries for the base partitions (the booted
# root is the verity device, and it must not mount the base root back rw).
# The base fstab is kept outside the root while the copy is made.
fstab_base="$(mktemp)"
cp "$FSTAB" "$fstab_base"
awk '$2 != "/" && $2 != "/boot" && $2 != "/boot/efi"' "$fstab_base" > "$FSTAB"
sync

# Keep these directories (they are mount points or expected to exist) but none
# of their contents: kernel filesystems, this build's scratch and logs, the EFI
# partition, and Ansible's copy of the module running this script.
exclude=()
for path in proc sys dev run tmp var/tmp var/log lost+found boot/efi root/.ansible; do
  exclude+=(--exclude-regex="^${path}/.")
done
mkfs.erofs -zlz4hc -T0 "${exclude[@]}" "$root_part" "$ROOT_DIR"
# Put the base fstab back: the build host still runs from the base root.
cat "$fstab_base" > "$FSTAB"
rm -f "$fstab_base"
log "Wrote the EROFS root to $root_part"

roothash_file="$(mktemp)"
veritysetup format "$root_part" "$verity_part" --root-hash-file="$roothash_file" >/dev/null
roothash="$(tr -d '[:space:]' < "$roothash_file")"
rm -f "$roothash_file"
[[ "$roothash" =~ ^[0-9a-f]{64}$ ]] || die "veritysetup printed no usable root hash"
veritysetup verify "$root_part" "$verity_part" "$roothash"
log "dm-verity root hash: $roothash"

# --- Kernel cmdline -----------------------------------------------------------
# update-grub emits root=PARTUUID=<base root> first; a later root= wins, both for
# the kernel and for systemd's generators, so the verity device is the root.
#
# Ubuntu cloud images set GRUB_FORCE_PARTUUID, which makes GRUB try the kernel
# without its initrd first. Only the initrd can open the verity device, so that
# attempt could only panic: it is switched off, and every boot uses the initrd.
cat > "$GRUB_DROPIN" <<EOF
# Written by seal-root.sh: boot the dm-verity root (measured into RTMR2 with the
# rest of the cmdline). See mero-tee#334.
GRUB_FORCE_PARTUUID=""
GRUB_CMDLINE_LINUX_DEFAULT="\${GRUB_CMDLINE_LINUX_DEFAULT} root=/dev/mapper/root rootfstype=erofs ro roothash=${roothash} systemd.verity_root_data=PARTLABEL=${ROOT_LABEL} systemd.verity_root_hash=PARTLABEL=${VERITY_LABEL} systemd.volatile=overlay"
EOF
update-grub
grep -m1 "roothash=${roothash}" "${SYSROOT}/boot/grub/grub.cfg" >/dev/null \
  || die "grub.cfg does not carry the root hash"
log "Kernel cmdline now boots the verity root"
lsblk -o NAME,SIZE,FSTYPE,PARTLABEL "$disk"
