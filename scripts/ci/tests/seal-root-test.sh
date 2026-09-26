#!/usr/bin/env bash
# Runs mero-tee/ansible/roles/verity-root/files/seal-root.sh against a disk image
# on a loop device, laid out like a GCP base image that was never grown: one
# root partition, then free space that sits past the backup GPT header.
#
# It checks that the root is written as EROFS with the booted system's fstab,
# without the build's scratch files; that dm-verity covers it and refuses a
# changed byte; and that grub.cfg carries the root hash. dracut and update-grub
# are stubbed: the initrd and the real boot are exercised by the release
# workflow's TDX probe VM.
#
# Needs root and loop devices. Skips (exit 0) without them.
set -euo pipefail

script="$(cd "$(dirname "$0")/../../.." && pwd)/mero-tee/ansible/roles/verity-root/files/seal-root.sh"

if [[ "$(id -u)" != 0 ]] || ! losetup -f >/dev/null 2>&1; then
  echo "SKIP: needs root and a free loop device"
  exit 0
fi
for tool in mkfs.erofs fsck.erofs veritysetup sgdisk partprobe mkfs.ext4; do
  command -v "$tool" >/dev/null || { echo "SKIP: missing $tool"; exit 0; }
done

work="$(mktemp -d)"
loop=""
cleanup() {
  mountpoint -q "$work/root" && umount "$work/root"
  [[ -n "$loop" ]] && losetup -d "$loop"
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# A 600 MiB "base image" with one root partition, then grown to 2 GiB without
# moving the backup GPT header, as a GCP boot disk is when growpart is off.
truncate -s 600M "$work/disk.img"
sgdisk --new=1:0:+400M --change-name=1:cloudimg-rootfs "$work/disk.img" >/dev/null
truncate -s 2G "$work/disk.img"
loop="$(losetup -P --show -f "$work/disk.img")"
partprobe "$loop" 2>/dev/null || true
mkfs.ext4 -q -L cloudimg-rootfs "${loop}p1"
mkdir -p "$work/root"
mount "${loop}p1" "$work/root"

r="$work/root"
mkdir -p "$r"/{etc/default/grub.d,boot/grub,usr/local/bin,var/log,tmp,root/.ansible,proc,sys,dev,run,mnt/data}
cat > "$r/etc/fstab" <<'EOF'
LABEL=cloudimg-rootfs / ext4 discard,errors=remount-ro 0 1
LABEL=BOOT /boot ext4 defaults 0 2
LABEL=UEFI /boot/efi vfat umask=0077 0 1
tmpfs /scratch tmpfs defaults 0 0
EOF
echo "merod" > "$r/usr/local/bin/merod"
echo "build log" > "$r/var/log/build.log"
echo "scratch" > "$r/tmp/scratch"
echo "module" > "$r/root/.ansible/module.py"

stubs="$work/stubs"
mkdir -p "$stubs"
cat > "$stubs/dracut" <<'EOF'
#!/usr/bin/env bash
echo "stub dracut $*"
EOF
cat > "$stubs/update-grub" <<'EOF'
#!/usr/bin/env bash
# Render the linux line the way GRUB would from the drop-ins.
GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0"
for f in "$SEAL_SYSROOT"/etc/default/grub.d/*.cfg; do
  # shellcheck disable=SC1090
  . "$f"
done
echo "linux /vmlinuz root=PARTUUID=base ro ${GRUB_CMDLINE_LINUX_DEFAULT}" > "$SEAL_SYSROOT/boot/grub/grub.cfg"
EOF
chmod +x "$stubs/dracut" "$stubs/update-grub"

SEAL_SYSROOT="$r" PATH="$stubs:$PATH" bash ${SEAL_TRACE:+-x} "$script" | tee "$work/seal.log"

part_of() { blkid -c /dev/null -t "PARTLABEL=$1" -o device | grep "^${loop}" | head -n1; }
root_part="$(part_of calimero-root)"
verity_part="$(part_of calimero-verity)"
[[ -b "$root_part" && -b "$verity_part" ]] || fail "sealed partitions missing"
[[ "$(blkid -c /dev/null -o value -s TYPE "$root_part")" == "erofs" ]] || fail "root partition is not EROFS"

roothash="$(grep -oE 'roothash=[0-9a-f]{64}' "$r/boot/grub/grub.cfg" | cut -d= -f2)"
[[ -n "$roothash" ]] || fail "grub.cfg carries no root hash"
grep -q "systemd.verity_root_data=PARTLABEL=calimero-root" "$r/boot/grub/grub.cfg" || fail "no verity data device on the cmdline"
grep -q "systemd.volatile=overlay" "$r/boot/grub/grub.cfg" || fail "no volatile overlay on the cmdline"
grep -q '^GRUB_FORCE_PARTUUID=""' "$r/etc/default/grub.d/70-calimero-verity.cfg" || fail "initrd-less boot is not switched off"
# The verity root= comes after the base one, so it wins.
[[ "$(grep -oE 'root=[^ ]+' "$r/boot/grub/grub.cfg" | tail -n1)" == "root=/dev/mapper/root" ]] || fail "the last root= is not the verity device"

veritysetup verify "$root_part" "$verity_part" "$roothash" || fail "verity does not verify the sealed root"

extracted="$work/extracted"
fsck.erofs --extract="$extracted" --no-preserve "$root_part" >/dev/null
[[ "$(cat "$extracted/usr/local/bin/merod")" == "merod" ]] || fail "root content missing from EROFS"
grep -qE '^\S+\s+/\s' "$extracted/etc/fstab" && fail "sealed fstab still mounts the base root"
grep -qE '^\S+\s+/boot\s' "$extracted/etc/fstab" && fail "sealed fstab still mounts /boot"
grep -q '/scratch' "$extracted/etc/fstab" || fail "sealed fstab lost an unrelated entry"
for scratch in var/log/build.log tmp/scratch root/.ansible/module.py; do
  [[ ! -e "$extracted/$scratch" ]] || fail "$scratch should not be in the sealed root"
done
[[ -d "$extracted/mnt/data" && -d "$extracted/proc" ]] || fail "mount points missing from the sealed root"
grep -qE '^\S+\s+/\s' "$r/etc/fstab" || fail "the build host's own fstab was not restored"

# One changed byte in the data partition must fail verification.
printf '\x01' | dd of="$root_part" bs=1 seek=8192 count=1 conv=notrunc status=none
if veritysetup verify "$root_part" "$verity_part" "$roothash" 2>/dev/null; then
  fail "verity accepted a changed root"
fi

# Sealing twice is refused.
if SEAL_SYSROOT="$r" PATH="$stubs:$PATH" bash "$script" >/dev/null 2>&1; then
  fail "a second seal was not refused"
fi

echo "PASS: seal-root"
