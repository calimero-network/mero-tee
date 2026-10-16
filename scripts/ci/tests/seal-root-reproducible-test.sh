#!/usr/bin/env bash
# Sealing identical files with the same --seed must give the same sealed root:
# the same verity root hash (what the kernel cmdline, and so RTMR2, carries)
# and byte-identical root and hash partitions. A different seed must not.
#
# Before --seed, mkfs.erofs picked a random filesystem UUID and veritysetup a
# random salt and UUID, so the root hash differed on every build even when every
# file was identical.
#
# dracut and update-grub are stubbed, as in seal-root-test.sh. Needs root and
# loop devices. Skips (exit 0) without them.
set -euo pipefail

script="$(cd "$(dirname "$0")/../../.." && pwd)/mero-tee/ansible/roles/verity-root/files/seal-root.sh"

if [[ "$(id -u)" != 0 ]] || ! losetup -f >/dev/null 2>&1; then
  echo "SKIP: needs root and a free loop device"
  exit 0
fi
for tool in mkfs.erofs veritysetup sgdisk partprobe mkfs.ext4; do
  command -v "$tool" >/dev/null || { echo "SKIP: missing $tool"; exit 0; }
done

work="$(mktemp -d)"
loops=()
mounts=()
cleanup() {
  for m in "${mounts[@]+"${mounts[@]}"}"; do mountpoint -q "$m" && umount "$m"; done
  for l in "${loops[@]+"${loops[@]}"}"; do losetup -d "$l" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

stubs="$work/stubs"
mkdir -p "$stubs"
printf '#!/usr/bin/env bash\necho "stub dracut $*"\n' > "$stubs/dracut"
cat > "$stubs/update-grub" <<'STUB'
#!/usr/bin/env bash
GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0"
for f in "$SEAL_SYSROOT"/etc/default/grub.d/*.cfg; do
  # shellcheck disable=SC1090
  . "$f"
done
echo "linux /vmlinuz root=PARTUUID=base ro ${GRUB_CMDLINE_LINUX_DEFAULT}" > "$SEAL_SYSROOT/boot/grub/grub.cfg"
STUB
chmod +x "$stubs/dracut" "$stubs/update-grub"

# Build a fresh base disk with the same files, seal it with SEED, and write
# "<root hash> <sha256 of root partition> <sha256 of hash partition>" to
# $work/NAME.result. Not run in a subshell, so cleanup sees its loops and mounts.
seal_fresh() {
  local name="$1" seed="$2" dir loop r
  dir="$work/$name"
  mkdir -p "$dir/root"
  truncate -s 600M "$dir/disk.img"
  sgdisk --new=1:0:+400M --change-name=1:cloudimg-rootfs "$dir/disk.img" >/dev/null
  truncate -s 2G "$dir/disk.img"
  loop="$(losetup -P --show -f "$dir/disk.img")"
  loops+=("$loop")
  partprobe "$loop" 2>/dev/null || true
  # udev makes the partition's node after partprobe returns: waiting for it
  # keeps mkfs from racing it ("/dev/loop1p1 does not exist", mero-tee#506).
  udevadm settle 2>/dev/null || true
  for _ in $(seq 100); do [[ -b "${loop}p1" ]] && break; sleep 0.1; done
  [[ -b "${loop}p1" ]] || fail "${loop}p1 never appeared"
  mkfs.ext4 -q -L cloudimg-rootfs "${loop}p1"
  mount "${loop}p1" "$dir/root"
  mounts+=("$dir/root")
  r="$dir/root"
  mkdir -p "$r"/{etc/default/grub.d,boot/grub,usr/local/bin,proc,sys,dev,run,tmp}
  echo "LABEL=cloudimg-rootfs / ext4 defaults 0 1" > "$r/etc/fstab"
  echo "merod" > "$r/usr/local/bin/merod"
  echo "config" > "$r/etc/calimero.conf"

  SEAL_SYSROOT="$r" PATH="$stubs:$PATH" bash "$script" --seed "$seed" >"$dir/seal.log" 2>&1 \
    || fail "seal of $name failed: $(tail -5 "$dir/seal.log")"

  local roothash root_part verity_part
  roothash="$(grep -oE 'roothash=[0-9a-f]{64}' "$r/boot/grub/grub.cfg" | cut -d= -f2)"
  root_part="$(blkid -c /dev/null -t PARTLABEL=calimero-root -o device | grep "^${loop}p" | head -n1)"
  verity_part="$(blkid -c /dev/null -t PARTLABEL=calimero-verity -o device | grep "^${loop}p" | head -n1)"
  [[ -n "$roothash" && -b "$root_part" && -b "$verity_part" ]] || fail "$name: sealed root not found"
  echo "$roothash $(sha256sum < "$root_part" | cut -c1-64) $(sha256sum < "$verity_part" | cut -c1-64)" \
    > "$work/$name.result"
}

seal_fresh a "1.2.3:node:locked-read-only"
sleep 1  # different file times on the base root; the sealed root must not see them
seal_fresh b "1.2.3:node:locked-read-only"
seal_fresh c "1.2.3:node:debug"

read -r hash_a root_a verity_a < "$work/a.result"
read -r hash_b root_b verity_b < "$work/b.result"
read -r hash_c _ _ < "$work/c.result"

[[ "$hash_a" == "$hash_b" ]] || fail "same files and seed gave different root hashes ($hash_a vs $hash_b)"
[[ "$root_a" == "$root_b" ]] || fail "same files and seed gave different root partitions"
[[ "$verity_a" == "$verity_b" ]] || fail "same files and seed gave different hash partitions"
[[ "$hash_a" != "$hash_c" ]] || fail "a different seed gave the same root hash"

echo "PASS: seal-root reproducible (root hash $hash_a)"
