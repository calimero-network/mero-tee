#!/usr/bin/env bash
# Build the mkosi node image (locked-read-only).
#
#   mero-tee/mkosi-node/build.sh OUTPUT_DIR [-- MKOSI_OPTION ...]
#
# 1. Copies this directory to a work directory.
# 2. Renders the node playbook's roles into it (scripts/image/render_role_tree.py)
#    with the versions in mero-tee/versions.json: the same templates, files and
#    sha256-pinned release binaries the Packer build puts in place. Downloads
#    go to $DOWNLOAD_CACHE (default OUTPUT_DIR/downloads) and are checked
#    against build-inputs.lock.json before use.
# 3. Adds the roles' packages and the units they enable and mask.
# 4. Runs mkosi (with any MKOSI_OPTIONs, e.g. --proxy-url), then checks mkosi's package manifest for what lockdown removes.
#
# Needs mkosi (v26), python3 with jinja2 and PyYAML, curl and tar.
set -euo pipefail
umask 022

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
shift
[[ "${1:-}" == "--" ]] && shift
cache="${DOWNLOAD_CACHE:-${out}/downloads}"
profile=locked-read-only

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cp -a "${here}/." "${work}/"
rm -f "${work}/build.sh"
mkdir -p "${work}/rendered" "${work}/mkosi.conf.d"

version() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "${here}/../versions.json" "$1"; }

python3 "${repo}/scripts/image/render_role_tree.py" "${here}/../playbook.yml" \
  --out "${work}/rendered/tree" --manifest "${work}/rendered/manifest.json" --cache "${cache}" --fetch \
  -e cpu_architecture=amd64 \
  -e "lockdown_profile=${profile}" \
  -e "image_version=$(version imageVersion)" \
  -e "merod_version=$(version merodVersion)" \
  -e "traefik_version=$(version traefikVersion)" \
  -e "node_exporter_version=$(version nodeExporterVersion)" \
  -e "vmagent_version=$(version vmagentVersion)" \
  -e "vector_version=$(version vectorVersion)"

# Packer-only: the GRUB drop-in (here role and profile are in mkosi.conf's
# KernelCommandLine) and the script that seals a running VM's root (here
# systemd-repart builds the verity root, mkosi.repart).
rm -f "${work}/rendered/tree/etc/default/grub.d/50-calimero-profile.cfg" \
      "${work}/rendered/tree/usr/local/sbin/calimero-seal-root"
find "${work}/rendered/tree" -depth -type d -empty -delete

python3 - "${work}" <<'PY'
import json, sys
work = sys.argv[1]
manifest = json.load(open(f"{work}/rendered/manifest.json"))
# erofs-utils is what calimero-seal-root formats the root with; here
# systemd-repart does that from mkosi's tools tree.
BUILD_ONLY = {"erofs-utils"}
present, absent = [], []
for entry in manifest["packages"]:
    names = [n for n in entry["names"] if n not in BUILD_ONLY]
    (absent if entry["state"] == "absent" else present).extend(names)
with open(f"{work}/mkosi.conf.d/50-rendered.conf", "w") as f:
    f.write("# Written by build.sh from the render manifest.\n[Content]\n")
    f.write(f"ExtraTrees={work}/rendered/tree:/\n")
    # What the roles delete, from whatever package put it there (/etc/ssh,
    # which systemd's ssh_config.d drop-in creates, among them).
    f.write("RemoveFiles=\n" + "".join(f"        {p}\n" for p in manifest["removed"] if not p.startswith("/tmp/")))
    f.write("Packages=\n" + "".join(f"        {n}\n" for n in sorted(set(present))))
# mkosi runs `systemctl preset-all` after mkosi.postinst. With no preset for
# them, systemd enables the roles' own units (merod, traefik, node_exporter...)
# that the Packer image leaves to calimero-init, and it fails on a masked
# template instance its presets enable (getty@tty1). So the image's presets say
# what the roles did: enable what they enabled, disable every other unit they
# installed and every unit they mask.
import pathlib, re
tree = pathlib.Path(f"{work}/rendered/tree")
installed = sorted(p.name for p in (tree / "etc/systemd/system").glob("*") if p.suffix in (".service", ".socket", ".timer", ".target"))
lines = ["# Written by build.sh from the render manifest (see there)."]
lines += [f"enable {u}" for u in manifest["enable"] + ["systemd-networkd.service", "systemd-resolved.service", "systemd-timesyncd.service"]]
lines += [f"disable {u}" for u in installed if u not in manifest["enable"]]
masked = manifest["mask"] + ["systemd-firstboot.service", "systemd-homed-firstboot.service"]
lines += [f"disable {re.sub(r'@[^.]+', '@', u)}" for u in masked]
preset = tree / "etc/systemd/system-preset/00-merotee.preset"
preset.parent.mkdir(parents=True, exist_ok=True)
preset.write_text("\n".join(dict.fromkeys(lines)) + "\n")
open(f"{work}/rendered/mask.list", "w").write("".join(f"{u}\n" for u in manifest["mask"]))
open(f"{work}/rendered/enable.list", "w").write("".join(f"{u}\n" for u in manifest["enable"]))
open(f"{work}/rendered/absent.list", "w").write("".join(f"{n}\n" for n in sorted(set(absent))))
PY
cat "${work}/mkosi.conf.d/50-rendered.conf"

mkosi --directory "${work}" --output-directory "${out}" "$@" build

# What the roles purge (lockdown R1, crash reporters, unattended upgrades) and
# the cloud agents lockdown masks must not be installed at all.
python3 - "${out}/merotee-node.manifest" "${work}/rendered/absent.list" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
installed = {p["name"] for p in manifest.get("packages", [])}
forbidden = set(open(sys.argv[2]).read().split()) | {
    "cloud-init", "snapd", "google-guest-agent", "google-compute-engine", "google-osconfig-agent",
}
found = sorted(installed & forbidden)
if found:
    sys.exit(f"conformance: installed but must not be: {' '.join(found)}")
print(f"{len(installed)} packages; none of {len(forbidden)} forbidden ones installed")
PY
cp "${work}/rendered/manifest.json" "${out}/merotee-node.rendered.json"
