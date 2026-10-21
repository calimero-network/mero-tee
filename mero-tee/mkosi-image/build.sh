#!/usr/bin/env bash
# Build one mkosi image: a role (node, kms, agent or inference) in one profile.
#
#   ROLE=node|kms|agent|inference PROFILE=locked-read-only|debug-read-only|debug \
#     mero-tee/mkosi-image/build.sh OUTPUT_DIR [-- MKOSI_OPTION ...]
#
# ROLE defaults to node, PROFILE to locked-read-only. The output is
# OUTPUT_DIR/merotee-<role>.{raw,efi,manifest,rendered.json}.
#
# The role's inputs are environment variables:
#   kms:   MERO_KMS_BINARY, KMS_NODE_POLICY_FILE, optional KMS_AGENT_POLICY_FILE
#   agent: MERO_AGENT_GATE_BINARY, and MERO_AGENT_BINARY or MERO_BOT_BUNDLE
#          (then the agent is scripts/agent/mero-bot-agent.sh)
#   inference: MERO_INFERENCE_GATE_BINARY; vLLM comes from
#          mero-tee/inference/requirements.lock (scripts/inference/install-runtime.sh,
#          which needs uv)
# The roles' own asserts refuse a build without them.
#
# The debug profiles also get openssh-server and the GCE guest environment (SSH
# keys from instance metadata, OS Login), and the serial console. The roles
# themselves differ per profile (lockdown and conformance run on
# locked-read-only only, the node's fleet sidecar on the read-only profiles),
# which the renderer takes from their when: conditions.
#
# 1. Copies this directory to a work directory.
# 2. Renders the role's playbook into it (scripts/image/render_role_tree.py)
#    with the versions in mero-tee/versions.json: the roles' templates, files
#    and sha256-pinned release binaries. Downloads
#    go to $DOWNLOAD_CACHE (default OUTPUT_DIR/downloads) and are checked
#    against build-inputs.lock.json before use.
# 3. Adds the roles' packages, users and the units they enable and mask.
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
profile="${PROFILE:-locked-read-only}"
case "${profile}" in
  locked-read-only | debug-read-only | debug) ;;
  *) echo "build.sh: PROFILE must be locked-read-only, debug-read-only or debug, not '${profile}'" >&2; exit 2 ;;
esac
role="${ROLE:-node}"
case "${role}" in
  node) playbook="playbook.yml" ;;
  kms) playbook="playbook-kms.yml" ;;
  agent) playbook="playbook-agent.yml" ;;
  inference) playbook="playbook-inference.yml" ;;
  *) echo "build.sh: ROLE must be node, kms, agent or inference, not '${role}'" >&2; exit 2 ;;
esac
# An input given is a file on this host; empty is "not given" (the role decides).
input() {
  if [[ -z "${2}" ]]; then return 0; fi
  [[ -f "${2}" ]] || { echo "build.sh: ${1}=${2} does not exist" >&2; exit 2; }
  realpath "${2}"
}
# (Assignments, so set -e stops the build on a missing file.)
mero_kms_binary="$(input MERO_KMS_BINARY "${MERO_KMS_BINARY:-}")"
kms_node_policy_file="$(input KMS_NODE_POLICY_FILE "${KMS_NODE_POLICY_FILE:-}")"
kms_agent_policy_file="$(input KMS_AGENT_POLICY_FILE "${KMS_AGENT_POLICY_FILE:-}")"
mero_agent_gate_binary="$(input MERO_AGENT_GATE_BINARY "${MERO_AGENT_GATE_BINARY:-}")"
mero_bot_bundle="$(input MERO_BOT_BUNDLE "${MERO_BOT_BUNDLE:-}")"
mero_agent_binary="$(input MERO_AGENT_BINARY "${MERO_AGENT_BINARY:-}")"
mero_inference_gate_binary="$(input MERO_INFERENCE_GATE_BINARY "${MERO_INFERENCE_GATE_BINARY:-}")"
if [[ -n "${mero_bot_bundle}" ]]; then
  # With mero-bot, the agent is the launcher.
  launcher="$(realpath "${repo}/scripts/agent/mero-bot-agent.sh")"
  if [[ -n "${mero_agent_binary}" && "${mero_agent_binary}" != "${launcher}" ]]; then
    echo "build.sh: with MERO_BOT_BUNDLE the agent is ${launcher}; unset MERO_AGENT_BINARY" >&2
    exit 2
  fi
  mero_agent_binary="${launcher}"
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cp -a "${here}/." "${work}/"
rm -f "${work}/build.sh"
mkdir -p "${work}/rendered" "${work}/mkosi.conf.d"

version() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "${here}/../versions.json" "$1"; }

python3 "${repo}/scripts/image/render_role_tree.py" "${here}/../${playbook}" \
  --out "${work}/rendered/tree" --manifest "${work}/rendered/manifest.json" --cache "${cache}" --fetch \
  -e cpu_architecture=amd64 \
  -e "lockdown_profile=${profile}" \
  -e "image_version=$(version imageVersion)" \
  -e "merod_version=$(version merodVersion)" \
  -e "traefik_version=$(version traefikVersion)" \
  -e "node_exporter_version=$(version nodeExporterVersion)" \
  -e "vmagent_version=$(version vmagentVersion)" \
  -e "vector_version=$(version vectorVersion)" \
  -e "mero_kms_binary=${mero_kms_binary}" \
  -e "kms_node_policy_file=${kms_node_policy_file}" \
  -e "kms_agent_policy_file=${kms_agent_policy_file}" \
  -e "mero_agent_binary=${mero_agent_binary}" \
  -e "mero_agent_gate_binary=${mero_agent_gate_binary}" \
  -e "mero_bot_bundle=${mero_bot_bundle}" \
  -e "mero_inference_gate_binary=${mero_inference_gate_binary}"

# No empty directories in the image, except one a role makes on purpose
# (`file: state=directory`): a program fills it at run time. Vector's journald
# source refuses to start without its data_dir, /etc/vector/data, so deleting
# that one left every image shipping no logs at all.
python3 - "${work}/rendered" <<'PY'
import json, os, sys
rendered = sys.argv[1]
tree = os.path.join(rendered, "tree")
made = {entry["path"] for entry in json.load(open(os.path.join(rendered, "manifest.json")))["written"]
        if entry["by"] == "file:directory"}
for path, _, _ in os.walk(tree, topdown=False):
    if path != tree and not os.listdir(path) and "/" + os.path.relpath(path, tree) not in made:
        os.rmdir(path)
PY

# The inference image's Python packages (vLLM): not a role's files but the
# hash-locked wheels of mero-tee/inference/requirements.lock, for the image's
# own Python, into the same tree.
if [[ "${role}" == inference ]]; then
  UV_CACHE_DIR="${cache}/uv" "${repo}/scripts/inference/install-runtime.sh" \
    "${work}/rendered/tree" /opt/mero-inference/site-packages
fi

printf '%s\n' "${profile}" > "${work}/rendered/profile"
printf '%s\n' "${role}" > "${work}/rendered/role"

python3 - "${work}" "${role}" "${profile}" <<'PY'
import json, sys
work, role, profile = sys.argv[1], sys.argv[2], sys.argv[3]
manifest = json.load(open(f"{work}/rendered/manifest.json"))
present, absent = [], []
for entry in manifest["packages"]:
    names = entry["names"]
    (absent if entry["state"] == "absent" else present).extend(names)
with open(f"{work}/mkosi.conf.d/50-rendered.conf", "w") as f:
    f.write(f"# Written by build.sh from the render manifest.\n[Output]\nImageId=merotee-{role}\n[Content]\n")
    f.write(f"ExtraTrees={work}/rendered/tree:/\n")
    # A list setting with no entries is left out: an empty assignment clears
    # what mkosi.conf set (an empty Packages= dropped every base package).
    def setting(key, values):
        if values:
            f.write(f"{key}=\n" + "".join(f"        {v}\n" for v in values))
    # What the roles delete, from whatever package put it there (/etc/ssh,
    # which systemd's ssh_config.d drop-in creates, among them).
    setting("RemoveFiles", [p for p in manifest["removed"] if not p.startswith("/tmp/")])
    # In this order, locked-read-only's is the one the node image has had since
    # it was first measured. The debug profiles leave out quiet: the KMS probe
    # reads the kernel command line and the verity setup off the serial console.
    cmdline = ["quiet"] if profile == "locked-read-only" else []
    cmdline += ["systemd.volatile=overlay", f"calimero.role={role}", f"calimero.profile={profile}"]
    if profile != "locked-read-only":
        # SSH and the GCE guest environment, as the Ubuntu cloud image has them.
        present += ["openssh-server", "google-compute-engine"]
        cmdline.append("console=ttyS0,115200")
    setting("KernelCommandLine", cmdline)
    setting("Packages", sorted(set(present)))
# mkosi runs `systemctl preset-all` after mkosi.postinst. With no preset for
# them, systemd enables the roles' own units (merod, traefik, node_exporter...)
# that calimero-init starts itself, and it fails on a masked
# template instance its presets enable (getty@tty1). So the image's presets say
# what the roles did: enable what they enabled, disable every other unit they
# installed and every unit they mask.
import pathlib, re
tree = pathlib.Path(f"{work}/rendered/tree")
installed = sorted(p.name for p in (tree / "etc/systemd/system").glob("*") if p.suffix in (".service", ".socket", ".timer", ".target"))
lines = ["# Written by build.sh from the render manifest (see there)."]
# An enabled template instance (the agent's mero-agent@<slot>.service) is
# enabled through its template's preset, with the instances listed: a plain
# `disable` of the template would remove them.
instances = {}
for u in manifest["enable"]:
    if m := re.fullmatch(r"(.+@)([^.]+)(\.\w+)", u):
        instances.setdefault(m.group(1) + m.group(3), []).append(m.group(2))
lines += [f"enable {u}" for u in manifest["enable"] + ["systemd-networkd.service", "systemd-resolved.service", "systemd-timesyncd.service",
                                                        "merotee-hostname.service"]
          if not re.fullmatch(r".+@[^.]+\.\w+", u)]
lines += [f"enable {t} {' '.join(i)}" for t, i in instances.items()]
lines += [f"disable {u}" for u in installed if u not in manifest["enable"] and u not in instances]
masked = manifest["mask"] + ["systemd-firstboot.service", "systemd-homed-firstboot.service"]
lines += [f"disable {re.sub(r'@[^.]+', '@', u)}" for u in masked]
# systemd's presets do not name the pcrlock units, so preset-all enables them,
# and on GCP's vTPM they fail every boot. Nothing here seals to a TPM policy:
# the node is trusted by its TDX quote, and its disk key comes from the KMS.
lines.append("disable systemd-pcrlock-*.service")
preset = tree / "etc/systemd/system-preset/00-merotee.preset"
preset.parent.mkdir(parents=True, exist_ok=True)
preset.write_text("\n".join(dict.fromkeys(lines)) + "\n")
open(f"{work}/rendered/mask.list", "w").write("".join(f"{u}\n" for u in manifest["mask"]))
open(f"{work}/rendered/enable.list", "w").write("".join(f"{u}\n" for u in manifest["enable"]))
# The users the roles create (the agent's slot users) or lock, for mkosi.postinst:
# name, then system/shell/create_home/password_lock as key=value.
with open(f"{work}/rendered/users.list", "w") as f:
    for user in manifest["users"]:
        if user.get("state", "present") != "present":
            raise SystemExit(f"build.sh: a role removes user {user['name']}; nothing renders that")
        f.write(" ".join([user["name"]] + [f"{k}={str(v).lower()}" for k, v in user.items() if k not in ("name", "state")]) + "\n")
open(f"{work}/rendered/absent.list", "w").write("".join(f"{n}\n" for n in sorted(set(absent))))
PY
cat "${work}/mkosi.conf.d/50-rendered.conf"

mkosi --directory "${work}" --output-directory "${out}" "$@" build

# What the roles purge (lockdown R1, crash reporters, unattended upgrades) and,
# on locked-read-only, the cloud agents lockdown masks must not be installed.
python3 - "${out}/merotee-${role}.manifest" "${work}/rendered/absent.list" "${profile}" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
installed = {p["name"] for p in manifest.get("packages", [])}
forbidden = set(open(sys.argv[2]).read().split())
if sys.argv[3] == "locked-read-only":
    forbidden |= {"cloud-init", "snapd", "google-guest-agent", "google-compute-engine", "google-osconfig-agent"}
found = sorted(installed & forbidden)
if found:
    sys.exit(f"conformance: installed but must not be: {' '.join(found)}")
print(f"{len(installed)} packages; none of {len(forbidden)} forbidden ones installed")
PY
cp "${work}/rendered/manifest.json" "${out}/merotee-${role}.rendered.json"
