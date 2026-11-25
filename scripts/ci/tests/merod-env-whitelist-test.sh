#!/usr/bin/env bash
# merod.env and merod.service carry only whitelisted keys, on every profile.
#
# calimero-init reads instance metadata, which the host writes, and turns some
# of it into merod's configuration. Each `merod init` flag is checked against a
# regex first (calimero-init-store-encryption-test.sh); merod.env and the
# merod.service unit are the other way in: every key in them is a setting of
# `merod run`, so one key that is not meant to be there (MEROD_DEV, a storage
# key, a listen address) could weaken the running node without touching the
# checked flags. This pins what can ever reach them, so a new key fails here
# until it is added to the whitelist below, on purpose and in review:
#
#   * calimero-init.sh.j2, rendered for each profile, writes merod.env only
#     through `printf 'KEY="..."\n'` lines, and the keys are exactly
#     ENV_WHITELIST; every other mention of the file is a comment, a log
#     line, chmod, rm, a test for it, or a `sed -i '/^KEY=/d'` of a
#     whitelisted key;
#   * the only merod.service drop-in it writes is job-node.conf, which unsets
#     MEROD_METRICS_LISTEN; nothing else in mero-tee/ writes one;
#   * the merod.service unit (roles/merotee/tasks/main.yml) has only the
#     whitelisted directives, Environment= only MEROD_LISTEN and
#     MEROD_METRICS_LISTEN on loopback, EnvironmentFile= only merod.env, and
#     ExecStart= takes no flags beyond --home, --node and `run`.
#
# The checker is then run against mutated copies (a new key, an echo, a new
# Environment= or ExecStartPre=, a new drop-in), each of which must fail, so a
# checker that stops looking fails too.
#
# Needs python3 with jinja2 and pyyaml (the "Check Ansible templates parse"
# step installs them).
#
# Usage: scripts/ci/tests/merod-env-whitelist-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"
TASKS="${REPO_ROOT}/mero-tee/ansible/roles/merotee/tasks/main.yml"
TREE="${REPO_ROOT}/mero-tee"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"
[[ -r "$TASKS" ]] || fail "cannot read ${TASKS}"
python3 -c 'import jinja2, yaml' 2>/dev/null || fail "python3 needs jinja2 and pyyaml (pip install jinja2 pyyaml)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/check.py" <<'PY'
"""check.py TEMPLATE TASKS TREE: exit 0 when merod.env and merod.service
carry only whitelisted keys, else print each finding and exit 1."""
import re
import sys
from pathlib import Path

import jinja2
import yaml

template, tasks, tree = (Path(a) for a in sys.argv[1:4])

# What merod.env may ever hold. A new key goes here, in review, with what
# merod does with it and why the host may not choose it.
ENV_WHITELIST = {
    "MERO_TEE_VERSION",         # tee-release-version, sanitized; floored by the image
    "MERO_TEE_MIN_VERSION",     # the image's own version (baked)
    "MERO_TEE_PROFILE",         # the image's profile (baked)
    "MEROD_KMS_DISK_EVIDENCE",  # a fixed path on /run/calimero
    "MEROD_RECOVERY_DIR",       # a fixed mount point
    "MEROD_JOB_NODE",           # job node: "true"
    "MEROD_CLUSTER_IDENTITY",   # job node: 64 lowercase hex, checked
    "MEROD_NODE_ID",            # job node: a number, checked
    "MEROD_CLUSTER",            # job node: CLUSTER_RE, checked
}
PROFILES = ("locked-read-only", "debug-read-only", "debug")

# The merod.service unit, directive by directive.
UNIT_DIRECTIVES = {
    "Unit": {"Description", "Requires", "After"},
    "Service": {"EnvironmentFile", "Environment", "ExecStart", "Restart", "LimitCORE"},
    "Install": {"WantedBy"},
}
UNIT_ENVIRONMENT = {"MEROD_LISTEN=127.0.0.1:2528", "MEROD_METRICS_LISTEN=127.0.0.1:9464"}
UNIT_ENVIRONMENT_FILE = "-/etc/calimero/merod.env"
UNIT_EXEC_START = "/usr/local/bin/merod --home /mnt/data/merod --node default run"
DROPIN_DIR = "/run/systemd/system/merod.service.d"
DROPIN_WRITE = (
    r"printf '[Service]\nUnsetEnvironment=MEROD_METRICS_LISTEN\n' "
    f">{DROPIN_DIR}/job-node.conf"
)

findings = []


def finding(msg):
    findings.append(msg)


ENV_PATH = "/etc/calimero/merod.env"
REF = r'(?:/etc/calimero/merod\.env|\$\{?MEROD_ENV_FILE\}?)'
WRITE_RE = re.compile(r'>>?\s*"?' + REF + r'"?\s*$')
PRINTF_RE = re.compile(r"""^printf '([A-Z][A-Z0-9_]*)="[^'"\\]*(?:%s)?[^'"\\]*"\\n'(?:\s|$)""")
ALLOWED_OTHER = [
    re.compile(r'^MEROD_ENV_FILE="/etc/calimero/merod\.env"$'),
    re.compile(r'^chmod 0644 "?' + REF + r'"?$'),
    re.compile(r'^rm -f "?' + REF + r'"?$'),
    re.compile(r'^if \[\[ !? ?-[fse] "?' + REF + r'"? \]\]; then$'),
]
SED_DELETE = re.compile(r"""^sed -i '/\^([A-Z][A-Z0-9_]*)=/d' "?""" + REF + r'"?$')


def env_keys(profile):
    """Render calimero-init for PROFILE; return the merod.env keys it writes."""
    src = template.read_text()
    try:
        text = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(src).render(
            lockdown_profile=profile)
    except jinja2.TemplateError as exc:
        finding(f"{profile}: calimero-init does not render: {exc}")
        return set()
    lines = text.splitlines()
    keys = set()
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Another name for the file would hide its writes from this check.
        if re.search(r'^[A-Za-z_][A-Za-z0-9_]*=.*merod\.env', line) \
                and not ALLOWED_OTHER[0].match(line):
            finding(f"{profile}:{i + 1}: a new name for merod.env: {line}")
            continue
        if not re.search(r'merod\.env|MEROD_ENV_FILE', line):
            continue
        if line.startswith(("log ", "fatal ")):
            continue
        if any(p.match(line) for p in ALLOWED_OTHER):
            continue
        m = SED_DELETE.match(line)
        if m:
            if m.group(1) not in ENV_WHITELIST:
                finding(f"{profile}:{i + 1}: deletes a key that is not whitelisted: {line}")
            continue
        if WRITE_RE.search(line):
            if line.startswith("}"):
                # A `{ ...; } > merod.env` group: walk back to its `{`.
                indent = len(raw) - len(raw.lstrip())
                j = i - 1
                while j >= 0 and not (lines[j].strip() == "{"
                                      and len(lines[j]) - len(lines[j].lstrip()) == indent):
                    j -= 1
                if j < 0:
                    finding(f"{profile}:{i + 1}: cannot find the group this write closes")
                    continue
                body = [(k, lines[k].strip()) for k in range(j + 1, i)]
            else:
                body = [(i, line)]
            for k, stmt in body:
                if not stmt or stmt.startswith("#") or stmt in ("fi", "else") \
                        or re.match(r'^(if|elif) \[\[ .* \]\]; then$', stmt):
                    continue
                pm = PRINTF_RE.match(stmt)
                if not pm:
                    finding(f"{profile}:{k + 1}: writes merod.env other than as "
                            f"printf 'KEY=\"...\"\\n': {stmt}")
                    continue
                keys.add(pm.group(1))
            continue
        finding(f"{profile}:{i + 1}: a use of merod.env this check does not know; "
                f"classify it in {Path(__file__).name}: {line}")

    # merod.service drop-ins: job-node.conf alone, and only what it unsets.
    for i, raw in enumerate(lines):
        line = raw.strip()
        if line.startswith("#") or "merod.service" not in line:
            continue
        if line in (f"mkdir -p {DROPIN_DIR}", DROPIN_WRITE):
            continue
        if line.startswith(("log ", "systemctl ")) and "set-environment" not in line \
                and "edit" not in line and "import-environment" not in line:
            continue
        finding(f"{profile}:{i + 1}: touches merod.service other than the job-node drop-in: {line}")
    for i, raw in enumerate(lines):
        if re.search(r'systemctl\s+(set-environment|import-environment)', raw) \
                and not raw.strip().startswith("#"):
            finding(f"{profile}:{i + 1}: sets the manager's environment, which merod inherits: {raw.strip()}")
    return keys


per_profile = {p: env_keys(p) for p in PROFILES}
for p, keys in per_profile.items():
    for k in sorted(keys - ENV_WHITELIST):
        finding(f"{p}: merod.env gets {k}, which is not in ENV_WHITELIST")
written = set().union(*per_profile.values())
for k in sorted(ENV_WHITELIST - written):
    finding(f"ENV_WHITELIST names {k}, which calimero-init no longer writes; drop it")

# Nothing else in the image writes a merod.service drop-in or the unit.
for path in sorted(tree.rglob("*")):
    if not path.is_file() or path == template or path == tasks:
        continue
    try:
        text = path.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    if "merod.service.d" in text:
        finding(f"{path.relative_to(tree)}: writes a merod.service drop-in")
    if re.search(r'dest:\s*/etc/systemd/system/merod\.service\b', text):
        finding(f"{path.relative_to(tree)}: writes the merod.service unit")

# The unit itself.
units = []
for task in yaml.safe_load(tasks.read_text()) or []:
    for module in ("copy", "ansible.builtin.copy", "template", "ansible.builtin.template"):
        spec = task.get(module) if isinstance(task, dict) else None
        if isinstance(spec, dict) and str(spec.get("dest", "")).startswith("/etc/systemd/system/merod.service"):
            units.append((module, spec))
if len(units) != 1 or units[0][0] not in ("copy", "ansible.builtin.copy") or "content" not in units[0][1]:
    finding(f"{tasks.name}: expected exactly one inline `copy: content:` merod.service, found {len(units)}")
else:
    section = None
    envs = set()
    for n, raw in enumerate(units[0][1]["content"].splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        sm = re.match(r'^\[(.+)\]$', line)
        if sm:
            section = sm.group(1)
            if section not in UNIT_DIRECTIVES:
                finding(f"merod.service:{n}: section [{section}] is not whitelisted")
            continue
        key, sep, value = line.partition("=")
        if not sep:
            finding(f"merod.service:{n}: not a directive: {line}")
            continue
        if key not in UNIT_DIRECTIVES.get(section, set()):
            finding(f"merod.service:{n}: [{section}] {key}= is not whitelisted")
            continue
        if key == "Environment":
            for item in value.split():
                envs.add(item)
                if item not in UNIT_ENVIRONMENT:
                    finding(f"merod.service:{n}: Environment={item} is not whitelisted")
        elif key == "EnvironmentFile" and value != UNIT_ENVIRONMENT_FILE:
            finding(f"merod.service:{n}: EnvironmentFile={value}, expected {UNIT_ENVIRONMENT_FILE}")
        elif key == "ExecStart" and value != UNIT_EXEC_START:
            finding(f"merod.service:{n}: ExecStart={value}, expected {UNIT_EXEC_START}")

if findings:
    for f in findings:
        print(f"  {f}")
    sys.exit(1)
print("merod.env keys by profile: " + "; ".join(
    f"{p}: {' '.join(sorted(k))}" for p, k in per_profile.items()))
PY

check() { python3 "$WORK/check.py" "$1" "$2" "$3"; }

# --- the real files --------------------------------------------------------------
if ! out="$(check "$TEMPLATE" "$TASKS" "$TREE" 2>&1)"; then
  fail "merod.env / merod.service carry something not whitelisted:
$out"
fi
echo "$out"

# --- mutations, each of which the checker must catch ------------------------------
# mutate NAME FILE(template|tasks) PYTHON-EXPR-ON-s EXPECTED-SUBSTRING
mutate() {
  local name="$1" which="$2" expr="$3" want="$4" dir="$WORK/m-$1"
  mkdir -p "$dir/tree"
  cp "$TEMPLATE" "$dir/t.j2"
  cp "$TASKS" "$dir/tasks.yml"
  local target="$dir/t.j2"
  [[ "$which" == tasks ]] && target="$dir/tasks.yml"
  python3 - "$target" "$expr" <<'PY'
import sys
path, expr = sys.argv[1], sys.argv[2]
s = open(path).read()
new = eval(expr, {"s": s})
if new == s:
    sys.exit(f"mutation did not change {path}")
open(path, "w").write(new)
PY
  local out
  if out="$(check "$dir/t.j2" "$dir/tasks.yml" "$dir/tree" 2>&1)"; then
    fail "mutation '$name' was not caught"
  fi
  grep -qF -- "$want" <<<"$out" || fail "mutation '$name' failed for another reason than expected ('$want'):
$out"
  echo "ok   mutation caught: $name"
}

ANCHOR='# --- merod 1.0: storage key and cluster configuration'
mutate new-key template \
  "s.replace('$ANCHOR', 'printf \\'MEROD_DEV=\"true\"\\\\n\\' >> /etc/calimero/merod.env\\n$ANCHOR', 1)" \
  "MEROD_DEV, which is not in ENV_WHITELIST"
mutate new-key-in-group template \
  "s.replace('    printf \\'MEROD_CLUSTER=\"%s\"\\\\n\\' \"\$JOB_CLUSTER\"\\n', '    printf \\'MEROD_CLUSTER=\"%s\"\\\\n\\' \"\$JOB_CLUSTER\"\\n    printf \\'MEROD_PEERS=\"%s\"\\\\n\\' \"\$(get_meta peers)\"\\n', 1)" \
  "MEROD_PEERS, which is not in ENV_WHITELIST"
mutate echo-write template \
  "s.replace('$ANCHOR', 'echo \"MEROD_LISTEN=0.0.0.0:2528\" >>\"\$MEROD_ENV_FILE\"\\n$ANCHOR', 1)" \
  "writes merod.env other than as printf"
mutate alias template \
  "s.replace('$ANCHOR', 'ENVF=/etc/calimero/merod.env\\n$ANCHOR', 1)" \
  "a new name for merod.env"
mutate new-dropin template \
  "s.replace('$ANCHOR', 'printf \\'[Service]\\\\nEnvironment=MEROD_DEV=true\\\\n\\' >/run/systemd/system/merod.service.d/dev.conf\\n$ANCHOR', 1)" \
  "touches merod.service other than the job-node drop-in"
mutate set-environment template \
  "s.replace('$ANCHOR', 'systemctl set-environment MEROD_DEV=true\\n$ANCHOR', 1)" \
  "sets the manager's environment"
mutate unit-environment tasks \
  "s.replace('Environment=MEROD_LISTEN=127.0.0.1:2528', 'Environment=MEROD_LISTEN=0.0.0.0:2528', 1)" \
  "Environment=MEROD_LISTEN=0.0.0.0:2528 is not whitelisted"
mutate unit-exec-start-pre tasks \
  "s.replace('        ExecStart=/usr/local/bin/merod', '        ExecStartPre=/bin/true\\n        ExecStart=/usr/local/bin/merod', 1)" \
  "ExecStartPre= is not whitelisted"
mutate unit-exec-start-flag tasks \
  "s.replace('--node default run', '--node default run --dev', 1)" \
  "ExecStart=/usr/local/bin/merod --home /mnt/data/merod --node default run --dev"
mutate unit-environment-file tasks \
  "s.replace('EnvironmentFile=-/etc/calimero/merod.env', 'EnvironmentFile=-/etc/calimero/merod.env\\n        EnvironmentFile=-/mnt/data/extra.env', 1)" \
  "EnvironmentFile=-/mnt/data/extra.env"

echo "PASS: merod.env and merod.service carry only whitelisted keys, on every profile"
