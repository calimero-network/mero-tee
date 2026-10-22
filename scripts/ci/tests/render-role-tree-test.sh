#!/usr/bin/env bash
# scripts/image/render_role_tree.py renders what an Ansible image playbook
# writes into a directory, for the mkosi image builds. Check that it:
#   - does what copy, template, file, get_url + unarchive and systemd do, the
#     way Ansible does (trim_blocks, per-task Jinja delimiters, unarchive's
#     mode on every member, role vars over play vars over defaults);
#   - evaluates when: and loop:, and skips a task that needs a registered
#     result, but fails on any other undefined variable;
#   - keeps set_fact results (lookup('file') + from_json) for later roles,
#     stats a build-host file for the asserts on it, fails the render on a
#     failing assert, unpacks a build-host archive, and lists `user` tasks;
#   - applies a task's and a block's own vars (the agent role's bundle pin),
#     and keeps a fact set inside such a block;
#   - refuses an unpinned download and one whose sha256 differs;
#   - renders the real node and KMS playbooks' file-only roles, so a module a
#     role starts using that it cannot render fails here, not in the image
#     build, and the KMS role's own checks (an empty allowlist) still hold.
#
# Usage: scripts/ci/tests/render-role-tree-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="${REPO_ROOT}/scripts/image/render_role_tree.py"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() { echo "FAIL: $*"; exit 1; }

# --- a synthetic playbook ------------------------------------------------------
pb="${work}/pb"
role="${pb}/roles/demo"
mkdir -p "${role}/tasks" "${role}/templates" "${role}/files" "${role}/defaults" "${pb}/cache-src/demo-1.0"
echo '{"demo": {"sha256": {}}}' > "${pb}/build-inputs.lock.json"
printf 'flavour: default\ngreeting: "hello {{ flavour }}"\n' > "${role}/defaults/main.yml"
printf 'static file\n' > "${role}/files/static.txt"
cat > "${role}/templates/script.sh.j2" <<'T'
#!/bin/bash
{% if flavour == 'vanilla' %}
FLAVOUR={{ flavour }}
{% endif %}
COUNT=${#items[@]}
T
cat > "${role}/templates/plain.j2" <<'T'
{{ greeting }}
T
printf 'binary\n' > "${pb}/cache-src/demo-1.0/demo"
tar -czf "${work}/demo-1.0.tar.gz" -C "${pb}/cache-src" demo-1.0
mkdir -p "${work}/cache"
cp "${work}/demo-1.0.tar.gz" "${work}/cache/"
sha="$(sha256sum "${work}/demo-1.0.tar.gz" | cut -d' ' -f1)"

cat > "${role}/tasks/main.yml" <<T
- name: Copy content
  copy:
    content: "{{ greeting }}\n"
    dest: /etc/demo/greeting
    mode: "0600"
- name: Copy a file
  copy:
    src: static.txt
    dest: /etc/demo/static.txt
- name: Template with Ansible's defaults and its own comment delimiter
  template:
    src: script.sh.j2
    dest: /usr/local/bin/demo.sh
    mode: "0755"
    comment_start_string: "{@#"
    comment_end_string: "#@}"
- name: Template plain
  template:
    src: plain.j2
    dest: /etc/demo/plain
- name: Never
  copy:
    content: "no"
    dest: /etc/demo/never
  when: flavour == 'chocolate'
- name: Directories from a loop
  file:
    path: "/var/lib/demo/{{ item }}"
    state: directory
    mode: "0700"
  loop: [a, b]
- name: Link
  file:
    src: /usr/local/bin/demo.sh
    dest: /usr/bin/demo
    state: link
- name: Remove one
  file:
    path: /var/lib/demo/b
    state: absent
- name: Download
  get_url:
    url: https://example.invalid/demo-1.0.tar.gz
    dest: /tmp/demo-1.0.tar.gz
    checksum: "sha256:${sha}"
- name: Unpack
  unarchive:
    src: /tmp/demo-1.0.tar.gz
    dest: /opt/demo
    mode: "0750"
    remote_src: yes
    extra_opts: [--strip-components=1]
- name: Packages
  apt:
    name: [jq, curl]
    state: present
- name: Purge
  apt:
    name: telnet
    state: absent
- name: Mask
  systemd:
    name: getty.target
    masked: true
- name: Enable
  systemd:
    name: demo.service
    enabled: true
- name: Read a build-host JSON file
  set_fact:
    policy: "{{ lookup('file', policy_file) | from_json }}"
- name: Stat a build-host file
  stat:
    path: "{{ policy_file }}"
    checksum_algorithm: sha256
  delegate_to: localhost
  register: policy_stat
- name: Assert on both
  assert:
    that:
      - policy.allowed | length > 0
      - policy_stat.stat.exists
      - policy_stat.stat.checksum | length == 64
    fail_msg: "the policy is empty"
- name: Assert with a task's own vars, as the agent role pins its bundle
  vars:
    first: "{{ policy.allowed[0] }}"
  assert:
    that:
      - first == "x"
    fail_msg: "first is {{ first }}"
- name: A block with vars that sets a fact
  vars:
    second: "{{ policy.allowed[1] }}"
  block:
    - name: Set it
      set_fact:
        from_block: "{{ second }}"
- name: The fact holds after the block
  copy:
    content: "{{ from_block }}\n"
    dest: /etc/demo/from-block
- name: Unpack a build-host archive
  unarchive:
    src: "{{ local_archive }}"
    dest: /opt/local
    extra_opts: [--strip-components=1]
- name: A user
  user:
    name: demo-1
    system: true
    shell: /usr/sbin/nologin
    create_home: false
- name: Probe
  command: /bin/true
  register: probe
- name: Uses the probe
  copy:
    content: "{{ probe.stdout }}"
    dest: /etc/demo/probe
T
cat > "${pb}/playbook.yml" <<'T'
- hosts: all
  vars:
    flavour: vanilla
  roles:
    - role: roles/demo
    - role: roles/later
T
mkdir -p "${pb}/roles/later/tasks"
cat > "${pb}/roles/later/tasks/main.yml" <<'T'
- name: A fact from the role before
  copy:
    content: "{{ policy.allowed | join(',') }}\n"
    dest: /etc/demo/allowed
T
echo '{"allowed": ["x", "y"]}' > "${work}/policy.json"
echo '{"allowed": []}' > "${work}/empty-policy.json"

render_args=(-e "policy_file=${work}/policy.json" -e "local_archive=${work}/demo-1.0.tar.gz")
python3 "${TOOL}" "${pb}/playbook.yml" --out "${work}/out" --manifest "${work}/manifest.json" --cache "${work}/cache" \
  "${render_args[@]}" >/dev/null || fail "render failed"
out="${work}/out"
[[ "$(cat "${out}/etc/demo/greeting")" == "hello vanilla" ]] || fail "play var over role default, var in var: $(cat "${out}/etc/demo/greeting")"
[[ "$(stat -c %a "${out}/etc/demo/greeting")" == "600" ]] || fail "copy mode"
[[ "$(cat "${out}/etc/demo/static.txt")" == "static file" ]] || fail "copy src"
expected=$'#!/bin/bash\nFLAVOUR=vanilla\nCOUNT=${#items[@]}'
[[ "$(cat "${out}/usr/local/bin/demo.sh")" == "${expected}" ]] || fail "template (trim_blocks, comment delimiter): $(cat "${out}/usr/local/bin/demo.sh")"
[[ "$(stat -c %a "${out}/usr/local/bin/demo.sh")" == "755" ]] || fail "template mode"
[[ ! -e "${out}/etc/demo/never" ]] || fail "when: false still ran"
[[ -d "${out}/var/lib/demo/a" && ! -e "${out}/var/lib/demo/b" ]] || fail "loop + absent"
[[ "$(stat -c %a "${out}/var/lib/demo/a")" == "700" ]] || fail "directory mode"
[[ "$(readlink "${out}/usr/bin/demo")" == "/usr/local/bin/demo.sh" ]] || fail "link"
[[ "$(cat "${out}/opt/demo/demo")" == "binary" ]] || fail "unarchive with --strip-components"
[[ "$(stat -c %a "${out}/opt/demo/demo")" == "750" ]] || fail "unarchive mode on the member"
[[ ! -e "${out}/etc/demo/probe" ]] || fail "a task on a registered result ran"
[[ "$(cat "${out}/etc/demo/allowed")" == "x,y" ]] || fail "set_fact for a later role: $(cat "${out}/etc/demo/allowed" 2>&1)"
[[ "$(cat "${out}/opt/local/demo")" == "binary" ]] || fail "unarchive of a build-host archive"
[[ "$(cat "${out}/etc/demo/from-block")" == "y" ]] || fail "a block's vars or its set_fact: $(cat "${out}/etc/demo/from-block" 2>&1)"

python3 - "${work}/manifest.json" <<'PY' || fail "manifest"
import json, sys
m = json.load(open(sys.argv[1]))
assert m["packages"] == [{"role": "demo", "names": ["jq", "curl"], "state": "present"},
                         {"role": "demo", "names": ["telnet"], "state": "absent"}], m["packages"]
assert m["mask"] == ["getty.target"] and m["enable"] == ["demo.service"], (m["mask"], m["enable"])
skipped = {s["task"] for s in m["skipped"]}
assert skipped == {"Probe", "Uses the probe"}, skipped
assert m["users"] == [{"name": "demo-1", "system": True, "shell": "/usr/sbin/nologin", "create_home": False}], m["users"]
PY

# A failing assert fails the render, and with it the image build.
if python3 "${TOOL}" "${pb}/playbook.yml" --out "${work}/out1" --manifest "${work}/m1.json" --cache "${work}/cache" \
     -e "policy_file=${work}/empty-policy.json" -e "local_archive=${work}/demo-1.0.tar.gz" >/dev/null 2>&1; then
  fail "a failing assert passed"
fi

# Any other undefined variable is an error, not a skip.
sed -i 's/{{ greeting }}\\n/{{ no_such_var }}/' "${role}/tasks/main.yml"
if python3 "${TOOL}" "${pb}/playbook.yml" --out "${work}/out2" --manifest "${work}/m2.json" --cache "${work}/cache" "${render_args[@]}" >/dev/null 2>&1; then
  fail "an undefined variable was skipped"
fi
sed -i 's/{{ no_such_var }}/{{ greeting }}\\n/' "${role}/tasks/main.yml"

# A download with a different sha256, or none, is refused.
printf 'tampered\n' >> "${work}/cache/demo-1.0.tar.gz"
if python3 "${TOOL}" "${pb}/playbook.yml" --out "${work}/out3" --manifest "${work}/m3.json" --cache "${work}/cache" "${render_args[@]}" >/dev/null 2>&1; then
  fail "a download whose sha256 differs was used"
fi
sed -i '/checksum:/d' "${role}/tasks/main.yml"
if python3 "${TOOL}" "${pb}/playbook.yml" --out "${work}/out4" --manifest "${work}/m4.json" --cache "${work}/cache" "${render_args[@]}" >/dev/null 2>&1; then
  fail "an unpinned download was used"
fi

# --- the real node playbook ---------------------------------------------------
# The roles that only lay down files (the ones with downloads need the cache).
python3 "${TOOL}" "${REPO_ROOT}/mero-tee/playbook.yml" --out "${work}/node" --manifest "${work}/node.json" \
  --cache "${work}/empty" -e lockdown_profile=locked-read-only -e image_version=0.0.0 -e cpu_architecture=amd64 \
  -e merod_version=0.0.0 --role merotee --role cleanup --role merod-lockdown --role merotee-conformance \
  >/dev/null || fail "the node playbook's roles do not render"
grep -q '^IMAGE_PROFILE="locked-read-only"$' "${work}/node/usr/local/lib/calimero/init.sh" || fail "calimero-init not rendered for the profile"
grep -qF "'server.apps.trust_proxy=true'" "${work}/node/usr/local/lib/calimero/init.sh" || fail "rendered init does not set server.apps.trust_proxy"
grep -qF 'DNS:*.$1' "${work}/node/usr/local/lib/calimero/fleet-sidecar.sh" || fail "rendered sidecar CSR has no wildcard SAN"
for path in etc/systemd/system/calimero-init.service usr/local/lib/calimero/fleet-sidecar.sh etc/securetty \
            etc/systemd/journald.conf.d/60-calimero-volatile.conf; do
  [[ -e "${work}/node/${path}" ]] || fail "node playbook: ${path} not rendered"
done

# --- the real KMS playbook ----------------------------------------------------
echo stub > "${work}/mero-kms"
kms_policy="${work}/kms-policy.json"
# The role takes only 96-hex measurements (see kms-node-allowlist-test.sh).
jq -n '{allowed_tcb_statuses: ["UpToDate"]}
  + ([["mrtd", "a"], ["rtmr0", "b"], ["rtmr1", "c"], ["rtmr2", "d"], ["rtmr3", "e"]]
     | map({key: "allowed_\(.[0])", value: [.[1] * 96]}) | from_entries)' > "${kms_policy}"
kms_render() {
  python3 "${TOOL}" "${REPO_ROOT}/mero-tee/playbook-kms.yml" --out "${work}/$1" --manifest "${work}/$1.json" \
    --cache "${work}/empty" -e lockdown_profile=locked-read-only -e image_version=0.0.0 \
    -e "mero_kms_binary=${work}/mero-kms" -e "kms_node_policy_file=$2" -e kms_agent_policy_file= \
    --role mero-kms --role cleanup --role merod-lockdown
}
kms_render kms "${kms_policy}" >/dev/null || fail "the KMS playbook's roles do not render"
grep -q '^IMAGE_PROFILE="locked-read-only"$' "${work}/kms/usr/local/lib/mero-kms/init.sh" || fail "kms-init not rendered for the profile"
for path in etc/mero-kms/kms.env etc/systemd/system/mero-kms.service usr/local/bin/mero-kms; do
  [[ -e "${work}/kms/${path}" ]] || fail "KMS playbook: ${path} not rendered"
done
grep -q '^ALLOWED_RTMR3=e\{96\}$' "${work}/kms/etc/mero-kms/kms.env" || fail "the node allowlist is not in kms.env"
jq '.allowed_rtmr3 = []' "${kms_policy}" > "${work}/kms-empty.json"
if kms_render kms-empty "${work}/kms-empty.json" >/dev/null 2>&1; then
  fail "a KMS image with an empty RTMR3 allowlist rendered"
fi

# --- the real inference playbook ----------------------------------------------
echo stub > "${work}/mero-inference-gate"
python3 "${TOOL}" "${REPO_ROOT}/mero-tee/playbook-inference.yml" --out "${work}/inference" \
  --manifest "${work}/inference.json" --cache "${work}/empty" -e lockdown_profile=locked-read-only \
  -e image_version=0.0.0 -e "mero_inference_gate_binary=${work}/mero-inference-gate" \
  --role mero-inference --role cleanup --role merod-lockdown \
  >/dev/null || fail "the inference playbook's roles do not render"
grep -q '^IMAGE_PROFILE="locked-read-only"$' "${work}/inference/usr/local/lib/mero-inference/init.sh" \
  || fail "inference-init not rendered for the profile"
for path in etc/mero-inference/gate.env etc/systemd/system/mero-inference-gate.service \
            etc/systemd/system/mero-inference-vllm.service usr/local/bin/mero-inference-gate \
            usr/local/lib/mero-inference/inference_model.py usr/local/lib/mero-inference/gpu-evidence; do
  [[ -e "${work}/inference/${path}" ]] || fail "inference playbook: ${path} not rendered"
done
# vLLM is started by inference-init, never enabled: the measurement VM has no model.
jq -e '.enable | index("mero-inference-vllm.service") | not' "${work}/inference.json" >/dev/null \
  || fail "mero-inference-vllm.service must not be enabled"
jq -e '[.packages[].names[]] | index("linux-modules-nvidia-580-server-open-gcp")' "${work}/inference.json" >/dev/null \
  || fail "the inference image does not install the NVIDIA open modules"
if python3 "${TOOL}" "${REPO_ROOT}/mero-tee/playbook-inference.yml" --out "${work}/inference-nogate" \
    --manifest "${work}/inference-nogate.json" --cache "${work}/empty" -e lockdown_profile=locked-read-only \
    -e image_version=0.0.0 -e mero_inference_gate_binary= --role mero-inference >/dev/null 2>&1; then
  fail "an inference image without its gate rendered"
fi

echo "PASS: render role tree"
