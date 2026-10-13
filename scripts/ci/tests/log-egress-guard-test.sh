#!/usr/bin/env bash
#
# Every log line passes the egress guard before it leaves the TEE.
#
# Logs go to `logs-endpoint` instance metadata, which whoever runs the VM
# chooses, so every shipped line is readable by the operator. Each image's
# vector_partial.yaml routes its journal through `guard_egress`, which runs
# mero-tee/ansible/roles/vector/files/egress-guard.vrl, and configure_vector.sh
# points the sink at nothing else. This checks, with the Vector release the
# image bakes (sha256 from build-inputs.lock.json):
#
#   * node, KMS and agent configs each carry `guard_egress` reading `add_labels`
#     and dropping, never passing, a line it cannot process;
#   * the generated vector.yaml validates and its sink reads only
#     `guard_egress`;
#   * configure_vector.sh refuses a partial without the guard;
#   * the program masks the credential shapes below, keeps the fields a line
#     needs, drops the rest of journald's, and caps a message at 8 KiB.
#
# Set VECTOR_BIN to a vector binary to skip the download.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLES="${ROOT}/mero-tee/ansible/roles"
GUARD="${ROLES}/vector/files/egress-guard.vrl"
CONFIGURE="${ROLES}/vector/files/configure_vector.sh"
PARTIALS=(
  "${ROLES}/merotee/files/vector-partial-merod.yaml"
  "${ROLES}/mero-kms/files/vector-partial-kms.yaml"
  "${ROLES}/mero-agent/files/vector-partial-agent.yaml"
)

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- the Vector binary the image bakes ---------------------------------------
if [[ -z "${VECTOR_BIN:-}" ]]; then
  read -r version asset digest < <(python3 - "${ROOT}/mero-tee/build-inputs.lock.json" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))["vector"]
(asset, digest), = [(a, d) for a, d in v["sha256"].items() if "x86_64-unknown-linux-gnu" in a]
print(v["version"], asset, digest)
PY
)
  curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors -o "${SB}/vector.tgz" \
    "https://github.com/vectordotdev/vector/releases/download/v${version}/${asset}"
  echo "${digest}  ${SB}/vector.tgz" | sha256sum -c --quiet - || fail "vector archive does not match build-inputs.lock.json"
  mkdir -p "${SB}/vector-dist"
  tar -xzf "${SB}/vector.tgz" -C "${SB}/vector-dist" --strip-components=2
  VECTOR_BIN="${SB}/vector-dist/bin/vector"
fi
"${VECTOR_BIN}" --version >/dev/null || fail "cannot run ${VECTOR_BIN}"

# --- each partial routes through the guard -----------------------------------
for partial in "${PARTIALS[@]}"; do
  python3 - "$partial" <<'PY' || exit 1
import re, sys
path = sys.argv[1]
text = open(path).read()
m = re.search(r"(?ms)^  guard_egress:\n((?:    .*\n?)+)", text)
if not m:
    sys.exit(f"FAIL: {path} has no guard_egress transform")
body = m.group(1)
want = {
    "type": "remap",
    "inputs": "[add_labels]",
    "file": "/etc/vector/egress-guard.vrl",
    "drop_on_error": "true",
    "drop_on_abort": "true",
}
for key, value in want.items():
    if not re.search(rf"(?m)^    {key}:\s*{re.escape(value)}\s*$", body):
        sys.exit(f"FAIL: {path}: guard_egress must set {key}: {value}")
if "sinks:" in text:
    sys.exit(f"FAIL: {path} declares a sink; configure_vector.sh owns the sink")
PY
done

# --- the generated config validates, and ships only guarded lines -----------
mkdir -p "${SB}/bin" "${SB}/etc/vector" "${SB}/etc/calimero"
printf '#!/usr/bin/env bash\nexit 0\n' > "${SB}/bin/systemctl"; chmod +x "${SB}/bin/systemctl"
sed -e "s@/etc/vector@${SB}/etc/vector@g" -e "s@/etc/calimero@${SB}/etc/calimero@g" \
  "$CONFIGURE" > "${SB}/configure.sh"; chmod +x "${SB}/configure.sh"
cp "$GUARD" "${SB}/etc/vector/egress-guard.vrl"
echo "locked-read-only" > "${SB}/etc/calimero/image-profile"

for partial in "${PARTIALS[@]}"; do
  sed -e "s@/etc/vector@${SB}/etc/vector@g" "$partial" > "${SB}/etc/vector/vector_partial.yaml"
  rm -f "${SB}/etc/vector/vector.yaml"
  PATH="${SB}/bin:${PATH}" "${SB}/configure.sh" "${SB}/etc/vector/vector_partial.yaml" \
    "https://victoria.test/insert/elasticsearch" false provided "" >"${SB}/out" 2>&1 \
    || { cat "${SB}/out" >&2; fail "configure_vector.sh failed for $(basename "$partial")"; }
  "${VECTOR_BIN}" validate --no-environment "${SB}/etc/vector/vector.yaml" >"${SB}/validate" 2>&1 \
    || { cat "${SB}/validate" >&2; fail "vector rejects the config generated from $(basename "$partial")"; }
  python3 - "${SB}/etc/vector/vector.yaml" <<'PY' || exit 1
import re, sys
text = open(sys.argv[1]).read()
sink = text[text.index("\nsinks:"):]
inputs = re.search(r"(?m)^    inputs:\n((?:      - .*\n)+)", sink).group(1)
if [l.strip()[2:] for l in inputs.splitlines()] != ["guard_egress"]:
    sys.exit(f"FAIL: the sink must read only guard_egress, got {inputs.split()}")
PY
done

# A partial without the guard is refused, not shipped unfiltered.
grep -v "guard_egress" "${PARTIALS[0]}" > "${SB}/etc/vector/vector_partial.yaml"
if PATH="${SB}/bin:${PATH}" "${SB}/configure.sh" "${SB}/etc/vector/vector_partial.yaml" \
    "https://victoria.test/insert/elasticsearch" false provided "" >"${SB}/out" 2>&1; then
  fail "configure_vector.sh configured a partial with no guard_egress"
fi

# --- what the program lets out -----------------------------------------------
long="$(python3 -c 'print("x" * 9000)')"
cat > "${SB}/events.json" <<EOF
{"timestamp":"t","message":"login ok token=abc.def.ghi user=alice","unit":"mero-auth.service","hostname":"h","instance_name":"merotee","instance_type":"gcp","instance_profile":"locked-read-only","PRIORITY":"6","_CMDLINE":"/usr/local/bin/merod --password LEAK-CMDLINE","_PID":"12","_BOOT_ID":"LEAK-BOOT","_MACHINE_ID":"LEAK-MACHINE"}
{"timestamp":"t","message":"Authorization: Bearer LEAKbearerTOKEN0123456789 done","unit":"traefik.service"}
{"timestamp":"t","message":"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJMRUFLIn0.LEAKsignature0123 used","unit":"mero-auth.service"}
{"timestamp":"t","message":"got key -----BEGIN PRIVATE KEY-----\nLEAKpem0123\n-----END PRIVATE KEY----- ok","unit":"calimero-init.service"}
{"timestamp":"t","message":"cut -----BEGIN EC PRIVATE KEY-----\nLEAKcutoff","unit":"calimero-init.service"}
{"timestamp":"t","message":"{\"password\":\"LEAKpw\",\"refresh_token\": \"LEAKrt\", \"api_key\":\"LEAKak\", \"client_secret\":\"LEAKcs\"} Cookie: LEAKcookie","unit":"merod.service"}
{"timestamp":"t","message":"basic Basic LEAKbasic0123456789 mnemonic=LEAKmn seed: LEAKseed private_key=LEAKpk","unit":"merod.service"}
{"timestamp":"t","message":"context_id=5Hx9abc public_key=ed25519:AbC token_id=7 tokens: 4 secrets loaded","unit":"merod.service"}
{"timestamp":"t","message":"${long}","unit":"merod.service"}
{"timestamp":"t","message":"execution log 0| LEAKguestlog balance=12","unit":"merod.service"}
{"timestamp":"t","message":"Request failed err=FunctionCallError(\"the method call returned an error: LEAKapperr\")","unit":"merod.service"}
{"timestamp":"t","message":"WASM method execution failed error_debug=RuntimeError guest panicked: LEAKpanic at src/lib.rs:1:1","unit":"merod.service"}
{"timestamp":"t","message":"\u001b[3merror_message\u001b[0m\u001b[2m=\u001b[0mLEAKcoloured","unit":"merod.service"}
{"timestamp":"t","message":"panicked panic.message=LEAKpanicmsg panic.backtrace=LEAKbt","unit":"merod.service"}
{"timestamp":"t","message":"Created the admin account (user: LEAKadmin) user=LEAKuser","unit":"merod.service"}
{"timestamp":"t","message":"Authentication failed: invalid type: string \"LEAKserde\", unknown variant \`LEAKvariant\`","unit":"mero-auth.service"}
{"timestamp":"t","message":"Refresh token reuse detected for key K1 (jti LEAKjti) client_id=Some(String(\"LEAKid\"))","unit":"merod.service"}
{"timestamp":"t","message":"KMS get-key request failed (500): Internal - LEAKkmsbody","unit":"merod.service"}
{"timestamp":"t","message":"fetching https://LEAKuser:LEAKpass@apps.test/a.wasm?access_token=LEAKqt&x=1","unit":"merod.service"}
{"timestamp":"t","message":"abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress leak","unit":"merod.service"}
EOF
"${VECTOR_BIN}" vrl -i "${SB}/events.json" -p "$GUARD" -o 2>/dev/null > "${SB}/shipped.json" \
  || fail "the guard program does not run"

python3 - "${SB}/shipped.json" <<'PY'
import json, sys
lines = [l for l in open(sys.argv[1]).read().splitlines() if l.startswith("{")]
events = [json.loads(l) for l in lines]
failures = []
if len(events) != 20:
    failures.append(f"expected 20 events out, got {len(events)}")
shipped = "\n".join(lines)
# Every planted secret contains "leak" in some case; none may survive.
if "leak" in shipped.lower():
    leaks = sorted({w for w in shipped.replace('"', " ").split() if "leak" in w.lower()})
    failures.append(f"secret material left the guard: {leaks}")
allowed = {"timestamp", "message", "unit", "hostname", "instance_name", "instance_type", "instance_profile", "priority"}
for e in events:
    extra = set(e) - allowed
    if extra:
        failures.append(f"fields beyond the allowlist left: {sorted(extra)}")
first = events[0] if events else {}
for k, v in {"unit": "mero-auth.service", "hostname": "h", "instance_profile": "locked-read-only", "priority": "6"}.items():
    if first.get(k) != v:
        failures.append(f"{k} should survive as {v!r}, got {first.get(k)!r}")
keep = events[7]["message"] if len(events) > 7 else ""
for word in ["context_id=5Hx9abc", "public_key=ed25519:AbC", "token_id=7", "tokens: 4", "secrets loaded"]:
    if word not in keep:
        failures.append(f"non-secret text was masked: {word!r} missing from {keep!r}")
if "]]" in shipped:
    failures.append("a value was masked twice (stray ']]' in the output)")
big = events[8]["message"] if len(events) > 8 else ""
if not (big.endswith("[TRUNCATED]") and len(big) <= 8192 + len(" [TRUNCATED]")):
    failures.append(f"a 9000-byte message was not capped at 8 KiB (got {len(big)} bytes)")
if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)
print("OK: node, KMS and agent logs leave only through the egress guard; credentials masked, fields allowlisted, messages capped")
PY
