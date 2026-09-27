#!/usr/bin/env bash
# The shippers' configure scripts must refuse a value that could inject config.
#
# `configure_vector.sh` pastes the logs URL and the bearer token into vector's
# YAML; `configure_vmagent.sh` pastes the remote-write URL into a systemd unit.
# Both values come from instance metadata, which whoever runs the VM can set. A
# newline in the vmagent URL is an extra `ExecStart=` line running as root, on
# a node beside its storage key and on a KMS replica beside the cluster root.
#
# Also checks the KMS image's labels: a replica must say `mero-kms` and its own
# profile (OBS_INSTANCE_TYPE / OBS_PROFILE_FILE), or its series join a node's.
#
# Usage: scripts/ci/tests/observability-config-injection-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLES="${REPO_ROOT}/mero-tee/ansible/roles"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
mkdir -p "${SB}/bin" "${SB}/vector" "${SB}/vmagent" "${SB}/calimero" "${SB}/mero-kms" "${SB}/systemd"

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in vector vmagent; do
  sed -e "s@/etc/vector@${SB}/vector@g" -e "s@/etc/vmagent@${SB}/vmagent@g" \
      -e "s@/etc/calimero@${SB}/calimero@g" -e "s@/etc/systemd/system@${SB}/systemd@g" \
      "${ROLES}/${tool}/files/configure_${tool}.sh" > "${SB}/configure_${tool}.sh"
  sed -e "s@/etc/${tool}@${SB}/${tool}@g" "${ROLES}/${tool}/files/fetch_secret.sh" > "${SB}/${tool}/fetch_secret.sh"
  chmod +x "${SB}/configure_${tool}.sh" "${SB}/${tool}/fetch_secret.sh"
done
cp "${ROLES}/mero-kms/files/vector-partial-kms.yaml" "${SB}/vector/vector_partial.yaml"
cp "${ROLES}/mero-kms/files/vmagent-scrape-config.yml" "${SB}/vmagent/scrape_config.yml"
printf 'locked-read-only\n' > "${SB}/mero-kms/image-profile"
printf '#!/usr/bin/env bash\nexit 0\n' > "${SB}/bin/systemctl"
printf '#!/usr/bin/env bash\necho replica-r0\n' > "${SB}/bin/hostname"
chmod +x "${SB}/bin/"*
export PATH="${SB}/bin:${PATH}"

vector() { "${SB}/configure_vector.sh" "${SB}/vector/vector_partial.yaml" "$@" >"${SB}/out" 2>&1; }
vmagent() { "${SB}/configure_vmagent.sh" "${SB}/vmagent/scrape_config.yml" "$@" >"${SB}/out" 2>&1; }

NL=$'\n'
BAD_URLS=(
  "https://victoria.test/api/v1/write${NL}ExecStartPost=/bin/sh -c id"
  'https://victoria.test/insert"injected: true'
  "https://victoria.test/a b"
  "file:///etc/shadow"
)
for url in "${BAD_URLS[@]}"; do
  rm -f "${SB}/vector/vector.yaml" "${SB}/systemd/vmagent.service"
  vector "$url" false provided "" && fail "configure_vector.sh accepted URL: $(printf %q "$url")"
  [[ -e "${SB}/vector/vector.yaml" ]] && fail "configure_vector.sh wrote a config for a refused URL"
  vmagent "$url" false provided "" && fail "configure_vmagent.sh accepted URL: $(printf %q "$url")"
  [[ -e "${SB}/systemd/vmagent.service" ]] && fail "configure_vmagent.sh wrote a unit for a refused URL"
done

# A token pasted into vector's YAML header must be a plain token.
printf 'abc"\n        injected: "x' > "${SB}/vector/provided_token"
rm -f "${SB}/vector/vector.yaml"
vector "https://victoria.test/insert/elasticsearch" true provided "${SB}/vector/provided_token" \
  && fail "configure_vector.sh accepted a token with a quote and a newline"
[[ -e "${SB}/vector/vector.yaml" ]] && fail "configure_vector.sh wrote a config for a refused token"

# The good path still works, with the KMS image's labels and an owner-only config.
printf 'tok.EN-123_~+/=' > "${SB}/vector/provided_token"
export OBS_PROFILE_FILE="${SB}/mero-kms/image-profile" OBS_INSTANCE_TYPE=mero-kms VMAGENT_HTTP_LISTEN=127.0.0.1:8429
vector "https://victoria.test/insert/elasticsearch" true provided "${SB}/vector/provided_token" \
  || { cat "${SB}/out" >&2; fail "configure_vector.sh refused a valid URL and token"; }
grep -q 'Authorization: "Bearer tok.EN-123_~+/="' "${SB}/vector/vector.yaml" || fail "the token was not written"
grep -q '\.instance_profile = "locked-read-only"' "${SB}/vector/vector.yaml" \
  || fail "the KMS profile was not read from OBS_PROFILE_FILE"
grep -q '\.instance_name = "mero-kms"' "${SB}/vector/vector.yaml" || fail "KMS logs are not labelled mero-kms"
[[ "$(stat -c %a "${SB}/vector/vector.yaml")" == "600" ]] || fail "vector.yaml (it holds the token) is not 0600"

vmagent "https://victoria.test/api/v1/write" true provided "${SB}/vector/provided_token" \
  || { cat "${SB}/out" >&2; fail "configure_vmagent.sh refused a valid URL"; }
grep -q 'instance_type=mero-kms' "${SB}/systemd/vmagent.service" || fail "KMS metrics are not labelled mero-kms"
grep -q 'instance_profile=locked-read-only' "${SB}/systemd/vmagent.service" || fail "KMS metrics carry the wrong profile"
grep -q -- '-httpListenAddr=127.0.0.1:8429' "${SB}/systemd/vmagent.service" || fail "vmagent does not listen on loopback"

echo "PASS: shipper configs refuse injected URLs and tokens; KMS labels and loopback hold"
