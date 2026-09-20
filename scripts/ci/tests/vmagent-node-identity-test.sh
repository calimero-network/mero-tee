#!/usr/bin/env bash
# Every sample a node ships must say which node it came from.
#
# The scrape config targets `localhost:9100`, so without identifying labels
# every node in the fleet produces the identical series identity
# `{instance="localhost:9100", job="node_exporter"}`. Two nodes and their
# samples interleave into ONE series: a counter that appears to reset, a gauge
# that flips between machines. That reads as plausible data and is wrong, which
# is worse than having no metrics at all -- and with a single node in the fleet
# it is invisible, so it only starts corrupting queries once a second one
# exists.
#
# Behavioural, not static: it runs the real `configure_vmagent.sh` against a
# sandbox and reads the systemd unit it generates, because what matters is the
# flags vmagent is actually started with.
#
# Usage: scripts/ci/tests/vmagent-node-identity-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="${REPO_ROOT}/mero-tee/ansible/roles/vmagent/files/configure_vmagent.sh"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
mkdir -p "${SB}/bin" "${SB}/vmagent" "${SB}/systemd"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$SRC" ]] || fail "cannot read ${SRC}"

# Redirect the two absolute paths the script writes to, then stub the commands
# that would touch the host.
sed -e "s@/etc/systemd/system@${SB}/systemd@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "$SRC" > "${SB}/configure.sh"
chmod +x "${SB}/configure.sh"

cat > "${SB}/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "${SB}/bin/hostname" <<'STUB'
#!/usr/bin/env bash
echo "node-testid.europe-west4-a.c.example.internal"
STUB
cat > "${SB}/vmagent/fetch_secret.sh" <<'STUB'
#!/usr/bin/env bash
echo "a-bearer-token"
STUB
chmod +x "${SB}/bin/systemctl" "${SB}/bin/hostname" "${SB}/vmagent/fetch_secret.sh"
printf 'scrape_configs: []\n' > "${SB}/vmagent/scrape_config.yml"

PATH="${SB}/bin:${PATH}"
export PATH

"${SB}/configure.sh" "${SB}/vmagent/scrape_config.yml" \
  "https://victoria-lb.test/api/v1/write" true provided "${SB}/vmagent/token" \
  >"${SB}/out" 2>&1 || { cat "${SB}/out" >&2; fail "configure_vmagent.sh exited non-zero"; }

unit="${SB}/systemd/vmagent.service"
[[ -s "$unit" ]] || fail "no systemd unit was generated"

grep -q -- '-remoteWrite.label=instance_name=node-testid.europe-west4-a.c.example.internal' "$unit" \
  || fail "the unit carries no instance_name label, so every node's samples land in one
       series and interleave:
$(grep ExecStart -A4 "$unit")"

grep -q -- '-remoteWrite.label=instance_type=merotee' "$unit" \
  || fail "the unit carries no instance_type label"

# The credential must still be wired -- the labels are appended to the same line.
grep -q -- '-remoteWrite.bearerTokenFile=' "$unit" \
  || fail "the bearer token flag was lost when the labels were added"

# And the endpoint.
grep -q -- '-remoteWrite.url=https://victoria-lb.test/api/v1/write' "$unit" \
  || fail "the remote write URL is wrong or missing"

# Unauthenticated deployments must still get labels.
rm -f "$unit"
"${SB}/configure.sh" "${SB}/vmagent/scrape_config.yml" \
  "https://victoria-lb.test/api/v1/write" false gcp "" >"${SB}/out2" 2>&1 \
  || { cat "${SB}/out2" >&2; fail "configure_vmagent.sh failed with auth disabled"; }
grep -q -- '-remoteWrite.label=instance_name=' "$unit" \
  || fail "labels are missing when auth is disabled; identity does not depend on the credential"

echo "PASS: vmagent is started with instance_name and instance_type labels"
