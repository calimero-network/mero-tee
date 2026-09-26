#!/usr/bin/env bash
# fetch_secret.sh's `gcp` provider must fetch a secret with no cloud CLI.
#
# It used to shell out to `gcloud`, which GCP Ubuntu images ship as a snap.
# locked-read-only masks snapd, so on production nodes the provider failed --
# `gcloud: command not found` or a confinement error -- and vector/vmagent came
# up with no credential while debug images worked fine (mero-tee#339). It now
# talks to the metadata server and Secret Manager's REST API with curl.
#
# Behavioural: both installed copies (vector's and vmagent's) run against a stub
# `curl` that plays the metadata server and Secret Manager, with `gcloud` and
# `aws` on PATH as tripwires that fail the test if anything calls them. It
# checks the exact bytes printed, the resource URL built from each accepted
# secret-name form, that the access token travels in a header on stdin rather
# than in curl's argv, and that a node with no service account fails loudly.
#
# Usage: scripts/ci/tests/fetch-secret-rest-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
mkdir -p "${SB}/bin"

fail() { echo "FAIL: $*" >&2; exit 1; }

ACCESS_TOKEN="ya29.stub-access-token"
# Bytes a naive decode would mangle: no trailing newline, embedded spaces.
SECRET_VALUE='bearer value with spaces'
SECRET_B64="$(printf '%s' "$SECRET_VALUE" | base64 -w0)"

# The stub records argv and stdin of every call, then answers by URL. The
# `NO_SA` switch makes the token endpoint 404, as it does on an instance with
# no service account.
cat > "${SB}/bin/curl" <<STUB
#!/usr/bin/env bash
set -euo pipefail
url="\${!#}"
{ printf 'ARGV'; printf ' %q' "\$@"; printf '\n'; } >> "${SB}/curl.log"
stdin=""
for a in "\$@"; do [[ "\$a" == "@-" ]] && stdin="\$(cat)"; done
printf 'STDIN %s\n' "\$stdin" >> "${SB}/curl.log"
case "\$url" in
  */instance/service-accounts/default/token)
    [[ -z "\${NO_SA:-}" ]] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
    printf '{"access_token":"${ACCESS_TOKEN}","expires_in":3599,"token_type":"Bearer"}' ;;
  */project/project-id)
    printf 'stub-project' ;;
  https://secretmanager.googleapis.com/v1/*/versions/latest:access)
    [[ "\$stdin" == "Authorization: Bearer ${ACCESS_TOKEN}" ]] || { echo "curl: (22) 401" >&2; exit 22; }
    printf '{"name":"x","payload":{"data":"${SECRET_B64}"}}' ;;
  *)
    echo "stub curl: unexpected URL \$url" >&2; exit 99 ;;
esac
STUB
for cli in gcloud aws; do
  cat > "${SB}/bin/${cli}" <<STUB
#!/usr/bin/env bash
echo "${cli} was called; the image cannot run it with snapd masked" >> "${SB}/tripwire"
exit 127
STUB
done
chmod +x "${SB}/bin/"*

PATH="${SB}/bin:${PATH}"
export PATH

for role in vector vmagent; do
  script="${REPO_ROOT}/mero-tee/ansible/roles/${role}/files/fetch_secret.sh"
  [[ -r "$script" ]] || fail "cannot read ${script}"

  for form in "obs-token:projects/stub-project/secrets/obs-token" \
              "projects/other/secrets/obs-token:projects/other/secrets/obs-token"; do
    name="${form%%:*}"
    want_resource="${form#*:}"
    rm -f "${SB}/curl.log" "${SB}/tripwire"

    rc=0
    bash "$script" gcp "$name" > "${SB}/out" 2> "${SB}/err" || rc=$?
    # The tripwire first: it is the reason a CLI-based provider exits non-zero.
    [[ ! -e "${SB}/tripwire" ]] || fail "${role}: $(cat "${SB}/tripwire")"
    [[ "$rc" -eq 0 ]] || fail "${role}: gcp '${name}' exited ${rc}: $(cat "${SB}/err")"

    # Byte-exact: `cmp` against the value, not a `$(...)` that strips newlines.
    printf '%s' "$SECRET_VALUE" | cmp -s - "${SB}/out" \
      || fail "${role}: gcp '${name}' printed $(od -c "${SB}/out" | head -3), want '${SECRET_VALUE}' with no newline"

    grep -q "secretmanager.googleapis.com/v1/${want_resource}/versions/latest:access" "${SB}/curl.log" \
      || fail "${role}: gcp '${name}' did not request ${want_resource}:
$(cat "${SB}/curl.log")"

    if grep '^ARGV' "${SB}/curl.log" | grep -q -- "$ACCESS_TOKEN"; then
      fail "${role}: the access token is in curl's argv, where \`ps\` shows it:
$(grep '^ARGV' "${SB}/curl.log")"
    fi
    echo "ok   ${role}: gcp '${name}' -> ${want_resource}, exact bytes, token off argv"
  done

  # No service account: must fail, say why, and print nothing a caller would
  # write to the bearer-token file as if it were a credential.
  rm -f "${SB}/tripwire"
  if NO_SA=1 bash "$script" gcp obs-token > "${SB}/out" 2> "${SB}/err"; then
    fail "${role}: gcp succeeded with no service account"
  fi
  [[ ! -s "${SB}/out" ]] || fail "${role}: printed '$(cat "${SB}/out")' on failure"
  grep -q "service account" "${SB}/err" \
    || fail "${role}: no-service-account failure does not say so: $(cat "${SB}/err")"
  [[ ! -e "${SB}/tripwire" ]] || fail "${role}: $(cat "${SB}/tripwire")"
  echo "ok   ${role}: no service account fails loudly with empty output"
done

echo "== fetch_secret.sh gcp fetches over REST, no cloud CLI =="
