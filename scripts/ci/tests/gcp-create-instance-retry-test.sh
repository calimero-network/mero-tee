#!/usr/bin/env bash
# The release probe VMs are created through gcp_create_instance
# (scripts/ci/gcp_create_instance.sh), which retries GCP's transient failures.
#
# Release run 39287102050 failed on one "Internal error" from
# `gcloud compute instances create`. The helper must retry that, must not
# retry an error that fails the same way every time, and must delete an
# instance a failed create left behind before it tries again under the same
# name.
#
# A stub `gcloud` on PATH plays GCP: each `instances create` takes the next
# scripted outcome, `describe` answers from a "the instance exists" flag, and
# every call is logged.
#
# Usage: scripts/ci/tests/gcp-create-instance-retry-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "${SB}/bin"
cat >"${SB}/bin/gcloud" <<'STUB'
#!/usr/bin/env bash
# Outcomes in $STUB_DIR/outcomes, one per line: "ok", "leftover:<error>"
# (fails but leaves the instance), or "<error>".
echo "$*" >>"${STUB_DIR}/calls"
case "$3" in
  create)
    outcome="$(head -1 "${STUB_DIR}/outcomes")"
    sed -i 1d "${STUB_DIR}/outcomes"
    if [[ "${outcome}" == "ok" ]]; then
      touch "${STUB_DIR}/exists"
      echo "Created [$4]." >&2
      exit 0
    fi
    if [[ "${outcome}" == leftover:* ]]; then
      touch "${STUB_DIR}/exists"
      outcome="${outcome#leftover:}"
    fi
    printf 'ERROR: (gcloud.compute.instances.create) %b\n' "${outcome}" >&2
    exit 1
    ;;
  describe)
    [[ -e "${STUB_DIR}/exists" ]] && { echo "$4"; exit 0; }
    echo "ERROR: The resource '$4' was not found" >&2
    exit 1
    ;;
  delete)
    [[ -e "${STUB_DIR}/undeletable" ]] && { echo "ERROR: delete failed" >&2; exit 1; }
    rm -f "${STUB_DIR}/exists"
    exit 0
    ;;
esac
exit 2
STUB
chmod +x "${SB}/bin/gcloud"

# One outcome per line; a literal \n in one is a line break in the error.
INTERNAL="Could not fetch resource:\\n - Internal error. Please try again or contact Google Support. (Code: '-5584569536554511605')"

# Run gcp_create_instance against scripted outcomes; leaves the exit code in
# ${RC} and the gcloud calls in ${SB}/run/calls.
run() {
  rm -rf "${SB}/run"
  mkdir -p "${SB}/run"
  printf '%s\n' "$@" >"${SB}/run/outcomes"
  [[ -z "${UNDELETABLE:-}" ]] || touch "${SB}/run/undeletable"
  set +e
  (
    PATH="${SB}/bin:${PATH}" STUB_DIR="${SB}/run" GCP_CREATE_RETRY_DELAY=0 \
      bash -euo pipefail -c "source '${REPO_ROOT}/scripts/ci/gcp_create_instance.sh'
        gcp_create_instance vm-1 proj zone-a --machine-type c3-standard-4"
  ) >"${SB}/run/out" 2>&1
  RC=$?
  set -e
}

count() { grep -c "^compute instances $1 " "${SB}/run/calls" || true; }

expect() { # label want-rc want-creates want-deletes
  [[ "${RC}" == "$2" ]] || { cat "${SB}/run/out" >&2; fail "$1: exit ${RC}, want $2"; }
  [[ "$(count create)" == "$3" ]] || fail "$1: $(count create) creates, want $3"
  [[ "$(count delete)" == "$4" ]] || fail "$1: $(count delete) deletes, want $4"
  echo "ok   $1"
}

# The flags reach gcloud unchanged.
run ok
expect "first attempt succeeds" 0 1 0
grep -qx "compute instances create vm-1 --project proj --zone zone-a --machine-type c3-standard-4" \
  "${SB}/run/calls" || fail "create was not called with the caller's flags"

# The error that failed run 39287102050 is retried.
run "${INTERNAL}" ok
expect "Internal error is retried" 0 2 0
grep -q "transient GCP error (attempt 1/3)" "${SB}/run/out" || fail "the retry was not logged"

for transient in \
  "Could not fetch resource: - backendError" \
  "HTTPError 503: Service Unavailable" \
  "Could not fetch resource: - Rate Limit Exceeded" \
  "The zone 'projects/p/zones/z' does not have enough resources available to fulfill the request. '(resource type:compute)'. ZONE_RESOURCE_POOL_EXHAUSTED"; do
  run "${transient}" ok
  expect "retried: ${transient:0:48}" 0 2 0
done

# Bounded: three transient failures fail the create.
run "${INTERNAL}" "${INTERNAL}" "${INTERNAL}" ok
expect "gives up after 3 attempts" 1 3 0
grep -q "on all 3 attempts" "${SB}/run/out" || fail "the final failure was not logged"

# Deterministic errors fail on the first attempt.
for permanent in \
  "argument --machine-type: unrecognized arguments: --bogus" \
  "Could not fetch resource: - Required 'compute.instances.create' permission for 'projects/p'" \
  "Could not fetch resource: - Quota 'CPUS' exceeded.  Limit: 24.0 in region europe-west4." \
  "Could not fetch resource: - The resource 'projects/p/zones/z/instances/vm-1' already exists" \
  "Could not fetch resource: - The resource 'projects/p/global/images/nope' was not found" \
  "something nobody has seen before"; do
  run "${permanent}" ok
  expect "not retried: ${permanent:0:48}" 1 1 0
done

# A failed create that left the instance behind: delete it, then retry under
# the same name.
run "leftover:${INTERNAL}" ok
expect "leftover instance is deleted before the retry" 0 2 1
grep -qx "compute instances delete vm-1 --project proj --zone zone-a --delete-disks=all --quiet" \
  "${SB}/run/calls" || fail "the leftover was not deleted with its disks"
[[ "$(grep -n 'instances delete' "${SB}/run/calls" | cut -d: -f1)" -lt \
   "$(grep -n 'instances create' "${SB}/run/calls" | tail -1 | cut -d: -f1)" ]] \
  || fail "the leftover was deleted after the retry, not before"

# ...and if the leftover cannot be deleted, stop instead of retrying into
# "already exists".
UNDELETABLE=1 run "leftover:${INTERNAL}" ok
expect "undeletable leftover stops the retries" 1 1 1

echo "PASS: gcp_create_instance retries only transient errors and clears leftovers"
