#!/usr/bin/env bash
# Create a GCE instance, retrying only GCP's transient failures.
#
# Release run 39287102050 built every image and then failed because
# `gcloud compute instances create` for the debug-read-only probe VM came back,
# after 16 minutes, with "Internal error. Please try again or contact Google
# Support." One such glitch should not fail a release, so every release-path
# probe VM is created through `gcp_create_instance`.
#
# Source this file, then:
#
#   gcp_create_instance NAME PROJECT ZONE [extra `instances create` flags...]
#
# NAME, PROJECT and ZONE become `create NAME --project PROJECT --zone ZONE`.
# The instance keeps its NAME on every attempt, so whatever cleanup the caller
# already has (delete by name, sweep by prefix) still covers it.
#
# Retried: the errors GCP says to try again on -- `Internal error`,
# `internalError`, `backendError`, HTTP 500/502/503/504, rate limiting, and a
# zone out of capacity (ZONE_RESOURCE_POOL_EXHAUSTED). Not retried: anything
# else, and in particular a flag or argument gcloud rejects, a permission
# denied, an exceeded quota and a name that already exists, which fail the
# same way every time.
#
# A create that failed transiently may still have left the instance behind,
# half-made. Before each retry the helper looks for an instance of that name
# and deletes it (with its disks); if it cannot, it stops rather than retry
# into "already exists".
#
# Tunables (environment):
#   GCP_CREATE_ATTEMPTS      total attempts (default 3)
#   GCP_CREATE_RETRY_DELAY   seconds before the first retry, doubled after
#                            each (default 30)

# Deterministic failures take precedence: an error naming one of these is
# never retried, even if it also says "internal".
_GCP_CREATE_PERMANENT_RE='already exists|alreadyExists|PERMISSION_DENIED|[Pp]ermission denied|Required .* permission|QUOTA_EXCEEDED|[Qq]uota .* exceeded|unrecognized arguments|[Ii]nvalid value|INVALID_ARGUMENT|invalid argument|was not found|notFound'
_GCP_CREATE_TRANSIENT_RE='Internal error|internalError|backendError|HTTPError 50[0234]|Error 50[0234]|Code: .50[0234].|503 Service Unavailable|currently unavailable|UNAVAILABLE|rateLimitExceeded|[Rr]ate [Ll]imit [Ee]xceeded|RESOURCE_EXHAUSTED|ZONE_RESOURCE_POOL_EXHAUSTED|does not have enough resources available'

# Print "transient" or "permanent" for a gcloud error message on stdin.
gcp_create_error_class() {
  local msg
  msg="$(cat)"
  if grep -Eq "${_GCP_CREATE_PERMANENT_RE}" <<<"${msg}"; then
    echo permanent
  elif grep -Eq "${_GCP_CREATE_TRANSIENT_RE}" <<<"${msg}"; then
    echo transient
  else
    echo permanent
  fi
}

# Delete an instance a failed create left behind. Returns non-zero only when
# one is there and could not be deleted.
_gcp_create_remove_leftover() {
  local name="$1" project="$2" zone="$3"
  if ! gcloud compute instances describe "${name}" \
    --project "${project}" --zone "${zone}" --format='value(name)' >/dev/null 2>&1; then
    return 0
  fi
  echo "gcp_create_instance: ${name} was left behind by the failed create; deleting it before retrying" >&2
  gcloud compute instances delete "${name}" \
    --project "${project}" --zone "${zone}" --delete-disks=all --quiet
}

gcp_create_instance() {
  local name="$1" project="$2" zone="$3"
  shift 3
  local attempts="${GCP_CREATE_ATTEMPTS:-3}"
  local delay="${GCP_CREATE_RETRY_DELAY:-30}"
  local errfile attempt rc class
  errfile="$(mktemp)"

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if gcloud compute instances create "${name}" \
      --project "${project}" --zone "${zone}" "$@" 2>"${errfile}"; then
      cat "${errfile}" >&2
      rm -f "${errfile}"
      return 0
    else
      rc=$?
    fi
    cat "${errfile}" >&2
    class="$(gcp_create_error_class <"${errfile}")"
    if [[ "${class}" != "transient" ]]; then
      echo "::error::creating instance ${name} failed (attempt ${attempt}/${attempts}) with an error that is not transient; not retrying"
      rm -f "${errfile}"
      return "${rc}"
    fi
    if ((attempt == attempts)); then
      echo "::error::creating instance ${name} failed with a transient GCP error on all ${attempts} attempts"
      rm -f "${errfile}"
      return "${rc}"
    fi
    echo "::warning::creating instance ${name} failed with a transient GCP error (attempt ${attempt}/${attempts}): $(grep -Eo "${_GCP_CREATE_TRANSIENT_RE}" "${errfile}" | head -1); retrying in ${delay}s"
    if ! _gcp_create_remove_leftover "${name}" "${project}" "${zone}"; then
      echo "::error::could not delete the instance ${name} the failed create left behind; not retrying"
      rm -f "${errfile}"
      return "${rc}"
    fi
    sleep "${delay}"
    delay=$((delay * 2))
  done
}
