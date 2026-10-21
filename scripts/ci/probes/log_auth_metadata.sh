#!/usr/bin/env bash
# The two instance-metadata keys mdma gives every VM that ships logs, for the
# KMS and agent image probes (run-cluster-probe.sh, run-agent-probe.sh) when
# they run the log-auth check (node_log_auth_probe.sh, release-kms.yaml).
#
# Source this file, then:
#
#   metadata+="$(log_auth_metadata)"
#
# With LOGS_ENDPOINT and OBSERVABILITY_TOKEN_FILE both set, prints
# `,logs-endpoint=<LOGS_ENDPOINT>,observability-token=<token in the file>`;
# with neither, prints nothing, so the VM's metadata stays exactly what it was.
# One without the other, or a value that would split gcloud's `--metadata`
# (a comma or `=` in the token, anything but a plain URL), fails instead.
#
# Neither key is measured: kms-init and agent-init read them after extending
# RTMR3, whose event names only the role, the profile and the root hash.

log_auth_metadata() {
  local endpoint="${LOGS_ENDPOINT:-}" token_file="${OBSERVABILITY_TOKEN_FILE:-}" token
  if [[ -z "${endpoint}" && -z "${token_file}" ]]; then
    return 0
  fi
  if [[ -z "${endpoint}" || -z "${token_file}" ]]; then
    echo "::error::LOGS_ENDPOINT and OBSERVABILITY_TOKEN_FILE are set together or not at all" >&2
    return 1
  fi
  if [[ ! "${endpoint}" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]]; then
    echo "::error::LOGS_ENDPOINT '${endpoint}' is not a plain http(s) URL" >&2
    return 1
  fi
  if ! token="$(cat "${token_file}" 2>/dev/null)"; then
    echo "::error::cannot read OBSERVABILITY_TOKEN_FILE ${token_file}" >&2
    return 1
  fi
  if [[ ! "${token}" =~ ^[A-Za-z0-9._~+/-]{1,4096}$ ]]; then
    echo "::error::the token in ${token_file} has characters gcloud's --metadata or a bearer token cannot carry" >&2
    return 1
  fi
  printf ',logs-endpoint=%s,observability-token=%s' "${endpoint}" "${token}"
}
