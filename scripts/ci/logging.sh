#!/usr/bin/env bash

if [[ -n "${CI_LOGGING_SH_LOADED:-}" ]]; then
  return 0
fi
CI_LOGGING_SH_LOADED=1

LOG_VERBOSITY="${CI_LOG_VERBOSITY:-${LOG_VERBOSITY:-compact}}"
if [[ "${LOG_VERBOSITY}" != "compact" && "${LOG_VERBOSITY}" != "debug" ]]; then
  LOG_VERBOSITY="compact"
fi

ci_ts() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

ci_log() {
  local level="$1"
  shift
  printf "%s [%s] %s\n" "$(ci_ts)" "${level}" "$*"
}

ci_start() { ci_log "START" "$*"; }
ci_info() { ci_log "INFO" "$*"; }
ci_check() { ci_log "CHECK" "$*"; }
ci_ok() { ci_log "OK" "$*"; }
ci_next() { ci_log "NEXT" "$*"; }
ci_artifact() { ci_log "ARTIFACT" "$*"; }

ci_notice() {
  ci_info "$*"
  echo "::notice::$*"
}

ci_warn() {
  ci_log "WARN" "$*"
  echo "::warning::$*"
}

ci_fail() {
  local code="$1"
  shift
  ci_log "FAIL" "code=${code} $*"
  echo "::error::[${code}] $*"
}

ci_group_start() {
  echo "::group::$*"
}

ci_group_end() {
  echo "::endgroup::"
}

ci_log_transition() {
  local label="$1"
  local current="$2"
  local previous="$3"
  local attempt="$4"
  local interval="${5:-10}"
  if [[ "${LOG_VERBOSITY}" == "debug" || "${current}" != "${previous}" || "${attempt}" -eq 1 || $((attempt % interval)) -eq 0 ]]; then
    ci_info "${label}: ${current} (attempt ${attempt})"
  fi
}

ci_tail_bounded() {
  local file="$1"
  local lines="${2:-120}"
  if [[ -f "${file}" ]]; then
    tail -n "${lines}" "${file}" || true
  else
    echo "(missing: ${file})"
  fi
}

ci_write_artifact_index() {
  local output_file="$1"
  shift
  : > "${output_file}"
  while (($#)); do
    printf "%s\n" "$1" >> "${output_file}"
    shift
  done
  ci_artifact "saved artifact index to ${output_file}"
}

ci_result() {
  local job="$1"
  local status="$2"
  local reason="$3"
  shift 3

  local line="RESULT|job=${job}|status=${status}|reason=${reason}"
  for kv in "$@"; do
    line="${line}|${kv}"
  done
  echo "${line}"
}
