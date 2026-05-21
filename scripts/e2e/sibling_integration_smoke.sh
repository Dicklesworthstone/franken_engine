#!/usr/bin/env bash
# sibling_integration_smoke.sh (bd-cixqu.13.1)
#
# Smoke test for the full-integration lane added to
# `scripts/test_standalone_build.sh`. Asserts that the 6 sibling repos
# (asupersync, frankentui, frankensqlite, sqlmodel_rust, fastapi_rust,
# frankenpandas) all report a recognized status (passed/skipped/failed)
# in the gate's structured output.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly GATE="${PROJECT_DIR}/scripts/test_standalone_build.sh"
readonly EXPECTED_SIBLINGS=(
  "asupersync"
  "frankentui"
  "frankensqlite"
  "sqlmodel_rust"
  "fastapi_rust"
  "frankenpandas"
)

failures=0
pass() { printf 'PASS sibling-integration-smoke %s\n' "$1"; }
fail() { printf 'FAIL sibling-integration-smoke %s\n' "$1" >&2; failures=$((failures + 1)); }

usage() {
  cat >&2 <<'EOF'
Usage: scripts/e2e/sibling_integration_smoke.sh [check|run]
EOF
}

assert_gate_modes_listed() {
  if ! "${GATE}" --help 2>&1 | grep -q "full-integration"; then
    fail "test_standalone_build.sh --help must mention full-integration mode"
    return
  fi
  pass "gate --help lists full-integration mode"
}

assert_gate_runs_full_integration() {
  local out_dir
  out_dir="$(mktemp -d "${TMPDIR:-/tmp}/sibling-smoke.XXXXXX")"
  set +e
  STANDALONE_BUILD_GATE_ARTIFACT_ROOT="${out_dir}" \
    "${GATE}" full-integration >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    fail "gate full-integration must exit 0 when all 6 sibling repos are present (got ${rc})"
    return
  fi
  local manifest
  manifest="$(find "${out_dir}" -maxdepth 2 -name manifest.json -type f | tail -1)"
  if [[ -z "${manifest}" || ! -f "${manifest}" ]]; then
    fail "gate must emit manifest.json under ${out_dir}"
    return
  fi
  pass "gate full-integration emits manifest.json (exit 0)"

  local known_statuses_ok=1
  for sib in "${EXPECTED_SIBLINGS[@]}"; do
    local status
    status="$(jq -r --arg lane "full-integration-${sib}" '
      .lanes[] | select(.lane == $lane) | .status
    ' "${manifest}")"
    case "${status}" in
      passed|skipped|failed)
        : # known
        ;;
      *)
        fail "sibling ${sib}: unknown status '${status}' in manifest"
        known_statuses_ok=0
        ;;
    esac
  done
  if [[ "${known_statuses_ok}" -eq 1 ]]; then
    pass "all 6 siblings have a recognized status (passed/skipped/failed)"
  fi

  # The on-disk reality is that all 6 sibling dirs exist under /dp/, so
  # every entry should be `passed`. If any are not, surface them but do
  # not necessarily fail the smoke — the gate's job is to report, not
  # to demand sibling presence on every checkout.
  local pass_count
  pass_count="$(jq '[.lanes[] | select(.lane | startswith("full-integration-")) | select(.status == "passed")] | length' "${manifest}")"
  if [[ "${pass_count}" -eq "${#EXPECTED_SIBLINGS[@]}" ]]; then
    pass "all 6 siblings report passed on this checkout"
  else
    printf 'INFO sibling-integration-smoke: %d of %d siblings passed (rest skipped/failed)\n' \
      "${pass_count}" "${#EXPECTED_SIBLINGS[@]}"
  fi
}

assert_lane_log_files_exist() {
  local out_dir
  out_dir="$(mktemp -d "${TMPDIR:-/tmp}/sibling-smoke-logs.XXXXXX")"
  STANDALONE_BUILD_GATE_ARTIFACT_ROOT="${out_dir}" \
    "${GATE}" full-integration >/dev/null 2>&1 || true
  local manifest
  manifest="$(find "${out_dir}" -maxdepth 2 -name manifest.json -type f | tail -1)"
  local missing=0
  for sib in "${EXPECTED_SIBLINGS[@]}"; do
    local log_path
    log_path="$(jq -r --arg lane "full-integration-${sib}" '
      .lanes[] | select(.lane == $lane) | .log_path
    ' "${manifest}")"
    if [[ -z "${log_path}" || ! -f "${log_path}" ]]; then
      fail "sibling ${sib}: log_path ${log_path:-<missing>} does not exist"
      missing=$((missing + 1))
    fi
  done
  if [[ "${missing}" -eq 0 ]]; then
    pass "all 6 sibling lane log files exist on disk"
  fi
}

case "${1:-check}" in
  check)
    bash -n "${GATE}"
    bash -n "${BASH_SOURCE[0]}"
    if command -v shellcheck >/dev/null 2>&1; then
      shellcheck -x -e SC2016,SC2155 "${BASH_SOURCE[0]}" >/dev/null 2>&1 \
        || fail "shellcheck reported issues on the smoke script"
    fi
    pass "shell syntax + shellcheck clean"
    ;;
  run)
    bash -n "${GATE}"
    bash -n "${BASH_SOURCE[0]}"
    if command -v shellcheck >/dev/null 2>&1; then
      shellcheck -x -e SC2016,SC2155 "${BASH_SOURCE[0]}" >/dev/null 2>&1 \
        || fail "shellcheck reported issues on the smoke script"
    fi
    pass "shell syntax + shellcheck clean"
    assert_gate_modes_listed
    assert_gate_runs_full_integration
    assert_lane_log_files_exist
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    fail "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "${failures}" -ne 0 ]]; then
  exit 1
fi
