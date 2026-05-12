#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_rel="scripts/rch_engine_lib_unit_smoke_gate.sh"
script_path="${repo_root}/${script_rel}"

PACKAGE="${FRANKEN_ENGINE_LIB_UNIT_PACKAGE:-frankenengine-engine}"
TARGET_KIND="${FRANKEN_ENGINE_LIB_UNIT_TARGET_KIND:-lib}"
TEST_FILTER="${FRANKEN_ENGINE_LIB_UNIT_TEST_FILTER:-adversarial_coevolution_harness::tests::strategy_id_display_matches_inner}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
RUSTFLAGS="${RUSTFLAGS:--C linker=cc}"
RCH_TIMEOUT_SECONDS="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_lib_unit_smoke_${timestamp}}"
artifact_root="${FRANKEN_ENGINE_LIB_UNIT_SMOKE_ARTIFACT_ROOT:-artifacts/rch_engine_lib_unit_smoke}"
run_dir="${artifact_root}/${timestamp}"
log_path="${run_dir}/cargo-output.log"
commands_path="${run_dir}/commands.txt"

usage() {
  cat <<'USAGE'
usage: scripts/rch_engine_lib_unit_smoke_gate.sh [run|--scan-log <path>|--check-script <path>|--print-command]

Runs a source-local frankenengine-engine library unit-test compile through rch
and fails closed if frankenengine-test-support appears in the lib-unit compile
path. The default mode is run.

Environment:
  FRANKEN_ENGINE_LIB_UNIT_PACKAGE       package to validate (default: frankenengine-engine)
  FRANKEN_ENGINE_LIB_UNIT_TEST_FILTER   source-local unit test filter
  RCH_BIN                               rch binary (default: rch)
  RCH_EXEC_TIMEOUT_SECONDS              outer timeout seconds (default: 900)
USAGE
}

log() {
  printf '[rch-engine-lib-unit-smoke] %s\n' "$*"
}

fail() {
  log "error=$*"
  exit 1
}

command_text() {
  printf 'rch exec -- env CARGO_INCREMENTAL=%s CARGO_BUILD_JOBS=%s CARGO_TARGET_DIR=%s RUSTFLAGS=%q cargo test -p %s --%s %s --no-run\n' \
    "$CARGO_INCREMENTAL" \
    "$CARGO_BUILD_JOBS" \
    "$CARGO_TARGET_DIR" \
    "$RUSTFLAGS" \
    "$PACKAGE" \
    "$TARGET_KIND" \
    "$TEST_FILTER"
}

check_script_wrapping() {
  local candidate="${1:-$script_path}"
  "${repo_root}/scripts/check_rch_cargo_wrapping.sh" --strict --root "$repo_root" "$candidate" >/dev/null
}

scan_log_for_forbidden_support() {
  local candidate_log="$1"
  [[ -f "$candidate_log" ]] || fail "log_not_found path=${candidate_log}"

  if grep -Eiq '(^|[[:space:]])(Compiling|Checking|Fresh|Dirty)[[:space:]]+frankenengine-test-support([[:space:]]|$)' "$candidate_log" ||
     grep -Fq '/franken-engine-test-support' "$candidate_log"; then
    fail "forbidden_support_dependency package=${PACKAGE} target_kind=${TARGET_KIND} log=${candidate_log}"
  fi

  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$candidate_log"; then
    fail "rch_local_fallback_detected log=${candidate_log}"
  fi

  log "support_dependency=absent package=${PACKAGE} target_kind=${TARGET_KIND} log=${candidate_log}"
}

run_gate() {
  [[ "$TARGET_KIND" == "lib" ]] || fail "unsupported_target_kind target_kind=${TARGET_KIND}"
  command -v "$RCH_BIN" >/dev/null 2>&1 || fail "rch_not_found binary=${RCH_BIN}"
  check_script_wrapping "$script_path"

  mkdir -p "$run_dir"
  command_text >"$commands_path"

  log "selected_package=${PACKAGE}"
  log "target_kind=${TARGET_KIND}"
  log "test_filter=${TEST_FILTER}"
  log "command=$(command_text)"
  log "log_path=${log_path}"

  local -a command=(
    "$RCH_BIN" exec -- env \
      "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" \
      "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
      "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
      "RUSTFLAGS=${RUSTFLAGS}" \
      cargo test -p "$PACKAGE" "--${TARGET_KIND}" "$TEST_FILTER" --no-run
  )

  if timeout "$RCH_TIMEOUT_SECONDS" "${command[@]}" >"$log_path" 2>&1; then
    scan_log_for_forbidden_support "$log_path"
    log "result=pass"
    return 0
  fi

  local exit_code=$?
  scan_log_for_forbidden_support "$log_path" || true
  log "result=fail exit_code=${exit_code} log=${log_path}"
  return "$exit_code"
}

mode="${1:-run}"
case "$mode" in
  run)
    run_gate
    ;;
  --scan-log)
    [[ $# -eq 2 ]] || fail "--scan-log requires a path"
    scan_log_for_forbidden_support "$2"
    ;;
  --check-script)
    [[ $# -eq 2 ]] || fail "--check-script requires a path"
    check_script_wrapping "$2"
    log "script_wrapping=pass path=$2"
    ;;
  --print-command)
    command_text
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
