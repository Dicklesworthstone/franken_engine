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
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
RUSTFLAGS="${RUSTFLAGS:--C linker=cc}"
RCH_TIMEOUT_SECONDS="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
EXPECTED_RCH_WORKER="${FRANKEN_ENGINE_LIB_UNIT_EXPECTED_WORKER:-${RCH_WORKER:-}}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_lib_unit_smoke_${timestamp}}"
artifact_root="${FRANKEN_ENGINE_LIB_UNIT_SMOKE_ARTIFACT_ROOT:-artifacts/rch_engine_lib_unit_smoke}"
run_dir="${artifact_root}/${timestamp}"
log_path="${run_dir}/cargo-output.log"
commands_path="${run_dir}/commands.txt"

usage() {
  cat <<'USAGE'
usage: scripts/rch_engine_lib_unit_smoke_gate.sh [run|run-execute|--scan-log <path>|--scan-execution-log <path>|--check-script <path>|--print-command]

Runs a source-local frankenengine-engine library unit-test compile through rch
and fails closed if frankenengine-test-support appears in the lib-unit compile
path. `run-execute` runs the filtered unit test and fails closed unless the log
shows Rust test execution. When an expected worker is configured, the gate first
checks `rch diagnose` so worker-selection drift fails before a long compile.
The default mode is compile-only run.

Environment:
  FRANKEN_ENGINE_LIB_UNIT_PACKAGE       package to validate (default: frankenengine-engine)
  FRANKEN_ENGINE_LIB_UNIT_TEST_FILTER   source-local unit test filter
  FRANKEN_ENGINE_LIB_UNIT_EXPECTED_WORKER
                                      fail closed if RCH selects a different worker
                                      (defaults to RCH_WORKER when set)
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

strip_ansi() {
  perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$1"
}

command_text() {
  local mode="${1:-compile}"
  if [[ "$mode" == "execute" ]]; then
    printf 'rch exec -- env RUSTUP_TOOLCHAIN=%s CARGO_INCREMENTAL=%s CARGO_BUILD_JOBS=%s CARGO_TARGET_DIR=%s RUSTFLAGS=%q cargo test -p %s --%s %s -- --nocapture\n' \
      "$RUSTUP_TOOLCHAIN" \
      "$CARGO_INCREMENTAL" \
      "$CARGO_BUILD_JOBS" \
      "$CARGO_TARGET_DIR" \
      "$RUSTFLAGS" \
      "$PACKAGE" \
      "$TARGET_KIND" \
      "$TEST_FILTER"
    return 0
  fi

  printf 'rch exec -- env RUSTUP_TOOLCHAIN=%s CARGO_INCREMENTAL=%s CARGO_BUILD_JOBS=%s CARGO_TARGET_DIR=%s RUSTFLAGS=%q cargo test -p %s --%s %s --no-run\n' \
    "$RUSTUP_TOOLCHAIN" \
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

  if [[ -n "$EXPECTED_RCH_WORKER" ]]; then
    local selected_worker
    selected_worker="$(strip_ansi "$candidate_log" | sed -n 's/.*Selected worker: \([^ ]*\).*/\1/p' | tail -n1 || true)"
    if [[ -z "$selected_worker" ]]; then
      fail "expected_worker_not_observed expected_worker=${EXPECTED_RCH_WORKER} log=${candidate_log}"
    fi
    if [[ "$selected_worker" != "$EXPECTED_RCH_WORKER" ]]; then
      fail "unexpected_worker_selected expected_worker=${EXPECTED_RCH_WORKER} selected_worker=${selected_worker} log=${candidate_log}"
    fi
    log "expected_worker=observed worker=${selected_worker} log=${candidate_log}"
  fi

  if grep -Eiq '(^|[[:space:]])(Compiling|Checking|Fresh|Dirty)[[:space:]]+frankenengine-test-support([[:space:]]|$)' "$candidate_log"; then
    fail "forbidden_support_dependency package=${PACKAGE} target_kind=${TARGET_KIND} log=${candidate_log}"
  fi

  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$candidate_log"; then
    fail "rch_local_fallback_detected log=${candidate_log}"
  fi

  log "support_dependency=absent package=${PACKAGE} target_kind=${TARGET_KIND} log=${candidate_log}"
}

scan_log_for_test_execution() {
  local candidate_log="$1"
  [[ -f "$candidate_log" ]] || fail "log_not_found path=${candidate_log}"

  if ! grep -Eq '(^|[[:space:]])running[[:space:]]+[1-9][0-9]*[[:space:]]+tests?($|[[:space:]])' "$candidate_log"; then
    fail "test_execution_not_observed package=${PACKAGE} target_kind=${TARGET_KIND} log=${candidate_log}"
  fi

  if ! grep -Eq '(^|[[:space:]])test[[:space:]]+result:[[:space:]]+ok\.' "$candidate_log"; then
    fail "test_success_not_observed package=${PACKAGE} target_kind=${TARGET_KIND} log=${candidate_log}"
  fi

  log "test_execution=observed package=${PACKAGE} target_kind=${TARGET_KIND} log=${candidate_log}"
}

preflight_expected_worker() {
  local mode="$1"
  [[ -n "$EXPECTED_RCH_WORKER" ]] || return 0

  command -v jq >/dev/null 2>&1 || fail "jq_not_found_for_expected_worker_preflight"

  local diagnose_path="${run_dir}/worker-diagnose.json"
  local diagnose_stderr_path="${run_dir}/worker-diagnose.stderr"
  log "expected_worker_preflight=checking expected_worker=${EXPECTED_RCH_WORKER} diagnose=${diagnose_path}"

  local -a diagnose_command=(
    "$RCH_BIN" diagnose --json -- env \
      "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN}" \
      "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" \
      "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
      "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
      "RUSTFLAGS=${RUSTFLAGS}" \
      cargo test -p "$PACKAGE" "--${TARGET_KIND}" "$TEST_FILTER" # rch-cargo-allow: diagnose preflight classifies only; Cargo is not executed here.
  )

  if [[ "$mode" == "compile" ]]; then
    diagnose_command+=(--no-run)
  elif [[ "$mode" == "execute" ]]; then
    diagnose_command+=(-- --nocapture)
  else
    fail "unsupported_mode mode=${mode}"
  fi

  set +e
  "${diagnose_command[@]}" >"$diagnose_path" 2>"$diagnose_stderr_path"
  local diagnose_status=$?
  set -e

  if [[ "$diagnose_status" -ne 0 ]]; then
    fail "expected_worker_preflight_diagnose_failed status=${diagnose_status} expected_worker=${EXPECTED_RCH_WORKER} diagnose=${diagnose_path} stderr=${diagnose_stderr_path}"
  fi

  local selected_worker
  selected_worker="$(jq -r '.data.worker_selection.worker.id // ""' "$diagnose_path")"
  if [[ -z "$selected_worker" ]]; then
    local reason
    reason="$(jq -r '.data.worker_selection.reason // "unknown"' "$diagnose_path")"
    fail "expected_worker_preflight_not_observed expected_worker=${EXPECTED_RCH_WORKER} reason=${reason} diagnose=${diagnose_path}"
  fi

  if [[ "$selected_worker" != "$EXPECTED_RCH_WORKER" ]]; then
    fail "expected_worker_preflight_mismatch expected_worker=${EXPECTED_RCH_WORKER} selected_worker=${selected_worker} diagnose=${diagnose_path}"
  fi

  log "expected_worker_preflight=observed worker=${selected_worker} diagnose=${diagnose_path}"
}

run_gate() {
  local mode="${1:-compile}"
  [[ "$TARGET_KIND" == "lib" ]] || fail "unsupported_target_kind target_kind=${TARGET_KIND}"
  command -v "$RCH_BIN" >/dev/null 2>&1 || fail "rch_not_found binary=${RCH_BIN}"
  check_script_wrapping "$script_path"

  mkdir -p "$run_dir"
  command_text "$mode" >"$commands_path"

  log "selected_package=${PACKAGE}"
  log "target_kind=${TARGET_KIND}"
  log "test_filter=${TEST_FILTER}"
  log "mode=${mode}"
  log "command=$(command_text "$mode")"
  log "log_path=${log_path}"
  preflight_expected_worker "$mode"

  local -a command=(
    "$RCH_BIN" exec -- env \
      "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN}" \
      "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" \
      "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
      "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
      "RUSTFLAGS=${RUSTFLAGS}" \
      cargo test -p "$PACKAGE" "--${TARGET_KIND}" "$TEST_FILTER"
  )

  if [[ "$mode" == "compile" ]]; then
    command+=(--no-run)
  elif [[ "$mode" == "execute" ]]; then
    command+=(-- --nocapture)
  else
    fail "unsupported_mode mode=${mode}"
  fi

  set +e
  timeout "$RCH_TIMEOUT_SECONDS" "${command[@]}" >"$log_path" 2>&1
  local exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    scan_log_for_forbidden_support "$log_path"
    if [[ "$mode" == "execute" ]]; then
      scan_log_for_test_execution "$log_path"
    fi
    log "result=pass"
    return 0
  fi

  scan_log_for_forbidden_support "$log_path" || true
  log "result=fail exit_code=${exit_code} log=${log_path}"
  return "$exit_code"
}

mode="${1:-run}"
case "$mode" in
  run)
    run_gate compile
    ;;
  run-execute)
    run_gate execute
    ;;
  --scan-log)
    [[ $# -eq 2 ]] || fail "--scan-log requires a path"
    scan_log_for_forbidden_support "$2"
    ;;
  --scan-execution-log)
    [[ $# -eq 2 ]] || fail "--scan-execution-log requires a path"
    scan_log_for_forbidden_support "$2"
    scan_log_for_test_execution "$2"
    ;;
  --check-script)
    [[ $# -eq 2 ]] || fail "--check-script requires a path"
    check_script_wrapping "$2"
    log "script_wrapping=pass path=$2"
    ;;
  --print-command)
    command_text compile
    ;;
  --print-execute-command)
    command_text execute
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
