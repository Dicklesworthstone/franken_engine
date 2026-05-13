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
NATIVE_ROUTE_ADVISORY_JSON="${FRANKEN_ENGINE_LIB_UNIT_NATIVE_ROUTE_ADVISORY_JSON:-}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_lib_unit_smoke_${timestamp}}"
artifact_root="${FRANKEN_ENGINE_LIB_UNIT_SMOKE_ARTIFACT_ROOT:-artifacts/rch_engine_lib_unit_smoke}"
run_dir="${artifact_root}/${timestamp}"
log_path="${run_dir}/cargo-output.log"
commands_path="${run_dir}/commands.txt"
NATIVE_ROUTE_COMPATIBLE_WORKERS=""
NATIVE_ROUTE_REASON_CODES=""
NATIVE_ROUTE_DECISION=""
NATIVE_ROUTE_TRUTH_STATE=""
RCH_SELECTION_ENV=()

usage() {
  cat <<'USAGE'
usage: scripts/rch_engine_lib_unit_smoke_gate.sh [run|run-execute|--scan-log <path>|--scan-execution-log <path>|--check-script <path>|--print-command]

Runs a source-local frankenengine-engine library unit-test compile through rch
and fails closed if frankenengine-test-support appears in the lib-unit compile
path. `run-execute` runs the filtered unit test and fails closed unless the log
shows Rust test execution. When an expected worker is configured, the gate first
checks `rch diagnose` so worker-selection drift fails before a long compile.
Every run also rejects critically pressured selected workers before Cargo starts.
The default mode is compile-only run.

Environment:
  FRANKEN_ENGINE_LIB_UNIT_PACKAGE       package to validate (default: frankenengine-engine)
  FRANKEN_ENGINE_LIB_UNIT_TEST_FILTER   source-local unit test filter
  FRANKEN_ENGINE_LIB_UNIT_EXPECTED_WORKER
                                      fail closed if RCH selects a different worker
                                      (defaults to RCH_WORKER when set)
  FRANKEN_ENGINE_LIB_UNIT_NATIVE_ROUTE_ADVISORY_JSON
                                      prefer advisory.compatible_worker_ids and
                                      fail closed if RCH selects outside them
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
  local rch_prefix="rch"
  if [[ "${#RCH_SELECTION_ENV[@]}" -gt 0 ]]; then
    rch_prefix="${RCH_SELECTION_ENV[*]} rch"
  fi
  if [[ "$mode" == "execute" ]]; then
    printf '%s exec -- env RUSTUP_TOOLCHAIN=%s CARGO_INCREMENTAL=%s CARGO_BUILD_JOBS=%s CARGO_TARGET_DIR=%s RUSTFLAGS=%q cargo test -p %s --%s %s -- --nocapture\n' \
      "$rch_prefix" \
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

  printf '%s exec -- env RUSTUP_TOOLCHAIN=%s CARGO_INCREMENTAL=%s CARGO_BUILD_JOBS=%s CARGO_TARGET_DIR=%s RUSTFLAGS=%q cargo test -p %s --%s %s --no-run\n' \
    "$rch_prefix" \
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

prepare_rch_selection_env() {
  RCH_SELECTION_ENV=()
  NATIVE_ROUTE_COMPATIBLE_WORKERS=""
  NATIVE_ROUTE_REASON_CODES=""
  NATIVE_ROUTE_DECISION=""
  NATIVE_ROUTE_TRUTH_STATE=""

  [[ -n "$NATIVE_ROUTE_ADVISORY_JSON" ]] || return 0
  [[ -f "$NATIVE_ROUTE_ADVISORY_JSON" ]] || fail "native_route_preflight_advisory_not_found path=${NATIVE_ROUTE_ADVISORY_JSON}"
  jq empty "$NATIVE_ROUTE_ADVISORY_JSON" >/dev/null 2>&1 || fail "native_route_preflight_advisory_invalid_json path=${NATIVE_ROUTE_ADVISORY_JSON}"

  NATIVE_ROUTE_DECISION="$(jq -r '.decision // "unknown"' "$NATIVE_ROUTE_ADVISORY_JSON")"
  NATIVE_ROUTE_TRUTH_STATE="$(jq -r '.truth_state // "unknown"' "$NATIVE_ROUTE_ADVISORY_JSON")"
  NATIVE_ROUTE_COMPATIBLE_WORKERS="$(jq -r '(.compatible_worker_ids // []) | join(",")' "$NATIVE_ROUTE_ADVISORY_JSON")"
  NATIVE_ROUTE_REASON_CODES="$(jq -r '(.reason_codes // []) | join(",")' "$NATIVE_ROUTE_ADVISORY_JSON")"

  if [[ "$NATIVE_ROUTE_DECISION" != "pass" ]]; then
    fail "native_route_preflight_blocked decision=${NATIVE_ROUTE_DECISION} truth_state=${NATIVE_ROUTE_TRUTH_STATE} reason_codes=${NATIVE_ROUTE_REASON_CODES:-none} advisory=${NATIVE_ROUTE_ADVISORY_JSON}"
  fi
  if [[ -z "$NATIVE_ROUTE_COMPATIBLE_WORKERS" ]]; then
    fail "native_route_preflight_no_compatible_workers advisory=${NATIVE_ROUTE_ADVISORY_JSON}"
  fi

  if [[ -z "${RCH_WORKER:-}" && -z "${RCH_WORKERS:-}" ]]; then
    RCH_SELECTION_ENV=("RCH_WORKERS=${NATIVE_ROUTE_COMPATIBLE_WORKERS}")
  fi
}

worker_selection_context() {
  local selected_worker="$1"
  local status_path="${run_dir}/worker-status.json"
  local status_stderr_path="${run_dir}/worker-status.stderr"

  set +e
  "$RCH_BIN" --json status --workers --jobs >"$status_path" 2>"$status_stderr_path"
  local status_code=$?
  set -e

  if [[ "$status_code" -ne 0 ]]; then
    printf 'worker_status_unavailable status=%s snapshot=%s stderr=%s' "$status_code" "$status_path" "$status_stderr_path"
    return 0
  fi

  jq -r \
    --arg selected "$selected_worker" \
    --arg compatible "$NATIVE_ROUTE_COMPATIBLE_WORKERS" \
    --arg snapshot "$status_path" '
    . as $status
    |
    def worker_context($worker_id):
      ([$status.data.daemon.workers[]?
        | select(.id == $worker_id)
        | "\(.id):status=\(.status // "unknown"),slots=\(.used_slots // "?")/\(.total_slots // "?"),pressure=\(.pressure_state // "unknown"),reason=\(.pressure_reason_code // "unknown")"
      ] | first) // ($worker_id + ":missing");
    ($compatible | split(",") | map(select(. != "")) | map(worker_context(.)) | join(";")) as $compatible_context
    | "worker_status_snapshot=\($snapshot) selected_context=\(worker_context($selected)) compatible_context=\($compatible_context)"
  ' "$status_path"
}

enforce_selected_worker_pressure_guard() {
  local selected_worker="$1"
  local status_path="${run_dir}/worker-pressure-status.json"
  local status_stderr_path="${run_dir}/worker-pressure-status.stderr"

  set +e
  "$RCH_BIN" --json status --workers --jobs >"$status_path" 2>"$status_stderr_path"
  local status_code=$?
  set -e

  if [[ "$status_code" -ne 0 ]]; then
    fail "worker_pressure_preflight_status_failed status=${status_code} selected_worker=${selected_worker} snapshot=${status_path} stderr=${status_stderr_path}"
  fi
  jq empty "$status_path" >/dev/null 2>&1 || fail "worker_pressure_preflight_status_invalid_json selected_worker=${selected_worker} snapshot=${status_path}"

  if ! jq -e --arg selected "$selected_worker" '.data.daemon.workers[]? | select(.id == $selected)' "$status_path" >/dev/null; then
    fail "worker_pressure_preflight_worker_missing selected_worker=${selected_worker} snapshot=${status_path}"
  fi

  local pressure_state
  local pressure_reason
  local pressure_policy
  local pressure_disk_free_gb
  local pressure_disk_free_ratio
  local pressure_memory_pressure
  local pressure_telemetry_fresh
  pressure_state="$(jq -r --arg selected "$selected_worker" '([.data.daemon.workers[]? | select(.id == $selected) | .pressure_state // "unknown"] | first) // "unknown"' "$status_path")"
  pressure_reason="$(jq -r --arg selected "$selected_worker" '([.data.daemon.workers[]? | select(.id == $selected) | .pressure_reason_code // "unknown"] | first) // "unknown"' "$status_path")"
  pressure_policy="$(jq -r --arg selected "$selected_worker" '([.data.daemon.workers[]? | select(.id == $selected) | .pressure_policy_rule // "unknown"] | first) // "unknown"' "$status_path")"
  pressure_disk_free_gb="$(jq -r --arg selected "$selected_worker" '([.data.daemon.workers[]? | select(.id == $selected) | .pressure_disk_free_gb // "unknown"] | first) // "unknown"' "$status_path")"
  pressure_disk_free_ratio="$(jq -r --arg selected "$selected_worker" '([.data.daemon.workers[]? | select(.id == $selected) | .pressure_disk_free_ratio // "unknown"] | first) // "unknown"' "$status_path")"
  pressure_memory_pressure="$(jq -r --arg selected "$selected_worker" '([.data.daemon.workers[]? | select(.id == $selected) | .pressure_memory_pressure // "unknown"] | first) // "unknown"' "$status_path")"
  pressure_telemetry_fresh="$(jq -r --arg selected "$selected_worker" '([.data.daemon.workers[]? | select(.id == $selected) | .pressure_telemetry_fresh // "unknown"] | first) // "unknown"' "$status_path")"

  local critical_pressure
  critical_pressure="$(jq -r --arg selected "$selected_worker" '
    ([.data.daemon.workers[]? | select(.id == $selected)] | first) as $worker
    | [
        ($worker.pressure_state // ""),
        ($worker.pressure_reason_code // ""),
        ($worker.pressure_policy_rule // "")
      ]
    | map(ascii_downcase)
    | any(. == "critical" or contains("critical"))
  ' "$status_path")"

  if [[ "$critical_pressure" == "true" ]]; then
    fail "worker_pressure_preflight_critical selected_worker=${selected_worker} pressure_state=${pressure_state} pressure_reason=${pressure_reason} pressure_policy=${pressure_policy} disk_free_gb=${pressure_disk_free_gb} disk_free_ratio=${pressure_disk_free_ratio} memory_pressure=${pressure_memory_pressure} telemetry_fresh=${pressure_telemetry_fresh} snapshot=${status_path}"
  fi

  log "worker_pressure_preflight=pass selected_worker=${selected_worker} pressure_state=${pressure_state} pressure_reason=${pressure_reason} pressure_policy=${pressure_policy} disk_free_gb=${pressure_disk_free_gb} disk_free_ratio=${pressure_disk_free_ratio} memory_pressure=${pressure_memory_pressure} telemetry_fresh=${pressure_telemetry_fresh} snapshot=${status_path}"
}

preflight_worker_selection() {
  local mode="$1"

  command -v jq >/dev/null 2>&1 || fail "jq_not_found_for_worker_selection_preflight"

  local diagnose_path="${run_dir}/worker-diagnose.json"
  local diagnose_stderr_path="${run_dir}/worker-diagnose.stderr"
  log "worker_selection_preflight=checking diagnose=${diagnose_path}"
  if [[ -n "$EXPECTED_RCH_WORKER" ]]; then
    log "expected_worker_preflight=checking expected_worker=${EXPECTED_RCH_WORKER} diagnose=${diagnose_path}"
  fi
  if [[ -n "$NATIVE_ROUTE_ADVISORY_JSON" ]]; then
    log "native_route_preflight=checking advisory=${NATIVE_ROUTE_ADVISORY_JSON} diagnose=${diagnose_path}"
  fi

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
  env "${RCH_SELECTION_ENV[@]}" "${diagnose_command[@]}" >"$diagnose_path" 2>"$diagnose_stderr_path"
  local diagnose_status=$?
  set -e

  if [[ "$diagnose_status" -ne 0 ]]; then
    fail "worker_selection_preflight_diagnose_failed status=${diagnose_status} expected_worker=${EXPECTED_RCH_WORKER:-unset} native_route_advisory=${NATIVE_ROUTE_ADVISORY_JSON:-unset} diagnose=${diagnose_path} stderr=${diagnose_stderr_path}"
  fi

  local selected_worker
  selected_worker="$(jq -r '.data.worker_selection.worker.id // ""' "$diagnose_path")"
  if [[ -z "$selected_worker" ]]; then
    local reason
    reason="$(jq -r '.data.worker_selection.reason // "unknown"' "$diagnose_path")"
    fail "worker_selection_preflight_not_observed expected_worker=${EXPECTED_RCH_WORKER:-unset} native_route_advisory=${NATIVE_ROUTE_ADVISORY_JSON:-unset} reason=${reason} diagnose=${diagnose_path}"
  fi

  enforce_selected_worker_pressure_guard "$selected_worker"

  if [[ -n "$EXPECTED_RCH_WORKER" && "$selected_worker" != "$EXPECTED_RCH_WORKER" ]]; then
    fail "expected_worker_preflight_mismatch expected_worker=${EXPECTED_RCH_WORKER} selected_worker=${selected_worker} diagnose=${diagnose_path}"
  fi

  if [[ -n "$EXPECTED_RCH_WORKER" ]]; then
    log "expected_worker_preflight=observed worker=${selected_worker} diagnose=${diagnose_path}"
  fi

  if [[ -n "$NATIVE_ROUTE_ADVISORY_JSON" ]]; then
    if ! jq -e --arg worker "$selected_worker" '(.compatible_worker_ids // []) | index($worker) != null' "$NATIVE_ROUTE_ADVISORY_JSON" >/dev/null; then
      local worker_context
      worker_context="$(worker_selection_context "$selected_worker")"
      fail "native_route_preflight_incompatible_worker selected_worker=${selected_worker} compatible_workers=${NATIVE_ROUTE_COMPATIBLE_WORKERS} reason_codes=${NATIVE_ROUTE_REASON_CODES:-none} advisory=${NATIVE_ROUTE_ADVISORY_JSON} ${worker_context}"
    fi

    log "native_route_preflight=compatible worker=${selected_worker} advisory=${NATIVE_ROUTE_ADVISORY_JSON}"
  fi
}

run_gate() {
  local mode="${1:-compile}"
  [[ "$TARGET_KIND" == "lib" ]] || fail "unsupported_target_kind target_kind=${TARGET_KIND}"
  command -v "$RCH_BIN" >/dev/null 2>&1 || fail "rch_not_found binary=${RCH_BIN}"
  check_script_wrapping "$script_path"

  mkdir -p "$run_dir"
  prepare_rch_selection_env
  command_text "$mode" >"$commands_path"

  log "selected_package=${PACKAGE}"
  log "target_kind=${TARGET_KIND}"
  log "test_filter=${TEST_FILTER}"
  log "mode=${mode}"
  if [[ "${#RCH_SELECTION_ENV[@]}" -gt 0 ]]; then
    log "rch_worker_preference=${RCH_SELECTION_ENV[*]}"
  fi
  log "command=$(command_text "$mode")"
  log "log_path=${log_path}"
  preflight_worker_selection "$mode"

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
  timeout "$RCH_TIMEOUT_SECONDS" env "${RCH_SELECTION_ENV[@]}" "${command[@]}" >"$log_path" 2>&1
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
