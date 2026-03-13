#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_performance_regression_gate}"
artifact_root="${RGC_PERFORMANCE_REGRESSION_GATE_ARTIFACT_ROOT:-artifacts/rgc_performance_regression_gate}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-${rch_timeout_seconds}}}"
rch_progress_stall_seconds="${RCH_PROGRESS_STALL_SECONDS:-0}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
regression_report_path="${run_dir}/regression_report.json"

trace_id="trace-rgc-performance-regression-gate-${timestamp}"
decision_id="decision-rgc-performance-regression-gate-${timestamp}"
policy_id="policy-rgc-performance-regression-gate-v1"
component="rgc_performance_regression_gate"
scenario_id="rgc-703"
replay_command="./scripts/e2e/rgc_performance_regression_gate_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC performance regression gate heavy commands" >&2
  exit 2
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=0|Finished.*profile|test result: ok\.' \
    && ! rch_strip_ansi "$log_path" | rg -qi 'error(\[[[:alnum:]]+\])?:'; then
    return 0
  fi
  return 1
}

rch_reported_timeout_seconds() {
  local log_path="$1"
  local timeout_value

  timeout_value="$(
    rch_strip_ansi "$log_path" | sed -nE 's/.*timeout_secs: ([0-9]+).*/\1/p' | tail -n 1
  )"
  if [[ -z "$timeout_value" ]]; then
    echo ""
    return
  fi

  echo "$timeout_value"
}

kill_process_tree() {
  local root_pid="$1"
  local child_pid

  while read -r child_pid; do
    [[ -n "$child_pid" ]] || continue
    kill_process_tree "$child_pid"
  done < <(ps -o pid= --ppid "$root_pid" 2>/dev/null || true)

  kill "$root_pid" 2>/dev/null || true
}

watch_rch_progress() {
  local log_path="$1"
  local step_pid="$2"
  local stall_seconds="$3"
  local expected_timeout="$4"
  local remote_started=false
  local last_size="-1"
  local last_progress_ts
  local current_size now_ts reported_timeout

  last_progress_ts="$(date +%s)"

  while kill -0 "$step_pid" 2>/dev/null; do
    sleep 5

    if [[ ! -f "$log_path" ]]; then
      continue
    fi

    current_size="$(wc -c <"$log_path")"
    if [[ "$current_size" != "$last_size" ]]; then
      last_size="$current_size"
      last_progress_ts="$(date +%s)"
    fi

    reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
    if [[ "$expected_timeout" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] \
      && (( reported_timeout < expected_timeout )); then
      echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${expected_timeout}" \
        | tee -a "$log_path"
      kill_process_tree "$step_pid"
      return 4
    fi

    if [[ "$remote_started" == false ]] \
      && rch_strip_ansi "$log_path" | rg -q 'Executing command remotely:'; then
      remote_started=true
      last_progress_ts="$(date +%s)"
      continue
    fi

    if [[ "$remote_started" != true || "$stall_seconds" -le 0 ]]; then
      continue
    fi

    now_ts="$(date +%s)"
    if (( now_ts - last_progress_ts < stall_seconds )); then
      continue
    fi

    echo "==> failure: no remote progress for ${stall_seconds}s after remote execution started" \
      | tee -a "$log_path"
    kill_process_tree "$step_pid"
    return 3
  done

  return 0
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local status remote_exit_code step_pid progress_watch_pid progress_watch_status reported_timeout
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  shift

  commands_run+=("$command_text")
  step_logs+=("$step_log_path")
  echo "==> $command_text"

  set +e
  : >"$step_log_path"
  run_rch "$@" > >(tee "$step_log_path") 2>&1 &
  step_pid=$!
  progress_watch_status=0
  progress_watch_pid=""
  if [[ "$rch_progress_stall_seconds" -gt 0 || "$rch_build_timeout_sec" -gt 0 ]]; then
    watch_rch_progress \
      "$step_log_path" \
      "$step_pid" \
      "$rch_progress_stall_seconds" \
      "$rch_build_timeout_sec" &
    progress_watch_pid=$!
  fi

  wait "$step_pid"
  status=$?
  if [[ -n "$progress_watch_pid" ]]; then
    wait "$progress_watch_pid"
    progress_watch_status=$?
  fi
  set -e

  if [[ "$progress_watch_status" -eq 3 ]]; then
    failed_command="${command_text} (rch-stalled-no-progress-${rch_progress_stall_seconds}s)"
    return 1
  fi
  if [[ "$progress_watch_status" -eq 4 ]]; then
    reported_timeout="$(rch_reported_timeout_seconds "$step_log_path")"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    return 1
  fi

  if [[ "$status" -ne 0 ]]; then
    if [[ "$status" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$step_log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$step_log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$step_log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$step_log_path" || true)"
      if [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  reported_timeout="$(rch_reported_timeout_seconds "$step_log_path")"
  if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] \
    && (( reported_timeout < rch_build_timeout_sec )); then
    echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" \
      | tee -a "$step_log_path"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    return 1
  fi

  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$step_log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    return 1
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

run_mode() {
  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --test rgc_performance_regression_gate" \
      cargo check -p frankenengine-engine --test rgc_performance_regression_gate
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test rgc_performance_regression_gate" \
      cargo test -p frankenengine-engine --test rgc_performance_regression_gate
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --test rgc_performance_regression_gate -- -D warnings" \
      cargo clippy -p frankenengine-engine --test rgc_performance_regression_gate -- -D warnings
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --test rgc_performance_regression_gate" \
      cargo check -p frankenengine-engine --test rgc_performance_regression_gate
    run_step "cargo test -p frankenengine-engine --test rgc_performance_regression_gate" \
      cargo test -p frankenengine-engine --test rgc_performance_regression_gate
    run_step "cargo clippy -p frankenengine-engine --test rgc_performance_regression_gate -- -D warnings" \
      cargo clippy -p frankenengine-engine --test rgc_performance_regression_gate -- -D warnings
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
  esac
}

write_regression_report() {
  local outcome="$1"
  local blocking highest_severity

  if [[ "$outcome" == "pass" ]]; then
    blocking=false
    highest_severity="none"
  else
    blocking=true
    highest_severity="critical"
  fi

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-performance-regression-gate.v1",'
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"component\": \"${component}\","
    echo "  \"blocking\": ${blocking},"
    echo "  \"is_blocking\": ${blocking},"
    echo "  \"highest_severity\": \"${highest_severity}\","
    echo "  \"severity\": \"${highest_severity}\","
    echo '  "regressions": [],'
    echo '  "culprit_ranking": [],'
    echo '  "logs": ['
    echo "    {\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":null,\"workload_id\":null}"
    echo '  ]'
    echo "}"
  } >"${regression_report_path}"
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-703-GATE-0001"'
  fi

  write_regression_report "$outcome"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-performance-regression-gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-performance-regression-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.8.3",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"regression_report\": \"${regression_report_path}\","
    echo '    "contract_doc": "docs/RGC_PERFORMANCE_REGRESSION_GATE_V1.md",'
    echo '    "contract_json": "docs/rgc_performance_regression_gate_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/rgc_performance_regression_gate.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${regression_report_path}\","
    echo '    "jq empty docs/rgc_performance_regression_gate_v1.json",'
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc performance regression gate manifest: ${manifest_path}"
  echo "rgc performance regression gate report: ${regression_report_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
