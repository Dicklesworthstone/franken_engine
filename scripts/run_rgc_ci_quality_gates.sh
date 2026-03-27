#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_CI_QUALITY_GATES_ARTIFACT_ROOT:-artifacts/rgc_ci_quality_gates}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-900}}"
rch_missing_marker_retry_count="${RCH_MISSING_MARKER_RETRY_COUNT:-1}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"
require_regression_verdict="${RGC_CI_QUALITY_REQUIRE_REGRESSION_VERDICT:-false}"
regression_verdict_path="${RGC_PERF_REGRESSION_VERDICT_PATH:-}"
if [[ -z "$regression_verdict_path" ]]; then
  regression_verdict_path="${RGC_CI_QUALITY_REGRESSION_VERDICT_PATH:-}"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/tmp/rch_target_franken_engine_rgc_ci_quality_gates_${timestamp}_$$"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
failure_summary_path="${run_dir}/failure_summary.json"
ci_gate_verdict_path="${run_dir}/ci_gate_verdict.json"
failure_routing_matrix_path="${run_dir}/failure_routing_matrix.json"
lane_repro_index_path="${run_dir}/lane_repro_index.json"
gate_health_summary_path="${run_dir}/gate_health_summary.md"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-rgc-ci-quality-gates-${timestamp}"
decision_id="decision-rgc-ci-quality-gates-${timestamp}"
policy_id="policy-rgc-ci-quality-gates-v1"
component="rgc_ci_quality_gates"
scenario_id="rgc-055"
replay_command="./scripts/e2e/rgc_ci_quality_gates_replay.sh ${mode}"

mkdir -p "$run_dir"
mkdir -p "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC CI quality gate heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for RGC CI quality gate verdict ingestion" >&2
  exit 2
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' < <(rch_strip_ansi "$log_path") | tail -n 1 || true)"
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
  if grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' < <(rch_strip_ansi "$log_path"); then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_missing_remote_exit_reason() {
  local log_path="$1"
  local run_rch_exit="$2"

  if [[ "$run_rch_exit" == "124" || "$run_rch_exit" == "137" ]]; then
    printf 'timeout-before-remote-exit-marker'
    return
  fi

  if grep -Eiq 'timed out|timeout protection|deadline exceeded|signal: 9|killed' < <(rch_strip_ansi "$log_path"); then
    printf 'timeout-before-remote-exit-marker'
    return
  fi

  if grep -Fq 'Executing command remotely:' < <(rch_strip_ansi "$log_path"); then
    printf 'remote-exit-marker-lost-after-remote-start'
    return
  fi

  printf 'missing-remote-exit-marker'
}

rch_missing_remote_exit_error_code() {
  local reason="$1"

  case "$reason" in
    timeout-before-remote-exit-marker)
      printf 'FE-RGC-CI-QUALITY-GATE-0009'
      ;;
    remote-exit-marker-lost-after-remote-start)
      printf 'FE-RGC-CI-QUALITY-GATE-0010'
      ;;
    *)
      printf 'FE-RGC-CI-QUALITY-GATE-0008'
      ;;
  esac
}

declare -a commands_run=()
declare -a events_buffer=()
declare -a failed_lanes=()
declare -A lane_status_by_name=()
failed_command=""
failure_owner=""
failure_lane=""
manifest_written=false
step_counter=0

default_owner_for_lane() {
  case "$1" in
    fmt|check|clippy|unit|integration)
      printf 'runtime-core'
      ;;
    e2e|replay)
      printf 'verification-lane'
      ;;
    regression)
      printf 'performance-governance'
      ;;
    *)
      printf 'runtime-core'
      ;;
  esac
}

lane_requires_rch() {
  case "$1" in
    fmt|check|clippy|unit|integration)
      printf 'true\n'
      ;;
    *)
      printf 'false\n'
      ;;
  esac
}

contract_lanes() {
  printf '%s\n' fmt check clippy unit integration e2e replay regression
}

planned_lanes() {
  case "$mode" in
    fmt|check|clippy|unit|integration|e2e|replay|regression)
      printf '%s\n' "$mode"
      ;;
    ci)
      contract_lanes
      ;;
    *)
      ;;
  esac
}

lane_repro_command() {
  local lane="$1"

  if [[ "$lane" == "regression" ]]; then
    regression_verdict_command_text
    return
  fi

  printf './scripts/run_rgc_ci_quality_gates.sh %s\n' "$lane"
}

lane_commands_json() {
  local lane="$1"
  local regression_command

  case "$lane" in
    fmt)
      jq -cn '["cargo fmt --check"]'
      ;;
    check)
      jq -cn '["cargo check --all-targets"]'
      ;;
    clippy)
      jq -cn '["cargo clippy --all-targets -- -D warnings"]'
      ;;
    unit)
      jq -cn '["cargo test -p frankenengine-engine --lib"]'
      ;;
    integration)
      jq -cn '["cargo test -p frankenengine-engine --test rgc_test_harness_integration --test rgc_verification_coverage_matrix --test rgc_execution_waves_integration --test rgc_execution_waves_enrichment_integration"]'
      ;;
    e2e)
      jq -cn '[
        "./scripts/run_rgc_test_harness_suite.sh ci",
        "./scripts/run_rgc_verification_coverage_matrix.sh ci"
      ]'
      ;;
    replay)
      jq -cn '[
        "./scripts/e2e/rgc_test_harness_replay.sh ci",
        "./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci"
      ]'
      ;;
    regression)
      regression_command="$(regression_verdict_command_text)"
      jq -cn --arg command "$regression_command" '[$command]'
      ;;
    *)
      jq -cn '[]'
      ;;
  esac
}

json_array_from_lines() {
  if [[ $# -eq 0 ]]; then
    jq -cn '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

shell_join() {
  local quoted joined=""
  for quoted in "$@"; do
    printf -v quoted '%q' "$quoted"
    if [[ -n "$joined" ]]; then
      joined+=" "
    fi
    joined+="$quoted"
  done

  printf '%s\n' "$joined"
}

regression_verdict_command_text() {
  local -a parts=()

  if [[ "$require_regression_verdict" == "true" ]]; then
    parts+=("RGC_CI_QUALITY_REQUIRE_REGRESSION_VERDICT=true")
  fi
  if [[ -n "$regression_verdict_path" ]]; then
    parts+=("RGC_CI_QUALITY_REGRESSION_VERDICT_PATH=${regression_verdict_path}")
  fi
  parts+=("./scripts/run_rgc_ci_quality_gates.sh" "regression")

  shell_join "${parts[@]}"
}

record_event() {
  local event_name="$1"
  local outcome="$2"
  local error_code="$3"
  local lane="$4"
  local detail="$5"

  events_buffer+=("$(jq -cn \
    --arg schema_version 'franken-engine.rgc-ci-quality-gates.event.v1' \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "$event_name" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg lane "$lane" \
    --arg detail "$detail" \
    '{schema_version:$schema_version,trace_id:$trace_id,decision_id:$decision_id,policy_id:$policy_id,component:$component,event:$event,outcome:$outcome,error_code:($error_code|select(length>0)),lane:$lane,detail:$detail}')")
}

run_step_rch() {
  local lane="$1"
  local command_text="$2"
  local log_path remote_exit_code run_rch_exit tee_exit command_slug missing_marker_reason missing_marker_error_code non_compilation_marker
  local -a rch_pipeline_status=()
  local attempt=0
  local max_retries="$rch_missing_marker_retry_count"
  shift 2

  commands_run+=("$command_text")
  lane_status_by_name["$lane"]="running"
  echo "==> $command_text"
  step_counter=$((step_counter + 1))
  command_slug="$(printf '%s' "$command_text" | tr '[:space:]/:' '_' | tr -cd '[:alnum:]_.-' | cut -c1-64)"
  if [[ -z "$command_slug" ]]; then
    command_slug="${lane}_step_${step_counter}"
  fi
  while true; do
    log_path="${step_logs_dir}/$(printf '%02d' "$step_counter")_${command_slug}"
    if (( attempt > 0 )); then
      log_path="${log_path}_retry${attempt}.log"
    else
      log_path="${log_path}.log"
    fi

    # Use a real pipeline so the step log is fully flushed before we inspect
    # it for non-compilation warnings and remote-exit markers.
    set +e
    run_rch "$@" 2>&1 | tee "$log_path"
    rch_pipeline_status=("${PIPESTATUS[@]}")
    set -e
    run_rch_exit="${rch_pipeline_status[0]:-1}"
    tee_exit="${rch_pipeline_status[1]:-1}"

    if [[ "$tee_exit" -ne 0 ]]; then
      failed_command="${command_text} (tee-exit=${tee_exit}; log=${log_path})"
      failure_lane="$lane"
      failure_owner="$(default_owner_for_lane "$lane")"
      failed_lanes+=("$lane")
      lane_status_by_name["$lane"]="fail"
      record_event "lane_failed" "fail" "FE-RGC-CI-QUALITY-GATE-0004" "$lane" "$failed_command"
      return 1
    fi

    non_compilation_marker=false
    if grep -Fq 'exec called with non-compilation command' < <(rch_strip_ansi "$log_path"); then
      non_compilation_marker=true
    fi

    remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
    if [[ -z "$remote_exit_code" && "$non_compilation_marker" == true ]]; then
      echo "==> info: remote exit marker missing for non-compilation command; using rch process exit=${run_rch_exit}" \
        | tee -a "$log_path"
      remote_exit_code="${run_rch_exit}"
    fi

    if [[ "$run_rch_exit" -ne 0 ]]; then
      if [[ "$remote_exit_code" == "0" ]]; then
        echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
      elif [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (remote-exit=${remote_exit_code}; rch-exit=${run_rch_exit}; retries=${attempt}; log=${log_path})"
        failure_lane="$lane"
        failure_owner="$(default_owner_for_lane "$lane")"
        failed_lanes+=("$lane")
        lane_status_by_name["$lane"]="fail"
        record_event "lane_failed" "fail" "FE-RGC-CI-QUALITY-GATE-0003" "$lane" "$failed_command"
        return 1
      else
        missing_marker_reason="$(rch_missing_remote_exit_reason "$log_path" "$run_rch_exit")"
        if (( attempt < max_retries )) && [[ "$missing_marker_reason" == "timeout-before-remote-exit-marker" || "$missing_marker_reason" == "remote-exit-marker-lost-after-remote-start" ]]; then
          echo "==> retrying lane ${lane} due to ${missing_marker_reason} (attempt $((attempt + 1))/${max_retries})" | tee -a "$log_path"
          attempt=$((attempt + 1))
          continue
        fi
        missing_marker_error_code="$(rch_missing_remote_exit_error_code "$missing_marker_reason")"
        failed_command="${command_text} (rch-exit=${run_rch_exit}; ${missing_marker_reason}; retries=${attempt}; log=${log_path})"
        failure_lane="$lane"
        failure_owner="$(default_owner_for_lane "$lane")"
        failed_lanes+=("$lane")
        lane_status_by_name["$lane"]="fail"
        record_event "lane_failed" "fail" "$missing_marker_error_code" "$lane" "$failed_command"
        return 1
      fi
    fi

    if ! rch_reject_local_fallback "$log_path"; then
      failed_command="${command_text} (rch-local-fallback-detected; retries=${attempt}; log=${log_path})"
      failure_lane="$lane"
      failure_owner="$(default_owner_for_lane "$lane")"
      failed_lanes+=("$lane")
      lane_status_by_name["$lane"]="fail"
      record_event "lane_failed" "fail" "FE-RGC-CI-QUALITY-GATE-0002" "$lane" "$failed_command"
      return 1
    fi

    if [[ -z "$remote_exit_code" ]]; then
      missing_marker_reason="$(rch_missing_remote_exit_reason "$log_path" "$run_rch_exit")"
      if (( attempt < max_retries )) && [[ "$missing_marker_reason" == "timeout-before-remote-exit-marker" || "$missing_marker_reason" == "remote-exit-marker-lost-after-remote-start" ]]; then
        echo "==> retrying lane ${lane} due to ${missing_marker_reason} (attempt $((attempt + 1))/${max_retries})" | tee -a "$log_path"
        attempt=$((attempt + 1))
        continue
      fi
      missing_marker_error_code="$(rch_missing_remote_exit_error_code "$missing_marker_reason")"
      failed_command="${command_text} (${missing_marker_reason}; rch-exit=${run_rch_exit}; retries=${attempt}; log=${log_path})"
      failure_lane="$lane"
      failure_owner="$(default_owner_for_lane "$lane")"
      failed_lanes+=("$lane")
      lane_status_by_name["$lane"]="fail"
      record_event "lane_failed" "fail" "$missing_marker_error_code" "$lane" "$failed_command"
      return 1
    fi

    if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
      failed_command="${command_text} (remote-exit=${remote_exit_code}; rch-exit=${run_rch_exit}; retries=${attempt}; log=${log_path})"
      failure_lane="$lane"
      failure_owner="$(default_owner_for_lane "$lane")"
      failed_lanes+=("$lane")
      lane_status_by_name["$lane"]="fail"
      record_event "lane_failed" "fail" "FE-RGC-CI-QUALITY-GATE-0003" "$lane" "$failed_command"
      return 1
    fi

    break
  done

  lane_status_by_name["$lane"]="pass"
  record_event "lane_completed" "pass" "" "$lane" "$command_text"
}

run_step_local() {
  local lane="$1"
  local command_text="$2"
  shift 2

  commands_run+=("$command_text")
  lane_status_by_name["$lane"]="running"
  echo "==> $command_text"
  if ! "$@"; then
    failed_command="$command_text"
    failure_lane="$lane"
    failure_owner="$(default_owner_for_lane "$lane")"
    failed_lanes+=("$lane")
    lane_status_by_name["$lane"]="fail"
    record_event "lane_failed" "fail" "FE-RGC-CI-QUALITY-GATE-0004" "$lane" "$command_text"
    return 1
  fi

  lane_status_by_name["$lane"]="pass"
  record_event "lane_completed" "pass" "" "$lane" "$command_text"
}

severity_is_blocking() {
  local severity="$1"
  case "$severity" in
    critical|high)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

evaluate_regression_verdict() {
  local lane="regression"
  local highest_severity is_blocking open_high_count detail

  commands_run+=("$(regression_verdict_command_text)")
  lane_status_by_name["$lane"]="running"

  if [[ -z "$regression_verdict_path" ]]; then
    if [[ "$require_regression_verdict" == "true" ]]; then
      failed_command="missing regression verdict path (set RGC_PERF_REGRESSION_VERDICT_PATH or RGC_CI_QUALITY_REGRESSION_VERDICT_PATH)"
      failure_lane="$lane"
      failure_owner="$(default_owner_for_lane "$lane")"
      failed_lanes+=("$lane")
      lane_status_by_name["$lane"]="fail"
      record_event "regression_verdict_missing" "fail" "FE-RGC-CI-QUALITY-GATE-0005" "$lane" "$failed_command"
      return 1
    fi

    lane_status_by_name["$lane"]="skipped"
    record_event "regression_verdict_skipped" "pass" "" "$lane" "no verdict path configured"
    return 0
  fi

  if [[ ! -f "$regression_verdict_path" ]]; then
    if [[ "$require_regression_verdict" == "true" ]]; then
      failed_command="configured regression verdict missing: ${regression_verdict_path}"
      failure_lane="$lane"
      failure_owner="$(default_owner_for_lane "$lane")"
      failed_lanes+=("$lane")
      lane_status_by_name["$lane"]="fail"
      record_event "regression_verdict_missing" "fail" "FE-RGC-CI-QUALITY-GATE-0006" "$lane" "$failed_command"
      return 1
    fi

    lane_status_by_name["$lane"]="skipped"
    record_event "regression_verdict_skipped" "pass" "" "$lane" "configured verdict file missing; skipping (prework mode)"
    return 0
  fi

  highest_severity="$(jq -r '(.highest_severity // .severity // "none") | ascii_downcase' "$regression_verdict_path")"
  is_blocking="$(jq -r '(.blocking // .is_blocking // false)' "$regression_verdict_path")"
  open_high_count="$(jq '[.regressions[]? | select(((.status // "active") | ascii_downcase) != "waived") | select(((.severity // .level // "none") | ascii_downcase) == "critical" or ((.severity // .level // "none") | ascii_downcase) == "high")] | length' "$regression_verdict_path")"

  if [[ "$is_blocking" == "true" ]] || severity_is_blocking "$highest_severity" || [[ "$open_high_count" != "0" ]]; then
    detail="regression verdict blocked promotion: highest_severity=${highest_severity}, blocking=${is_blocking}, open_high_or_critical=${open_high_count}, file=${regression_verdict_path}"
    failed_command="$detail"
    failure_lane="$lane"
    failure_owner="$(default_owner_for_lane "$lane")"
    failed_lanes+=("$lane")
    lane_status_by_name["$lane"]="fail"
    record_event "regression_verdict_blocked" "fail" "FE-RGC-CI-QUALITY-GATE-0007" "$lane" "$detail"
    return 1
  fi

  lane_status_by_name["$lane"]="pass"
  detail="regression verdict clear: highest_severity=${highest_severity}, blocking=${is_blocking}, open_high_or_critical=${open_high_count}, file=${regression_verdict_path}"
  record_event "regression_verdict_clear" "pass" "" "$lane" "$detail"
}

run_mode() {
  case "$mode" in
    fmt)
      run_step_rch "fmt" "cargo fmt --check" cargo fmt --check
      ;;
    check)
      run_step_rch "check" "cargo check --all-targets" cargo check --all-targets
      ;;
    clippy)
      run_step_rch "clippy" "cargo clippy --all-targets -- -D warnings" cargo clippy --all-targets -- -D warnings
      ;;
    unit)
      run_step_rch "unit" "cargo test -p frankenengine-engine --lib" cargo test -p frankenengine-engine --lib
      ;;
    integration)
      run_step_rch "integration" "cargo test -p frankenengine-engine --test rgc_test_harness_integration --test rgc_verification_coverage_matrix --test rgc_execution_waves_integration --test rgc_execution_waves_enrichment_integration" \
        cargo test -p frankenengine-engine --test rgc_test_harness_integration --test rgc_verification_coverage_matrix --test rgc_execution_waves_integration --test rgc_execution_waves_enrichment_integration
      ;;
    e2e)
      run_step_local "e2e" "./scripts/run_rgc_test_harness_suite.sh ci" "${root_dir}/scripts/run_rgc_test_harness_suite.sh" ci
      run_step_local "e2e" "./scripts/run_rgc_verification_coverage_matrix.sh ci" "${root_dir}/scripts/run_rgc_verification_coverage_matrix.sh" ci
      ;;
    replay)
      run_step_local "replay" "./scripts/e2e/rgc_test_harness_replay.sh ci" "${root_dir}/scripts/e2e/rgc_test_harness_replay.sh" ci
      run_step_local "replay" "./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci" "${root_dir}/scripts/e2e/rgc_verification_coverage_matrix_replay.sh" ci
      ;;
    ci)
      run_mode fmt
      run_mode check
      run_mode clippy
      run_mode unit
      run_mode integration
      run_mode e2e
      run_mode replay
      evaluate_regression_verdict
      ;;
    regression)
      evaluate_regression_verdict
      ;;
    *)
      echo "usage: $0 [fmt|check|clippy|unit|integration|e2e|replay|regression|ci]" >&2
      exit 2
      ;;
  esac
}

write_failure_summary() {
  local outcome="$1"
  local failed_lanes_json

  if (( ${#failed_lanes[@]} == 0 )); then
    failed_lanes_json='[]'
  else
    failed_lanes_json="$(printf '%s\n' "${failed_lanes[@]}" | jq -R . | jq -s .)"
  fi

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-ci-quality-gates.failure-summary.v1",'
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    else
      echo '  "failed_command": null,'
    fi
    if [[ -n "$failure_lane" ]]; then
      echo "  \"failed_lane\": \"${failure_lane}\","
    else
      echo '  "failed_lane": null,'
    fi
    if [[ -n "$failure_owner" ]]; then
      echo "  \"owner_hint\": \"${failure_owner}\","
    else
      echo '  "owner_hint": null,'
    fi
    echo "  \"failed_lanes\": ${failed_lanes_json},"
    echo "  \"repro_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    if [[ -n "$regression_verdict_path" ]]; then
      echo "  \"regression_verdict_path\": \"$(parser_frontier_json_escape "${regression_verdict_path}")\""
    else
      echo '  "regression_verdict_path": null'
    fi
    echo "}"
  } >"$failure_summary_path"
}

write_ci_gate_verdict() {
  local outcome="$1"
  local failed_lanes_json planned_lanes_json
  local is_blocking_json

  if [[ "$outcome" == "fail" ]]; then
    is_blocking_json=true
  else
    is_blocking_json=false
  fi

  if (( ${#failed_lanes[@]} == 0 )); then
    failed_lanes_json='[]'
  else
    failed_lanes_json="$(printf '%s\n' "${failed_lanes[@]}" | jq -R . | jq -s .)"
  fi
  planned_lanes_json="$(planned_lanes | jq -R . | jq -s .)"

  jq -cn \
    --arg schema_version 'franken-engine.rgc-ci-quality-gates.verdict.v1' \
    --arg bead_id 'bd-1lsy.11.5' \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg scenario_id "$scenario_id" \
    --arg mode "$mode" \
    --arg outcome "$outcome" \
    --arg failure_lane "$failure_lane" \
    --arg failure_owner "$failure_owner" \
    --arg failed_command "$failed_command" \
    --arg failure_summary "$failure_summary_path" \
    --arg routing_matrix "$failure_routing_matrix_path" \
    --arg repro_index "$lane_repro_index_path" \
    --arg health_summary "$gate_health_summary_path" \
    --argjson is_blocking "$is_blocking_json" \
    --argjson failed_lanes "$failed_lanes_json" \
    --argjson planned_lanes "$planned_lanes_json" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      scenario_id: $scenario_id,
      mode: $mode,
      outcome: $outcome,
      is_blocking: $is_blocking,
      planned_lanes: $planned_lanes,
      failed_lanes: $failed_lanes,
      failure: {
        lane: (if $failure_lane == "" then null else $failure_lane end),
        owner_hint: (if $failure_owner == "" then null else $failure_owner end),
        detail: (if $failed_command == "" then null else $failed_command end)
      },
      artifact_bundle: {
        failure_summary: $failure_summary,
        failure_routing_matrix: $routing_matrix,
        lane_repro_index: $repro_index,
        gate_health_summary: $health_summary
      }
    }' >"$ci_gate_verdict_path"
}

write_failure_routing_matrix() {
  local outcome="$1"
  local lanes_json='[]'
  local lane status detail owner_hint requires_rch_json commands_json repro_command

  while IFS= read -r lane; do
    [[ -z "$lane" ]] && continue
    status="${lane_status_by_name[$lane]:-not_run}"
    owner_hint="$(default_owner_for_lane "$lane")"
    requires_rch_json="$(lane_requires_rch "$lane")"
    commands_json="$(lane_commands_json "$lane")"
    repro_command="$(lane_repro_command "$lane")"
    detail=""
    if [[ "$lane" == "$failure_lane" ]]; then
      detail="$failed_command"
    fi

    lanes_json="$(jq -cn \
      --argjson lanes "$lanes_json" \
      --arg lane "$lane" \
      --arg status "$status" \
      --arg owner_hint "$owner_hint" \
      --arg repro_command "$repro_command" \
      --arg detail "$detail" \
      --argjson requires_rch "$requires_rch_json" \
      --argjson commands "$commands_json" \
      '$lanes + [{
        lane: $lane,
        status: $status,
        owner_hint: $owner_hint,
        requires_rch: $requires_rch,
        repro_command: $repro_command,
        commands: $commands,
        detail: (if $detail == "" then null else $detail end)
      }]')"
  done < <(planned_lanes)

  jq -cn \
    --arg schema_version 'franken-engine.rgc-ci-quality-gates.failure-routing-matrix.v1' \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg mode "$mode" \
    --arg outcome "$outcome" \
    --arg failure_summary "$failure_summary_path" \
    --arg verdict "$ci_gate_verdict_path" \
    --argjson lanes "$lanes_json" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      mode: $mode,
      outcome: $outcome,
      lanes: $lanes,
      supporting_artifacts: {
        failure_summary: $failure_summary,
        ci_gate_verdict: $verdict
      }
    }' >"$failure_routing_matrix_path"
}

write_lane_repro_index() {
  local planned_lanes_json lanes_json='[]'
  local lane repro_command commands_json requires_rch_json

  planned_lanes_json="$(planned_lanes | jq -R . | jq -s .)"

  while IFS= read -r lane; do
    [[ -z "$lane" ]] && continue
    repro_command="$(lane_repro_command "$lane")"
    commands_json="$(lane_commands_json "$lane")"
    requires_rch_json="$(lane_requires_rch "$lane")"

    lanes_json="$(jq -cn \
      --argjson lanes "$lanes_json" \
      --arg lane "$lane" \
      --arg gate_entrypoint "./scripts/run_rgc_ci_quality_gates.sh ${lane}" \
      --arg replay_entrypoint "$repro_command" \
      --argjson requires_rch "$requires_rch_json" \
      --argjson commands "$commands_json" \
      '$lanes + [{
        lane: $lane,
        gate_entrypoint: $gate_entrypoint,
        replay_entrypoint: $replay_entrypoint,
        requires_rch: $requires_rch,
        commands: $commands
      }]')"
  done < <(contract_lanes)

  jq -cn \
    --arg schema_version 'franken-engine.rgc-ci-quality-gates.lane-repro-index.v1' \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg mode "$mode" \
    --arg gate_ci "./scripts/run_rgc_ci_quality_gates.sh ci" \
    --arg replay_ci "./scripts/e2e/rgc_ci_quality_gates_replay.sh ci" \
    --arg replay_regression "./scripts/e2e/rgc_ci_quality_gates_replay.sh regression" \
    --argjson planned_lanes "$planned_lanes_json" \
    --argjson lanes "$lanes_json" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      mode: $mode,
      planned_lanes: $planned_lanes,
      operator_entrypoints: {
        gate_ci: $gate_ci,
        replay_ci: $replay_ci,
        replay_regression: $replay_regression
      },
      lanes: $lanes
    }' >"$lane_repro_index_path"
}

write_gate_health_summary() {
  local outcome="$1"
  local lane status

  {
    echo "# RGC CI Quality Gates Summary"
    echo
    echo "- Outcome: \`${outcome}\`"
    echo "- Mode: \`${mode}\`"
    if [[ -n "$failure_lane" ]]; then
      echo "- Failed lane: \`${failure_lane}\`"
    else
      echo '- Failed lane: `none`'
    fi
    if [[ -n "$failure_owner" ]]; then
      echo "- Owner hint: \`${failure_owner}\`"
    else
      echo '- Owner hint: `none`'
    fi
    echo "- Replay command: \`${replay_command}\`"
    echo
    echo "## Lane Status"
    while IFS= read -r lane; do
      [[ -z "$lane" ]] && continue
      status="${lane_status_by_name[$lane]:-not_run}"
      echo "- \`${lane}\`: \`${status}\`"
    done < <(planned_lanes)
    echo
    echo "## Artifact Bundle"
    echo "- \`run_manifest.json\`"
    echo "- \`events.jsonl\`"
    echo "- \`commands.txt\`"
    echo "- \`failure_summary.json\`"
    echo "- \`ci_gate_verdict.json\`"
    echo "- \`failure_routing_matrix.json\`"
    echo "- \`lane_repro_index.json\`"
    echo "- \`gate_health_summary.md\`"
  } >"$gate_health_summary_path"
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
    error_code_json='"FE-RGC-CI-QUALITY-GATE-0000"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  printf '%s\n' "${events_buffer[@]}" >"$events_path"

  write_failure_summary "$outcome"
  write_ci_gate_verdict "$outcome"
  write_failure_routing_matrix "$outcome"
  write_lane_repro_index
  write_gate_health_summary "$outcome"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-ci-quality-gates.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.5",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"scenario_id\": \"${scenario_id}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"rch_build_timeout_sec\": ${rch_build_timeout_sec},"
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"outcome\": \"${outcome}\"," 
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\"," 
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    if [[ -n "$regression_verdict_path" ]]; then
      echo "  \"regression_verdict_path\": \"$(parser_frontier_json_escape "${regression_verdict_path}")\"," 
    else
      echo '  "regression_verdict_path": null,'
    fi
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\"," 
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"failure_summary\": \"${failure_summary_path}\","
    echo "    \"ci_gate_verdict\": \"${ci_gate_verdict_path}\","
    echo "    \"failure_routing_matrix\": \"${failure_routing_matrix_path}\","
    echo "    \"lane_repro_index\": \"${lane_repro_index_path}\","
    echo "    \"gate_health_summary\": \"${gate_health_summary_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo '    "contract_doc": "docs/RGC_CI_QUALITY_GATES.md",'
    echo '    "gate_fixture": "crates/franken-engine/tests/fixtures/rgc_ci_quality_gates_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/rgc_ci_quality_gates.rs",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_ci_quality_gates_replay.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${failure_summary_path}\","
    echo "    \"cat ${ci_gate_verdict_path}\","
    echo "    \"cat ${failure_routing_matrix_path}\","
    echo "    \"cat ${lane_repro_index_path}\","
    echo "    \"cat ${gate_health_summary_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc ci quality gates manifest: ${manifest_path}"
  echo "rgc ci quality gates events: ${events_path}"
  echo "rgc ci quality gates failure summary: ${failure_summary_path}"
  echo "rgc ci quality gates verdict: ${ci_gate_verdict_path}"
  echo "rgc ci quality gates routing matrix: ${failure_routing_matrix_path}"
  echo "rgc ci quality gates repro index: ${lane_repro_index_path}"
  echo "rgc ci quality gates health summary: ${gate_health_summary_path}"
}

main_exit=0
run_mode || main_exit=$?
record_event "gate_completed" "$([[ $main_exit -eq 0 ]] && echo pass || echo fail)" "$([[ $main_exit -eq 0 ]] && echo '' || echo FE-RGC-CI-QUALITY-GATE-0000)" "$mode" "${replay_command}"
write_manifest "$main_exit"

exit "$main_exit"
