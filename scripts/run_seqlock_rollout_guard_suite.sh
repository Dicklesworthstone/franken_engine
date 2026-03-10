#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_exec_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-1800}}"
artifact_root="${SEQLOCK_ROLLOUT_GUARD_ARTIFACT_ROOT:-artifacts/seqlock_rollout_guard}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_seqlock_rollout_guard}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/suite_run_manifest.json"
events_path="${run_dir}/events.jsonl"
trace_id="${SEQLOCK_ROLLOUT_GUARD_TRACE_ID:-trace.rgc.621c}"
decision_id="${SEQLOCK_ROLLOUT_GUARD_DECISION_ID:-decision.rgc.621c}"
policy_id="${SEQLOCK_ROLLOUT_GUARD_POLICY_ID:-policy.rgc.621c}"
run_id="run-seqlock-rollout-guard-${timestamp}"
source_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
suite_commands_path="${run_dir}/suite_commands.txt"
step_logs_dir="${run_dir}/step_logs"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for seqlock rollout guard heavy commands" >&2
  exit 2
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is required to fail closed on seqlock rollout guard rch steps" >&2
  exit 2
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_exec_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_strip_ansi() {
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(rch_strip_ansi "$log_path" | grep -Eo 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
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

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23'; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
failed_step_log_path=""
manifest_written=false
step_counter=0

run_step() {
  local command_text="$1"
  local fallback_flag log_path monitor_pid rch_pid remote_exit_code reported_timeout run_rc status
  local stream_path
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"

  step_counter=$((step_counter + 1))
  log_path="${step_logs_dir}/step_${step_counter}.log"
  : >"$log_path"
  fallback_flag="$(mktemp)"
  stream_path="$(mktemp -u)"
  mkfifo "$stream_path"

  run_rch "$@" >"$stream_path" 2>&1 &
  rch_pid=$!
  {
    while IFS= read -r line; do
      printf '%s\n' "$line"
      printf '%s\n' "$line" >>"$log_path"
      if grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' <<<"$line"; then
        printf 'fallback-detected\n' >"$fallback_flag"
        kill "$rch_pid" 2>/dev/null || true
      fi
    done <"$stream_path"
  } &
  monitor_pid=$!

  if wait "$rch_pid"; then
    status=0
  else
    status=$?
  fi
  wait "$monitor_pid" || true
  rm -f "$stream_path"

  if [[ -s "$fallback_flag" ]]; then
    rm -f "$fallback_flag"
    failed_command="${command_text} (rch-local-fallback-detected)"
    failed_step_log_path="$log_path"
    return 1
  fi
  rm -f "$fallback_flag"

  if [[ "$status" -ne 0 ]]; then
    run_rc=$status
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
    if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
      (( reported_timeout < rch_build_timeout_sec )); then
      echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
      failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
      failed_step_log_path="$log_path"
      return 1
    fi
    if [[ "$run_rc" -eq 124 ]]; then
      failed_command="${command_text} (timeout-${rch_exec_timeout_seconds}s)"
    elif [[ -n "$remote_exit_code" ]]; then
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
    else
      failed_command="${command_text} (rch-exit-${run_rc})"
    fi
    failed_step_log_path="$log_path"
    return 1
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    failed_step_log_path="$log_path"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    failed_step_log_path="$log_path"
    return 1
  fi

  reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
  if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
    (( reported_timeout < rch_build_timeout_sec )); then
    echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    failed_step_log_path="$log_path"
    return 1
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
  if [[ -z "$remote_exit_code" ]]; then
    echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
    failed_command="${command_text} (missing-remote-exit-marker)"
    failed_step_log_path="$log_path"
    return 1
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (remote-exit-${remote_exit_code})"
    failed_step_log_path="$log_path"
    return 1
  fi
}

verify_bundle() {
  local artifact
  for artifact in \
    commands.txt \
    env.json \
    events.jsonl \
    loom_schedule_coverage_report.json \
    manifest.json \
    repro.lock \
    run_manifest.json \
    seqlock_rollout_guard.json \
    seqlock_safety_case.json \
    starvation_microbench_report.json \
    summary.md \
    trace_ids.json; do
    [[ -f "${run_dir}/${artifact}" ]] || {
      echo "missing required artifact: ${artifact}" >&2
      return 1
    }
  done

  jq -e '.schema_version == "franken-engine.rgc-seqlock-safety-case.v1"' \
    "${run_dir}/seqlock_safety_case.json" >/dev/null
  jq -e '.schema_version == "franken-engine.rgc-seqlock-starvation-microbench.v1"' \
    "${run_dir}/starvation_microbench_report.json" >/dev/null
  jq -e '.schema_version == "franken-engine.rgc-seqlock-loom-schedule-coverage.v1"' \
    "${run_dir}/loom_schedule_coverage_report.json" >/dev/null
  jq -e '.schema_version == "franken-engine.rgc-seqlock-rollout-guard.v1"' \
    "${run_dir}/seqlock_rollout_guard.json" >/dev/null
  jq -e '.all_candidates_disabled == true and (.rows | length) >= 1' \
    "${run_dir}/seqlock_rollout_guard.json" >/dev/null
  jq -e '.schema_version == "franken-engine.rgc-seqlock-rollout-run-manifest.v1"' \
    "${run_dir}/run_manifest.json" >/dev/null
  jq -e '.safety_case_hash != null and .loom_schedule_coverage_hash != null and .rollout_guard_hash != null' \
    "${run_dir}/run_manifest.json" >/dev/null
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin franken_seqlock_rollout_guard" \
        cargo check -p frankenengine-engine --bin franken_seqlock_rollout_guard
      run_step "cargo check -p frankenengine-engine --test seqlock_rollout_guard" \
        cargo check -p frankenengine-engine --test seqlock_rollout_guard
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib seqlock_rollout_guard" \
        cargo test -p frankenengine-engine --lib seqlock_rollout_guard
      run_step "cargo test -p frankenengine-engine --test seqlock_rollout_guard" \
        cargo test -p frankenengine-engine --test seqlock_rollout_guard
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin franken_seqlock_rollout_guard -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_seqlock_rollout_guard -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --test seqlock_rollout_guard -- -D warnings" \
        cargo clippy -p frankenengine-engine --test seqlock_rollout_guard -- -D warnings
      ;;
    run)
      run_step "cargo run -p frankenengine-engine --bin franken_seqlock_rollout_guard -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_seqlock_rollout_guard -- \
          --artifact-dir "${run_dir}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --run-id "${run_id}" \
          --generated-at-utc "${generated_at_utc}" \
          --source-commit "${source_commit}" \
          --toolchain "${toolchain}" \
          --summary
      verify_bundle
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin franken_seqlock_rollout_guard" \
        cargo check -p frankenengine-engine --bin franken_seqlock_rollout_guard
      run_step "cargo check -p frankenengine-engine --test seqlock_rollout_guard" \
        cargo check -p frankenengine-engine --test seqlock_rollout_guard
      run_step "cargo test -p frankenengine-engine --lib seqlock_rollout_guard" \
        cargo test -p frankenengine-engine --lib seqlock_rollout_guard
      run_step "cargo test -p frankenengine-engine --test seqlock_rollout_guard" \
        cargo test -p frankenengine-engine --test seqlock_rollout_guard
      run_step "cargo clippy -p frankenengine-engine --bin franken_seqlock_rollout_guard -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_seqlock_rollout_guard -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --test seqlock_rollout_guard -- -D warnings" \
        cargo clippy -p frankenengine-engine --test seqlock_rollout_guard -- -D warnings
      run_step "cargo run -p frankenengine-engine --bin franken_seqlock_rollout_guard -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_seqlock_rollout_guard -- \
          --artifact-dir "${run_dir}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --run-id "${run_id}" \
          --generated-at-utc "${generated_at_utc}" \
          --source-commit "${source_commit}" \
          --toolchain "${toolchain}" \
          --summary
      verify_bundle
      ;;
    *)
      echo "usage: $0 [check|test|clippy|run|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome dirty_worktree error_code_json idx comma
  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-621C-SUITE-0001"'
  fi

  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${suite_commands_path}"
  {
    echo "{\"schema_version\":\"franken-engine.rgc-seqlock-rollout-guard.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"seqlock_rollout_guard_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-seqlock-rollout-run-manifest.v1",'
    echo '  "component": "seqlock_rollout_guard",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"rch_exec_timeout_seconds\": ${rch_exec_timeout_seconds},"
    echo "  \"rch_build_timeout_sec\": ${rch_build_timeout_sec},"
    echo "  \"git_commit\": \"${source_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${generated_at_utc}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "${failed_command}" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    if [[ -n "${failed_step_log_path}" ]]; then
      echo "  \"failed_step_log\": \"${failed_step_log_path}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$((${#commands_run[@]} - 1))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${suite_commands_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo "    \"safety_case\": \"${run_dir}/seqlock_safety_case.json\","
    echo "    \"starvation_report\": \"${run_dir}/starvation_microbench_report.json\","
    echo "    \"loom_coverage\": \"${run_dir}/loom_schedule_coverage_report.json\","
    echo "    \"rollout_guard\": \"${run_dir}/seqlock_rollout_guard.json\","
    echo "    \"runner_manifest\": \"${run_dir}/run_manifest.json\","
    echo "    \"suite_manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${run_dir}/seqlock_safety_case.json\","
    echo "    \"cat ${run_dir}/seqlock_rollout_guard.json\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${manifest_path}\","
    echo "    \"ls -1 ${step_logs_dir}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

trap 'write_manifest $?' EXIT
run_mode
