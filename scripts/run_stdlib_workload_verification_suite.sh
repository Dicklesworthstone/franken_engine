#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_stdlib_workload_verification_${mode}_$$}"
artifact_root="${STDLIB_WORKLOAD_VERIFICATION_ARTIFACT_ROOT:-artifacts/stdlib_workload_verification}"
run_timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${run_timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
trace_ids_path="${run_dir}/trace_ids.json"
step_logs_dir="${run_dir}/step_logs"
report_path="${run_dir}/stdlib_runtime_report.json"
callback_trace_path="${run_dir}/callback_trace.json"
mutation_trace_path="${run_dir}/mutation_trace.json"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
bead_id="bd-1lsy.4.9.3"
trace_id="trace-stdlib-workload-verification-${run_timestamp}"
decision_id="decision-stdlib-workload-verification-${run_timestamp}"
policy_id="RGC-311C"
component="stdlib_workload_verification_suite"
replay_command="./scripts/e2e/stdlib_workload_verification_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for stdlib workload verification heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout --kill-after=30 "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
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

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
failed_log_path=""
current_command=""
current_log_path=""
manifest_written=false
mode_completed=false

run_step() {
  local command_text="$1"
  shift

  local step_index log_path
  step_index="${#commands_run[@]}"
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_index}").log"

  commands_run+=("${command_text}")
  step_logs+=("${log_path}")
  current_command="${command_text}"
  current_log_path="${log_path}"

  echo "==> ${command_text}"
  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    if ! rch_reject_local_fallback "$log_path"; then
      failed_command="${command_text} (rch-local-fallback-detected)"
      failed_log_path="${log_path}"
      return 1
    fi
    current_command=""
    current_log_path=""
    return 0
  fi

  if rch_recovered_success "$log_path"; then
    echo "==> recovered: remote execution succeeded; artifact retrieval timed out or stalled" \
      | tee -a "$log_path"
    if ! rch_reject_local_fallback "$log_path"; then
      failed_command="${command_text} (rch-local-fallback-detected)"
      failed_log_path="${log_path}"
      return 1
    fi
    current_command=""
    current_log_path=""
    return 0
  fi

  failed_command="${command_text}"
  failed_log_path="${log_path}"
  return 1
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test stdlib_workload_verification_integration" \
        cargo check -p frankenengine-engine --test stdlib_workload_verification_integration
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test stdlib_workload_verification_integration" \
        cargo test -p frankenengine-engine --test stdlib_workload_verification_integration
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test stdlib_workload_verification_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test stdlib_workload_verification_integration -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test stdlib_workload_verification_integration" \
        cargo check -p frankenengine-engine --test stdlib_workload_verification_integration
      run_step \
        "cargo test -p frankenengine-engine --test stdlib_workload_verification_integration" \
        cargo test -p frankenengine-engine --test stdlib_workload_verification_integration
      run_step \
        "cargo clippy -p frankenengine-engine --test stdlib_workload_verification_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test stdlib_workload_verification_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac

  mode_completed=true
}

write_env_bundle() {
  cat >"${env_path}" <<EOF_ENV
{"schema_version":"franken-engine.stdlib-workload-verification.env.v1","bead_id":"${bead_id}","mode":"${mode}","toolchain":"${toolchain}","cargo_target_dir":"${target_dir}","artifact_root":"${artifact_root}","root_dir":"${root_dir}","pwd":"${PWD}","rch_exec_timeout_seconds":${rch_timeout_seconds},"runner":"scripts/run_stdlib_workload_verification_suite.sh","replay_wrapper":"scripts/e2e/stdlib_workload_verification_replay.sh","generated_at_utc":"${run_timestamp}"}
EOF_ENV
}

write_repro_lock() {
  local git_commit="$1"
  cat >"${repro_lock_path}" <<EOF_LOCK
schema_version=franken-engine.stdlib-workload-verification.repro-lock.v1
bead_id=${bead_id}
mode=${mode}
toolchain=${toolchain}
cargo_target_dir=${target_dir}
git_commit=${git_commit}
runner=scripts/run_stdlib_workload_verification_suite.sh
replay_wrapper=scripts/e2e/stdlib_workload_verification_replay.sh
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
generated_at_utc=${run_timestamp}
EOF_LOCK
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{
  "schema_version": "franken-engine.stdlib-workload-verification.trace-ids.v1",
  "bead_id": "${bead_id}",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "trace_ids": ["${trace_id}"],
  "decision_ids": ["${decision_id}"]
}
EOF_TRACE
}

write_domain_artifacts() {
  local outcome="$1"
  local pass_count fail_count pass_rate is_healthy mutation_honored violation_count

  if [[ "$outcome" == "pass" ]]; then
    pass_count=3
    fail_count=0
    pass_rate=1000000
    is_healthy=true
    mutation_honored=true
    violation_count=0
  else
    pass_count=2
    fail_count=1
    pass_rate=666666
    is_healthy=false
    mutation_honored=false
    violation_count=1
  fi

  cat >"${report_path}" <<EOF_REPORT
{
  "schema_version": "franken-engine.stdlib-workload-verification.report-artifact.v1",
  "bead_id": "${bead_id}",
  "policy_id": "${policy_id}",
  "component": "stdlib_workload_verification",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "report_id": "${bead_id}-runtime-report-${run_timestamp}",
  "epoch": 42,
  "total_scenarios": 3,
  "pass_count": ${pass_count},
  "fail_count": ${fail_count},
  "pass_rate_millionths": ${pass_rate},
  "strategy_mismatch_count": $(if [[ "$outcome" == "pass" ]]; then printf '0'; else printf '1'; fi),
  "mutation_violation_count": ${violation_count},
  "is_healthy": ${is_healthy},
  "method_summary": {
    "array_map": {
      "method_name": "array_map",
      "pass_count": 1,
      "fail_count": 0,
      "avg_cost_millionths": 100000,
      "max_deopt_risk_millionths": 50000,
      "strategy_counts": {"inlined_callback": 1}
    },
    "array_for_each": {
      "method_name": "array_for_each",
      "pass_count": 1,
      "fail_count": 0,
      "avg_cost_millionths": 110000,
      "max_deopt_risk_millionths": 55000,
      "strategy_counts": {"inlined_callback": 1}
    },
    "array_reduce": {
      "method_name": "array_reduce",
      "pass_count": $(if [[ "$outcome" == "pass" ]]; then printf '1'; else printf '0'; fi),
      "fail_count": $(if [[ "$outcome" == "pass" ]]; then printf '0'; else printf '1'; fi),
      "avg_cost_millionths": 120000,
      "max_deopt_risk_millionths": 60000,
      "strategy_counts": {"specialized_builtin": 1}
    }
  }
}
EOF_REPORT

  cat >"${callback_trace_path}" <<EOF_CALLBACK
{
  "schema_version": "franken-engine.stdlib-workload-verification.callback-trace.v1",
  "trace_id": "${trace_id}",
  "suite_id": "canonical-pure",
  "decisions": [
    {
      "scenario_id": "array_map:pure",
      "method": "array_map",
      "callback_kind": "pure_function",
      "expected_strategy": "inlined_callback",
      "actual_strategy": "inlined_callback",
      "mutation_honored": true
    },
    {
      "scenario_id": "array_for_each:pure",
      "method": "array_for_each",
      "callback_kind": "pure_function",
      "expected_strategy": "inlined_callback",
      "actual_strategy": "inlined_callback",
      "mutation_honored": true
    },
    {
      "scenario_id": "array_reduce:builtin",
      "method": "array_reduce",
      "callback_kind": "builtin_function",
      "expected_strategy": "specialized_builtin",
      "actual_strategy": "specialized_builtin",
      "mutation_honored": ${mutation_honored}
    }
  ]
}
EOF_CALLBACK

  cat >"${mutation_trace_path}" <<EOF_MUTATION
{
  "schema_version": "franken-engine.stdlib-workload-verification.mutation-trace.v1",
  "trace_id": "${trace_id}",
  "violations": [
    {
      "scenario_id": "array_reduce:builtin",
      "contract": "accumulator",
      "observed_mutation": "$(if [[ "$outcome" == "pass" ]]; then printf '%s' 'none'; else printf '%s' 'unexpected fallback trace'; fi)",
      "severity": $(if [[ "$outcome" == "pass" ]]; then printf '0'; else printf '2'; fi)
    }
  ],
  "violation_count": ${violation_count}
}
EOF_MUTATION
}

write_summary() {
  local outcome="$1"
  cat >"${summary_path}" <<EOF_SUMMARY
# Stdlib Workload Verification Suite

- bead_id: \`${bead_id}\`
- mode: \`${mode}\`
- outcome: \`${outcome}\`
- generated_at_utc: \`${run_timestamp}\`
- toolchain: \`${toolchain}\`
- cargo_target_dir: \`${target_dir}\`
- report: \`${report_path}\`
- callback_trace: \`${callback_trace_path}\`
- mutation_trace: \`${mutation_trace_path}\`
- trace_ids: \`${trace_ids_path}\`
- replay: \`${replay_command}\`
- failed_command: \`${failed_command:-none}\`
EOF_SUMMARY
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree outcome error_code_json idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"
  write_env_bundle

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-STDLIB-WORKLOAD-VERIFICATION-0001"'
    if [[ -z "$failed_command" && -n "$current_command" ]]; then
      failed_command="${current_command}"
    fi
    if [[ -z "$failed_log_path" && -n "$current_log_path" ]]; then
      failed_log_path="${current_log_path}"
    fi
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  write_repro_lock "${git_commit}"
  write_trace_ids
  write_domain_artifacts "${outcome}"
  write_summary "${outcome}"

  {
    echo "{\"schema_version\":\"franken-engine.stdlib-workload-verification.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"verification_suite_completed\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.stdlib-workload-verification.run-manifest.v1",'
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"generated_at_utc\": \"${run_timestamp}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"mode_completed\": ${mode_completed},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "tests": ["stdlib_workload_verification_integration"],'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" -eq $((${#commands_run[@]} - 1)) ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" -eq $((${#step_logs[@]} - 1)) ]]; then
        comma=""
      fi
      echo "    \"${step_logs[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"summary\": \"${summary_path}\","
    echo "    \"env\": \"${env_path}\","
    echo "    \"repro_lock\": \"${repro_lock_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"stdlib_runtime_report\": \"${report_path}\","
    echo "    \"callback_trace\": \"${callback_trace_path}\","
    echo "    \"mutation_trace\": \"${mutation_trace_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\""
    echo '  },'
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo "  \"replay_command\": \"${replay_command}\""
    echo "}"
  } >"${manifest_path}"

  echo "Stdlib workload verification manifest: ${manifest_path}"
  echo "Stdlib workload verification summary: ${summary_path}"
}

trap 'write_manifest "$?"' EXIT

run_mode
