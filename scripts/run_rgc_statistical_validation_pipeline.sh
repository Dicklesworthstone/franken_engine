#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_statistical_validation_pipeline}"
artifact_root="${RGC_STATISTICAL_VALIDATION_ARTIFACT_ROOT:-artifacts/rgc_statistical_validation_pipeline}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
summary_path="${run_dir}/summary.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
step_logs_dir="${run_dir}/step_logs"
support_bundle_dir="${run_dir}/support_bundle"
stats_report_path="${support_bundle_dir}/stats_verdict_report.json"

trace_id="trace-rgc-statistical-validation-pipeline-${timestamp}"
decision_id="decision-rgc-statistical-validation-pipeline-${timestamp}"
policy_id="policy-rgc-statistical-validation-pipeline-v1"
component="rgc_statistical_validation_pipeline_gate"
scenario_id="rgc-702"
replay_command="./scripts/e2e/rgc_statistical_validation_pipeline_replay.sh ${mode}"

mkdir -p "$run_dir" "$support_bundle_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC statistical validation pipeline heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -q -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"
  if rg -q 'Remote command finished: exit=0|Finished `dev` profile|Finished `test` profile|test result: ok\.' "$log_path" \
    && ! rg -qi 'error(\[[[:alnum:]]+\])?:' "$log_path"; then
    return 0
  fi
  return 1
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local step_log_path="${step_logs_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  shift

  commands_run+=("$command_text")
  step_logs+=("$step_log_path")
  echo "==> $command_text"

  set +e
  run_rch "$@" > >(tee "$step_log_path") 2>&1
  local status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    if [[ "$status" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$step_log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$step_log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$step_log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi
}

run_mode() {
  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --test rgc_statistical_validation_pipeline --test performance_statistical_validation_integration" \
      cargo check -p frankenengine-engine \
      --test rgc_statistical_validation_pipeline \
      --test performance_statistical_validation_integration
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test rgc_statistical_validation_pipeline --test performance_statistical_validation_integration" \
      cargo test -p frankenengine-engine \
      --test rgc_statistical_validation_pipeline \
      --test performance_statistical_validation_integration
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --test rgc_statistical_validation_pipeline --test performance_statistical_validation_integration -- -D warnings" \
      cargo clippy -p frankenengine-engine \
      --test rgc_statistical_validation_pipeline \
      --test performance_statistical_validation_integration \
      -- -D warnings
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --test rgc_statistical_validation_pipeline --test performance_statistical_validation_integration" \
      cargo check -p frankenengine-engine \
      --test rgc_statistical_validation_pipeline \
      --test performance_statistical_validation_integration
    run_step "cargo test -p frankenengine-engine --test rgc_statistical_validation_pipeline --test performance_statistical_validation_integration" \
      cargo test -p frankenengine-engine \
      --test rgc_statistical_validation_pipeline \
      --test performance_statistical_validation_integration
    run_step "cargo clippy -p frankenengine-engine --test rgc_statistical_validation_pipeline --test performance_statistical_validation_integration -- -D warnings" \
      cargo clippy -p frankenengine-engine \
      --test rgc_statistical_validation_pipeline \
      --test performance_statistical_validation_integration \
      -- -D warnings
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
  esac
}

write_support_bundle() {
  local outcome="$1"

  cat >"${stats_report_path}" <<EOF_REPORT
{"schema_version":"franken-engine.rgc-statistical-validation-pipeline.stats-report.v1","trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","scenario_id":"${scenario_id}","outcome":"${outcome}","failed_command":"$(parser_frontier_json_escape "${failed_command}")"}
EOF_REPORT
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{"schema_version":"franken-engine.rgc-statistical-validation-pipeline.trace-ids.v1","trace_ids":["${trace_id}"],"decision_ids":["${decision_id}"],"policy_ids":["${policy_id}"],"scenario_id":"${scenario_id}"}
EOF_TRACE
}

write_env_bundle() {
  cat >"${env_path}" <<EOF_ENV
{"schema_version":"franken-engine.rgc-statistical-validation-pipeline.env.v1","bead_id":"bd-1lsy.8.2","mode":"${mode}","toolchain":"${toolchain}","cargo_target_dir":"${target_dir}","artifact_root":"${artifact_root}","root_dir":"${root_dir}","pwd":"${PWD}","rch_exec_timeout_seconds":${rch_timeout_seconds},"runner":"scripts/run_rgc_statistical_validation_pipeline.sh","replay_wrapper":"scripts/e2e/rgc_statistical_validation_pipeline_replay.sh","generated_at_utc":"${timestamp}"}
EOF_ENV
}

write_repro_lock() {
  local git_commit="$1"

  cat >"${repro_lock_path}" <<EOF_LOCK
schema_version=franken-engine.rgc-statistical-validation-pipeline.repro-lock.v1
bead_id=bd-1lsy.8.2
mode=${mode}
toolchain=${toolchain}
cargo_target_dir=${target_dir}
git_commit=${git_commit}
runner=scripts/run_rgc_statistical_validation_pipeline.sh
replay_wrapper=scripts/e2e/rgc_statistical_validation_pipeline_replay.sh
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
generated_at_utc=${timestamp}
EOF_LOCK
}

write_summary() {
  local outcome="$1"

  cat >"${summary_path}" <<EOF_SUMMARY
# RGC Statistical Validation Pipeline

- bead: \`bd-1lsy.8.2\`
- scenario: \`${scenario_id}\`
- outcome: \`${outcome}\`
- trace_id: \`${trace_id}\`
- decision_id: \`${decision_id}\`
- policy_id: \`${policy_id}\`
- cargo_target_dir: \`${target_dir}\`
- stats_report: \`${stats_report_path}\`
- replay: \`${replay_command}\`
- failed_command: \`${failed_command:-none}\`
EOF_SUMMARY
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
    error_code_json='"FE-RGC-702-GATE-0001"'
  fi

  write_support_bundle "$outcome"
  write_trace_ids
  write_env_bundle

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi
  write_repro_lock "$git_commit"
  write_summary "$outcome"

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-statistical-validation-pipeline.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"path_type\":\"golden\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-statistical-validation-pipeline.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.8.2",'
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
    echo "    \"trace_ids\": \"${trace_ids_path}\"," 
    echo "    \"summary\": \"${summary_path}\"," 
    echo "    \"env\": \"${env_path}\"," 
    echo "    \"repro_lock\": \"${repro_lock_path}\"," 
    echo "    \"step_logs\": \"${step_logs_dir}\"," 
    echo "    \"stats_verdict_report\": \"${stats_report_path}\"," 
    echo '    "contract_doc": "docs/RGC_STATISTICAL_VALIDATION_PIPELINE_V1.md",'
    echo '    "contract_json": "docs/rgc_statistical_validation_pipeline_v1.json",'
    echo '    "gate_tests": ['
    echo '      "crates/franken-engine/tests/rgc_statistical_validation_pipeline.rs",'
    echo '      "crates/franken-engine/tests/performance_statistical_validation_integration.rs"'
    echo '    ]'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${trace_ids_path}\"," 
    echo "    \"cat ${summary_path}\"," 
    echo "    \"cat ${env_path}\"," 
    echo "    \"cat ${repro_lock_path}\"," 
    echo '    "jq empty docs/rgc_statistical_validation_pipeline_v1.json",'
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc statistical validation manifest: ${manifest_path}"
  echo "rgc statistical validation events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
