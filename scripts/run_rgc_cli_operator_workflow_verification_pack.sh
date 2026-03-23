#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_cli_operator_workflow_verification_pack}"
artifact_root="${RGC_CLI_OPERATOR_WORKFLOW_ARTIFACT_ROOT:-artifacts/rgc_cli_operator_workflow_verification_pack}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-rgc-cli-operator-workflow-verification-pack-${timestamp}"
decision_id="decision-rgc-cli-operator-workflow-verification-pack-${timestamp}"
policy_id="policy-rgc-cli-operator-workflow-verification-pack-v1"
component="rgc_cli_operator_workflow_verification_pack_gate"
scenario_id="rgc-061"
replay_command="./scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC CLI/operator workflow verification pack heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
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

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local step_log_path="${step_logs_dir}/step_$(printf '%03d' "$step_log_index").log"
  local status remote_exit_code
  step_log_index=$((step_log_index + 1))
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"

  set +e
  run_rch "$@" > >(tee "$step_log_path") 2>&1
  status=$?
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
      remote_exit_code="$(rch_remote_exit_code "$step_log_path" || true)"
      if [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
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
    run_step "cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    run_step "cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    run_step "cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
  esac
}

write_trace_ids() {
  jq -n \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg scenario_id "$scenario_id" \
    --arg manifest_path "$manifest_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg first_step_log "${step_logs_dir}/step_000.log" \
    '{
      schema_version: "franken-engine.rgc-cli-operator-workflow-verification-pack.trace-ids.v1",
      bead_id: "bd-1lsy.11.11",
      component: $component,
      scenario_id: $scenario_id,
      trace_ids: [$trace_id],
      decision_ids: [$decision_id],
      policy_ids: [$policy_id],
      artifact_paths: {
        run_manifest: $manifest_path,
        events: $events_path,
        commands: $commands_path,
        first_step_log: $first_step_log
      }
    }' >"$trace_ids_path"
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
    error_code_json='"FE-RGC-061-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-cli-operator-workflow-verification-pack.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"path_type\":\"golden\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-cli-operator-workflow-verification-pack.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.11",'
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
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo "    \"step_logs\": \"${step_logs_dir}\","
    echo "    \"first_step_log\": \"${step_logs_dir}/step_000.log\","
    echo '    "contract_doc": "docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md",'
    echo '    "contract_json": "docs/rgc_cli_operator_workflow_verification_pack_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/rgc_cli_operator_workflow_verification_pack.rs",'
    echo '    "runtime_cli_tests": "crates/franken-engine/tests/runtime_diagnostics_cli.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${step_logs_dir}/step_000.log\","
    echo '    "jq empty docs/rgc_cli_operator_workflow_verification_pack_v1.json",'
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc cli/operator workflow verification pack manifest: ${manifest_path}"
  echo "rgc cli/operator workflow verification pack trace ids: ${trace_ids_path}"
  echo "rgc cli/operator workflow verification pack events: ${events_path}"
  echo "rgc cli/operator workflow verification pack first step log: ${step_logs_dir}/step_000.log"
}

main_exit=0
run_mode || main_exit=$?
write_trace_ids
write_manifest "$main_exit"
exit "$main_exit"
