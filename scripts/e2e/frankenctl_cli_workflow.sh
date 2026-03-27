#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_frankenctl_cli_workflow}"
artifact_root="${FRANKENCTL_CLI_ARTIFACT_ROOT:-artifacts/frankenctl_cli_workflow}"
explicit_replay_run_dir="${FRANKENCTL_CLI_WORKFLOW_REPLAY_RUN_DIR:-}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
doctor_input_path="${run_dir}/doctor_input.json"
support_bundle_dir="${run_dir}/support_bundle"
support_preflight_path="${support_bundle_dir}/preflight_report.json"
support_scorecard_path="${support_bundle_dir}/onboarding_scorecard.json"
support_rollout_path="${support_bundle_dir}/rollout_decision_artifact.json"
support_doctor_report_path="${support_bundle_dir}/frankenctl_doctor_report.json"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-frankenctl-cli-workflow-${timestamp}"
decision_id="decision-frankenctl-cli-workflow-${timestamp}"
policy_id="policy-frankenctl-cli-workflow-v1"
doctor_trace_id="trace-frankenctl-cli-workflow-doctor-${timestamp}"
doctor_decision_id="decision-frankenctl-cli-workflow-doctor-${timestamp}"
doctor_policy_id="policy-frankenctl-cli-workflow-doctor-v1"
component="frankenctl_cli_workflow_gate"
scenario_id="bd-1lsy.10.1"
replay_command="FRANKENCTL_CLI_WORKFLOW_REPLAY_RUN_DIR=\"${run_dir}\" ./scripts/e2e/frankenctl_cli_workflow.sh ${mode}"

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/step_logs/step_000.log" ]] || return 1
}

replay_existing_run_dir() {
  local candidate="${1:-}"
  if ! run_dir_is_complete "${candidate}"; then
    echo "frankenctl workflow replay could not use explicit run directory; explicit run directory is incomplete: ${candidate}" >&2
    exit 1
  fi

  echo "frankenctl workflow replay manifest: ${candidate}/run_manifest.json"
  cat "${candidate}/run_manifest.json"
  echo "frankenctl workflow replay trace ids: ${candidate}/trace_ids.json"
  cat "${candidate}/trace_ids.json"
  echo "frankenctl workflow replay events: ${candidate}/events.jsonl"
  cat "${candidate}/events.jsonl"
  echo "frankenctl workflow replay commands: ${candidate}/commands.txt"
  cat "${candidate}/commands.txt"
  echo "frankenctl workflow replay first step log: ${candidate}/step_logs/step_000.log"
  cat "${candidate}/step_logs/step_000.log"
}

if [[ -n "${explicit_replay_run_dir}" ]]; then
  replay_existing_run_dir "${explicit_replay_run_dir}"
  exit 0
fi

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for frankenctl CLI workflow heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -q -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
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

emit_operator_verification_entry() {
  local command_text="$1"
  local suffix="${2:-}"
  echo "    \"$(parser_frontier_json_escape "${command_text}")\"${suffix}"
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local log_path remote_exit_code status
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))

  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    if [[ "$status" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
    failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    return 1
  fi
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

write_doctor_input() {
  cat >"$doctor_input_path" <<EOF
{
  "trace_id": "${doctor_trace_id}",
  "decision_id": "${doctor_decision_id}",
  "policy_id": "${doctor_policy_id}",
  "runtime_state": {
    "snapshot_timestamp_ns": 42000,
    "loaded_extensions": [
      {
        "extension_id": "frankenctl-cli-workflow",
        "containment_state": "running"
      }
    ],
    "active_policies": [
      "${doctor_policy_id}",
      "${policy_id}"
    ],
    "security_epoch": 7,
    "gc_pressure": [
      {
        "extension_id": "frankenctl-cli-workflow",
        "used_bytes": 64,
        "budget_bytes": 8192
      }
    ],
    "scheduler_lanes": [
      {
        "lane": "ready",
        "queue_depth": 0,
        "max_depth": 32,
        "tasks_submitted": 8,
        "tasks_scheduled": 8,
        "tasks_completed": 8,
        "tasks_timed_out": 0
      }
    ]
  },
  "evidence_entries": [],
  "hostcall_records": [],
  "containment_receipts": [],
  "replay_artifacts": []
}
EOF
}

run_artifact_flow() {
  write_doctor_input

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- doctor --input ${doctor_input_path} --out-dir ${run_dir}" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- doctor \
      --input "${doctor_input_path}" \
      --out-dir "${run_dir}"

  for required_path in \
    "${doctor_input_path}" \
    "${support_preflight_path}" \
    "${support_scorecard_path}" \
    "${support_rollout_path}" \
    "${support_doctor_report_path}"; do
    if [[ ! -f "${required_path}" ]]; then
      echo "required artifact missing: ${required_path}" >&2
      failed_command="artifact_presence_check (${required_path})"
      return 1
    fi
  done
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli" \
        cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli
      run_artifact_flow
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test frankenctl_cli" \
        cargo test -p frankenengine-engine --test frankenctl_cli
      run_artifact_flow
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings
      run_artifact_flow
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli" \
        cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli
      run_step "cargo test -p frankenengine-engine --test frankenctl_cli" \
        cargo test -p frankenengine-engine --test frankenctl_cli
      run_step "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings
      run_artifact_flow
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
    --arg doctor_trace_id "$doctor_trace_id" \
    --arg doctor_decision_id "$doctor_decision_id" \
    --arg doctor_policy_id "$doctor_policy_id" \
    --arg component "$component" \
    --arg scenario_id "$scenario_id" \
    --arg manifest_path "$manifest_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg doctor_input_path "$doctor_input_path" \
    --arg support_bundle_dir "$support_bundle_dir" \
    '{
      schema_version: "franken-engine.frankenctl.cli.workflow.trace-ids.v1",
      bead_id: "bd-1lsy.10.1",
      component: $component,
      scenario_id: $scenario_id,
      trace_ids: [$trace_id, $doctor_trace_id],
      decision_ids: [$decision_id, $doctor_decision_id],
      policy_ids: [$policy_id, $doctor_policy_id],
      artifact_paths: {
        run_manifest: $manifest_path,
        events: $events_path,
        commands: $commands_path,
        doctor_input: $doctor_input_path,
        support_bundle_root: $support_bundle_dir
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
    error_code_json='"FE-RGC-901-FRANKENCTL-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"frankenctl.cli.workflow.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "frankenctl.cli.workflow.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.10.1",'
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
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    "
    echo "  },"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"step_logs\": \"${step_logs_dir}\","
    echo "    \"first_step_log\": \"${step_logs_dir}/step_000.log\","
    echo "    \"doctor_input\": \"${doctor_input_path}\","
    echo '    "support_bundle": ['
    echo '      "support_bundle/preflight_report.json",'
    echo '      "support_bundle/onboarding_scorecard.json",'
    echo '      "support_bundle/rollout_decision_artifact.json",'
    echo '      "support_bundle/frankenctl_doctor_report.json"'
    echo '    ],'
    echo '    "frankenctl_bin": "crates/franken-engine/src/bin/frankenctl.rs",'
    echo '    "frankenctl_integration_test": "crates/franken-engine/tests/frankenctl_cli.rs",'
    echo '    "replay_wrapper": "scripts/e2e/frankenctl_cli_workflow.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    emit_operator_verification_entry "cat \"${manifest_path}\"" ","
    emit_operator_verification_entry "cat \"${trace_ids_path}\"" ","
    emit_operator_verification_entry "cat \"${events_path}\"" ","
    emit_operator_verification_entry "cat \"${commands_path}\"" ","
    emit_operator_verification_entry "cat \"${step_logs_dir}/step_000.log\"" ","
    emit_operator_verification_entry "cargo run -q -p frankenengine-engine --bin frankenctl -- doctor --input ${doctor_input_path} --out-dir ${run_dir}" ","
    emit_operator_verification_entry "cat \"${support_preflight_path}\"" ","
    emit_operator_verification_entry "cat \"${support_scorecard_path}\"" ","
    emit_operator_verification_entry "cat \"${support_rollout_path}\"" ","
    emit_operator_verification_entry "cat \"${support_doctor_report_path}\"" ","
    emit_operator_verification_entry "${replay_command}"
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "frankenctl workflow manifest: ${manifest_path}"
  echo "frankenctl workflow trace ids: ${trace_ids_path}"
  echo "frankenctl workflow events: ${events_path}"
  echo "frankenctl workflow commands: ${commands_path}"
  echo "frankenctl workflow first step log: ${step_logs_dir}/step_000.log"
  echo "frankenctl workflow replay command: ${replay_command}"
}

main_exit=0
run_mode || main_exit=$?
write_trace_ids
write_manifest "$main_exit"
exit "$main_exit"
