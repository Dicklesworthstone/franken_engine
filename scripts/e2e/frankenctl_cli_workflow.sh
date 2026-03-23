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
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"

trace_id="trace-frankenctl-cli-workflow-${timestamp}"
decision_id="decision-frankenctl-cli-workflow-${timestamp}"
policy_id="policy-frankenctl-cli-workflow-v1"
component="frankenctl_cli_workflow_gate"
scenario_id="bd-1lsy.10.1"
replay_command="./scripts/e2e/frankenctl_cli_workflow.sh ${mode}"

mkdir -p "$run_dir"

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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rch_strip_ansi "$log_path" | rg -q "Remote command finished: exit=0"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
    rm -f "$log_path"
    failed_command="${command_text} (missing-remote-exit-marker)"
    return 1
  fi
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi

  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli" \
        cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test frankenctl_cli" \
        cargo test -p frankenengine-engine --test frankenctl_cli
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli" \
        cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli
      run_step "cargo test -p frankenengine-engine --test frankenctl_cli" \
        cargo test -p frankenengine-engine --test frankenctl_cli
      run_step "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings
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
    '{
      schema_version: "franken-engine.frankenctl.cli.workflow.trace-ids.v1",
      bead_id: "bd-1lsy.10.1",
      component: $component,
      scenario_id: $scenario_id,
      trace_ids: [$trace_id],
      decision_ids: [$decision_id],
      policy_ids: [$policy_id],
      artifact_paths: {
        run_manifest: $manifest_path,
        events: $events_path,
        commands: $commands_path
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
    echo '    "frankenctl_bin": "crates/franken-engine/src/bin/frankenctl.rs",'
    echo '    "frankenctl_integration_test": "crates/franken-engine/tests/frankenctl_cli.rs",'
    echo '    "replay_wrapper": "scripts/e2e/frankenctl_cli_workflow.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "frankenctl workflow manifest: ${manifest_path}"
  echo "frankenctl workflow trace ids: ${trace_ids_path}"
  echo "frankenctl workflow events: ${events_path}"
  echo "frankenctl workflow commands: ${commands_path}"
}

main_exit=0
run_mode || main_exit=$?
write_trace_ids
write_manifest "$main_exit"
exit "$main_exit"
