#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
uid="$(id -u)"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/.rch_target/rgc_execution_waves_uid${uid}_${mode}_${timestamp}_$$}"
artifact_root="${RGC_EXECUTION_WAVES_ARTIFACT_ROOT:-artifacts/rgc_execution_waves_coordination}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-rgc-execution-waves-${timestamp}"
decision_id="decision-rgc-execution-waves-${timestamp}"
policy_id="policy-rgc-execution-waves-v1"
component="rgc_execution_waves_coordination_gate"
replay_command="./scripts/e2e/rgc_execution_waves_coordination_replay.sh ${mode}"

mkdir -p "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC execution-wave coordination heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(
    rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true
  )"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: Project sync failed|running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \('; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
declare -a step_log_paths=()
failed_command=""
manifest_written=false
dry_run_attempted=false
dry_run_validated=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code rch_exit_code step_number
  shift

  step_number=$(( ${#commands_run[@]} + 1 ))
  commands_run+=("$command_text")
  log_path="${step_logs_dir}/step_$(printf '%02d' "$step_number").log"
  : >"$log_path"
  printf '==> %s\n' "$command_text" | tee -a "$log_path"
  step_log_paths+=("$log_path")
  rch_exit_code=0

  if run_rch "$@" > >(tee -a "$log_path") 2>&1; then
    :
  else
    rch_exit_code=$?
    if rch_strip_ansi "$log_path" | rg -q "Remote command finished: exit=0"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (rch-exit=${rch_exit_code}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${rch_exit_code}; missing-remote-exit-marker)"
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
    failed_command="${command_text} (missing-remote-exit-marker)"
    return 1
  fi

  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test rgc_execution_waves_integration" \
        cargo check -p frankenengine-engine --test rgc_execution_waves_integration || return $?
      run_step "cargo check -p frankenengine-engine --test rgc_execution_waves_enrichment_integration" \
        cargo check -p frankenengine-engine --test rgc_execution_waves_enrichment_integration || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test rgc_execution_waves_integration" \
        cargo test -p frankenengine-engine --test rgc_execution_waves_integration || return $?
      run_step "cargo test -p frankenengine-engine --test rgc_execution_waves_enrichment_integration" \
        cargo test -p frankenengine-engine --test rgc_execution_waves_enrichment_integration || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_execution_waves_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_execution_waves_integration -- -D warnings || return $?
      run_step "cargo clippy -p frankenengine-engine --test rgc_execution_waves_enrichment_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_execution_waves_enrichment_integration -- -D warnings || return $?
      ;;
    dry-run)
      dry_run_attempted=true
      run_step "cargo test -p frankenengine-engine --test rgc_execution_waves_integration -- --exact rgc_execution_waves_dry_run_emits_required_coordination_events" \
        cargo test -p frankenengine-engine --test rgc_execution_waves_integration -- --exact rgc_execution_waves_dry_run_emits_required_coordination_events || return $?
      dry_run_validated=true
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_execution_waves_integration" \
        cargo check -p frankenengine-engine --test rgc_execution_waves_integration || return $?
      run_step "cargo check -p frankenengine-engine --test rgc_execution_waves_enrichment_integration" \
        cargo check -p frankenengine-engine --test rgc_execution_waves_enrichment_integration || return $?
      run_step "cargo test -p frankenengine-engine --test rgc_execution_waves_integration" \
        cargo test -p frankenengine-engine --test rgc_execution_waves_integration || return $?
      run_step "cargo test -p frankenengine-engine --test rgc_execution_waves_enrichment_integration" \
        cargo test -p frankenengine-engine --test rgc_execution_waves_enrichment_integration || return $?
      run_step "cargo clippy -p frankenengine-engine --test rgc_execution_waves_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_execution_waves_integration -- -D warnings || return $?
      run_step "cargo clippy -p frankenengine-engine --test rgc_execution_waves_enrichment_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_execution_waves_enrichment_integration -- -D warnings || return $?
      dry_run_attempted=true
      run_step "cargo test -p frankenengine-engine --test rgc_execution_waves_integration -- --exact rgc_execution_waves_dry_run_emits_required_coordination_events" \
        cargo test -p frankenengine-engine --test rgc_execution_waves_integration -- --exact rgc_execution_waves_dry_run_emits_required_coordination_events || return $?
      dry_run_validated=true
      ;;
    *)
      echo "usage: $0 [check|test|clippy|dry-run|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma
  local dry_run_outcome dry_run_error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-EXECUTION-WAVES-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    if [[ "$dry_run_attempted" == true ]]; then
      if [[ "$dry_run_validated" == true ]]; then
        dry_run_outcome="pass"
        dry_run_error_code_json="null"
      else
        dry_run_outcome="fail"
        dry_run_error_code_json='"FE-RGC-EXECUTION-WAVES-0001"'
      fi
      echo "{\"schema_version\":\"franken-engine.rgc-coordination.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"protocol_dry_run_validated\",\"outcome\":\"${dry_run_outcome}\",\"error_code\":${dry_run_error_code_json}}"
    fi
    echo "{\"schema_version\":\"franken-engine.rgc-coordination.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-execution-waves.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.1.4",'
    echo '  "related_bead_id": "bd-1lsy.1.5",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
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
    echo '  "step_logs": ['
    for idx in "${!step_log_paths[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#step_log_paths[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${step_log_paths[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo '    "protocol_doc": "docs/RGC_EXECUTION_WAVE_PROTOCOL.md",'
    echo '    "module": "crates/franken-engine/src/rgc_execution_waves.rs",'
    echo '    "integration_tests": "crates/franken-engine/tests/rgc_execution_waves_integration.rs",'
    echo '    "enrichment_tests": "crates/franken-engine/tests/rgc_execution_waves_enrichment_integration.rs",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_execution_waves_coordination_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"ls -1 ${step_logs_dir}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "rgc execution-wave coordination manifest: ${manifest_path}"
  echo "rgc execution-wave coordination events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" \
  --events "$events_path" \
  --schema-prefix "franken-engine.rgc-coordination"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
