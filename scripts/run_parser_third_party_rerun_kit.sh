#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
default_target_dir="${root_dir}/target_rch_parser_third_party_rerun_kit_${timestamp}_$$"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
artifact_root="${PARSER_RERUN_KIT_ARTIFACT_ROOT:-artifacts/parser_third_party_rerun_kit}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"
kit_index_path="${run_dir}/rerun_kit_index.json"
verifier_notes_path="${run_dir}/verifier_notes.md"

auto_discover_matrix="${PARSER_RERUN_KIT_AUTO_DISCOVER_MATRIX:-1}"
matrix_artifact_root="${PARSER_RERUN_KIT_MATRIX_ARTIFACT_ROOT:-artifacts/parser_cross_arch_repro_matrix}"
matrix_summary_path="${PARSER_RERUN_KIT_MATRIX_SUMMARY:-}"
matrix_deltas_path="${PARSER_RERUN_KIT_MATRIX_DELTAS:-}"
matrix_manifest_path="${PARSER_RERUN_KIT_MATRIX_MANIFEST:-}"
matrix_summary_source="missing"
matrix_deltas_source="missing"
matrix_manifest_source="missing"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-${rch_timeout_seconds}}}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"

trace_id="trace-parser-third-party-rerun-kit-${timestamp}"
decision_id="decision-parser-third-party-rerun-kit-${timestamp}"
policy_id="policy-parser-third-party-rerun-kit-v1"
component="parser_third_party_rerun_kit_gate"
replay_command="./scripts/e2e/parser_third_party_rerun_kit_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser third-party rerun kit heavy commands" >&2
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

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326'; then
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

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  rch_strip_ansi "$log_path" | grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts'
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23'; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
failed_step_log_path=""
step_counter=0
manifest_written=false
matrix_input_status="pending_upstream_matrix"
matrix_complete=false
critical_delta_count=-1
matrix_eval_error=""

find_latest_matrix_summary() {
  if [[ ! -d "$matrix_artifact_root" ]]; then
    return 0
  fi

  find "$matrix_artifact_root" -type f -name matrix_summary.json 2>/dev/null | sort | tail -n 1
}

resolve_matrix_input_from_run_dir() {
  local path_var_name="$1"
  local source_var_name="$2"
  local run_dir_path="$3"
  local filename="$4"
  local current_value="${!path_var_name:-}"
  local candidate_path=""

  if [[ -n "$current_value" ]]; then
    printf -v "$source_var_name" '%s' "env"
    return
  fi

  if [[ "$auto_discover_matrix" != "1" || -z "$run_dir_path" ]]; then
    printf -v "$source_var_name" '%s' "missing"
    return
  fi

  candidate_path="${run_dir_path}/${filename}"
  if [[ -f "$candidate_path" ]]; then
    printf -v "$path_var_name" '%s' "$candidate_path"
    printf -v "$source_var_name" '%s' "auto_discovered"
    return
  fi

  printf -v "$source_var_name" '%s' "missing"
}

auto_discover_matrix_inputs() {
  local discovered_summary="" matrix_run_dir=""

  if [[ -n "$matrix_summary_path" ]]; then
    matrix_summary_source="env"
    matrix_run_dir="$(dirname "$matrix_summary_path")"
  elif [[ "$auto_discover_matrix" == "1" ]]; then
    discovered_summary="$(find_latest_matrix_summary)"
    if [[ -n "$discovered_summary" ]]; then
      matrix_summary_path="$discovered_summary"
      matrix_summary_source="auto_discovered"
      matrix_run_dir="$(dirname "$discovered_summary")"
    fi
  fi

  resolve_matrix_input_from_run_dir \
    matrix_deltas_path \
    matrix_deltas_source \
    "$matrix_run_dir" \
    "matrix_lane_deltas.jsonl"
  resolve_matrix_input_from_run_dir \
    matrix_manifest_path \
    matrix_manifest_source \
    "$matrix_run_dir" \
    "run_manifest.json"
}

run_step() {
  local command_text="$1"
  local log_path run_rc remote_exit_code reported_timeout
  shift

  step_counter=$((step_counter + 1))
  log_path="${step_logs_dir}/step_${step_counter}.log"
  commands_run+=("$command_text")
  step_logs+=("$log_path")
  echo "==> $command_text"

  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    run_rc=0
  else
    run_rc=$?
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
    if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
      (( reported_timeout < rch_build_timeout_sec )); then
      echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
      failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
      failed_step_log_path="$log_path"
      return 1
    fi
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      if [[ "$run_rc" -eq 124 ]]; then
        failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      elif [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (remote-exit-${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit-${run_rc})"
      fi
      failed_step_log_path="$log_path"
      return 1
    fi
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
  if [[ "$remote_exit_code" != "0" ]]; then
    if [[ -z "$remote_exit_code" ]]; then
      echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
      failed_command="${command_text} (missing-remote-exit-marker)"
    else
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
    fi
    failed_step_log_path="$log_path"
    return 1
  fi
}

auto_discover_matrix_inputs

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo test --no-run -p frankenengine-engine --test parser_third_party_rerun_kit" \
        cargo test --no-run -p frankenengine-engine --test parser_third_party_rerun_kit || return 1
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test parser_third_party_rerun_kit" \
        cargo test -p frankenengine-engine --test parser_third_party_rerun_kit || return 1
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_third_party_rerun_kit -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_third_party_rerun_kit -- -D warnings || return 1
      ;;
    ci)
      run_step \
        "cargo test --no-run -p frankenengine-engine --test parser_third_party_rerun_kit" \
        cargo test --no-run -p frankenengine-engine --test parser_third_party_rerun_kit || return 1
      run_step \
        "cargo test -p frankenengine-engine --test parser_third_party_rerun_kit" \
        cargo test -p frankenengine-engine --test parser_third_party_rerun_kit || return 1
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_third_party_rerun_kit -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_third_party_rerun_kit -- -D warnings || return 1
      ;;
    package)
      run_step \
        "cargo test -p frankenengine-engine --test parser_third_party_rerun_kit -- --exact parser_third_party_rerun_kit_matrix_status_classifier_remains_stable" \
        cargo test -p frankenengine-engine --test parser_third_party_rerun_kit -- --exact parser_third_party_rerun_kit_matrix_status_classifier_remains_stable || return 1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci|package]" >&2
      exit 2
      ;;
  esac
}

classify_matrix_input_status() {
  if [[ -z "$matrix_summary_path" ]]; then
    matrix_input_status="pending_upstream_matrix"
    matrix_complete=false
    critical_delta_count=-1
    return 0
  fi

  if [[ ! -f "$matrix_summary_path" ]]; then
    matrix_eval_error="matrix summary path does not exist: ${matrix_summary_path}"
    return 1
  fi

  matrix_complete="$(jq -r '.matrix_complete // false' "$matrix_summary_path")"
  critical_delta_count="$(jq -r '.critical_delta_count // -1' "$matrix_summary_path")"

  if [[ "$matrix_complete" != "true" ]]; then
    matrix_input_status="incomplete_matrix"
    return 0
  fi

  if [[ "$critical_delta_count" =~ ^[0-9]+$ && "$critical_delta_count" -gt 0 ]]; then
    matrix_input_status="blocked_critical_deltas"
    return 0
  fi

  matrix_input_status="ready_for_external_rerun"
}

write_kit_index() {
  local matrix_summary_exists matrix_deltas_exists matrix_manifest_exists

  matrix_summary_exists=false
  matrix_deltas_exists=false
  matrix_manifest_exists=false

  if [[ -n "$matrix_summary_path" && -f "$matrix_summary_path" ]]; then
    matrix_summary_exists=true
  fi
  if [[ -n "$matrix_deltas_path" && -f "$matrix_deltas_path" ]]; then
    matrix_deltas_exists=true
  fi
  if [[ -n "$matrix_manifest_path" && -f "$matrix_manifest_path" ]]; then
    matrix_manifest_exists=true
  fi

  jq -n \
    --arg schema_version "franken-engine.parser-third-party-rerun-kit.index.v1" \
    --arg bead_id "bd-2mds.1.7.3" \
    --arg policy_id "$policy_id" \
    --arg generated_at_utc "$timestamp" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg component "$component" \
    --arg matrix_input_status "$matrix_input_status" \
    --arg matrix_summary_path "$matrix_summary_path" \
    --arg matrix_deltas_path "$matrix_deltas_path" \
    --arg matrix_manifest_path "$matrix_manifest_path" \
    --arg matrix_summary_source "$matrix_summary_source" \
    --arg matrix_deltas_source "$matrix_deltas_source" \
    --arg matrix_manifest_source "$matrix_manifest_source" \
    --arg auto_discover_matrix "$auto_discover_matrix" \
    --arg replay_command "$replay_command" \
    --arg cross_arch_replay "./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh" \
    --arg matrix_eval_error "$matrix_eval_error" \
    --argjson matrix_summary_exists "$matrix_summary_exists" \
    --argjson matrix_deltas_exists "$matrix_deltas_exists" \
    --argjson matrix_manifest_exists "$matrix_manifest_exists" \
    --argjson matrix_complete "$matrix_complete" \
    --argjson critical_delta_count "$critical_delta_count" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      policy_id: $policy_id,
      generated_at_utc: $generated_at_utc,
      trace_id: $trace_id,
      decision_id: $decision_id,
      component: $component,
      matrix_input_status: $matrix_input_status,
      matrix_input_auto_discovery_enabled: ($auto_discover_matrix == "1"),
      matrix_complete: $matrix_complete,
      critical_delta_count: $critical_delta_count,
      matrix_inputs: {
        summary: { path: $matrix_summary_path, exists: $matrix_summary_exists, source: $matrix_summary_source },
        deltas: { path: $matrix_deltas_path, exists: $matrix_deltas_exists, source: $matrix_deltas_source },
        run_manifest: { path: $matrix_manifest_path, exists: $matrix_manifest_exists, source: $matrix_manifest_source }
      },
      replay_commands: {
        rerun_kit: $replay_command,
        cross_arch_matrix: $cross_arch_replay
      },
      fail_closed: ($matrix_input_status != "ready_for_external_rerun"),
      matrix_eval_error: (if $matrix_eval_error == "" then null else $matrix_eval_error end)
    }' >"$kit_index_path"
}

write_verifier_notes() {
  cat >"$verifier_notes_path" <<EOF
# Parser Third-Party Rerun Kit Notes

Generated at: ${timestamp}
Bead: bd-2mds.1.7.3
Policy: ${policy_id}
Matrix input status: ${matrix_input_status}

## Inputs

- Matrix auto-discovery enabled: ${auto_discover_matrix}
- Matrix summary: ${matrix_summary_path:-<not provided>} (${matrix_summary_source})
- Matrix deltas: ${matrix_deltas_path:-<not provided>} (${matrix_deltas_source})
- Matrix run manifest: ${matrix_manifest_path:-<not provided>} (${matrix_manifest_source})

## Replay Commands

- ${replay_command}
- ./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh

## Fail-Closed Guidance

Promotion and claim workflows must fail closed unless
\`matrix_input_status == ready_for_external_rerun\`.
EOF
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
    error_code_json='"FE-PARSER-THIRD-PARTY-RERUN-KIT-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-third-party-rerun-kit.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"matrix_input_status\":\"${matrix_input_status}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
    echo "{\"schema_version\":\"franken-engine.parser-third-party-rerun-kit.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"kit_index_written\",\"matrix_input_status\":\"${matrix_input_status}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"pass\",\"error_code\":null}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-third-party-rerun-kit.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.7.3",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"rch_build_timeout_sec\": ${rch_build_timeout_sec},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    if [[ -n "$failed_step_log_path" ]]; then
      echo "  \"failed_step_log\": \"$(parser_frontier_json_escape "${failed_step_log_path}")\","
    fi
    echo "  \"matrix_input_status\": \"${matrix_input_status}\","
    echo "  \"matrix_complete\": ${matrix_complete},"
    echo "  \"critical_delta_count\": ${critical_delta_count},"
    if [[ -n "$matrix_eval_error" ]]; then
      echo "  \"matrix_eval_error\": \"$(parser_frontier_json_escape "${matrix_eval_error}")\","
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo '  "matrix_inputs": {'
    echo "    \"auto_discovery_enabled\": $([[ "$auto_discover_matrix" == "1" ]] && echo true || echo false),"
    echo '    "summary": {'
    echo "      \"path\": \"$(parser_frontier_json_escape "${matrix_summary_path}")\","
    echo "      \"source\": \"${matrix_summary_source}\","
    echo "      \"exists\": $([[ -n "$matrix_summary_path" && -f "$matrix_summary_path" ]] && echo true || echo false)"
    echo '    },'
    echo '    "deltas": {'
    echo "      \"path\": \"$(parser_frontier_json_escape "${matrix_deltas_path}")\","
    echo "      \"source\": \"${matrix_deltas_source}\","
    echo "      \"exists\": $([[ -n "$matrix_deltas_path" && -f "$matrix_deltas_path" ]] && echo true || echo false)"
    echo '    },'
    echo '    "run_manifest": {'
    echo "      \"path\": \"$(parser_frontier_json_escape "${matrix_manifest_path}")\","
    echo "      \"source\": \"${matrix_manifest_source}\","
    echo "      \"exists\": $([[ -n "$matrix_manifest_path" && -f "$matrix_manifest_path" ]] && echo true || echo false)"
    echo '    }'
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
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo "    \"rerun_kit_index\": \"${kit_index_path}\","
    echo "    \"verifier_notes\": \"${verifier_notes_path}\","
    echo '    "contract_doc": "docs/PARSER_THIRD_PARTY_RERUN_KIT.md",'
    echo '    "fixture": "crates/franken-engine/tests/fixtures/parser_third_party_rerun_kit_v1.json",'
    echo '    "integration_tests": "crates/franken-engine/tests/parser_third_party_rerun_kit.rs",'
    echo '    "replay_wrapper": "scripts/e2e/parser_third_party_rerun_kit_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"ls -1 ${step_logs_dir}\","
    echo "    \"cat ${kit_index_path}\","
    echo "    \"cat ${verifier_notes_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser third-party rerun kit manifest: ${manifest_path}"
  echo "parser third-party rerun kit index: ${kit_index_path}"
  echo "parser third-party rerun kit events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?

if ! classify_matrix_input_status; then
  if [[ "$main_exit" -eq 0 ]]; then
    main_exit=1
  fi
  failed_command="${failed_command:-classify_matrix_input_status}"
fi

write_kit_index
write_verifier_notes
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
