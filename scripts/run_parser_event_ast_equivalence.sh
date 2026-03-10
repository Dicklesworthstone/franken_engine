#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
scenario="${PARSER_EVENT_AST_EQUIVALENCE_SCENARIO:-parity}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_event_ast_equivalence}"
artifact_root="${PARSER_EVENT_AST_EQUIVALENCE_ARTIFACT_ROOT:-artifacts/parser_event_ast_equivalence}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
bead_id="${PARSER_EVENT_AST_EQUIVALENCE_BEAD_ID:-bd-2mds.1.4.4}"

case "${scenario}" in
  parity|malformed|tamper|replay|full|matrix)
    ;;
  *)
    echo "unsupported PARSER_EVENT_AST_EQUIVALENCE_SCENARIO: ${scenario}" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
matrix_summary_path="${run_dir}/matrix_summary.json"

trace_id="trace-parser-event-ast-equivalence-${scenario}-${timestamp}"
decision_id="decision-parser-event-ast-equivalence-${scenario}-${timestamp}"
policy_id="policy-parser-event-ast-equivalence-v1"
component="parser_event_ast_equivalence_gate"
replay_command="PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=${scenario} ${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser event->AST equivalence heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for parser event->AST equivalence matrix summary generation" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(grep -Eo 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
}

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts' "$log_path"
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|artifact retrieval .*rsync error|rsync error: .*code 23' "$log_path"; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path
  local remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
  if [[ -z "$remote_exit_code" ]]; then
    echo "rch did not emit a remote exit marker for step: ${command_text}" >&2
    rm -f "$log_path"
    failed_command="${command_text} (rch-remote-exit-marker-missing)"
    return 1
  fi

  if [[ "$remote_exit_code" != "0" ]]; then
    echo "rch reported non-zero remote exit for step: ${command_text}" >&2
    rm -f "$log_path"
    failed_command="${command_text} (rch-remote-exit-nonzero)"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    return 1
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  rm -f "$log_path"
}

run_test_scenario() {
  case "${scenario}" in
    parity)
      run_step \
        "cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --skip parser_event_ast_equivalence_failure_case_has_replayable_error_codes --skip parser_event_ast_equivalence_tamper_detection_is_deterministic --skip parser_event_ast_equivalence_replay_scenarios_are_deterministic" \
        cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- \
          --skip parser_event_ast_equivalence_failure_case_has_replayable_error_codes \
          --skip parser_event_ast_equivalence_tamper_detection_is_deterministic \
          --skip parser_event_ast_equivalence_replay_scenarios_are_deterministic || return $?
      ;;
    malformed)
      run_step \
        "cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --skip parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses --skip parser_event_ast_equivalence_tamper_detection_is_deterministic --skip parser_event_ast_equivalence_replay_scenarios_are_deterministic" \
        cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- \
          --skip parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses \
          --skip parser_event_ast_equivalence_tamper_detection_is_deterministic \
          --skip parser_event_ast_equivalence_replay_scenarios_are_deterministic || return $?
      ;;
    tamper)
      run_step \
        "cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --skip parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses --skip parser_event_ast_equivalence_failure_case_has_replayable_error_codes --skip parser_event_ast_equivalence_replay_scenarios_are_deterministic" \
        cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- \
          --skip parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses \
          --skip parser_event_ast_equivalence_failure_case_has_replayable_error_codes \
          --skip parser_event_ast_equivalence_replay_scenarios_are_deterministic || return $?
      ;;
    replay)
      run_step \
        "cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --skip parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses --skip parser_event_ast_equivalence_failure_case_has_replayable_error_codes --skip parser_event_ast_equivalence_tamper_detection_is_deterministic" \
        cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- \
          --skip parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses \
          --skip parser_event_ast_equivalence_failure_case_has_replayable_error_codes \
          --skip parser_event_ast_equivalence_tamper_detection_is_deterministic || return $?
      ;;
    full)
      run_step "cargo test -p frankenengine-engine --test parser_event_ast_equivalence" \
        cargo test -p frankenengine-engine --test parser_event_ast_equivalence || return $?
      ;;
    matrix)
      run_step \
        "cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --exact parser_event_ast_equivalence_matrix_dimensions_contract_is_complete" \
        cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --exact parser_event_ast_equivalence_matrix_dimensions_contract_is_complete || return $?
      run_step \
        "cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --exact parser_event_ast_equivalence_cases_cover_required_matrix_tiers" \
        cargo test -p frankenengine-engine --test parser_event_ast_equivalence -- --exact parser_event_ast_equivalence_cases_cover_required_matrix_tiers || return $?
      ;;
  esac
}

run_mode() {
  case "${mode}" in
    check)
      run_step "cargo check -p frankenengine-engine --test parser_event_ast_equivalence" \
        cargo check -p frankenengine-engine --test parser_event_ast_equivalence || return $?
      ;;
    test)
      run_test_scenario || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test parser_event_ast_equivalence -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_event_ast_equivalence -- -D warnings || return $?
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test parser_event_ast_equivalence" \
        cargo check -p frankenengine-engine --test parser_event_ast_equivalence || return $?
      run_test_scenario || return $?
      run_step "cargo clippy -p frankenengine-engine --test parser_event_ast_equivalence -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_event_ast_equivalence -- -D warnings || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

resolve_error_code() {
  case "${scenario}" in
    parity)
      echo "FE-PARSER-EVENT-AST-EQUIV-PARITY-0001"
      ;;
    malformed)
      echo "FE-PARSER-EVENT-AST-EQUIV-MALFORMED-0001"
      ;;
    tamper)
      echo "FE-PARSER-EVENT-AST-EQUIV-TAMPER-0001"
      ;;
    replay)
      echo "FE-PARSER-EVENT-AST-EQUIV-REPLAY-0001"
      ;;
    full)
      echo "FE-PARSER-EVENT-AST-EQUIV-FULL-0001"
      ;;
    matrix)
      echo "FE-PARSER-EVENT-AST-EQUIV-MATRIX-0001"
      ;;
    *)
      echo "FE-PARSER-EVENT-AST-EQUIV-0001"
      ;;
  esac
}

write_matrix_summary() {
  local exit_code="${1:-0}"
  local fixture_path matrix_complete matrix_dimensions_json matrix_error_code

  fixture_path="crates/franken-engine/tests/fixtures/parser_event_ast_equivalence_v1.json"
  matrix_dimensions_json="$(jq -c '.matrix_dimensions // {}' "$fixture_path")"

  matrix_complete=false
  if [[ "${scenario}" == "matrix" && "${exit_code}" -eq 0 ]]; then
    matrix_complete=true
  fi

  matrix_error_code="null"
  if [[ "${scenario}" == "matrix" && "${exit_code}" -ne 0 ]]; then
    matrix_error_code="\"FE-PARSER-EVENT-AST-EQUIV-MATRIX-0001\""
  fi

  jq -nc \
    --arg schema_version "franken-engine.parser-event-ast-equivalence.matrix-summary.v1" \
    --arg bead_id "${bead_id}" \
    --arg scenario "${scenario}" \
    --arg mode "${mode}" \
    --arg generated_at_utc "${timestamp}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg replay_command "${replay_command}" \
    --arg failed_command "${failed_command}" \
    --argjson matrix_complete "${matrix_complete}" \
    --argjson command_count "${#commands_run[@]}" \
    --argjson matrix_dimensions "${matrix_dimensions_json}" \
    --argjson error_code "${matrix_error_code}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      scenario: $scenario,
      mode: $mode,
      generated_at_utc: $generated_at_utc,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      matrix_dimensions: $matrix_dimensions,
      executed_scenarios: [$scenario],
      matrix_complete: $matrix_complete,
      command_count: $command_count,
      replay_command: $replay_command,
      failed_command: (if ($failed_command | length) == 0 then null else $failed_command end),
      error_code: $error_code
    }' >"$matrix_summary_path"
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "${manifest_written}" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json="\"$(resolve_error_code)\""
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  write_matrix_summary "${exit_code}"

  {
    echo "{\"schema_version\":\"franken-engine.parser-event-ast-equivalence.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario\":\"${scenario}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-event-ast-equivalence.run-manifest.v1",'
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"component\": \"${component}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"scenario\": \"${scenario}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\"," 
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "${failed_command}" ]]; then
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
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo '    "contract_doc": "docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md",'
    echo '    "gate_fixture": "crates/franken-engine/tests/fixtures/parser_event_ast_equivalence_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/parser_event_ast_equivalence.rs",'
    echo '    "replay_wrapper": "./scripts/e2e/parser_event_ast_equivalence_replay.sh",'
    echo "    \"matrix_summary\": \"${matrix_summary_path}\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${matrix_summary_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser event->AST equivalence manifest: ${manifest_path}"
  echo "parser event->AST equivalence events: ${events_path}"
  echo "parser event->AST equivalence matrix summary: ${matrix_summary_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
