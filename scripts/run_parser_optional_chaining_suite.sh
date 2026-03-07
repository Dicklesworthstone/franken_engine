#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
scenario="${PARSER_OPTIONAL_CHAINING_SCENARIO:-full}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_optional_chaining}"
artifact_root="${PARSER_OPTIONAL_CHAINING_ARTIFACT_ROOT:-artifacts/parser_optional_chaining}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
bead_id="${PARSER_OPTIONAL_CHAINING_BEAD_ID:-bd-1lsy.2.6.2}"
family_id="expression.call_member_chain"
backlog_fixture_path="crates/franken-engine/tests/fixtures/parser_grammar_closure_backlog.json"
test_file="crates/franken-engine/tests/parser_trait_ast.rs"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
report_path="${run_dir}/parser_optional_chaining_report.json"

trace_id="trace-parser-optional-chaining-${scenario}-${timestamp}"
decision_id="decision-parser-optional-chaining-${scenario}-${timestamp}"
policy_id="policy-parser-optional-chaining-v1"
component="parser_optional_chaining_suite"
replay_command="./scripts/e2e/parser_optional_chaining_replay.sh ${scenario} ${mode}"

case "${scenario}" in
  positive|negative|family|full)
    ;;
  *)
    echo "unsupported PARSER_OPTIONAL_CHAINING_SCENARIO: ${scenario}" >&2
    exit 2
    ;;
esac

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser optional chaining heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for parser optional chaining structured artifacts" >&2
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

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path
  local remote_success_marker='Remote command finished: exit=0'
  local remote_failure_marker='Remote command finished: exit=[1-9][0-9]*'
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "$remote_success_marker" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if rg -q "$remote_failure_marker" "$log_path"; then
    echo "rch reported non-zero remote exit for step: ${command_text}" >&2
    rm -f "$log_path"
    failed_command="${command_text} (rch-remote-exit-nonzero)"
    return 1
  fi

  if ! rg -q "$remote_success_marker" "$log_path"; then
    echo "rch did not emit a remote success marker for step: ${command_text}" >&2
    rm -f "$log_path"
    failed_command="${command_text} (rch-remote-success-marker-missing)"
    return 1
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  rm -f "$log_path"
}

run_positive_tests() {
  run_step \
    "cargo test -p frankenengine-engine --test parser_trait_ast parser_optional_chain_ -- --nocapture" \
    cargo test -p frankenengine-engine --test parser_trait_ast parser_optional_chain_ -- --nocapture
}

run_negative_tests() {
  run_step \
    "cargo test -p frankenengine-engine --test parser_trait_ast parser_rejects_optional_chain_ -- --nocapture" \
    cargo test -p frankenengine-engine --test parser_trait_ast parser_rejects_optional_chain_ -- --nocapture
}

run_family_replay() {
  run_step \
    "PARSER_GRAMMAR_FAMILY=${family_id} cargo test -p frankenengine-engine --test parser_grammar_closure_backlog parser_grammar_closure_backlog_fixtures_are_replayable_by_family -- --nocapture" \
    env PARSER_GRAMMAR_FAMILY="${family_id}" cargo test -p frankenengine-engine --test parser_grammar_closure_backlog parser_grammar_closure_backlog_fixtures_are_replayable_by_family -- --nocapture
}

run_test_scenario() {
  case "${scenario}" in
    positive)
      run_positive_tests || return $?
      ;;
    negative)
      run_negative_tests || return $?
      ;;
    family)
      run_family_replay || return $?
      ;;
    full)
      run_positive_tests || return $?
      run_negative_tests || return $?
      run_family_replay || return $?
      ;;
  esac
}

run_mode() {
  case "${mode}" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog" \
        cargo check -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog || return $?
      ;;
    test)
      run_test_scenario || return $?
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog -- -D warnings || return $?
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog" \
        cargo check -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog || return $?
      run_test_scenario || return $?
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_trait_ast --test parser_grammar_closure_backlog -- -D warnings || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

json_array_or_default() {
  local jq_expr="$1"
  local default_json="$2"
  if [[ -f "$backlog_fixture_path" ]]; then
    jq -c "$jq_expr" "$backlog_fixture_path"
  else
    echo "$default_json"
  fi
}

json_scalar_or_default() {
  local jq_expr="$1"
  local default_value="$2"
  if [[ -f "$backlog_fixture_path" ]]; then
    jq -r "$jq_expr // \"${default_value}\"" "$backlog_fixture_path"
  else
    echo "$default_value"
  fi
}

write_report() {
  local exit_code="${1:-0}"
  local outcome error_code_json current_status notes
  local fixture_ids_json replay_commands_json unit_targets_json property_targets_json
  local e2e_scripts_json evidence_paths_json

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-PARSER-OPTIONAL-CHAINING-0001"'
  fi

  current_status="$(json_scalar_or_default ".families[] | select(.family_id == \"${family_id}\") | .current_status" "unknown")"
  notes="$(json_scalar_or_default ".families[] | select(.family_id == \"${family_id}\") | .notes" "")"
  fixture_ids_json="$(json_array_or_default "[.families[] | select(.family_id == \"${family_id}\") | .fixture_ids[]]" "[]")"
  replay_commands_json="$(json_array_or_default "[.families[] | select(.family_id == \"${family_id}\") | .replay_commands[]]" "[]")"
  unit_targets_json="$(json_array_or_default "[.families[] | select(.family_id == \"${family_id}\") | .unit_test_targets[]]" "[]")"
  property_targets_json="$(json_array_or_default "[.families[] | select(.family_id == \"${family_id}\") | .property_test_targets[]]" "[]")"
  e2e_scripts_json="$(json_array_or_default "[.families[] | select(.family_id == \"${family_id}\") | .e2e_conformance_scripts[]]" "[]")"
  evidence_paths_json="$(json_array_or_default "[.families[] | select(.family_id == \"${family_id}\") | .evidence_paths[]]" "[]")"

  jq -nc \
    --arg schema_version "franken-engine.parser-optional-chaining-report.v1" \
    --arg bead_id "${bead_id}" \
    --arg component "${component}" \
    --arg mode "${mode}" \
    --arg scenario "${scenario}" \
    --arg generated_at_utc "${timestamp}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg replay_command "${replay_command}" \
    --arg family_id "${family_id}" \
    --arg current_status "${current_status}" \
    --arg notes "${notes}" \
    --arg test_file "${test_file}" \
    --arg failed_command "${failed_command}" \
    --argjson command_count "${#commands_run[@]}" \
    --argjson fixture_ids "${fixture_ids_json}" \
    --argjson replay_commands "${replay_commands_json}" \
    --argjson unit_test_targets "${unit_targets_json}" \
    --argjson property_test_targets "${property_targets_json}" \
    --argjson e2e_conformance_scripts "${e2e_scripts_json}" \
    --argjson evidence_paths "${evidence_paths_json}" \
    --argjson error_code "${error_code_json}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      mode: $mode,
      scenario: $scenario,
      generated_at_utc: $generated_at_utc,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      replay_command: $replay_command,
      family_id: $family_id,
      family_status: $current_status,
      parser_test_file: $test_file,
      unit_test_targets: $unit_test_targets,
      property_test_targets: $property_test_targets,
      e2e_conformance_scripts: $e2e_conformance_scripts,
      fixture_ids: $fixture_ids,
      family_replay_commands: $replay_commands,
      evidence_paths: $evidence_paths,
      notes: (if ($notes | length) == 0 then null else $notes end),
      executed_command_count: $command_count,
      outcome: (if $error_code == null then "pass" else "fail" end),
      error_code: $error_code,
      failed_command: (if ($failed_command | length) == 0 then null else $failed_command end)
    }' >"${report_path}"
}

write_trace_ids() {
  jq -nc \
    --arg schema_version "franken-engine.parser-optional-chaining.trace-ids.v1" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg bead_id "${bead_id}" \
    --arg component "${component}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id
    }' >"${trace_ids_path}"
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
    error_code_json='"FE-PARSER-OPTIONAL-CHAINING-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"
  write_trace_ids
  write_report "${exit_code}"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"parser_optional_chaining_completed\",\"scenario\":\"${scenario}\",\"family_id\":\"${family_id}\",\"report\":\"$(parser_frontier_json_escape "${report_path}")\",\"replay_command\":\"$(parser_frontier_json_escape "${replay_command}")\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-optional-chaining.run-manifest.v1",'
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"scenario\": \"${scenario}\","
    echo "  \"family_id\": \"${family_id}\","
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
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"report\": \"${report_path}\","
    echo "    \"parser_tests\": \"${test_file}\","
    echo "    \"backlog_fixture\": \"${backlog_fixture_path}\","
    echo '    "replay_wrapper": "scripts/e2e/parser_optional_chaining_replay.sh",'
    echo '    "run_script": "scripts/run_parser_optional_chaining_suite.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${report_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"${manifest_path}"

  echo "parser optional chaining manifest: ${manifest_path}"
  echo "parser optional chaining report: ${report_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "${main_exit}"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "${events_path}"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "${main_exit}"
