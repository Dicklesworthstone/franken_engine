#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
scenario="${PARSER_FRONTIER_HARNESS_SCENARIO:-full}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_frontier_harness}"
artifact_root="${PARSER_FRONTIER_HARNESS_ARTIFACT_ROOT:-artifacts/parser_frontier_harness}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
bead_id="${PARSER_FRONTIER_HARNESS_BEAD_ID:-bd-1lsy.2.6.4}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
report_path="${run_dir}/parser_gap_report.json"
case_diagnostics_dir="${run_dir}/case_diagnostics"
suite_summaries_dir="${run_dir}/suite_summaries"
optional_artifact_root="${run_dir}/optional_chaining"
tagged_meta_artifact_root="${run_dir}/tagged_meta_frontier"
gap_inventory_out_dir="${run_dir}/parser_gap_inventory"

trace_id="trace-parser-frontier-harness-${scenario}-${timestamp}"
decision_id="decision-parser-frontier-harness-${scenario}-${timestamp}"
policy_id="policy-parser-frontier-harness-v1"
component="parser_frontier_harness"
replay_command="./scripts/e2e/parser_frontier_harness_replay.sh ${scenario} ${mode}"

optional_manifest_path=""
optional_trace_ids_path=""
optional_report_path=""
tagged_meta_manifest_path=""
tagged_meta_trace_ids_path=""
tagged_meta_report_path=""
gap_manifest_path=""
gap_inventory_path=""
gap_events_path=""
gap_commands_path=""

case "${scenario}" in
  positive|negative|inventory|full)
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    echo "supported PARSER_FRONTIER_HARNESS_SCENARIO values: positive|negative|inventory|full" >&2
    exit 2
    ;;
esac

case "${mode}" in
  check|test|clippy|ci)
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
esac

mkdir -p "${run_dir}" "${case_diagnostics_dir}" "${suite_summaries_dir}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser frontier harness heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for parser frontier harness structured artifacts" >&2
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

latest_artifact_dir() {
  local artifact_root="$1"
  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

verify_child_report_pass() {
  local suite_id="$1"
  local report_path="$2"
  local outcome

  if [[ ! -f "${report_path}" ]]; then
    echo "missing child report for ${suite_id}: ${report_path}" >&2
    failed_command="${suite_id} (missing-child-report)"
    return 1
  fi

  outcome="$(jq -r '.outcome // empty' "${report_path}")"
  if [[ "${outcome}" != "pass" ]]; then
    echo "${suite_id} reported non-pass outcome: ${outcome:-missing}" >&2
    failed_command="${suite_id} (child-report-outcome:${outcome:-missing})"
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_local_step() {
  local command_text="$1"
  shift

  commands_run+=("${command_text}")
  echo "==> ${command_text}"
  if ! "$@"; then
    failed_command="${command_text}"
    return 1
  fi
}

run_rch_step() {
  local command_text="$1"
  local log_path
  local remote_success_marker='Remote command finished: exit=0'
  local remote_failure_marker='Remote command finished: exit=[1-9][0-9]*'
  shift

  commands_run+=("${command_text}")
  echo "==> ${command_text}"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "${log_path}") 2>&1; then
    if rg -q "${remote_success_marker}" "${log_path}"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "${log_path}"
    else
      rm -f "${log_path}"
      failed_command="${command_text}"
      return 1
    fi
  fi

  if rg -q "${remote_failure_marker}" "${log_path}"; then
    echo "rch reported non-zero remote exit for step: ${command_text}" >&2
    rm -f "${log_path}"
    failed_command="${command_text} (rch-remote-exit-nonzero)"
    return 1
  fi

  if ! rg -q "${remote_success_marker}" "${log_path}"; then
    echo "rch did not emit a remote success marker for step: ${command_text}" >&2
    rm -f "${log_path}"
    failed_command="${command_text} (rch-remote-success-marker-missing)"
    return 1
  fi

  if ! rch_reject_local_fallback "${log_path}"; then
    rm -f "${log_path}"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  rm -f "${log_path}"
}

run_optional_suite() {
  local suite_scenario="$1"
  local latest_dir

  run_local_step \
    "PARSER_OPTIONAL_CHAINING_SCENARIO=${suite_scenario} PARSER_OPTIONAL_CHAINING_ARTIFACT_ROOT=${optional_artifact_root} ./scripts/run_parser_optional_chaining_suite.sh ${mode}" \
    env \
      PARSER_OPTIONAL_CHAINING_SCENARIO="${suite_scenario}" \
      PARSER_OPTIONAL_CHAINING_ARTIFACT_ROOT="${optional_artifact_root}" \
      ./scripts/run_parser_optional_chaining_suite.sh "${mode}"

  latest_dir="$(latest_artifact_dir "${optional_artifact_root}")"
  optional_manifest_path="${latest_dir}/run_manifest.json"
  optional_trace_ids_path="${latest_dir}/trace_ids.json"
  optional_report_path="${latest_dir}/parser_optional_chaining_report.json"
  verify_child_report_pass "optional_chaining" "${optional_report_path}"
}

run_tagged_meta_suite() {
  local suite_scenario="$1"
  local latest_dir

  run_local_step \
    "PARSER_TAGGED_META_FRONTIER_SCENARIO=${suite_scenario} PARSER_TAGGED_META_FRONTIER_ARTIFACT_ROOT=${tagged_meta_artifact_root} ./scripts/run_parser_tagged_meta_frontier_suite.sh ${mode}" \
    env \
      PARSER_TAGGED_META_FRONTIER_SCENARIO="${suite_scenario}" \
      PARSER_TAGGED_META_FRONTIER_ARTIFACT_ROOT="${tagged_meta_artifact_root}" \
      ./scripts/run_parser_tagged_meta_frontier_suite.sh "${mode}"

  latest_dir="$(latest_artifact_dir "${tagged_meta_artifact_root}")"
  tagged_meta_manifest_path="${latest_dir}/run_manifest.json"
  tagged_meta_trace_ids_path="${latest_dir}/trace_ids.json"
  tagged_meta_report_path="${latest_dir}/parser_tagged_meta_frontier_report.json"
  verify_child_report_pass "tagged_meta_frontier" "${tagged_meta_report_path}"
}

run_parser_gap_inventory() {
  run_rch_step \
    "cargo run -p frankenengine-engine --bin franken_parser_gap_inventory -- --out-dir ${gap_inventory_out_dir}" \
    cargo run -p frankenengine-engine --bin franken_parser_gap_inventory -- --out-dir "${gap_inventory_out_dir}"

  gap_manifest_path="${gap_inventory_out_dir}/run_manifest.json"
  gap_inventory_path="${gap_inventory_out_dir}/parser_gap_inventory.json"
  gap_events_path="${gap_inventory_out_dir}/events.jsonl"
  gap_commands_path="${gap_inventory_out_dir}/commands.txt"
}

run_contract_checks() {
  case "${mode}" in
    check)
      run_rch_step \
        "cargo check -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness" \
        cargo check -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness
      ;;
    test)
      run_rch_step \
        "cargo test -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- --nocapture" \
        cargo test -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- --nocapture
      ;;
    clippy)
      run_rch_step \
        "cargo clippy -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- -D warnings
      ;;
    ci)
      run_rch_step \
        "cargo check -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness" \
        cargo check -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness
      run_rch_step \
        "cargo test -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- --nocapture" \
        cargo test -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- --nocapture
      run_rch_step \
        "cargo clippy -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_gap_inventory_cli --test parser_frontier_harness -- -D warnings
      ;;
  esac
}

run_suite_scenario() {
  case "${scenario}" in
    positive)
      run_optional_suite positive || return $?
      run_tagged_meta_suite positive || return $?
      ;;
    negative)
      run_optional_suite negative || return $?
      run_tagged_meta_suite negative || return $?
      ;;
    inventory)
      ;;
    full)
      run_optional_suite full || return $?
      run_tagged_meta_suite full || return $?
      ;;
  esac
}

write_trace_ids() {
  jq -nc \
    --arg schema_version "franken-engine.parser-frontier-harness.trace-ids.v1" \
    --arg bead_id "${bead_id}" \
    --arg component "${component}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id
    }' >"${trace_ids_path}"
}

write_suite_summary() {
  local suite_id="$1"
  local suite_report_path="$2"
  local suite_manifest_path="$3"
  local suite_trace_ids_path="$4"
  local output_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.parser-frontier-harness.child-run.v1" \
    --arg suite_id "${suite_id}" \
    --arg report_path "${suite_report_path}" \
    --arg manifest_path "${suite_manifest_path}" \
    --arg trace_ids_path "${suite_trace_ids_path}" \
    --argjson report "$(cat "${suite_report_path}")" \
    --argjson trace_ids "$(cat "${suite_trace_ids_path}")" \
    '{
      schema_version: $schema_version,
      suite_id: $suite_id,
      component: $report.component,
      scenario: $report.scenario,
      outcome: $report.outcome,
      trace_id: $trace_ids.trace_id,
      decision_id: $trace_ids.decision_id,
      policy_id: $trace_ids.policy_id,
      artifacts: {
        report: $report_path,
        manifest: $manifest_path,
        trace_ids: $trace_ids_path
      }
    }' >"${output_path}"
}

write_gap_inventory_summary() {
  local output_path="$1"

  jq -nc \
    --arg schema_version "franken-engine.parser-frontier-harness.child-run.v1" \
    --arg suite_id "parser_gap_inventory" \
    --arg manifest_path "${gap_manifest_path}" \
    --arg inventory_path "${gap_inventory_path}" \
    --arg events_path "${gap_events_path}" \
    --arg commands_path "${gap_commands_path}" \
    --argjson manifest "$(cat "${gap_manifest_path}")" \
    --argjson inventory "$(cat "${gap_inventory_path}")" \
    '{
      schema_version: $schema_version,
      suite_id: $suite_id,
      component: "parser_gap_inventory",
      scenario: "inventory",
      outcome: "pass",
      site_count: ($inventory.sites | length),
      fail_closed_site_count: ([ $inventory.sites[] | select(.remediation_status == "fail_closed") ] | length),
      open_placeholder_site_count: ([ $inventory.sites[] | select(.remediation_status == "open_placeholder") ] | length),
      trace_id: $manifest.trace_id,
      decision_id: $manifest.decision_id,
      policy_id: $manifest.policy_id,
      artifacts: {
        manifest: $manifest_path,
        inventory: $inventory_path,
        events: $events_path,
        commands: $commands_path
      }
    }' >"${output_path}"
}

write_case_diagnostic() {
  local case_id="$1"
  local suite_summary_path="$2"
  local output_path="$3"

  jq -nc \
    --arg schema_version "franken-engine.parser-frontier-harness.case-diagnostic.v1" \
    --arg case_id "${case_id}" \
    --argjson summary "$(cat "${suite_summary_path}")" \
    '{
      schema_version: $schema_version,
      case_id: $case_id,
      suite_id: $summary.suite_id,
      scenario: $summary.scenario,
      component: $summary.component,
      outcome: $summary.outcome,
      trace_id: ($summary.trace_id // null),
      decision_id: ($summary.decision_id // null),
      policy_id: ($summary.policy_id // null),
      artifacts: $summary.artifacts
    }' >"${output_path}"
}

write_report() {
  local exit_code="${1:-0}"
  local outcome error_code_json suite_summaries_json case_paths_json

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-PARSER-FRONTIER-HARNESS-0001"'
  fi

  if find "${suite_summaries_dir}" -maxdepth 1 -type f -name '*.json' | grep -q .; then
    suite_summaries_json="$(
      find "${suite_summaries_dir}" -maxdepth 1 -type f -name '*.json' \
        | sort \
        | xargs jq -s '.'
    )"
  else
    suite_summaries_json='[]'
  fi

  case_paths_json="$(
    find "${case_diagnostics_dir}" -maxdepth 1 -type f -name '*.json' \
      | sort \
      | jq -R . \
      | jq -s '.'
  )"

  jq -nc \
    --arg schema_version "franken-engine.parser-frontier-harness.report.v1" \
    --arg bead_id "${bead_id}" \
    --arg component "${component}" \
    --arg mode "${mode}" \
    --arg scenario "${scenario}" \
    --arg generated_at_utc "${timestamp}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg replay_command "${replay_command}" \
    --arg failed_command "${failed_command}" \
    --argjson command_count "${#commands_run[@]}" \
    --argjson child_runs "${suite_summaries_json}" \
    --argjson case_diagnostics "${case_paths_json}" \
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
      child_runs: $child_runs,
      case_diagnostics: $case_diagnostics,
      executed_command_count: $command_count,
      outcome: (if $error_code == null then "pass" else "fail" end),
      error_code: $error_code,
      failed_command: (if ($failed_command | length) == 0 then null else $failed_command end)
    }' >"${report_path}"
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
    error_code_json='"FE-PARSER-FRONTIER-HARNESS-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"
  write_trace_ids

  if [[ -n "${optional_report_path}" ]]; then
    write_suite_summary \
      "optional_chaining" \
      "${optional_report_path}" \
      "${optional_manifest_path}" \
      "${optional_trace_ids_path}" \
      "${suite_summaries_dir}/optional_chaining.json"
    write_case_diagnostic \
      "optional_chaining" \
      "${suite_summaries_dir}/optional_chaining.json" \
      "${case_diagnostics_dir}/optional_chaining.json"
  fi

  if [[ -n "${tagged_meta_report_path}" ]]; then
    write_suite_summary \
      "tagged_meta_frontier" \
      "${tagged_meta_report_path}" \
      "${tagged_meta_manifest_path}" \
      "${tagged_meta_trace_ids_path}" \
      "${suite_summaries_dir}/tagged_meta_frontier.json"
    write_case_diagnostic \
      "tagged_meta_frontier" \
      "${suite_summaries_dir}/tagged_meta_frontier.json" \
      "${case_diagnostics_dir}/tagged_meta_frontier.json"
  fi

  if [[ -n "${gap_inventory_path}" ]]; then
    write_gap_inventory_summary "${suite_summaries_dir}/parser_gap_inventory.json"
    write_case_diagnostic \
      "parser_gap_inventory" \
      "${suite_summaries_dir}/parser_gap_inventory.json" \
      "${case_diagnostics_dir}/parser_gap_inventory.json"
  fi

  write_report "${exit_code}"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"parser_frontier_harness_completed\",\"scenario\":\"${scenario}\",\"report\":\"$(parser_frontier_json_escape "${report_path}")\",\"replay_command\":\"$(parser_frontier_json_escape "${replay_command}")\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-frontier-harness.run-manifest.v1",'
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
    echo '  "child_runs": ['
    local child_paths=()
    if [[ -f "${suite_summaries_dir}/optional_chaining.json" ]]; then
      child_paths+=("${suite_summaries_dir}/optional_chaining.json")
    fi
    if [[ -f "${suite_summaries_dir}/tagged_meta_frontier.json" ]]; then
      child_paths+=("${suite_summaries_dir}/tagged_meta_frontier.json")
    fi
    if [[ -f "${suite_summaries_dir}/parser_gap_inventory.json" ]]; then
      child_paths+=("${suite_summaries_dir}/parser_gap_inventory.json")
    fi
    for idx in "${!child_paths[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#child_paths[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${child_paths[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
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
    echo "    \"case_diagnostics_dir\": \"${case_diagnostics_dir}\","
    echo "    \"optional_chaining_root\": \"${optional_artifact_root}\","
    echo "    \"tagged_meta_frontier_root\": \"${tagged_meta_artifact_root}\","
    echo "    \"parser_gap_inventory_dir\": \"${gap_inventory_out_dir}\","
    echo '    "replay_wrapper": "scripts/e2e/parser_frontier_harness_replay.sh",'
    echo '    "run_script": "scripts/run_parser_frontier_harness.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${report_path}\","
    echo "    \"ls -1 ${case_diagnostics_dir}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"${manifest_path}"

  echo "parser frontier harness manifest: ${manifest_path}"
  echo "parser frontier harness report: ${report_path}"
}

main_exit=0
run_suite_scenario || main_exit=$?
if [[ "${main_exit}" -eq 0 ]]; then
  run_parser_gap_inventory || main_exit=$?
fi
if [[ "${main_exit}" -eq 0 ]]; then
  run_contract_checks || main_exit=$?
fi
write_manifest "${main_exit}"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "${events_path}"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "${main_exit}"
