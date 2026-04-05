#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
artifact_root="${LOWERING_GAP_TRUTH_INVARIANT_ARTIFACT_ROOT:-artifacts/lowering_gap_truth_invariant}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_lowering_gap_truth_invariant_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
contract_copy_path="${run_dir}/lowering_gap_truth_invariant.json"
validation_report_path="${run_dir}/lowering_gap_truth_invariant_validation_report.json"
step_logs_dir="${run_dir}/step_logs"
preflight_log_path="${step_logs_dir}/step_000.log"

contract_doc="docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md"
contract_json="docs/lowering_gap_truth_invariant_v1.json"
contract_test="crates/franken-engine/tests/lowering_gap_truth_invariant.rs"
replay_wrapper="scripts/e2e/lowering_gap_truth_invariant_replay.sh"

trace_id="trace-lowering-gap-truth-invariant-${timestamp}"
decision_id="decision-lowering-gap-truth-invariant-${timestamp}"
policy_id="policy-lowering-gap-truth-invariant-v1"
component="lowering_gap_truth_invariant_gate"
scenario_id="rgc-920d1"
main_outcome="passed"
main_exit=0
validation_error_code=""
failed_command=""

declare -a commands_run=()
declare -a step_logs=("${preflight_log_path}")
declare -a validation_errors=()
test_log_path=""
rust_validation_requested=false
rust_validation_executed=false
rust_validation_passed=false

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for lowering gap truth invariant validation" >&2
  exit 2
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for lowering gap truth invariant heavy commands" >&2
  exit 2
fi

mkdir -p "${run_dir}" "${step_logs_dir}"
cp "${contract_json}" "${contract_copy_path}" 2>/dev/null || true

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "CARGO_INCREMENTAL=${cargo_incremental}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  [[ -n "${remote_exit_line}" ]] || return 1
  printf '%s\n' "${remote_exit_line##*=}"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

append_event() {
  local event="$1"
  local outcome="$2"
  local error_code="$3"
  local detail="$4"
  local rule_id="${5:-}"

  jq -nc \
    --arg schema_version "franken-engine.lowering-gap-truth-invariant.event.v1" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg event "${event}" \
    --arg outcome "${outcome}" \
    --arg error_code "${error_code}" \
    --arg rule_id "${rule_id}" \
    --arg detail "${detail}" \
    '{
      schema_version: $schema_version,
      scenario_id: $scenario_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      rule_id: (if $rule_id == "" then null else $rule_id end),
      site_id: null,
      status: null,
      parser_ready_syntax: null,
      execution_ready_semantics: null,
      detail: (if $detail == "" then null else $detail end)
    }' >>"${events_path}"
}

validate_source_inputs() {
  commands_run+=("jq empty ${contract_json}")
  printf '==> validate source inputs\n' >"${preflight_log_path}"

  for path in "${contract_doc}" "${contract_json}" "${contract_test}" "${replay_wrapper}"; do
    if [[ ! -f "${path}" ]]; then
      validation_errors+=("missing required source input: ${path}")
    fi
  done

  if [[ -f "${contract_json}" ]] && ! jq -e '.' "${contract_json}" >/dev/null 2>&1; then
    validation_errors+=("failed to parse contract json: ${contract_json}")
  fi

  if [[ -f "${contract_json}" ]]; then
    mapfile -t source_inputs < <(jq -r '.source_inputs[]' "${contract_json}")
    for input in "${source_inputs[@]}"; do
      if [[ ! -e "${input}" ]]; then
        validation_errors+=("missing declared source input: ${input}")
      fi
    done

    if ! jq -e '
      .invariant_contract.allowed_status_matrix
      | map(.rule_id)
      | index("resolved_exec_ready")
      and index("open_placeholder_parser_ready")
      and index("fail_closed_parser_ready")
    ' "${contract_json}" >/dev/null; then
      validation_errors+=("contract is missing one or more required invariant rules")
    fi
  fi

  {
    printf '%s\n' "contract_doc=${contract_doc}"
    printf '%s\n' "contract_json=${contract_json}"
    printf '%s\n' "contract_test=${contract_test}"
    printf '%s\n' "replay_wrapper=${replay_wrapper}"
    if (( ${#validation_errors[@]} == 0 )); then
      printf '%s\n' "preflight=pass"
    else
      printf '%s\n' "preflight=fail"
      printf '%s\n' "${validation_errors[@]}"
    fi
  } >>"${preflight_log_path}"
}

run_contract_test() {
  local command_text log_path status remote_exit_code

  rust_validation_requested=true
  commands_run+=("rch exec -- env RUSTUP_TOOLCHAIN=${toolchain} CARGO_TARGET_DIR=${target_dir} CARGO_BUILD_JOBS=${cargo_build_jobs} CARGO_INCREMENTAL=${cargo_incremental} cargo test -p frankenengine-engine --test lowering_gap_truth_invariant")

  if [[ "${mode}" == "check" ]]; then
    return 0
  fi

  command_text="cargo test -p frankenengine-engine --test lowering_gap_truth_invariant"
  log_path="${step_logs_dir}/step_001.log"
  step_logs+=("${log_path}")
  test_log_path="${log_path}"
  rust_validation_executed=true

  set +e
  run_rch cargo test -p frankenengine-engine --test lowering_gap_truth_invariant > >(tee "${log_path}") 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    if [[ "${status}" -eq 124 ]]; then
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      validation_error_code="timeout"
      return 1
    fi
    remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
    if [[ -n "${remote_exit_code}" ]]; then
      failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    else
      failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    fi
    validation_error_code="cargo_test_failed"
    return 1
  fi

  if ! rch_reject_local_fallback "${log_path}"; then
    failed_command="${command_text} (local-fallback)"
    validation_error_code="rch_local_fallback"
    return 1
  fi

  rust_validation_passed=true
  return 0
}

write_outputs() {
  local source_input_count rule_count example_count

  source_input_count="$(jq '.source_inputs | length' "${contract_json}")"
  rule_count="$(jq '.invariant_contract.allowed_status_matrix | length' "${contract_json}")"
  example_count="$(jq '.invariant_contract.disallowed_state_examples | length' "${contract_json}")"

  jq -nc \
    --arg schema_version "franken-engine.lowering-gap-truth-invariant.trace-ids.v1" \
    --arg component "${component}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    '{
      schema_version: $schema_version,
      component: $component,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id
    }' >"${trace_ids_path}"

  jq -nc \
    --arg schema_version "franken-engine.lowering-gap-truth-invariant.validation-report.v1" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg mode "${mode}" \
    --arg outcome "${main_outcome}" \
    --arg error_code "${validation_error_code}" \
    --arg contract_schema_version "$(jq -r '.schema_version' "${contract_json}")" \
    --arg rule_set_id "$(jq -r '.invariant_contract.rule_set_id' "${contract_json}")" \
    --arg deferred_application_bead "$(jq -r '.invariant_contract.deferred_application_bead' "${contract_json}")" \
    --arg consumer_alignment_bead "$(jq -r '.invariant_contract.consumer_alignment_bead' "${contract_json}")" \
    --arg rust_command "cargo test -p frankenengine-engine --test lowering_gap_truth_invariant" \
    --arg test_log_path "${test_log_path}" \
    --argjson source_input_count "${source_input_count}" \
    --argjson allowed_rule_count "${rule_count}" \
    --argjson disallowed_example_count "${example_count}" \
    --argjson rust_validation_requested "$( [[ "${rust_validation_requested}" == true ]] && echo true || echo false )" \
    --argjson rust_validation_executed "$( [[ "${rust_validation_executed}" == true ]] && echo true || echo false )" \
    --argjson rust_validation_passed "$( [[ "${rust_validation_passed}" == true ]] && echo true || echo false )" \
    --argjson preflight_passed "$( (( ${#validation_errors[@]} == 0 )) && echo true || echo false )" \
    '{
      schema_version: $schema_version,
      scenario_id: $scenario_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      mode: $mode,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      contract_schema_version: $contract_schema_version,
      rule_set_id: $rule_set_id,
      deferred_application_bead: $deferred_application_bead,
      consumer_alignment_bead: $consumer_alignment_bead,
      source_input_count: $source_input_count,
      allowed_rule_count: $allowed_rule_count,
      disallowed_example_count: $disallowed_example_count,
      preflight_passed: $preflight_passed,
      rust_validation: {
        requested: $rust_validation_requested,
        executed: $rust_validation_executed,
        passed: $rust_validation_passed,
        command: $rust_command,
        log_path: (if $test_log_path == "" then null else $test_log_path end)
      },
      notes: [
        "bd-2muur.4.1 defines the invariant only; bd-2muur.4.2 applies it to the lowering-gap generator.",
        "bd-2muur.4.3 aligns manifests, tests, and consumers once the generator matches the invariant."
      ]
    }' >"${validation_report_path}"

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  jq -nc \
    --arg schema_version "franken-engine.lowering-gap-truth-invariant.run-manifest.v1" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg mode "${mode}" \
    --arg outcome "${main_outcome}" \
    --arg error_code "${validation_error_code}" \
    --arg failed_command "${failed_command}" \
    '{
      schema_version: $schema_version,
      scenario_id: $scenario_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      mode: $mode,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      failed_command: (if $failed_command == "" then null else $failed_command end),
      artifact_paths: {
        trace_ids: "trace_ids.json",
        run_manifest: "run_manifest.json",
        events_jsonl: "events.jsonl",
        commands_txt: "commands.txt",
        contract_copy: "lowering_gap_truth_invariant.json",
        validation_report: "lowering_gap_truth_invariant_validation_report.json",
        step_logs_dir: "step_logs"
      }
    }' >"${manifest_path}"
}

append_event "contract_validation_started" "started" "" "lowering gap truth invariant validation started"
validate_source_inputs

if (( ${#validation_errors[@]} != 0 )); then
  main_outcome="failed"
  validation_error_code="preflight_validation_failed"
  append_event "source_inputs_validated" "failed" "${validation_error_code}" "$(printf '%s; ' "${validation_errors[@]}")"
  main_exit=1
else
  append_event "source_inputs_validated" "passed" "" "contract json and declared source inputs are present"
  if run_contract_test; then
    if [[ "${mode}" == "check" ]]; then
      append_event "rust_validation_skipped" "skipped" "" "mode=check skips rch-backed cargo test"
    else
      append_event "rust_validation_completed" "passed" "" "rch-backed contract test passed"
    fi
  else
    main_outcome="failed"
    append_event "rust_validation_completed" "failed" "${validation_error_code}" "${failed_command}"
    main_exit=1
  fi
fi

append_event "contract_validation_completed" "${main_outcome}" "${validation_error_code}" "lowering gap truth invariant validation finished"
write_outputs

exit "${main_exit}"
