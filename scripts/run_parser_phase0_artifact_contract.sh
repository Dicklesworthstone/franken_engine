#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
artifact_root="${PARSER_PHASE0_ARTIFACT_CONTRACT_ARTIFACT_ROOT:-artifacts/parser_phase0_artifact_contract}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_parser_phase0_artifact_contract_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
contract_copy_path="${run_dir}/parser_phase0_artifact_contract.json"
validation_report_path="${run_dir}/parser_phase0_artifact_contract_validation_report.json"
step_logs_dir="${run_dir}/step_logs"
preflight_log_path="${step_logs_dir}/step_000.log"

contract_doc="docs/PARSER_PHASE0_ARTIFACT_CONTRACT_V1.md"
contract_json="docs/parser_phase0_artifact_contract_v1.json"
generator_script="scripts/generate_parser_phase0_artifacts.sh"
replay_wrapper="scripts/e2e/parser_phase0_artifact_contract_replay.sh"

trace_id="trace-parser-phase0-artifact-contract-${timestamp}"
decision_id="decision-parser-phase0-artifact-contract-${timestamp}"
policy_id="policy-parser-phase0-artifact-contract-v1"
component="parser_phase0_artifact_contract_gate"
scenario_id="rgc-920f1"
replay_command="./scripts/e2e/parser_phase0_artifact_contract_replay.sh ${mode}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for parser phase0 artifact contract validation" >&2
  exit 2
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser phase0 artifact contract heavy commands" >&2
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

rch_recovered_success() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=0|Finished.*profile|test result: ok\.' \
    && ! rch_strip_ansi "$log_path" | rg -qi 'error(\[[[:alnum:]]+\])?:'; then
    return 0
  fi
  return 1
}

worktree_is_dirty() {
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 1
  fi

  local worktree_status
  worktree_status="$(
    git status --short --untracked-files=normal -- . \
      ":(exclude)${artifact_root%/}/" \
      ":(exclude).beads/" \
      ":(exclude).claude/" 2>/dev/null || true
  )"
  [[ -n "${worktree_status}" ]]
}

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

declare -a commands_run=()
declare -a validation_errors=()
declare -a step_logs=("${preflight_log_path}")
failed_command=""
manifest_written=false
step_log_index=1

printf '==> validate source inputs\n' >"${preflight_log_path}"

validate_source_inputs() {
  local input
  commands_run+=("jq empty ${contract_json}")

  if [[ ! -f "${contract_doc}" ]]; then
    validation_errors+=("missing contract doc: ${contract_doc}")
  fi
  if [[ ! -f "${contract_json}" ]]; then
    validation_errors+=("missing contract json: ${contract_json}")
  fi
  if [[ ! -f "${generator_script}" ]]; then
    validation_errors+=("missing generator script: ${generator_script}")
  fi
  if [[ ! -f "${replay_wrapper}" ]]; then
    validation_errors+=("missing replay wrapper: ${replay_wrapper}")
  fi

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
      .artifact_contract.accepted_real_artifact_shapes
      | map(.shape_id)
      | index("real_flamegraph_svg")
      and index("profile_summary_only")
    ' "${contract_json}" >/dev/null; then
      validation_errors+=("contract is missing required real artifact shape ids")
    fi

    if ! jq -e '
      .artifact_contract.accepted_degraded_receipt_shape.allowed_reason_codes
      | map(.reason_id)
      | index("profiler_unavailable")
      and index("capture_disabled_by_policy")
      and index("platform_unsupported")
      and index("permission_denied")
      and index("preflight_failed")
      and index("upstream_command_failed")
    ' "${contract_json}" >/dev/null; then
      validation_errors+=("contract is missing one or more degraded reason ids")
    fi

    if ! jq -e '
      .artifact_contract.rejected_placeholder_signatures
      | index("parser phase0 flamegraph placeholder")
      and index("parser_phase0 scalar_reference baseline lane (placeholder flamegraph artifact)")
    ' "${contract_json}" >/dev/null; then
      validation_errors+=("contract is missing required placeholder rejection signatures")
    fi
  fi

  {
    printf '%s\n' "contract_doc=${contract_doc}"
    printf '%s\n' "contract_json=${contract_json}"
    printf '%s\n' "generator_script=${generator_script}"
    printf '%s\n' "replay_wrapper=${replay_wrapper}"
    if (( ${#validation_errors[@]} == 0 )); then
      printf '%s\n' "preflight=pass"
    else
      printf '%s\n' "preflight=fail"
      printf '%s\n' "${validation_errors[@]}"
    fi
  } >>"${preflight_log_path}"

  (( ${#validation_errors[@]} == 0 ))
}

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_logs+=("${log_path}")
  step_log_index=$((step_log_index + 1))

  echo "==> ${command_text}"

  set +e
  run_rch "$@" > >(tee "${log_path}") 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    if [[ "${status}" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "${log_path}"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "${log_path}"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "${log_path}"
    else
      remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
      if [[ -n "${remote_exit_code}" ]]; then
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "${log_path}"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
  if [[ -z "${remote_exit_code}" || "${remote_exit_code}" != "0" ]]; then
    failed_command="${command_text} (rch-remote-exit-invalid)"
    return 1
  fi
}

run_mode() {
  case "${mode}" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test parser_phase0_artifact_contract" \
        cargo check -p frankenengine-engine --test parser_phase0_artifact_contract
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test parser_phase0_artifact_contract" \
        cargo test -p frankenengine-engine --test parser_phase0_artifact_contract
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_phase0_artifact_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_phase0_artifact_contract -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test parser_phase0_artifact_contract" \
        cargo check -p frankenengine-engine --test parser_phase0_artifact_contract
      run_step \
        "cargo test -p frankenengine-engine --test parser_phase0_artifact_contract" \
        cargo test -p frankenengine-engine --test parser_phase0_artifact_contract
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_phase0_artifact_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_phase0_artifact_contract -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{
  "schema_version": "franken-engine.parser-phase0-artifact-contract.trace-ids.v1",
  "bead_id": "bd-2muur.6.1",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "trace_ids": ["${trace_id}"],
  "decision_ids": ["${decision_id}"]
}
EOF_TRACE
}

write_validation_report() {
  local exit_code="${1:-0}"
  local outcome error_code_json real_shapes_json degraded_reason_ids_json fail_closed_json

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-920F1-GATE-0001"'
  fi

  real_shapes_json="$(jq -c '.artifact_contract.accepted_real_artifact_shapes | map(.shape_id)' "${contract_json}")"
  degraded_reason_ids_json="$(jq -c '.artifact_contract.accepted_degraded_receipt_shape.allowed_reason_codes | map(.reason_id)' "${contract_json}")"
  fail_closed_json="$(jq -c '.artifact_contract.consumer_fail_closed_reasons' "${contract_json}")"

  jq -n \
    --arg schema_version "franken-engine.parser-phase0-artifact-contract.validation-report.v1" \
    --arg bead_id "bd-2muur.6.1" \
    --arg component "${component}" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg contract_doc "${contract_doc}" \
    --arg contract_json "${contract_json}" \
    --arg generator_script "${generator_script}" \
    --arg replay_wrapper "${replay_wrapper}" \
    --arg replay_command "${replay_command}" \
    --arg outcome "${outcome}" \
    --argjson error_code "${error_code_json}" \
    --argjson source_inputs_present "$(if (( ${#validation_errors[@]} == 0 )); then echo true; else echo false; fi)" \
    --argjson validation_errors "$(json_array_from_args "${validation_errors[@]}")" \
    --argjson real_shape_ids "${real_shapes_json}" \
    --argjson degraded_reason_ids "${degraded_reason_ids_json}" \
    --argjson fail_closed_reasons "${fail_closed_json}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      scenario_id: $scenario_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      contract_doc: $contract_doc,
      contract_json: $contract_json,
      generator_script: $generator_script,
      replay_wrapper: $replay_wrapper,
      replay_command: $replay_command,
      source_inputs_present: $source_inputs_present,
      accepted_real_shape_ids: $real_shape_ids,
      degraded_reason_ids: $degraded_reason_ids,
      fail_closed_reasons: $fail_closed_reasons,
      validation_errors: $validation_errors,
      outcome: $outcome,
      error_code: $error_code
    }' >"${validation_report_path}"
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
    error_code_json='"FE-RGC-920F1-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if worktree_is_dirty; then
    dirty_worktree=true
  else
    dirty_worktree=false
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  {
    echo "{\"schema_version\":\"franken-engine.parser-phase0-artifact-contract.event.v1\",\"scenario_id\":\"${scenario_id}\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"artifact_mode\":\"contract_validation\",\"receipt_reason_code\":null,\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-phase0-artifact-contract.run-manifest.v1",'
    echo '  "bead_id": "bd-2muur.6.1",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"cargo_incremental\": ${cargo_incremental},"
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
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    "
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
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
    echo "    \"contract_doc\": \"${contract_doc}\","
    echo "    \"contract_json\": \"${contract_copy_path}\","
    echo "    \"validation_report\": \"${validation_report_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\""
    echo '  },'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${validation_report_path}\","
    echo "    \"ls -1 ${step_logs_dir}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

main_exit=0
if ! validate_source_inputs; then
  failed_command="validate_source_inputs"
  main_exit=1
else
  cp "${contract_json}" "${contract_copy_path}"
  run_mode || main_exit=$?
fi

write_trace_ids
write_validation_report "${main_exit}"
write_manifest "${main_exit}"

echo "parser phase0 artifact contract artifacts: ${run_dir}"
echo "replay command: ${replay_command}"

exit "${main_exit}"
