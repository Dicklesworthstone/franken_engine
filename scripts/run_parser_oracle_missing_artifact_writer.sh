#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
artifact_root="${PARSER_ORACLE_MISSING_ARTIFACT_WRITER_ARTIFACT_ROOT:-artifacts/parser_oracle_missing_artifact_writer}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_parser_oracle_missing_artifact_writer_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
writer_report_path="${run_dir}/parser_oracle_missing_artifact_writer_report.json"
step_logs_dir="${run_dir}/step_logs"
preflight_log_path="${step_logs_dir}/step_000.log"

gate_script="scripts/run_parser_oracle_gate.sh"
gate_doc="docs/PARSER_ORACLE_GATE.md"
contract_doc="docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md"
contract_json="docs/parser_oracle_missing_artifact_contract_v1.json"
contract_validation_script="scripts/run_parser_oracle_missing_artifact_contract.sh"
replay_wrapper="scripts/e2e/parser_oracle_missing_artifact_writer_replay.sh"

trace_id="trace-parser-oracle-missing-artifact-writer-${timestamp}"
decision_id="decision-parser-oracle-missing-artifact-writer-${timestamp}"
policy_id="policy-parser-oracle-missing-artifact-writer-v1"
component="parser_oracle_missing_artifact_writer_gate"
scenario_id="rgc-920g2"
replay_command="./scripts/e2e/parser_oracle_missing_artifact_writer_replay.sh ${mode}"

declare -a commands_run=()
declare -a validation_errors=()
declare -a step_logs=("${preflight_log_path}")
failed_command=""
manifest_written=false
step_log_index=1
scenario_results_json='[]'

mkdir -p "${run_dir}" "${step_logs_dir}"
printf '==> validate parser oracle missing-artifact writer sources\n' >"${preflight_log_path}"

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

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

validate_source_inputs() {
  local input
  commands_run+=("jq empty ${contract_json}")

  if ! command -v jq >/dev/null 2>&1; then
    validation_errors+=("jq is required for writer validation")
  fi

  for input in \
    "${gate_script}" \
    "${gate_doc}" \
    "${contract_doc}" \
    "${contract_json}" \
    "${contract_validation_script}" \
    "${replay_wrapper}"; do
    if [[ ! -f "${input}" ]]; then
      validation_errors+=("missing required input: ${input}")
    fi
  done

  if [[ -f "${contract_json}" ]] && ! jq -e '.' "${contract_json}" >/dev/null 2>&1; then
    validation_errors+=("failed to parse contract json: ${contract_json}")
  fi

  if [[ -f "${gate_script}" ]]; then
    if ! rg -q 'write_missing_artifact_receipt' "${gate_script}"; then
      validation_errors+=("gate script must expose write_missing_artifact_receipt")
    fi
    if ! rg -q 'emit_missing_artifact_receipt' "${gate_script}"; then
      validation_errors+=("gate script must expose emit_missing_artifact_receipt")
    fi
    if ! rg -q 'select_missing_artifact_reason_id' "${gate_script}"; then
      validation_errors+=("gate script must expose select_missing_artifact_reason_id")
    fi
    if rg -q 'echo "\{\}" >"\$baseline_path"' "${gate_script}"; then
      validation_errors+=("gate script must not emit baseline.json placeholder backfills")
    fi
    if rg -q 'echo "\{\\\"status\\\":\\\"not_run\\\"\}" >"\$relation_report_path"' "${gate_script}"; then
      validation_errors+=("gate script must not emit relation_report.json placeholder backfills")
    fi
    if rg -q ': >"\$relation_events_path"' "${gate_script}"; then
      validation_errors+=("gate script must not emit zero-byte relation_events backfills")
    fi
    if rg -q ': >"\$evidence_path"' "${gate_script}"; then
      validation_errors+=("gate script must not emit zero-byte metamorphic evidence backfills")
    fi
    if rg -q ': >"\$drift_digest_path"' "${gate_script}"; then
      validation_errors+=("gate script must not emit zero-byte drift digest backfills")
    fi
  fi

  {
    printf '%s\n' "gate_script=${gate_script}"
    printf '%s\n' "gate_doc=${gate_doc}"
    printf '%s\n' "contract_doc=${contract_doc}"
    printf '%s\n' "contract_json=${contract_json}"
    printf '%s\n' "contract_validation_script=${contract_validation_script}"
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

run_receipt_scenario() {
  local scenario_name="$1"
  local mode_value="$2"
  local exit_code="$3"
  local fixture_state="$4"
  local reason_override="${5:-}"
  local scenario_dir="${run_dir}/scenarios/${scenario_name}"

  commands_run+=("scenario:${scenario_name}:${mode_value}:${fixture_state}:${reason_override:-auto}")
  mkdir -p "${scenario_dir}"

  ROOT_DIR="${root_dir}" \
  SCENARIO_DIR="${scenario_dir}" \
  SCENARIO_MODE="${mode_value}" \
  SCENARIO_EXIT_CODE="${exit_code}" \
  SCENARIO_FIXTURE_STATE="${fixture_state}" \
  SCENARIO_REASON_OVERRIDE="${reason_override}" \
    bash <<'EOF'
set -euo pipefail

set -- "${SCENARIO_MODE}"
source "${ROOT_DIR}/scripts/run_parser_oracle_gate.sh"

run_dir="${SCENARIO_DIR}"
command_logs_dir="${run_dir}/command_logs"
failures_dir="${run_dir}/minimized_failures"
baseline_path="${run_dir}/baseline.json"
relation_report_path="${run_dir}/relation_report.json"
relation_events_path="${run_dir}/relation_events.jsonl"
evidence_path="${run_dir}/metamorphic_evidence.jsonl"
golden_checksums_path="${run_dir}/golden_checksums.txt"
proof_note_path="${run_dir}/proof_note.md"
drift_digest_path="${run_dir}/drift_digest.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
manifest_path="${run_dir}/manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
missing_artifact_receipt_path="${run_dir}/parser_oracle_missing_artifact_receipt.json"
mode="${SCENARIO_MODE}"

mkdir -p "${run_dir}" "${command_logs_dir}" "${failures_dir}"

case "${SCENARIO_FIXTURE_STATE}" in
  relation_only)
    printf '{}\n' >"${relation_report_path}"
    ;;
  all_artifacts)
    printf '{"baseline":"real"}\n' >"${baseline_path}"
    printf '{"summary":{"equivalent_count":1,"minor_drift_count":0,"critical_drift_count":0},"decision":{"action":"allow","fallback_reason":"none"}}\n' >"${relation_report_path}"
    printf '{"event":"relation"}\n' >"${relation_events_path}"
    printf '{"event":"evidence"}\n' >"${evidence_path}"
    printf '# real drift digest\n' >"${drift_digest_path}"
    ;;
  none)
    ;;
  *)
    echo "unsupported scenario fixture state: ${SCENARIO_FIXTURE_STATE}" >&2
    exit 2
    ;;
esac

if [[ -n "${SCENARIO_REASON_OVERRIDE}" ]]; then
  export PARSER_ORACLE_MISSING_ARTIFACT_REASON_OVERRIDE="${SCENARIO_REASON_OVERRIDE}"
else
  unset PARSER_ORACLE_MISSING_ARTIFACT_REASON_OVERRIDE || true
fi

write_missing_artifact_receipt "${SCENARIO_EXIT_CODE}"
EOF

  printf '%s\n' "${scenario_dir}"
}

record_scenario_result() {
  local scenario_name="$1"
  local scenario_dir="$2"
  local expected_present="$3"
  local expected_reason_id="$4"
  local expected_stage="$5"
  local expected_consumer_action="$6"
  local expected_missing_csv="$7"

  local receipt_path="${scenario_dir}/parser_oracle_missing_artifact_receipt.json"
  local scenario_log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  local -a errors=()
  local expected_missing_json actual_missing_json
  local receipt_present legacy_baseline legacy_relation_report legacy_relation_events legacy_evidence legacy_digest
  local receipt_json result_json

  step_logs+=("${scenario_log_path}")
  step_log_index=$((step_log_index + 1))

  if [[ -f "${receipt_path}" ]]; then
    receipt_present=true
  else
    receipt_present=false
  fi

  if [[ "${expected_present}" == "true" && "${receipt_present}" != true ]]; then
    errors+=("expected receipt but none was emitted")
  fi
  if [[ "${expected_present}" == "false" && "${receipt_present}" != false ]]; then
    errors+=("did not expect receipt but one was emitted")
  fi

  if [[ "${receipt_present}" == true ]]; then
    if [[ "$(jq -r '.reason_id' "${receipt_path}")" != "${expected_reason_id}" ]]; then
      errors+=("reason_id mismatch")
    fi
    if [[ "$(jq -r '.stage' "${receipt_path}")" != "${expected_stage}" ]]; then
      errors+=("stage mismatch")
    fi
    if [[ "$(jq -r '.consumer_action' "${receipt_path}")" != "${expected_consumer_action}" ]]; then
      errors+=("consumer_action mismatch")
    fi
    if [[ "$(jq -r '.placeholder_rejected' "${receipt_path}")" != "true" ]]; then
      errors+=("placeholder_rejected must be true")
    fi

    expected_missing_json="$(
      printf '%s\n' "${expected_missing_csv}" | tr ',' '\n' | jq -R . | jq -c -s 'map(select(length > 0))'
    )"
    actual_missing_json="$(jq -c '[.missing_artifacts[].artifact_path]' "${receipt_path}")"
    if [[ "${actual_missing_json}" != "${expected_missing_json}" ]]; then
      errors+=("missing_artifacts mismatch")
    fi
  fi

  if [[ "${receipt_present}" == true ]]; then
    receipt_json="$(jq -c '.' "${receipt_path}")"
  else
    receipt_json="null"
  fi

  legacy_baseline=false
  legacy_relation_report=false
  legacy_relation_events=false
  legacy_evidence=false
  legacy_digest=false

  if [[ -f "${scenario_dir}/baseline.json" ]] && [[ "$(cat "${scenario_dir}/baseline.json")" == "{}" ]]; then
    legacy_baseline=true
    errors+=("legacy baseline placeholder was written")
  fi
  if [[ -f "${scenario_dir}/relation_report.json" ]] && [[ "$(cat "${scenario_dir}/relation_report.json")" == '{"status":"not_run"}' ]]; then
    legacy_relation_report=true
    errors+=("legacy relation_report placeholder was written")
  fi
  if [[ -f "${scenario_dir}/relation_events.jsonl" ]] && [[ ! -s "${scenario_dir}/relation_events.jsonl" ]]; then
    legacy_relation_events=true
    errors+=("legacy zero-byte relation_events placeholder was written")
  fi
  if [[ -f "${scenario_dir}/metamorphic_evidence.jsonl" ]] && [[ ! -s "${scenario_dir}/metamorphic_evidence.jsonl" ]]; then
    legacy_evidence=true
    errors+=("legacy zero-byte metamorphic_evidence placeholder was written")
  fi
  if [[ -f "${scenario_dir}/drift_digest.md" ]] && [[ ! -s "${scenario_dir}/drift_digest.md" ]]; then
    legacy_digest=true
    errors+=("legacy zero-byte drift_digest placeholder was written")
  fi

  result_json="$(
    jq -n \
      --arg scenario_name "${scenario_name}" \
      --arg scenario_dir "${scenario_dir}" \
      --argjson receipt_present "${receipt_present}" \
      --arg expected_reason_id "${expected_reason_id}" \
      --arg expected_stage "${expected_stage}" \
      --arg expected_consumer_action "${expected_consumer_action}" \
      --argjson legacy_baseline "${legacy_baseline}" \
      --argjson legacy_relation_report "${legacy_relation_report}" \
      --argjson legacy_relation_events "${legacy_relation_events}" \
      --argjson legacy_evidence "${legacy_evidence}" \
      --argjson legacy_digest "${legacy_digest}" \
      --argjson receipt "${receipt_json}" \
      --argjson errors "$(json_array_from_args "${errors[@]}")" \
      --argjson status "$([[ ${#errors[@]} -eq 0 ]] && echo '"pass"' || echo '"fail"')" \
      '{
        scenario_name: $scenario_name,
        scenario_dir: $scenario_dir,
        receipt_present: $receipt_present,
        expected_reason_id: $expected_reason_id,
        expected_stage: $expected_stage,
        expected_consumer_action: $expected_consumer_action,
        receipt: $receipt,
        legacy_baseline_placeholder_written: $legacy_baseline,
        legacy_relation_report_placeholder_written: $legacy_relation_report,
        legacy_relation_events_placeholder_written: $legacy_relation_events,
        legacy_metamorphic_evidence_placeholder_written: $legacy_evidence,
        legacy_drift_digest_placeholder_written: $legacy_digest,
        errors: $errors,
        status: $status
      }'
  )"

  printf '%s\n' "${result_json}" >"${scenario_log_path}"
  scenario_results_json="$(jq -c --argjson result "${result_json}" '. + [$result]' <<<"${scenario_results_json}")"
}

run_local_scenarios() {
  local scenario_dir

  scenario_dir="$(run_receipt_scenario "not_run_by_design_check" "check" "0" "none")"
  record_scenario_result \
    "not_run_by_design_check" \
    "${scenario_dir}" \
    "true" \
    "not_run_by_design" \
    "mode_selection" \
    "record_and_continue" \
    "baseline.json,relation_report.json,relation_events.jsonl,metamorphic_evidence.jsonl,drift_digest.md"

  scenario_dir="$(run_receipt_scenario "skipped_by_gate_condition_override" "ci" "0" "none" "skipped_by_gate_condition")"
  record_scenario_result \
    "skipped_by_gate_condition_override" \
    "${scenario_dir}" \
    "true" \
    "skipped_by_gate_condition" \
    "gate_condition" \
    "surface_degraded" \
    "baseline.json,relation_report.json,relation_events.jsonl,metamorphic_evidence.jsonl,drift_digest.md"

  scenario_dir="$(run_receipt_scenario "failed_before_artifact_creation" "ci" "1" "none")"
  record_scenario_result \
    "failed_before_artifact_creation" \
    "${scenario_dir}" \
    "true" \
    "failed_before_artifact_creation" \
    "execution" \
    "fail_closed" \
    "baseline.json,relation_report.json,relation_events.jsonl,metamorphic_evidence.jsonl,drift_digest.md"

  scenario_dir="$(run_receipt_scenario "missing_unexpected_absence" "ci" "0" "relation_only")"
  record_scenario_result \
    "missing_unexpected_absence" \
    "${scenario_dir}" \
    "true" \
    "missing_unexpected_absence" \
    "post_run_validation" \
    "fail_closed" \
    "baseline.json,relation_events.jsonl,metamorphic_evidence.jsonl,drift_digest.md"

  scenario_dir="$(run_receipt_scenario "all_artifacts_present" "ci" "0" "all_artifacts")"
  record_scenario_result \
    "all_artifacts_present" \
    "${scenario_dir}" \
    "false" \
    "none" \
    "none" \
    "none" \
    ""
}

run_mode() {
  run_local_scenarios

  case "${mode}" in
    check|test)
      ;;
    ci)
      if ! command -v rch >/dev/null 2>&1; then
        echo "rch is required for parser oracle missing-artifact writer ci verification" >&2
        return 2
      fi
      run_step \
        "cargo check -p frankenengine-engine --test parser_oracle_missing_artifact_writer" \
        cargo check -p frankenengine-engine --test parser_oracle_missing_artifact_writer
      run_step \
        "cargo test -p frankenengine-engine --test parser_oracle_missing_artifact_writer" \
        cargo test -p frankenengine-engine --test parser_oracle_missing_artifact_writer
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_oracle_missing_artifact_writer -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_oracle_missing_artifact_writer -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{
  "schema_version": "franken-engine.parser-oracle-missing-artifact-writer.trace-ids.v1",
  "bead_id": "bd-2muur.7.2",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "trace_ids": ["${trace_id}"],
  "decision_ids": ["${decision_id}"]
}
EOF_TRACE
}

write_writer_report() {
  local exit_code="${1:-0}"
  local outcome error_code_json

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-920G2-GATE-0001"'
  fi

  jq -n \
    --arg schema_version "franken-engine.parser-oracle-missing-artifact-writer.report.v1" \
    --arg bead_id "bd-2muur.7.2" \
    --arg component "${component}" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg gate_script "${gate_script}" \
    --arg gate_doc "${gate_doc}" \
    --arg contract_doc "${contract_doc}" \
    --arg contract_json "${contract_json}" \
    --arg contract_validation_script "${contract_validation_script}" \
    --arg replay_wrapper "${replay_wrapper}" \
    --arg replay_command "${replay_command}" \
    --arg outcome "${outcome}" \
    --argjson error_code "${error_code_json}" \
    --argjson preflight_errors "$(json_array_from_args "${validation_errors[@]}")" \
    --argjson scenarios "${scenario_results_json}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      scenario_id: $scenario_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      gate_script: $gate_script,
      gate_doc: $gate_doc,
      contract_doc: $contract_doc,
      contract_json: $contract_json,
      contract_validation_script: $contract_validation_script,
      replay_wrapper: $replay_wrapper,
      replay_command: $replay_command,
      preflight_errors: $preflight_errors,
      scenarios: $scenarios,
      all_scenarios_passed: ($scenarios | all(.status == "pass")),
      outcome: $outcome,
      error_code: $error_code
    }' >"${writer_report_path}"
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
    error_code_json='"FE-RGC-920G2-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if [[ -n "$(git status --short --untracked-files=normal -- . ":(exclude)${artifact_root%/}/" ":(exclude).beads/" ":(exclude).claude/" 2>/dev/null || true)" ]]; then
    dirty_worktree=true
  else
    dirty_worktree=false
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  jq -c \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg outcome "${outcome}" \
    --argjson error_code "${error_code_json}" \
    --arg replay_command "${replay_command}" \
    '.[] | {
      schema_version: "franken-engine.parser-oracle-missing-artifact-writer.event.v1",
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: "scenario_validated",
      scenario_name,
      artifact_path: ((.receipt.missing_artifacts[0].artifact_path) // "parser_oracle_missing_artifact_receipt.json"),
      artifact_role: ((.receipt.missing_artifacts[0].artifact_role) // "missing_artifact_receipt"),
      stage: ((.receipt.stage) // "none"),
      reason_code: ((.receipt.reason_code) // "none"),
      consumer_action: ((.receipt.consumer_action) // "none"),
      outcome: .status,
      error_code: (if .status == "pass" then null else "FE-RGC-920G2-SCENARIO-0001" end),
      replay_command: $replay_command
    }' <<<"${scenario_results_json}" >"${events_path}"

  jq -nc \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg outcome "${outcome}" \
    --argjson error_code "${error_code_json}" \
    --arg replay_command "${replay_command}" \
    '{
      schema_version: "franken-engine.parser-oracle-missing-artifact-writer.event.v1",
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: "gate_completed",
      artifact_path: "parser_oracle_missing_artifact_receipt.json",
      artifact_role: "missing_artifact_receipt",
      stage: "writer_validation",
      reason_code: "none",
      consumer_action: "none",
      outcome: $outcome,
      error_code: $error_code,
      replay_command: $replay_command
    }' >>"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-oracle-missing-artifact-writer.run-manifest.v1",'
    echo '  "bead_id": "bd-2muur.7.2",'
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
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo "  \"replay_command\": \"${replay_command}\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"writer_report\": \"${writer_report_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\""
    echo '  },'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${step_logs[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${writer_report_path}\","
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
  run_mode || main_exit=$?
fi

if jq -e 'all(.status == "pass")' <<<"${scenario_results_json}" >/dev/null 2>&1; then
  :
else
  main_exit=1
  if [[ -z "${failed_command}" ]]; then
    failed_command="run_local_scenarios"
  fi
fi

write_trace_ids
write_writer_report "${main_exit}"
write_manifest "${main_exit}"

echo "parser oracle missing-artifact writer artifacts: ${run_dir}"
echo "replay command: ${replay_command}"

exit "${main_exit}"
