#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
forecaster="${root_dir}/scripts/swarm_autopilot_brownout_forecaster.sh"
fixtures_path="${SWARM_AUTOPILOT_BROWNOUT_FORECASTER_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_brownout_forecaster/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_brownout_forecaster_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_BROWNOUT_FORECASTER.md"
mode="${1:-check}"
failures=0
fixed_now_epoch_seconds="1778122000"
validated_horizon_seconds="1800"
stale_after_seconds="1800"

record_pass() {
  printf 'PASS swarm-autopilot-brownout-forecaster %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-brownout-forecaster %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-brownout-forecaster-fixtures.v1"
    and .base_evidence_warehouse_json.schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and .base_queue_signal_input_json.schema_version == "franken-engine.swarm-topology-queue-signal-input.v1"
    and .base_queue_fidelity_receipt_json.schema_version == "franken-engine.swarm-topology-aware-queue-fidelity-receipt.v1"
    and .base_hindsight_bundle_json.schema_version == "franken-engine.swarm-autopilot-brownout-hindsight-bundle.v1"
    and (.cases | length) == 5
    and ([.cases[].case_id] | unique | length) == 5
    and any(.cases[]; .case_id == "green_low_pressure" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "imminent_rch_slot_brownout" and .expected.required_category == "rch_slot_exhaustion" and .expected.required_state == "brownout")
    and any(.cases[]; .case_id == "proof_cache_pressure_escalation" and .expected.required_category == "proof_cache_pressure" and .expected.required_state == "brownout")
    and any(.cases[]; .case_id == "stale_progress_risk" and .expected.required_category == "stale_progress_risk" and .expected.required_state == "brownout")
    and any(.cases[]; .case_id == "contradictory_evidence_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-BROWNOUT-CONTRADICTORY-EVIDENCE")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-brownout-forecaster-contract.v1"
    and .bead_id == "bd-g7bk2"
    and ((["bd-4t4oi","bd-2pn2x"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_brownout_forecaster.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_BROWNOUT_FORECASTER.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_brownout_forecaster/cases.json"
    and .forecast_schema_version == "franken-engine.swarm-autopilot-brownout-forecast.v1"
    and .comparison_schema_version == "franken-engine.swarm-autopilot-brownout-hindsight-comparison.v1"
    and ((["admitted_heavy_lane_pressure","rch_slot_exhaustion","target_dir_pressure","stale_progress_risk","proof_cache_pressure","fairness_starvation_window"] - .forecast_categories) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The forecaster is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Local fallback contamination fails closed.' "$docs_path" \
    && grep -Fq 'Incomplete or contradictory evidence fails closed.' "$docs_path" \
    && grep -Fq 'Forecasts stay bounded by the validated horizon.' "$docs_path" \
    && grep -Fq 'The forecaster compares predicted states against actual hindsight bundle outcomes.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | {
        evidence_warehouse_json: ($root.base_evidence_warehouse_json * ($case.overrides.evidence_warehouse_json // {})),
        queue_signal_input_json: ($root.base_queue_signal_input_json * ($case.overrides.queue_signal_input_json // {})),
        queue_fidelity_receipt_json: ($root.base_queue_fidelity_receipt_json * ($case.overrides.queue_fidelity_receipt_json // {})),
        hindsight_bundle_json: ($root.base_hindsight_bundle_json * ($case.overrides.hindsight_bundle_json // {}))
      }
  ' "$fixtures_path" >"${case_dir}/materialized_inputs.json"

  jq '.evidence_warehouse_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/evidence_warehouse.json"
  jq '.queue_signal_input_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/queue_signal_input.json"
  jq '.queue_fidelity_receipt_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/queue_fidelity_receipt.json"
  jq '.hindsight_bundle_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/hindsight_bundle.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in \
    swarm_autopilot_brownout_forecast.json \
    swarm_autopilot_brownout_hindsight_comparison.json \
    events.jsonl \
    commands.txt \
    report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local forecast_json="${output_case_dir}/swarm_autopilot_brownout_forecast.json"
  local comparison_json="${output_case_dir}/swarm_autopilot_brownout_hindsight_comparison.json"
  local required_error required_category required_state expected_match_count

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-brownout-forecast.v1"
    and .decision == $expected[0].decision
    and .validated_horizon_seconds == 1800
    and (.forecast_id | startswith("brownout-forecast-"))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and (.artifact_paths.swarm_autopilot_brownout_forecast_json | length > 0)
    and (.artifact_paths.swarm_autopilot_brownout_hindsight_comparison_json | length > 0)
  ' "$forecast_json" >/dev/null || record_failure "${case_id} forecast shape mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-brownout-hindsight-comparison.v1"
    and (.comparison_id | startswith("brownout-compare-"))
    and .summary.compared_category_count == 6
    and (.comparisons | length) == 6
  ' "$comparison_json" >/dev/null || record_failure "${case_id} comparison shape mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$forecast_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
    jq -e '.summary.overall_state == "fail_closed" and .summary.brownout_state == "fail_closed"' "$forecast_json" >/dev/null \
      || record_failure "${case_id} fail_closed summary mismatch"
  fi

  required_category="$(jq -r '.required_category // ""' "$expected_json")"
  required_state="$(jq -r '.required_state // ""' "$expected_json")"
  if [[ -n "$required_category" && -n "$required_state" ]]; then
    jq -e --arg required_category "$required_category" --arg required_state "$required_state" '.forecasts[$required_category].state == $required_state' "$forecast_json" >/dev/null \
      || record_failure "${case_id} missing expected ${required_category}=${required_state}"
    jq -e --arg required_category "$required_category" --arg required_state "$required_state" '.comparisons | any(.category == $required_category and .actual_state == $required_state)' "$comparison_json" >/dev/null \
      || record_failure "${case_id} hindsight comparison missing ${required_category} actual state"
  fi

  expected_match_count="$(jq -r '.expected_match_count // -1' "$expected_json")"
  if [[ "$expected_match_count" -ge 0 ]]; then
    jq -e --argjson expected_match_count "$expected_match_count" '.summary.match_count == $expected_match_count' "$comparison_json" >/dev/null \
      || record_failure "${case_id} unexpected comparison match count"
  fi

  grep -Fq './scripts/swarm_autopilot_brownout_forecaster.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing forecaster command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local expected_json="${case_dir}/expected.json"
  local output_case_dir="${case_dir}/output"
  local rc

  mkdir -p "$case_dir" "$output_case_dir"
  materialize_case "$case_id" "$case_dir"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"$expected_json"

  set +e
  bash "$forecaster" \
    --evidence-warehouse-json "${case_dir}/evidence_warehouse.json" \
    --queue-signal-input-json "${case_dir}/queue_signal_input.json" \
    --queue-fidelity-receipt-json "${case_dir}/queue_fidelity_receipt.json" \
    --hindsight-bundle-json "${case_dir}/hindsight_bundle.json" \
    --source-revision "fixture-${case_id}" \
    --now-epoch-seconds "$fixed_now_epoch_seconds" \
    --stale-after-seconds "$stale_after_seconds" \
    --validated-horizon-seconds "$validated_horizon_seconds" \
    --output-dir "$output_case_dir"
  rc=$?
  set -e

  if [[ "$rc" -ne "$(jq -r '.expected_exit_code' "$expected_json")" ]]; then
    record_failure "${case_id} exit code ${rc} != expected $(jq -r '.expected_exit_code' "$expected_json")"
  fi

  validate_required_artifacts "$output_case_dir"
  validate_outputs "$output_case_dir" "$case_id" "$expected_json"
}

run_check() {
  fixtures_shape_ok || record_failure "fixtures shape mismatch"
  contract_shape_ok || record_failure "contract JSON shape mismatch"
  docs_shape_ok || record_failure "docs truth text mismatch"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local temp_dir
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' RETURN

  while IFS= read -r case_id; do
    run_case "$case_id" "${temp_dir}/${case_id}"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest"
  else
    exit 1
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    else
      exit 1
    fi
    ;;
  *)
    usage
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
