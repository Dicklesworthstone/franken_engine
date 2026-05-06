#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/swarm_starvation_rescue_conformance_gate.sh"
planner="${root_dir}/scripts/swarm_starvation_rescue_planner.sh"
contract_json="${root_dir}/docs/swarm_starvation_rescue_conformance_gate_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_STARVATION_RESCUE_CONFORMANCE_GATE.md"

record_pass() {
  printf 'PASS swarm-starvation-rescue-conformance-gate %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-starvation-rescue-conformance-gate %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

write_case_commands() {
  local case_root="$1"
  local case_id="$2"
  mkdir -p "${case_root}/${case_id}"
  cat >"${case_root}/${case_id}/commands.txt" <<'EOF'
./scripts/swarm_starvation_rescue_input_normalizer.sh --brownout-report-json /artifacts/brownout.json --stale-lock-recommendations-json /artifacts/stale-lock.json --lease-exchange-salvage-simulation-json /artifacts/lease.json --admission-budget-plan-json /artifacts/admission.json --capacity-forecast-json /artifacts/capacity.json --slo-threshold-receipt-json /artifacts/slo.json
./scripts/swarm_starvation_rescue_planner.sh --starvation-rescue-input-json /artifacts/swarm_starvation_rescue_input.json --scenario-matrix-report-json /artifacts/swarm_starvation_rescue_scenario_matrix_report.json
EOF
}

write_matrix_fixture() {
  local path="$1"
  local case_root="$2"

  mkdir -p "$case_root"
  write_case_commands "$case_root" "healthy_advisory_ready"
  write_case_commands "$case_root" "brownout_low_priority_starvation"
  write_case_commands "$case_root" "contradictory_ownership_fail_closed"
  write_case_commands "$case_root" "salvage_pinned_manual_review"
  write_case_commands "$case_root" "stale_telemetry_fail_closed"
  write_case_commands "$case_root" "local_fallback_rejected"

  write_json "$path" '{
    "schema_version": "franken-engine.swarm-starvation-rescue-scenario-matrix-report.v1",
    "matrix_schema_version": "franken-engine.swarm-starvation-rescue-scenario-matrix.v1",
    "failure_count": 0,
    "required_scenario_classes": [
      "healthy",
      "brownout",
      "ownership_contradiction",
      "salvage_pinned",
      "stale_telemetry",
      "local_fallback"
    ],
    "cases": [
      {"case_id":"healthy_advisory_ready","scenario_class":"healthy","matched_expected":true},
      {"case_id":"brownout_low_priority_starvation","scenario_class":"brownout","matched_expected":true},
      {"case_id":"contradictory_ownership_fail_closed","scenario_class":"ownership_contradiction","matched_expected":true},
      {"case_id":"salvage_pinned_manual_review","scenario_class":"salvage_pinned","matched_expected":true},
      {"case_id":"stale_telemetry_fail_closed","scenario_class":"stale_telemetry","matched_expected":true},
      {"case_id":"local_fallback_rejected","scenario_class":"local_fallback","matched_expected":true}
    ]
  }'
}

write_input_fixture() {
  local path="$1"
  local scenario="$2"
  local generated_epoch_seconds="$3"

  case "$scenario" in
    rescue)
      write_json "$path" "{
        \"schema_version\": \"franken-engine.swarm-starvation-rescue-input.v1\",
        \"generated_epoch_seconds\": ${generated_epoch_seconds},
        \"decision\": \"pass\",
        \"summary\": {
          \"readiness\": \"ready\",
          \"brownout_finding_count\": 0,
          \"starvation_finding_count\": 0,
          \"safe_to_reopen_count\": 2,
          \"contact_first_count\": 0,
          \"lease_exchange_candidate_count\": 2,
          \"manual_review_count\": 0,
          \"ownership_fail_closed_count\": 0
        },
        \"derived_truth\": {
          \"local_rch_fallback_detected\": false,
          \"contradictory_ownership_detected\": false,
          \"lease_decision\": \"advisory\"
        },
        \"normalized_inputs\": {
          \"admission_budget_plan\": {\"decision\":\"admit\"},
          \"lease_exchange_salvage_simulation\": {\"decision\":\"advisory\"}
        },
        \"fail_closed_reasons\": []
      }"
      ;;
    manual)
      write_json "$path" "{
        \"schema_version\": \"franken-engine.swarm-starvation-rescue-input.v1\",
        \"generated_epoch_seconds\": ${generated_epoch_seconds},
        \"decision\": \"pass\",
        \"summary\": {
          \"readiness\": \"degraded\",
          \"brownout_finding_count\": 0,
          \"starvation_finding_count\": 0,
          \"safe_to_reopen_count\": 0,
          \"contact_first_count\": 1,
          \"lease_exchange_candidate_count\": 0,
          \"manual_review_count\": 1,
          \"ownership_fail_closed_count\": 0
        },
        \"derived_truth\": {
          \"local_rch_fallback_detected\": false,
          \"contradictory_ownership_detected\": false,
          \"lease_decision\": \"manual_review_required\"
        },
        \"normalized_inputs\": {
          \"admission_budget_plan\": {\"decision\":\"admit\"},
          \"lease_exchange_salvage_simulation\": {\"decision\":\"manual_review_required\"}
        },
        \"fail_closed_reasons\": []
      }"
      ;;
    fail)
      write_json "$path" "{
        \"schema_version\": \"franken-engine.swarm-starvation-rescue-input.v1\",
        \"generated_epoch_seconds\": ${generated_epoch_seconds},
        \"decision\": \"fail_closed\",
        \"summary\": {
          \"readiness\": \"fail_closed\",
          \"brownout_finding_count\": 0,
          \"starvation_finding_count\": 0,
          \"safe_to_reopen_count\": 0,
          \"contact_first_count\": 0,
          \"lease_exchange_candidate_count\": 0,
          \"manual_review_count\": 0,
          \"ownership_fail_closed_count\": 1
        },
        \"derived_truth\": {
          \"local_rch_fallback_detected\": true,
          \"contradictory_ownership_detected\": true,
          \"lease_decision\": \"fail_closed\"
        },
        \"normalized_inputs\": {
          \"admission_budget_plan\": {\"decision\":\"admit\"},
          \"lease_exchange_salvage_simulation\": {\"decision\":\"fail_closed\"}
        },
        \"fail_closed_reasons\": [
          {\"kind\":\"local_rch_fallback_admitted\",\"detail\":\"capacity forecast passed while local fallback remained admitted\"},
          {\"kind\":\"contradictory_ownership\",\"detail\":\"lease simulation reports ownership fail-closed state\"}
        ]
      }"
      ;;
    stale)
      write_json "$path" "{
        \"schema_version\": \"franken-engine.swarm-starvation-rescue-input.v1\",
        \"generated_epoch_seconds\": ${generated_epoch_seconds},
        \"decision\": \"pass\",
        \"summary\": {
          \"readiness\": \"ready\",
          \"brownout_finding_count\": 0,
          \"starvation_finding_count\": 0,
          \"safe_to_reopen_count\": 1,
          \"contact_first_count\": 0,
          \"lease_exchange_candidate_count\": 1,
          \"manual_review_count\": 0,
          \"ownership_fail_closed_count\": 0
        },
        \"derived_truth\": {
          \"local_rch_fallback_detected\": false,
          \"contradictory_ownership_detected\": false,
          \"lease_decision\": \"advisory\"
        },
        \"normalized_inputs\": {
          \"admission_budget_plan\": {\"decision\":\"admit\"},
          \"lease_exchange_salvage_simulation\": {\"decision\":\"advisory\"}
        },
        \"fail_closed_reasons\": []
      }"
      ;;
    *)
      record_fail "unknown fixture scenario ${scenario}"
      ;;
  esac
}

run_gate_case() {
  local scenario="$1"
  local planner_expected_exit="$2"
  local gate_expected_exit="$3"
  local tmp_root="$4"
  local input_generated_epoch_seconds="$5"
  local gate_now_epoch_seconds="$6"
  local case_dir="${tmp_root}/${scenario}"
  local matrix_path="${case_dir}/matrix.json"
  local input_path="${case_dir}/input.json"
  local plan_dir="${case_dir}/plan"
  local gate_dir="${case_dir}/gate"

  mkdir -p "$plan_dir" "$gate_dir" "${case_dir}/cases"
  write_matrix_fixture "$matrix_path" "${case_dir}/cases"
  write_input_fixture "$input_path" "$scenario" "$input_generated_epoch_seconds"

  set +e
  "$planner" \
    --starvation-rescue-input-json "$input_path" \
    --scenario-matrix-report-json "$matrix_path" \
    --output-dir "$plan_dir" >/dev/null 2>&1
  local planner_exit=$?
  set -e
  [[ "$planner_exit" -eq "$planner_expected_exit" ]] || record_fail "${scenario}: planner exit ${planner_exit} != ${planner_expected_exit}"

  set +e
  "$gate" \
    --starvation-rescue-plan-json "${plan_dir}/swarm_starvation_rescue_plan.json" \
    --now-epoch-seconds "$gate_now_epoch_seconds" \
    --stale-after-seconds 1800 \
    --output-dir "$gate_dir" >/dev/null 2>&1
  local gate_exit=$?
  set -e
  [[ "$gate_exit" -eq "$gate_expected_exit" ]] || record_fail "${scenario}: gate exit ${gate_exit} != ${gate_expected_exit}"

  [[ -f "${gate_dir}/swarm_starvation_rescue_conformance_report.json" ]] || record_fail "${scenario}: missing conformance report"
}

run_check() {
  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  jq -e '
    .schema_version == "franken-engine.swarm-starvation-rescue-conformance-gate-contract.v1"
    and .report_schema_version == "franken-engine.swarm-starvation-rescue-conformance-report.v1"
    and (.required_inputs | length) == 3
    and (.validated_invariants | length) >= 5
  ' "$contract_json" >/dev/null || record_fail "contract check"
  grep -q 'swarm_starvation_rescue_conformance_report.json' "$docs_path"
  grep -qi 'bare cargo' "$docs_path"
  record_pass "check"
}

run_selftest() {
  local tmp_root now_epoch stale_epoch
  tmp_root="$(mktemp -d)"
  now_epoch="$(date -u +%s)"
  stale_epoch="$((now_epoch - 7200))"

  run_gate_case rescue 0 0 "$tmp_root" "$now_epoch" "$now_epoch"
  jq -e '
    .decision == "pass"
    and .summary.plan_decision == "advisory"
    and .summary.gate_failure_count == 0
    and (.verified_invariants | any(.name == "artifact_lineage_is_real" and .outcome == "pass"))
  ' "${tmp_root}/rescue/gate/swarm_starvation_rescue_conformance_report.json" >/dev/null \
    || record_fail "rescue: conformance assertions failed"
  record_pass "healthy advisory rescue stays conformant"

  run_gate_case manual 75 0 "$tmp_root" "$now_epoch" "$now_epoch"
  jq -e '
    .decision == "pass"
    and .summary.plan_decision == "manual_review_required"
    and (.verified_invariants | any(.name == "contact_first_blocks_advisory" and .outcome == "pass"))
    and (.verified_invariants | any(.name == "salvage_pinned_blocks_advisory" and .outcome == "pass"))
  ' "${tmp_root}/manual/gate/swarm_starvation_rescue_conformance_report.json" >/dev/null \
    || record_fail "manual: conformance assertions failed"
  record_pass "manual review rescue stays ownership-safe"

  run_gate_case fail 42 0 "$tmp_root" "$now_epoch" "$now_epoch"
  jq -e '
    .decision == "pass"
    and .summary.plan_decision == "fail_closed"
    and (.verified_invariants | any(.name == "contradictory_ownership_blocks_rescue" and .outcome == "pass"))
    and (.verified_invariants | any(.name == "local_fallback_forces_fail_closed" and .outcome == "pass"))
  ' "${tmp_root}/fail/gate/swarm_starvation_rescue_conformance_report.json" >/dev/null \
    || record_fail "fail: conformance assertions failed"
  record_pass "denied rescue stays fail-closed and honest"

  run_gate_case stale 0 42 "$tmp_root" "$stale_epoch" "$now_epoch"
  jq -e '
    .decision == "fail_closed"
    and (.gate_failures | any(.code == "stale_rescue_input_evidence"))
  ' "${tmp_root}/stale/gate/swarm_starvation_rescue_conformance_report.json" >/dev/null \
    || record_fail "stale: missing stale evidence failure"
  record_pass "stale rescue evidence fails closed"

  cp -R "${tmp_root}/rescue" "${tmp_root}/bare"
  printf 'cargo test -p frankenengine-engine --test forbidden\n' >> "${tmp_root}/bare/cases/healthy_advisory_ready/commands.txt"
  set +e
  "$planner" \
    --starvation-rescue-input-json "${tmp_root}/bare/input.json" \
    --scenario-matrix-report-json "${tmp_root}/bare/matrix.json" \
    --output-dir "${tmp_root}/bare/plan" >/dev/null 2>&1
  local bare_planner_exit=$?
  set -e
  [[ "$bare_planner_exit" -eq 0 ]] || record_fail "bare cargo: planner exit ${bare_planner_exit} != 0"
  set +e
  "$gate" \
    --starvation-rescue-plan-json "${tmp_root}/bare/plan/swarm_starvation_rescue_plan.json" \
    --now-epoch-seconds "$now_epoch" \
    --stale-after-seconds 1800 \
    --output-dir "${tmp_root}/bare/gate-bare" >/dev/null 2>&1
  local bare_exit=$?
  set -e
  [[ "$bare_exit" -eq 42 ]] || record_fail "bare cargo: gate exit ${bare_exit} != 42"
  jq -e '
    .decision == "fail_closed"
    and (.gate_failures | any(.code == "bare_cargo_command_detected"))
  ' "${tmp_root}/bare/gate-bare/swarm_starvation_rescue_conformance_report.json" >/dev/null \
    || record_fail "bare cargo: missing gate failure"
  record_pass "bare cargo drill transcript fails closed"

  printf 'swarm_starvation_rescue_conformance_gate_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_fail "unknown mode ${1:-}"
    ;;
esac
