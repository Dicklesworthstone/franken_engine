#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_starvation_rescue_planner.sh"
contract_json="${root_dir}/docs/swarm_starvation_rescue_planner_contract_v1.json"

record_pass() {
  printf 'PASS swarm-starvation-rescue-planner %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-starvation-rescue-planner %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

write_matrix_fixture() {
  local path="$1"
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

  case "$scenario" in
    rescue)
      write_json "$path" '{
        "schema_version": "franken-engine.swarm-starvation-rescue-input.v1",
        "decision": "pass",
        "summary": {
          "readiness": "ready",
          "brownout_finding_count": 0,
          "starvation_finding_count": 0,
          "safe_to_reopen_count": 2,
          "contact_first_count": 0,
          "lease_exchange_candidate_count": 2,
          "manual_review_count": 0,
          "ownership_fail_closed_count": 0
        },
        "derived_truth": {
          "local_rch_fallback_detected": false,
          "lease_decision": "advisory"
        },
        "normalized_inputs": {
          "admission_budget_plan": {"decision":"admit"},
          "lease_exchange_salvage_simulation": {"decision":"advisory"}
        },
        "fail_closed_reasons": []
      }'
      ;;
    defer)
      write_json "$path" '{
        "schema_version": "franken-engine.swarm-starvation-rescue-input.v1",
        "decision": "pass",
        "summary": {
          "readiness": "degraded",
          "brownout_finding_count": 2,
          "starvation_finding_count": 1,
          "safe_to_reopen_count": 1,
          "contact_first_count": 0,
          "lease_exchange_candidate_count": 1,
          "manual_review_count": 0,
          "ownership_fail_closed_count": 0
        },
        "derived_truth": {
          "local_rch_fallback_detected": false,
          "lease_decision": "advisory"
        },
        "normalized_inputs": {
          "admission_budget_plan": {"decision":"admit_narrow"},
          "lease_exchange_salvage_simulation": {"decision":"advisory"}
        },
        "fail_closed_reasons": []
      }'
      ;;
    manual)
      write_json "$path" '{
        "schema_version": "franken-engine.swarm-starvation-rescue-input.v1",
        "decision": "pass",
        "summary": {
          "readiness": "degraded",
          "brownout_finding_count": 0,
          "starvation_finding_count": 0,
          "safe_to_reopen_count": 0,
          "contact_first_count": 1,
          "lease_exchange_candidate_count": 0,
          "manual_review_count": 1,
          "ownership_fail_closed_count": 0
        },
        "derived_truth": {
          "local_rch_fallback_detected": false,
          "lease_decision": "manual_review_required"
        },
        "normalized_inputs": {
          "admission_budget_plan": {"decision":"admit"},
          "lease_exchange_salvage_simulation": {"decision":"manual_review_required"}
        },
        "fail_closed_reasons": []
      }'
      ;;
    fail)
      write_json "$path" '{
        "schema_version": "franken-engine.swarm-starvation-rescue-input.v1",
        "decision": "fail_closed",
        "summary": {
          "readiness": "fail_closed",
          "brownout_finding_count": 0,
          "starvation_finding_count": 0,
          "safe_to_reopen_count": 0,
          "contact_first_count": 0,
          "lease_exchange_candidate_count": 0,
          "manual_review_count": 0,
          "ownership_fail_closed_count": 1
        },
        "derived_truth": {
          "local_rch_fallback_detected": true,
          "lease_decision": "fail_closed"
        },
        "normalized_inputs": {
          "admission_budget_plan": {"decision":"admit"},
          "lease_exchange_salvage_simulation": {"decision":"fail_closed"}
        },
        "fail_closed_reasons": [
          {"kind":"local_rch_fallback_admitted","detail":"capacity forecast passed while local fallback remained admitted"},
          {"kind":"contradictory_ownership","detail":"lease simulation reports ownership fail-closed state"}
        ]
      }'
      ;;
    *)
      record_fail "unknown fixture scenario ${scenario}"
      ;;
  esac
}

run_case() {
  local scenario="$1"
  local expected_exit="$2"
  local expected_decision="$3"
  local expected_action="$4"
  local tmp_root="$5"
  local case_dir="${tmp_root}/${scenario}"
  mkdir -p "${case_dir}/out"

  write_matrix_fixture "${case_dir}/matrix.json"
  write_input_fixture "${case_dir}/input.json" "$scenario"

  set +e
  "${planner}" \
    --starvation-rescue-input-json "${case_dir}/input.json" \
    --scenario-matrix-report-json "${case_dir}/matrix.json" \
    --output-dir "${case_dir}/out" >/dev/null 2>&1
  local exit_code=$?
  set -e

  [[ "$exit_code" -eq "$expected_exit" ]] || record_fail "${scenario}: exit ${exit_code} != ${expected_exit}"

  local report_json="${case_dir}/out/swarm_starvation_rescue_plan.json"
  [[ -f "$report_json" ]] || record_fail "${scenario}: missing planner report"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_action "$expected_action" \
    '
      .schema_version == "franken-engine.swarm-starvation-rescue-plan.v1"
      and .decision == $expected_decision
      and .summary.top_recommendation_action == $expected_action
      and (.artifact_paths.swarm_starvation_rescue_plan_json | length > 0)
    ' "$report_json" >/dev/null || record_fail "${scenario}: planner assertions failed"

  case "$scenario" in
    rescue)
      jq -e '.scenario_class == "healthy" and .summary.recommendation_count == 2' "$report_json" >/dev/null \
        || record_fail "${scenario}: healthy rescue shape incorrect"
      ;;
    defer)
      jq -e '.scenario_class == "brownout" and .recommendations[0].action == "defer_broad_work_and_rebalance"' "$report_json" >/dev/null \
        || record_fail "${scenario}: defer shape incorrect"
      ;;
    manual)
      jq -e '.decision == "manual_review_required" and .recommendations[0].action == "preserve_pinned_evidence"' "$report_json" >/dev/null \
        || record_fail "${scenario}: manual review shape incorrect"
      ;;
    fail)
      jq -e '.decision == "fail_closed" and any(.fail_closed_reasons[]?; .kind == "local_rch_fallback_admitted")' "$report_json" >/dev/null \
        || record_fail "${scenario}: fail-closed shape incorrect"
      ;;
  esac
}

run_check() {
  jq -e '
    .schema_version == "franken-engine.swarm-starvation-rescue-planner-contract.v1"
    and .report_schema_version == "franken-engine.swarm-starvation-rescue-plan.v1"
    and (.required_inputs | length) == 2
    and (.decision_modes | index("manual_review_required") != null)
  ' "$contract_json" >/dev/null || record_fail "contract check"
  record_pass "check"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d)"
  run_case rescue 0 advisory reopen_stale_claim_then_rebalance "$tmp_root"
  run_case defer 0 advisory defer_broad_work_and_rebalance "$tmp_root"
  run_case manual 75 manual_review_required preserve_pinned_evidence "$tmp_root"
  run_case fail 42 fail_closed reject_local_fallback_and_refresh_forecast "$tmp_root"
  printf 'swarm_starvation_rescue_planner_smoke_artifacts=%s\n' "$tmp_root"
  record_pass "selftest"
}

case "${1:-selftest}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_fail "unknown mode ${1:-}"
    exit 64
    ;;
esac
