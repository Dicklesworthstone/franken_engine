#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/swarm_checkpoint_restore_conformance_gate.sh"
planner="${root_dir}/scripts/swarm_checkpoint_restore_planner.sh"
bundle_packer="${root_dir}/scripts/swarm_checkpoint_bundle_packer.sh"
docs_path="${root_dir}/docs/SWARM_CHECKPOINT_RESTORE_CONFORMANCE_GATE.md"
contract_path="${root_dir}/docs/swarm_checkpoint_restore_conformance_gate_contract_v1.json"

record_pass() {
  printf 'PASS swarm-checkpoint-restore-conformance-gate %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-checkpoint-restore-conformance-gate %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

mutate_json() {
  local path="$1"
  local filter="$2"
  local tmp="${path}.tmp"
  jq "$filter" "$path" >"$tmp"
  mv "$tmp" "$path"
}

write_fixture_set() {
  local dir="$1"
  local scenario="$2"
  local generated_epoch="$3"

  local forecast_decision="pass"
  local archive_decision="pass"
  local salvage_decision="advisory"
  local salvage_manual_review_count=0
  local salvage_ownership_fail_closed_count=0
  local status_overall_state="normal"
  local status_restore_action="resume_from_checkpoint"
  local status_unresolved_risks='[]'
  local local_fallback_reason="none"

  case "$scenario" in
    healthy)
      ;;
    local_fallback)
      local_fallback_reason="local_fallback_admitted"
      ;;
    contradictory)
      salvage_decision="fail_closed"
      salvage_ownership_fail_closed_count=1
      status_overall_state="blocked"
      status_restore_action="do_not_resume"
      ;;
    manual_review)
      salvage_decision="manual_review_required"
      salvage_manual_review_count=1
      status_overall_state="degraded"
      status_restore_action="review_checkpoint_before_resume"
      status_unresolved_risks='[{"code":"salvage_manual_review","detail":"salvage requires manual review"}]'
      ;;
    *)
      record_fail "unknown fixture scenario ${scenario}"
      ;;
  esac

  write_json "${dir}/swarm_capacity_snapshot.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    --arg local_fallback_reason "$local_fallback_reason" \
    '{
      schema_version: "franken-engine.swarm-capacity-snapshot.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: "pass",
      summary: {overall_state:"normal", ready_count:2, in_progress_count:1},
      evidence: {rch_transport:{failure_kind:$local_fallback_reason}},
      artifact_paths: {swarm_capacity_snapshot_json:"/fixture/swarm_capacity_snapshot.json"}
    }')"

  write_json "${dir}/swarm_capacity_forecast.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    --arg forecast_decision "$forecast_decision" \
    --arg local_fallback_reason "$local_fallback_reason" \
    '{
      schema_version: "franken-engine.swarm-capacity-forecast.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $forecast_decision,
      confidence_band: "high",
      summary: {overall_state:"normal", blocked_categories:[], degraded_categories:[]},
      forecasts: {rch_transport:{state:(if $local_fallback_reason == "none" then "normal" else "degraded" end), supporting_signals:{failure_kind:$local_fallback_reason}}},
      artifact_paths: {swarm_capacity_forecast_json:"/fixture/swarm_capacity_forecast.json"}
    }')"

  write_json "${dir}/swarm_admission_budget_plan.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    '{
      schema_version: "franken-engine.swarm-admission-budget-plan.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: "admit",
      budget_profile: "steady_state",
      summary: {admitted_count:2, admitted_narrow_count:0, deferred_count:0},
      recommendations: [],
      artifact_paths: {swarm_admission_budget_plan_json:"/fixture/swarm_admission_budget_plan.json"}
    }')"

  write_json "${dir}/remote_proof_archive_pressure_scoreboard.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    --arg archive_decision "$archive_decision" \
    '{
      schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $archive_decision,
      summary: {pressure_band:"low", eviction_candidate_count:0},
      artifact_paths: {remote_proof_archive_pressure_scoreboard_json:"/fixture/remote_proof_archive_pressure_scoreboard.json"}
    }')"

  write_json "${dir}/stale_lock_recommendations.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    '{
      schema_version: "franken-engine.stale-lock-recommendations.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      stale_lock_recommendations: [],
      safe_to_reopen: ["bd-ready"],
      contact_first: [],
      artifact_paths: {stale_lock_recommendations_json:"/fixture/stale_lock_recommendations.json"}
    }')"

  write_json "${dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    --arg salvage_decision "$salvage_decision" \
    --argjson salvage_manual_review_count "$salvage_manual_review_count" \
    --argjson salvage_ownership_fail_closed_count "$salvage_ownership_fail_closed_count" \
    '{
      schema_version: "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $salvage_decision,
      summary: {
        manual_review_count: $salvage_manual_review_count,
        ownership_fail_closed_count: $salvage_ownership_fail_closed_count,
        lease_exchange_candidate_count: 1,
        salvage_promotion_candidate_count: 0
      },
      artifact_paths: {swarm_lease_exchange_cancellation_salvage_simulation_json:"/fixture/swarm_lease_exchange_cancellation_salvage_simulation.json"}
    }')"

  write_json "${dir}/swarm_starvation_rescue_plan.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    '{
      schema_version: "franken-engine.swarm-starvation-rescue-plan.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: "pass",
      scenario_class: "healthy",
      summary: {recommendation_count:1, top_recommendation_action:"resume_from_checkpoint", readiness:"ready", manual_review_count:0, contact_first_count:0, ownership_fail_closed_count:0},
      recommendations: [],
      fail_closed_reasons: [],
      artifact_paths: {swarm_starvation_rescue_plan_json:"/fixture/swarm_starvation_rescue_plan.json"}
    }')"

  write_json "${dir}/swarm_operator_status_report.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    --arg status_overall_state "$status_overall_state" \
    --arg status_restore_action "$status_restore_action" \
    --argjson status_unresolved_risks "$status_unresolved_risks" \
    '{
      schema_version: "franken-engine.swarm-operator-status-report.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      predictive_dashboard: {
        telemetry_snapshot: {schema_version:"franken-engine.swarm-capacity-snapshot.v1"},
        capacity_forecast: {summary:{overall_state:$status_overall_state}},
        starvation_rescue: {top_recommendation_action:$status_restore_action, unresolved_risks:$status_unresolved_risks}
      }
    }')"

  write_json "${dir}/swarm_high_core_scenario_matrix_report.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    '{
      schema_version: "franken-engine.swarm-high-core-scenario-matrix-report.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      matrix_schema_version: "franken-engine.swarm-high-core-scenario-matrix.v1",
      summary: {scenario_count:4}
    }')"

  write_json "${dir}/swarm_operator_slo_tuning_advisory.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    '{
      schema_version: "franken-engine.swarm-operator-slo-tuning-advisory.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      summary: {recommendation_count:2}
    }')"

  write_json "${dir}/proof_economy_replay_trace.json" "$(jq -n \
    --argjson generated_epoch_seconds "$generated_epoch" \
    '{
      schema_version: "franken-engine.proof-economy-replay-trace.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      summary: {replay_event_count:6}
    }')"
}

build_checkpoint_bundle() {
  local output_dir="$1"
  local fixture_dir="$2"
  local now_epoch="$3"
  local expected_exit="${4:-0}"
  local output actual_exit

  set +e
  output="$("$bundle_packer" \
    --output-dir "$output_dir" \
    --swarm-capacity-snapshot-json "${fixture_dir}/swarm_capacity_snapshot.json" \
    --swarm-capacity-forecast-json "${fixture_dir}/swarm_capacity_forecast.json" \
    --swarm-admission-budget-plan-json "${fixture_dir}/swarm_admission_budget_plan.json" \
    --remote-proof-archive-pressure-scoreboard-json "${fixture_dir}/remote_proof_archive_pressure_scoreboard.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --swarm-lease-exchange-cancellation-salvage-simulation-json "${fixture_dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --swarm-starvation-rescue-plan-json "${fixture_dir}/swarm_starvation_rescue_plan.json" \
    --swarm-operator-status-report-json "${fixture_dir}/swarm_operator_status_report.json" \
    --swarm-high-core-scenario-matrix-report-json "${fixture_dir}/swarm_high_core_scenario_matrix_report.json" \
    --swarm-operator-slo-tuning-advisory-json "${fixture_dir}/swarm_operator_slo_tuning_advisory.json" \
    --proof-economy-replay-trace-json "${fixture_dir}/proof_economy_replay_trace.json" \
    --now-epoch-seconds "$now_epoch" \
    --stale-after-seconds 1800 2>&1)"
  actual_exit=$?
  set -e
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    printf '%s\n' "$output" >&2
    record_fail "checkpoint bundle build exit ${actual_exit}, expected ${expected_exit}"
  fi
  test -s "${output_dir}/checkpoint_bundle.json"
}

build_restore_plan() {
  local output_dir="$1"
  local checkpoint_json="$2"
  local current_dir="$3"
  local now_epoch="$4"
  local expected_exit="$5"
  local output actual_exit

  set +e
  output="$("$planner" \
    --output-dir "$output_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${current_dir}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${current_dir}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${current_dir}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${current_dir}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${current_dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${current_dir}/swarm_operator_status_report.json" \
    --now-epoch-seconds "$now_epoch" 2>&1)"
  actual_exit=$?
  set -e
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    printf '%s\n' "$output" >&2
    record_fail "checkpoint restore plan build exit ${actual_exit}, expected ${expected_exit}"
  fi
  test -s "${output_dir}/swarm_checkpoint_restore_plan.json"
}

run_gate_case() {
  local case_name="$1"
  local expected_exit="$2"
  local output_dir="$3"
  local bundle_json="$4"
  local plan_json="$5"

  local output actual_exit
  set +e
  output="$("$gate" --output-dir "$output_dir" --checkpoint-bundle-json "$bundle_json" --checkpoint-restore-plan-json "$plan_json" 2>&1)"
  actual_exit=$?
  set -e
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    printf '%s\n' "$output" >&2
    record_fail "${case_name} exit ${actual_exit}, expected ${expected_exit}"
  fi

  test -s "${output_dir}/swarm_checkpoint_restore_conformance_report.json"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
  record_pass "$case_name"
}

run_check() {
  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  rg -q "Local-fallback heavy-proof truth must stay fail closed" "$docs_path" || record_fail "docs missing local-fallback invariant"
  record_pass "bash syntax and docs contract"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d)"
  trap 'rm -rf "${tmp_root:-}"' RETURN

  local healthy_fixtures healthy_bundle_dir healthy_plan_dir healthy_gate_dir
  healthy_fixtures="${tmp_root}/healthy-fixtures"
  healthy_bundle_dir="${tmp_root}/healthy-bundle"
  healthy_plan_dir="${tmp_root}/healthy-plan"
  healthy_gate_dir="${tmp_root}/healthy-gate"
  mkdir -p "$healthy_fixtures"
  write_fixture_set "$healthy_fixtures" healthy 1900
  build_checkpoint_bundle "$healthy_bundle_dir" "$healthy_fixtures" 1000 0
  build_restore_plan "$healthy_plan_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "$healthy_fixtures" 2000 0
  run_gate_case "healthy-pass" 0 "$healthy_gate_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "${healthy_plan_dir}/swarm_checkpoint_restore_plan.json"
  jq -e '
    .decision == "pass"
    and .summary.restore_decision == "resume"
    and (.gate_failures | length == 0)
  ' "${healthy_gate_dir}/swarm_checkpoint_restore_conformance_report.json" >/dev/null || record_fail "healthy assertions"
  record_pass "healthy assertions"

  local stale_plan_dir stale_gate_dir stale_tampered_dir
  stale_plan_dir="${tmp_root}/stale-plan"
  stale_gate_dir="${tmp_root}/stale-gate"
  stale_tampered_dir="${tmp_root}/stale-tampered-gate"
  build_restore_plan "$stale_plan_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "$healthy_fixtures" 4000 42
  run_gate_case "stale-truthful-pass" 0 "$stale_gate_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "${stale_plan_dir}/swarm_checkpoint_restore_plan.json"
  jq -e '.decision == "pass" and .summary.restore_decision == "fail_closed"' "${stale_gate_dir}/swarm_checkpoint_restore_conformance_report.json" >/dev/null || record_fail "stale truthful assertions"
  record_pass "stale truthful assertions"
  mutate_json "${stale_plan_dir}/swarm_checkpoint_restore_plan.json" '.decision = "resume" | .summary.top_restore_action = "resume_from_checkpoint" | .drift_receipt.fail_closed_reasons = []'
  run_gate_case "stale-tampered-fail" 42 "$stale_tampered_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "${stale_plan_dir}/swarm_checkpoint_restore_plan.json"
  jq -e '(.gate_failures | any(.code == "stale_or_incomplete_checkpoint_promoted"))' "${stale_tampered_dir}/swarm_checkpoint_restore_conformance_report.json" >/dev/null || record_fail "stale tampered assertions"
  record_pass "stale tampered assertions"

  local fallback_fixtures fallback_bundle_dir fallback_plan_dir fallback_gate_dir
  fallback_fixtures="${tmp_root}/fallback-fixtures"
  fallback_bundle_dir="${tmp_root}/fallback-bundle"
  fallback_plan_dir="${tmp_root}/fallback-plan"
  fallback_gate_dir="${tmp_root}/fallback-gate"
  mkdir -p "$fallback_fixtures"
  write_fixture_set "$fallback_fixtures" local_fallback 1900
  build_checkpoint_bundle "$fallback_bundle_dir" "$fallback_fixtures" 1000 42
  build_restore_plan "$fallback_plan_dir" "${fallback_bundle_dir}/checkpoint_bundle.json" "$fallback_fixtures" 2000 42
  mutate_json "${fallback_plan_dir}/swarm_checkpoint_restore_plan.json" '.decision = "resume" | .summary.top_restore_action = "resume_from_checkpoint"'
  run_gate_case "local-fallback-tampered-fail" 42 "$fallback_gate_dir" "${fallback_bundle_dir}/checkpoint_bundle.json" "${fallback_plan_dir}/swarm_checkpoint_restore_plan.json"
  jq -e '(.gate_failures | any(.code == "local_fallback_promoted"))' "${fallback_gate_dir}/swarm_checkpoint_restore_conformance_report.json" >/dev/null || record_fail "local-fallback assertions"
  record_pass "local-fallback assertions"

  local contradictory_fixtures contradictory_plan_dir contradictory_gate_dir
  contradictory_fixtures="${tmp_root}/contradictory-fixtures"
  contradictory_plan_dir="${tmp_root}/contradictory-plan"
  contradictory_gate_dir="${tmp_root}/contradictory-gate"
  mkdir -p "$contradictory_fixtures"
  write_fixture_set "$contradictory_fixtures" healthy 1950
  mutate_json "${contradictory_fixtures}/stale_lock_recommendations.json" '.safe_to_reopen = [] | .contact_first = ["bd-ready"]'
  build_restore_plan "$contradictory_plan_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "$contradictory_fixtures" 2000 42
  mutate_json "${contradictory_plan_dir}/swarm_checkpoint_restore_plan.json" '.decision = "advisory_manual_review"'
  run_gate_case "ownership-tampered-fail" 42 "$contradictory_gate_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "${contradictory_plan_dir}/swarm_checkpoint_restore_plan.json"
  jq -e '(.gate_failures | any(.code == "contradictory_ownership_downgraded"))' "${contradictory_gate_dir}/swarm_checkpoint_restore_conformance_report.json" >/dev/null || record_fail "ownership assertions"
  record_pass "ownership assertions"

  local manual_review_fixtures manual_review_plan_dir manual_review_gate_dir
  manual_review_fixtures="${tmp_root}/manual-review-fixtures"
  manual_review_plan_dir="${tmp_root}/manual-review-plan"
  manual_review_gate_dir="${tmp_root}/manual-review-gate"
  mkdir -p "$manual_review_fixtures"
  write_fixture_set "$manual_review_fixtures" manual_review 1950
  build_restore_plan "$manual_review_plan_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "$manual_review_fixtures" 2000 75
  mutate_json "${manual_review_plan_dir}/swarm_checkpoint_restore_plan.json" '.decision = "resume" | .summary.top_restore_action = "resume_from_checkpoint"'
  run_gate_case "salvage-tampered-fail" 42 "$manual_review_gate_dir" "${healthy_bundle_dir}/checkpoint_bundle.json" "${manual_review_plan_dir}/swarm_checkpoint_restore_plan.json"
  jq -e '(.gate_failures | any(.code == "salvage_manual_review_ignored"))' "${manual_review_gate_dir}/swarm_checkpoint_restore_conformance_report.json" >/dev/null || record_fail "salvage assertions"
  record_pass "salvage assertions"
}

mode="${1:-check}"
case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  *)
    printf 'usage: %s [check|selftest]\n' "${0##*/}" >&2
    exit 64
    ;;
esac
