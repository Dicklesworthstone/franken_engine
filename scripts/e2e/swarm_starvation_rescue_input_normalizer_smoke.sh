#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_starvation_rescue_input_normalizer.sh"
contract_json="${root_dir}/docs/swarm_starvation_rescue_input_contract_v1.json"

record_pass() {
  printf 'PASS swarm-starvation-rescue-input-normalizer %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-starvation-rescue-input-normalizer %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

write_fixture_set() {
  local dir="$1"
  local scenario="$2"
  local now_epoch="$3"
  local stale_epoch="$4"
  local stale_lock_epoch="$now_epoch"
  local capacity_epoch="$now_epoch"
  local slo_epoch="$now_epoch"
  local brownout_decision="pass"
  local brownout_findings='[]'
  local lease_decision="advisory"
  local ownership_fail_closed_count=0
  local lease_manual_review_count=0
  local lease_exchange_candidate_count=1
  local salvage_promotion_candidate_count=0
  local capacity_decision="pass"
  local capacity_overall_state="normal"
  local capacity_confidence_band="high"
  local rch_failure_kind="none"
  local admission_decision="admit"
  local budget_profile="steady_state"
  local slo_decision="pass"
  local slo_confidence_class="high"

  case "$scenario" in
    healthy)
      ;;
    stale)
      stale_lock_epoch="$stale_epoch"
      ;;
    contradictory)
      lease_decision="fail_closed"
      ownership_fail_closed_count=1
      lease_exchange_candidate_count=0
      ;;
    degraded_rch)
      capacity_overall_state="degraded"
      capacity_confidence_band="medium"
      rch_failure_kind="ssh_timeout_no_final_verdict"
      brownout_decision="fail_closed"
      brownout_findings='[
        {
          "finding_id": "finding-queue-brownout",
          "severity": "error",
          "code": "queue_brownout_all_workers_busy",
          "message": "All replayed commands were deferred."
        },
        {
          "finding_id": "finding-low-priority-starvation",
          "severity": "warning",
          "code": "low_priority_starvation",
          "message": "Low-priority work is starving behind focused heavy proofs."
        }
      ]'
      admission_decision="admit_narrow"
      ;;
    local_fallback_success)
      capacity_overall_state="degraded"
      rch_failure_kind="local_fallback_admitted"
      ;;
    *)
      record_fail "unknown fixture scenario ${scenario}"
      ;;
  esac

  write_json "${dir}/brownout.json" "$(jq -n \
    --arg decision "$brownout_decision" \
    --argjson findings "$brownout_findings" \
    '{
      schema_version: "franken-engine.proof-queue-brownout-report.v1",
      brownout_id: "brownout-smoke",
      policy_decision: $decision,
      summary: {
        command_count: 4,
        finding_count: ($findings | length)
      },
      severity_counts: {
        error: ([ $findings[]? | select(.severity == "error") ] | length),
        warning: ([ $findings[]? | select(.severity == "warning") ] | length)
      },
      findings: $findings,
      artifact_paths: {
        brownout_report_json: "/fixture/brownout.json"
      }
    }')"

  write_json "${dir}/stale.json" "$(jq -n \
    --argjson generated_epoch_seconds "$stale_lock_epoch" \
    '{
      schema_version: "franken-engine.stale-lock-recommendations.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      stale_lock_recommendations: [
        {
          bead_id: "bd-stale",
          safe_to_reopen: true,
          contact_first: false,
          recommendation: "safe_to_reopen",
          evidence: ["no recent owner activity"]
        }
      ],
      safe_to_reopen: ["bd-stale"],
      contact_first: [],
      artifact_paths: {
        stale_lock_recommendations_json: "/fixture/stale.json"
      }
    }')"

  write_json "${dir}/lease.json" "$(jq -n \
    --arg decision "$lease_decision" \
    --argjson ownership_fail_closed_count "$ownership_fail_closed_count" \
    --argjson manual_review_count "$lease_manual_review_count" \
    --argjson lease_exchange_candidate_count "$lease_exchange_candidate_count" \
    --argjson salvage_promotion_candidate_count "$salvage_promotion_candidate_count" \
    --arg scenario "$scenario" \
    '{
      schema_version: "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
      decision: $decision,
      summary: {
        request_count: 1,
        manual_review_count: $manual_review_count,
        ownership_fail_closed_count: $ownership_fail_closed_count,
        lease_exchange_candidate_count: $lease_exchange_candidate_count,
        salvage_promotion_candidate_count: $salvage_promotion_candidate_count
      },
      recommendations: [
        {
          request_id: "req-1",
          bead_id: "bd-stale",
          ownership_status: (if $scenario == "contradictory" then "contradictory" else "stale_reclaimable" end),
          simulated_action: (if $scenario == "contradictory" then "fail_closed_missing_ownership" else "simulate_lease_exchange" end),
          overall_score_millionths: 910000
        }
      ],
      artifact_paths: {
        lease_exchange_cancellation_salvage_simulation_json: "/fixture/lease.json"
      }
    }')"

  write_json "${dir}/admission.json" "$(jq -n \
    --arg decision "$admission_decision" \
    --arg budget_profile "$budget_profile" \
    '{
      schema_version: "franken-engine.swarm-admission-budget-plan.v1",
      decision: $decision,
      budget_profile: $budget_profile,
      summary: {
        requested_count: 2,
        admitted_count: (if $decision == "admit" then 2 else 1 end),
        admitted_narrow_count: (if $decision == "admit_narrow" then 1 else 0 end),
        deferred_count: (if $decision == "admit" then 0 else 1 end),
        focused_heavy_admissions: 1
      },
      recommendations: [],
      artifact_paths: {
        swarm_admission_budget_plan_json: "/fixture/admission.json"
      }
    }')"

  write_json "${dir}/capacity.json" "$(jq -n \
    --arg decision "$capacity_decision" \
    --arg overall_state "$capacity_overall_state" \
    --arg confidence_band "$capacity_confidence_band" \
    --arg failure_kind "$rch_failure_kind" \
    --argjson generated_epoch_seconds "$capacity_epoch" \
    '{
      schema_version: "franken-engine.swarm-capacity-forecast.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      stale_after_seconds: 1800,
      decision: $decision,
      confidence_band: $confidence_band,
      summary: {
        overall_state: $overall_state,
        brownout_state: (if $overall_state == "normal" then "normal" else "brownout" end),
        snapshot_age_seconds: 0,
        high_cost_command_count: (if $overall_state == "normal" then 0 else 2 end),
        deferred_command_count: (if $overall_state == "normal" then 0 else 1 end),
        contact_first_count: 0,
        blocked_categories: [],
        degraded_categories: (if $overall_state == "normal" then [] else ["rch_transport","coordination"] end)
      },
      fail_closed_reasons: [],
      forecasts: {
        rch_transport: {
          state: (if $failure_kind == "none" then "normal" else "degraded" end),
          risk_level: (if $failure_kind == "none" then "low" else "high" end),
          confidence_band: $confidence_band,
          supporting_signals: {
            failure_kind: $failure_kind,
            recommended_next_action: (if $failure_kind == "local_fallback_admitted" then "Do not accept local fallback as remote proof truth." else "Keep proof remote-only and narrow scope." end)
          }
        }
      },
      artifact_paths: {
        swarm_capacity_forecast_json: "/fixture/capacity.json"
      }
    }')"

  write_json "${dir}/slo.json" "$(jq -n \
    --arg decision "$slo_decision" \
    --arg confidence_class "$slo_confidence_class" \
    --argjson generated_epoch_seconds "$slo_epoch" \
    '{
      schema_version: "franken-engine.swarm-slo-threshold-receipt.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $decision,
      confidence_class: $confidence_class,
      summary: {
        accepted_threshold_count: 3,
        downgraded_threshold_count: (if $confidence_class == "high" then 0 else 1 end),
        rejected_threshold_count: 0,
        missing_scenario_classes: [],
        reviewed_scenario_count: 5
      },
      thresholds: {
        starvation_brownout_guardrails: {
          status: (if $confidence_class == "high" then "accepted" else "downgraded" end),
          reason: "fixture"
        }
      },
      artifact_paths: {
        swarm_slo_threshold_receipt_json: "/fixture/slo.json"
      }
    }')"
}

run_case() {
  local scenario="$1"
  local expected_exit="$2"
  local expected_decision="$3"
  local expected_readiness="$4"
  local tmp_root="$5"
  local case_dir="${tmp_root}/${scenario}"
  mkdir -p "$case_dir/out"

  write_fixture_set "$case_dir" "$scenario" 2000 100

  set +e
  "${normalizer}" \
    --brownout-report-json "${case_dir}/brownout.json" \
    --stale-lock-recommendations-json "${case_dir}/stale.json" \
    --lease-exchange-salvage-simulation-json "${case_dir}/lease.json" \
    --admission-budget-plan-json "${case_dir}/admission.json" \
    --capacity-forecast-json "${case_dir}/capacity.json" \
    --slo-threshold-receipt-json "${case_dir}/slo.json" \
    --now-epoch-seconds 2000 \
    --stale-after-seconds 300 \
    --output-dir "${case_dir}/out" >/dev/null 2>&1
  local exit_code=$?
  set -e

  [[ "$exit_code" -eq "$expected_exit" ]] || record_fail "${scenario}: exit ${exit_code} != ${expected_exit}"

  local report_json="${case_dir}/out/swarm_starvation_rescue_input.json"
  [[ -f "$report_json" ]] || record_fail "${scenario}: missing report"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_readiness "$expected_readiness" \
    '
      .schema_version == "franken-engine.swarm-starvation-rescue-input.v1"
      and .decision == $expected_decision
      and .summary.readiness == $expected_readiness
      and (.artifact_paths.swarm_starvation_rescue_input_json | length > 0)
    ' "$report_json" >/dev/null || record_fail "${scenario}: report assertions failed"

  case "$scenario" in
    healthy)
      jq -e '(.fail_closed_reasons | length) == 0 and .summary.lease_exchange_candidate_count == 1 and .summary.safe_to_reopen_count == 1' "$report_json" >/dev/null \
        || record_fail "${scenario}: healthy counts incorrect"
      ;;
    stale)
      jq -e 'any(.fail_closed_reasons[]?; .kind == "stale_required_input" and .source == "stale_lock_recommendations_json")' "$report_json" >/dev/null \
        || record_fail "${scenario}: stale failure missing"
      ;;
    contradictory)
      jq -e '.derived_truth.contradictory_ownership_detected == true and any(.fail_closed_reasons[]?; .kind == "contradictory_ownership")' "$report_json" >/dev/null \
        || record_fail "${scenario}: contradictory ownership not detected"
      ;;
    degraded_rch)
      jq -e '.decision == "pass" and .summary.readiness == "degraded" and .derived_truth.local_rch_fallback_detected == false and .summary.brownout_finding_count == 2' "$report_json" >/dev/null \
        || record_fail "${scenario}: degraded rch shape incorrect"
      ;;
    local_fallback_success)
      jq -e '.derived_truth.local_rch_fallback_detected == true and any(.fail_closed_reasons[]?; .kind == "local_rch_fallback_admitted")' "$report_json" >/dev/null \
        || record_fail "${scenario}: local fallback was not rejected"
      ;;
  esac
}

run_check() {
  jq -e '
    .schema_version == "franken-engine.swarm-starvation-rescue-input-contract.v1"
    and .report_schema_version == "franken-engine.swarm-starvation-rescue-input.v1"
    and (.required_inputs | length == 6)
    and (.required_artifact_paths | index("artifact_paths.swarm_starvation_rescue_input_json") != null)
    and (.fail_closed_rules | index("capacity forecast decision must stay pass and must not admit local-rch fallback as success") != null)
  ' "$contract_json" >/dev/null || record_fail "contract check"
  record_pass "check"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d)"
  run_case healthy 0 pass ready "$tmp_root"
  run_case stale 42 fail_closed fail_closed "$tmp_root"
  run_case contradictory 42 fail_closed fail_closed "$tmp_root"
  run_case degraded_rch 0 pass degraded "$tmp_root"
  run_case local_fallback_success 42 fail_closed fail_closed "$tmp_root"
  printf 'swarm_starvation_rescue_input_normalizer_smoke_artifacts=%s\n' "$tmp_root"
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
    ;;
esac
