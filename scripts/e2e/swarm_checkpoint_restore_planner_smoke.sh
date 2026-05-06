#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_checkpoint_restore_planner.sh"
bundle_packer="${root_dir}/scripts/swarm_checkpoint_bundle_packer.sh"
docs_path="${root_dir}/docs/SWARM_CHECKPOINT_RESTORE_PLANNER.md"
contract_path="${root_dir}/docs/swarm_checkpoint_restore_planner_contract_v1.json"

record_pass() {
  printf 'PASS swarm-checkpoint-restore-planner %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-checkpoint-restore-planner %s\n' "$1" >&2
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
  local stale_epoch="$4"

  local snapshot_epoch="$generated_epoch"
  local forecast_epoch="$generated_epoch"
  local admission_epoch="$generated_epoch"
  local archive_epoch="$generated_epoch"
  local stale_lock_epoch="$generated_epoch"
  local salvage_epoch="$generated_epoch"
  local rescue_epoch="$generated_epoch"
  local status_epoch="$generated_epoch"
  local high_core_epoch="$generated_epoch"
  local advisory_epoch="$generated_epoch"
  local proof_epoch="$generated_epoch"

  local forecast_decision="pass"
  local admission_decision="admit"
  local archive_decision="pass"
  local salvage_decision="advisory"
  local salvage_manual_review_count=0
  local salvage_ownership_fail_closed_count=0
  local rescue_decision="pass"
  local rescue_readiness="ready"
  local status_overall_state="normal"
  local status_restore_action="resume_from_checkpoint"
  local status_unresolved_risks='[]'
  local snapshot_decision="pass"
  local optional_inputs_mode="present"
  local local_fallback_reason="none"

  case "$scenario" in
    healthy)
      ;;
    degraded)
      admission_decision="admit_narrow"
      salvage_manual_review_count=1
      rescue_readiness="manual_review"
      status_overall_state="degraded"
      status_restore_action="review_checkpoint_before_resume"
      status_unresolved_risks='[
        {
          "code": "manual_review_pressure",
          "detail": "salvage pressure still requires review"
        }
      ]'
      optional_inputs_mode="missing"
      ;;
    stale)
      snapshot_epoch="$stale_epoch"
      ;;
    contradictory)
      salvage_decision="fail_closed"
      salvage_ownership_fail_closed_count=1
      status_overall_state="blocked"
      status_restore_action="do_not_resume"
      status_unresolved_risks='[
        {
          "code": "contradictory_ownership",
          "detail": "ownership evidence conflicts"
        }
      ]'
      ;;
    local_fallback)
      local_fallback_reason="local_fallback_admitted"
      ;;
    *)
      record_fail "unknown fixture scenario ${scenario}"
      ;;
  esac

  write_json "${dir}/swarm_capacity_snapshot.json" "$(jq -n \
    --argjson generated_epoch_seconds "$snapshot_epoch" \
    --arg snapshot_decision "$snapshot_decision" \
    --arg local_fallback_reason "$local_fallback_reason" \
    '{
      schema_version: "franken-engine.swarm-capacity-snapshot.v1",
      snapshot_id: "snapshot-fixture",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $snapshot_decision,
      summary: {
        overall_state: "normal",
        ready_count: 2,
        in_progress_count: 1
      },
      telemetry_summary: {
        snapshot_decision: $snapshot_decision
      },
      evidence: {
        rch_transport: {
          failure_kind: $local_fallback_reason
        }
      },
      artifact_paths: {
        swarm_capacity_snapshot_json: "/fixture/swarm_capacity_snapshot.json"
      }
    }')"

  write_json "${dir}/swarm_capacity_forecast.json" "$(jq -n \
    --argjson generated_epoch_seconds "$forecast_epoch" \
    --arg forecast_decision "$forecast_decision" \
    --arg local_fallback_reason "$local_fallback_reason" \
    '{
      schema_version: "franken-engine.swarm-capacity-forecast.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $forecast_decision,
      confidence_band: "high",
      summary: {
        overall_state: (if $forecast_decision == "pass" then "normal" else "degraded" end),
        blocked_categories: [],
        degraded_categories: []
      },
      forecasts: {
        rch_transport: {
          state: (if $local_fallback_reason == "none" then "normal" else "degraded" end),
          supporting_signals: {
            failure_kind: $local_fallback_reason
          }
        }
      },
      artifact_paths: {
        swarm_capacity_forecast_json: "/fixture/swarm_capacity_forecast.json"
      }
    }')"

  write_json "${dir}/swarm_admission_budget_plan.json" "$(jq -n \
    --argjson generated_epoch_seconds "$admission_epoch" \
    --arg admission_decision "$admission_decision" \
    '{
      schema_version: "franken-engine.swarm-admission-budget-plan.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $admission_decision,
      budget_profile: "steady_state",
      summary: {
        admitted_count: 2,
        admitted_narrow_count: (if $admission_decision == "admit_narrow" then 1 else 0 end),
        deferred_count: 0
      },
      recommendations: [],
      artifact_paths: {
        swarm_admission_budget_plan_json: "/fixture/swarm_admission_budget_plan.json"
      }
    }')"

  write_json "${dir}/remote_proof_archive_pressure_scoreboard.json" "$(jq -n \
    --argjson generated_epoch_seconds "$archive_epoch" \
    --arg archive_decision "$archive_decision" \
    '{
      schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $archive_decision,
      summary: {
        pressure_band: "low",
        eviction_candidate_count: 0
      },
      artifact_paths: {
        remote_proof_archive_pressure_scoreboard_json: "/fixture/remote_proof_archive_pressure_scoreboard.json"
      }
    }')"

  write_json "${dir}/stale_lock_recommendations.json" "$(jq -n \
    --argjson generated_epoch_seconds "$stale_lock_epoch" \
    '{
      schema_version: "franken-engine.stale-lock-recommendations.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      stale_lock_recommendations: [],
      safe_to_reopen: ["bd-ready"],
      contact_first: [],
      artifact_paths: {
        stale_lock_recommendations_json: "/fixture/stale_lock_recommendations.json"
      }
    }')"

  write_json "${dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" "$(jq -n \
    --argjson generated_epoch_seconds "$salvage_epoch" \
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
      recommendations: [],
      artifact_paths: {
        swarm_lease_exchange_cancellation_salvage_simulation_json: "/fixture/swarm_lease_exchange_cancellation_salvage_simulation.json"
      }
    }')"

  write_json "${dir}/swarm_starvation_rescue_plan.json" "$(jq -n \
    --argjson generated_epoch_seconds "$rescue_epoch" \
    --arg rescue_decision "$rescue_decision" \
    --arg rescue_readiness "$rescue_readiness" \
    --argjson salvage_manual_review_count "$salvage_manual_review_count" \
    '{
      schema_version: "franken-engine.swarm-starvation-rescue-plan.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $rescue_decision,
      scenario_class: "healthy",
      summary: {
        recommendation_count: 1,
        top_recommendation_action: (if $rescue_readiness == "ready" then "resume_from_checkpoint" else "review_checkpoint_before_resume" end),
        readiness: $rescue_readiness,
        manual_review_count: $salvage_manual_review_count,
        contact_first_count: 0,
        ownership_fail_closed_count: 0
      },
      recommendations: [],
      fail_closed_reasons: [],
      artifact_paths: {
        swarm_starvation_rescue_plan_json: "/fixture/swarm_starvation_rescue_plan.json"
      }
    }')"

  write_json "${dir}/swarm_operator_status_report.json" "$(jq -n \
    --argjson generated_epoch_seconds "$status_epoch" \
    --arg status_overall_state "$status_overall_state" \
    --arg status_restore_action "$status_restore_action" \
    --argjson status_unresolved_risks "$status_unresolved_risks" \
    '{
      schema_version: "franken-engine.swarm-operator-status-report.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      predictive_dashboard: {
        telemetry_snapshot: {
          schema_version: "franken-engine.swarm-capacity-snapshot.v1"
        },
        capacity_forecast: {
          summary: {
            overall_state: $status_overall_state
          }
        },
        starvation_rescue: {
          top_recommendation_action: $status_restore_action,
          unresolved_risks: $status_unresolved_risks
        }
      }
    }')"

  if [[ "$optional_inputs_mode" == "present" ]]; then
    write_json "${dir}/swarm_high_core_scenario_matrix_report.json" "$(jq -n \
      --argjson generated_epoch_seconds "$high_core_epoch" \
      '{
        schema_version: "franken-engine.swarm-high-core-scenario-matrix-report.v1",
        generated_epoch_seconds: $generated_epoch_seconds,
        matrix_schema_version: "franken-engine.swarm-high-core-scenario-matrix.v1",
        summary: {
          scenario_count: 4
        }
      }')"

    write_json "${dir}/swarm_operator_slo_tuning_advisory.json" "$(jq -n \
      --argjson generated_epoch_seconds "$advisory_epoch" \
      '{
        schema_version: "franken-engine.swarm-operator-slo-tuning-advisory.v1",
        generated_epoch_seconds: $generated_epoch_seconds,
        summary: {
          recommendation_count: 2
        }
      }')"

    write_json "${dir}/proof_economy_replay_trace.json" "$(jq -n \
      --argjson generated_epoch_seconds "$proof_epoch" \
      '{
        schema_version: "franken-engine.proof-economy-replay-trace.v1",
        generated_epoch_seconds: $generated_epoch_seconds,
        summary: {
          replay_event_count: 6
        }
      }')"
  fi
}

build_checkpoint_bundle() {
  local output_dir="$1"
  local fixture_dir="$2"
  local now_epoch="$3"
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

  if [[ "$actual_exit" -ne 0 ]]; then
    printf '%s\n' "$output" >&2
    record_fail "checkpoint bundle build failed"
  fi

  test -s "${output_dir}/checkpoint_bundle.json"
}

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local output_dir="$3"
  shift 3

  local output actual_exit
  set +e
  output="$("$planner" --output-dir "$output_dir" "$@" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    printf '%s\n' "$output" >&2
    record_fail "${case_name} exit ${actual_exit}, expected ${expected_exit}"
  fi

  test -s "${output_dir}/swarm_checkpoint_restore_plan.json"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
  record_pass "$case_name"
}

run_check() {
  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  rg -q "fixture-fed only" "$docs_path" || record_fail "docs missing fixture-fed note"
  rg -q "Missing current comparisons must keep restore advisory-only" "$docs_path" || record_fail "docs missing current-comparison guardrail"
  record_pass "bash syntax and docs contract"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d)"
  trap 'rm -rf "${tmp_root:-}"' RETURN

  local checkpoint_fixtures checkpoint_dir
  checkpoint_fixtures="${tmp_root}/checkpoint-fixtures"
  checkpoint_dir="${tmp_root}/checkpoint-bundle"
  mkdir -p "$checkpoint_fixtures"
  write_fixture_set "$checkpoint_fixtures" healthy 1900 0
  build_checkpoint_bundle "$checkpoint_dir" "$checkpoint_fixtures" 1000

  local checkpoint_json="${checkpoint_dir}/checkpoint_bundle.json"

  local healthy_current healthy_dir
  healthy_current="${tmp_root}/current-healthy"
  healthy_dir="${tmp_root}/resume"
  mkdir -p "$healthy_current"
  write_fixture_set "$healthy_current" healthy 1950 0
  run_case "resume" 0 "$healthy_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${healthy_current}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${healthy_current}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${healthy_current}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${healthy_current}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${healthy_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${healthy_current}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000
  jq -e '
    .schema_version == "franken-engine.swarm-checkpoint-restore-plan.v1"
    and .decision == "resume"
    and .drift_class == "none"
    and .summary.top_restore_action == "resume_from_checkpoint"
    and (.drift_receipt.fail_closed_reasons | length == 0)
    and (.drift_receipt.findings | length == 0)
  ' "${healthy_dir}/swarm_checkpoint_restore_plan.json" >/dev/null || record_fail "resume assertions"
  record_pass "resume assertions"

  local stale_dir
  stale_dir="${tmp_root}/stale"
  run_case "stale-checkpoint" 42 "$stale_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${healthy_current}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${healthy_current}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${healthy_current}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${healthy_current}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${healthy_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${healthy_current}/swarm_operator_status_report.json" \
    --now-epoch-seconds 4000
  jq -e '
    .decision == "fail_closed"
    and .summary.top_restore_action == "capture_fresh_checkpoint_bundle"
    and (.drift_receipt.fail_closed_reasons | any(.kind == "stale_checkpoint_age"))
  ' "${stale_dir}/swarm_checkpoint_restore_plan.json" >/dev/null || record_fail "stale assertions"
  record_pass "stale assertions"

  local owner_current owner_dir
  owner_current="${tmp_root}/current-owner-drift"
  owner_dir="${tmp_root}/owner-drift"
  mkdir -p "$owner_current"
  write_fixture_set "$owner_current" healthy 1950 0
  mutate_json "${owner_current}/stale_lock_recommendations.json" '.safe_to_reopen = [] | .contact_first = ["bd-ready"]'
  run_case "owner-drift" 42 "$owner_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${owner_current}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${owner_current}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${owner_current}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${owner_current}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${owner_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${owner_current}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000
  jq -e '
    .decision == "fail_closed"
    and .summary.top_restore_action == "manual_ownership_review"
    and (.drift_receipt.fail_closed_reasons | any(.kind == "ownership_contact_first"))
  ' "${owner_dir}/swarm_checkpoint_restore_plan.json" >/dev/null || record_fail "owner-drift assertions"
  record_pass "owner-drift assertions"

  local salvage_current salvage_dir
  salvage_current="${tmp_root}/current-salvage-manual-review"
  salvage_dir="${tmp_root}/salvage-manual-review"
  mkdir -p "$salvage_current"
  write_fixture_set "$salvage_current" healthy 1950 0
  mutate_json "${salvage_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" '.decision = "manual_review_required" | .summary.manual_review_count = 1'
  mutate_json "${salvage_current}/swarm_operator_status_report.json" '.predictive_dashboard.capacity_forecast.summary.overall_state = "degraded" | .predictive_dashboard.starvation_rescue.top_recommendation_action = "review_checkpoint_before_resume" | .predictive_dashboard.starvation_rescue.unresolved_risks = [{"code":"salvage_manual_review","detail":"salvage still requires manual review"}]'
  run_case "salvage-manual-review" 75 "$salvage_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${salvage_current}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${salvage_current}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${salvage_current}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${salvage_current}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${salvage_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${salvage_current}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000
  jq -e '
    .decision == "advisory_manual_review"
    and .summary.top_restore_action == "review_salvage_pressure_before_resume"
    and (.drift_receipt.findings | any(.kind == "salvage_manual_review"))
  ' "${salvage_dir}/swarm_checkpoint_restore_plan.json" >/dev/null || record_fail "salvage-manual-review assertions"
  record_pass "salvage-manual-review assertions"

  local contradictory_current contradictory_dir
  contradictory_current="${tmp_root}/current-contradictory"
  contradictory_dir="${tmp_root}/contradictory"
  mkdir -p "$contradictory_current"
  write_fixture_set "$contradictory_current" healthy 1950 0
  mutate_json "${contradictory_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" '.decision = "fail_closed" | .summary.ownership_fail_closed_count = 1'
  run_case "contradictory" 42 "$contradictory_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${contradictory_current}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${contradictory_current}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${contradictory_current}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${contradictory_current}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${contradictory_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${contradictory_current}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000
  jq -e '
    .decision == "fail_closed"
    and (.drift_receipt.fail_closed_reasons | any(.kind == "salvage_contradiction"))
  ' "${contradictory_dir}/swarm_checkpoint_restore_plan.json" >/dev/null || record_fail "contradictory assertions"
  record_pass "contradictory assertions"

  local worker_current worker_dir
  worker_current="${tmp_root}/current-worker-drift"
  worker_dir="${tmp_root}/worker-drift"
  mkdir -p "$worker_current"
  write_fixture_set "$worker_current" healthy 1950 0
  mutate_json "${worker_current}/swarm_capacity_snapshot.json" '.summary.ready_count = 1'
  mutate_json "${worker_current}/swarm_capacity_forecast.json" '.confidence_band = "low" | .summary.overall_state = "degraded"'
  mutate_json "${worker_current}/swarm_operator_status_report.json" '.predictive_dashboard.capacity_forecast.summary.overall_state = "degraded" | .predictive_dashboard.starvation_rescue.top_recommendation_action = "review_checkpoint_before_resume"'
  run_case "worker-drift" 75 "$worker_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${worker_current}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${worker_current}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${worker_current}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${worker_current}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${worker_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${worker_current}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000
  jq -e '
    .decision == "advisory_manual_review"
    and (.drift_receipt.findings | any(.kind == "worker_pool_drift"))
  ' "${worker_dir}/swarm_checkpoint_restore_plan.json" >/dev/null || record_fail "worker-drift assertions"
  record_pass "worker-drift assertions"

  local archive_current archive_dir
  archive_current="${tmp_root}/current-archive-blocked"
  archive_dir="${tmp_root}/archive-blocked"
  mkdir -p "$archive_current"
  write_fixture_set "$archive_current" healthy 1950 0
  mutate_json "${archive_current}/remote_proof_archive_pressure_scoreboard.json" '.decision = "fail_closed" | .summary.pressure_band = "critical" | .summary.eviction_candidate_count = 3'
  run_case "archive-blocked" 42 "$archive_dir" \
    --checkpoint-bundle-json "$checkpoint_json" \
    --current-swarm-capacity-snapshot-json "${archive_current}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${archive_current}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${archive_current}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${archive_current}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${archive_current}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${archive_current}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000
  jq -e '
    .decision == "fail_closed"
    and .summary.top_restore_action == "clear_archive_blockers_before_restore"
    and (.drift_receipt.fail_closed_reasons | any(.kind == "archive_pressure_blocked"))
  ' "${archive_dir}/swarm_checkpoint_restore_plan.json" >/dev/null || record_fail "archive-blocked assertions"
  record_pass "archive-blocked assertions"
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
