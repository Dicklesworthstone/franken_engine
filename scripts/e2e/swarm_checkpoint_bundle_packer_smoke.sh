#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
packer="${root_dir}/scripts/swarm_checkpoint_bundle_packer.sh"
docs_path="${root_dir}/docs/SWARM_CHECKPOINT_BUNDLE_PACKER.md"
contract_path="${root_dir}/docs/swarm_checkpoint_bundle_contract_v1.json"

record_pass() {
  printf 'PASS swarm-checkpoint-bundle-packer %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-checkpoint-bundle-packer %s\n' "$1" >&2
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
      forecast_decision="pass"
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

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local output_dir="$3"
  local fixture_dir="$4"
  shift 4

  local output actual_exit
  set +e
  output="$("$packer" \
    --output-dir "$output_dir" \
    --swarm-capacity-snapshot-json "${fixture_dir}/swarm_capacity_snapshot.json" \
    --swarm-capacity-forecast-json "${fixture_dir}/swarm_capacity_forecast.json" \
    --swarm-admission-budget-plan-json "${fixture_dir}/swarm_admission_budget_plan.json" \
    --remote-proof-archive-pressure-scoreboard-json "${fixture_dir}/remote_proof_archive_pressure_scoreboard.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --swarm-lease-exchange-cancellation-salvage-simulation-json "${fixture_dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --swarm-starvation-rescue-plan-json "${fixture_dir}/swarm_starvation_rescue_plan.json" \
    --swarm-operator-status-report-json "${fixture_dir}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000 \
    --stale-after-seconds 1800 \
    "$@" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    printf '%s\n' "$output" >&2
    record_fail "${case_name} exit ${actual_exit}, expected ${expected_exit}"
  fi

  test -s "${output_dir}/checkpoint_bundle.json"
  test -s "${output_dir}/run_manifest.json"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/summary.md"
  record_pass "$case_name"
}

run_check() {
  bash -n "$packer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  rg -q "fixture-fed only" "$docs_path" || record_fail "docs missing fixture-fed note"
  rg -q "Local-fallback heavy-proof evidence must fail closed" "$docs_path" || record_fail "docs missing local-fallback fail-closed note"
  record_pass "bash syntax and docs contract"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d)"
  trap 'rm -rf "${tmp_root:-}"' RETURN

  local healthy_dir degraded_dir stale_dir contradictory_dir local_fallback_dir
  local healthy_fixtures degraded_fixtures stale_fixtures contradictory_fixtures local_fallback_fixtures

  healthy_fixtures="${tmp_root}/fixtures-healthy"
  degraded_fixtures="${tmp_root}/fixtures-degraded"
  stale_fixtures="${tmp_root}/fixtures-stale"
  contradictory_fixtures="${tmp_root}/fixtures-contradictory"
  local_fallback_fixtures="${tmp_root}/fixtures-local-fallback"
  mkdir -p "$healthy_fixtures" "$degraded_fixtures" "$stale_fixtures" "$contradictory_fixtures" "$local_fallback_fixtures"

  write_fixture_set "$healthy_fixtures" healthy 1900 0
  write_fixture_set "$degraded_fixtures" degraded 1900 0
  write_fixture_set "$stale_fixtures" stale 1900 0
  write_fixture_set "$contradictory_fixtures" contradictory 1900 0
  write_fixture_set "$local_fallback_fixtures" local_fallback 1900 0

  healthy_dir="${tmp_root}/healthy"
  run_case "healthy" 0 "$healthy_dir" "$healthy_fixtures" \
    --swarm-high-core-scenario-matrix-report-json "${healthy_fixtures}/swarm_high_core_scenario_matrix_report.json" \
    --swarm-operator-slo-tuning-advisory-json "${healthy_fixtures}/swarm_operator_slo_tuning_advisory.json" \
    --proof-economy-replay-trace-json "${healthy_fixtures}/proof_economy_replay_trace.json"
  jq -e '
    .schema_version == "franken-engine.swarm-checkpoint-bundle.v1"
    and .capture_decision == "captured"
    and .restore_readiness_hint == "candidate"
    and (.blockers | length == 0)
    and .artifact_ledger.swarm_high_core_scenario_matrix_report.trust_state == "optional"
    and .artifact_paths.run_manifest_json != null
  ' "${healthy_dir}/checkpoint_bundle.json" >/dev/null || record_fail "healthy assertions"
  record_pass "healthy assertions"

  degraded_dir="${tmp_root}/degraded"
  run_case "degraded" 0 "$degraded_dir" "$degraded_fixtures"
  jq -e '
    .capture_decision == "captured_degraded"
    and .restore_readiness_hint == "manual_review"
    and (.blockers | length == 0)
    and .artifact_ledger.swarm_admission_budget_plan.trust_state == "degraded"
    and .artifact_ledger.swarm_high_core_scenario_matrix_report.trust_state == "missing"
  ' "${degraded_dir}/checkpoint_bundle.json" >/dev/null || record_fail "degraded assertions"
  record_pass "degraded assertions"

  stale_dir="${tmp_root}/stale"
  run_case "stale" 42 "$stale_dir" "$stale_fixtures"
  jq -e '
    .capture_decision == "fail_closed"
    and .restore_readiness_hint == "blocked"
    and (.blockers | any(.code == "stale_required_artifact"))
  ' "${stale_dir}/checkpoint_bundle.json" >/dev/null || record_fail "stale assertions"
  record_pass "stale assertions"

  contradictory_dir="${tmp_root}/contradictory"
  run_case "contradictory" 42 "$contradictory_dir" "$contradictory_fixtures"
  jq -e '
    .capture_decision == "fail_closed"
    and .artifact_ledger.swarm_lease_exchange_cancellation_salvage_simulation.trust_state == "contradictory"
    and (.blockers | any(.code == "contradictory_ownership"))
  ' "${contradictory_dir}/checkpoint_bundle.json" >/dev/null || record_fail "contradictory assertions"
  record_pass "contradictory assertions"

  local_fallback_dir="${tmp_root}/local-fallback"
  run_case "local-fallback" 42 "$local_fallback_dir" "$local_fallback_fixtures"
  jq -e '
    .capture_decision == "fail_closed"
    and .artifact_ledger.swarm_capacity_snapshot.trust_state == "local_fallback"
    and (.blockers | any(.code == "local_fallback_heavy_proof_contamination"))
  ' "${local_fallback_dir}/checkpoint_bundle.json" >/dev/null || record_fail "local-fallback assertions"
  record_pass "local-fallback assertions"
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
