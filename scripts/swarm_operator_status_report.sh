#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_OPERATOR_STATUS_REPORT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-operator-status}"
run_id="${SWARM_OPERATOR_STATUS_REPORT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPERATOR_STATUS_REPORT_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_OPERATOR_STATUS_REPORT_BEAD_ID:-bd-jw854}"
source_revision="${SWARM_OPERATOR_STATUS_REPORT_SOURCE_REVISION:-smoke-rev}"
agent_mail_status="unknown"
rch_status="unknown"
proof_index_status="unknown"

ready_json=""
in_progress_json=""
bv_plan_json=""
reservations_json=""
resource_decision_json=""
validation_plan_json=""
proof_index_json=""
proof_outcomes_json=""
stale_evidence_json=""
dirty_files_json=""
collision_receipt_json=""
proof_freshness_json=""
rch_incident_packet_json=""
resource_lease_plan_json=""
proof_cache_plan_json=""
qos_batch_plan_json=""
stale_lock_recommendations_json=""
staged_ownership_report_json=""
capacity_forecast_json=""
admission_budget_plan_json=""
lease_exchange_salvage_simulation_json=""
warm_target_prefetch_roi_advisory_json=""
starvation_rescue_plan_json=""
starvation_rescue_conformance_report_json=""
checkpoint_bundle_json=""
checkpoint_restore_plan_json=""
checkpoint_restore_conformance_report_json=""
execution_queue_artifact_json=""
execution_queue_risk_budget_json=""
execution_queue_bottleneck_report_json=""
execution_queue_run_manifest_json=""
queue_fidelity_score_receipt_json=""
queue_drift_ledger_json=""
queue_counterfactual_backtest_report_json=""
queue_tuning_plan_json=""
queue_tuning_frontier_json=""
queue_tuning_bundle_json=""
queue_tuning_promotion_guard_receipt_json=""
queue_tuning_rollout_plan_json=""
queue_tuning_rollback_comparator_receipt_json=""
queue_tuning_canary_verdict_ledger_json=""
queue_policy_adoption_receipt_json=""
queue_policy_adoption_snapshot_bundle_json=""
queue_policy_sustained_gain_receipt_json=""
queue_policy_expiry_supersession_plan_json=""
queue_policy_expiry_supersession_ledger_json=""
swarm_agent_causal_trace_graph_json=""
swarm_agent_causal_trace_anomaly_report_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_operator_status_report.sh [OPTIONS]

Builds a fixture-fed operator status report. Inputs are explicit JSON snapshots
from br/bv, Agent Mail, rch, validation plans, resource decisions, and proof
evidence. The script does not claim beads, edit tracker state, or query live
services by itself.

Options:
  --output-dir DIR
  --bead-id ID
  --source-revision REV
  --agent-mail-status ok|degraded|missing|unknown
  --rch-status ok|degraded|missing|unknown
  --proof-index-status ok|degraded|missing|unknown
  --ready-json FILE
  --in-progress-json FILE
  --bv-plan-json FILE
  --reservations-json FILE
  --resource-decision-json FILE
  --validation-plan-json FILE
  --proof-index-json FILE
  --proof-outcomes-json FILE
  --stale-evidence-json FILE
  --dirty-files-json FILE
  --collision-receipt-json FILE
  --proof-freshness-json FILE
  --rch-incident-packet-json FILE
  --resource-lease-plan-json FILE
  --proof-cache-plan-json FILE
  --qos-batch-plan-json FILE
  --stale-lock-recommendations-json FILE
  --staged-ownership-report-json FILE
  --capacity-forecast-json FILE
  --admission-budget-plan-json FILE
  --lease-exchange-salvage-simulation-json FILE
  --warm-target-prefetch-roi-advisory-json FILE
  --starvation-rescue-plan-json FILE
  --starvation-rescue-conformance-report-json FILE
  --checkpoint-bundle-json FILE
  --checkpoint-restore-plan-json FILE
  --checkpoint-restore-conformance-report-json FILE
  --execution-queue-artifact-json FILE
  --execution-queue-risk-budget-json FILE
  --execution-queue-bottleneck-report-json FILE
  --execution-queue-run-manifest-json FILE
  --queue-fidelity-score-receipt-json FILE
  --queue-drift-ledger-json FILE
  --queue-counterfactual-backtest-report-json FILE
  --queue-tuning-plan-json FILE
  --queue-tuning-frontier-json FILE
  --queue-tuning-bundle-json FILE
  --queue-tuning-promotion-guard-receipt-json FILE
  --queue-tuning-rollout-plan-json FILE
  --queue-tuning-rollback-comparator-receipt-json FILE
  --queue-tuning-canary-verdict-ledger-json FILE
  --queue-policy-adoption-receipt-json FILE
  --queue-policy-adoption-snapshot-bundle-json FILE
  --queue-policy-sustained-gain-receipt-json FILE
  --queue-policy-expiry-supersession-plan-json FILE
  --queue-policy-expiry-supersession-ledger-json FILE
  --swarm-agent-causal-trace-graph-json FILE
  --swarm-agent-causal-trace-anomaly-report-json FILE
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --bead-id)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bead_id="$2"
      shift 2
      ;;
    --source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      source_revision="$2"
      shift 2
      ;;
    --agent-mail-status)
      agent_mail_status="$2"
      shift 2
      ;;
    --rch-status)
      rch_status="$2"
      shift 2
      ;;
    --proof-index-status)
      proof_index_status="$2"
      shift 2
      ;;
    --ready-json)
      ready_json="$2"
      shift 2
      ;;
    --in-progress-json)
      in_progress_json="$2"
      shift 2
      ;;
    --bv-plan-json)
      bv_plan_json="$2"
      shift 2
      ;;
    --reservations-json)
      reservations_json="$2"
      shift 2
      ;;
    --resource-decision-json)
      resource_decision_json="$2"
      shift 2
      ;;
    --validation-plan-json)
      validation_plan_json="$2"
      shift 2
      ;;
    --proof-index-json)
      proof_index_json="$2"
      shift 2
      ;;
    --proof-outcomes-json)
      proof_outcomes_json="$2"
      shift 2
      ;;
    --stale-evidence-json)
      stale_evidence_json="$2"
      shift 2
      ;;
    --dirty-files-json)
      dirty_files_json="$2"
      shift 2
      ;;
    --collision-receipt-json)
      collision_receipt_json="$2"
      shift 2
      ;;
    --proof-freshness-json)
      proof_freshness_json="$2"
      shift 2
      ;;
    --rch-incident-packet-json)
      rch_incident_packet_json="$2"
      shift 2
      ;;
    --resource-lease-plan-json)
      resource_lease_plan_json="$2"
      shift 2
      ;;
    --proof-cache-plan-json)
      proof_cache_plan_json="$2"
      shift 2
      ;;
    --qos-batch-plan-json)
      qos_batch_plan_json="$2"
      shift 2
      ;;
    --stale-lock-recommendations-json)
      stale_lock_recommendations_json="$2"
      shift 2
      ;;
    --staged-ownership-report-json)
      staged_ownership_report_json="$2"
      shift 2
      ;;
    --capacity-forecast-json)
      capacity_forecast_json="$2"
      shift 2
      ;;
    --admission-budget-plan-json)
      admission_budget_plan_json="$2"
      shift 2
      ;;
    --lease-exchange-salvage-simulation-json)
      lease_exchange_salvage_simulation_json="$2"
      shift 2
      ;;
    --warm-target-prefetch-roi-advisory-json)
      warm_target_prefetch_roi_advisory_json="$2"
      shift 2
      ;;
    --starvation-rescue-plan-json)
      starvation_rescue_plan_json="$2"
      shift 2
      ;;
    --starvation-rescue-conformance-report-json)
      starvation_rescue_conformance_report_json="$2"
      shift 2
      ;;
    --checkpoint-bundle-json)
      checkpoint_bundle_json="$2"
      shift 2
      ;;
    --checkpoint-restore-plan-json)
      checkpoint_restore_plan_json="$2"
      shift 2
      ;;
    --checkpoint-restore-conformance-report-json)
      checkpoint_restore_conformance_report_json="$2"
      shift 2
      ;;
    --execution-queue-artifact-json)
      execution_queue_artifact_json="$2"
      shift 2
      ;;
    --execution-queue-risk-budget-json)
      execution_queue_risk_budget_json="$2"
      shift 2
      ;;
    --execution-queue-bottleneck-report-json)
      execution_queue_bottleneck_report_json="$2"
      shift 2
      ;;
    --execution-queue-run-manifest-json)
      execution_queue_run_manifest_json="$2"
      shift 2
      ;;
    --queue-fidelity-score-receipt-json)
      queue_fidelity_score_receipt_json="$2"
      shift 2
      ;;
    --queue-drift-ledger-json)
      queue_drift_ledger_json="$2"
      shift 2
      ;;
    --queue-counterfactual-backtest-report-json)
      queue_counterfactual_backtest_report_json="$2"
      shift 2
      ;;
    --queue-tuning-plan-json)
      queue_tuning_plan_json="$2"
      shift 2
      ;;
    --queue-tuning-frontier-json)
      queue_tuning_frontier_json="$2"
      shift 2
      ;;
    --queue-tuning-bundle-json)
      queue_tuning_bundle_json="$2"
      shift 2
      ;;
    --queue-tuning-promotion-guard-receipt-json)
      queue_tuning_promotion_guard_receipt_json="$2"
      shift 2
      ;;
    --queue-tuning-rollout-plan-json)
      queue_tuning_rollout_plan_json="$2"
      shift 2
      ;;
    --queue-tuning-rollback-comparator-receipt-json)
      queue_tuning_rollback_comparator_receipt_json="$2"
      shift 2
      ;;
    --queue-tuning-canary-verdict-ledger-json)
      queue_tuning_canary_verdict_ledger_json="$2"
      shift 2
      ;;
    --queue-policy-adoption-receipt-json)
      queue_policy_adoption_receipt_json="$2"
      shift 2
      ;;
    --queue-policy-adoption-snapshot-bundle-json)
      queue_policy_adoption_snapshot_bundle_json="$2"
      shift 2
      ;;
    --queue-policy-sustained-gain-receipt-json)
      queue_policy_sustained_gain_receipt_json="$2"
      shift 2
      ;;
    --queue-policy-expiry-supersession-plan-json)
      queue_policy_expiry_supersession_plan_json="$2"
      shift 2
      ;;
    --queue-policy-expiry-supersession-ledger-json)
      queue_policy_expiry_supersession_ledger_json="$2"
      shift 2
      ;;
    --swarm-agent-causal-trace-graph-json)
      swarm_agent_causal_trace_graph_json="$2"
      shift 2
      ;;
    --swarm-agent-causal-trace-anomaly-report-json)
      swarm_agent_causal_trace_anomaly_report_json="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

mkdir -p "$run_dir"
status_path="${run_dir}/status.json"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

printf './scripts/swarm_operator_status_report.sh' >"$commands_path"
printf ' --output-dir %q' "$run_dir" >>"$commands_path"
printf '\n' >>"$commands_path"

json_or_default() {
  local path="$1"
  local default_json="$2"
  local label="$3"

  if [[ -z "$path" ]]; then
    printf '%s' "$default_json"
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'swarm-operator-status missing %s file: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'swarm-operator-status invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path"
}

ready_data="$(json_or_default "$ready_json" '[]' 'ready')"
in_progress_data="$(json_or_default "$in_progress_json" '[]' 'in-progress')"
bv_plan_data="$(json_or_default "$bv_plan_json" '{"plan":{"tracks":[]}}' 'bv-plan')"
reservations_data="$(json_or_default "$reservations_json" '[]' 'reservations')"
resource_decision_data="$(json_or_default "$resource_decision_json" '{"decision":"unknown","findings":[]}' 'resource-decision')"
validation_plan_data="$(json_or_default "$validation_plan_json" '{"decision":"unknown","commands":[],"omitted_commands":[]}' 'validation-plan')"
proof_index_data="$(json_or_default "$proof_index_json" '{"queries":[]}' 'proof-index')"
proof_outcomes_data="$(json_or_default "$proof_outcomes_json" '[]' 'proof-outcomes')"
stale_evidence_data="$(json_or_default "$stale_evidence_json" '[]' 'stale-evidence')"
dirty_files_data="$(json_or_default "$dirty_files_json" '[]' 'dirty-files')"
collision_receipt_data="$(json_or_default "$collision_receipt_json" '{"collision_risk":"none","conflicting_agents":[],"safe_alternatives":[],"reservation_recommendations":[],"conflicts":{"reservations":[],"dirty":[],"in_progress":[]}}' 'collision-receipt')"
proof_freshness_data="$(json_or_default "$proof_freshness_json" '{"freshness_state":"not_provided","reusable":null,"reason":"No proof freshness report was provided.","recommended_next_action":"Provide a proof freshness report before reusing prior proof artifacts."}' 'proof-freshness')"
rch_incident_packet_data="$(json_or_default "$rch_incident_packet_json" '{"status":"not_provided","failure_kind":"none","retry_safety":"not_required","recommended_next_action":"No rch incident packet was provided."}' 'rch-incident-packet')"
resource_lease_plan_status="missing"
proof_cache_plan_status="missing"
qos_batch_plan_status="missing"
stale_lock_recommendations_status="missing"
staged_ownership_report_status="missing"
capacity_forecast_status="missing"
admission_budget_plan_status="missing"
lease_exchange_salvage_simulation_status="missing"
warm_target_prefetch_roi_advisory_status="missing"
starvation_rescue_plan_status="missing"
starvation_rescue_conformance_report_status="missing"
checkpoint_bundle_status="missing"
checkpoint_restore_plan_status="missing"
checkpoint_restore_conformance_report_status="missing"
execution_queue_artifact_status="missing"
execution_queue_risk_budget_status="missing"
execution_queue_bottleneck_report_status="missing"
execution_queue_run_manifest_status="missing"
queue_fidelity_score_receipt_status="missing"
queue_drift_ledger_status="missing"
queue_counterfactual_backtest_report_status="missing"
queue_tuning_plan_status="missing"
queue_tuning_frontier_status="missing"
queue_tuning_bundle_status="missing"
queue_tuning_promotion_guard_receipt_status="missing"
queue_tuning_rollout_plan_status="missing"
queue_tuning_rollback_comparator_receipt_status="missing"
queue_tuning_canary_verdict_ledger_status="missing"
queue_policy_adoption_receipt_status="missing"
queue_policy_adoption_snapshot_bundle_status="missing"
queue_policy_sustained_gain_receipt_status="missing"
queue_policy_expiry_supersession_plan_status="missing"
queue_policy_expiry_supersession_ledger_status="missing"
swarm_agent_causal_trace_graph_status="missing"
swarm_agent_causal_trace_anomaly_report_status="missing"
if [[ -n "$resource_lease_plan_json" ]]; then resource_lease_plan_status="provided"; fi
if [[ -n "$proof_cache_plan_json" ]]; then proof_cache_plan_status="provided"; fi
if [[ -n "$qos_batch_plan_json" ]]; then qos_batch_plan_status="provided"; fi
if [[ -n "$stale_lock_recommendations_json" ]]; then stale_lock_recommendations_status="provided"; fi
if [[ -n "$staged_ownership_report_json" ]]; then staged_ownership_report_status="provided"; fi
if [[ -n "$capacity_forecast_json" ]]; then capacity_forecast_status="provided"; fi
if [[ -n "$admission_budget_plan_json" ]]; then admission_budget_plan_status="provided"; fi
if [[ -n "$lease_exchange_salvage_simulation_json" ]]; then lease_exchange_salvage_simulation_status="provided"; fi
if [[ -n "$warm_target_prefetch_roi_advisory_json" ]]; then warm_target_prefetch_roi_advisory_status="provided"; fi
if [[ -n "$starvation_rescue_plan_json" ]]; then starvation_rescue_plan_status="provided"; fi
if [[ -n "$starvation_rescue_conformance_report_json" ]]; then starvation_rescue_conformance_report_status="provided"; fi
if [[ -n "$checkpoint_bundle_json" ]]; then checkpoint_bundle_status="provided"; fi
if [[ -n "$checkpoint_restore_plan_json" ]]; then checkpoint_restore_plan_status="provided"; fi
if [[ -n "$checkpoint_restore_conformance_report_json" ]]; then checkpoint_restore_conformance_report_status="provided"; fi
if [[ -n "$execution_queue_artifact_json" ]]; then execution_queue_artifact_status="provided"; fi
if [[ -n "$execution_queue_risk_budget_json" ]]; then execution_queue_risk_budget_status="provided"; fi
if [[ -n "$execution_queue_bottleneck_report_json" ]]; then execution_queue_bottleneck_report_status="provided"; fi
if [[ -n "$execution_queue_run_manifest_json" ]]; then execution_queue_run_manifest_status="provided"; fi
if [[ -n "$queue_fidelity_score_receipt_json" ]]; then queue_fidelity_score_receipt_status="provided"; fi
if [[ -n "$queue_drift_ledger_json" ]]; then queue_drift_ledger_status="provided"; fi
if [[ -n "$queue_counterfactual_backtest_report_json" ]]; then queue_counterfactual_backtest_report_status="provided"; fi
if [[ -n "$queue_tuning_plan_json" ]]; then queue_tuning_plan_status="provided"; fi
if [[ -n "$queue_tuning_frontier_json" ]]; then queue_tuning_frontier_status="provided"; fi
if [[ -n "$queue_tuning_bundle_json" ]]; then queue_tuning_bundle_status="provided"; fi
if [[ -n "$queue_tuning_promotion_guard_receipt_json" ]]; then queue_tuning_promotion_guard_receipt_status="provided"; fi
if [[ -n "$queue_tuning_rollout_plan_json" ]]; then queue_tuning_rollout_plan_status="provided"; fi
if [[ -n "$queue_tuning_rollback_comparator_receipt_json" ]]; then queue_tuning_rollback_comparator_receipt_status="provided"; fi
if [[ -n "$queue_tuning_canary_verdict_ledger_json" ]]; then queue_tuning_canary_verdict_ledger_status="provided"; fi
if [[ -n "$queue_policy_adoption_receipt_json" ]]; then queue_policy_adoption_receipt_status="provided"; fi
if [[ -n "$queue_policy_adoption_snapshot_bundle_json" ]]; then queue_policy_adoption_snapshot_bundle_status="provided"; fi
if [[ -n "$queue_policy_sustained_gain_receipt_json" ]]; then queue_policy_sustained_gain_receipt_status="provided"; fi
if [[ -n "$queue_policy_expiry_supersession_plan_json" ]]; then queue_policy_expiry_supersession_plan_status="provided"; fi
if [[ -n "$queue_policy_expiry_supersession_ledger_json" ]]; then queue_policy_expiry_supersession_ledger_status="provided"; fi
if [[ -n "$swarm_agent_causal_trace_graph_json" ]]; then swarm_agent_causal_trace_graph_status="provided"; fi
if [[ -n "$swarm_agent_causal_trace_anomaly_report_json" ]]; then swarm_agent_causal_trace_anomaly_report_status="provided"; fi
resource_lease_plan_data="$(json_or_default "$resource_lease_plan_json" '{"schema_version":"franken-engine.swarm-resource-lease-plan.v1","lease_decision":"missing","reason":"No resource lease plan was provided.","findings":[],"safe_alternatives":[]}' 'resource-lease-plan')"
proof_cache_plan_data="$(json_or_default "$proof_cache_plan_json" '{"schema_version":"franken-engine.proof-reuse-cache-plan.v1","proof_cache_decision":"missing","reason":"No proof cache plan was provided.","cache_hit_artifacts":[],"required_refreshes":[],"invalid_artifacts":[],"invalidated_paths":[],"refresh_commands":[]}' 'proof-cache-plan')"
qos_batch_plan_data="$(json_or_default "$qos_batch_plan_json" '{"schema_version":"franken-engine.build-storm-batch-plan.v1","batch_decision":"missing","fairness_reason":"No build-storm QoS batch plan was provided.","admitted_commands":[],"deferred_commands":[],"retry_after_seconds":0}' 'qos-batch-plan')"
stale_lock_recommendations_data="$(json_or_default "$stale_lock_recommendations_json" '{"schema_version":"franken-engine.stale-lock-recommendations.v1","stale_lock_recommendations":[],"safe_to_reopen":[],"contact_first":[]}' 'stale-lock-recommendations')"
staged_ownership_report_data="$(json_or_default "$staged_ownership_report_json" '{"schema_version":"franken-engine.staged-ownership-report.v1","decision":"missing","offender_count":0,"offending_paths":[],"findings":[]}' 'staged-ownership-report')"
capacity_forecast_data="$(json_or_default "$capacity_forecast_json" '{"schema_version":"franken-engine.swarm-capacity-forecast.v1","decision":"missing","confidence_band":"low","summary":{"overall_state":"unknown","blocked_categories":[],"degraded_categories":[]},"telemetry_summary":{"snapshot_decision":"unknown"},"inputs":[],"forecasts":{},"artifact_paths":{}}' 'capacity-forecast')"
admission_budget_plan_data="$(json_or_default "$admission_budget_plan_json" '{"schema_version":"franken-engine.swarm-admission-budget-plan.v1","decision":"missing","budget_profile":"unknown","summary":{"admitted_count":0,"deferred_count":0},"recommendations":[],"artifact_paths":{}}' 'admission-budget-plan')"
lease_exchange_salvage_simulation_data="$(json_or_default "$lease_exchange_salvage_simulation_json" '{"schema_version":"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1","decision":"missing","summary":{"manual_review_count":0,"lease_exchange_candidate_count":0,"salvage_promotion_candidate_count":0},"upstream_summary":{"archive_pressure_advisory":"unknown","salvage_workflow_state":"unknown"},"recommendations":[],"artifact_paths":{}}' 'lease-exchange-salvage-simulation')"
warm_target_prefetch_roi_advisory_data="$(json_or_default "$warm_target_prefetch_roi_advisory_json" '{"schema_version":"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1","advisory":"missing","recommended_action":"Provide a warm-target prefetch ROI advisory before claiming prefetch value.","reason":"No warm-target prefetch ROI advisory was provided.","budget_summary":{"budget_profile":"unknown"},"warm_target_summary":{"target_dir":null},"proof_cache_summary":{"proof_cache_decision":"unknown"},"archive_pressure_summary":{"advisory":"unknown"},"validation_cost_summary":{"estimated_cpu_slots_total":0},"roi_summary":{"expected_reuse_score":0,"realized_reuse_score":0,"reuse_delta":0},"artifact_paths":{}}' 'warm-target-prefetch-roi-advisory')"
starvation_rescue_plan_data="$(json_or_default "$starvation_rescue_plan_json" '{"schema_version":"franken-engine.swarm-starvation-rescue-plan.v1","decision":"missing","scenario_class":"unknown","summary":{"recommendation_count":0,"top_recommendation_action":null,"readiness":"unknown","brownout_finding_count":0,"starvation_finding_count":0,"safe_to_reopen_count":0,"contact_first_count":0,"lease_exchange_candidate_count":0,"manual_review_count":0,"ownership_fail_closed_count":0},"policy_basis":{"matched_case_ids":[],"matched_case_count":0,"required_scenario_classes":[]},"recommendations":[],"fail_closed_reasons":[],"artifact_paths":{}}' 'starvation-rescue-plan')"
starvation_rescue_conformance_report_data="$(json_or_default "$starvation_rescue_conformance_report_json" '{"schema_version":"franken-engine.swarm-starvation-rescue-conformance-report.v1","decision":"missing","summary":{"plan_decision":"missing","scenario_class":"unknown","gate_failure_count":0},"verified_invariants":[],"gate_failures":[],"artifact_paths":{}}' 'starvation-rescue-conformance-report')"
checkpoint_bundle_data="$(json_or_default "$checkpoint_bundle_json" '{"schema_version":"franken-engine.swarm-checkpoint-bundle.v1","checkpoint_id":"missing","capture_decision":"missing","restore_readiness_hint":"unknown","artifact_paths":{},"blockers":[],"artifact_ledger":{}}' 'checkpoint-bundle')"
checkpoint_restore_plan_data="$(json_or_default "$checkpoint_restore_plan_json" '{"schema_version":"franken-engine.swarm-checkpoint-restore-plan.v1","checkpoint_id":"missing","decision":"missing","drift_class":"unknown","summary":{"top_restore_action":null,"provided_current_comparison_count":0,"missing_current_comparison_count":0},"drift_receipt":{"checkpoint_age_seconds":null,"fail_closed_reasons":[],"findings":[]},"artifact_paths":{}}' 'checkpoint-restore-plan')"
checkpoint_restore_conformance_report_data="$(json_or_default "$checkpoint_restore_conformance_report_json" '{"schema_version":"franken-engine.swarm-checkpoint-restore-conformance-report.v1","decision":"missing","summary":{"restore_decision":"missing","checkpoint_capture_decision":"missing","top_restore_action":null,"gate_failure_count":0,"checked_artifact_path_count":0},"gate_failures":[],"artifact_paths":{}}' 'checkpoint-restore-conformance-report')"
execution_queue_artifact_data="$(json_or_default "$execution_queue_artifact_json" '{"schema_version":"franken-engine.swarm-execution-queue-artifact.v1","artifact_hash_hex":null,"normalized_input_hash_hex":null,"queue_artifact":{"queue":[],"bottlenecks":[],"risk_budget":{"remaining_millionths":0,"consumed_millionths":0,"conservative_mode":false,"conservative_threshold_millionths":200000}}}' 'execution-queue-artifact')"
execution_queue_risk_budget_data="$(json_or_default "$execution_queue_risk_budget_json" '{"schema_version":"franken-engine.swarm-execution-risk-budget-receipt.v1","decision":"missing","risk_budget":{"remaining_millionths":0,"consumed_millionths":0,"conservative_mode":false,"conservative_threshold_millionths":200000},"conservative_mode":false,"queue_depth":0}' 'execution-queue-risk-budget')"
execution_queue_bottleneck_report_data="$(json_or_default "$execution_queue_bottleneck_report_json" '{"schema_version":"franken-engine.swarm-execution-bottleneck-report.v1","bottleneck_count":0,"critical_bottleneck_count":0,"bottlenecks":[]}' 'execution-queue-bottleneck-report')"
execution_queue_run_manifest_data="$(json_or_default "$execution_queue_run_manifest_json" '{"schema_version":"franken-engine.swarm-execution-queue-runner.v1","decision":"missing","task_count":0,"queue_depth":0,"artifact_hash_hex":null,"artifact_paths":{}}' 'execution-queue-run-manifest')"
queue_fidelity_score_receipt_data="$(json_or_default "$queue_fidelity_score_receipt_json" '{"schema_version":"franken-engine.swarm-execution-queue-fidelity-score-receipt.v1","decision":"missing","overall_fidelity_millionths":0,"confidence_band":"unknown","component_scores":{},"summary":{"row_count":0,"fail_closed_reason_count":0,"degraded_input_count":0},"artifact_paths":{}}' 'queue-fidelity-score-receipt')"
queue_drift_ledger_data="$(json_or_default "$queue_drift_ledger_json" '{"schema_version":"franken-engine.swarm-execution-queue-drift-ledger.v1","decision":"missing","rows":[],"fail_closed_reasons":[],"degraded_inputs":[]}' 'queue-drift-ledger')"
queue_counterfactual_backtest_report_data="$(json_or_default "$queue_counterfactual_backtest_report_json" '{"schema_version":"franken-engine.swarm-execution-queue-counterfactual-backtest-report.v1","decision":"missing","baseline_overall_fidelity_millionths":0,"evaluated_candidate_count":0,"positive_candidate_count":0,"fail_closed_reasons":[],"candidates":[],"artifact_paths":{}}' 'queue-counterfactual-backtest-report')"
queue_tuning_plan_data="$(json_or_default "$queue_tuning_plan_json" '{"schema_version":"franken-engine.swarm-execution-queue-tuning-plan.v1","decision":"missing","plan_class":"missing","recommended_candidate":null,"ranked_candidates":[],"operator_notes":["No queue tuning plan was provided."],"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"advisory_only":true}}' 'queue-tuning-plan')"
queue_tuning_frontier_data="$(json_or_default "$queue_tuning_frontier_json" '{"schema_version":"franken-engine.swarm-execution-queue-counterfactual-frontier.v1","frontier":[]}' 'queue-tuning-frontier')"
queue_tuning_bundle_data="$(json_or_default "$queue_tuning_bundle_json" '{"schema_version":"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1","decision":"missing","bundle_id":null,"promoted_candidate":{},"evidence_links":[],"manual_approval":{"required":true,"blockers":[]},"rollback_references":{},"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"advisory_only":true},"artifact_paths":{}}' 'queue-tuning-bundle')"
queue_tuning_promotion_guard_receipt_data="$(json_or_default "$queue_tuning_promotion_guard_receipt_json" '{"schema_version":"franken-engine.swarm-execution-queue-tuning-promotion-guard-receipt.v1","decision":"missing","reject_reasons":[],"manual_approval_blockers":[],"preconditions":{},"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"advisory_only":true},"artifact_paths":{}}' 'queue-tuning-promotion-guard-receipt')"
queue_tuning_rollout_plan_data="$(json_or_default "$queue_tuning_rollout_plan_json" '{"schema_version":"franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1","decision":"missing","manual_approval":{"required":true,"blockers":[]},"stop_conditions":[],"rejection_reasons":[],"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"advisory_only":true},"artifact_paths":{}}' 'queue-tuning-rollout-plan')"
queue_tuning_rollback_comparator_receipt_data="$(json_or_default "$queue_tuning_rollback_comparator_receipt_json" '{"schema_version":"franken-engine.swarm-execution-queue-tuning-rollback-comparator-receipt.v1","verdict":"missing","fail_closed_reasons":[],"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"advisory_only":true},"artifact_paths":{}}' 'queue-tuning-rollback-comparator-receipt')"
queue_tuning_canary_verdict_ledger_data="$(json_or_default "$queue_tuning_canary_verdict_ledger_json" '{"schema_version":"franken-engine.swarm-execution-queue-canary-verdict-ledger.v1","verdict":"missing","recommended_action":"missing","rollback_triggers":[],"fail_closed_reasons":[],"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"advisory_only":true},"artifact_paths":{}}' 'queue-tuning-canary-verdict-ledger')"
queue_policy_adoption_receipt_data="$(json_or_default "$queue_policy_adoption_receipt_json" '{"schema_version":"franken-engine.swarm-execution-queue-policy-adoption-receipt.v1","decision":"missing","adoption_receipt_id":null,"adopted_policy_bundle_id":null,"operator_decision":{"adoption_state":"missing"},"adopted_candidate":{},"observation_window":{},"supersession":{},"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"mutates_br":false,"sends_agent_mail":false,"mutates_remote_workers":false,"rewrites_historical_outcomes":false},"artifact_paths":{}}' 'queue-policy-adoption-receipt')"
queue_policy_adoption_snapshot_bundle_data="$(json_or_default "$queue_policy_adoption_snapshot_bundle_json" '{"schema_version":"franken-engine.swarm-execution-queue-policy-adoption-snapshot-bundle.v1","decision":"missing","snapshot_id":null,"adoption_receipt_id":null,"adopted_policy_bundle_id":null,"candidate_id":null,"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"mutates_br":false,"sends_agent_mail":false,"mutates_remote_workers":false,"rewrites_historical_outcomes":false},"artifact_paths":{}}' 'queue-policy-adoption-snapshot-bundle')"
queue_policy_sustained_gain_receipt_data="$(json_or_default "$queue_policy_sustained_gain_receipt_json" '{"schema_version":"franken-engine.swarm-execution-queue-policy-sustained-gain-receipt.v1","verdict":"missing","sustained_gain_receipt_id":null,"adopted_policy_bundle_id":null,"candidate_id":null,"rollback_drift_count":0,"fail_closed_reasons":[],"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"mutates_br":false,"sends_agent_mail":false,"mutates_remote_workers":false,"rewrites_historical_outcomes":false},"artifact_paths":{}}' 'queue-policy-sustained-gain-receipt')"
queue_policy_expiry_supersession_plan_data="$(json_or_default "$queue_policy_expiry_supersession_plan_json" '{"schema_version":"franken-engine.swarm-execution-queue-policy-expiry-supersession-plan.v1","decision":"missing","plan_id":null,"adopted_policy_bundle_id":null,"sustained_gain_verdict":"missing","expiry_required":false,"supersession_required":false,"advisory_status":{"execution_state":"missing","retirement_executed":false,"supersession_executed":false},"decision_reasons":[],"fail_closed_reasons":[],"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"mutates_br":false,"sends_agent_mail":false,"mutates_remote_workers":false,"rewrites_historical_outcomes":false,"retirement_executed":false,"supersession_executed":false},"artifact_paths":{}}' 'queue-policy-expiry-supersession-plan')"
queue_policy_expiry_supersession_ledger_data="$(json_or_default "$queue_policy_expiry_supersession_ledger_json" '{"schema_version":"franken-engine.swarm-execution-queue-policy-expiry-supersession-ledger.v1","decision":"missing","ledger_rows":[],"ownership_rows":[],"fail_closed_reasons":[],"mutation_policy":{"changes_active_queue":false,"applies_live_retuning":false,"mutates_br":false,"sends_agent_mail":false,"mutates_remote_workers":false,"rewrites_historical_outcomes":false,"retirement_executed":false,"supersession_executed":false},"artifact_paths":{}}' 'queue-policy-expiry-supersession-ledger')"
swarm_agent_causal_trace_graph_data="$(json_or_default "$swarm_agent_causal_trace_graph_json" '{"schema_version":"franken-engine.swarm-agent-causal-trace-graph.v1","trace_id":null,"bead_id":null,"source_revision":null,"nodes":[],"edges":[],"anomaly_summary":{"decision":"missing","anomaly_count":0,"fail_closed_count":0,"degraded_count":0,"anomaly_classes":[]},"mutation_policy":{"fixture_fed_only":true,"mutates_br":false,"reassigns_beads":false,"releases_reservations":false,"sends_agent_mail":false,"queries_live_agent_mail":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false,"rewrites_historical_outcomes":false,"operator_wording_required":"advisory-only"},"artifact_paths":{}}' 'swarm-agent-causal-trace-graph')"
swarm_agent_causal_trace_anomaly_report_data="$(json_or_default "$swarm_agent_causal_trace_anomaly_report_json" '{"schema_version":"franken-engine.swarm-agent-causal-trace-anomaly-report.v1","trace_id":null,"bead_id":null,"source_revision":null,"decision":"missing","anomaly_count":0,"fail_closed_count":0,"degraded_count":0,"anomaly_classes":[],"anomalies":[],"artifact_paths":{}}' 'swarm-agent-causal-trace-anomaly-report')"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-operator-status-report.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg agent_mail_status "$agent_mail_status" \
  --arg rch_status "$rch_status" \
  --arg proof_index_status "$proof_index_status" \
  --arg resource_lease_plan_status "$resource_lease_plan_status" \
  --arg proof_cache_plan_status "$proof_cache_plan_status" \
  --arg qos_batch_plan_status "$qos_batch_plan_status" \
  --arg stale_lock_recommendations_status "$stale_lock_recommendations_status" \
  --arg staged_ownership_report_status "$staged_ownership_report_status" \
  --arg capacity_forecast_status "$capacity_forecast_status" \
  --arg admission_budget_plan_status "$admission_budget_plan_status" \
  --arg lease_exchange_salvage_simulation_status "$lease_exchange_salvage_simulation_status" \
  --arg warm_target_prefetch_roi_advisory_status "$warm_target_prefetch_roi_advisory_status" \
  --arg starvation_rescue_plan_status "$starvation_rescue_plan_status" \
  --arg starvation_rescue_conformance_report_status "$starvation_rescue_conformance_report_status" \
  --arg checkpoint_bundle_status "$checkpoint_bundle_status" \
  --arg checkpoint_restore_plan_status "$checkpoint_restore_plan_status" \
  --arg checkpoint_restore_conformance_report_status "$checkpoint_restore_conformance_report_status" \
  --arg execution_queue_artifact_status "$execution_queue_artifact_status" \
  --arg execution_queue_risk_budget_status "$execution_queue_risk_budget_status" \
  --arg execution_queue_bottleneck_report_status "$execution_queue_bottleneck_report_status" \
  --arg execution_queue_run_manifest_status "$execution_queue_run_manifest_status" \
  --arg queue_fidelity_score_receipt_status "$queue_fidelity_score_receipt_status" \
  --arg queue_drift_ledger_status "$queue_drift_ledger_status" \
  --arg queue_counterfactual_backtest_report_status "$queue_counterfactual_backtest_report_status" \
  --arg queue_tuning_plan_status "$queue_tuning_plan_status" \
  --arg queue_tuning_frontier_status "$queue_tuning_frontier_status" \
  --arg queue_tuning_bundle_status "$queue_tuning_bundle_status" \
  --arg queue_tuning_promotion_guard_receipt_status "$queue_tuning_promotion_guard_receipt_status" \
  --arg queue_tuning_rollout_plan_status "$queue_tuning_rollout_plan_status" \
  --arg queue_tuning_rollback_comparator_receipt_status "$queue_tuning_rollback_comparator_receipt_status" \
  --arg queue_tuning_canary_verdict_ledger_status "$queue_tuning_canary_verdict_ledger_status" \
  --arg queue_policy_adoption_receipt_status "$queue_policy_adoption_receipt_status" \
  --arg queue_policy_adoption_snapshot_bundle_status "$queue_policy_adoption_snapshot_bundle_status" \
  --arg queue_policy_sustained_gain_receipt_status "$queue_policy_sustained_gain_receipt_status" \
  --arg queue_policy_expiry_supersession_plan_status "$queue_policy_expiry_supersession_plan_status" \
  --arg queue_policy_expiry_supersession_ledger_status "$queue_policy_expiry_supersession_ledger_status" \
  --arg swarm_agent_causal_trace_graph_status "$swarm_agent_causal_trace_graph_status" \
  --arg swarm_agent_causal_trace_anomaly_report_status "$swarm_agent_causal_trace_anomaly_report_status" \
  --arg status_path "$status_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson ready "$ready_data" \
  --argjson in_progress "$in_progress_data" \
  --argjson bv_plan "$bv_plan_data" \
  --argjson reservations "$reservations_data" \
  --argjson resource_decision "$resource_decision_data" \
  --argjson validation_plan "$validation_plan_data" \
  --argjson proof_index "$proof_index_data" \
  --argjson proof_outcomes "$proof_outcomes_data" \
  --argjson stale_evidence "$stale_evidence_data" \
  --argjson dirty_files "$dirty_files_data" \
  --argjson collision_receipt "$collision_receipt_data" \
  --argjson proof_freshness "$proof_freshness_data" \
  --argjson rch_incident_packet "$rch_incident_packet_data" \
  --argjson resource_lease_plan "$resource_lease_plan_data" \
  --argjson proof_cache_plan "$proof_cache_plan_data" \
  --argjson qos_batch_plan "$qos_batch_plan_data" \
  --argjson stale_lock_recommendations "$stale_lock_recommendations_data" \
  --argjson staged_ownership_report "$staged_ownership_report_data" \
  --argjson capacity_forecast "$capacity_forecast_data" \
  --argjson admission_budget_plan "$admission_budget_plan_data" \
  --argjson lease_exchange_salvage_simulation "$lease_exchange_salvage_simulation_data" \
  --argjson warm_target_prefetch_roi_advisory "$warm_target_prefetch_roi_advisory_data" \
  --argjson starvation_rescue_plan "$starvation_rescue_plan_data" \
  --argjson starvation_rescue_conformance_report "$starvation_rescue_conformance_report_data" \
  --argjson checkpoint_bundle "$checkpoint_bundle_data" \
  --argjson checkpoint_restore_plan "$checkpoint_restore_plan_data" \
  --argjson checkpoint_restore_conformance_report "$checkpoint_restore_conformance_report_data" \
  --argjson execution_queue_artifact "$execution_queue_artifact_data" \
  --argjson execution_queue_risk_budget "$execution_queue_risk_budget_data" \
  --argjson execution_queue_bottleneck_report "$execution_queue_bottleneck_report_data" \
  --argjson execution_queue_run_manifest "$execution_queue_run_manifest_data" \
  --argjson queue_fidelity_score_receipt "$queue_fidelity_score_receipt_data" \
  --argjson queue_drift_ledger "$queue_drift_ledger_data" \
  --argjson queue_counterfactual_backtest_report "$queue_counterfactual_backtest_report_data" \
  --argjson queue_tuning_plan "$queue_tuning_plan_data" \
  --argjson queue_tuning_frontier "$queue_tuning_frontier_data" \
  --argjson queue_tuning_bundle "$queue_tuning_bundle_data" \
  --argjson queue_tuning_promotion_guard_receipt "$queue_tuning_promotion_guard_receipt_data" \
  --argjson queue_tuning_rollout_plan "$queue_tuning_rollout_plan_data" \
  --argjson queue_tuning_rollback_comparator_receipt "$queue_tuning_rollback_comparator_receipt_data" \
  --argjson queue_tuning_canary_verdict_ledger "$queue_tuning_canary_verdict_ledger_data" \
  --argjson queue_policy_adoption_receipt "$queue_policy_adoption_receipt_data" \
  --argjson queue_policy_adoption_snapshot_bundle "$queue_policy_adoption_snapshot_bundle_data" \
  --argjson queue_policy_sustained_gain_receipt "$queue_policy_sustained_gain_receipt_data" \
  --argjson queue_policy_expiry_supersession_plan "$queue_policy_expiry_supersession_plan_data" \
  --argjson queue_policy_expiry_supersession_ledger "$queue_policy_expiry_supersession_ledger_data" \
  --argjson swarm_agent_causal_trace_graph "$swarm_agent_causal_trace_graph_data" \
  --argjson swarm_agent_causal_trace_anomaly_report "$swarm_agent_causal_trace_anomaly_report_data" \
  '
  def degraded($component; $status; $impact; $remediation):
    if ($status == "ok") then empty
    else {component: $component, status: $status, impact: $impact, remediation: $remediation}
    end;
  def bead_row:
    {
      id: .id,
      title: .title,
      priority: (.priority // null),
      status: (.status // null),
      assignee: (.assignee // null)
    };
  def recommendation($action; $bead; $reason):
    {action: $action, bead_id: $bead, reason: $reason};
  def nonempty_or($primary; $fallback):
    if (($primary // []) | length) > 0 then $primary else ($fallback // []) end;
  def bounded($items): (($items // [])[0:8]);
  def strings($items): bounded(($items // []) | map(tostring));
  def mismatch_severity_rank($class):
    if ($class // "") | IN("contradictory_evidence", "missing_outcome") then 50
    elif ($class // "") == "proof_brownout_miss" then 40
    elif ($class // "") == "stale_owner_miss" then 30
    elif ($class // "") | IN("over_conservative", "conservative_but_correct") then 20
    elif ($class // "") == "exact_match" then 0
    else 10
    end;

  ($ready | map(bead_row) | sort_by(.priority // 999, .id)) as $ready_rows
  | ($in_progress | map(bead_row) | sort_by(.id)) as $in_progress_rows
  | ($dirty_files | map(select(.reserved == true or .overlaps_ready == true))) as $dirty_reserved
  | ($stale_evidence | map(select((.stale // false) == true))) as $stale
  | ($proof_outcomes | map(select((.status // "") | test("fail|blocked|stale")))) as $bad_proofs
  | ([($bv_plan.plan.tracks // [])[]?.items[]? | select((.status // "") == "blocked")]) as $blocked_items
  | ($validation_plan.commands // []
      | map(select(.predicted_cost? != null)
        | {
            command_id: (.command_id // null),
            display: (.display // null),
            command_kind: (.command_kind // null),
            cost_class: (.predicted_cost.cost_class // "unknown"),
            cost_state: (.predicted_cost.state // "unknown"),
            sample_count: (.predicted_cost.sample_count // 0),
            elapsed_ms_p50: (.predicted_cost.elapsed_ms_p50 // 0),
            elapsed_ms_max: (.predicted_cost.elapsed_ms_max // 0),
            compiled_target_count_max: (.predicted_cost.compiled_target_count_max // 0),
            linked_target_count_max: (.predicted_cost.linked_target_count_max // 0),
            risk_flags: (.risk_flags // []),
            cost_evidence: (.cost_evidence // {})
          })) as $cost_rows
  | ($cost_rows
      | map(select(
          (.cost_class // "unknown") == "high"
          or (((.risk_flags // []) | map(select(test("high|failed|fallback|unknown|stale|mismatched|contradictory"))) | length) > 0)
          or (((.cost_evidence.status // "") | test("unknown|stale|mismatched|contradictory|failed")))
        ))) as $high_cost_rows
  | ($validation_plan.proof_cost_budgets // []) as $proof_cost_budgets
  | ($validation_plan.collision_risk // $collision_receipt.collision_risk // "none") as $collision_risk
  | ({
      risk: $collision_risk,
      conflicting_agents: nonempty_or($validation_plan.conflicting_agents; $collision_receipt.conflicting_agents),
      safe_alternatives: nonempty_or($validation_plan.safe_alternatives; $collision_receipt.safe_alternatives),
      reservation_recommendations: nonempty_or($validation_plan.reservation_recommendations; $collision_receipt.reservation_recommendations),
      conflicts: ($collision_receipt.conflicts // {reservations: [], dirty: [], in_progress: []})
    }) as $collision_summary
  | ({
      state: ($proof_freshness.freshness_state // "not_provided"),
      reusable: (if ($proof_freshness | has("reusable")) then $proof_freshness.reusable else null end),
      artifact_id: ($proof_freshness.proof_artifact_id // null),
      artifact_path: ($proof_freshness.artifact_path // null),
      reason: ($proof_freshness.reason // null),
      recommended_next_action: ($proof_freshness.recommended_next_action // null),
      covered_paths: ($proof_freshness.covered_paths // []),
      changed_paths: ($proof_freshness.changed_paths // [])
    }) as $proof_freshness_summary
  | (if (($rch_incident_packet.status // "not_provided") == "not_provided"
          and ($rch_incident_packet.failure_kind // "none") == "none") then
      []
    else
      [{
        incident_id: ($rch_incident_packet.incident_id // null),
        status: ($rch_incident_packet.status // "unknown"),
        failure_kind: ($rch_incident_packet.failure_kind // "unknown"),
        retry_safety: ($rch_incident_packet.retry_safety // "unknown"),
        classification_confidence: ($rch_incident_packet.classification_confidence // "unknown"),
        worker_id: ($rch_incident_packet.worker_id // null),
        command: ($rch_incident_packet.command // null),
        target_dir: ($rch_incident_packet.target_dir // null),
        recommended_next_action: ($rch_incident_packet.recommended_next_action // null)
      }]
    end) as $rch_incident_summaries
  | ({
      artifact_status: $resource_lease_plan_status,
      severity: (
        if $resource_lease_plan_status == "missing" then "warning"
        elif (($resource_lease_plan.lease_decision // "") | IN("admit")) then "ok"
        elif (($resource_lease_plan.lease_decision // "") | IN("admit_narrow", "defer")) then "warning"
        else "critical"
        end
      ),
      lease_decision: ($resource_lease_plan.lease_decision // "missing"),
      reason: ($resource_lease_plan.reason // null),
      agent_id: ($resource_lease_plan.agent_id // null),
      bead_id: ($resource_lease_plan.bead_id // null),
      requested_command: ($resource_lease_plan.requested_command // null),
      target_dir: ($resource_lease_plan.target_dir // null),
      assigned_worker: ($resource_lease_plan.assigned_worker // null),
      safe_alternatives: bounded($resource_lease_plan.safe_alternatives),
      findings: bounded($resource_lease_plan.findings),
      actionable_commands: (
        if $resource_lease_plan_status == "missing" then
          ["./scripts/swarm_resource_lease_planner.sh --agent-id <agent-id> --bead-id <bead-id> --requested-command <command> --target-dir <target-dir>"]
        elif (($resource_lease_plan.lease_decision // "") | IN("admit", "admit_narrow")) then
          []
        else
          strings($resource_lease_plan.safe_alternatives)
        end
      )
    }) as $resource_leases_summary
  | ({
      artifact_status: $proof_cache_plan_status,
      severity: (
        if $proof_cache_plan_status == "missing" then "warning"
        elif (($proof_cache_plan.proof_cache_decision // "") == "cache_hit") then "ok"
        elif (($proof_cache_plan.proof_cache_decision // "") | IN("partial_refresh", "refresh_required")) then "warning"
        else "critical"
        end
      ),
      proof_cache_decision: ($proof_cache_plan.proof_cache_decision // "missing"),
      reason: ($proof_cache_plan.reason // null),
      cache_hit_count: (($proof_cache_plan.cache_hit_artifacts // []) | length),
      refresh_count: (($proof_cache_plan.required_refreshes // []) | length),
      invalid_count: (($proof_cache_plan.invalid_artifacts // []) | length),
      cache_hit_artifacts: bounded($proof_cache_plan.cache_hit_artifacts),
      required_refreshes: bounded($proof_cache_plan.required_refreshes),
      invalid_artifacts: bounded($proof_cache_plan.invalid_artifacts),
      invalidated_paths: bounded($proof_cache_plan.invalidated_paths),
      refresh_commands: strings($proof_cache_plan.refresh_commands),
      actionable_commands: (
        if $proof_cache_plan_status == "missing" then
          ["./scripts/proof_reuse_cache_planner.sh --proof-index-json <proof-index.json> --freshness-report <freshness.json>"]
        else
          strings($proof_cache_plan.refresh_commands)
        end
      )
    }) as $proof_cache_summary
  | ({
      artifact_status: $qos_batch_plan_status,
      severity: (
        if $qos_batch_plan_status == "missing" then "warning"
        elif (($qos_batch_plan.batch_decision // "") == "planned" and (($qos_batch_plan.deferred_commands // []) | length) == 0) then "ok"
        elif (($qos_batch_plan.batch_decision // "") | IN("planned", "all_deferred")) then "warning"
        else "critical"
        end
      ),
      batch_id: ($qos_batch_plan.batch_id // null),
      batch_decision: ($qos_batch_plan.batch_decision // "missing"),
      fairness_reason: ($qos_batch_plan.fairness_reason // null),
      max_parallel_heavy: ($qos_batch_plan.max_parallel_heavy // null),
      retry_after_seconds: ($qos_batch_plan.retry_after_seconds // 0),
      admitted_count: (($qos_batch_plan.admitted_commands // []) | length),
      deferred_count: (($qos_batch_plan.deferred_commands // []) | length),
      admitted_commands: bounded($qos_batch_plan.admitted_commands),
      deferred_commands: bounded($qos_batch_plan.deferred_commands),
      actionable_commands: (
        if $qos_batch_plan_status == "missing" then
          ["./scripts/build_storm_qos_batch_planner.sh --pending-requests-json <pending.json> --resource-lease-plans-json <leases.json> --proof-cost-history-json <costs.json> --rch-workers-json <workers.json>"]
        else
          strings((($qos_batch_plan.admitted_commands // []) + ($qos_batch_plan.deferred_commands // [])) | map(.command // empty))
        end
      )
    }) as $qos_batches_summary
  | ({
      artifact_status: $stale_lock_recommendations_status,
      severity: (
        if $stale_lock_recommendations_status == "missing" then "warning"
        elif ((($stale_lock_recommendations.safe_to_reopen // []) | length) == 0 and (($stale_lock_recommendations.contact_first // []) | length) == 0) then "ok"
        else "warning"
        end
      ),
      recommendation_count: (($stale_lock_recommendations.stale_lock_recommendations // []) | length),
      safe_to_reopen_count: (($stale_lock_recommendations.safe_to_reopen // []) | length),
      contact_first_count: (($stale_lock_recommendations.contact_first // []) | length),
      safe_to_reopen: bounded($stale_lock_recommendations.safe_to_reopen),
      contact_first: bounded($stale_lock_recommendations.contact_first),
      recommendations: bounded($stale_lock_recommendations.stale_lock_recommendations),
      actionable_commands: (
        if $stale_lock_recommendations_status == "missing" then
          ["./scripts/stale_lock_stalled_bead_recommender.sh --in-progress-json <in-progress.json>"]
        else
          strings([
            ($stale_lock_recommendations.stale_lock_recommendations // [])[]?
            | (.suggested_br_commands // [])[]?,
              (.contact_commands // [])[]?
          ])
        end
      )
    }) as $stale_lock_summary
  | ({
      artifact_status: $staged_ownership_report_status,
      severity: (
        if $staged_ownership_report_status == "missing" then "warning"
        elif (($staged_ownership_report.decision // "") == "pass") then "ok"
        elif (($staged_ownership_report.decision // "") == "pass_degraded") then "warning"
        else "critical"
        end
      ),
      decision: ($staged_ownership_report.decision // "missing"),
      staged_path_count: ($staged_ownership_report.staged_path_count // 0),
      offender_count: ($staged_ownership_report.offender_count // 0),
      scoped_beads_issue_ids: bounded($staged_ownership_report.scoped_beads_issue_ids),
      offending_paths: bounded($staged_ownership_report.offending_paths),
      findings: bounded($staged_ownership_report.findings),
      actionable_commands: (
        if $staged_ownership_report_status == "missing" then
          ["./scripts/staged_ownership_contamination_guard.sh --agent-id <agent-id> --bead-id <bead-id> --allowed-path <path>"]
        else
          strings(($staged_ownership_report.offending_paths // []) | map(.remediation // empty))
        end
      )
    }) as $staged_contamination_summary
  | ({
      artifact_status: $capacity_forecast_status,
      severity: (
        if $capacity_forecast_status == "missing" then "warning"
        elif (($capacity_forecast.decision // "") == "fail_closed") then "critical"
        elif (($capacity_forecast.summary.overall_state // "") | IN("blocked", "brownout", "degraded"))
          or (($capacity_forecast.confidence_band // "") != "high") then "warning"
        else "ok"
        end
      ),
      decision: ($capacity_forecast.decision // "missing"),
      confidence_band: ($capacity_forecast.confidence_band // "low"),
      overall_state: ($capacity_forecast.summary.overall_state // "unknown"),
      blocked_categories: bounded($capacity_forecast.summary.blocked_categories),
      degraded_categories: bounded($capacity_forecast.summary.degraded_categories),
      category_states: {
        compile_pressure: ($capacity_forecast.forecasts.compile_pressure.state // "unknown"),
        disk_memory_pressure: ($capacity_forecast.forecasts.disk_memory_pressure.state // "unknown"),
        rch_degradation: ($capacity_forecast.forecasts.rch_degradation.state // "unknown"),
        target_dir_heat: ($capacity_forecast.forecasts.target_dir_heat.state // "unknown"),
        proof_availability: ($capacity_forecast.forecasts.proof_availability.state // "unknown"),
        coordination_pressure: ($capacity_forecast.forecasts.coordination_pressure.state // "unknown")
      },
      recommended_actions: {
        compile_pressure: ($capacity_forecast.forecasts.compile_pressure.recommended_action // null),
        disk_memory_pressure: ($capacity_forecast.forecasts.disk_memory_pressure.recommended_action // null),
        rch_degradation: ($capacity_forecast.forecasts.rch_degradation.recommended_action // null),
        target_dir_heat: ($capacity_forecast.forecasts.target_dir_heat.recommended_action // null),
        proof_availability: ($capacity_forecast.forecasts.proof_availability.recommended_action // null),
        coordination_pressure: ($capacity_forecast.forecasts.coordination_pressure.recommended_action // null)
      },
      artifact_path: ($capacity_forecast.artifact_paths.swarm_capacity_forecast_json // null)
    }) as $capacity_forecast_summary
  | ({
      artifact_status: $capacity_forecast_status,
      severity: (
        if $capacity_forecast_status == "missing" then "warning"
        elif (($capacity_forecast.decision // "") == "fail_closed")
          or (($capacity_forecast.confidence_band // "") == "low") then "critical"
        elif (($capacity_forecast.summary.degraded_categories // []) | length) != 0 then "warning"
        else "ok"
        end
      ),
      decision: ($capacity_forecast.telemetry_summary.snapshot_decision // $capacity_forecast.decision // "missing"),
      confidence_band: ($capacity_forecast.confidence_band // "low"),
      input_count: (($capacity_forecast.inputs // []) | length),
      provided_input_count: (($capacity_forecast.inputs // []) | map(select((.status // "") == "provided")) | length),
      missing_input_count: (($capacity_forecast.inputs // []) | map(select((.status // "") != "provided")) | length),
      failure_count: (($capacity_forecast.failures // []) | length),
      inputs: bounded($capacity_forecast.inputs),
      notes: bounded($capacity_forecast.notes),
      recommended_action: (
        if (($capacity_forecast.decision // "") == "fail_closed")
          or (($capacity_forecast.confidence_band // "") == "low") then
          "Refresh stale or missing telemetry artifacts before trusting the predictive dashboard."
        else
          "Treat the predictive forecast as advisory snapshot evidence only."
        end
      ),
      artifact_path: ($capacity_forecast.artifact_paths.swarm_capacity_forecast_json // null)
    }) as $telemetry_quality_summary
  | ({
      artifact_status: $admission_budget_plan_status,
      severity: (
        if $admission_budget_plan_status == "missing" then "warning"
        elif (($admission_budget_plan.decision // "") == "fail_closed") then "critical"
        elif (($admission_budget_plan.summary.deferred_count // 0) > 0)
          or (($admission_budget_plan.decision // "") != "admit") then "warning"
        else "ok"
        end
      ),
      decision: ($admission_budget_plan.decision // "missing"),
      budget_profile: ($admission_budget_plan.budget_profile // "unknown"),
      admitted_count: ($admission_budget_plan.summary.admitted_count // 0),
      deferred_count: ($admission_budget_plan.summary.deferred_count // 0),
      protected_request_count: (($admission_budget_plan.recommendations // []) | map(select((.budget_class // "") == "protected")) | length),
      proof_obligation_count: (($admission_budget_plan.recommendations // []) | map(select((.proof_obligation // false) == true)) | length),
      recommendations: bounded($admission_budget_plan.recommendations),
      artifact_path: ($admission_budget_plan.artifact_paths.swarm_admission_budget_plan_json // null)
    }) as $admission_budget_summary
  | ({
      artifact_status: $lease_exchange_salvage_simulation_status,
      severity: (
        if $lease_exchange_salvage_simulation_status == "missing" then "warning"
        elif (($lease_exchange_salvage_simulation.decision // "") | test("fail_closed")) then "critical"
        elif (($lease_exchange_salvage_simulation.summary.manual_review_count // 0) > 0)
          or (($lease_exchange_salvage_simulation.summary.lease_exchange_candidate_count // 0) > 0)
          or (($lease_exchange_salvage_simulation.summary.salvage_promotion_candidate_count // 0) > 0) then "warning"
        else "ok"
        end
      ),
      decision: ($lease_exchange_salvage_simulation.decision // "missing"),
      manual_review_count: ($lease_exchange_salvage_simulation.summary.manual_review_count // 0),
      lease_exchange_candidate_count: ($lease_exchange_salvage_simulation.summary.lease_exchange_candidate_count // 0),
      salvage_promotion_candidate_count: ($lease_exchange_salvage_simulation.summary.salvage_promotion_candidate_count // 0),
      archive_pressure_advisory: ($lease_exchange_salvage_simulation.upstream_summary.archive_pressure_advisory // "unknown"),
      salvage_workflow_state: ($lease_exchange_salvage_simulation.upstream_summary.salvage_workflow_state // "unknown"),
      recommendations: bounded($lease_exchange_salvage_simulation.recommendations),
      artifact_path: ($lease_exchange_salvage_simulation.artifact_paths.lease_exchange_cancellation_salvage_simulation_json // null)
    }) as $lease_exchange_salvage_summary
  | ({
      artifact_status: $warm_target_prefetch_roi_advisory_status,
      severity: (
        if $warm_target_prefetch_roi_advisory_status == "missing" then "warning"
        elif (($warm_target_prefetch_roi_advisory.advisory // "") == "fail_closed") then "critical"
        elif (($warm_target_prefetch_roi_advisory.exit_code // 0) == 75)
          or (($warm_target_prefetch_roi_advisory.advisory // "") != "prefetch_recommended") then "warning"
        else "ok"
        end
      ),
      advisory: ($warm_target_prefetch_roi_advisory.advisory // "missing"),
      recommended_action: ($warm_target_prefetch_roi_advisory.recommended_action // "Provide a warm-target ROI advisory before recommending prefetch."),
      reason: ($warm_target_prefetch_roi_advisory.reason // null),
      budget_profile: ($warm_target_prefetch_roi_advisory.budget_summary.budget_profile // "unknown"),
      target_dir: ($warm_target_prefetch_roi_advisory.warm_target_summary.target_dir // null),
      proof_cache_decision: ($warm_target_prefetch_roi_advisory.proof_cache_summary.proof_cache_decision // "unknown"),
      archive_pressure_advisory: ($warm_target_prefetch_roi_advisory.archive_pressure_summary.advisory // "unknown"),
      estimated_cpu_slots_total: ($warm_target_prefetch_roi_advisory.validation_cost_summary.estimated_cpu_slots_total // 0),
      expected_reuse_score: ($warm_target_prefetch_roi_advisory.roi_summary.expected_reuse_score // 0),
      realized_reuse_score: ($warm_target_prefetch_roi_advisory.roi_summary.realized_reuse_score // 0),
      reuse_delta: ($warm_target_prefetch_roi_advisory.roi_summary.reuse_delta // 0),
      artifact_path: ($warm_target_prefetch_roi_advisory.artifact_paths.swarm_warm_target_prefetch_roi_advisory_json // null)
    }) as $prefetch_roi_summary
  | ({
      artifact_status: $starvation_rescue_plan_status,
      conformance_artifact_status: $starvation_rescue_conformance_report_status,
      severity: (
        if $starvation_rescue_plan_status == "missing"
          or $starvation_rescue_conformance_report_status == "missing" then "warning"
        elif (($starvation_rescue_conformance_report.decision // "") == "fail_closed")
          or (($starvation_rescue_plan.decision // "") == "fail_closed") then "critical"
        elif (($starvation_rescue_plan.decision // "") == "manual_review_required")
          or (($starvation_rescue_plan.scenario_class // "") == "brownout") then "warning"
        else "ok"
        end
      ),
      plan_decision: ($starvation_rescue_plan.decision // "missing"),
      conformance_decision: ($starvation_rescue_conformance_report.decision // "missing"),
      scenario_class: ($starvation_rescue_plan.scenario_class // "unknown"),
      top_recommendation_action: ($starvation_rescue_plan.summary.top_recommendation_action // null),
      recommendation_count: ($starvation_rescue_plan.summary.recommendation_count // 0),
      escalation_band: (
        if $starvation_rescue_plan_status == "missing"
          or $starvation_rescue_conformance_report_status == "missing" then "unknown"
        elif (($starvation_rescue_conformance_report.decision // "") == "fail_closed")
          or (($starvation_rescue_plan.decision // "") == "fail_closed") then "fail_closed"
        elif (($starvation_rescue_plan.decision // "") == "manual_review_required") then "manual_review"
        elif (($starvation_rescue_plan.scenario_class // "") == "brownout") then "degraded"
        else "ready"
        end
      ),
      recommended_ordering: bounded(
        ($starvation_rescue_plan.recommendations // [])
        | map({
            rank: (.rank // null),
            action: (.action // null),
            fairness_reason: (.fairness_reason // null),
            required_next_actions: (.required_next_actions // [])
          })
      ),
      unresolved_risks: bounded(
        if (($starvation_rescue_conformance_report.gate_failures // []) | length) > 0 then
          ($starvation_rescue_conformance_report.gate_failures // [])
        elif (($starvation_rescue_plan.fail_closed_reasons // []) | length) > 0 then
          ($starvation_rescue_plan.fail_closed_reasons // [])
        else
          [
            (if (($starvation_rescue_plan.summary.contact_first_count // 0) > 0) then
              {code:"contact_first_uncertainty", detail:"stale-lock uncertainty still requires owner contact before rescue"}
            else empty end),
            (if (($starvation_rescue_plan.summary.manual_review_count // 0) > 0) then
              {code:"salvage_manual_review", detail:"salvage-pinned evidence still requires manual review before rescue"}
            else empty end),
            (if (($starvation_rescue_plan.summary.brownout_finding_count // 0) > 0) then
              {code:"brownout_pressure", detail:"brownout or starvation pressure remains active while the rescue handoff is advisory only"}
            else empty end)
          ]
        end
      ),
      artifact_path: ($starvation_rescue_plan.artifact_paths.swarm_starvation_rescue_plan_json // null),
      conformance_artifact_path: ($starvation_rescue_conformance_report.artifact_paths.swarm_starvation_rescue_conformance_report_json // null)
    }) as $starvation_rescue_summary
  | ({
      artifact_status: $checkpoint_bundle_status,
      plan_artifact_status: $checkpoint_restore_plan_status,
      conformance_artifact_status: $checkpoint_restore_conformance_report_status,
      severity: (
        if $checkpoint_bundle_status == "missing"
          or $checkpoint_restore_plan_status == "missing"
          or $checkpoint_restore_conformance_report_status == "missing" then "warning"
        elif (($checkpoint_restore_conformance_report.decision // "") == "fail_closed")
          or (($checkpoint_restore_plan.decision // "") == "fail_closed")
          or (($checkpoint_bundle.capture_decision // "") == "fail_closed")
          or (($checkpoint_bundle.restore_readiness_hint // "") == "blocked") then "critical"
        elif (($checkpoint_restore_plan.decision // "") == "advisory_manual_review")
          or (($checkpoint_bundle.restore_readiness_hint // "") == "manual_review")
          or (($checkpoint_restore_plan.drift_class // "") == "soft") then "warning"
        else "ok"
        end
      ),
      checkpoint_id: ($checkpoint_bundle.checkpoint_id // $checkpoint_restore_plan.checkpoint_id // null),
      checkpoint_capture_decision: ($checkpoint_bundle.capture_decision // "missing"),
      restore_readiness_hint: ($checkpoint_bundle.restore_readiness_hint // "unknown"),
      plan_decision: ($checkpoint_restore_plan.decision // "missing"),
      conformance_decision: ($checkpoint_restore_conformance_report.decision // "missing"),
      drift_class: ($checkpoint_restore_plan.drift_class // "unknown"),
      checkpoint_age_seconds: ($checkpoint_restore_plan.drift_receipt.checkpoint_age_seconds // null),
      top_restore_action: ($checkpoint_restore_plan.summary.top_restore_action // $checkpoint_restore_conformance_report.summary.top_restore_action // null),
      gate_failure_count: ($checkpoint_restore_conformance_report.summary.gate_failure_count // (($checkpoint_restore_conformance_report.gate_failures // []) | length)),
      escalation_band: (
        if $checkpoint_bundle_status == "missing"
          or $checkpoint_restore_plan_status == "missing"
          or $checkpoint_restore_conformance_report_status == "missing" then "unknown"
        elif (($checkpoint_restore_conformance_report.decision // "") == "fail_closed")
          or (($checkpoint_restore_plan.decision // "") == "fail_closed")
          or (($checkpoint_bundle.capture_decision // "") == "fail_closed")
          or (($checkpoint_bundle.restore_readiness_hint // "") == "blocked") then "fail_closed"
        elif (($checkpoint_restore_plan.decision // "") == "advisory_manual_review")
          or (($checkpoint_bundle.restore_readiness_hint // "") == "manual_review")
          or (($checkpoint_restore_plan.drift_class // "") == "soft") then "manual_review"
        else "ready"
        end
      ),
      unresolved_risks: bounded(
        if (($checkpoint_restore_conformance_report.gate_failures // []) | length) > 0 then
          ($checkpoint_restore_conformance_report.gate_failures // [])
        elif (($checkpoint_restore_plan.drift_receipt.fail_closed_reasons // []) | length) > 0 then
          ($checkpoint_restore_plan.drift_receipt.fail_closed_reasons // [])
        elif (($checkpoint_restore_plan.drift_receipt.findings // []) | length) > 0 then
          ($checkpoint_restore_plan.drift_receipt.findings // [])
        else
          []
        end
      ),
      checked_artifact_path_count: ($checkpoint_restore_conformance_report.summary.checked_artifact_path_count // 0),
      artifact_path: ($checkpoint_bundle.artifact_paths.checkpoint_bundle_json // null),
      plan_artifact_path: ($checkpoint_restore_plan.artifact_paths.swarm_checkpoint_restore_plan_json // null),
      conformance_artifact_path: ($checkpoint_restore_conformance_report.artifact_paths.swarm_checkpoint_restore_conformance_report_json // null)
    }) as $checkpoint_restore_summary
  | ($execution_queue_artifact.queue_artifact.queue // []) as $execution_queue_entries
  | ($execution_queue_bottleneck_report.bottlenecks // $execution_queue_artifact.queue_artifact.bottlenecks // []) as $execution_queue_bottlenecks
  | ({
      artifact_status: $execution_queue_artifact_status,
      risk_budget_artifact_status: $execution_queue_risk_budget_status,
      bottleneck_artifact_status: $execution_queue_bottleneck_report_status,
      run_manifest_artifact_status: $execution_queue_run_manifest_status,
      severity: (
        if $execution_queue_artifact_status == "missing"
          or $execution_queue_risk_budget_status == "missing"
          or $execution_queue_bottleneck_report_status == "missing"
          or $execution_queue_run_manifest_status == "missing" then "warning"
        elif (($execution_queue_risk_budget.decision // $execution_queue_run_manifest.decision // "") == "fail_closed") then "critical"
        elif (($execution_queue_risk_budget.conservative_mode // $execution_queue_artifact.queue_artifact.risk_budget.conservative_mode // false) == true)
          or (($execution_queue_bottleneck_report.critical_bottleneck_count // 0) > 0)
          or ($checkpoint_restore_summary.severity != "ok") then "warning"
        else "ok"
        end
      ),
      decision: ($execution_queue_risk_budget.decision // $execution_queue_run_manifest.decision // "missing"),
      conservative_mode: (($execution_queue_risk_budget.conservative_mode // $execution_queue_artifact.queue_artifact.risk_budget.conservative_mode // false) == true),
      queue_depth: ($execution_queue_risk_budget.queue_depth // ($execution_queue_entries | length)),
      top_recommended_starts: bounded(
        $execution_queue_entries
        | map(select((.wave // "") == "ready_now"))
        | map({
            rank: (.rank // null),
            task_id: (.task_id // null),
            title: (.title // null),
            wave: (.wave // null),
            first_action: (.first_action // null),
            fallback_trigger: (.fallback_trigger // "none"),
            ev_millionths: (.ev_millionths // null)
          })
      ),
      deferred_items: bounded(
        $execution_queue_entries
        | map(select(((.wave // "") != "ready_now") or ((.fallback_trigger // "none") != "none")))
        | map({
            rank: (.rank // null),
            task_id: (.task_id // null),
            title: (.title // null),
            wave: (.wave // null),
            first_action: (.first_action // null),
            fallback_trigger: (.fallback_trigger // "none"),
            open_blocker_count: (.open_blocker_count // 0)
          })
      ),
      bottlenecks: bounded($execution_queue_bottlenecks),
      bottleneck_count: ($execution_queue_bottleneck_report.bottleneck_count // ($execution_queue_bottlenecks | length)),
      critical_bottleneck_count: ($execution_queue_bottleneck_report.critical_bottleneck_count // 0),
      risk_budget: {
        remaining_millionths: ($execution_queue_risk_budget.risk_budget.remaining_millionths // $execution_queue_artifact.queue_artifact.risk_budget.remaining_millionths // 0),
        consumed_millionths: ($execution_queue_risk_budget.risk_budget.consumed_millionths // $execution_queue_artifact.queue_artifact.risk_budget.consumed_millionths // 0),
        conservative_threshold_millionths: ($execution_queue_risk_budget.risk_budget.conservative_threshold_millionths // $execution_queue_artifact.queue_artifact.risk_budget.conservative_threshold_millionths // 200000)
      },
      artifact_hash_hex: ($execution_queue_artifact.artifact_hash_hex // $execution_queue_run_manifest.artifact_hash_hex // null),
      normalized_input_hash_hex: ($execution_queue_artifact.normalized_input_hash_hex // $execution_queue_run_manifest.normalized_input_hash_hex // null),
      proof_lane_rationale: (
        if $execution_queue_artifact_status == "missing"
          or $execution_queue_risk_budget_status == "missing"
          or $execution_queue_bottleneck_report_status == "missing"
          or $execution_queue_run_manifest_status == "missing" then
          "Provide execution queue runner artifacts before trusting queue advisory output."
        elif (($execution_queue_risk_budget.conservative_mode // false) == true) then
          "Risk budget is in conservative mode; prefer narrow/no-cargo proof work before broad validation."
        else
          "Execution queue runner artifacts are present and risk budget permits advisory queue use."
        end
      ),
      restore_dependency_state: (
        if $checkpoint_bundle_status == "missing"
          or $checkpoint_restore_plan_status == "missing"
          or $checkpoint_restore_conformance_report_status == "missing" then "restore_unknown"
        elif $checkpoint_restore_summary.severity == "critical" then "restore_blocked"
        elif $checkpoint_restore_summary.severity == "warning" then "restore_manual_review"
        else "clear"
        end
      ),
      restore_dependency_detail: (
        if $checkpoint_bundle_status == "missing"
          or $checkpoint_restore_plan_status == "missing"
          or $checkpoint_restore_conformance_report_status == "missing" then
          "Checkpoint restore handoff artifacts are missing; queue advice is advisory only."
        elif $checkpoint_restore_summary.severity == "critical" then
          "Checkpoint restore handoff is fail-closed or blocked; do not let queue advice override restore remediation."
        elif $checkpoint_restore_summary.severity == "warning" then
          "Checkpoint restore handoff requires manual review; queue advice must stay secondary."
        else
          "Checkpoint restore handoff is ready."
        end
      ),
      queue_artifact_path: ($execution_queue_run_manifest.artifact_paths.execution_queue_artifact_json // null),
      risk_budget_artifact_path: ($execution_queue_run_manifest.artifact_paths.risk_budget_receipt_json // null),
      bottleneck_report_artifact_path: ($execution_queue_run_manifest.artifact_paths.bottleneck_report_json // null),
      run_manifest_artifact_path: ($execution_queue_run_manifest.artifact_paths.run_manifest_json // null)
    }) as $execution_queue_summary
  | (($queue_drift_ledger.rows // []) | if type == "array" then . else [] end) as $queue_drift_rows
  | ($queue_drift_rows
      | map(select((.mismatch_class // "exact_match") != "exact_match"))
      | sort_by((0 - mismatch_severity_rank(.mismatch_class)), (.row_score_millionths // 1000000), (.task_id // ""))) as $queue_mismatches
  | ($queue_tuning_plan.recommended_candidate // {}) as $queue_top_candidate
  | ({
      artifact_status: $queue_fidelity_score_receipt_status,
      drift_ledger_artifact_status: $queue_drift_ledger_status,
      counterfactual_backtest_artifact_status: $queue_counterfactual_backtest_report_status,
      tuning_plan_artifact_status: $queue_tuning_plan_status,
      frontier_artifact_status: $queue_tuning_frontier_status,
      severity: (
        if $queue_fidelity_score_receipt_status == "missing"
          or $queue_drift_ledger_status == "missing"
          or $queue_counterfactual_backtest_report_status == "missing"
          or $queue_tuning_plan_status == "missing"
          or $queue_tuning_frontier_status == "missing" then "warning"
        elif (($queue_fidelity_score_receipt.decision // "") == "fail_closed")
          or (($queue_drift_ledger.decision // "") == "fail_closed")
          or (($queue_counterfactual_backtest_report.decision // "") == "fail_closed")
          or (($queue_tuning_plan.decision // "") == "fail_closed") then "critical"
        elif (($queue_fidelity_score_receipt.decision // "") == "degraded")
          or (($queue_counterfactual_backtest_report.decision // "") == "degraded")
          or (($queue_tuning_plan.decision // "") == "degraded")
          or (($queue_fidelity_score_receipt.confidence_band // "") | IN("low", "insufficient_evidence", "unknown")) then "warning"
        else "ok"
        end
      ),
      trust_level: (
        if $queue_fidelity_score_receipt_status == "missing"
          or $queue_drift_ledger_status == "missing"
          or $queue_counterfactual_backtest_report_status == "missing"
          or $queue_tuning_plan_status == "missing"
          or $queue_tuning_frontier_status == "missing" then "missing"
        elif (($queue_fidelity_score_receipt.decision // "") == "fail_closed")
          or (($queue_drift_ledger.decision // "") == "fail_closed")
          or (($queue_counterfactual_backtest_report.decision // "") == "fail_closed")
          or (($queue_tuning_plan.decision // "") == "fail_closed") then "rejected"
        elif (($queue_fidelity_score_receipt.decision // "") == "degraded")
          or (($queue_counterfactual_backtest_report.decision // "") == "degraded")
          or (($queue_tuning_plan.decision // "") == "degraded")
          or (($queue_fidelity_score_receipt.overall_fidelity_millionths // 0) < 650000) then "degraded"
        elif (($queue_fidelity_score_receipt.confidence_band // "") == "high")
          and (($queue_fidelity_score_receipt.overall_fidelity_millionths // 0) >= 800000) then "trustworthy"
        else "advisory"
        end
      ),
      decision: ($queue_fidelity_score_receipt.decision // "missing"),
      overall_fidelity_millionths: ($queue_fidelity_score_receipt.overall_fidelity_millionths // 0),
      confidence_band: ($queue_fidelity_score_receipt.confidence_band // "unknown"),
      drift_class: (
        if ($queue_mismatches | length) == 0 then "none"
        else ($queue_mismatches[0].mismatch_class // "unknown")
        end
      ),
      highest_severity_mismatch: (
        if ($queue_mismatches | length) == 0 then null
        else {
          task_id: ($queue_mismatches[0].task_id // null),
          mismatch_class: ($queue_mismatches[0].mismatch_class // "unknown"),
          drift_class: ($queue_mismatches[0].drift_class // "unknown"),
          row_score_millionths: ($queue_mismatches[0].row_score_millionths // null),
          remediation: ($queue_mismatches[0].remediation // null)
        }
        end
      ),
      mismatch_count: ($queue_mismatches | length),
      row_count: ($queue_fidelity_score_receipt.summary.row_count // ($queue_drift_rows | length)),
      fail_closed_reason_count: (($queue_fidelity_score_receipt.summary.fail_closed_reason_count // 0) + (($queue_counterfactual_backtest_report.fail_closed_reasons // []) | length)),
      tuning_plan_decision: ($queue_tuning_plan.decision // "missing"),
      tuning_plan_class: ($queue_tuning_plan.plan_class // "missing"),
      top_tuning_recommendation: (
        if (($queue_top_candidate | type) == "object") and (($queue_top_candidate.candidate_id // "") | length) > 0 then {
          candidate_id: ($queue_top_candidate.candidate_id // null),
          expected_fidelity_delta_millionths: ($queue_top_candidate.expected_fidelity_delta_millionths // 0),
          confidence_band: ($queue_top_candidate.confidence_band // "unknown"),
          safety_status: ($queue_top_candidate.safety_status // "unknown"),
          manual_review_required: (($queue_top_candidate.manual_review_required // false) == true)
        }
        else null
        end
      ),
      frontier: bounded($queue_tuning_frontier.frontier),
      operator_notes: bounded($queue_tuning_plan.operator_notes),
      mutation_policy: {
        advisory_only: (($queue_tuning_plan.mutation_policy.advisory_only // true) == true),
        changes_active_queue: (($queue_tuning_plan.mutation_policy.changes_active_queue // false) == true),
        applies_live_retuning: (($queue_tuning_plan.mutation_policy.applies_live_retuning // false) == true)
      },
      artifact_paths: {
        fidelity_score_receipt_json: ($queue_fidelity_score_receipt.artifact_paths.fidelity_score_receipt_json // null),
        drift_ledger_json: ($queue_fidelity_score_receipt.artifact_paths.drift_ledger_json // null),
        counterfactual_backtest_report_json: ($queue_counterfactual_backtest_report.artifact_paths.counterfactual_backtest_report_json // null),
        tuning_plan_json: ($queue_counterfactual_backtest_report.artifact_paths.tuning_plan_json // null),
        frontier_json: ($queue_counterfactual_backtest_report.artifact_paths.frontier_json // null)
      }
    }) as $queue_fidelity_summary
  | ([
      $queue_tuning_bundle.mutation_policy,
      $queue_tuning_promotion_guard_receipt.mutation_policy,
      $queue_tuning_rollout_plan.mutation_policy,
      $queue_tuning_rollback_comparator_receipt.mutation_policy,
      $queue_tuning_canary_verdict_ledger.mutation_policy
    ] | map({
      advisory_only: ((.advisory_only // true) == true),
      changes_active_queue: ((.changes_active_queue // false) == true),
      applies_live_retuning: ((.applies_live_retuning // false) == true)
    })) as $queue_tuning_mutation_policies
  | ($queue_tuning_mutation_policies | map(select(.changes_active_queue == true)) | length > 0) as $queue_tuning_changes_active_queue
  | ($queue_tuning_mutation_policies | map(select(.applies_live_retuning == true)) | length > 0) as $queue_tuning_applies_live_retuning
  | ($queue_tuning_mutation_policies | map(select(.advisory_only != true)) | length > 0) as $queue_tuning_lacks_advisory_only
  | ((($queue_tuning_promotion_guard_receipt.reject_reasons // []) | length)
      + (($queue_tuning_promotion_guard_receipt.manual_approval_blockers // []) | length)
      + (($queue_tuning_rollout_plan.manual_approval.blockers // []) | length)
      + (($queue_tuning_rollout_plan.rejection_reasons // []) | length)) as $queue_tuning_manual_blocker_count
  | ({
      artifact_statuses: {
        bundle: $queue_tuning_bundle_status,
        promotion_guard_receipt: $queue_tuning_promotion_guard_receipt_status,
        rollout_plan: $queue_tuning_rollout_plan_status,
        rollback_comparator_receipt: $queue_tuning_rollback_comparator_receipt_status,
        canary_verdict_ledger: $queue_tuning_canary_verdict_ledger_status
      },
      severity: (
        if $queue_tuning_bundle_status == "missing"
          or $queue_tuning_promotion_guard_receipt_status == "missing"
          or $queue_tuning_rollout_plan_status == "missing"
          or $queue_tuning_rollback_comparator_receipt_status == "missing"
          or $queue_tuning_canary_verdict_ledger_status == "missing" then "warning"
        elif $queue_tuning_changes_active_queue or $queue_tuning_applies_live_retuning or $queue_tuning_lacks_advisory_only then "critical"
        elif (($queue_tuning_promotion_guard_receipt.decision // "") | IN("reject", "fail_closed", "blocked"))
          or (($queue_tuning_rollout_plan.decision // "") | IN("reject", "fail_closed", "blocked"))
          or (($queue_tuning_rollback_comparator_receipt.verdict // "") | IN("worse_than_current", "fail_closed"))
          or (($queue_tuning_canary_verdict_ledger.recommended_action // "") | IN("rollback_required", "stop_canary", "revert", "fail_closed")) then "critical"
        elif (($queue_tuning_promotion_guard_receipt.decision // "") | IN("manual_review", "missing"))
          or (($queue_tuning_rollout_plan.decision // "") | IN("manual_review", "missing"))
          or (($queue_tuning_rollback_comparator_receipt.verdict // "") | IN("ambiguous_verdict", "missing"))
          or (($queue_tuning_canary_verdict_ledger.recommended_action // "") | IN("manual_review", "missing", "hold_canary")) then "warning"
        else "ok"
        end
      ),
      readiness: (
        if $queue_tuning_bundle_status == "missing"
          or $queue_tuning_promotion_guard_receipt_status == "missing"
          or $queue_tuning_rollout_plan_status == "missing"
          or $queue_tuning_rollback_comparator_receipt_status == "missing"
          or $queue_tuning_canary_verdict_ledger_status == "missing" then "missing"
        elif $queue_tuning_changes_active_queue or $queue_tuning_applies_live_retuning or $queue_tuning_lacks_advisory_only then "fail_closed"
        elif (($queue_tuning_promotion_guard_receipt.decision // "") | IN("reject", "fail_closed", "blocked"))
          or (($queue_tuning_rollout_plan.decision // "") | IN("reject", "fail_closed", "blocked")) then "fail_closed"
        elif (($queue_tuning_rollback_comparator_receipt.verdict // "") | IN("worse_than_current", "fail_closed"))
          or (($queue_tuning_canary_verdict_ledger.recommended_action // "") | IN("rollback_required", "stop_canary", "revert", "fail_closed")) then "rollback_required"
        elif (($queue_tuning_promotion_guard_receipt.decision // "") | IN("manual_review", "missing"))
          or (($queue_tuning_rollout_plan.decision // "") | IN("manual_review", "missing"))
          or (($queue_tuning_rollback_comparator_receipt.verdict // "") | IN("ambiguous_verdict", "missing"))
          or (($queue_tuning_canary_verdict_ledger.recommended_action // "") | IN("manual_review", "missing", "hold_canary")) then "manual_review"
        elif (($queue_tuning_promotion_guard_receipt.decision // "") == "safe_noop") then "noop"
        elif (($queue_tuning_promotion_guard_receipt.decision // "") == "eligible_canary")
          and (($queue_tuning_rollback_comparator_receipt.verdict // "") == "better_than_current")
          and (($queue_tuning_canary_verdict_ledger.recommended_action // "") | IN("continue_canary", "promote_after_canary")) then "ready"
        else "advisory"
        end
      ),
      bundle_id: ($queue_tuning_bundle.bundle_id // null),
      candidate_id: ($queue_tuning_bundle.promoted_candidate.candidate_id // $queue_tuning_promotion_guard_receipt.candidate_id // null),
      candidate_delta_millionths: ($queue_tuning_bundle.promoted_candidate.expected_fidelity_delta_millionths // $queue_tuning_promotion_guard_receipt.expected_fidelity_delta_millionths // null),
      bundle_decision: ($queue_tuning_bundle.decision // "missing"),
      promotion_decision: ($queue_tuning_promotion_guard_receipt.decision // "missing"),
      rollout_decision: ($queue_tuning_rollout_plan.decision // "missing"),
      rollback_verdict: ($queue_tuning_rollback_comparator_receipt.verdict // "missing"),
      canary_verdict: ($queue_tuning_canary_verdict_ledger.verdict // "missing"),
      canary_recommended_action: ($queue_tuning_canary_verdict_ledger.recommended_action // "missing"),
      manual_approval_required: (($queue_tuning_bundle.manual_approval.required // $queue_tuning_rollout_plan.manual_approval.required // true) == true),
      manual_approval_blocker_count: $queue_tuning_manual_blocker_count,
      evidence_link_count: (($queue_tuning_bundle.evidence_links // []) | length),
      rollback_trigger_count: (($queue_tuning_canary_verdict_ledger.rollback_triggers // []) | length),
      top_stop_condition: (
        if (($queue_tuning_rollout_plan.stop_conditions // []) | length) == 0 then null
        else $queue_tuning_rollout_plan.stop_conditions[0]
        end
      ),
      reject_reasons: bounded(($queue_tuning_promotion_guard_receipt.reject_reasons // []) + ($queue_tuning_rollout_plan.rejection_reasons // [])),
      rollback_triggers: bounded($queue_tuning_canary_verdict_ledger.rollback_triggers),
      mutation_policy: {
        advisory_only: (($queue_tuning_lacks_advisory_only | not) and ($queue_tuning_changes_active_queue | not) and ($queue_tuning_applies_live_retuning | not)),
        changes_active_queue: $queue_tuning_changes_active_queue,
        applies_live_retuning: $queue_tuning_applies_live_retuning
      },
      artifact_paths: {
        bundle_json: ($queue_tuning_bundle.artifact_paths.tuning_policy_bundle_json // $queue_tuning_bundle.artifact_paths.bundle_json // null),
        promotion_guard_receipt_json: ($queue_tuning_promotion_guard_receipt.artifact_paths.promotion_guard_receipt_json // null),
        rollout_plan_json: ($queue_tuning_rollout_plan.artifact_paths.manual_approval_rollout_plan_json // $queue_tuning_rollout_plan.artifact_paths.rollout_plan_json // null),
        rollback_comparator_receipt_json: ($queue_tuning_rollback_comparator_receipt.artifact_paths.rollback_comparator_receipt_json // null),
        canary_verdict_ledger_json: ($queue_tuning_canary_verdict_ledger.artifact_paths.canary_verdict_ledger_json // null)
      }
    }) as $queue_tuning_promotion_summary
  | ([
      $queue_policy_adoption_receipt.mutation_policy,
      $queue_policy_adoption_snapshot_bundle.mutation_policy,
      $queue_policy_sustained_gain_receipt.mutation_policy,
      $queue_policy_expiry_supersession_plan.mutation_policy,
      $queue_policy_expiry_supersession_ledger.mutation_policy
    ] | map({
      changes_active_queue: ((.changes_active_queue // false) == true),
      applies_live_retuning: ((.applies_live_retuning // false) == true),
      mutates_br: ((.mutates_br // false) == true),
      sends_agent_mail: ((.sends_agent_mail // false) == true),
      mutates_remote_workers: ((.mutates_remote_workers // false) == true),
      rewrites_historical_outcomes: ((.rewrites_historical_outcomes // false) == true),
      retirement_executed: ((.retirement_executed // false) == true),
      supersession_executed: ((.supersession_executed // false) == true)
    })) as $queue_policy_mutation_policies
  | (any($queue_policy_mutation_policies[]; .changes_active_queue)) as $queue_policy_changes_active_queue
  | (any($queue_policy_mutation_policies[]; .applies_live_retuning)) as $queue_policy_applies_live_retuning
  | (any($queue_policy_mutation_policies[]; .mutates_br or .sends_agent_mail or .mutates_remote_workers or .rewrites_historical_outcomes)) as $queue_policy_mutates_external_state
  | (any($queue_policy_mutation_policies[]; .retirement_executed or .supersession_executed)) as $queue_policy_claims_execution
  | ({
      artifact_statuses: {
        adoption_receipt: $queue_policy_adoption_receipt_status,
        adoption_snapshot_bundle: $queue_policy_adoption_snapshot_bundle_status,
        sustained_gain_receipt: $queue_policy_sustained_gain_receipt_status,
        expiry_supersession_plan: $queue_policy_expiry_supersession_plan_status,
        expiry_supersession_ledger: $queue_policy_expiry_supersession_ledger_status
      },
      severity: (
        if $queue_policy_adoption_receipt_status == "missing"
          or $queue_policy_adoption_snapshot_bundle_status == "missing"
          or $queue_policy_sustained_gain_receipt_status == "missing"
          or $queue_policy_expiry_supersession_plan_status == "missing"
          or $queue_policy_expiry_supersession_ledger_status == "missing" then "warning"
        elif $queue_policy_changes_active_queue or $queue_policy_applies_live_retuning or $queue_policy_mutates_external_state or $queue_policy_claims_execution then "critical"
        elif (($queue_policy_expiry_supersession_plan.decision // "") == "fail_closed")
          or (($queue_policy_sustained_gain_receipt.verdict // "") == "fail_closed") then "critical"
        elif (($queue_policy_expiry_supersession_plan.expiry_required // false) == true)
          or (($queue_policy_expiry_supersession_plan.supersession_required // false) == true)
          or (($queue_policy_sustained_gain_receipt.verdict // "") | IN("regression_detected", "inconclusive_drift")) then "warning"
        else "ok"
        end
      ),
      readiness: (
        if $queue_policy_adoption_receipt_status == "missing"
          or $queue_policy_adoption_snapshot_bundle_status == "missing"
          or $queue_policy_sustained_gain_receipt_status == "missing"
          or $queue_policy_expiry_supersession_plan_status == "missing"
          or $queue_policy_expiry_supersession_ledger_status == "missing" then "missing"
        elif $queue_policy_changes_active_queue or $queue_policy_applies_live_retuning or $queue_policy_mutates_external_state or $queue_policy_claims_execution then "fail_closed"
        elif (($queue_policy_expiry_supersession_plan.decision // "") == "fail_closed")
          or (($queue_policy_sustained_gain_receipt.verdict // "") == "fail_closed") then "fail_closed"
        elif (($queue_policy_expiry_supersession_plan.supersession_required // false) == true) then "supersession_required"
        elif (($queue_policy_expiry_supersession_plan.expiry_required // false) == true) then "expiry_required"
        elif (($queue_policy_sustained_gain_receipt.verdict // "") == "inconclusive_drift") then "manual_review"
        elif (($queue_policy_expiry_supersession_plan.decision // "") == "retain_adopted_policy") then "retained"
        else "advisory"
        end
      ),
      adoption_receipt_id: ($queue_policy_adoption_receipt.adoption_receipt_id // null),
      adoption_state: ($queue_policy_adoption_receipt.operator_decision.adoption_state // "missing"),
      adopted_policy_bundle_id: ($queue_policy_adoption_receipt.adopted_policy_bundle_id // $queue_policy_expiry_supersession_plan.adopted_policy_bundle_id // null),
      adopted_candidate_id: ($queue_policy_adoption_receipt.adopted_candidate.candidate_id // $queue_policy_expiry_supersession_plan.adopted_candidate_id // null),
      adopted_expected_delta_millionths: ($queue_policy_adoption_receipt.adopted_candidate.expected_fidelity_delta_millionths // $queue_policy_expiry_supersession_plan.adopted_expected_delta_millionths // null),
      observation_window: ($queue_policy_adoption_receipt.observation_window // {}),
      supersession_metadata: ($queue_policy_adoption_receipt.supersession // {}),
      sustained_gain_verdict: ($queue_policy_sustained_gain_receipt.verdict // "missing"),
      sustained_gain_receipt_id: ($queue_policy_sustained_gain_receipt.sustained_gain_receipt_id // null),
      rollback_relevant_drift_count: ($queue_policy_expiry_supersession_plan.rollback_relevant_drift_count // $queue_policy_sustained_gain_receipt.rollback_drift_count // 0),
      expiry_decision: ($queue_policy_expiry_supersession_plan.decision // "missing"),
      expiry_required: (($queue_policy_expiry_supersession_plan.expiry_required // false) == true),
      supersession_required: (($queue_policy_expiry_supersession_plan.supersession_required // false) == true),
      newer_candidate_bundle_id: ($queue_policy_expiry_supersession_plan.newer_candidate_bundle_id // null),
      newer_candidate_id: ($queue_policy_expiry_supersession_plan.newer_candidate_id // null),
      execution_state: ($queue_policy_expiry_supersession_plan.advisory_status.execution_state // "missing"),
      retirement_executed: (($queue_policy_expiry_supersession_plan.advisory_status.retirement_executed // false) == true),
      supersession_executed: (($queue_policy_expiry_supersession_plan.advisory_status.supersession_executed // false) == true),
      decision_reasons: bounded($queue_policy_expiry_supersession_plan.decision_reasons),
      fail_closed_reasons: bounded(($queue_policy_expiry_supersession_plan.fail_closed_reasons // []) + ($queue_policy_expiry_supersession_ledger.fail_closed_reasons // [])),
      ledger_rows: bounded($queue_policy_expiry_supersession_ledger.ledger_rows),
      mutation_policy: {
        advisory_only: (($queue_policy_changes_active_queue | not) and ($queue_policy_applies_live_retuning | not) and ($queue_policy_mutates_external_state | not) and ($queue_policy_claims_execution | not)),
        changes_active_queue: $queue_policy_changes_active_queue,
        applies_live_retuning: $queue_policy_applies_live_retuning,
        mutates_external_state: $queue_policy_mutates_external_state,
        retirement_executed: (($queue_policy_expiry_supersession_plan.mutation_policy.retirement_executed // false) == true),
        supersession_executed: (($queue_policy_expiry_supersession_plan.mutation_policy.supersession_executed // false) == true)
      },
      artifact_paths: {
        adoption_receipt_json: ($queue_policy_adoption_receipt.artifact_paths.adoption_receipt_json // null),
        adoption_snapshot_bundle_json: ($queue_policy_adoption_snapshot_bundle.artifact_paths.adoption_snapshot_bundle_json // null),
        sustained_gain_receipt_json: ($queue_policy_sustained_gain_receipt.artifact_paths.sustained_gain_receipt_json // null),
        expiry_supersession_plan_json: ($queue_policy_expiry_supersession_plan.artifact_paths.expiry_supersession_plan_json // null),
        expiry_supersession_ledger_json: ($queue_policy_expiry_supersession_plan.artifact_paths.expiry_supersession_ledger_json // null)
      }
    }) as $queue_policy_adoption_summary
  | ($swarm_agent_causal_trace_graph.edges // []) as $causal_trace_edges
  | ($swarm_agent_causal_trace_graph.nodes // []) as $causal_trace_nodes
  | ($swarm_agent_causal_trace_anomaly_report.anomalies // []) as $causal_trace_anomalies
  | ($causal_trace_edges | map(.edge_type // "unknown") | unique | sort) as $causal_trace_edge_types
  | (["bead_claimed", "reservation_covers_path", "validation_proves_closeout", "commit_closes_bead"] - $causal_trace_edge_types) as $causal_trace_missing_edges
  | (($causal_trace_nodes | map(select((.node_type // "") == "bead_state")) | .[0].payload.status) // "unknown") as $causal_trace_bead_status
  | ($swarm_agent_causal_trace_anomaly_report.decision // $swarm_agent_causal_trace_graph.anomaly_summary.decision // "missing") as $causal_trace_decision
  | ($swarm_agent_causal_trace_anomaly_report.anomaly_count // $swarm_agent_causal_trace_graph.anomaly_summary.anomaly_count // 0) as $causal_trace_anomaly_count
  | ($swarm_agent_causal_trace_anomaly_report.fail_closed_count // $swarm_agent_causal_trace_graph.anomaly_summary.fail_closed_count // 0) as $causal_trace_fail_closed_count
  | ($swarm_agent_causal_trace_anomaly_report.degraded_count // $swarm_agent_causal_trace_graph.anomaly_summary.degraded_count // 0) as $causal_trace_degraded_count
  | ($swarm_agent_causal_trace_anomaly_report.anomaly_classes // $swarm_agent_causal_trace_graph.anomaly_summary.anomaly_classes // []) as $causal_trace_anomaly_classes
  | ($causal_trace_anomaly_classes
      | map(select(. == "local_rch_fallback_contaminates_remote_proof"
          or . == "stale_owner_recent_activity_conflict"
          or . == "ack_required_message_unacknowledged"))) as $causal_trace_contaminating_classes
  | (reduce $causal_trace_edges[] as $edge ({}; .[$edge.edge_type // "unknown"] += 1)) as $causal_trace_edge_counts
  | ({
      artifact_statuses: {
        graph: $swarm_agent_causal_trace_graph_status,
        anomaly_report: $swarm_agent_causal_trace_anomaly_report_status
      },
      readiness: (
        if ($causal_trace_decision == "fail_closed")
          or ($causal_trace_fail_closed_count > 0)
          or (($causal_trace_contaminating_classes | length) > 0) then "contaminated"
        elif $swarm_agent_causal_trace_graph_status == "missing"
          or $swarm_agent_causal_trace_anomaly_report_status == "missing" then "degraded"
        elif ($causal_trace_decision == "degraded")
          or ($causal_trace_anomaly_count > 0)
          or ($causal_trace_degraded_count > 0) then "degraded"
        elif $causal_trace_bead_status == "in_progress"
          and (($causal_trace_missing_edges | length) > 0) then "blocked"
        elif (($causal_trace_missing_edges | length) == 0) then "complete"
        else "degraded"
        end
      ),
      severity: (
        if ($causal_trace_decision == "fail_closed")
          or ($causal_trace_fail_closed_count > 0)
          or (($causal_trace_contaminating_classes | length) > 0) then "critical"
        elif $swarm_agent_causal_trace_graph_status == "missing"
          or $swarm_agent_causal_trace_anomaly_report_status == "missing" then "warning"
        elif ($causal_trace_decision == "degraded")
          or ($causal_trace_anomaly_count > 0)
          or ($causal_trace_degraded_count > 0)
          or ($causal_trace_bead_status == "in_progress" and (($causal_trace_missing_edges | length) > 0)) then "warning"
        else "ok"
        end
      ),
      decision: $causal_trace_decision,
      trace_id: ($swarm_agent_causal_trace_graph.trace_id // $swarm_agent_causal_trace_anomaly_report.trace_id // null),
      bead_id: ($swarm_agent_causal_trace_graph.bead_id // $swarm_agent_causal_trace_anomaly_report.bead_id // null),
      source_revision: ($swarm_agent_causal_trace_graph.source_revision // $swarm_agent_causal_trace_anomaly_report.source_revision // null),
      bead_status: $causal_trace_bead_status,
      required_edge_types: ["bead_claimed", "reservation_covers_path", "validation_proves_closeout", "commit_closes_bead"],
      present_edge_types: $causal_trace_edge_types,
      missing_required_edges: $causal_trace_missing_edges,
      edge_counts: $causal_trace_edge_counts,
      node_count: ($causal_trace_nodes | length),
      edge_count: ($causal_trace_edges | length),
      anomaly_count: $causal_trace_anomaly_count,
      fail_closed_count: $causal_trace_fail_closed_count,
      degraded_count: $causal_trace_degraded_count,
      anomaly_classes: $causal_trace_anomaly_classes,
      contaminating_anomaly_classes: $causal_trace_contaminating_classes,
      top_anomaly: (if ($causal_trace_anomalies | length) == 0 then null else $causal_trace_anomalies[0] end),
      mutation_policy: ($swarm_agent_causal_trace_graph.mutation_policy // {}),
      artifact_paths: {
        causal_graph_json: ($swarm_agent_causal_trace_graph.artifact_paths.causal_graph_json // null),
        anomaly_report_json: ($swarm_agent_causal_trace_anomaly_report.artifact_paths.anomaly_report_json // $swarm_agent_causal_trace_graph.artifact_paths.anomaly_report_json // null)
      }
    }) as $causal_trace_summary
  | ([
      degraded("agent_mail"; $agent_mail_status; "reservation and inbox data may be incomplete"; "Use bead assignee and dirty paths as degraded fallback evidence."),
      degraded("rch"; $rch_status; "remote proof routing may be unavailable"; "Defer heavy validation until rch status is ok or use script-only proof."),
      degraded("proof_evidence_index"; $proof_index_status; "proof queries may be incomplete"; "Use explicit proof outcome snapshots until bd-p03vs lands.")
    ]
    + (if (($validation_plan.decision // "") == "fail_closed") then
        [{component: "validation_plan", status: "fail_closed", impact: "planned validation cannot run safely", remediation: "Fix unknown path mappings or ownership before running validation."}]
      else [] end)
    + (if (($resource_decision.decision // "") | IN("defer", "fail_closed")) then
        [{component: "resource_governor", status: ($resource_decision.decision // "unknown"), impact: "resource admission is not green", remediation: "Follow resource-governor remediation before starting heavy validation."}]
      else [] end)
    + ($dirty_reserved | map({component: "dirty_reserved_file", status: "degraded", impact: (.path + " is dirty or reserved"), remediation: "Avoid this file or coordinate with the holder."}))
    + ($stale | map({component: "stale_proof_artifact", status: "degraded", impact: (.artifact_id + " is stale"), remediation: "Refresh or mark the proof stale before relying on it."}))
    + ($bad_proofs | map({component: "proof_outcome", status: (.status // "degraded"), impact: (.bead_id + " proof is not passing"), remediation: "Inspect the proof outcome before recommending dependent work."}))
    + ($blocked_items | map({component: "blocked_bead_chain", status: "blocked", impact: (.id + " is blocked in the bv track"), remediation: "Inspect dependencies before recommending this bead."}))
    + ($high_cost_rows | map({component: "predictive_cost", status: (.cost_class // "unknown"), impact: ((.command_id // "unknown_command") + " has elevated predicted validation cost"), remediation: "Narrow the command, defer until resource pressure clears, or preserve the high-cost receipt."}))
    + (if $resource_lease_plan_status == "missing" then
        [{component: "resource_leases", status: "missing", impact: "resource lease admission artifact is missing", remediation: "Provide --resource-lease-plan-json before publishing the operator status feed."}]
      elif $resource_leases_summary.severity != "ok" then
        [{component: "resource_leases", status: $resource_leases_summary.lease_decision, impact: "resource lease admission is not fully green", remediation: ($resource_leases_summary.reason // "Inspect the resource lease plan before running validation.")}]
      else [] end)
    + (if $proof_cache_plan_status == "missing" then
        [{component: "proof_cache", status: "missing", impact: "proof reuse cache artifact is missing", remediation: "Provide --proof-cache-plan-json before reusing prior proof artifacts."}]
      elif $proof_cache_summary.severity != "ok" then
        [{component: "proof_cache", status: $proof_cache_summary.proof_cache_decision, impact: "proof cache does not report a clean cache hit", remediation: ($proof_cache_summary.reason // "Refresh proof artifacts before relying on them.")}]
      else [] end)
    + (if $qos_batch_plan_status == "missing" then
        [{component: "qos_batches", status: "missing", impact: "build-storm QoS batch artifact is missing", remediation: "Provide --qos-batch-plan-json before publishing admission state."}]
      elif $qos_batches_summary.severity != "ok" then
        [{component: "qos_batches", status: $qos_batches_summary.batch_decision, impact: "one or more validation requests are deferred or the batch is unavailable", remediation: ($qos_batches_summary.fairness_reason // "Inspect QoS batch plan before admitting more heavy proof work.")}]
      else [] end)
    + (if $stale_lock_recommendations_status == "missing" then
        [{component: "stale_lock_recommendations", status: "missing", impact: "stale-lock recommendation artifact is missing", remediation: "Provide --stale-lock-recommendations-json before reopening stalled beads."}]
      elif $stale_lock_summary.severity != "ok" then
        [{component: "stale_lock_recommendations", status: "attention", impact: "stalled beads require reopen or contact-first action", remediation: "Follow the stale-lock recommendation commands before changing assignees."}]
      else [] end)
    + (if $staged_ownership_report_status == "missing" then
        [{component: "staged_contamination", status: "missing", impact: "staged ownership guard artifact is missing", remediation: "Provide --staged-ownership-report-json before commit or closeout."}]
      elif $staged_contamination_summary.severity != "ok" then
        [{component: "staged_contamination", status: $staged_contamination_summary.decision, impact: "staged paths are contaminated or only degraded ownership evidence is available", remediation: "Run the staged ownership guard and unstage offending paths before commit."}]
      else [] end)
    + (if $capacity_forecast_status == "missing" then
        [{component: "capacity_forecast", status: "missing", impact: "predictive capacity forecast artifact is missing", remediation: "Provide --capacity-forecast-json before publishing forecast confidence."}]
      elif $capacity_forecast_summary.severity != "ok" then
        [{component: "capacity_forecast", status: $capacity_forecast_summary.overall_state, impact: "predictive capacity forecast is low-confidence or degraded", remediation: (($capacity_forecast_summary.recommended_actions.compile_pressure // $telemetry_quality_summary.recommended_action) // "Refresh forecast inputs before trusting this dashboard section.")}]
      else [] end)
    + (if $admission_budget_plan_status == "missing" then
        [{component: "admission_budgets", status: "missing", impact: "admission budget plan artifact is missing", remediation: "Provide --admission-budget-plan-json before summarizing budget posture."}]
      elif $admission_budget_summary.severity != "ok" then
        [{component: "admission_budgets", status: $admission_budget_summary.decision, impact: "admission budget planning is constrained or deferred", remediation: "Follow the budget recommendations before admitting more work."}]
      else [] end)
    + (if $lease_exchange_salvage_simulation_status == "missing" then
        [{component: "lease_exchange_salvage", status: "missing", impact: "lease-exchange salvage simulation artifact is missing", remediation: "Provide --lease-exchange-salvage-simulation-json before recommending ownership reshuffles."}]
      elif $lease_exchange_salvage_summary.severity != "ok" then
        [{component: "lease_exchange_salvage", status: $lease_exchange_salvage_summary.decision, impact: "lease-exchange or salvage promotion requires review", remediation: "Use the simulation recommendations instead of changing ownership blindly."}]
      else [] end)
    + (if $warm_target_prefetch_roi_advisory_status == "missing" then
        [{component: "prefetch_roi", status: "missing", impact: "warm-target prefetch ROI advisory artifact is missing", remediation: "Provide --warm-target-prefetch-roi-advisory-json before recommending prefetch."}]
      elif $prefetch_roi_summary.severity != "ok" then
        [{component: "prefetch_roi", status: $prefetch_roi_summary.advisory, impact: "prefetch ROI is degraded, blocked, or not worth taking", remediation: ($prefetch_roi_summary.recommended_action // "Respect the prefetch ROI advisory before warming targets.")}]
      else [] end)
    + (if $starvation_rescue_plan_status == "missing"
          or $starvation_rescue_conformance_report_status == "missing" then
        [{component: "starvation_rescue_handoff", status: "missing", impact: "starvation rescue handoff artifacts are incomplete", remediation: "Provide both --starvation-rescue-plan-json and --starvation-rescue-conformance-report-json before trusting rescue readiness."}]
      elif $starvation_rescue_summary.severity != "ok" then
        [{component: "starvation_rescue_handoff", status: $starvation_rescue_summary.escalation_band, impact: "starvation rescue handoff still has unresolved risks or manual review pressure", remediation: "Respect the rescue escalation band and recommended ordering before reopening or reassigning work."}]
      else [] end)
    + (if $checkpoint_bundle_status == "missing"
          or $checkpoint_restore_plan_status == "missing"
          or $checkpoint_restore_conformance_report_status == "missing" then
        [{component: "checkpoint_restore_handoff", status: "missing", impact: "checkpoint restore handoff artifacts are incomplete", remediation: "Provide --checkpoint-bundle-json, --checkpoint-restore-plan-json, and --checkpoint-restore-conformance-report-json before trusting restore readiness."}]
      elif $checkpoint_restore_summary.severity != "ok" then
        [{component: "checkpoint_restore_handoff", status: $checkpoint_restore_summary.escalation_band, impact: "checkpoint restore handoff still carries fail-closed or manual-review drift", remediation: "Respect the checkpoint restore escalation band and top restore action before resuming from a saved checkpoint."}]
      else [] end)
    + (if $execution_queue_artifact_status == "missing"
          or $execution_queue_risk_budget_status == "missing"
          or $execution_queue_bottleneck_report_status == "missing"
          or $execution_queue_run_manifest_status == "missing" then
        [{component: "execution_queue_advisory", status: "missing", impact: "execution queue runner artifacts are incomplete", remediation: "Provide queue artifact, risk-budget receipt, bottleneck report, and run manifest before trusting queue advice."}]
      elif $execution_queue_summary.severity != "ok" then
        [{component: "execution_queue_advisory", status: $execution_queue_summary.severity, impact: "execution queue advisory is conservative, blocked, or coupled to restore drift", remediation: $execution_queue_summary.proof_lane_rationale}]
      else [] end)
    + (if $queue_fidelity_score_receipt_status == "missing"
          or $queue_drift_ledger_status == "missing"
          or $queue_counterfactual_backtest_report_status == "missing"
          or $queue_tuning_plan_status == "missing"
          or $queue_tuning_frontier_status == "missing" then
        [{component: "queue_fidelity", status: "missing", impact: "queue fidelity and tuning artifacts are incomplete", remediation: "Provide fidelity receipt, drift ledger, counterfactual backtest, tuning plan, and frontier before trusting hindsight tuning advice."}]
      elif ($queue_fidelity_summary.mutation_policy.changes_active_queue == true
            or $queue_fidelity_summary.mutation_policy.applies_live_retuning == true
            or $queue_fidelity_summary.mutation_policy.advisory_only != true) then
        [{component: "queue_fidelity", status: "fail_closed", impact: "queue tuning input implies live mutation", remediation: "Reject tuning artifacts that claim automatic queue retuning or live mutation."}]
      elif $queue_fidelity_summary.severity != "ok" then
        [{component: "queue_fidelity", status: $queue_fidelity_summary.trust_level, impact: "queue hindsight drift or counterfactual tuning evidence is degraded", remediation: "Review the highest-severity mismatch and tuning frontier before changing queue policy."}]
      else [] end)
    + (if $queue_tuning_bundle_status == "missing"
          or $queue_tuning_promotion_guard_receipt_status == "missing"
          or $queue_tuning_rollout_plan_status == "missing"
          or $queue_tuning_rollback_comparator_receipt_status == "missing"
          or $queue_tuning_canary_verdict_ledger_status == "missing" then
        [{component: "queue_tuning_promotion", status: "missing", impact: "queue tuning promotion artifacts are incomplete", remediation: "Provide bundle, promotion guard, rollout plan, rollback comparator, and canary verdict artifacts before trusting promotion advice."}]
      elif ($queue_tuning_promotion_summary.mutation_policy.changes_active_queue == true
            or $queue_tuning_promotion_summary.mutation_policy.applies_live_retuning == true
            or $queue_tuning_promotion_summary.mutation_policy.advisory_only != true) then
        [{component: "queue_tuning_promotion", status: "fail_closed", impact: "queue tuning promotion input implies live mutation", remediation: "Reject promotion artifacts that claim automatic queue retuning, live mutation, or direct scheduler changes."}]
      elif $queue_tuning_promotion_summary.severity == "critical" then
        [{component: "queue_tuning_promotion", status: $queue_tuning_promotion_summary.readiness, impact: "queue tuning promotion is blocked, rejected, or requires rollback", remediation: "Respect the promotion guard, rollback comparator, and canary verdict before changing queue policy."}]
      elif $queue_tuning_promotion_summary.severity == "warning" then
        [{component: "queue_tuning_promotion", status: $queue_tuning_promotion_summary.readiness, impact: "queue tuning promotion needs manual review or fresher evidence", remediation: "Review manual approval blockers, stale evidence, and canary stop conditions before promotion."}]
      else [] end)
    + (if $queue_policy_adoption_summary.readiness == "missing" then
        [{component: "queue_policy_adoption", status: "missing", impact: "policy adoption, sustained-gain, or expiry advisory artifacts are incomplete", remediation: "Provide adoption receipt, snapshot, sustained-gain receipt, expiry plan, and expiry ledger before trusting policy lifecycle advice."}]
      elif $queue_policy_adoption_summary.mutation_policy.advisory_only != true then
        [{component: "queue_policy_adoption", status: "fail_closed", impact: "policy lifecycle input implies live mutation or executed retirement", remediation: "Reject lifecycle artifacts that claim automatic retuning, direct queue changes, or already executed retirement/supersession."}]
      elif $queue_policy_adoption_summary.severity == "critical" then
        [{component: "queue_policy_adoption", status: $queue_policy_adoption_summary.readiness, impact: "policy lifecycle evidence failed closed", remediation: "Respect sustained-gain and expiry/supersession fail-closed reasons before acting on the adopted policy."}]
      elif $queue_policy_adoption_summary.severity == "warning" then
        [{component: "queue_policy_adoption", status: $queue_policy_adoption_summary.readiness, impact: "policy lifecycle evidence recommends expiry, supersession, or manual review", remediation: "Route the advisory to a human operator; do not treat it as executed policy retirement or supersession."}]
      else [] end)
    + (if $causal_trace_summary.severity == "critical" then
        [{component: "swarm_agent_causal_trace", status: $causal_trace_summary.readiness, impact: "causal trace evidence is contaminated or failed closed", remediation: "Reject the handoff until ownership, acknowledgement, RCH proof, and closeout evidence are repaired."}]
      elif $causal_trace_summary.severity == "warning" then
        [{component: "swarm_agent_causal_trace", status: $causal_trace_summary.readiness, impact: "causal trace evidence is degraded or missing required in-progress edges", remediation: "Review missing causal edges and degraded anomaly classes before trusting the handoff."}]
      else [] end)
    + (if ($collision_summary.risk != "none") then
        [{component: "collision_risk", status: $collision_summary.risk, impact: "planned work may collide with another agent or dirty surface", remediation: "Coordinate with listed agents or use safe alternatives before editing."}]
      else [] end)
    + (if (($proof_freshness_summary.state | IN("fresh", "not_provided"))
            and ($proof_freshness_summary.reusable == true or $proof_freshness_summary.reusable == null)) then
        []
      else
        [{component: "proof_freshness", status: $proof_freshness_summary.state, impact: "prior proof evidence is not reusable", remediation: ($proof_freshness_summary.recommended_next_action // "Refresh the proof before relying on it.")}]
      end)
    + ($rch_incident_summaries | map(select((.status // "") != "pass") | {component: "rch_incident_packet", status: (.failure_kind // "unknown"), impact: "rch proof execution has an incident packet", remediation: (.recommended_next_action // "Inspect the packet before retrying.")}))
    ) as $degraded
  | {
      schema_version: $schema_version,
      bead_id: $bead_id,
      source_revision: $source_revision,
      status: (if ($degraded | length) == 0 then "healthy" else "degraded" end),
      tui_ready: true,
      dashboard_contract: {
        schema_version: "franken-engine.swarm-predictive-dashboard.v1",
        contract_doc: "docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md",
        contract_json: "docs/swarm_predictive_dashboard_contract_v1.json",
        renderer: {
          provider: "/dp/frankentui",
          shipped_in_franken_engine: false,
          local_renderer: false
        }
      },
      summary: {
        ready_count: ($ready_rows | length),
        in_progress_count: ($in_progress_rows | length),
        reservation_count: ($reservations | length),
        degraded_count: ($degraded | length),
        planned_command_count: (($validation_plan.commands // []) | length),
        predictive_cost_command_count: ($cost_rows | length),
        high_cost_command_count: ($high_cost_rows | length),
        proof_cost_budget_count: ($proof_cost_budgets | length),
        stale_evidence_count: ($stale | length),
        dirty_reserved_count: ($dirty_reserved | length),
        blocked_bead_count: ($blocked_items | length),
        collision_risk: $collision_summary.risk,
        rch_incident_count: ($rch_incident_summaries | length),
        resource_lease_decision: $resource_leases_summary.lease_decision,
        proof_cache_decision: $proof_cache_summary.proof_cache_decision,
        qos_batch_decision: $qos_batches_summary.batch_decision,
        qos_admitted_count: $qos_batches_summary.admitted_count,
        qos_deferred_count: $qos_batches_summary.deferred_count,
        stale_lock_safe_to_reopen_count: $stale_lock_summary.safe_to_reopen_count,
        stale_lock_contact_first_count: $stale_lock_summary.contact_first_count,
        forecast_overall_state: $capacity_forecast_summary.overall_state,
        forecast_confidence_band: $capacity_forecast_summary.confidence_band,
        telemetry_missing_input_count: $telemetry_quality_summary.missing_input_count,
        admission_budget_profile: $admission_budget_summary.budget_profile,
        admission_deferred_count: $admission_budget_summary.deferred_count,
        lease_exchange_decision: $lease_exchange_salvage_summary.decision,
        lease_exchange_candidate_count: $lease_exchange_salvage_summary.lease_exchange_candidate_count,
        salvage_promotion_candidate_count: $lease_exchange_salvage_summary.salvage_promotion_candidate_count,
        prefetch_advisory: $prefetch_roi_summary.advisory,
        prefetch_target_dir: $prefetch_roi_summary.target_dir,
        starvation_rescue_plan_decision: $starvation_rescue_summary.plan_decision,
        starvation_rescue_escalation_band: $starvation_rescue_summary.escalation_band,
        starvation_rescue_top_action: $starvation_rescue_summary.top_recommendation_action,
        starvation_rescue_unresolved_risk_count: (($starvation_rescue_summary.unresolved_risks // []) | length),
        checkpoint_restore_plan_decision: $checkpoint_restore_summary.plan_decision,
        checkpoint_restore_escalation_band: $checkpoint_restore_summary.escalation_band,
        checkpoint_restore_top_action: $checkpoint_restore_summary.top_restore_action,
        checkpoint_restore_unresolved_risk_count: (($checkpoint_restore_summary.unresolved_risks // []) | length),
        execution_queue_decision: $execution_queue_summary.decision,
        execution_queue_conservative_mode: $execution_queue_summary.conservative_mode,
        execution_queue_restore_dependency_state: $execution_queue_summary.restore_dependency_state,
        execution_queue_top_start_count: (($execution_queue_summary.top_recommended_starts // []) | length),
        execution_queue_deferred_count: (($execution_queue_summary.deferred_items // []) | length),
        execution_queue_bottleneck_count: $execution_queue_summary.bottleneck_count,
        queue_fidelity_trust_level: $queue_fidelity_summary.trust_level,
        queue_fidelity_drift_class: $queue_fidelity_summary.drift_class,
        queue_fidelity_highest_mismatch: ($queue_fidelity_summary.highest_severity_mismatch.mismatch_class // "none"),
        queue_tuning_plan_class: $queue_fidelity_summary.tuning_plan_class,
        queue_tuning_top_recommendation: ($queue_fidelity_summary.top_tuning_recommendation.candidate_id // "none"),
        queue_tuning_promotion_readiness: $queue_tuning_promotion_summary.readiness,
        queue_tuning_promotion_decision: $queue_tuning_promotion_summary.promotion_decision,
        queue_tuning_rollback_verdict: $queue_tuning_promotion_summary.rollback_verdict,
        queue_tuning_canary_action: $queue_tuning_promotion_summary.canary_recommended_action,
        queue_tuning_manual_blocker_count: $queue_tuning_promotion_summary.manual_approval_blocker_count,
        queue_tuning_evidence_link_count: $queue_tuning_promotion_summary.evidence_link_count,
        queue_policy_adoption_readiness: $queue_policy_adoption_summary.readiness,
        queue_policy_adoption_state: $queue_policy_adoption_summary.adoption_state,
        queue_policy_sustained_gain_verdict: $queue_policy_adoption_summary.sustained_gain_verdict,
        queue_policy_expiry_decision: $queue_policy_adoption_summary.expiry_decision,
        queue_policy_expiry_required: $queue_policy_adoption_summary.expiry_required,
        queue_policy_supersession_required: $queue_policy_adoption_summary.supersession_required,
        causal_trace_readiness: $causal_trace_summary.readiness,
        causal_trace_decision: $causal_trace_summary.decision,
        causal_trace_anomaly_count: $causal_trace_summary.anomaly_count,
        causal_trace_missing_edge_count: (($causal_trace_summary.missing_required_edges // []) | length),
        staged_contamination_decision: $staged_contamination_summary.decision,
        staged_contamination_offender_count: $staged_contamination_summary.offender_count
      },
      services: {
        agent_mail: $agent_mail_status,
        rch: $rch_status,
        proof_evidence_index: $proof_index_status
      },
      ready_beads: $ready_rows,
      in_progress_beads: $in_progress_rows,
      bv_tracks: ($bv_plan.plan.tracks // []),
      active_reservations: ($reservations | sort_by(.path // .path_pattern // "")),
      resource_decision: $resource_decision,
      validation_plan: {
        decision: ($validation_plan.decision // "unknown"),
        collision_risk: ($validation_plan.collision_risk // null),
        risk_flags: ($validation_plan.risk_flags // []),
        commands: ($validation_plan.commands // []),
        omitted_commands: ($validation_plan.omitted_commands // []),
        proof_cost_budgets: $proof_cost_budgets,
        conflicting_agents: ($validation_plan.conflicting_agents // []),
        safe_alternatives: ($validation_plan.safe_alternatives // [])
      },
      proof_evidence_index: $proof_index,
      proof_outcomes: ($proof_outcomes | sort_by(.bead_id // "", .artifact_id // "")),
      stale_evidence: ($stale_evidence | sort_by(.artifact_id // "")),
      dirty_files: ($dirty_files | sort_by(.path)),
      predictive_dashboard: {
        schema_version: "franken-engine.swarm-predictive-dashboard.v1",
        renderer_contract: {
          provider: "/dp/frankentui",
          shipped_in_franken_engine: false,
          local_renderer: false
        },
        predictive_cost: {
          status: (if ($high_cost_rows | length) == 0 then "nominal" else "elevated" end),
          commands: ($cost_rows | sort_by(.command_id // "")),
          high_risk_commands: ($high_cost_rows | sort_by(.command_id // "")),
          proof_cost_budgets: $proof_cost_budgets
        },
        collision_risk: $collision_summary,
        proof_freshness: $proof_freshness_summary,
        rch_incidents: {
          status: (
            if ($rch_incident_summaries | length) == 0 then "none"
            elif any($rch_incident_summaries[]; (.status // "") != "pass") then "degraded"
            else "observed"
            end
          ),
          incidents: $rch_incident_summaries
        },
        resource_leases: $resource_leases_summary,
        proof_cache: $proof_cache_summary,
        qos_batches: $qos_batches_summary,
        stale_lock_recommendations: $stale_lock_summary,
        telemetry_quality: $telemetry_quality_summary,
        capacity_forecast: $capacity_forecast_summary,
        admission_budgets: $admission_budget_summary,
        lease_exchange_salvage: $lease_exchange_salvage_summary,
        prefetch_roi: $prefetch_roi_summary,
        starvation_rescue: $starvation_rescue_summary,
        checkpoint_restore: $checkpoint_restore_summary,
        execution_queue_advisory: $execution_queue_summary,
        queue_fidelity: $queue_fidelity_summary,
        queue_tuning_promotion: $queue_tuning_promotion_summary,
        queue_policy_adoption: $queue_policy_adoption_summary,
        swarm_agent_causal_trace: $causal_trace_summary,
        staged_contamination: $staged_contamination_summary,
        fixture_contract: {
          golden_cases: ["healthy", "degraded", "stale_proof", "high_cost", "collision_risk", "overloaded", "forecast_low_confidence", "execution_queue_conservative", "execution_queue_restore_blocked", "queue_fidelity_high_drift", "queue_fidelity_insufficient_evidence", "queue_tuning_promotion_blocked", "queue_tuning_promotion_stale_evidence", "queue_tuning_promotion_rollback_required", "queue_policy_adoption_expiry_required", "queue_policy_adoption_supersession_required", "causal_trace_degraded", "causal_trace_contaminated"],
          intended_renderer_repo: "/dp/frankentui",
          local_tui_renderer: false
        }
      },
      degraded: $degraded,
      recommendations: (
        if $staged_contamination_summary.severity == "critical" then
          [recommendation("reject_staged_contamination"; null; "staged ownership guard reports contamination")]
        elif $causal_trace_summary.readiness == "contaminated" then
          [recommendation("respect_causal_trace_contamination"; $causal_trace_summary.bead_id; "causal trace handoff is contaminated by fail-closed anomaly evidence")]
        elif $causal_trace_summary.readiness == "blocked" then
          [recommendation("complete_causal_trace_edges"; $causal_trace_summary.bead_id; "in-progress causal trace is missing required handoff edges")]
        elif $checkpoint_restore_summary.severity == "critical" then
          [recommendation("respect_checkpoint_restore_fail_closed"; null; "checkpoint restore handoff is fail-closed or contradicted by conformance evidence")]
        elif $starvation_rescue_summary.severity == "critical" then
          [recommendation("respect_starvation_rescue_fail_closed"; null; "starvation rescue handoff is fail-closed or contradicted by conformance evidence")]
        elif $execution_queue_summary.restore_dependency_state == "restore_blocked" then
          [recommendation("respect_restore_before_queue"; null; "execution queue advisory reports checkpoint restore is blocked")]
        elif $execution_queue_summary.severity == "critical" then
          [recommendation("respect_execution_queue_fail_closed"; null; "execution queue advisory failed closed or has critical bottlenecks")]
        elif $queue_fidelity_summary.severity == "critical" then
          [recommendation("respect_queue_fidelity_fail_closed"; null; "queue fidelity or counterfactual tuning evidence failed closed")]
        elif $queue_tuning_promotion_summary.severity == "critical" then
          [recommendation("respect_queue_tuning_promotion_fail_closed"; null; "queue tuning promotion is rejected, rollback-required, or unsafe")]
        elif $checkpoint_restore_summary.severity == "warning" then
          [recommendation("review_checkpoint_restore_handoff"; null; "checkpoint restore handoff requires manual review before resume")]
        elif $execution_queue_summary.restore_dependency_state == "restore_manual_review" then
          [recommendation("review_restore_before_queue"; null; "execution queue advisory is secondary to checkpoint restore manual review")]
        elif $execution_queue_summary.severity == "warning" then
          [recommendation("use_execution_queue_conservatively"; null; "execution queue advisory reports conservative risk budget or degraded evidence")]
        elif $queue_fidelity_summary.severity == "warning" then
          [recommendation("review_queue_fidelity_drift"; null; "queue hindsight fidelity or counterfactual tuning evidence is degraded")]
        elif $queue_tuning_promotion_summary.severity == "warning" then
          [recommendation("review_queue_tuning_promotion"; null; "queue tuning promotion needs manual approval, fresher evidence, or canary review")]
        elif $queue_policy_adoption_summary.severity == "critical" then
          [recommendation("respect_queue_policy_adoption_fail_closed"; null; "queue policy adoption lifecycle evidence failed closed")]
        elif $queue_policy_adoption_summary.severity == "warning" then
          [recommendation("review_queue_policy_adoption_lifecycle"; null; "queue policy adoption lifecycle recommends expiry, supersession, or manual review")]
        elif $causal_trace_summary.readiness == "degraded" then
          [recommendation("review_causal_trace_handoff"; $causal_trace_summary.bead_id; "causal trace handoff is degraded but not contaminated")]
        elif $starvation_rescue_summary.severity == "warning" then
          [recommendation("review_starvation_rescue_handoff"; null; "starvation rescue handoff requires manual review or degraded coordination")]
        elif $capacity_forecast_summary.severity == "critical" then
          [recommendation("refresh_capacity_forecast"; null; "predictive capacity forecast is fail-closed or low-confidence")]
        elif $resource_leases_summary.severity == "critical" then
          [recommendation("fix_resource_lease"; null; "resource lease planner denied or failed closed")]
        elif $proof_cache_summary.severity == "critical" then
          [recommendation("fix_proof_cache"; null; "proof reuse cache planner failed closed")]
        elif $prefetch_roi_summary.severity == "critical" then
          [recommendation("respect_prefetch_fail_closed"; null; "prefetch ROI advisory failed closed")]
        elif ($dirty_reserved | length) != 0 then
          [recommendation("avoid_dirty_reserved_files"; null; "dirty or reserved files overlap active work")]
        elif ($stale_lock_summary.safe_to_reopen_count > 0) then
          [recommendation("reopen_stale_beads"; $stale_lock_summary.safe_to_reopen[0]; "stale-lock recommender reports a safe reopen candidate")]
        elif ($stale_lock_summary.contact_first_count > 0) then
          [recommendation("contact_stalled_owner"; $stale_lock_summary.contact_first[0]; "stale-lock recommender requires contact before reopening")]
        elif ($collision_summary.risk != "none") then
          [recommendation("coordinate_collision_risk"; null; "planned dashboard feed reports collision risk")]
        elif $lease_exchange_salvage_summary.severity == "warning" then
          [recommendation("review_lease_exchange_salvage"; null; "lease-exchange salvage simulation recommends coordination or manual review")]
        elif $admission_budget_summary.severity == "warning" then
          [recommendation("respect_admission_budget"; null; "admission budget planner defers or narrows queued work")]
        elif $prefetch_roi_summary.severity == "warning" then
          [recommendation("use_prefetch_roi_as_advisory"; null; "prefetch ROI advisory recommends warming only under bounded conditions")]
        elif $proof_cache_summary.severity == "warning" then
          [recommendation("refresh_or_partition_proof_cache"; null; "proof cache requires refresh or partial refresh")]
        elif $qos_batches_summary.deferred_count > 0 then
          [recommendation("respect_qos_batch_defer"; null; "QoS batch deferred lower-ranked or over-budget validation work")]
        elif $resource_leases_summary.severity == "warning" then
          [recommendation("treat_resource_lease_as_degraded"; null; "resource lease planner admitted only in degraded or deferred mode")]
        elif $staged_contamination_summary.severity == "warning" then
          [recommendation("refresh_staged_ownership_evidence"; null; "staged ownership guard is degraded or missing")]
        elif ($high_cost_rows | length) != 0 then
          [recommendation("narrow_high_cost_validation"; null; "predicted validation cost is elevated")]
        elif ((($proof_freshness_summary.state | IN("fresh", "not_provided"))
                and ($proof_freshness_summary.reusable == true or $proof_freshness_summary.reusable == null)) | not) then
          [recommendation("refresh_stale_proof"; null; "proof freshness gate reports non-reusable evidence")]
        elif (($rch_incident_summaries | map(select((.status // "") != "pass")) | length) != 0) then
          [recommendation("inspect_rch_incident_packet"; null; "rch incident packet is degraded")]
        elif ($agent_mail_status != "ok") then
          [recommendation("use_degraded_coordination"; null; "Agent Mail is not healthy")]
        elif (($resource_decision.decision // "") == "admit" or ($resource_decision.decision // "") == "admit_narrow") and ($ready_rows | length) > 0 then
          [recommendation("pick_next_ready_bead"; $ready_rows[0].id; "resource governor admits validation and bead is ready")]
        elif (($resource_decision.decision // "") == "defer") then
          [recommendation("defer_heavy_validation"; null; "resource governor reports pressure")]
        else
          [recommendation("inspect_degraded_fields"; null; "one or more required status surfaces are degraded")]
        end
      ),
      artifact_paths: {
        status_json: $status_path,
        commands_txt: $commands_path,
        report_md: $report_path,
        capacity_forecast_json: $capacity_forecast_summary.artifact_path,
        admission_budget_plan_json: $admission_budget_summary.artifact_path,
        lease_exchange_salvage_simulation_json: $lease_exchange_salvage_summary.artifact_path,
        warm_target_prefetch_roi_advisory_json: $prefetch_roi_summary.artifact_path,
        starvation_rescue_plan_json: $starvation_rescue_summary.artifact_path,
        starvation_rescue_conformance_report_json: $starvation_rescue_summary.conformance_artifact_path,
        checkpoint_bundle_json: $checkpoint_restore_summary.artifact_path,
        checkpoint_restore_plan_json: $checkpoint_restore_summary.plan_artifact_path,
        checkpoint_restore_conformance_report_json: $checkpoint_restore_summary.conformance_artifact_path,
        execution_queue_artifact_json: $execution_queue_summary.queue_artifact_path,
        execution_queue_risk_budget_json: $execution_queue_summary.risk_budget_artifact_path,
        execution_queue_bottleneck_report_json: $execution_queue_summary.bottleneck_report_artifact_path,
        execution_queue_run_manifest_json: $execution_queue_summary.run_manifest_artifact_path,
        queue_fidelity_score_receipt_json: $queue_fidelity_summary.artifact_paths.fidelity_score_receipt_json,
        queue_drift_ledger_json: $queue_fidelity_summary.artifact_paths.drift_ledger_json,
        queue_counterfactual_backtest_report_json: $queue_fidelity_summary.artifact_paths.counterfactual_backtest_report_json,
        queue_tuning_plan_json: $queue_fidelity_summary.artifact_paths.tuning_plan_json,
        queue_tuning_frontier_json: $queue_fidelity_summary.artifact_paths.frontier_json,
        queue_tuning_bundle_json: $queue_tuning_promotion_summary.artifact_paths.bundle_json,
        queue_tuning_promotion_guard_receipt_json: $queue_tuning_promotion_summary.artifact_paths.promotion_guard_receipt_json,
        queue_tuning_rollout_plan_json: $queue_tuning_promotion_summary.artifact_paths.rollout_plan_json,
        queue_tuning_rollback_comparator_receipt_json: $queue_tuning_promotion_summary.artifact_paths.rollback_comparator_receipt_json,
        queue_tuning_canary_verdict_ledger_json: $queue_tuning_promotion_summary.artifact_paths.canary_verdict_ledger_json,
        queue_policy_adoption_receipt_json: $queue_policy_adoption_summary.artifact_paths.adoption_receipt_json,
        queue_policy_adoption_snapshot_bundle_json: $queue_policy_adoption_summary.artifact_paths.adoption_snapshot_bundle_json,
        queue_policy_sustained_gain_receipt_json: $queue_policy_adoption_summary.artifact_paths.sustained_gain_receipt_json,
        queue_policy_expiry_supersession_plan_json: $queue_policy_adoption_summary.artifact_paths.expiry_supersession_plan_json,
        queue_policy_expiry_supersession_ledger_json: $queue_policy_adoption_summary.artifact_paths.expiry_supersession_ledger_json,
        swarm_agent_causal_trace_graph_json: $causal_trace_summary.artifact_paths.causal_graph_json,
        swarm_agent_causal_trace_anomaly_report_json: $causal_trace_summary.artifact_paths.anomaly_report_json
      }
    }
  ' >"$status_path"

{
  printf '# Swarm Operator Status\n\n'
  printf -- "- Status: \`%s\`\n" "$(jq -r '.status' "$status_path")"
  printf -- "- Ready beads: \`%s\`\n" "$(jq '.summary.ready_count' "$status_path")"
  printf -- "- In progress: \`%s\`\n" "$(jq '.summary.in_progress_count' "$status_path")"
  printf -- "- Degraded fields: \`%s\`\n\n" "$(jq '.summary.degraded_count' "$status_path")"
  printf -- "- Dashboard contract: \`%s\` via \`%s\`\n" "$(jq -r '.dashboard_contract.schema_version' "$status_path")" "$(jq -r '.dashboard_contract.renderer.provider' "$status_path")"
  printf -- "- Forecast confidence: \`%s\` / \`%s\`\n" "$(jq -r '.summary.forecast_confidence_band' "$status_path")" "$(jq -r '.summary.forecast_overall_state' "$status_path")"
  printf -- "- Admission budget: \`%s\` with \`%s\` deferred\n" "$(jq -r '.summary.admission_budget_profile' "$status_path")" "$(jq '.summary.admission_deferred_count' "$status_path")"
  printf -- "- Lease exchange posture: \`%s\`\n" "$(jq -r '.summary.lease_exchange_decision' "$status_path")"
  printf -- "- Prefetch advisory: \`%s\`\n" "$(jq -r '.summary.prefetch_advisory' "$status_path")"
  printf -- "- Starvation rescue escalation: \`%s\` via \`%s\`\n" "$(jq -r '.summary.starvation_rescue_escalation_band' "$status_path")" "$(jq -r '.summary.starvation_rescue_top_action' "$status_path")"
  printf -- "- Checkpoint restore escalation: \`%s\` via \`%s\`\n" "$(jq -r '.summary.checkpoint_restore_escalation_band' "$status_path")" "$(jq -r '.summary.checkpoint_restore_top_action' "$status_path")"
  printf -- "- Execution queue: \`%s\` top=\`%s\` deferred=\`%s\` restore=\`%s\`\n" "$(jq -r '.summary.execution_queue_decision' "$status_path")" "$(jq '.summary.execution_queue_top_start_count' "$status_path")" "$(jq '.summary.execution_queue_deferred_count' "$status_path")" "$(jq -r '.summary.execution_queue_restore_dependency_state' "$status_path")"
  printf -- "- Queue fidelity: trust=\`%s\` drift=\`%s\` top-mismatch=\`%s\` tuning=\`%s\`\n" "$(jq -r '.summary.queue_fidelity_trust_level' "$status_path")" "$(jq -r '.summary.queue_fidelity_drift_class' "$status_path")" "$(jq -r '.summary.queue_fidelity_highest_mismatch' "$status_path")" "$(jq -r '.summary.queue_tuning_top_recommendation' "$status_path")"
  printf -- "- Queue tuning promotion: readiness=\`%s\` decision=\`%s\` rollback=\`%s\` canary=\`%s\`\n" "$(jq -r '.summary.queue_tuning_promotion_readiness' "$status_path")" "$(jq -r '.summary.queue_tuning_promotion_decision' "$status_path")" "$(jq -r '.summary.queue_tuning_rollback_verdict' "$status_path")" "$(jq -r '.summary.queue_tuning_canary_action' "$status_path")"
  printf -- "- Queue policy adoption: readiness=\`%s\` sustained=\`%s\` expiry=\`%s\` expire=\`%s\` supersede=\`%s\`\n" "$(jq -r '.summary.queue_policy_adoption_readiness' "$status_path")" "$(jq -r '.summary.queue_policy_sustained_gain_verdict' "$status_path")" "$(jq -r '.summary.queue_policy_expiry_decision' "$status_path")" "$(jq -r '.summary.queue_policy_expiry_required' "$status_path")" "$(jq -r '.summary.queue_policy_supersession_required' "$status_path")"
  printf -- "- Causal trace: readiness=\`%s\` decision=\`%s\` anomalies=\`%s\` missing-edges=\`%s\`\n" "$(jq -r '.summary.causal_trace_readiness' "$status_path")" "$(jq -r '.summary.causal_trace_decision' "$status_path")" "$(jq '.summary.causal_trace_anomaly_count' "$status_path")" "$(jq '.summary.causal_trace_missing_edge_count' "$status_path")"
  printf -- "- High-cost commands: \`%s\`\n" "$(jq '.summary.high_cost_command_count' "$status_path")"
  printf -- "- Collision risk: \`%s\`\n" "$(jq -r '.summary.collision_risk' "$status_path")"
  printf -- "- RCH incidents: \`%s\`\n\n" "$(jq '.summary.rch_incident_count' "$status_path")"
  printf '## Artifact Sources\n\n'
  jq -r '
    [
      {label:"Capacity forecast", path:.artifact_paths.capacity_forecast_json},
      {label:"Admission budget plan", path:.artifact_paths.admission_budget_plan_json},
      {label:"Lease exchange salvage simulation", path:.artifact_paths.lease_exchange_salvage_simulation_json},
      {label:"Warm target prefetch ROI advisory", path:.artifact_paths.warm_target_prefetch_roi_advisory_json},
      {label:"Starvation rescue plan", path:.artifact_paths.starvation_rescue_plan_json},
      {label:"Starvation rescue conformance report", path:.artifact_paths.starvation_rescue_conformance_report_json},
      {label:"Checkpoint bundle", path:.artifact_paths.checkpoint_bundle_json},
      {label:"Checkpoint restore plan", path:.artifact_paths.checkpoint_restore_plan_json},
      {label:"Checkpoint restore conformance report", path:.artifact_paths.checkpoint_restore_conformance_report_json},
      {label:"Execution queue artifact", path:.artifact_paths.execution_queue_artifact_json},
      {label:"Execution queue risk budget", path:.artifact_paths.execution_queue_risk_budget_json},
      {label:"Execution queue bottleneck report", path:.artifact_paths.execution_queue_bottleneck_report_json},
      {label:"Execution queue run manifest", path:.artifact_paths.execution_queue_run_manifest_json},
      {label:"Queue fidelity score receipt", path:.artifact_paths.queue_fidelity_score_receipt_json},
      {label:"Queue drift ledger", path:.artifact_paths.queue_drift_ledger_json},
      {label:"Queue counterfactual backtest report", path:.artifact_paths.queue_counterfactual_backtest_report_json},
      {label:"Queue tuning plan", path:.artifact_paths.queue_tuning_plan_json},
      {label:"Queue tuning frontier", path:.artifact_paths.queue_tuning_frontier_json},
      {label:"Queue tuning policy bundle", path:.artifact_paths.queue_tuning_bundle_json},
      {label:"Queue tuning promotion guard receipt", path:.artifact_paths.queue_tuning_promotion_guard_receipt_json},
      {label:"Queue tuning rollout plan", path:.artifact_paths.queue_tuning_rollout_plan_json},
      {label:"Queue tuning rollback comparator receipt", path:.artifact_paths.queue_tuning_rollback_comparator_receipt_json},
      {label:"Queue tuning canary verdict ledger", path:.artifact_paths.queue_tuning_canary_verdict_ledger_json},
      {label:"Queue policy adoption receipt", path:.artifact_paths.queue_policy_adoption_receipt_json},
      {label:"Queue policy adoption snapshot bundle", path:.artifact_paths.queue_policy_adoption_snapshot_bundle_json},
      {label:"Queue policy sustained-gain receipt", path:.artifact_paths.queue_policy_sustained_gain_receipt_json},
      {label:"Queue policy expiry/supersession plan", path:.artifact_paths.queue_policy_expiry_supersession_plan_json},
      {label:"Queue policy expiry/supersession ledger", path:.artifact_paths.queue_policy_expiry_supersession_ledger_json},
      {label:"Causal trace graph", path:.artifact_paths.swarm_agent_causal_trace_graph_json},
      {label:"Causal trace anomalies", path:.artifact_paths.swarm_agent_causal_trace_anomaly_report_json}
    ][]
    | "- " + .label + ": `" + (.path // "missing") + "`"
  ' "$status_path"
  printf '\n'
  jq -r '.recommendations[] | "- `" + .action + "`" + (if .bead_id == null then "" else " for `" + .bead_id + "`" end) + ": " + .reason' "$status_path"
  if [[ "$(jq '.degraded | length' "$status_path")" -ne 0 ]]; then
    printf '\n## Degraded\n\n'
    jq -r '.degraded[] | "- `" + .component + "` `" + .status + "`: " + .impact + ". " + .remediation' "$status_path"
  fi
} >"$report_path"

printf 'swarm_operator_status_report=%s\n' "$status_path"
printf 'swarm_operator_status_markdown=%s\n' "$report_path"
