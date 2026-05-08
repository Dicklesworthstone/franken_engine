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
swarm_resource_envelope_json=""
swarm_fair_share_batch_plan_json=""
swarm_topology_placement_plan_json=""
swarm_topology_placement_receipt_json=""
swarm_topology_placement_evidence_ledger_json=""
swarm_topology_aware_queue_advisory_json=""
swarm_benchmark_workload_catalog_json=""
swarm_benchmark_responsiveness_advisory_json=""
swarm_actionability_report_json=""
swarm_capability_affinity_routing_advisory_json=""
swarm_capability_affinity_routing_outcome_ledger_json=""
swarm_control_surface_catalog_json=""
swarm_control_surface_intent_plan_json=""
swarm_control_surface_drift_report_json=""

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
  --swarm-resource-envelope-json FILE
  --swarm-fair-share-batch-plan-json FILE
  --swarm-topology-placement-plan-json FILE
  --swarm-topology-placement-receipt-json FILE
  --swarm-topology-placement-evidence-ledger-json FILE
  --swarm-topology-aware-queue-advisory-json FILE
  --swarm-benchmark-workload-catalog-json FILE
  --swarm-benchmark-responsiveness-advisory-json FILE
  --swarm-actionability-report-json FILE
  --swarm-capability-affinity-routing-advisory-json FILE
  --swarm-capability-affinity-routing-outcome-ledger-json FILE
  --swarm-control-surface-catalog-json FILE
  --swarm-control-surface-intent-plan-json FILE
  --swarm-control-surface-drift-report-json FILE
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
    --swarm-resource-envelope-json)
      swarm_resource_envelope_json="$2"
      shift 2
      ;;
    --swarm-fair-share-batch-plan-json)
      swarm_fair_share_batch_plan_json="$2"
      shift 2
      ;;
    --swarm-topology-placement-plan-json)
      swarm_topology_placement_plan_json="$2"
      shift 2
      ;;
    --swarm-topology-placement-receipt-json)
      swarm_topology_placement_receipt_json="$2"
      shift 2
      ;;
    --swarm-topology-placement-evidence-ledger-json)
      swarm_topology_placement_evidence_ledger_json="$2"
      shift 2
      ;;
    --swarm-topology-aware-queue-advisory-json)
      swarm_topology_aware_queue_advisory_json="$2"
      shift 2
      ;;
    --swarm-benchmark-workload-catalog-json)
      swarm_benchmark_workload_catalog_json="$2"
      shift 2
      ;;
    --swarm-benchmark-responsiveness-advisory-json)
      swarm_benchmark_responsiveness_advisory_json="$2"
      shift 2
      ;;
    --swarm-actionability-report-json)
      swarm_actionability_report_json="$2"
      shift 2
      ;;
    --swarm-capability-affinity-routing-advisory-json)
      swarm_capability_affinity_routing_advisory_json="$2"
      shift 2
      ;;
    --swarm-capability-affinity-routing-outcome-ledger-json)
      swarm_capability_affinity_routing_outcome_ledger_json="$2"
      shift 2
      ;;
    --swarm-control-surface-catalog-json)
      swarm_control_surface_catalog_json="$2"
      shift 2
      ;;
    --swarm-control-surface-intent-plan-json)
      swarm_control_surface_intent_plan_json="$2"
      shift 2
      ;;
    --swarm-control-surface-drift-report-json)
      swarm_control_surface_drift_report_json="$2"
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
swarm_resource_envelope_status="missing"
swarm_fair_share_batch_plan_status="missing"
swarm_topology_placement_plan_status="missing"
swarm_topology_placement_receipt_status="missing"
swarm_topology_placement_evidence_ledger_status="missing"
swarm_benchmark_workload_catalog_status="missing"
swarm_benchmark_responsiveness_advisory_status="missing"
swarm_capability_affinity_routing_advisory_status="missing"
swarm_capability_affinity_routing_outcome_ledger_status="missing"
swarm_actionability_report_status="missing"
swarm_control_surface_catalog_status="missing"
swarm_control_surface_intent_plan_status="missing"
swarm_control_surface_drift_report_status="missing"
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
if [[ -n "$swarm_resource_envelope_json" ]]; then swarm_resource_envelope_status="provided"; fi
if [[ -n "$swarm_fair_share_batch_plan_json" ]]; then swarm_fair_share_batch_plan_status="provided"; fi
if [[ -n "$swarm_topology_placement_plan_json" ]]; then swarm_topology_placement_plan_status="provided"; fi
if [[ -n "$swarm_topology_placement_receipt_json" ]]; then swarm_topology_placement_receipt_status="provided"; fi
if [[ -n "$swarm_topology_placement_evidence_ledger_json" ]]; then swarm_topology_placement_evidence_ledger_status="provided"; fi
if [[ -n "$swarm_topology_aware_queue_advisory_json" ]]; then swarm_topology_aware_queue_advisory_status="provided"; else swarm_topology_aware_queue_advisory_status="missing"; fi
if [[ -n "$swarm_benchmark_workload_catalog_json" ]]; then swarm_benchmark_workload_catalog_status="provided"; fi
if [[ -n "$swarm_benchmark_responsiveness_advisory_json" ]]; then swarm_benchmark_responsiveness_advisory_status="provided"; fi
if [[ -n "$swarm_actionability_report_json" ]]; then swarm_actionability_report_status="provided"; fi
if [[ -n "$swarm_capability_affinity_routing_advisory_json" ]]; then swarm_capability_affinity_routing_advisory_status="provided"; fi
if [[ -n "$swarm_capability_affinity_routing_outcome_ledger_json" ]]; then swarm_capability_affinity_routing_outcome_ledger_status="provided"; fi
if [[ -n "$swarm_control_surface_catalog_json" ]]; then swarm_control_surface_catalog_status="provided"; fi
if [[ -n "$swarm_control_surface_intent_plan_json" ]]; then swarm_control_surface_intent_plan_status="provided"; fi
if [[ -n "$swarm_control_surface_drift_report_json" ]]; then swarm_control_surface_drift_report_status="provided"; fi
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
swarm_resource_envelope_data="$(json_or_default "$swarm_resource_envelope_json" '{"schema_version":"franken-engine.swarm-resource-envelope.v1","decision":"missing","readiness":"missing","host_identity":{},"cpu_topology":{},"memory_pressure":{},"target_dir_pressure":{},"rch_slots":{},"capacity_budget":{"script_lane_limit":0,"proof_lane_limit":0,"build_lane_limit":0,"remote_rch_slot_limit":0,"memory_bytes_budget":0,"target_dir_bytes_budget":0,"defer_reasons":[]},"degraded_reasons":[],"blocked_reasons":[],"fail_closed_reasons":[],"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false}}' 'swarm-resource-envelope')"
swarm_fair_share_batch_plan_data="$(json_or_default "$swarm_fair_share_batch_plan_json" '{"schema_version":"franken-engine.swarm-fair-share-batch-plan.v1","decision":"missing","summary":{"requested_count":0,"admitted_count":0,"deferred_count":0,"heavy_admitted_count":0,"heavy_lane_limit":0,"remote_rch_slot_limit":0,"rch_slots_used":0,"contaminated_input":false},"admitted_lanes":[],"deferred_lanes":[],"fairness_rationale":[],"fail_closed_reasons":[],"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false}}' 'swarm-fair-share-batch-plan')"
swarm_topology_placement_plan_data="$(json_or_default "$swarm_topology_placement_plan_json" '{"schema_version":"franken-engine.swarm-topology-placement-plan.v1","decision":"missing","placement_readiness":"missing","recommended_topology_class":"missing","recommended_worker_targets":[],"warm_cache_residency_state":"missing","warm_cache_opportunities":[],"degraded_reasons":[],"blocked_reasons":[],"fail_closed_reasons":[],"locality_assumptions":[],"summary":{"target_count":0,"warm_cache_opportunity_count":0,"heavy_target_count":0,"latency_sensitive_target_count":0},"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"proof_only":true,"advisory_only":true,"mutates_br":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false,"pins_workers_automatically":false,"rebinds_hosts_automatically":false,"repairs_target_dirs_automatically":false}}' 'swarm-topology-placement-plan')"
swarm_topology_placement_receipt_data="$(json_or_default "$swarm_topology_placement_receipt_json" '{"schema_version":"franken-engine.swarm-topology-placement-receipt.v1","decision":"missing","adoption_status":"missing","recommended_placement_targets":[],"recommended_worker_ids":[],"topology_locality_assumptions":[],"cache_warmth_assumptions":{"state":"missing","opportunities":[]},"validity_window":{},"degraded_reasons":[],"blocked_reasons":[],"fail_closed_reasons":[],"adoption_drift_reason_codes":[],"adoption_drift_reasons":[],"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"proof_only":true,"advisory_only":true,"mutates_br":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false,"pins_workers_automatically":false,"rebinds_hosts_automatically":false,"enforces_placement_automatically":false}}' 'swarm-topology-placement-receipt')"
swarm_topology_placement_evidence_ledger_data="$(json_or_default "$swarm_topology_placement_evidence_ledger_json" '{"schema_version":"franken-engine.swarm-topology-placement-evidence-ledger.v1","decision":"missing","receipts":[],"adoption_history":[],"summary":{"receipt_count":0,"adopted_count":0,"drifted_count":0,"expired_count":0,"blocked_count":0,"fail_closed_count":0},"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"proof_only":true,"advisory_only":true,"mutates_br":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false,"pins_workers_automatically":false,"rebinds_hosts_automatically":false,"enforces_placement_automatically":false}}' 'swarm-topology-placement-evidence-ledger')"
swarm_topology_aware_queue_advisory_data="$(json_or_default "$swarm_topology_aware_queue_advisory_json" '{"schema_version":"franken-engine.swarm-topology-aware-queue-advisory.v1","decision":"missing","truth_state":"missing","reason_codes":[],"worker_exclusions":{"excluded_worker_ids":[],"excluded_worker_count":0},"locality_bias_summary":{"rank_bias_mode":"missing","usable_preferred_worker_ids":[],"preferred_worker_ids":[],"preferred_numa_nodes":[],"hot_cache_reuse_confidence_millionths":0,"locality_confidence_millionths":0},"risk_budget_summary":{"task_count":0,"queue_row_count":0,"bottleneck_count":0,"critical_bottleneck_count":0,"proof_transport_state":"missing"},"feedback_summary":{"locality_outcome_sample_count":0,"confirmed_task_ids":[],"missed_cache_reuse_task_ids":[],"drift_task_ids":[],"contamination_task_ids":[]},"degraded_reasons":[],"blocked_reasons":[],"fail_closed_reasons":[],"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"proof_only":true,"advisory_only":true,"mutates_br":false,"reassigns_beads":false,"releases_reservations":false,"sends_agent_mail":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false,"pins_workers_automatically":false}}' 'swarm-topology-aware-queue-advisory')"
swarm_benchmark_workload_catalog_data="$(json_or_default "$swarm_benchmark_workload_catalog_json" '{"schema_version":"franken-engine.swarm-benchmark-workload-catalog.v1","decision":"missing","workloads":[],"findings":[],"artifact_paths":{},"mutation_policy":{"advisory_only":true,"mutates_br":false,"runs_cargo":false,"runs_rch":false}}' 'swarm-benchmark-workload-catalog')"
swarm_benchmark_responsiveness_advisory_data="$(json_or_default "$swarm_benchmark_responsiveness_advisory_json" '{"schema_version":"franken-engine.swarm-benchmark-responsiveness-advisory.v1","decision":"missing","truth_state":"missing","throughput_gap_band":"unknown","utilization_pressure_band":"unknown","cold_warm_cache_recommendation":"insufficient_cache_evidence","remote_proof_confidence_state":"missing","bottleneck_classes":[],"advisory_commands":[],"degraded_reasons":[],"fail_closed_reasons":[],"artifact_paths":{},"mutation_policy":{"advisory_only":true,"proof_only":true,"fixture_fed_only":true,"mutates_br":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false}}' 'swarm-benchmark-responsiveness-advisory')"
swarm_actionability_report_data="$(json_or_default "$swarm_actionability_report_json" '{"schema_version":"franken-engine.swarm-actionability-truth-gate.v1","decision":"missing","primary_candidate_id":null,"candidate_summary":{"candidate_count":0,"ready_count":0,"in_progress_count":0,"blocked_count":0,"reservation_count":0,"dirty_overlap_count":0},"candidate_reports":[],"fail_closed_reasons":[],"remediation_commands":[],"source_freshness":{"db_newer":false,"all_sources_fresh":true,"missing_optional_sources":[]},"artifact_paths":{},"mutation_policy":{"advisory_only":true,"proof_only":true,"mutates_br":false,"claims_beads":false,"reopens_beads":false,"closes_beads":false,"reassigns_beads":false,"releases_reservations":false,"sends_agent_mail":false,"mutates_git":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false}}' 'swarm-actionability-report')"
swarm_capability_affinity_routing_advisory_data="$(json_or_default "$swarm_capability_affinity_routing_advisory_json" '{"schema_version":"franken-engine.capability-affinity-queue-routing-advisory.v1","decision":"missing","truth_state":"missing","reason_codes":[],"worker_affinity_summary":{"task_count":0,"routing_mode":"missing","recommended_topology_class":"missing","preferred_worker_ids":[],"advised_worker_ids":[],"excluded_worker_ids":[],"watch_worker_ids":[],"rehab_candidate_worker_ids":[],"broader_fallback_task_ids":[],"preferred_cohort_score":{"capability_coverage_score":0,"toolchain_parity_score":0,"locality_compatibility_score":0,"rehabilitation_exclusion_score":0,"total_score":0},"advisory_cohort_score":{"capability_coverage_score":0,"toolchain_parity_score":0,"locality_compatibility_score":0,"rehabilitation_exclusion_score":0,"total_score":0},"confidence_score":0},"capability_coverage_summary":{"required_capabilities":[],"coverage_confirmed_task_ids":[],"missing_required_capability_task_ids":[],"score":0},"toolchain_parity_summary":{"required_toolchain_fingerprints":[],"toolchain_mismatch_task_ids":[],"score":0},"supporting_evidence_summary":{"routing_outcome_samples_present":false,"routing_outcome_sample_count":0},"degraded_reasons":[],"blocked_reasons":[],"fail_closed_reasons":[],"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"proof_only":true,"advisory_only":true,"mutates_br":false,"reassigns_beads":false,"releases_reservations":false,"sends_agent_mail":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false,"reroutes_tasks_automatically":false}}' 'swarm-capability-affinity-routing-advisory')"
swarm_capability_affinity_routing_outcome_ledger_data="$(json_or_default "$swarm_capability_affinity_routing_outcome_ledger_json" '{"schema_version":"franken-engine.swarm-capability-affinity-routing-outcome-ledger.v1","decision":"missing","truth_state":"missing","routing_mode":"missing","reason_codes":[],"planned_advised_worker_ids":[],"upstream_missing_required_capability_task_ids":[],"upstream_toolchain_mismatch_task_ids":[],"matched_task_ids":[],"mismatched_task_ids":[],"capability_gap_task_ids":[],"toolchain_drift_task_ids":[],"contamination_task_ids":[],"degraded_reasons":[],"blocked_reasons":[],"fail_closed_reasons":[],"task_outcomes":[],"artifact_paths":{},"mutation_policy":{"fixture_fed_only":true,"proof_only":true,"advisory_only":true,"mutates_br":false,"reassigns_beads":false,"releases_reservations":false,"sends_agent_mail":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false,"reroutes_tasks_automatically":false}}' 'swarm-capability-affinity-routing-outcome-ledger')"
swarm_control_surface_catalog_data="$(json_or_default "$swarm_control_surface_catalog_json" '{"schema_version":"franken-engine.swarm-control-surface-catalog.v1","decision":"missing","surface_count":0,"fail_closed_count":0,"degraded_count":0,"surfaces":[],"findings":[],"artifact_paths":{},"mutation_policy":{"advisory_only":true,"proof_only":true,"fixture_fed_only":true,"mutates_br":false,"sends_agent_mail":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false}}' 'swarm-control-surface-catalog')"
swarm_control_surface_intent_plan_data="$(json_or_default "$swarm_control_surface_intent_plan_json" '{"schema_version":"franken-engine.swarm-control-surface-intent-plan.v1","decision":"missing","recommendations":[],"advisory_commands":[],"artifacts_to_preserve":[],"blocked_reasons":[],"degraded_reasons":[],"fail_closed_reasons":[],"fail_closed_count":0,"duplicate_new_work_warnings":[],"artifact_paths":{},"mutation_policy":{"advisory_only":true,"proof_only":true,"fixture_fed_only":true,"mutates_br":false,"sends_agent_mail":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false}}' 'swarm-control-surface-intent-plan')"
swarm_control_surface_drift_report_data="$(json_or_default "$swarm_control_surface_drift_report_json" '{"schema_version":"franken-engine.swarm-control-surface-drift-report.v1","decision":"missing","fail_closed_count":0,"findings":[],"remediation_commands":[],"artifact_paths":{},"mutation_policy":{"advisory_only":true,"proof_only":true,"fixture_fed_only":true,"mutates_br":false,"sends_agent_mail":false,"runs_cargo":false,"runs_rch":false,"mutates_remote_workers":false,"changes_live_queue_policy":false}}' 'swarm-control-surface-drift-report')"
inputs_bundle_path="${run_dir}/inputs.bundle.json"
{
  printf '{\n'
  printf '"ready":%s,\n' "$ready_data"
  printf '"in_progress":%s,\n' "$in_progress_data"
  printf '"bv_plan":%s,\n' "$bv_plan_data"
  printf '"reservations":%s,\n' "$reservations_data"
  printf '"resource_decision":%s,\n' "$resource_decision_data"
  printf '"validation_plan":%s,\n' "$validation_plan_data"
  printf '"proof_index":%s,\n' "$proof_index_data"
  printf '"proof_outcomes":%s,\n' "$proof_outcomes_data"
  printf '"stale_evidence":%s,\n' "$stale_evidence_data"
  printf '"dirty_files":%s,\n' "$dirty_files_data"
  printf '"collision_receipt":%s,\n' "$collision_receipt_data"
  printf '"proof_freshness":%s,\n' "$proof_freshness_data"
  printf '"rch_incident_packet":%s,\n' "$rch_incident_packet_data"
  printf '"resource_lease_plan":%s,\n' "$resource_lease_plan_data"
  printf '"proof_cache_plan":%s,\n' "$proof_cache_plan_data"
  printf '"qos_batch_plan":%s,\n' "$qos_batch_plan_data"
  printf '"stale_lock_recommendations":%s,\n' "$stale_lock_recommendations_data"
  printf '"staged_ownership_report":%s,\n' "$staged_ownership_report_data"
  printf '"capacity_forecast":%s,\n' "$capacity_forecast_data"
  printf '"admission_budget_plan":%s,\n' "$admission_budget_plan_data"
  printf '"lease_exchange_salvage_simulation":%s,\n' "$lease_exchange_salvage_simulation_data"
  printf '"warm_target_prefetch_roi_advisory":%s,\n' "$warm_target_prefetch_roi_advisory_data"
  printf '"starvation_rescue_plan":%s,\n' "$starvation_rescue_plan_data"
  printf '"starvation_rescue_conformance_report":%s,\n' "$starvation_rescue_conformance_report_data"
  printf '"checkpoint_bundle":%s,\n' "$checkpoint_bundle_data"
  printf '"checkpoint_restore_plan":%s,\n' "$checkpoint_restore_plan_data"
  printf '"checkpoint_restore_conformance_report":%s,\n' "$checkpoint_restore_conformance_report_data"
  printf '"execution_queue_artifact":%s,\n' "$execution_queue_artifact_data"
  printf '"execution_queue_risk_budget":%s,\n' "$execution_queue_risk_budget_data"
  printf '"execution_queue_bottleneck_report":%s,\n' "$execution_queue_bottleneck_report_data"
  printf '"execution_queue_run_manifest":%s,\n' "$execution_queue_run_manifest_data"
  printf '"queue_fidelity_score_receipt":%s,\n' "$queue_fidelity_score_receipt_data"
  printf '"queue_drift_ledger":%s,\n' "$queue_drift_ledger_data"
  printf '"queue_counterfactual_backtest_report":%s,\n' "$queue_counterfactual_backtest_report_data"
  printf '"queue_tuning_plan":%s,\n' "$queue_tuning_plan_data"
  printf '"queue_tuning_frontier":%s,\n' "$queue_tuning_frontier_data"
  printf '"queue_tuning_bundle":%s,\n' "$queue_tuning_bundle_data"
  printf '"queue_tuning_promotion_guard_receipt":%s,\n' "$queue_tuning_promotion_guard_receipt_data"
  printf '"queue_tuning_rollout_plan":%s,\n' "$queue_tuning_rollout_plan_data"
  printf '"queue_tuning_rollback_comparator_receipt":%s,\n' "$queue_tuning_rollback_comparator_receipt_data"
  printf '"queue_tuning_canary_verdict_ledger":%s,\n' "$queue_tuning_canary_verdict_ledger_data"
  printf '"queue_policy_adoption_receipt":%s,\n' "$queue_policy_adoption_receipt_data"
  printf '"queue_policy_adoption_snapshot_bundle":%s,\n' "$queue_policy_adoption_snapshot_bundle_data"
  printf '"queue_policy_sustained_gain_receipt":%s,\n' "$queue_policy_sustained_gain_receipt_data"
  printf '"queue_policy_expiry_supersession_plan":%s,\n' "$queue_policy_expiry_supersession_plan_data"
  printf '"queue_policy_expiry_supersession_ledger":%s,\n' "$queue_policy_expiry_supersession_ledger_data"
  printf '"swarm_agent_causal_trace_graph":%s,\n' "$swarm_agent_causal_trace_graph_data"
  printf '"swarm_agent_causal_trace_anomaly_report":%s,\n' "$swarm_agent_causal_trace_anomaly_report_data"
  printf '"swarm_resource_envelope":%s,\n' "$swarm_resource_envelope_data"
  printf '"swarm_fair_share_batch_plan":%s,\n' "$swarm_fair_share_batch_plan_data"
  printf '"swarm_topology_placement_plan":%s,\n' "$swarm_topology_placement_plan_data"
  printf '"swarm_topology_placement_receipt":%s,\n' "$swarm_topology_placement_receipt_data"
  printf '"swarm_topology_placement_evidence_ledger":%s,\n' "$swarm_topology_placement_evidence_ledger_data"
  printf '"swarm_topology_aware_queue_advisory":%s,\n' "$swarm_topology_aware_queue_advisory_data"
  printf '"swarm_benchmark_workload_catalog":%s,\n' "$swarm_benchmark_workload_catalog_data"
  printf '"swarm_benchmark_responsiveness_advisory":%s,\n' "$swarm_benchmark_responsiveness_advisory_data"
  printf '"swarm_actionability_report":%s,\n' "$swarm_actionability_report_data"
  printf '"swarm_capability_affinity_routing_advisory":%s,\n' "$swarm_capability_affinity_routing_advisory_data"
  printf '"swarm_capability_affinity_routing_outcome_ledger":%s,\n' "$swarm_capability_affinity_routing_outcome_ledger_data"
  printf '"swarm_control_surface_catalog":%s,\n' "$swarm_control_surface_catalog_data"
  printf '"swarm_control_surface_intent_plan":%s,\n' "$swarm_control_surface_intent_plan_data"
  printf '"swarm_control_surface_drift_report":%s\n' "$swarm_control_surface_drift_report_data"
  printf '}\n'
} >"$inputs_bundle_path"

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
  --arg swarm_resource_envelope_status "$swarm_resource_envelope_status" \
  --arg swarm_fair_share_batch_plan_status "$swarm_fair_share_batch_plan_status" \
  --arg swarm_topology_placement_plan_status "$swarm_topology_placement_plan_status" \
  --arg swarm_topology_placement_receipt_status "$swarm_topology_placement_receipt_status" \
  --arg swarm_topology_placement_evidence_ledger_status "$swarm_topology_placement_evidence_ledger_status" \
  --arg swarm_topology_aware_queue_advisory_status "$swarm_topology_aware_queue_advisory_status" \
  --arg swarm_benchmark_workload_catalog_status "$swarm_benchmark_workload_catalog_status" \
  --arg swarm_benchmark_responsiveness_advisory_status "$swarm_benchmark_responsiveness_advisory_status" \
  --arg swarm_actionability_report_status "$swarm_actionability_report_status" \
  --arg swarm_capability_affinity_routing_advisory_status "$swarm_capability_affinity_routing_advisory_status" \
  --arg swarm_capability_affinity_routing_outcome_ledger_status "$swarm_capability_affinity_routing_outcome_ledger_status" \
  --arg swarm_control_surface_catalog_status "$swarm_control_surface_catalog_status" \
  --arg swarm_control_surface_intent_plan_status "$swarm_control_surface_intent_plan_status" \
  --arg swarm_control_surface_drift_report_status "$swarm_control_surface_drift_report_status" \
  --arg swarm_resource_envelope_json "$swarm_resource_envelope_json" \
  --arg swarm_fair_share_batch_plan_json "$swarm_fair_share_batch_plan_json" \
  --arg swarm_topology_placement_plan_json "$swarm_topology_placement_plan_json" \
  --arg swarm_topology_placement_receipt_json "$swarm_topology_placement_receipt_json" \
  --arg swarm_topology_placement_evidence_ledger_json "$swarm_topology_placement_evidence_ledger_json" \
  --arg swarm_topology_aware_queue_advisory_json "$swarm_topology_aware_queue_advisory_json" \
  --arg swarm_benchmark_workload_catalog_json "$swarm_benchmark_workload_catalog_json" \
  --arg swarm_benchmark_responsiveness_advisory_json "$swarm_benchmark_responsiveness_advisory_json" \
  --arg swarm_actionability_report_json "$swarm_actionability_report_json" \
  --arg swarm_capability_affinity_routing_advisory_json "$swarm_capability_affinity_routing_advisory_json" \
  --arg swarm_capability_affinity_routing_outcome_ledger_json "$swarm_capability_affinity_routing_outcome_ledger_json" \
  --arg swarm_control_surface_catalog_json "$swarm_control_surface_catalog_json" \
  --arg swarm_control_surface_intent_plan_json "$swarm_control_surface_intent_plan_json" \
  --arg swarm_control_surface_drift_report_json "$swarm_control_surface_drift_report_json" \
  --arg status_path "$status_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile inputs "$inputs_bundle_path" \
  -f /dev/stdin >"$status_path" <<'JQ'
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
  def as_array($items):
    if $items == null then []
    elif ($items | type) == "array" then $items
    else [$items]
    end;
  def tag_labels($items):
    bounded(as_array($items)
      | map(if (type == "object") then (.purpose // .surface_id // .tag // empty) else . end)
      | map(if (type == "string" or type == "number" or type == "boolean") then tostring else empty end)
      | map(select(length > 0))
      | unique);
  def reason_code: (.code // .reason_code // .finding_code // "unknown") | tostring;
  def mismatch_severity_rank($class):
    if ($class // "") | IN("contradictory_evidence", "missing_outcome") then 50
    elif ($class // "") == "proof_brownout_miss" then 40
    elif ($class // "") == "stale_owner_miss" then 30
    elif ($class // "") | IN("over_conservative", "conservative_but_correct") then 20
    elif ($class // "") == "exact_match" then 0
    else 10
    end;

  ($inputs[0]) as $input
  | $input.ready as $ready
  | $input.in_progress as $in_progress
  | $input.bv_plan as $bv_plan
  | $input.reservations as $reservations
  | $input.resource_decision as $resource_decision
  | $input.validation_plan as $validation_plan
  | $input.proof_index as $proof_index
  | $input.proof_outcomes as $proof_outcomes
  | $input.stale_evidence as $stale_evidence
  | $input.dirty_files as $dirty_files
  | $input.collision_receipt as $collision_receipt
  | $input.proof_freshness as $proof_freshness
  | $input.rch_incident_packet as $rch_incident_packet
  | $input.resource_lease_plan as $resource_lease_plan
  | $input.proof_cache_plan as $proof_cache_plan
  | $input.qos_batch_plan as $qos_batch_plan
  | $input.stale_lock_recommendations as $stale_lock_recommendations
  | $input.staged_ownership_report as $staged_ownership_report
  | $input.capacity_forecast as $capacity_forecast
  | $input.admission_budget_plan as $admission_budget_plan
  | $input.lease_exchange_salvage_simulation as $lease_exchange_salvage_simulation
  | $input.warm_target_prefetch_roi_advisory as $warm_target_prefetch_roi_advisory
  | $input.starvation_rescue_plan as $starvation_rescue_plan
  | $input.starvation_rescue_conformance_report as $starvation_rescue_conformance_report
  | $input.checkpoint_bundle as $checkpoint_bundle
  | $input.checkpoint_restore_plan as $checkpoint_restore_plan
  | $input.checkpoint_restore_conformance_report as $checkpoint_restore_conformance_report
  | $input.execution_queue_artifact as $execution_queue_artifact
  | $input.execution_queue_risk_budget as $execution_queue_risk_budget
  | $input.execution_queue_bottleneck_report as $execution_queue_bottleneck_report
  | $input.execution_queue_run_manifest as $execution_queue_run_manifest
  | $input.queue_fidelity_score_receipt as $queue_fidelity_score_receipt
  | $input.queue_drift_ledger as $queue_drift_ledger
  | $input.queue_counterfactual_backtest_report as $queue_counterfactual_backtest_report
  | $input.queue_tuning_plan as $queue_tuning_plan
  | $input.queue_tuning_frontier as $queue_tuning_frontier
  | $input.queue_tuning_bundle as $queue_tuning_bundle
  | $input.queue_tuning_promotion_guard_receipt as $queue_tuning_promotion_guard_receipt
  | $input.queue_tuning_rollout_plan as $queue_tuning_rollout_plan
  | $input.queue_tuning_rollback_comparator_receipt as $queue_tuning_rollback_comparator_receipt
  | $input.queue_tuning_canary_verdict_ledger as $queue_tuning_canary_verdict_ledger
  | $input.queue_policy_adoption_receipt as $queue_policy_adoption_receipt
  | $input.queue_policy_adoption_snapshot_bundle as $queue_policy_adoption_snapshot_bundle
  | $input.queue_policy_sustained_gain_receipt as $queue_policy_sustained_gain_receipt
  | $input.queue_policy_expiry_supersession_plan as $queue_policy_expiry_supersession_plan
  | $input.queue_policy_expiry_supersession_ledger as $queue_policy_expiry_supersession_ledger
  | $input.swarm_agent_causal_trace_graph as $swarm_agent_causal_trace_graph
  | $input.swarm_agent_causal_trace_anomaly_report as $swarm_agent_causal_trace_anomaly_report
  | $input.swarm_resource_envelope as $swarm_resource_envelope
  | $input.swarm_fair_share_batch_plan as $swarm_fair_share_batch_plan
  | $input.swarm_topology_placement_plan as $swarm_topology_placement_plan
  | $input.swarm_topology_placement_receipt as $swarm_topology_placement_receipt
  | $input.swarm_topology_placement_evidence_ledger as $swarm_topology_placement_evidence_ledger
  | $input.swarm_topology_aware_queue_advisory as $swarm_topology_aware_queue_advisory
  | $input.swarm_benchmark_workload_catalog as $swarm_benchmark_workload_catalog
  | $input.swarm_benchmark_responsiveness_advisory as $swarm_benchmark_responsiveness_advisory
  | $input.swarm_actionability_report as $swarm_actionability_report
  | $input.swarm_capability_affinity_routing_advisory as $swarm_capability_affinity_routing_advisory
  | $input.swarm_capability_affinity_routing_outcome_ledger as $swarm_capability_affinity_routing_outcome_ledger
  | $input.swarm_control_surface_catalog as $swarm_control_surface_catalog
  | $input.swarm_control_surface_intent_plan as $swarm_control_surface_intent_plan
  | $input.swarm_control_surface_drift_report as $swarm_control_surface_drift_report
  | ($ready | map(bead_row) | sort_by(.priority // 999, .id)) as $ready_rows
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
  | (($swarm_resource_envelope.fail_closed_reasons // []) | map(.code // .kind // .)) as $resource_envelope_fail_classes
  | (($swarm_fair_share_batch_plan.fail_closed_reasons // []) | map(.code // .kind // .)) as $fair_share_fail_classes
  | (($resource_envelope_fail_classes + $fair_share_fail_classes)
      | map(select(. == "rch_local_fallback_contaminates_capacity"
          or . == "rch_slot_snapshot_contradiction"
          or . == "contradictory_cpu_or_memory_capacity"
          or . == "causal_trace_contamination_blocks_admission"
          or . == "heavy_command_missing_budget"
          or . == "unsafe_live_mutation_claim"
          or . == "contaminated_resource_envelope"
          or . == "local_rch_fallback_contamination"
          or . == "causal_trace_contamination"
          or . == "unsafe_auto_run_claim"))
      | unique | sort) as $resource_envelope_contaminating_classes
  | ({
      artifact_statuses: {
        resource_envelope: $swarm_resource_envelope_status,
        fair_share_batch_plan: $swarm_fair_share_batch_plan_status
      },
      readiness: (
        if (($resource_envelope_contaminating_classes | length) > 0)
          or (($swarm_resource_envelope.decision // "") == "fail_closed")
          or (($swarm_fair_share_batch_plan.decision // "") == "fail_closed") then "contaminated"
        elif (($swarm_resource_envelope.decision // "") == "blocked")
          or (($swarm_resource_envelope.readiness // "") == "defer")
          or (($swarm_fair_share_batch_plan.decision // "") == "defer") then "blocked"
        elif $swarm_resource_envelope_status == "missing"
          or $swarm_fair_share_batch_plan_status == "missing"
          or (($swarm_resource_envelope.decision // "") == "degraded") then "degraded"
        else "ready"
        end
      ),
      severity: (
        if (($resource_envelope_contaminating_classes | length) > 0)
          or (($swarm_resource_envelope.decision // "") == "fail_closed")
          or (($swarm_fair_share_batch_plan.decision // "") == "fail_closed") then "critical"
        elif $swarm_resource_envelope_status == "missing"
          or $swarm_fair_share_batch_plan_status == "missing"
          or (($swarm_resource_envelope.decision // "") | IN("blocked", "degraded"))
          or (($swarm_fair_share_batch_plan.decision // "") == "defer") then "warning"
        else "ok"
        end
      ),
      decision: ($swarm_resource_envelope.decision // "missing"),
      fair_share_decision: ($swarm_fair_share_batch_plan.decision // "missing"),
      host_id: ($swarm_resource_envelope.host_identity.host_id // null),
      capacity_budget: ($swarm_resource_envelope.capacity_budget // {}),
      capacity: {
        script_lane_limit: ($swarm_resource_envelope.capacity_budget.script_lane_limit // 0),
        proof_lane_limit: ($swarm_resource_envelope.capacity_budget.proof_lane_limit // 0),
        build_lane_limit: ($swarm_resource_envelope.capacity_budget.build_lane_limit // 0),
        remote_rch_slot_limit: ($swarm_resource_envelope.capacity_budget.remote_rch_slot_limit // 0),
        memory_bytes_budget: ($swarm_resource_envelope.capacity_budget.memory_bytes_budget // 0),
        target_dir_bytes_budget: ($swarm_resource_envelope.capacity_budget.target_dir_bytes_budget // 0),
        rch_slots_available: ($swarm_resource_envelope.rch_slots.available // 0),
        target_dir_min_available_bytes: ($swarm_resource_envelope.target_dir_pressure.min_available_bytes // 0)
      },
      fair_share: {
        requested_count: ($swarm_fair_share_batch_plan.summary.requested_count // 0),
        admitted_count: ($swarm_fair_share_batch_plan.summary.admitted_count // (($swarm_fair_share_batch_plan.admitted_lanes // []) | length)),
        deferred_count: ($swarm_fair_share_batch_plan.summary.deferred_count // (($swarm_fair_share_batch_plan.deferred_lanes // []) | length)),
        heavy_admitted_count: ($swarm_fair_share_batch_plan.summary.heavy_admitted_count // 0),
        rch_slots_used: ($swarm_fair_share_batch_plan.summary.rch_slots_used // 0),
        fairness_rationale: ($swarm_fair_share_batch_plan.fairness_rationale // [])
      },
      contaminating_classes: $resource_envelope_contaminating_classes,
      degraded_reason_count: (($swarm_resource_envelope.degraded_reasons // []) | length),
      blocked_reason_count: (($swarm_resource_envelope.blocked_reasons // []) | length),
      fail_closed_reason_count: (($swarm_resource_envelope.fail_closed_reasons // []) | length),
      artifact_paths: {
        resource_envelope_json: ($swarm_resource_envelope.artifact_paths.envelope_json // $swarm_resource_envelope_json),
        fair_share_batch_plan_json: ($swarm_fair_share_batch_plan.artifact_paths.swarm_fair_share_batch_plan_json // $swarm_fair_share_batch_plan_json)
      }
    }) as $resource_envelope_summary
  | ([
        $swarm_topology_placement_plan.mutation_policy,
        $swarm_topology_placement_receipt.mutation_policy,
        $swarm_topology_placement_evidence_ledger.mutation_policy
      ]
      | map(select(. != null))
      | any(.[]; (.advisory_only != true)
          or (.mutates_br == true)
          or (.reassigns_beads == true)
          or (.releases_reservations == true)
          or (.sends_agent_mail == true)
          or (.queries_live_agent_mail == true)
          or (.runs_cargo == true)
          or (.runs_rch == true)
          or (.mutates_remote_workers == true)
          or (.changes_live_queue_policy == true)
          or (.pins_workers_automatically == true)
          or (.rebinds_hosts_automatically == true)
          or (.repairs_target_dirs_automatically == true)
          or (.enforces_placement_automatically == true))) as $topology_placement_unsafe_mutation_claim
  | ((($swarm_topology_placement_plan.fail_closed_reasons // [])
      + ($swarm_topology_placement_receipt.fail_closed_reasons // [])
      + (($swarm_topology_placement_evidence_ledger.receipts // []) | map(.fail_closed_reasons // []) | add // []))
      | unique_by([.code, .source_id, .detail])) as $topology_placement_fail_reasons
  | ((($swarm_topology_placement_plan.blocked_reasons // [])
      + ($swarm_topology_placement_receipt.blocked_reasons // [])
      + (($swarm_topology_placement_evidence_ledger.receipts // []) | map(.blocked_reasons // []) | add // []))
      | unique_by([.code, .source_id, .detail])) as $topology_placement_blocked_reasons
  | ((($swarm_topology_placement_plan.degraded_reasons // [])
      + ($swarm_topology_placement_receipt.degraded_reasons // [])
      + (($swarm_topology_placement_evidence_ledger.receipts // []) | map(.degraded_reasons // []) | add // [])
      + (($swarm_topology_placement_receipt.adoption_drift_reasons // []) | map(select((.code // "") != "adopted_recommended_target" and (.code // "") != "cache_reuse_confirmed" and (.code // "") != "cache_cold_no_reuse_claim"))))
      | unique_by([.code, .source_id, .detail])) as $topology_placement_warning_reasons
  | ({
      artifact_statuses: {
        placement_plan: $swarm_topology_placement_plan_status,
        placement_receipt: $swarm_topology_placement_receipt_status,
        evidence_ledger: $swarm_topology_placement_evidence_ledger_status
      },
      readiness: (
        if $topology_placement_unsafe_mutation_claim
          or (($swarm_topology_placement_plan.decision // "") == "fail_closed")
          or (($swarm_topology_placement_receipt.decision // "") == "fail_closed")
          or (($swarm_topology_placement_evidence_ledger.decision // "") == "fail_closed") then "contaminated"
        elif (($swarm_topology_placement_plan.decision // "") == "blocked")
          or (($swarm_topology_placement_receipt.decision // "") == "blocked")
          or (($swarm_topology_placement_evidence_ledger.decision // "") == "blocked") then "blocked"
        elif $swarm_topology_placement_plan_status == "missing"
          or $swarm_topology_placement_receipt_status == "missing"
          or $swarm_topology_placement_evidence_ledger_status == "missing"
          or (($swarm_topology_placement_plan.decision // "") == "degraded")
          or (($swarm_topology_placement_receipt.decision // "") == "degraded")
          or (($swarm_topology_placement_evidence_ledger.decision // "") == "degraded")
          or (($swarm_topology_placement_receipt.adoption_status // "") | IN("drifted", "expired", "pending_observation")) then "degraded"
        else "ready"
        end
      ),
      severity: (
        if $topology_placement_unsafe_mutation_claim
          or (($swarm_topology_placement_plan.decision // "") == "fail_closed")
          or (($swarm_topology_placement_receipt.decision // "") == "fail_closed")
          or (($swarm_topology_placement_evidence_ledger.decision // "") == "fail_closed") then "critical"
        elif $swarm_topology_placement_plan_status == "missing"
          or $swarm_topology_placement_receipt_status == "missing"
          or $swarm_topology_placement_evidence_ledger_status == "missing"
          or (($swarm_topology_placement_plan.decision // "") | IN("blocked", "degraded"))
          or (($swarm_topology_placement_receipt.decision // "") | IN("blocked", "degraded"))
          or (($swarm_topology_placement_evidence_ledger.decision // "") | IN("blocked", "degraded"))
          or (($swarm_topology_placement_receipt.adoption_status // "") | IN("drifted", "expired", "pending_observation")) then "warning"
        else "ok"
        end
      ),
      plan_decision: ($swarm_topology_placement_plan.decision // "missing"),
      receipt_decision: ($swarm_topology_placement_receipt.decision // "missing"),
      ledger_decision: ($swarm_topology_placement_evidence_ledger.decision // "missing"),
      placement_readiness: ($swarm_topology_placement_plan.placement_readiness // "missing"),
      recommended_topology_class: ($swarm_topology_placement_plan.recommended_topology_class // "missing"),
      recommended_worker_targets: bounded($swarm_topology_placement_plan.recommended_worker_targets),
      recommended_worker_target_count: ($swarm_topology_placement_plan.summary.target_count // (($swarm_topology_placement_plan.recommended_worker_targets // []) | length)),
      recommended_worker_ids: ($swarm_topology_placement_receipt.recommended_worker_ids // []),
      heavy_target_count: ($swarm_topology_placement_plan.summary.heavy_target_count // (($swarm_topology_placement_plan.recommended_worker_targets // []) | map(select(.lane_class == "heavy")) | length)),
      latency_sensitive_target_count: ($swarm_topology_placement_plan.summary.latency_sensitive_target_count // (($swarm_topology_placement_plan.recommended_worker_targets // []) | map(select(.lane_class == "latency_sensitive")) | length)),
      warm_cache_residency_state: ($swarm_topology_placement_plan.warm_cache_residency_state // $swarm_topology_placement_receipt.cache_warmth_assumptions.state // "missing"),
      warm_cache_opportunities: bounded($swarm_topology_placement_plan.warm_cache_opportunities),
      warm_cache_opportunity_count: ($swarm_topology_placement_plan.summary.warm_cache_opportunity_count // (($swarm_topology_placement_plan.warm_cache_opportunities // []) | length)),
      shard_hints: bounded(($swarm_topology_placement_plan.recommended_worker_targets // []) | map(.shard_hint // empty)),
      adoption_status: ($swarm_topology_placement_receipt.adoption_status // "missing"),
      adoption_drift_reason_codes: ($swarm_topology_placement_receipt.adoption_drift_reason_codes // []),
      adoption_history: bounded($swarm_topology_placement_evidence_ledger.adoption_history),
      expiry: ($swarm_topology_placement_receipt.validity_window // {}),
      warnings: bounded($topology_placement_warning_reasons + $topology_placement_blocked_reasons + $topology_placement_fail_reasons),
      fail_closed_reason_count: ($topology_placement_fail_reasons | length),
      blocked_reason_count: ($topology_placement_blocked_reasons | length),
      degraded_reason_count: ($topology_placement_warning_reasons | length),
      ledger_summary: ($swarm_topology_placement_evidence_ledger.summary // {}),
      mutation_policy: {
        advisory_only: (
          ($swarm_topology_placement_plan.mutation_policy.advisory_only // true)
          and ($swarm_topology_placement_receipt.mutation_policy.advisory_only // true)
          and ($swarm_topology_placement_evidence_ledger.mutation_policy.advisory_only // true)
        ),
        mutates_br: (
          ($swarm_topology_placement_plan.mutation_policy.mutates_br // false)
          or ($swarm_topology_placement_receipt.mutation_policy.mutates_br // false)
          or ($swarm_topology_placement_evidence_ledger.mutation_policy.mutates_br // false)
        ),
        mutates_remote_workers: (
          ($swarm_topology_placement_plan.mutation_policy.mutates_remote_workers // false)
          or ($swarm_topology_placement_receipt.mutation_policy.mutates_remote_workers // false)
          or ($swarm_topology_placement_evidence_ledger.mutation_policy.mutates_remote_workers // false)
        ),
        changes_live_queue_policy: (
          ($swarm_topology_placement_plan.mutation_policy.changes_live_queue_policy // false)
          or ($swarm_topology_placement_receipt.mutation_policy.changes_live_queue_policy // false)
          or ($swarm_topology_placement_evidence_ledger.mutation_policy.changes_live_queue_policy // false)
        ),
        pins_workers_automatically: (
          ($swarm_topology_placement_plan.mutation_policy.pins_workers_automatically // false)
          or ($swarm_topology_placement_receipt.mutation_policy.pins_workers_automatically // false)
          or ($swarm_topology_placement_evidence_ledger.mutation_policy.pins_workers_automatically // false)
        ),
        enforces_placement_automatically: ($swarm_topology_placement_receipt.mutation_policy.enforces_placement_automatically // $swarm_topology_placement_evidence_ledger.mutation_policy.enforces_placement_automatically // false)
      },
      artifact_paths: {
        placement_plan_json: ($swarm_topology_placement_plan.artifact_paths.swarm_topology_placement_plan_json // $swarm_topology_placement_plan_json),
        placement_receipt_json: ($swarm_topology_placement_receipt.artifact_paths.swarm_topology_placement_receipt_json // $swarm_topology_placement_receipt_json),
        placement_evidence_ledger_json: ($swarm_topology_placement_evidence_ledger.artifact_paths.swarm_topology_placement_evidence_ledger_json // $swarm_topology_placement_evidence_ledger_json)
      }
    }) as $topology_placement_summary
  | ([
        $swarm_topology_aware_queue_advisory.mutation_policy
      ]
      | map(select(. != null))
      | any(.[]; (.advisory_only != true)
          or (.mutates_br == true)
          or (.reassigns_beads == true)
          or (.releases_reservations == true)
          or (.sends_agent_mail == true)
          or (.runs_cargo == true)
          or (.runs_rch == true)
          or (.mutates_remote_workers == true)
          or (.changes_live_queue_policy == true)
          or (.pins_workers_automatically == true))) as $topology_queue_unsafe_mutation_claim
  | (($swarm_topology_aware_queue_advisory.fail_closed_reasons // [])
      | unique_by([.code, .source_id, .detail])) as $topology_queue_fail_reasons
  | (($swarm_topology_aware_queue_advisory.blocked_reasons // [])
      | unique_by([.code, .source_id, .detail])) as $topology_queue_blocked_reasons
  | (($swarm_topology_aware_queue_advisory.degraded_reasons // [])
      | unique_by([.code, .source_id, .detail])) as $topology_queue_degraded_reasons
  | (($swarm_topology_aware_queue_advisory.reason_codes // [])
      | map(select(. == "local_fallback_contaminated" or . == "local_fallback_contamination"))
      | unique | sort) as $topology_queue_contaminating_codes
  | ({
      artifact_status: $swarm_topology_aware_queue_advisory_status,
      readiness: (
        if $swarm_topology_aware_queue_advisory_status == "missing" then "degraded"
        elif $topology_queue_unsafe_mutation_claim
          or (($topology_queue_fail_reasons | length) > 0)
          or (($topology_queue_contaminating_codes | length) > 0)
          or (($swarm_topology_aware_queue_advisory.decision // "") == "fail_closed")
          or (($swarm_topology_aware_queue_advisory.truth_state // "") == "contaminated") then "contaminated"
        elif (($topology_queue_blocked_reasons | length) > 0)
          or (($swarm_topology_aware_queue_advisory.decision // "") == "blocked")
          or (($swarm_topology_aware_queue_advisory.truth_state // "") == "blocked") then "blocked"
        elif (($topology_queue_degraded_reasons | length) > 0)
          or (($swarm_topology_aware_queue_advisory.decision // "") == "degraded")
          or (($swarm_topology_aware_queue_advisory.truth_state // "") == "degraded") then "degraded"
        else "ready"
        end
      ),
      severity: (
        if $topology_queue_unsafe_mutation_claim
          or (($topology_queue_fail_reasons | length) > 0)
          or (($topology_queue_contaminating_codes | length) > 0)
          or (($swarm_topology_aware_queue_advisory.decision // "") == "fail_closed")
          or (($swarm_topology_aware_queue_advisory.truth_state // "") == "contaminated") then "critical"
        elif $swarm_topology_aware_queue_advisory_status == "missing"
          or (($topology_queue_blocked_reasons | length) > 0)
          or (($topology_queue_degraded_reasons | length) > 0)
          or (($swarm_topology_aware_queue_advisory.decision // "") | IN("blocked", "degraded"))
          or (($swarm_topology_aware_queue_advisory.truth_state // "") | IN("blocked", "degraded")) then "warning"
        else "ok"
        end
      ),
      advisory_decision: ($swarm_topology_aware_queue_advisory.decision // "missing"),
      truth_state: ($swarm_topology_aware_queue_advisory.truth_state // "missing"),
      queue_advisory_id: ($swarm_topology_aware_queue_advisory.queue_advisory_id // null),
      reason_codes: ($swarm_topology_aware_queue_advisory.reason_codes // []),
      preferred_locality_confidence_millionths: ($swarm_topology_aware_queue_advisory.locality_bias_summary.locality_confidence_millionths // 0),
      hot_cache_reuse_confidence_millionths: ($swarm_topology_aware_queue_advisory.locality_bias_summary.hot_cache_reuse_confidence_millionths // 0),
      rank_bias_mode: ($swarm_topology_aware_queue_advisory.locality_bias_summary.rank_bias_mode // "missing"),
      preferred_worker_ids: ($swarm_topology_aware_queue_advisory.locality_bias_summary.preferred_worker_ids // []),
      usable_preferred_worker_ids: ($swarm_topology_aware_queue_advisory.locality_bias_summary.usable_preferred_worker_ids // []),
      preferred_numa_nodes: ($swarm_topology_aware_queue_advisory.locality_bias_summary.preferred_numa_nodes // []),
      worker_exclusions: {
        excluded_worker_ids: ($swarm_topology_aware_queue_advisory.worker_exclusions.excluded_worker_ids // []),
        excluded_worker_count: ($swarm_topology_aware_queue_advisory.worker_exclusions.excluded_worker_count // (($swarm_topology_aware_queue_advisory.worker_exclusions.excluded_worker_ids // []) | length))
      },
      cache_reuse_guidance: {
        proof_transport_state: ($swarm_topology_aware_queue_advisory.risk_budget_summary.proof_transport_state // "missing"),
        confirmed_task_ids: ($swarm_topology_aware_queue_advisory.feedback_summary.confirmed_task_ids // []),
        missed_cache_reuse_task_ids: ($swarm_topology_aware_queue_advisory.feedback_summary.missed_cache_reuse_task_ids // []),
        drift_task_ids: ($swarm_topology_aware_queue_advisory.feedback_summary.drift_task_ids // []),
        contamination_task_ids: ($swarm_topology_aware_queue_advisory.feedback_summary.contamination_task_ids // [])
      },
      queue_counts: {
        task_count: ($swarm_topology_aware_queue_advisory.risk_budget_summary.task_count // 0),
        queue_row_count: ($swarm_topology_aware_queue_advisory.risk_budget_summary.queue_row_count // 0),
        bottleneck_count: ($swarm_topology_aware_queue_advisory.risk_budget_summary.bottleneck_count // 0),
        critical_bottleneck_count: ($swarm_topology_aware_queue_advisory.risk_budget_summary.critical_bottleneck_count // 0)
      },
      related_queue_fidelity: {
        trust_level: $queue_fidelity_summary.trust_level,
        drift_class: $queue_fidelity_summary.drift_class,
        top_tuning_recommendation: ($queue_fidelity_summary.top_tuning_recommendation.candidate_id // null)
      },
      warnings: bounded($topology_queue_fail_reasons + $topology_queue_blocked_reasons + $topology_queue_degraded_reasons),
      mutation_policy: {
        advisory_only: ($swarm_topology_aware_queue_advisory.mutation_policy.advisory_only // true),
        mutates_br: ($swarm_topology_aware_queue_advisory.mutation_policy.mutates_br // false),
        mutates_remote_workers: ($swarm_topology_aware_queue_advisory.mutation_policy.mutates_remote_workers // false),
        changes_live_queue_policy: ($swarm_topology_aware_queue_advisory.mutation_policy.changes_live_queue_policy // false),
        pins_workers_automatically: ($swarm_topology_aware_queue_advisory.mutation_policy.pins_workers_automatically // false)
      },
      artifact_paths: {
        queue_advisory_bundle_json: ($swarm_topology_aware_queue_advisory.artifact_paths.advisory_bundle_json // $swarm_topology_aware_queue_advisory.artifact_paths.queue_advisory_bundle_json // $swarm_topology_aware_queue_advisory_json),
        queue_advisory_sources_json: ($swarm_topology_aware_queue_advisory.artifact_paths.sources_json // null),
        queue_advisory_events_jsonl: ($swarm_topology_aware_queue_advisory.artifact_paths.events_jsonl // null),
        queue_advisory_commands_txt: ($swarm_topology_aware_queue_advisory.artifact_paths.commands_txt // null)
      }
    }) as $topology_queue_advisory_summary
  | (($swarm_benchmark_workload_catalog_status != "missing")
      or ($swarm_benchmark_responsiveness_advisory_status != "missing")) as $swarm_benchmark_present
  | ([
        $swarm_benchmark_workload_catalog.mutation_policy,
        $swarm_benchmark_responsiveness_advisory.mutation_policy
      ]
      | map(select(. != null))
      | any(.[]; (.advisory_only != true)
          or (.mutates_br == true)
          or (.sends_agent_mail == true)
          or (.runs_cargo == true)
          or (.runs_rch == true)
          or (.mutates_remote_workers == true)
          or (.changes_live_queue_policy == true))) as $benchmark_unsafe_mutation_claim
  | (((($swarm_benchmark_workload_catalog.findings // [])
        | map(select((.severity // "") == "fail_closed")))
      + ($swarm_benchmark_responsiveness_advisory.fail_closed_reasons // []))
      | unique_by([(.code // .reason_code // "unknown"), (.workload_id // .source_id // .field // ""), (.detail // "")])) as $benchmark_fail_reasons
  | (((($swarm_benchmark_workload_catalog.findings // [])
        | map(select((.severity // "") == "degraded")))
      + ($swarm_benchmark_responsiveness_advisory.degraded_reasons // []))
      | unique_by([(.code // .reason_code // "unknown"), (.workload_id // .source_id // .field // ""), (.detail // "")])) as $benchmark_degraded_reasons
  | (if (($swarm_benchmark_responsiveness_advisory.throughput_gap_band // "") == "blocked_measurement") then
        [{code:"blocked_runtime_measurement", source_id:"swarm_benchmark_responsiveness_advisory", detail:"benchmark throughput measurement remains blocked"}]
      else []
      end) as $benchmark_blocked_reasons
  | (($swarm_benchmark_responsiveness_advisory.bottleneck_classes // [])
      | map(.reason_code // .bottleneck_class // "benchmark_bottleneck")
      | map(tostring)
      | unique) as $benchmark_bottleneck_reason_codes
  | (($swarm_benchmark_workload_catalog.workloads // [])) as $benchmark_workloads
  | (($swarm_benchmark_responsiveness_advisory.advisory_commands[0].command // null)) as $benchmark_primary_command
  | (
      if ($benchmark_workloads | length) == 0 then null
      elif ($benchmark_primary_command == null or $benchmark_primary_command == "") then $benchmark_workloads[0]
      else (
        ($benchmark_workloads
          | map(select(
              ((.validation_commands // []) | index($benchmark_primary_command)) != null
              or ((.benchmark_entrypoint // "") == ($benchmark_primary_command | sub("^\\./"; "")))
              or (("./" + (.benchmark_entrypoint // "")) == $benchmark_primary_command)
            ))
          | .[0]) // $benchmark_workloads[0]
      )
      end
    ) as $benchmark_selected_workload
  | ({
      artifact_statuses: {
        workload_catalog: $swarm_benchmark_workload_catalog_status,
        responsiveness_advisory: $swarm_benchmark_responsiveness_advisory_status
      },
      readiness: (
        if $benchmark_unsafe_mutation_claim
          or (($benchmark_fail_reasons | length) > 0)
          or (($swarm_benchmark_responsiveness_advisory.decision // "") == "fail_closed")
          or (($swarm_benchmark_responsiveness_advisory.truth_state // "") == "contaminated") then "contaminated"
        elif (($benchmark_blocked_reasons | length) > 0) then "blocked"
        elif $swarm_benchmark_workload_catalog_status == "missing"
          or $swarm_benchmark_responsiveness_advisory_status == "missing"
          or (($benchmark_degraded_reasons | length) > 0)
          or (($swarm_benchmark_workload_catalog.decision // "") == "degraded")
          or (($swarm_benchmark_responsiveness_advisory.decision // "") == "degraded")
          or (($swarm_benchmark_responsiveness_advisory.truth_state // "") == "degraded")
          or (($swarm_benchmark_responsiveness_advisory.utilization_pressure_band // "") == "saturated") then "degraded"
        else "ready"
        end
      ),
      severity: (
        if $benchmark_unsafe_mutation_claim
          or (($benchmark_fail_reasons | length) > 0)
          or (($swarm_benchmark_responsiveness_advisory.decision // "") == "fail_closed")
          or (($swarm_benchmark_responsiveness_advisory.truth_state // "") == "contaminated") then "critical"
        elif $swarm_benchmark_workload_catalog_status == "missing"
          or $swarm_benchmark_responsiveness_advisory_status == "missing"
          or (($benchmark_blocked_reasons | length) > 0)
          or (($benchmark_degraded_reasons | length) > 0)
          or (($swarm_benchmark_workload_catalog.decision // "") == "degraded")
          or (($swarm_benchmark_responsiveness_advisory.decision // "") == "degraded")
          or (($swarm_benchmark_responsiveness_advisory.truth_state // "") == "degraded")
          or (($swarm_benchmark_responsiveness_advisory.utilization_pressure_band // "") == "saturated") then "warning"
        else "ok"
        end
      ),
      catalog_decision: ($swarm_benchmark_workload_catalog.decision // "missing"),
      advisory_decision: ($swarm_benchmark_responsiveness_advisory.decision // "missing"),
      truth_state: ($swarm_benchmark_responsiveness_advisory.truth_state // "missing"),
      selected_workload_id: ($benchmark_selected_workload.workload_id // null),
      benchmark_class: ($benchmark_selected_workload.benchmark_class // null),
      benchmark_entrypoint: ($benchmark_selected_workload.benchmark_entrypoint // null),
      throughput_gap_band: ($swarm_benchmark_responsiveness_advisory.throughput_gap_band // "unknown"),
      utilization_pressure_band: ($swarm_benchmark_responsiveness_advisory.utilization_pressure_band // "unknown"),
      cold_warm_cache_recommendation: ($swarm_benchmark_responsiveness_advisory.cold_warm_cache_recommendation // "insufficient_cache_evidence"),
      remote_proof_confidence_state: ($swarm_benchmark_responsiveness_advisory.remote_proof_confidence_state // "missing"),
      top_bottleneck_class: ($swarm_benchmark_responsiveness_advisory.bottleneck_classes[0].bottleneck_class // null),
      bottleneck_classes: bounded($swarm_benchmark_responsiveness_advisory.bottleneck_classes),
      advisory_commands: bounded($swarm_benchmark_responsiveness_advisory.advisory_commands),
      reason_codes: ((($benchmark_fail_reasons | map(.code // .reason_code // "unknown"))
          + ($benchmark_blocked_reasons | map(.code))
          + ($benchmark_degraded_reasons | map(.code // .reason_code // "unknown"))
          + ($swarm_benchmark_responsiveness_advisory.reason_codes // [])
          + $benchmark_bottleneck_reason_codes) | map(tostring) | unique),
      blocked_reason_codes: (($benchmark_blocked_reasons | map(.code)) | unique),
      degraded_reason_codes: (($benchmark_degraded_reasons | map(.code // .reason_code // "unknown")) | unique),
      fail_closed_reason_codes: (($benchmark_fail_reasons | map(.code // .reason_code // "unknown")) | unique),
      warning_reasons: bounded($benchmark_fail_reasons + $benchmark_blocked_reasons + $benchmark_degraded_reasons),
      mutation_policy: {
        advisory_only: (
          ($swarm_benchmark_workload_catalog.mutation_policy.advisory_only // true)
          and ($swarm_benchmark_responsiveness_advisory.mutation_policy.advisory_only // true)
        ),
        mutates_br: (
          ($swarm_benchmark_workload_catalog.mutation_policy.mutates_br // false)
          or ($swarm_benchmark_responsiveness_advisory.mutation_policy.mutates_br // false)
        ),
        sends_agent_mail: (
          ($swarm_benchmark_workload_catalog.mutation_policy.sends_agent_mail // false)
          or ($swarm_benchmark_responsiveness_advisory.mutation_policy.sends_agent_mail // false)
        ),
        runs_cargo: (
          ($swarm_benchmark_workload_catalog.mutation_policy.runs_cargo // false)
          or ($swarm_benchmark_responsiveness_advisory.mutation_policy.runs_cargo // false)
        ),
        runs_rch: (
          ($swarm_benchmark_workload_catalog.mutation_policy.runs_rch // false)
          or ($swarm_benchmark_responsiveness_advisory.mutation_policy.runs_rch // false)
        ),
        mutates_remote_workers: (
          ($swarm_benchmark_workload_catalog.mutation_policy.mutates_remote_workers // false)
          or ($swarm_benchmark_responsiveness_advisory.mutation_policy.mutates_remote_workers // false)
        ),
        changes_live_queue_policy: (
          ($swarm_benchmark_workload_catalog.mutation_policy.changes_live_queue_policy // false)
          or ($swarm_benchmark_responsiveness_advisory.mutation_policy.changes_live_queue_policy // false)
        )
      },
      artifact_paths: {
        workload_catalog_json: ($swarm_benchmark_workload_catalog.artifact_paths.swarm_benchmark_workload_catalog_json // $swarm_benchmark_workload_catalog_json),
        catalog_findings_json: ($swarm_benchmark_workload_catalog.artifact_paths.catalog_findings_json // null),
        responsiveness_advisory_json: ($swarm_benchmark_responsiveness_advisory.artifact_paths.swarm_benchmark_responsiveness_advisory_json // $swarm_benchmark_responsiveness_advisory_json),
        advisory_events_jsonl: ($swarm_benchmark_responsiveness_advisory.artifact_paths.events_jsonl // null),
        advisory_commands_txt: ($swarm_benchmark_responsiveness_advisory.artifact_paths.commands_txt // null),
        advisory_report_md: ($swarm_benchmark_responsiveness_advisory.artifact_paths.report_md // null)
      }
    }) as $benchmark_advisory_summary
  | ([
        $swarm_actionability_report.mutation_policy
      ]
      | map(select(. != null))
      | any(.[]; (.advisory_only != true)
          or (.mutates_br == true)
          or (.claims_beads == true)
          or (.reopens_beads == true)
          or (.closes_beads == true)
          or (.reassigns_beads == true)
          or (.releases_reservations == true)
          or (.sends_agent_mail == true)
          or (.mutates_git == true)
          or (.runs_cargo == true)
          or (.runs_rch == true)
          or (.mutates_remote_workers == true)
          or (.changes_live_queue_policy == true))) as $actionability_unsafe_mutation_claim
  | (($swarm_actionability_report.fail_closed_reasons // [])
      | unique_by([.code, .source_id, .detail])) as $actionability_fail_reasons
  | (($swarm_actionability_report.candidate_reports // [])
      | map(select(.candidate_id == ($swarm_actionability_report.primary_candidate_id // "")))
      | .[0]) as $actionability_primary_candidate
  | (($swarm_actionability_report.source_freshness // {})) as $actionability_source_freshness
  | ((($actionability_source_freshness.db_newer // false)
      or ((if ($actionability_source_freshness | has("all_sources_fresh")) then $actionability_source_freshness.all_sources_fresh else true end) | not))) as $actionability_stale_sources
  | ({
      artifact_status: $swarm_actionability_report_status,
      readiness: (
        if $swarm_actionability_report_status == "missing" then "missing"
        elif $actionability_unsafe_mutation_claim
          or $actionability_stale_sources then "contaminated"
        elif (($swarm_actionability_report.decision // "") == "fail_closed") then "blocked"
        elif (($swarm_actionability_report.decision // "") | IN("defer", "observe_only")) then "degraded"
        else "ready"
        end
      ),
      severity: (
        if $swarm_actionability_report_status == "missing" then "warning"
        elif $actionability_unsafe_mutation_claim
          or $actionability_stale_sources then "critical"
        elif (($swarm_actionability_report.decision // "") | IN("fail_closed", "defer", "observe_only")) then "warning"
        else "ok"
        end
      ),
      guard_decision: ($swarm_actionability_report.decision // "missing"),
      primary_candidate_id: ($swarm_actionability_report.primary_candidate_id // null),
      primary_candidate_decision: ($actionability_primary_candidate.decision // null),
      primary_candidate_states: ($actionability_primary_candidate.states // []),
      primary_candidate_assignees: ($actionability_primary_candidate.evidence.assignees // []),
      reason_codes: ($actionability_fail_reasons | map(.code) | unique),
      remediation_commands: ($swarm_actionability_report.remediation_commands // []),
      source_freshness: {
        db_newer: ($actionability_source_freshness.db_newer // false),
        all_sources_fresh: (if ($actionability_source_freshness | has("all_sources_fresh")) then $actionability_source_freshness.all_sources_fresh else true end),
        missing_optional_sources: ($actionability_source_freshness.missing_optional_sources // [])
      },
      candidate_summary: {
        candidate_count: ($swarm_actionability_report.candidate_summary.candidate_count // 0),
        ready_count: ($swarm_actionability_report.candidate_summary.ready_count // 0),
        in_progress_count: ($swarm_actionability_report.candidate_summary.in_progress_count // 0),
        blocked_count: ($swarm_actionability_report.candidate_summary.blocked_count // 0),
        reservation_count: ($swarm_actionability_report.candidate_summary.reservation_count // 0),
        dirty_overlap_count: ($swarm_actionability_report.candidate_summary.dirty_overlap_count // 0)
      },
      warnings: bounded($actionability_fail_reasons),
      mutation_policy: {
        advisory_only: ($swarm_actionability_report.mutation_policy.advisory_only // true),
        mutates_br: ($swarm_actionability_report.mutation_policy.mutates_br // false),
        claims_beads: ($swarm_actionability_report.mutation_policy.claims_beads // false),
        reopens_beads: ($swarm_actionability_report.mutation_policy.reopens_beads // false),
        closes_beads: ($swarm_actionability_report.mutation_policy.closes_beads // false),
        reassigns_beads: ($swarm_actionability_report.mutation_policy.reassigns_beads // false),
        releases_reservations: ($swarm_actionability_report.mutation_policy.releases_reservations // false),
        sends_agent_mail: ($swarm_actionability_report.mutation_policy.sends_agent_mail // false),
        mutates_git: ($swarm_actionability_report.mutation_policy.mutates_git // false),
        runs_cargo: ($swarm_actionability_report.mutation_policy.runs_cargo // false),
        runs_rch: ($swarm_actionability_report.mutation_policy.runs_rch // false),
        mutates_remote_workers: ($swarm_actionability_report.mutation_policy.mutates_remote_workers // false),
        changes_live_queue_policy: ($swarm_actionability_report.mutation_policy.changes_live_queue_policy // false)
      },
      artifact_paths: {
        actionability_report_json: ($swarm_actionability_report.artifact_paths.actionability_report_json // $swarm_actionability_report_json),
        events_jsonl: ($swarm_actionability_report.artifact_paths.events_jsonl // null),
        commands_txt: ($swarm_actionability_report.artifact_paths.commands_txt // null),
        report_md: ($swarm_actionability_report.artifact_paths.report_md // null)
      }
    }) as $actionability_summary
  | ([
        $swarm_capability_affinity_routing_advisory.mutation_policy,
        $swarm_capability_affinity_routing_outcome_ledger.mutation_policy
      ]
      | map(select(. != null))
      | any(.[]; (.advisory_only != true)
          or (.mutates_br == true)
          or (.reassigns_beads == true)
          or (.releases_reservations == true)
          or (.sends_agent_mail == true)
          or (.runs_cargo == true)
          or (.runs_rch == true)
          or (.mutates_remote_workers == true)
          or (.changes_live_queue_policy == true)
          or (.reroutes_tasks_automatically == true))) as $capability_affinity_unsafe_mutation_claim
  | ((($swarm_capability_affinity_routing_advisory.fail_closed_reasons // [])
      + ($swarm_capability_affinity_routing_outcome_ledger.fail_closed_reasons // []))
      | unique_by([.code, .source_id, .detail])) as $capability_affinity_fail_reasons
  | ((($swarm_capability_affinity_routing_advisory.blocked_reasons // [])
      + ($swarm_capability_affinity_routing_outcome_ledger.blocked_reasons // []))
      | unique_by([.code, .source_id, .detail])) as $capability_affinity_blocked_reasons
  | ((($swarm_capability_affinity_routing_advisory.degraded_reasons // [])
      + ($swarm_capability_affinity_routing_outcome_ledger.degraded_reasons // []))
      | unique_by([.code, .source_id, .detail])) as $capability_affinity_warning_reasons
  | ({
      artifact_statuses: {
        routing_advisory: $swarm_capability_affinity_routing_advisory_status,
        outcome_ledger: $swarm_capability_affinity_routing_outcome_ledger_status
      },
      readiness: (
        if $capability_affinity_unsafe_mutation_claim
          or (($swarm_capability_affinity_routing_advisory.decision // "") == "fail_closed")
          or (($swarm_capability_affinity_routing_outcome_ledger.decision // "") == "fail_closed")
          or (($swarm_capability_affinity_routing_advisory.truth_state // "") == "contaminated")
          or (($swarm_capability_affinity_routing_outcome_ledger.truth_state // "") == "contaminated") then "contaminated"
        elif (($swarm_capability_affinity_routing_advisory.decision // "") == "blocked")
          or (($swarm_capability_affinity_routing_outcome_ledger.decision // "") == "blocked")
          or (($swarm_capability_affinity_routing_advisory.truth_state // "") == "blocked")
          or (($swarm_capability_affinity_routing_outcome_ledger.truth_state // "") == "blocked") then "blocked"
        elif $swarm_capability_affinity_routing_advisory_status == "missing"
          or $swarm_capability_affinity_routing_outcome_ledger_status == "missing"
          or (($swarm_capability_affinity_routing_advisory.decision // "") == "degraded")
          or (($swarm_capability_affinity_routing_outcome_ledger.decision // "") == "degraded")
          or (($swarm_capability_affinity_routing_advisory.truth_state // "") == "degraded")
          or (($swarm_capability_affinity_routing_outcome_ledger.truth_state // "") == "degraded") then "degraded"
        else "ready"
        end
      ),
      severity: (
        if $capability_affinity_unsafe_mutation_claim
          or (($swarm_capability_affinity_routing_advisory.decision // "") == "fail_closed")
          or (($swarm_capability_affinity_routing_outcome_ledger.decision // "") == "fail_closed")
          or (($swarm_capability_affinity_routing_advisory.truth_state // "") == "contaminated")
          or (($swarm_capability_affinity_routing_outcome_ledger.truth_state // "") == "contaminated") then "critical"
        elif $swarm_capability_affinity_routing_advisory_status == "missing"
          or $swarm_capability_affinity_routing_outcome_ledger_status == "missing"
          or (($swarm_capability_affinity_routing_advisory.decision // "") | IN("blocked", "degraded"))
          or (($swarm_capability_affinity_routing_outcome_ledger.decision // "") | IN("blocked", "degraded"))
          or (($swarm_capability_affinity_routing_advisory.truth_state // "") | IN("blocked", "degraded"))
          or (($swarm_capability_affinity_routing_outcome_ledger.truth_state // "") | IN("blocked", "degraded")) then "warning"
        else "ok"
        end
      ),
      advisory_decision: ($swarm_capability_affinity_routing_advisory.decision // "missing"),
      outcome_ledger_decision: ($swarm_capability_affinity_routing_outcome_ledger.decision // "missing"),
      routing_mode: ($swarm_capability_affinity_routing_advisory.worker_affinity_summary.routing_mode // $swarm_capability_affinity_routing_outcome_ledger.routing_mode // "missing"),
      recommended_topology_class: ($swarm_capability_affinity_routing_advisory.worker_affinity_summary.recommended_topology_class // "missing"),
      preferred_worker_ids: bounded($swarm_capability_affinity_routing_advisory.worker_affinity_summary.preferred_worker_ids),
      advised_worker_ids: bounded(($swarm_capability_affinity_routing_outcome_ledger.planned_advised_worker_ids // $swarm_capability_affinity_routing_advisory.worker_affinity_summary.advised_worker_ids)),
      preferred_worker_count: (($swarm_capability_affinity_routing_advisory.worker_affinity_summary.preferred_worker_ids // []) | length),
      advised_worker_count: ((($swarm_capability_affinity_routing_outcome_ledger.planned_advised_worker_ids // $swarm_capability_affinity_routing_advisory.worker_affinity_summary.advised_worker_ids) // []) | length),
      required_capabilities: bounded($swarm_capability_affinity_routing_advisory.capability_coverage_summary.required_capabilities),
      required_capability_count: (($swarm_capability_affinity_routing_advisory.capability_coverage_summary.required_capabilities // []) | length),
      required_toolchain_fingerprints: bounded($swarm_capability_affinity_routing_advisory.toolchain_parity_summary.required_toolchain_fingerprints),
      required_toolchain_fingerprint_count: (($swarm_capability_affinity_routing_advisory.toolchain_parity_summary.required_toolchain_fingerprints // []) | length),
      matched_task_ids: bounded($swarm_capability_affinity_routing_outcome_ledger.matched_task_ids),
      mismatch_task_ids: bounded($swarm_capability_affinity_routing_outcome_ledger.mismatched_task_ids),
      capability_gap_task_ids: bounded($swarm_capability_affinity_routing_outcome_ledger.capability_gap_task_ids),
      toolchain_drift_task_ids: bounded($swarm_capability_affinity_routing_outcome_ledger.toolchain_drift_task_ids),
      contamination_task_ids: bounded($swarm_capability_affinity_routing_outcome_ledger.contamination_task_ids),
      matched_task_count: (($swarm_capability_affinity_routing_outcome_ledger.matched_task_ids // []) | length),
      mismatch_task_count: (($swarm_capability_affinity_routing_outcome_ledger.mismatched_task_ids // []) | length),
      capability_gap_task_count: (($swarm_capability_affinity_routing_outcome_ledger.capability_gap_task_ids // []) | length),
      toolchain_drift_task_count: (($swarm_capability_affinity_routing_outcome_ledger.toolchain_drift_task_ids // []) | length),
      contamination_task_count: (($swarm_capability_affinity_routing_outcome_ledger.contamination_task_ids // []) | length),
      capability_coverage_score: ($swarm_capability_affinity_routing_advisory.capability_coverage_summary.score // 0),
      toolchain_parity_score: ($swarm_capability_affinity_routing_advisory.toolchain_parity_summary.score // 0),
      confidence_score: ($swarm_capability_affinity_routing_advisory.worker_affinity_summary.confidence_score // 0),
      supporting_evidence_summary: ($swarm_capability_affinity_routing_advisory.supporting_evidence_summary // {}),
      reason_codes: ((($swarm_capability_affinity_routing_advisory.reason_codes // []) + ($swarm_capability_affinity_routing_outcome_ledger.reason_codes // [])) | map(tostring) | unique),
      warnings: bounded($capability_affinity_warning_reasons + $capability_affinity_blocked_reasons + $capability_affinity_fail_reasons),
      fail_closed_reason_count: ($capability_affinity_fail_reasons | length),
      blocked_reason_count: ($capability_affinity_blocked_reasons | length),
      degraded_reason_count: ($capability_affinity_warning_reasons | length),
      mutation_policy: {
        advisory_only: (
          ($swarm_capability_affinity_routing_advisory.mutation_policy.advisory_only // true)
          and ($swarm_capability_affinity_routing_outcome_ledger.mutation_policy.advisory_only // true)
        ),
        mutates_br: (
          ($swarm_capability_affinity_routing_advisory.mutation_policy.mutates_br // false)
          or ($swarm_capability_affinity_routing_outcome_ledger.mutation_policy.mutates_br // false)
        ),
        mutates_remote_workers: (
          ($swarm_capability_affinity_routing_advisory.mutation_policy.mutates_remote_workers // false)
          or ($swarm_capability_affinity_routing_outcome_ledger.mutation_policy.mutates_remote_workers // false)
        ),
        changes_live_queue_policy: (
          ($swarm_capability_affinity_routing_advisory.mutation_policy.changes_live_queue_policy // false)
          or ($swarm_capability_affinity_routing_outcome_ledger.mutation_policy.changes_live_queue_policy // false)
        ),
        reroutes_tasks_automatically: (
          ($swarm_capability_affinity_routing_advisory.mutation_policy.reroutes_tasks_automatically // false)
          or ($swarm_capability_affinity_routing_outcome_ledger.mutation_policy.reroutes_tasks_automatically // false)
        )
      },
      artifact_paths: {
        routing_advisory_json: ($swarm_capability_affinity_routing_advisory.artifact_paths.advisory_json // $swarm_capability_affinity_routing_advisory_json),
        outcome_ledger_json: ($swarm_capability_affinity_routing_outcome_ledger.artifact_paths.outcome_ledger_json // $swarm_capability_affinity_routing_outcome_ledger_json)
      }
    }) as $capability_affinity_summary
  | (($swarm_control_surface_catalog_status != "missing")
      or ($swarm_control_surface_intent_plan_status != "missing")
      or ($swarm_control_surface_drift_report_status != "missing")) as $control_surface_catalog_present
  | ([
        $swarm_control_surface_catalog.mutation_policy,
        $swarm_control_surface_intent_plan.mutation_policy,
        $swarm_control_surface_drift_report.mutation_policy
      ]
      | map(select(. != null))
      | any(.[]; (.advisory_only != true)
          or (.mutates_br == true)
          or (.claims_beads == true)
          or (.reopens_beads == true)
          or (.closes_beads == true)
          or (.reassigns_beads == true)
          or (.releases_reservations == true)
          or (.sends_agent_mail == true)
          or (.mutates_git == true)
          or (.runs_cargo == true)
          or (.runs_rch == true)
          or (.mutates_remote_workers == true)
          or (.changes_live_queue_policy == true)
          or (.reroutes_tasks_automatically == true)
          or (.repairs_automatically == true)
          or (.automatic_remediation == true))) as $control_surface_unsafe_mutation_claim
  | (((($swarm_control_surface_catalog.findings // []) | map(select((.severity // "") == "fail_closed")))
      + ($swarm_control_surface_intent_plan.fail_closed_reasons // [])
      + (($swarm_control_surface_drift_report.findings // []) | map(select((.severity // "fail_closed") == "fail_closed"))))
      | unique_by([reason_code, .surface_id, .source_id, .detail])) as $control_surface_fail_reasons
  | (($swarm_control_surface_intent_plan.blocked_reasons // [])
      | unique_by([reason_code, .surface_id, .source_id, .detail])) as $control_surface_blocked_reasons
  | (((($swarm_control_surface_catalog.findings // []) | map(select((.severity // "") == "degraded")))
      + ($swarm_control_surface_intent_plan.degraded_reasons // []))
      | unique_by([reason_code, .surface_id, .source_id, .detail])) as $control_surface_degraded_reasons
  | (($swarm_control_surface_intent_plan.recommendations // [])[0]) as $control_surface_top_recommendation
  | ({
      artifact_statuses: {
        catalog: $swarm_control_surface_catalog_status,
        intent_plan: $swarm_control_surface_intent_plan_status,
        drift_report: $swarm_control_surface_drift_report_status
      },
      readiness: (
        if ($control_surface_catalog_present | not) then "missing"
        elif $control_surface_unsafe_mutation_claim
          or (($swarm_control_surface_catalog.decision // "") == "fail_closed")
          or (($swarm_control_surface_intent_plan.decision // "") == "fail_closed")
          or (($swarm_control_surface_drift_report.decision // "") == "fail_closed") then "contaminated"
        elif (($swarm_control_surface_intent_plan.decision // "") == "blocked")
          or (($control_surface_blocked_reasons | length) > 0) then "blocked"
        elif $swarm_control_surface_catalog_status == "missing"
          or $swarm_control_surface_intent_plan_status == "missing"
          or $swarm_control_surface_drift_report_status == "missing"
          or (($swarm_control_surface_catalog.decision // "") == "degraded")
          or (($swarm_control_surface_intent_plan.decision // "") == "degraded")
          or (($swarm_control_surface_drift_report.decision // "") == "degraded")
          or (($control_surface_degraded_reasons | length) > 0) then "degraded"
        else "ready"
        end
      ),
      severity: (
        if ($control_surface_catalog_present | not) then "warning"
        elif $control_surface_unsafe_mutation_claim
          or (($swarm_control_surface_catalog.decision // "") == "fail_closed")
          or (($swarm_control_surface_intent_plan.decision // "") == "fail_closed")
          or (($swarm_control_surface_drift_report.decision // "") == "fail_closed") then "critical"
        elif (($swarm_control_surface_intent_plan.decision // "") | IN("blocked", "degraded"))
          or (($swarm_control_surface_catalog.decision // "") == "degraded")
          or (($swarm_control_surface_drift_report.decision // "") == "degraded")
          or (($control_surface_blocked_reasons | length) > 0)
          or (($control_surface_degraded_reasons | length) > 0) then "warning"
        else "ok"
        end
      ),
      catalog_decision: ($swarm_control_surface_catalog.decision // "missing"),
      intent_plan_decision: ($swarm_control_surface_intent_plan.decision // "missing"),
      drift_report_decision: ($swarm_control_surface_drift_report.decision // "missing"),
      surface_count: ($swarm_control_surface_catalog.surface_count // (($swarm_control_surface_catalog.surfaces // []) | length)),
      drift_count: ($swarm_control_surface_drift_report.fail_closed_count // (($swarm_control_surface_drift_report.findings // []) | length)),
      top_recommended_surface: ($control_surface_top_recommendation.surface_id // null),
      top_recommended_track: ($control_surface_top_recommendation.track // null),
      top_recommended_purpose: ($control_surface_top_recommendation.purpose // null),
      top_recommended_operator_status_section: ($control_surface_top_recommendation.operator_status_section // null),
      top_recommended_script: ($control_surface_top_recommendation.implementation_script // null),
      top_recommended_smoke_script: ($control_surface_top_recommendation.smoke_script // null),
      top_recommended_contract_json: ($control_surface_top_recommendation.contract_json // null),
      top_recommended_runbook_doc: ($control_surface_top_recommendation.runbook_doc // null),
      top_recommended_score: ($control_surface_top_recommendation.score // null),
      top_recommended_required_inputs: bounded($control_surface_top_recommendation.required_inputs),
      top_recommended_emitted_artifacts: bounded($control_surface_top_recommendation.emitted_artifacts),
      top_recommended_validation_commands: bounded($control_surface_top_recommendation.validation_commands),
      top_recommended_intent_tags: tag_labels($control_surface_top_recommendation.intent_tags),
      top_recommended_symptom_tags: tag_labels($control_surface_top_recommendation.symptom_tags),
      top_recommended_matched_intent_tags: tag_labels($control_surface_top_recommendation.matched_intent_tags),
      top_recommended_matched_symptom_tags: tag_labels($control_surface_top_recommendation.matched_symptom_tags),
      recommended_command_count: (($swarm_control_surface_intent_plan.advisory_commands // []) | length),
      artifacts_to_preserve_count: (($swarm_control_surface_intent_plan.artifacts_to_preserve // []) | length),
      blocked_reason_codes: ($control_surface_blocked_reasons | map(reason_code) | unique),
      degraded_reason_codes: ($control_surface_degraded_reasons | map(reason_code) | unique),
      fail_closed_reason_codes: ($control_surface_fail_reasons | map(reason_code) | unique),
      duplicate_new_work_warning: (($swarm_control_surface_intent_plan.duplicate_new_work_warnings // [])[0] // null),
      duplicate_new_work_warnings: ($swarm_control_surface_intent_plan.duplicate_new_work_warnings // []),
      recommended_commands: bounded($swarm_control_surface_intent_plan.advisory_commands),
      artifacts_to_preserve: bounded($swarm_control_surface_intent_plan.artifacts_to_preserve),
      warnings: bounded($control_surface_degraded_reasons + $control_surface_blocked_reasons + $control_surface_fail_reasons),
      mutation_policy: {
        advisory_only: (
          ($swarm_control_surface_catalog.mutation_policy.advisory_only // true)
          and ($swarm_control_surface_intent_plan.mutation_policy.advisory_only // true)
          and ($swarm_control_surface_drift_report.mutation_policy.advisory_only // true)
        ),
        fixture_fed_only: true,
        mutates_br: (
          ($swarm_control_surface_catalog.mutation_policy.mutates_br // false)
          or ($swarm_control_surface_intent_plan.mutation_policy.mutates_br // false)
          or ($swarm_control_surface_drift_report.mutation_policy.mutates_br // false)
        ),
        sends_agent_mail: (
          ($swarm_control_surface_catalog.mutation_policy.sends_agent_mail // false)
          or ($swarm_control_surface_intent_plan.mutation_policy.sends_agent_mail // false)
          or ($swarm_control_surface_drift_report.mutation_policy.sends_agent_mail // false)
        ),
        runs_cargo: (
          ($swarm_control_surface_catalog.mutation_policy.runs_cargo // false)
          or ($swarm_control_surface_intent_plan.mutation_policy.runs_cargo // false)
          or ($swarm_control_surface_drift_report.mutation_policy.runs_cargo // false)
        ),
        runs_rch: (
          ($swarm_control_surface_catalog.mutation_policy.runs_rch // false)
          or ($swarm_control_surface_intent_plan.mutation_policy.runs_rch // false)
          or ($swarm_control_surface_drift_report.mutation_policy.runs_rch // false)
        ),
        mutates_remote_workers: (
          ($swarm_control_surface_catalog.mutation_policy.mutates_remote_workers // false)
          or ($swarm_control_surface_intent_plan.mutation_policy.mutates_remote_workers // false)
          or ($swarm_control_surface_drift_report.mutation_policy.mutates_remote_workers // false)
        ),
        changes_live_queue_policy: (
          ($swarm_control_surface_catalog.mutation_policy.changes_live_queue_policy // false)
          or ($swarm_control_surface_intent_plan.mutation_policy.changes_live_queue_policy // false)
          or ($swarm_control_surface_drift_report.mutation_policy.changes_live_queue_policy // false)
        )
      },
      artifact_paths: {
        catalog_json: ($swarm_control_surface_catalog.artifact_paths.swarm_control_surface_catalog_json // $swarm_control_surface_catalog_json),
        catalog_findings_json: ($swarm_control_surface_catalog.artifact_paths.catalog_findings_json // null),
        intent_plan_json: ($swarm_control_surface_intent_plan.artifact_paths.swarm_control_surface_intent_plan_json // $swarm_control_surface_intent_plan_json),
        intent_events_jsonl: ($swarm_control_surface_intent_plan.artifact_paths.events_jsonl // null),
        intent_commands_txt: ($swarm_control_surface_intent_plan.artifact_paths.commands_txt // null),
        intent_report_md: ($swarm_control_surface_intent_plan.artifact_paths.report_md // null),
        drift_report_json: ($swarm_control_surface_drift_report.artifact_paths.control_surface_drift_report_json // $swarm_control_surface_drift_report_json),
        drift_events_jsonl: ($swarm_control_surface_drift_report.artifact_paths.events_jsonl // null),
        drift_commands_txt: ($swarm_control_surface_drift_report.artifact_paths.commands_txt // null),
        drift_report_md: ($swarm_control_surface_drift_report.artifact_paths.report_md // null)
      }
    }) as $control_surface_catalog_summary
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
    + (if $swarm_actionability_report_status == "missing" then
        []
      elif $actionability_summary.readiness == "contaminated" then
        [{component: "swarm_actionability_guard", status: "contaminated", impact: "actionability guard report is stale or carries unsafe mutation claims", remediation: (if (($actionability_summary.remediation_commands // []) | length) > 0 then (($actionability_summary.remediation_commands // []) | join("; ")) else "Refresh the actionability report before trusting claim guidance." end)}]
      elif $actionability_summary.readiness == "blocked" then
        [{component: "swarm_actionability_guard", status: "blocked", impact: "actionability guard reports blocked or divergent claimability", remediation: (if (($actionability_summary.remediation_commands // []) | length) > 0 then (($actionability_summary.remediation_commands // []) | join("; ")) else "Respect blocked actionability evidence before claiming new work." end)}]
      elif $actionability_summary.readiness == "degraded" then
        [{component: "swarm_actionability_guard", status: "degraded", impact: "actionability guard cannot yet endorse a safe claim", remediation: (if (($actionability_summary.remediation_commands // []) | length) > 0 then (($actionability_summary.remediation_commands // []) | join("; ")) else "Review reservations, dirty overlap, and ownership evidence before claiming work." end)}]
      else [] end)
    + (if $swarm_benchmark_present and $benchmark_advisory_summary.readiness == "contaminated" then
        [{component: "swarm_benchmark_responsiveness", status: "contaminated", impact: "benchmark responsiveness advisory is contaminated by fail-closed or unsafe mutation claims", remediation: (if (($benchmark_advisory_summary.advisory_commands // []) | length) > 0 then (($benchmark_advisory_summary.advisory_commands | map(.command) | join("; "))) else "Refresh benchmark bundle and workload catalog evidence before trusting benchmark guidance." end)}]
      elif $swarm_benchmark_present and $benchmark_advisory_summary.readiness == "blocked" then
        [{component: "swarm_benchmark_responsiveness", status: "blocked", impact: "benchmark throughput evidence is blocked and cannot support workload readiness claims", remediation: (if (($benchmark_advisory_summary.advisory_commands // []) | length) > 0 then (($benchmark_advisory_summary.advisory_commands | map(.command) | join("; "))) else "Refresh blocked throughput evidence before trusting benchmark guidance." end)}]
      elif $swarm_benchmark_present and $benchmark_advisory_summary.readiness == "degraded" then
        [{component: "swarm_benchmark_responsiveness", status: "degraded", impact: "benchmark responsiveness advisory is degraded by stale, saturated, or incomplete evidence", remediation: (if (($benchmark_advisory_summary.advisory_commands // []) | length) > 0 then (($benchmark_advisory_summary.advisory_commands | map(.command) | join("; "))) else "Refresh benchmark catalog and responsiveness advisory evidence before using benchmark guidance." end)}]
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
    + (if $swarm_resource_envelope_status == "missing" then
        [{component: "swarm_resource_envelope", status: "missing", impact: "resource envelope and fair-share artifacts are missing", remediation: "Provide --swarm-resource-envelope-json and --swarm-fair-share-batch-plan-json before publishing host envelope readiness."}]
      elif $resource_envelope_summary.severity != "ok" then
        [{component: "swarm_resource_envelope", status: $resource_envelope_summary.readiness, impact: "host resource envelope or fair-share admission is degraded, blocked, or contaminated", remediation: "Refresh the resource envelope and respect the fair-share plan before admitting more work."}]
      else [] end)
    + (if $swarm_topology_placement_plan_status == "missing"
          or $swarm_topology_placement_receipt_status == "missing"
          or $swarm_topology_placement_evidence_ledger_status == "missing" then
        [{component: "swarm_topology_placement", status: "missing", impact: "topology placement plan, receipt, or evidence ledger is missing", remediation: "Provide topology placement planner and receipt ledger artifacts before publishing locality and cache-residency advice."}]
      elif $topology_placement_summary.severity != "ok" then
        [{component: "swarm_topology_placement", status: $topology_placement_summary.readiness, impact: "topology placement or cache-residency adoption evidence is degraded, blocked, or contaminated", remediation: "Refresh placement evidence or respect blocked/drift/expiry warnings before using locality advice."}]
      else [] end)
    + (if $swarm_topology_aware_queue_advisory_status != "missing" and $topology_queue_advisory_summary.severity != "ok" then
        [{component: "swarm_topology_aware_queue_advisory", status: $topology_queue_advisory_summary.readiness, impact: "topology-aware queue locality advice is degraded, blocked, or contaminated", remediation: "Refresh queue advisory evidence or respect degraded/blocked/local-fallback queue locality warnings before ranking work."}]
      else [] end)
    + (if $control_surface_catalog_present and $control_surface_catalog_summary.readiness == "contaminated" then
        [{component: "swarm_control_surface_catalog", status: "contaminated", impact: "control-surface catalog routing evidence failed closed or carries unsafe mutation claims", remediation: "Refresh catalog, intent-router, and drift-gate artifacts before using control-surface routing guidance."}]
      elif $control_surface_catalog_present and $control_surface_catalog_summary.readiness == "blocked" then
        [{component: "swarm_control_surface_catalog", status: "blocked", impact: "control-surface intent routing is blocked by active ownership or explicit route blockers", remediation: "Respect blocked route reasons before creating or claiming adjacent control-surface work."}]
      elif $control_surface_catalog_present and $control_surface_catalog_summary.readiness == "degraded" then
        [{component: "swarm_control_surface_catalog", status: "degraded", impact: "control-surface catalog routing is incomplete or degraded", remediation: "Refresh missing catalog, intent-router, or drift-gate artifacts before relying on the routing handoff."}]
      else [] end)
    + (if $swarm_capability_affinity_routing_advisory_status == "missing"
          or $swarm_capability_affinity_routing_outcome_ledger_status == "missing" then
        [{component: "swarm_capability_affinity_routing", status: "missing", impact: "capability-affinity routing advisory or outcome ledger is missing", remediation: "Provide capability-affinity advisory and outcome-ledger artifacts before publishing worker-cohort or toolchain-safe routing advice."}]
      elif $capability_affinity_summary.severity != "ok" then
        [{component: "swarm_capability_affinity_routing", status: $capability_affinity_summary.readiness, impact: "capability-affinity routing evidence is degraded, blocked, or contaminated", remediation: "Refresh routing advisory evidence or respect mismatch, capability-gap, toolchain-drift, and contamination warnings before using worker-affinity advice."}]
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
      summary: ({
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
        resource_envelope_readiness: $resource_envelope_summary.readiness,
        resource_envelope_decision: $resource_envelope_summary.decision,
        resource_envelope_severity: $resource_envelope_summary.severity,
        fair_share_decision: $resource_envelope_summary.fair_share_decision,
        fair_share_admitted_count: $resource_envelope_summary.fair_share.admitted_count,
        fair_share_deferred_count: $resource_envelope_summary.fair_share.deferred_count,
        fair_share_heavy_admitted_count: $resource_envelope_summary.fair_share.heavy_admitted_count,
        topology_placement_readiness: $topology_placement_summary.readiness,
        topology_placement_plan_decision: $topology_placement_summary.plan_decision,
        topology_placement_receipt_decision: $topology_placement_summary.receipt_decision,
        topology_placement_topology_class: $topology_placement_summary.recommended_topology_class,
        topology_placement_warm_cache_state: $topology_placement_summary.warm_cache_residency_state,
        topology_placement_warm_cache_opportunity_count: $topology_placement_summary.warm_cache_opportunity_count,
        topology_placement_adoption_status: $topology_placement_summary.adoption_status,
        topology_placement_drift_reason_count: (($topology_placement_summary.warnings // []) | length),
        capability_affinity_readiness: $capability_affinity_summary.readiness,
        capability_affinity_advisory_decision: $capability_affinity_summary.advisory_decision,
        capability_affinity_outcome_ledger_decision: $capability_affinity_summary.outcome_ledger_decision,
        capability_affinity_routing_mode: $capability_affinity_summary.routing_mode,
        capability_affinity_topology_class: $capability_affinity_summary.recommended_topology_class,
        capability_affinity_preferred_worker_count: $capability_affinity_summary.preferred_worker_count,
        capability_affinity_mismatch_count: $capability_affinity_summary.mismatch_task_count,
        capability_affinity_capability_gap_count: $capability_affinity_summary.capability_gap_task_count,
        capability_affinity_toolchain_drift_count: $capability_affinity_summary.toolchain_drift_task_count,
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
      }
      + (if $swarm_benchmark_present then {
        benchmark_readiness: $benchmark_advisory_summary.readiness,
        benchmark_catalog_decision: $benchmark_advisory_summary.catalog_decision,
        benchmark_advisory_decision: $benchmark_advisory_summary.advisory_decision,
        benchmark_selected_workload_id: ($benchmark_advisory_summary.selected_workload_id // "none"),
        benchmark_class: ($benchmark_advisory_summary.benchmark_class // "unknown"),
        benchmark_throughput_gap_band: $benchmark_advisory_summary.throughput_gap_band,
        benchmark_utilization_pressure_band: $benchmark_advisory_summary.utilization_pressure_band,
        benchmark_cold_warm_cache_recommendation: $benchmark_advisory_summary.cold_warm_cache_recommendation,
        benchmark_remote_proof_confidence_state: $benchmark_advisory_summary.remote_proof_confidence_state,
        benchmark_top_bottleneck_class: ($benchmark_advisory_summary.top_bottleneck_class // "none")
      } else {} end)
      + (if $control_surface_catalog_present then {
        control_surface_catalog_readiness: $control_surface_catalog_summary.readiness,
        control_surface_catalog_decision: $control_surface_catalog_summary.catalog_decision,
        control_surface_catalog_surface_count: $control_surface_catalog_summary.surface_count,
        control_surface_catalog_drift_count: $control_surface_catalog_summary.drift_count,
        control_surface_catalog_top_recommended_surface: ($control_surface_catalog_summary.top_recommended_surface // "none"),
        control_surface_catalog_top_recommended_track: ($control_surface_catalog_summary.top_recommended_track // "none"),
        control_surface_catalog_top_recommended_operator_status_section: ($control_surface_catalog_summary.top_recommended_operator_status_section // "none"),
        control_surface_catalog_top_recommended_script: ($control_surface_catalog_summary.top_recommended_script // "none"),
        control_surface_catalog_recommended_command_count: $control_surface_catalog_summary.recommended_command_count
      } else {} end)),
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
      predictive_dashboard: ({
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
        swarm_actionability_guard: $actionability_summary,
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
        swarm_resource_envelope: $resource_envelope_summary,
        swarm_topology_placement: $topology_placement_summary,
        swarm_capability_affinity_routing: $capability_affinity_summary,
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
          golden_cases: (["healthy", "degraded", "stale_proof", "high_cost", "collision_risk", "overloaded", "forecast_low_confidence", "execution_queue_conservative", "execution_queue_restore_blocked", "queue_fidelity_high_drift", "queue_fidelity_insufficient_evidence", "queue_tuning_promotion_blocked", "queue_tuning_promotion_stale_evidence", "queue_tuning_promotion_rollback_required", "queue_policy_adoption_expiry_required", "queue_policy_adoption_supersession_required", "causal_trace_degraded", "causal_trace_contaminated", "resource_envelope_healthy", "resource_envelope_degraded", "resource_envelope_blocked", "resource_envelope_contaminated", "topology_placement_healthy", "topology_placement_drifted", "topology_placement_expired", "topology_placement_blocked", "topology_queue_advisory_healthy", "topology_queue_advisory_degraded", "topology_queue_advisory_blocked", "topology_queue_advisory_contaminated", "benchmark_advisory_healthy", "benchmark_advisory_blocked_measurement", "benchmark_advisory_local_fallback_contaminated", "benchmark_advisory_stale_baseline", "benchmark_advisory_resource_saturation", "capability_affinity_healthy", "capability_affinity_degraded", "capability_affinity_blocked", "actionability_guard_healthy", "actionability_guard_blocked_divergence", "actionability_guard_stale_source", "actionability_guard_dirty_overlap"] + (if $control_surface_catalog_present then ["control_surface_catalog_healthy", "control_surface_catalog_no_match", "control_surface_catalog_drift_fail_closed", "control_surface_catalog_duplicate_warning", "control_surface_catalog_shadow_blocked", "control_surface_catalog_remote_proof_resident", "control_surface_catalog_proof_economy_what_if", "control_surface_catalog_build_storm_qos", "control_surface_catalog_worker_toolchain_mismatch", "control_surface_catalog_warm_target_roi", "control_surface_catalog_local_fallback_contaminated"] else [] end)),
          intended_renderer_repo: "/dp/frankentui",
          local_tui_renderer: false
        }
      }
      + (if $swarm_benchmark_present then {swarm_benchmark_responsiveness: $benchmark_advisory_summary} else {} end)
      + (if $swarm_topology_aware_queue_advisory_status != "missing" then {swarm_topology_aware_queue_advisory: $topology_queue_advisory_summary} else {} end)
      + (if $control_surface_catalog_present then {swarm_control_surface_catalog: $control_surface_catalog_summary} else {} end)),
      degraded: $degraded,
      recommendations: (
        if $staged_contamination_summary.severity == "critical" then
          [recommendation("reject_staged_contamination"; null; "staged ownership guard reports contamination")]
        elif $causal_trace_summary.readiness == "contaminated" then
          [recommendation("respect_causal_trace_contamination"; $causal_trace_summary.bead_id; "causal trace handoff is contaminated by fail-closed anomaly evidence")]
        elif $causal_trace_summary.readiness == "blocked" then
          [recommendation("complete_causal_trace_edges"; $causal_trace_summary.bead_id; "in-progress causal trace is missing required handoff edges")]
        elif $swarm_actionability_report_status != "missing" and $actionability_summary.readiness == "contaminated" then
          [recommendation("refresh_actionability_guard"; $actionability_summary.primary_candidate_id; "actionability guard report is stale or contaminated")]
        elif $swarm_actionability_report_status != "missing" and $actionability_summary.readiness == "blocked" then
          [recommendation("respect_actionability_guard_block"; $actionability_summary.primary_candidate_id; "actionability guard reports blocked or divergent claimability")]
        elif $swarm_actionability_report_status != "missing" and $actionability_summary.readiness == "degraded" then
          [recommendation("review_actionability_guard"; $actionability_summary.primary_candidate_id; "actionability guard cannot yet recommend a safe claim")]
        elif $swarm_benchmark_present and $benchmark_advisory_summary.readiness == "contaminated" then
          [recommendation("respect_benchmark_advisory_contamination"; $benchmark_advisory_summary.selected_workload_id; "benchmark responsiveness advisory is contaminated by fail-closed or unsafe mutation claims")]
        elif $swarm_benchmark_present and $benchmark_advisory_summary.readiness == "blocked" then
          [recommendation("respect_benchmark_measurement_block"; $benchmark_advisory_summary.selected_workload_id; "benchmark throughput evidence remains blocked and cannot support workload readiness claims")]
        elif $swarm_benchmark_present and $benchmark_advisory_summary.readiness == "degraded" then
          [recommendation("review_benchmark_advisory"; $benchmark_advisory_summary.selected_workload_id; "benchmark responsiveness advisory is degraded by stale, saturated, or incomplete evidence")]
        elif $resource_envelope_summary.readiness == "contaminated" then
          [recommendation("respect_resource_envelope_contamination"; null; "resource envelope or fair-share plan is contaminated by fail-closed capacity evidence")]
        elif $resource_envelope_summary.readiness == "blocked" then
          [recommendation("respect_resource_envelope_block"; null; "resource envelope reports saturated but trustworthy capacity")]
        elif $resource_envelope_summary.readiness == "degraded" then
          [recommendation("refresh_resource_envelope"; null; "resource envelope or fair-share plan is missing or degraded")]
        elif $topology_placement_summary.readiness == "contaminated" then
          [recommendation("respect_topology_placement_contamination"; null; "topology placement evidence is contaminated by fail-closed or unsafe mutation claims")]
        elif $topology_placement_summary.readiness == "blocked" then
          [recommendation("respect_topology_placement_block"; null; "topology placement evidence is blocked by contradictory locality or non-adoptable receipt state")]
        elif $topology_placement_summary.readiness == "degraded" then
          [recommendation("review_topology_placement_advisory"; null; "topology placement evidence has drift, expiry, pending observation, or degraded cache-residency assumptions")]
        elif $swarm_topology_aware_queue_advisory_status != "missing" and $topology_queue_advisory_summary.readiness == "contaminated" then
          [recommendation("respect_topology_queue_advisory_contamination"; null; "topology-aware queue advisory is contaminated by local fallback or unsafe mutation claims")]
        elif $swarm_topology_aware_queue_advisory_status != "missing" and $topology_queue_advisory_summary.readiness == "blocked" then
          [recommendation("respect_topology_queue_advisory_block"; null; "topology-aware queue advisory is blocked by contradictory locality evidence")]
        elif $swarm_topology_aware_queue_advisory_status != "missing" and $topology_queue_advisory_summary.readiness == "degraded" then
          [recommendation("review_topology_queue_advisory"; null; "topology-aware queue advisory has missing locality support, cache-miss feedback, or degraded queue evidence")]
        elif $control_surface_catalog_present and $control_surface_catalog_summary.readiness == "contaminated" then
          [recommendation("respect_control_surface_catalog_fail_closed"; null; "control-surface catalog routing evidence failed closed or carries unsafe mutation claims")]
        elif $control_surface_catalog_present and $control_surface_catalog_summary.readiness == "blocked" then
          [recommendation("respect_control_surface_catalog_block"; null; "control-surface catalog routing is blocked by ownership, route, or active-lane evidence")]
        elif $control_surface_catalog_present and $control_surface_catalog_summary.readiness == "degraded" then
          [recommendation("review_control_surface_catalog_routing"; null; "control-surface catalog, intent-router, or drift-gate evidence is incomplete or degraded")]
        elif $capability_affinity_summary.readiness == "contaminated" then
          [recommendation("respect_capability_affinity_contamination"; null; "capability-affinity routing evidence is contaminated by fail-closed or unsafe mutation claims")]
        elif $capability_affinity_summary.readiness == "blocked" then
          [recommendation("respect_capability_affinity_block"; null; "capability-affinity routing evidence is blocked by unsupported capability coverage or toolchain drift")]
        elif $capability_affinity_summary.readiness == "degraded" then
          [recommendation("review_capability_affinity_advisory"; null; "capability-affinity routing evidence has mismatch, broader-cohort fallback, or degraded support evidence")]
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
      artifact_paths: ({
        status_json: $status_path,
        commands_txt: $commands_path,
        report_md: $report_path,
        capacity_forecast_json: $capacity_forecast_summary.artifact_path,
        admission_budget_plan_json: $admission_budget_summary.artifact_path,
        swarm_resource_envelope_json: $resource_envelope_summary.artifact_paths.resource_envelope_json,
        swarm_fair_share_batch_plan_json: $resource_envelope_summary.artifact_paths.fair_share_batch_plan_json,
        swarm_topology_placement_plan_json: $topology_placement_summary.artifact_paths.placement_plan_json,
        swarm_topology_placement_receipt_json: $topology_placement_summary.artifact_paths.placement_receipt_json,
        swarm_topology_placement_evidence_ledger_json: $topology_placement_summary.artifact_paths.placement_evidence_ledger_json,
        swarm_capability_affinity_routing_advisory_json: $capability_affinity_summary.artifact_paths.routing_advisory_json,
        swarm_capability_affinity_routing_outcome_ledger_json: $capability_affinity_summary.artifact_paths.outcome_ledger_json,
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
        swarm_agent_causal_trace_anomaly_report_json: $causal_trace_summary.artifact_paths.anomaly_report_json,
        swarm_actionability_report_json: $actionability_summary.artifact_paths.actionability_report_json
      } + (if $swarm_benchmark_present then {
        swarm_benchmark_workload_catalog_json: $benchmark_advisory_summary.artifact_paths.workload_catalog_json,
        swarm_benchmark_catalog_findings_json: $benchmark_advisory_summary.artifact_paths.catalog_findings_json,
        swarm_benchmark_responsiveness_advisory_json: $benchmark_advisory_summary.artifact_paths.responsiveness_advisory_json
      } else {} end) + (if $control_surface_catalog_present then {
        swarm_control_surface_catalog_json: $control_surface_catalog_summary.artifact_paths.catalog_json,
        swarm_control_surface_intent_plan_json: $control_surface_catalog_summary.artifact_paths.intent_plan_json,
        swarm_control_surface_drift_report_json: $control_surface_catalog_summary.artifact_paths.drift_report_json
      } else {} end))
    }
JQ

{
  printf '# Swarm Operator Status\n\n'
  printf -- "- Status: \`%s\`\n" "$(jq -r '.status' "$status_path")"
  printf -- "- Ready beads: \`%s\`\n" "$(jq '.summary.ready_count' "$status_path")"
  printf -- "- In progress: \`%s\`\n" "$(jq '.summary.in_progress_count' "$status_path")"
  printf -- "- Degraded fields: \`%s\`\n\n" "$(jq '.summary.degraded_count' "$status_path")"
  printf -- "- Dashboard contract: \`%s\` via \`%s\`\n" "$(jq -r '.dashboard_contract.schema_version' "$status_path")" "$(jq -r '.dashboard_contract.renderer.provider' "$status_path")"
  printf -- "- Forecast confidence: \`%s\` / \`%s\`\n" "$(jq -r '.summary.forecast_confidence_band' "$status_path")" "$(jq -r '.summary.forecast_overall_state' "$status_path")"
  printf -- "- Admission budget: \`%s\` with \`%s\` deferred\n" "$(jq -r '.summary.admission_budget_profile' "$status_path")" "$(jq '.summary.admission_deferred_count' "$status_path")"
  printf -- "- Resource envelope: \`%s\` / \`%s\` with \`%s\` admitted and \`%s\` deferred\n" "$(jq -r '.summary.resource_envelope_readiness' "$status_path")" "$(jq -r '.summary.fair_share_decision' "$status_path")" "$(jq '.summary.fair_share_admitted_count' "$status_path")" "$(jq '.summary.fair_share_deferred_count' "$status_path")"
  printf -- "- Topology placement: \`%s\` class=\`%s\` cache=\`%s\` adoption=\`%s\`\n" "$(jq -r '.summary.topology_placement_readiness' "$status_path")" "$(jq -r '.summary.topology_placement_topology_class' "$status_path")" "$(jq -r '.summary.topology_placement_warm_cache_state' "$status_path")" "$(jq -r '.summary.topology_placement_adoption_status' "$status_path")"
  if jq -e '.predictive_dashboard | has("swarm_topology_aware_queue_advisory")' "$status_path" >/dev/null; then
    printf -- "- Topology queue advisory: \`%s\` decision=\`%s\` bias=\`%s\` excluded=\`%s\`\n" "$(jq -r '.predictive_dashboard.swarm_topology_aware_queue_advisory.readiness' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_topology_aware_queue_advisory.advisory_decision' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_topology_aware_queue_advisory.rank_bias_mode' "$status_path")" "$(jq '.predictive_dashboard.swarm_topology_aware_queue_advisory.worker_exclusions.excluded_worker_count' "$status_path")"
  fi
  if jq -e '.predictive_dashboard | has("swarm_control_surface_catalog")' "$status_path" >/dev/null; then
    printf -- "- Control surface catalog: \`%s\` decision=\`%s\` surfaces=\`%s\` drift=\`%s\` top=\`%s\` track=\`%s\` script=\`%s\` commands=\`%s\`\n" "$(jq -r '.predictive_dashboard.swarm_control_surface_catalog.readiness' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_control_surface_catalog.catalog_decision' "$status_path")" "$(jq '.predictive_dashboard.swarm_control_surface_catalog.surface_count' "$status_path")" "$(jq '.predictive_dashboard.swarm_control_surface_catalog.drift_count' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_control_surface_catalog.top_recommended_surface // "none"' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_control_surface_catalog.top_recommended_track // "none"' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_control_surface_catalog.top_recommended_script // "none"' "$status_path")" "$(jq '.predictive_dashboard.swarm_control_surface_catalog.recommended_command_count' "$status_path")"
    printf -- "  - Control surface handoff: section=\`%s\` purpose=\`%s\` fail=\`%s\` degraded=\`%s\` blocked=\`%s\`\n" "$(jq -r '.predictive_dashboard.swarm_control_surface_catalog.top_recommended_operator_status_section // "none"' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_control_surface_catalog.top_recommended_purpose // "none"' "$status_path")" "$(jq -c '.predictive_dashboard.swarm_control_surface_catalog.fail_closed_reason_codes' "$status_path")" "$(jq -c '.predictive_dashboard.swarm_control_surface_catalog.degraded_reason_codes' "$status_path")" "$(jq -c '.predictive_dashboard.swarm_control_surface_catalog.blocked_reason_codes' "$status_path")"
  fi
  if jq -e '.predictive_dashboard | has("swarm_actionability_guard")' "$status_path" >/dev/null; then
    printf -- "- Actionability guard: \`%s\` decision=\`%s\` candidate=\`%s\` reasons=\`%s\`\n" "$(jq -r '.predictive_dashboard.swarm_actionability_guard.readiness' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_actionability_guard.guard_decision' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_actionability_guard.primary_candidate_id // "none"' "$status_path")" "$(jq '.predictive_dashboard.swarm_actionability_guard.reason_codes | length' "$status_path")"
  fi
  if jq -e '.predictive_dashboard | has("swarm_benchmark_responsiveness")' "$status_path" >/dev/null; then
    printf -- "- Benchmark advisory: \`%s\` workload=\`%s\` class=\`%s\` gap=\`%s\` utilization=\`%s\`\n" "$(jq -r '.predictive_dashboard.swarm_benchmark_responsiveness.readiness' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_benchmark_responsiveness.selected_workload_id // "none"' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_benchmark_responsiveness.benchmark_class // "unknown"' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_benchmark_responsiveness.throughput_gap_band' "$status_path")" "$(jq -r '.predictive_dashboard.swarm_benchmark_responsiveness.utilization_pressure_band' "$status_path")"
  fi
  printf -- "- Capability affinity: \`%s\` mode=\`%s\` preferred=\`%s\` mismatch=\`%s\` gap=\`%s\` drift=\`%s\`\n" "$(jq -r '.summary.capability_affinity_readiness' "$status_path")" "$(jq -r '.summary.capability_affinity_routing_mode' "$status_path")" "$(jq '.summary.capability_affinity_preferred_worker_count' "$status_path")" "$(jq '.summary.capability_affinity_mismatch_count' "$status_path")" "$(jq '.summary.capability_affinity_capability_gap_count' "$status_path")" "$(jq '.summary.capability_affinity_toolchain_drift_count' "$status_path")"
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
    ([
      {label:"Capacity forecast", path:.artifact_paths.capacity_forecast_json},
      {label:"Admission budget plan", path:.artifact_paths.admission_budget_plan_json},
      {label:"Swarm resource envelope", path:.artifact_paths.swarm_resource_envelope_json},
      {label:"Swarm fair-share batch plan", path:.artifact_paths.swarm_fair_share_batch_plan_json},
      {label:"Swarm topology placement plan", path:.artifact_paths.swarm_topology_placement_plan_json},
      {label:"Swarm topology placement receipt", path:.artifact_paths.swarm_topology_placement_receipt_json},
      {label:"Swarm topology placement evidence ledger", path:.artifact_paths.swarm_topology_placement_evidence_ledger_json},
      {label:"Swarm actionability report", path:.artifact_paths.swarm_actionability_report_json},
      {label:"Swarm capability-affinity routing advisory", path:.artifact_paths.swarm_capability_affinity_routing_advisory_json},
      {label:"Swarm capability-affinity routing outcome ledger", path:.artifact_paths.swarm_capability_affinity_routing_outcome_ledger_json},
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
    ] + (if (.predictive_dashboard | has("swarm_control_surface_catalog")) then [
      {label:"Swarm control-surface catalog", path:.artifact_paths.swarm_control_surface_catalog_json},
      {label:"Swarm control-surface intent plan", path:.artifact_paths.swarm_control_surface_intent_plan_json},
      {label:"Swarm control-surface drift report", path:.artifact_paths.swarm_control_surface_drift_report_json}
    ] else [] end))[]
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
