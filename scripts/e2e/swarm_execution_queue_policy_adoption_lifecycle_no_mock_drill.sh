#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
adoption_writer="${root_dir}/scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh"
sustained_scorer="${root_dir}/scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh"
expiry_planner="${root_dir}/scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_runbook_truth_gate.sh"
contract_path="${root_dir}/docs/swarm_execution_queue_policy_adoption_lifecycle_drill_contract_v1.json"
mode="${1:-check}"
artifact_root="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_LIFECYCLE_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-policy-adoption-lifecycle}"
run_id="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_LIFECYCLE_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_LIFECYCLE_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-policy-adoption-lifecycle-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-policy-adoption-lifecycle-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh [check|selftest]

Runs a deterministic fixture-fed lifecycle drill through the real adoption
writer, sustained-gain scorer, expiry/supersession planner, and operator-status
producer. The fixtures are synthetic; the producers are not mocked.
EOF
}

run_check() {
  for path in "$adoption_writer" "$sustained_scorer" "$expiry_planner" "$operator_status" "$truth_gate" "$contract_path"; do
    [[ -f "$path" ]] || record_failure "missing required path ${path#"$root_dir"/}"
  done
  bash -n "$adoption_writer" "$sustained_scorer" "$expiry_planner" "$operator_status" "$truth_gate"
  jq empty "$contract_path" >/dev/null
  bash "$truth_gate" check >/dev/null

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static lifecycle contract validates"
}

write_adoption_inputs() {
  local input_dir="$1"
  mkdir -p "$input_dir"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
    bundle_id:"queue-policy-lifecycle-bundle",
    source_revision:"selftest",
    generated_at:"2026-05-06T00:00:00Z",
    decision:"pass",
    promoted_candidate:{candidate_id:"raise_proof_health_penalty",expected_fidelity_delta_millionths:240000,confidence_band:"high",safety_status:"safe_to_replay",source_tuning_plan_json:"tuning_plan.json"},
    evidence_links:[{artifact_kind:"fidelity_score_receipt_json",path:"fidelity_score_receipt.json",sha256:"fixture"}],
    manual_approval:{required:true,approver_role:"human_operator",approval_artifact_path:"approvals/manual-approval.required.json"},
    canary_constraints:{enabled:true,observation_window_seconds:1800,max_queue_depth_delta:1,max_candidate_weight_delta_millionths:200000,rollback_on_drift_classes:["proof_drift","ownership_drift","restore_drift"],stop_on_missing_evidence:true},
    rollback_references:{prior_policy_bundle_id:"queue-policy-lifecycle-bundle",prior_frontier_json:"frontier/prior.json",rollback_comparator_report_json:"rollback/comparator.json",canary_verdict_ledger_json:"rollback/canary.json"},
    mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
    automation_claim:"none"
  }' >"${input_dir}/candidate_bundle.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-tuning-promotion-guard-receipt.v1",
    decision:"eligible_canary",
    candidate_bundle_id:"queue-policy-lifecycle-bundle",
    candidate_id:"raise_proof_health_penalty",
    expected_fidelity_delta_millionths:240000,
    reject_reasons:[],
    manual_approval_blockers:[],
    mutation_policy:{changes_active_queue:false,applies_live_retuning:false,advisory_only:true}
  }' >"${input_dir}/promotion_guard_receipt.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1",
    decision:"eligible_canary",
    candidate_bundle_id:"queue-policy-lifecycle-bundle",
    candidate_id:"raise_proof_health_penalty",
    manual_approval:{required:true,blockers:[]},
    stop_conditions:[],
    rejection_reasons:[],
    mutation_policy:{changes_active_queue:false,applies_live_retuning:false,advisory_only:true}
  }' >"${input_dir}/rollout_plan.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-tuning-rollback-comparator-receipt.v1",
    verdict:"better_than_current",
    candidate_bundle_id:"queue-policy-lifecycle-bundle",
    candidate_id:"raise_proof_health_penalty",
    current_fidelity_millionths:760000,
    candidate_expected_fidelity_millionths:1000000,
    candidate_delta_millionths:240000,
    mutation_policy:{changes_active_queue:false,applies_live_retuning:false,advisory_only:true}
  }' >"${input_dir}/rollback_comparator_receipt.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-canary-verdict-ledger.v1",
    verdict:"canary_running",
    recommended_action:"continue_canary",
    candidate_bundle_id:"queue-policy-lifecycle-bundle",
    candidate_id:"raise_proof_health_penalty",
    rollback_triggers:[],
    fail_closed_reasons:[],
    mutation_policy:{changes_active_queue:false,applies_live_retuning:false,advisory_only:true}
  }' >"${input_dir}/canary_verdict_ledger.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-policy-adoption-operator-decision.v1",
    decision:"adopt",
    adopted_policy_bundle_id:"queue-policy-lifecycle-bundle",
    approved_by:"human_operator",
    approved_at:"2026-05-06T00:00:00Z",
    approval_artifact_path:"approvals/queue-policy-adoption.json",
    decision_reason:"lifecycle drill fixture",
    adoption_state:"recorded_active_policy",
    observation_window:{starts_at:"2026-05-06T00:00:00Z",duration_seconds:3600,minimum_sample_count:3,monitored_metrics:["queue_fidelity_millionths","proof_drift_count","rollback_trigger_count"],stop_on_missing_evidence:true},
    supersession:{supersedes_adoption_receipt_id:null,supersedes_policy_bundle_id:"current-queue-policy",supersession_reason:"lifecycle drill",previous_policy_retention:"retain_for_rollback",expiry_policy:"score after window"},
    mutation_policy:{receipt_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
    automation_claim:"none"
  }' >"${input_dir}/operator_decision.json"
}

write_post_adoption_inputs() {
  local input_dir="$1"
  mkdir -p "$input_dir"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-fidelity-score-receipt.v1",
    source_revision:"selftest",
    decision:"pass",
    overall_fidelity_millionths:900000,
    confidence_band:"high",
    summary:{row_count:4,fail_closed_reason_count:0,degraded_input_count:0}
  }' >"${input_dir}/post_adoption_fidelity_score_receipt.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-drift-ledger.v1",
    source_revision:"selftest",
    decision:"pass",
    rows:[{task_id:"bd-post-adoption-a",drift_class:"none",mismatch_class:"exact_match",row_score_millionths:920000,remediation:"retain adopted policy under current evidence"}],
    fail_closed_reasons:[],
    degraded_inputs:[]
  }' >"${input_dir}/post_adoption_drift_ledger.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-policy-evidence-ownership.v1",
    source_revision:"selftest",
    rows:[
      {artifact_kind:"adoption_receipt_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
      {artifact_kind:"adoption_snapshot_bundle_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
      {artifact_kind:"post_adoption_fidelity_score_receipt_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
      {artifact_kind:"post_adoption_drift_ledger_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
      {artifact_kind:"sustained_gain_receipt_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
      {artifact_kind:"newer_candidate_bundle_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false}
    ],
    mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
  }' >"${input_dir}/evidence_ownership.json"
}

run_selftest() {
  local input_dir="${run_dir}/inputs"
  local post_dir="${run_dir}/post_adoption_inputs"
  local adoption_dir="${run_dir}/adoption"
  local sustained_dir="${run_dir}/sustained_gain"
  local expiry_dir="${run_dir}/expiry_supersession"
  local operator_dir="${run_dir}/operator_status"
  local receipt_path="${run_dir}/adoption_lifecycle_drill_receipt.json"
  local commands_path="${run_dir}/commands.txt"
  local report_path="${run_dir}/report.md"

  run_check
  mkdir -p "$run_dir" "$adoption_dir" "$sustained_dir" "$expiry_dir" "$operator_dir"
  write_adoption_inputs "$input_dir"
  write_post_adoption_inputs "$post_dir"
  printf './scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh selftest\n' >"$commands_path"

  env SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$adoption_writer" \
      --candidate-bundle-json "${input_dir}/candidate_bundle.json" \
      --promotion-guard-receipt-json "${input_dir}/promotion_guard_receipt.json" \
      --rollout-plan-json "${input_dir}/rollout_plan.json" \
      --rollback-comparator-receipt-json "${input_dir}/rollback_comparator_receipt.json" \
      --canary-verdict-ledger-json "${input_dir}/canary_verdict_ledger.json" \
      --operator-decision-json "${input_dir}/operator_decision.json" \
      --source-revision "lifecycle-selftest" \
      --output-dir "$adoption_dir" >/dev/null

  env SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_GENERATED_AT="2026-05-06T01:00:00Z" \
    bash "$sustained_scorer" \
      --adoption-receipt-json "${adoption_dir}/adoption_receipt.json" \
      --adoption-snapshot-bundle-json "${adoption_dir}/adoption_snapshot_bundle.json" \
      --post-adoption-fidelity-score-receipt-json "${post_dir}/post_adoption_fidelity_score_receipt.json" \
      --post-adoption-drift-ledger-json "${post_dir}/post_adoption_drift_ledger.json" \
      --evidence-ownership-json "${post_dir}/evidence_ownership.json" \
      --source-revision "lifecycle-selftest" \
      --output-dir "$sustained_dir" >/dev/null

  env SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_GENERATED_AT="2026-05-06T02:00:00Z" \
    bash "$expiry_planner" \
      --adoption-receipt-json "${adoption_dir}/adoption_receipt.json" \
      --sustained-gain-receipt-json "${sustained_dir}/sustained_gain_receipt.json" \
      --post-adoption-drift-ledger-json "${sustained_dir}/post_adoption_drift_ledger.json" \
      --newer-candidate-bundle-json "${input_dir}/candidate_bundle.json" \
      --evidence-ownership-json "${post_dir}/evidence_ownership.json" \
      --source-revision "lifecycle-selftest" \
      --output-dir "$expiry_dir" >/dev/null

  bash "$operator_status" \
    --bead-id bd-k6ng4 \
    --source-revision lifecycle-selftest \
    --output-dir "$operator_dir" \
    --agent-mail-status ok \
    --rch-status ok \
    --proof-index-status ok \
    --queue-policy-adoption-receipt-json "${adoption_dir}/adoption_receipt.json" \
    --queue-policy-adoption-snapshot-bundle-json "${adoption_dir}/adoption_snapshot_bundle.json" \
    --queue-policy-sustained-gain-receipt-json "${sustained_dir}/sustained_gain_receipt.json" \
    --queue-policy-expiry-supersession-plan-json "${expiry_dir}/expiry_supersession_plan.json" \
    --queue-policy-expiry-supersession-ledger-json "${expiry_dir}/expiry_supersession_ledger.json" >/dev/null

  jq -e '
    .decision == "admitted"
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
  ' "${adoption_dir}/adoption_receipt.json" >/dev/null || record_failure "adoption receipt did not admit"
  jq -e '.verdict == "sustained_gain"' "${sustained_dir}/sustained_gain_receipt.json" >/dev/null || record_failure "sustained-gain verdict mismatch"
  jq -e '.decision == "retain_adopted_policy" and .advisory_status.execution_state == "advisory_not_executed"' "${expiry_dir}/expiry_supersession_plan.json" >/dev/null || record_failure "expiry plan mismatch"
  jq -e '
    .predictive_dashboard.queue_policy_adoption.readiness == "retained"
    and .predictive_dashboard.queue_policy_adoption.sustained_gain_verdict == "sustained_gain"
    and .predictive_dashboard.queue_policy_adoption.expiry_decision == "retain_adopted_policy"
    and .predictive_dashboard.queue_policy_adoption.mutation_policy.advisory_only == true
    and .predictive_dashboard.queue_policy_adoption.mutation_policy.retirement_executed == false
    and .predictive_dashboard.queue_policy_adoption.mutation_policy.supersession_executed == false
  ' "${operator_dir}/status.json" >/dev/null || record_failure "operator lifecycle section mismatch"

  jq -n \
    --arg adoption_receipt_json "${adoption_dir}/adoption_receipt.json" \
    --arg adoption_snapshot_bundle_json "${adoption_dir}/adoption_snapshot_bundle.json" \
    --arg sustained_gain_receipt_json "${sustained_dir}/sustained_gain_receipt.json" \
    --arg post_adoption_drift_ledger_json "${sustained_dir}/post_adoption_drift_ledger.json" \
    --arg expiry_supersession_plan_json "${expiry_dir}/expiry_supersession_plan.json" \
    --arg expiry_supersession_ledger_json "${expiry_dir}/expiry_supersession_ledger.json" \
    --arg operator_status_json "${operator_dir}/status.json" \
    --arg commands_txt "$commands_path" \
    --arg report_md "$report_path" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-adoption-lifecycle-drill-receipt.v1",
      decision:"pass",
      producer_chain:[
        "scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh",
        "scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh",
        "scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh",
        "scripts/swarm_operator_status_report.sh"
      ],
      assertions:{
        adoption_decision:"admitted",
        sustained_gain_verdict:"sustained_gain",
        expiry_decision:"retain_adopted_policy",
        operator_status_readiness:"retained",
        advisory_only:true
      },
      artifact_paths:{
        adoption_receipt_json:$adoption_receipt_json,
        adoption_snapshot_bundle_json:$adoption_snapshot_bundle_json,
        sustained_gain_receipt_json:$sustained_gain_receipt_json,
        post_adoption_drift_ledger_json:$post_adoption_drift_ledger_json,
        expiry_supersession_plan_json:$expiry_supersession_plan_json,
        expiry_supersession_ledger_json:$expiry_supersession_ledger_json,
        operator_status_json:$operator_status_json,
        commands_txt:$commands_txt,
        report_md:$report_md
      },
      mutation_policy:{
        no_mock_e2e_only:true,
        changes_active_queue:false,
        applies_live_retuning:false,
        mutates_br:false,
        sends_agent_mail:false,
        mutates_remote_workers:false,
        rewrites_historical_outcomes:false,
        retirement_executed:false,
        supersession_executed:false
      }
    }' >"$receipt_path"

  {
    printf '# Queue Policy Adoption Lifecycle Drill\n\n'
    printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$receipt_path")"
    printf -- "- Adoption: \`%s\`\n" "$(jq -r '.assertions.adoption_decision' "$receipt_path")"
    printf -- "- Sustained gain: \`%s\`\n" "$(jq -r '.assertions.sustained_gain_verdict' "$receipt_path")"
    printf -- "- Expiry decision: \`%s\`\n" "$(jq -r '.assertions.expiry_decision' "$receipt_path")"
    printf -- "- Operator readiness: \`%s\`\n" "$(jq -r '.assertions.operator_status_readiness' "$receipt_path")"
  } >"$report_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "selftest real lifecycle producers"
  printf 'adoption_lifecycle_drill_receipt=%s\n' "$receipt_path"
  printf 'adoption_lifecycle_drill_report=%s\n' "$report_path"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
