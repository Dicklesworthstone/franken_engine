#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
comparator="${root_dir}/scripts/swarm_execution_queue_tuning_rollback_comparator.sh"
bundle_contract_smoke="${root_dir}/scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR.md"
contract_path="${root_dir}/docs/swarm_execution_queue_tuning_rollback_comparator_contract_v1.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-tuning-rollback-comparator %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-tuning-rollback-comparator %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_tuning_rollback_comparator_smoke.sh [check|selftest]

Validates the advisory-only queue tuning rollback comparator with deterministic
receipts for better-than-current, worse-than-current, ambiguous verdict, and
missing rollback evidence.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatic retuning is allowed|automatically retunes|applies retuning automatically|changes active queue automatically|manual approval is optional|manual approval may be skipped|live queue mutation surface|does not reject local fallback proof|local fallback proof is acceptable' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe automation, approval, or local-fallback wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$line" != *"rch exec --"* || "$line" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${line}"
      fi
    fi
  done <"$path"
}

run_check() {
  if [[ ! -f "$comparator" ]]; then
    record_failure "missing comparator ${comparator}"
    return 1
  fi
  if [[ ! -f "$docs_path" ]]; then
    record_failure "missing docs ${docs_path}"
    return 1
  fi
  if [[ ! -f "$contract_path" ]]; then
    record_failure "missing contract ${contract_path}"
    return 1
  fi

  bash -n "$comparator"
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-tuning-rollback-comparator-contract.v1"
    and .bead_id == "bd-j2rny.4"
    and .parent_bead_id == "bd-j2rny"
    and (.depends_on | index("bd-j2rny.2") != null)
    and .script == "scripts/swarm_execution_queue_tuning_rollback_comparator.sh"
    and .rollout_plan_schema_version == "franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1"
    and .current_policy_state_schema_version == "franken-engine.swarm-execution-queue-current-policy-state.v1"
    and .receipt_schema_version == "franken-engine.swarm-execution-queue-tuning-rollback-comparator-receipt.v1"
    and .canary_verdict_ledger_schema_version == "franken-engine.swarm-execution-queue-canary-verdict-ledger.v1"
    and (.verdicts | index("better_than_current") != null)
    and (.verdicts | index("worse_than_current") != null)
    and (.verdicts | index("ambiguous_verdict") != null)
    and (.verdicts | index("fail_closed") != null)
    and (.fail_closed_rules | index("missing hindsight/fidelity evidence fails closed") != null)
    and (.fail_closed_rules | index("rollback reference mismatch fails closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null || record_failure "rollback comparator contract shape mismatch"

  grep -Fq "advisory-only planning artifact" "$docs_path" || record_failure "docs missing advisory-only wording"
  grep -Fq "never changes active queue settings" "$docs_path" || record_failure "docs missing active queue non-mutation wording"
  grep -Fq "reject local fallback proof evidence" "$docs_path" || record_failure "docs missing local fallback rejection wording"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static rollback comparator contract validates"
}

write_bundle() {
  local path="$1"
  local scenario="$2"
  local delta="$3"
  local prior_id="${4:-current-policy-bundle}"
  local evidence_mode="${5:-complete}"
  local digest="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

  jq -n \
    --arg scenario "$scenario" \
    --arg prior_id "$prior_id" \
    --arg evidence_mode "$evidence_mode" \
    --arg digest "$digest" \
    --argjson delta "$delta" '
    {
      schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
      bundle_id:("queue-tuning-policy-bundle-" + $scenario),
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      decision:"pass",
      plan_class:(if $delta > 0 then "one_clear_improvement" elif $delta < 0 then "conflicting_improvements" else "no_improvement" end),
      promoted_candidate:{
        candidate_id:(if $delta == 0 then "baseline_current" else "raise_proof_health_penalty" end),
        expected_fidelity_delta_millionths:$delta,
        confidence_band:(if $delta >= 150000 then "high" elif $delta < 0 then "low" else "medium" end),
        safety_status:(if $delta < 0 then "unsafe" elif $delta == 0 then "no_change" else "safe_to_replay" end),
        source_tuning_plan_json:"counterfactual/tuning_plan.json"
      },
      evidence_links:[
        {artifact_kind:"fidelity_score_receipt_json",path:"fidelity/fidelity_score_receipt.json",sha256:$digest},
        {artifact_kind:"drift_ledger_json",path:"fidelity/drift_ledger.json",sha256:$digest},
        {artifact_kind:"counterfactual_backtest_report_json",path:"counterfactual/counterfactual_backtest_report.json",sha256:$digest},
        {artifact_kind:"tuning_plan_json",path:"counterfactual/tuning_plan.json",sha256:$digest},
        {artifact_kind:"frontier_json",path:"counterfactual/frontier.json",sha256:$digest},
        {artifact_kind:"operator_status_json",path:"operator-status/status.json",sha256:$digest}
      ] | if $evidence_mode == "missing" then map(select(.artifact_kind != "drift_ledger_json")) else . end,
      manual_approval:{required:true,approver_role:"human_operator",approval_artifact_path:"approvals/manual-approval.required.json"},
      canary_constraints:{
        enabled:true,
        observation_window_seconds:1800,
        max_queue_depth_delta:1,
        max_candidate_weight_delta_millionths:200000,
        rollback_on_drift_classes:["proof_drift","ownership_drift","restore_drift"],
        stop_on_missing_evidence:true
      },
      rollback_references:{
        prior_policy_bundle_id:$prior_id,
        prior_frontier_json:"rollback/prior_frontier.json",
        rollback_comparator_report_json:"rollback/comparator_report.json",
        canary_verdict_ledger_json:"rollback/canary_verdict_ledger.json"
      },
      mutation_policy:{
        planning_artifact_only:true,
        changes_active_queue:false,
        applies_live_retuning:false,
        mutates_br:false,
        sends_agent_mail:false,
        mutates_remote_workers:false,
        rewrites_historical_outcomes:false
      },
      automation_claim:"none",
      fail_closed_rules:[
        "missing evidence links fail closed",
        "manual approval missing fail closed",
        "rollback references missing fail closed",
        "automatic retuning claims fail closed",
        "unsafe canary constraints fail closed",
        "reject local fallback proof evidence"
      ]
    }' >"$path"
}

write_rollout_plan() {
  local path="$1"
  local scenario="$2"
  local bundle_id="queue-tuning-policy-bundle-${scenario}"

  jq -n --arg bundle_id "$bundle_id" '{
    schema_version:"franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1",
    source_revision:"selftest",
    generated_at:"2026-05-06T00:00:00Z",
    decision:"eligible_canary",
    candidate_bundle_id:$bundle_id,
    candidate_id:"raise_proof_health_penalty",
    manual_approval:{required:true,approval_artifact_path:"approvals/manual-approval.required.json",approver_role:"human_operator"},
    canary_recommendation:{stage_order:["manual_review","shadow_canary","bounded_queue_canary","canary_verdict_review"],observation_window_seconds:1800,max_queue_depth_delta:1,max_candidate_weight_delta_millionths:200000},
    stop_conditions:["reject local fallback proof evidence"],
    rejection_reasons:[],
    mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
  }' >"$path"
}

write_policy_state() {
  local path="$1"
  local rollback_mode="${2:-complete}"

  jq -n --arg rollback_mode "$rollback_mode" '{
    schema_version:"franken-engine.swarm-execution-queue-current-policy-state.v1",
    source_revision:"selftest",
    current_policy_bundle_id:"current-policy-bundle",
    evidence_freshness:"fresh",
    current_policy_metrics:{overall_fidelity_millionths:700000},
    rollback_material:{
      prior_frontier_available:true,
      rollback_comparator_available:($rollback_mode == "complete"),
      canary_verdict_ledger_available:true
    },
    mutation_policy:{changes_active_queue:false,applies_live_retuning:false}
  }' >"$path"
}

run_comparator_case() {
  local scenario="$1"
  local delta="$2"
  local expected_exit="$3"
  local expected_verdict="$4"
  local rollback_mode="${5:-complete}"
  local evidence_mode="${6:-complete}"
  local tmp_root bundle_path plan_path state_path output_dir exit_code receipt_path ledger_path

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-tuning-rollback-comparator.XXXXXX")"
  bundle_path="${tmp_root}/${scenario}-bundle.json"
  plan_path="${tmp_root}/${scenario}-rollout-plan.json"
  state_path="${tmp_root}/${scenario}-policy-state.json"
  output_dir="${tmp_root}/${scenario}-output"
  mkdir -p "$output_dir"

  write_bundle "$bundle_path" "$scenario" "$delta" "current-policy-bundle" "$evidence_mode"
  write_rollout_plan "$plan_path" "$scenario"
  write_policy_state "$state_path" "$rollback_mode"

  if [[ "$evidence_mode" == "complete" ]]; then
    bash "$bundle_contract_smoke" validate-bundle "$bundle_path" >/dev/null
  fi

  set +e
  SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$comparator" \
      --candidate-bundle-json "$bundle_path" \
      --rollout-plan-json "$plan_path" \
      --current-policy-state-json "$state_path" \
      --source-revision "selftest-${scenario}" \
      --output-dir "$output_dir" >/dev/null 2>&1
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${scenario} exited ${exit_code}, expected ${expected_exit}"
    return 1
  fi

  receipt_path="${output_dir}/rollback_comparator_receipt.json"
  ledger_path="${output_dir}/canary_verdict_ledger.json"
  jq empty "$receipt_path" "$ledger_path"

  jq -e --arg expected_verdict "$expected_verdict" '
    .verdict == $expected_verdict
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
  ' "$receipt_path" >/dev/null || record_failure "${scenario} receipt mismatch"

  jq -e --arg expected_verdict "$expected_verdict" '
    .verdict == $expected_verdict
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and (.rollback_triggers | index("reject local fallback proof evidence") != null)
  ' "$ledger_path" >/dev/null || record_failure "${scenario} ledger mismatch"

  record_pass "selftest ${scenario}"
}

run_selftest() {
  run_check
  run_comparator_case "better_than_current" 240000 0 "better_than_current"
  run_comparator_case "worse_than_current" -100000 0 "worse_than_current"
  run_comparator_case "ambiguous_verdict" 50000 0 "ambiguous_verdict"
  run_comparator_case "missing_rollback_evidence" 240000 42 "fail_closed" "missing"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
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
