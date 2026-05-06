#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
guard="${root_dir}/scripts/swarm_execution_queue_tuning_promotion_guard.sh"
contract_smoke="${root_dir}/scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD.md"
contract_path="${root_dir}/docs/swarm_execution_queue_tuning_promotion_guard_contract_v1.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-tuning-promotion-guard %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-tuning-promotion-guard %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_tuning_promotion_guard_smoke.sh [check|selftest]

Validates the advisory-only queue tuning promotion guard and manual-approval
rollout planner across safe/no-op, eligible canary, stale evidence,
contradictory provenance, and auto-retune rejection scenarios.
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
  if [[ ! -f "$guard" ]]; then
    record_failure "missing guard ${guard}"
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

  bash -n "$guard"
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-tuning-promotion-guard-contract.v1"
    and .bead_id == "bd-j2rny.3"
    and .parent_bead_id == "bd-j2rny"
    and (.depends_on | index("bd-j2rny.2") != null)
    and .script == "scripts/swarm_execution_queue_tuning_promotion_guard.sh"
    and .current_policy_state_schema_version == "franken-engine.swarm-execution-queue-current-policy-state.v1"
    and .receipt_schema_version == "franken-engine.swarm-execution-queue-tuning-promotion-guard-receipt.v1"
    and .rollout_plan_schema_version == "franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1"
    and (.decisions | index("safe_noop") != null)
    and (.decisions | index("eligible_canary") != null)
    and (.decisions | index("reject") != null)
    and (.reject_rules | index("stale evidence rejects promotion") != null)
    and (.reject_rules | index("contradictory queue-policy provenance rejects promotion") != null)
    and (.reject_rules | index("autonomous scheduler mutation claims reject promotion") != null)
    and (.reject_rules | index("reject local fallback proof evidence") != null)
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null || record_failure "promotion guard contract shape mismatch"

  grep -Fq "advisory-only planning artifact" "$docs_path" || record_failure "docs missing advisory-only wording"
  grep -Fq "never changes active queue settings" "$docs_path" || record_failure "docs missing active queue non-mutation wording"
  grep -Fq "reject local fallback proof evidence" "$docs_path" || record_failure "docs missing local fallback rejection wording"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static promotion guard contract validates"
}

write_bundle() {
  local path="$1"
  local scenario="$2"
  local delta="$3"
  local plan_class="$4"
  local automation_claim="${5:-none}"
  local digest="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  jq -n \
    --arg scenario "$scenario" \
    --arg automation_claim "$automation_claim" \
    --argjson delta "$delta" \
    --arg plan_class "$plan_class" \
    --arg digest "$digest" '
    {
      schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
      bundle_id:("queue-tuning-policy-bundle-" + $scenario),
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      decision:"pass",
      plan_class:$plan_class,
      promoted_candidate:{
        candidate_id:(if $delta > 0 then "raise_proof_health_penalty" else "baseline_current" end),
        expected_fidelity_delta_millionths:$delta,
        confidence_band:(if $delta > 0 then "high" else "low" end),
        safety_status:(if $delta > 0 then "safe_to_replay" else "no_change" end),
        source_tuning_plan_json:"counterfactual/tuning_plan.json"
      },
      evidence_links:[
        {artifact_kind:"fidelity_score_receipt_json",path:"fidelity/fidelity_score_receipt.json",sha256:$digest},
        {artifact_kind:"drift_ledger_json",path:"fidelity/drift_ledger.json",sha256:$digest},
        {artifact_kind:"counterfactual_backtest_report_json",path:"counterfactual/counterfactual_backtest_report.json",sha256:$digest},
        {artifact_kind:"tuning_plan_json",path:"counterfactual/tuning_plan.json",sha256:$digest},
        {artifact_kind:"frontier_json",path:"counterfactual/frontier.json",sha256:$digest},
        {artifact_kind:"operator_status_json",path:"operator-status/status.json",sha256:$digest}
      ],
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
        prior_policy_bundle_id:"current-policy-bundle",
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
      automation_claim:$automation_claim,
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

write_policy_state() {
  local path="$1"
  local freshness="$2"
  local provenance="$3"
  local bundle_id="${4:-current-policy-bundle}"

  jq -n \
    --arg freshness "$freshness" \
    --arg provenance "$provenance" \
    --arg bundle_id "$bundle_id" '{
      schema_version:"franken-engine.swarm-execution-queue-current-policy-state.v1",
      source_revision:"selftest",
      current_policy_bundle_id:$bundle_id,
      evidence_freshness:$freshness,
      provenance_state:$provenance,
      rollback_material:{
        prior_frontier_available:true,
        rollback_comparator_available:true,
        canary_verdict_ledger_available:true
      },
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false
      }
    }' >"$path"
}

run_guard_case() {
  local scenario="$1"
  local expected_exit="$2"
  local expected_decision="$3"
  local bundle_delta="$4"
  local plan_class="$5"
  local freshness="$6"
  local provenance="$7"
  local automation_claim="${8:-none}"
  local policy_bundle_id="${9:-current-policy-bundle}"
  local tmp_root bundle_path state_path output_dir exit_code receipt_path plan_path

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-tuning-promotion-guard.XXXXXX")"
  bundle_path="${tmp_root}/${scenario}-bundle.json"
  state_path="${tmp_root}/${scenario}-policy-state.json"
  output_dir="${tmp_root}/${scenario}-output"
  mkdir -p "$output_dir"

  write_bundle "$bundle_path" "$scenario" "$bundle_delta" "$plan_class" "$automation_claim"
  write_policy_state "$state_path" "$freshness" "$provenance" "$policy_bundle_id"

  if [[ "$automation_claim" == "none" && "$expected_exit" -eq 0 ]]; then
    bash "$contract_smoke" validate-bundle "$bundle_path" >/dev/null
  fi

  set +e
  SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$guard" \
      --candidate-bundle-json "$bundle_path" \
      --current-policy-state-json "$state_path" \
      --source-revision "selftest-${scenario}" \
      --output-dir "$output_dir" >/dev/null 2>&1
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${scenario} exited ${exit_code}, expected ${expected_exit}"
    return 1
  fi

  receipt_path="${output_dir}/promotion_guard_receipt.json"
  plan_path="${output_dir}/manual_approval_rollout_plan.json"
  jq empty "$receipt_path" "$plan_path"

  jq -e \
    --arg expected_decision "$expected_decision" '
      .decision == $expected_decision
      and .mutation_policy.changes_active_queue == false
      and .mutation_policy.applies_live_retuning == false
      and .mutation_policy.mutates_br == false
    ' "$receipt_path" >/dev/null || record_failure "${scenario} receipt mismatch"

  jq -e \
    --arg expected_decision "$expected_decision" '
      .decision == $expected_decision
      and .manual_approval.required == true
      and .mutation_policy.changes_active_queue == false
      and .mutation_policy.applies_live_retuning == false
      and (.stop_conditions | index("reject local fallback proof evidence") != null)
    ' "$plan_path" >/dev/null || record_failure "${scenario} rollout plan mismatch"

  record_pass "selftest ${scenario}"
}

run_selftest() {
  run_check
  run_guard_case "safe_noop" 0 "safe_noop" 0 "no_improvement" "fresh" "consistent"
  run_guard_case "eligible_canary" 0 "eligible_canary" 240000 "one_clear_improvement" "fresh" "consistent"
  run_guard_case "stale_evidence_reject" 42 "reject" 240000 "one_clear_improvement" "stale" "consistent"
  run_guard_case "contradictory_provenance_reject" 42 "reject" 240000 "one_clear_improvement" "fresh" "contradictory"
  run_guard_case "auto_retune_reject" 42 "reject" 240000 "one_clear_improvement" "fresh" "consistent" "automatically retunes live queue"

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
