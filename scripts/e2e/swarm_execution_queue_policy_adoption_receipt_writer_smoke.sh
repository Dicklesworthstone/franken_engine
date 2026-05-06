#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
writer="${root_dir}/scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh"
receipt_contract_smoke="${root_dir}/scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_WRITER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_policy_adoption_receipt_writer_contract_v1.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-policy-adoption-receipt-writer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-policy-adoption-receipt-writer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_policy_adoption_receipt_writer_smoke.sh [check|selftest]

Validates the deterministic adoption receipt writer with shell/JQ fixtures for
eligible adoption, rejected promotion guard, worse rollback verdict, missing
operator approval, mismatched bundle id, and automatic adoption claims.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatically adopts|automatic adoption is allowed|automatically retunes|applies retuning automatically|changes active queue automatically|manual approval is optional|manual approval may be skipped|proves sustained gain|local fallback proof is acceptable|does not reject local fallback proof' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe automation, approval, sustained-gain, or local-fallback wording"
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
  if [[ ! -f "$writer" ]]; then
    record_failure "missing writer ${writer}"
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

  bash -n "$writer"
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-policy-adoption-receipt-writer-contract.v1"
    and .bead_id == "bd-adgrb"
    and .parent_bead_id == "bd-6qnx9"
    and (.depends_on | index("bd-my39p") != null)
    and (.depends_on | index("bd-j2rny") != null)
    and .script == "scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh"
    and .receipt_schema_version == "franken-engine.swarm-execution-queue-policy-adoption-receipt.v1"
    and .snapshot_schema_version == "franken-engine.swarm-execution-queue-policy-adoption-snapshot-bundle.v1"
    and ([.required_inputs[].field] | index("candidate_bundle_json") != null)
    and ([.required_inputs[].field] | index("promotion_guard_receipt_json") != null)
    and ([.required_inputs[].field] | index("rollout_plan_json") != null)
    and ([.required_inputs[].field] | index("rollback_comparator_receipt_json") != null)
    and ([.required_inputs[].field] | index("canary_verdict_ledger_json") != null)
    and ([.required_inputs[].field] | index("operator_decision_json") != null)
    and .admission_requirements.candidate_bundle_decision == "pass"
    and .admission_requirements.promotion_guard_decision == "eligible_canary"
    and .admission_requirements.rollback_comparator_verdict == "better_than_current"
    and .admission_requirements.operator_decision == "adopt"
    and .admission_requirements.bundle_ids_must_match == true
    and .mutation_policy.receipt_artifact_only == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and (.fail_closed_rules | index("non-eligible promotion guard decisions fail closed") != null)
    and (.fail_closed_rules | index("non-continuing canary verdicts fail closed") != null)
    and (.fail_closed_rules | index("contradictory bundle or candidate identities fail closed") != null)
    and (.fail_closed_rules | index("missing operator approval fails closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
  ' "$contract_path" >/dev/null || record_failure "writer contract shape mismatch"

  grep -Fq "never changes active queue settings" "$docs_path" || record_failure "docs missing active queue non-mutation wording"
  grep -Fq "never applies live retuning" "$docs_path" || record_failure "docs missing live retuning non-mutation wording"
  grep -Fq "never mutates \`br\`" "$docs_path" || record_failure "docs missing br non-mutation wording"
  grep -Fq "sustained gain" "$docs_path" || record_failure "docs missing sustained gain boundary"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static writer contract validates"
}

write_fixture_inputs() {
  local input_dir="$1"
  local scenario="$2"
  mkdir -p "$input_dir"

  local bundle_id="swarm-execution-queue-tuning-policy-bundle-smoke"
  local candidate_id="raise_proof_health_penalty"
  local guard_decision="eligible_canary"
  local rollout_decision="eligible_canary"
  local rollback_verdict="better_than_current"
  local canary_action="continue_canary"
  local operator_decision="adopt"
  local approval_path="approvals/queue-policy-adoption.json"
  local operator_bundle_id="$bundle_id"
  local automation_claim="none"

  case "$scenario" in
    eligible_adoption)
      ;;
    guard_reject)
      guard_decision="reject"
      rollout_decision="reject"
      ;;
    rollback_worse_than_current)
      rollback_verdict="worse_than_current"
      canary_action="rollback_required"
      ;;
    missing_operator_approval)
      approval_path=""
      ;;
    mismatched_bundle_id)
      operator_bundle_id="different-policy-bundle"
      ;;
    automatic_adoption_claim)
      automation_claim="automatically adopts and retunes the live queue"
      ;;
    *)
      record_failure "unknown fixture scenario ${scenario}"
      return 64
      ;;
  esac

  jq -n \
    --arg bundle_id "$bundle_id" \
    --arg candidate_id "$candidate_id" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
      bundle_id:$bundle_id,
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      decision:"pass",
      plan_class:"one_clear_improvement",
      promoted_candidate:{
        candidate_id:$candidate_id,
        expected_fidelity_delta_millionths:240000,
        confidence_band:"high",
        safety_status:"safe_to_replay",
        source_tuning_plan_json:"counterfactual/tuning_plan.json"
      },
      manual_approval:{required:true,approver_role:"human_operator",approval_artifact_path:"approvals/manual-approval.required.json"},
      rollback_references:{
        prior_policy_bundle_id:"current-policy-bundle",
        prior_frontier_json:"rollback/prior_frontier.json",
        rollback_comparator_report_json:"rollback/comparator_report.json",
        canary_verdict_ledger_json:"rollback/canary_verdict_ledger.json"
      },
      mutation_policy:{changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
    }' >"${input_dir}/candidate_bundle.json"

  jq -n \
    --arg decision "$guard_decision" \
    --arg bundle_id "$bundle_id" \
    --arg candidate_id "$candidate_id" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-promotion-guard-receipt.v1",
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      decision:$decision,
      candidate_bundle_id:$bundle_id,
      candidate_id:$candidate_id,
      expected_fidelity_delta_millionths:240000,
      mutation_policy:{changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false}
    }' >"${input_dir}/promotion_guard_receipt.json"

  jq -n \
    --arg decision "$rollout_decision" \
    --arg bundle_id "$bundle_id" \
    --arg candidate_id "$candidate_id" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1",
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      decision:$decision,
      candidate_bundle_id:$bundle_id,
      candidate_id:$candidate_id,
      manual_approval:{required:true,approval_artifact_path:"approvals/manual-approval.required.json",approver_role:"human_operator"},
      mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
    }' >"${input_dir}/rollout_plan.json"

  jq -n \
    --arg verdict "$rollback_verdict" \
    --arg bundle_id "$bundle_id" \
    --arg candidate_id "$candidate_id" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-rollback-comparator-receipt.v1",
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      verdict:$verdict,
      candidate_bundle_id:$bundle_id,
      candidate_id:$candidate_id,
      current_policy_bundle_id:"current-policy-bundle",
      candidate_delta_millionths:(if $verdict == "better_than_current" then 240000 else -64000 end),
      mutation_policy:{changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false}
    }' >"${input_dir}/rollback_comparator_receipt.json"

  jq -n \
    --arg verdict "$rollback_verdict" \
    --arg action "$canary_action" \
    --arg bundle_id "$bundle_id" \
    --arg candidate_id "$candidate_id" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-canary-verdict-ledger.v1",
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      candidate_bundle_id:$bundle_id,
      candidate_id:$candidate_id,
      verdict:$verdict,
      recommended_action:$action,
      mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
    }' >"${input_dir}/canary_verdict_ledger.json"

  jq -n \
    --arg decision "$operator_decision" \
    --arg approval_path "$approval_path" \
    --arg bundle_id "$operator_bundle_id" \
    --arg automation_claim "$automation_claim" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-adoption-operator-decision.v1",
      decision:$decision,
      approved_by:"human_operator",
      approved_at:"2026-05-06T00:00:00Z",
      approval_artifact_path:$approval_path,
      decision_reason:"eligible canary evidence is complete and rollback references are available",
      adoption_state:"recorded_pending_activation",
      adopted_policy_bundle_id:$bundle_id,
      observation_window:{
        starts_at:"2026-05-06T00:00:00Z",
        duration_seconds:3600,
        minimum_sample_count:3,
        monitored_metrics:["queue_fidelity_millionths","proof_drift_count","rollback_trigger_count"],
        stop_on_missing_evidence:true
      },
      supersession:{
        supersedes_adoption_receipt_id:null,
        supersedes_policy_bundle_id:"current-policy-bundle",
        supersession_reason:"first recorded policy adoption receipt for this lifecycle",
        previous_policy_retention:"retain_for_rollback",
        expiry_policy:"expire after observation window if drift scorer rejects sustained gain"
      },
      mutation_policy:{receipt_artifact_only:true,records_operator_decision:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
      automation_claim:$automation_claim
    }' >"${input_dir}/operator_decision.json"
}

run_writer_case() {
  local case_name="$1"
  local expected_code="$2"
  local expected_reason="${3:-}"
  local case_dir="$4"
  local input_dir="${case_dir}/inputs"
  local output_dir="${case_dir}/writer"
  local exit_code

  write_fixture_inputs "$input_dir" "$case_name"
  set +e
  env SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$writer" \
      --candidate-bundle-json "${input_dir}/candidate_bundle.json" \
      --promotion-guard-receipt-json "${input_dir}/promotion_guard_receipt.json" \
      --rollout-plan-json "${input_dir}/rollout_plan.json" \
      --rollback-comparator-receipt-json "${input_dir}/rollback_comparator_receipt.json" \
      --canary-verdict-ledger-json "${input_dir}/canary_verdict_ledger.json" \
      --operator-decision-json "${input_dir}/operator_decision.json" \
      --source-revision "selftest-${case_name}" \
      --output-dir "$output_dir" >/dev/null
  exit_code=$?
  set -e

  if [[ "$exit_code" != "$expected_code" ]]; then
    record_failure "${case_name} expected exit ${expected_code}, got ${exit_code}"
    return 1
  fi

  if [[ "$expected_code" == "0" ]]; then
    bash "$receipt_contract_smoke" validate-receipt "${output_dir}/adoption_receipt.json" >/dev/null
    jq -e '
      .schema_version == "franken-engine.swarm-execution-queue-policy-adoption-snapshot-bundle.v1"
      and .decision == "admitted"
      and ((.snapshot_id // "") | length > 0)
      and ((.adoption_receipt_id // "") | length > 0)
      and .mutation_policy.changes_active_queue == false
      and .mutation_policy.applies_live_retuning == false
    ' "${output_dir}/adoption_snapshot_bundle.json" >/dev/null || record_failure "${case_name} snapshot invariant mismatch"
    record_pass "selftest ${case_name}"
    return 0
  fi

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg expected_reason "$expected_reason" '
      .decision == "fail_closed"
      and any(.fail_closed_reasons[]; .kind == $expected_reason)
    ' "${output_dir}/adoption_receipt.json" >/dev/null || record_failure "${case_name} missing fail-closed reason ${expected_reason}"
  fi
  record_pass "selftest ${case_name}"
}

run_selftest() {
  local tmp_root
  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-policy-adoption-writer.XXXXXX")"

  run_writer_case "eligible_adoption" "0" "" "${tmp_root}/eligible_adoption"
  run_writer_case "guard_reject" "42" "promotion_guard_not_eligible" "${tmp_root}/guard_reject"
  run_writer_case "rollback_worse_than_current" "42" "rollback_verdict_not_adoptable" "${tmp_root}/rollback_worse_than_current"
  run_writer_case "missing_operator_approval" "42" "missing_operator_approval" "${tmp_root}/missing_operator_approval"
  run_writer_case "mismatched_bundle_id" "42" "operator_bundle_id_mismatch" "${tmp_root}/mismatched_bundle_id"
  run_writer_case "automatic_adoption_claim" "42" "unsafe_operator_claim" "${tmp_root}/automatic_adoption_claim"

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
