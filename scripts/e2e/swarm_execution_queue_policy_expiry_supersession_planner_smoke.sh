#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_PLANNER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_policy_expiry_supersession_planner_contract_v1.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-policy-expiry-supersession-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-policy-expiry-supersession-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_policy_expiry_supersession_planner_smoke.sh [check|selftest]

Validates the deterministic expiry/supersession planner with shell/JQ fixtures
for retain, expire, supersede, inconclusive retention, ambiguous ownership,
stale ownership, and conflicting candidate prior-policy evidence.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatically expires|automatically supersedes|automatic supersession is allowed|automatically retunes|applies retuning automatically|changes active queue automatically|manual approval is optional|manual approval may be skipped|local fallback proof is acceptable|does not reject local fallback proof' "$path"; then
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
  if [[ ! -f "$planner" ]]; then
    record_failure "missing planner ${planner}"
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

  bash -n "$planner"
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-policy-expiry-supersession-planner-contract.v1"
    and .bead_id == "bd-48ooe"
    and .parent_bead_id == "bd-6qnx9"
    and (.depends_on | index("bd-adgrb") != null)
    and (.depends_on | index("bd-mj81s") != null)
    and .script == "scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh"
    and .plan_schema_version == "franken-engine.swarm-execution-queue-policy-expiry-supersession-plan.v1"
    and .ledger_schema_version == "franken-engine.swarm-execution-queue-policy-expiry-supersession-ledger.v1"
    and ([.required_inputs[].field] | index("adoption_receipt_json") != null)
    and ([.required_inputs[].field] | index("sustained_gain_receipt_json") != null)
    and ([.required_inputs[].field] | index("post_adoption_drift_ledger_json") != null)
    and ([.required_inputs[].field] | index("newer_candidate_bundle_json") != null)
    and ([.required_inputs[].field] | index("evidence_ownership_json") != null)
    and .ownership_policy.ambiguous_owner_fails_closed == true
    and .ownership_policy.stale_or_rejected_evidence_fails_closed == true
    and .mutation_policy.planning_artifact_only == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.retirement_executed == false
    and .mutation_policy.supersession_executed == false
    and (.decisions | index("retain_adopted_policy") != null)
    and (.decisions | index("expire_adopted_policy") != null)
    and (.decisions | index("supersede_adopted_policy") != null)
    and (.fail_closed_rules | index("ambiguous evidence ownership fails closed") != null)
    and (.fail_closed_rules | index("stale or rejected evidence ownership fails closed") != null)
    and (.fail_closed_rules | index("conflicting candidate prior-policy references fail closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
  ' "$contract_path" >/dev/null || record_failure "expiry/supersession planner contract shape mismatch"

  grep -Fq "advisory-only planning artifact" "$docs_path" || record_failure "docs missing advisory-only wording"
  grep -Fq "never changes active queue settings" "$docs_path" || record_failure "docs missing active queue non-mutation wording"
  grep -Fq "never applies live retuning" "$docs_path" || record_failure "docs missing live retuning non-mutation wording"
  grep -Fq "does not claim that retirement or supersession has already" "$docs_path" || record_failure "docs missing non-execution wording"
  grep -Fq "reject local fallback proof evidence" "$docs_path" || record_failure "docs missing local fallback rejection wording"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static planner contract validates"
}

write_fixture_inputs() {
  local input_dir="$1"
  local scenario="$2"
  mkdir -p "$input_dir"

  local sustained_verdict="sustained_gain"
  local rollback_count=0
  local drift_class="none"
  local rollback_relevant=false
  local newer_bundle_id="adopted-policy-bundle"
  local newer_candidate_id="raise_proof_health_penalty"
  local newer_delta=240000
  local prior_bundle="adopted-policy-bundle"
  local ambiguous=false
  local freshness="fresh"
  local trust="accepted"

  case "$scenario" in
    retain_sustained_no_newer_candidate)
      ;;
    supersede_sustained_newer_candidate)
      newer_bundle_id="newer-policy-bundle"
      newer_candidate_id="raise_owner_friction_penalty"
      newer_delta=320000
      ;;
    expire_regression_no_newer_candidate)
      sustained_verdict="regression_detected"
      rollback_count=1
      drift_class="proof_drift"
      rollback_relevant=true
      ;;
    retain_inconclusive_no_newer_candidate)
      sustained_verdict="inconclusive_drift"
      ;;
    ambiguous_ownership)
      ambiguous=true
      ;;
    stale_ownership)
      freshness="stale"
      trust="accepted"
      ;;
    candidate_prior_conflict)
      newer_bundle_id="newer-policy-bundle"
      newer_candidate_id="raise_owner_friction_penalty"
      newer_delta=320000
      prior_bundle="different-policy-bundle"
      ;;
    *)
      record_failure "unknown fixture scenario ${scenario}"
      return 64
      ;;
  esac

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-policy-adoption-receipt.v1",
    adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
    adopted_policy_bundle_id:"adopted-policy-bundle",
    source_revision:"selftest",
    generated_at:"2026-05-06T00:00:00Z",
    decision:"admitted",
    operator_decision:{decision:"adopt",approved_by:"human_operator",approved_at:"2026-05-06T00:00:00Z",approval_artifact_path:"approvals/queue-policy-adoption.json",decision_reason:"eligible evidence",adoption_state:"recorded_active_policy"},
    adopted_candidate:{candidate_id:"raise_proof_health_penalty",expected_fidelity_delta_millionths:240000,source_policy_bundle_id:"adopted-policy-bundle",source_promotion_guard_receipt_json:"promotion/promotion_guard_receipt.json",source_canary_verdict_ledger_json:"rollback/canary_verdict_ledger.json"},
    observation_window:{starts_at:"2026-05-06T00:00:00Z",duration_seconds:3600,minimum_sample_count:3,monitored_metrics:["queue_fidelity_millionths","proof_drift_count","rollback_trigger_count"],stop_on_missing_evidence:true},
    supersession:{supersedes_adoption_receipt_id:null,supersedes_policy_bundle_id:"previous-policy-bundle",supersession_reason:"test",previous_policy_retention:"retain_for_rollback",expiry_policy:"score after window"},
    mutation_policy:{receipt_artifact_only:true,records_operator_decision:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
    automation_claim:"none"
  }' >"${input_dir}/adoption_receipt.json"

  jq -n \
    --arg sustained_verdict "$sustained_verdict" \
    --argjson rollback_count "$rollback_count" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-sustained-gain-receipt.v1",
      sustained_gain_receipt_id:"queue-policy-sustained-gain-smoke",
      source_revision:"selftest",
      generated_at:"2026-05-06T01:00:00Z",
      verdict:$sustained_verdict,
      adopted_policy_bundle_id:"adopted-policy-bundle",
      adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
      candidate_id:"raise_proof_health_penalty",
      baseline_fidelity_millionths:760000,
      promised_delta_millionths:240000,
      sustained_floor_millionths:880000,
      observed_fidelity_millionths:(if $sustained_verdict == "regression_detected" then 700000 elif $sustained_verdict == "inconclusive_drift" then 820000 else 900000 end),
      sample_count:4,
      rollback_drift_count:$rollback_count,
      fail_closed_reasons:[],
      mutation_policy:{scoring_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
    }' >"${input_dir}/sustained_gain_receipt.json"

  jq -n \
    --arg drift_class "$drift_class" \
    --argjson rollback_relevant "$rollback_relevant" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-expiry-supersession-ledger.fixture",
      placeholder:false
    }' >/dev/null

  jq -n \
    --arg drift_class "$drift_class" \
    --argjson rollback_relevant "$rollback_relevant" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-post-adoption-drift-ledger.v1",
      source_revision:"selftest",
      generated_at:"2026-05-06T01:00:00Z",
      verdict:(if $rollback_relevant then "regression_detected" else "sustained_gain" end),
      adopted_policy_bundle_id:"adopted-policy-bundle",
      adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
      candidate_id:"raise_proof_health_penalty",
      drift_rows:[
        {task_id:"bd-post-adoption-a",drift_class:$drift_class,mismatch_class:(if $rollback_relevant then "proof_brownout_miss" else "exact_match" end),row_score_millionths:(if $rollback_relevant then 480000 else 920000 end),rollback_relevant:$rollback_relevant,remediation:"observe post-adoption fidelity"}
      ],
      fail_closed_reasons:[],
      evidence_links:[],
      mutation_policy:{scoring_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
    }' >"${input_dir}/post_adoption_drift_ledger.json"

  jq -n \
    --arg newer_bundle_id "$newer_bundle_id" \
    --arg newer_candidate_id "$newer_candidate_id" \
    --argjson newer_delta "$newer_delta" \
    --arg prior_bundle "$prior_bundle" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
      bundle_id:$newer_bundle_id,
      source_revision:"selftest",
      generated_at:"2026-05-06T02:00:00Z",
      decision:"pass",
      plan_class:"single_improvement",
      promoted_candidate:{candidate_id:$newer_candidate_id,expected_fidelity_delta_millionths:$newer_delta,confidence_band:"high",safety_status:"safe_to_replay",source_tuning_plan_json:"tuning/tuning_plan.json"},
      evidence_links:[],
      manual_approval:{required:true,approver_role:"human_operator",approval_artifact_path:"approvals/manual-approval.required.json"},
      canary_constraints:{enabled:true,observation_window_seconds:1800,max_queue_depth_delta:1,max_candidate_weight_delta_millionths:200000,rollback_on_drift_classes:["proof_drift","ownership_drift","restore_drift"],stop_on_missing_evidence:true},
      rollback_references:{prior_policy_bundle_id:$prior_bundle,prior_frontier_json:"frontier/prior.json",rollback_comparator_report_json:"rollback/comparator.json",canary_verdict_ledger_json:"rollback/canary.json"},
      mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
      automation_claim:"none"
    }' >"${input_dir}/newer_candidate_bundle.json"

  jq -n \
    --argjson ambiguous "$ambiguous" \
    --arg freshness "$freshness" \
    --arg trust "$trust" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-evidence-ownership.v1",
      source_revision:"selftest",
      rows:[
        {artifact_kind:"adoption_receipt_json",owners:["BrownCreek"],trust_state:$trust,freshness_state:$freshness,ambiguous_owner:$ambiguous},
        {artifact_kind:"sustained_gain_receipt_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
        {artifact_kind:"post_adoption_drift_ledger_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
        {artifact_kind:"newer_candidate_bundle_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false}
      ],
      mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
    }' >"${input_dir}/evidence_ownership.json"
}

run_planner_case() {
  local case_name="$1"
  local expected_code="$2"
  local expected_decision="$3"
  local expected_reason="${4:-}"
  local case_dir="$5"
  local input_dir="${case_dir}/inputs"
  local output_dir="${case_dir}/planner"
  local exit_code

  write_fixture_inputs "$input_dir" "$case_name"
  set +e
  env SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_GENERATED_AT="2026-05-06T03:00:00Z" \
    bash "$planner" \
      --adoption-receipt-json "${input_dir}/adoption_receipt.json" \
      --sustained-gain-receipt-json "${input_dir}/sustained_gain_receipt.json" \
      --post-adoption-drift-ledger-json "${input_dir}/post_adoption_drift_ledger.json" \
      --newer-candidate-bundle-json "${input_dir}/newer_candidate_bundle.json" \
      --evidence-ownership-json "${input_dir}/evidence_ownership.json" \
      --source-revision "selftest-${case_name}" \
      --output-dir "$output_dir" >/dev/null
  exit_code=$?
  set -e

  if [[ "$exit_code" != "$expected_code" ]]; then
    record_failure "${case_name} expected exit ${expected_code}, got ${exit_code}"
    return 1
  fi

  jq -e \
    --arg expected_decision "$expected_decision" \
    '.schema_version == "franken-engine.swarm-execution-queue-policy-expiry-supersession-plan.v1"
     and .decision == $expected_decision
     and ((.plan_id // "") | length > 0)
     and .advisory_status.execution_state == "advisory_not_executed"
     and .mutation_policy.changes_active_queue == false
     and .mutation_policy.applies_live_retuning == false
     and .mutation_policy.retirement_executed == false
     and .mutation_policy.supersession_executed == false' \
    "${output_dir}/expiry_supersession_plan.json" >/dev/null || record_failure "${case_name} plan invariant mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-policy-expiry-supersession-ledger.v1"
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and (.ledger_rows | length) >= 3
  ' "${output_dir}/expiry_supersession_ledger.json" >/dev/null || record_failure "${case_name} ledger invariant mismatch"

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg expected_reason "$expected_reason" '
      any(.fail_closed_reasons[]; .kind == $expected_reason)
    ' "${output_dir}/expiry_supersession_plan.json" >/dev/null || record_failure "${case_name} missing fail-closed reason ${expected_reason}"
  fi
  record_pass "selftest ${case_name}"
}

run_selftest() {
  local tmp_root
  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-policy-expiry-supersession.XXXXXX")"

  run_planner_case "retain_sustained_no_newer_candidate" "0" "retain_adopted_policy" "" "${tmp_root}/retain_sustained_no_newer_candidate"
  run_planner_case "supersede_sustained_newer_candidate" "0" "supersede_adopted_policy" "" "${tmp_root}/supersede_sustained_newer_candidate"
  run_planner_case "expire_regression_no_newer_candidate" "0" "expire_adopted_policy" "" "${tmp_root}/expire_regression_no_newer_candidate"
  run_planner_case "retain_inconclusive_no_newer_candidate" "0" "retain_adopted_policy" "" "${tmp_root}/retain_inconclusive_no_newer_candidate"
  run_planner_case "ambiguous_ownership" "42" "fail_closed" "ambiguous_evidence_ownership" "${tmp_root}/ambiguous_ownership"
  run_planner_case "stale_ownership" "42" "fail_closed" "stale_or_rejected_evidence_ownership" "${tmp_root}/stale_ownership"
  run_planner_case "candidate_prior_conflict" "42" "fail_closed" "candidate_prior_policy_conflict" "${tmp_root}/candidate_prior_conflict"

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
