#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scorer="${root_dir}/scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_SCORER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_policy_sustained_gain_scorer_contract_v1.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-policy-sustained-gain-scorer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-policy-sustained-gain-scorer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_policy_sustained_gain_scorer_smoke.sh [check|selftest]

Validates the deterministic sustained-gain scorer with shell/JQ fixtures for
sustained gain, regression, inconclusive drift, incomplete observation windows,
ambiguous ownership, and missing monitored metrics.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatically adopts|automatic adoption is allowed|automatically retunes|applies retuning automatically|changes active queue automatically|manual approval is optional|manual approval may be skipped|local fallback proof is acceptable|does not reject local fallback proof' "$path"; then
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
  if [[ ! -f "$scorer" ]]; then
    record_failure "missing scorer ${scorer}"
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

  bash -n "$scorer"
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-policy-sustained-gain-scorer-contract.v1"
    and .bead_id == "bd-mj81s"
    and .parent_bead_id == "bd-6qnx9"
    and (.depends_on | index("bd-my39p") != null)
    and (.depends_on | index("bd-adgrb") != null)
    and .script == "scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh"
    and .sustained_gain_receipt_schema_version == "franken-engine.swarm-execution-queue-policy-sustained-gain-receipt.v1"
    and .post_adoption_drift_ledger_schema_version == "franken-engine.swarm-execution-queue-post-adoption-drift-ledger.v1"
    and ([.required_inputs[].field] | index("adoption_receipt_json") != null)
    and ([.required_inputs[].field] | index("adoption_snapshot_bundle_json") != null)
    and ([.required_inputs[].field] | index("post_adoption_fidelity_score_receipt_json") != null)
    and ([.required_inputs[].field] | index("post_adoption_drift_ledger_json") != null)
    and ([.required_inputs[].field] | index("evidence_ownership_json") != null)
    and .ownership_policy.ambiguous_owner_fails_closed == true
    and .ownership_policy.stale_or_rejected_evidence_fails_closed == true
    and .mutation_policy.scoring_artifact_only == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and (.verdicts | index("sustained_gain") != null)
    and (.verdicts | index("regression_detected") != null)
    and (.verdicts | index("inconclusive_drift") != null)
    and (.fail_closed_rules | index("incomplete observation window fails closed") != null)
    and (.fail_closed_rules | index("ambiguous evidence ownership fails closed") != null)
    and (.fail_closed_rules | index("missing monitored metrics fail closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
  ' "$contract_path" >/dev/null || record_failure "sustained-gain scorer contract shape mismatch"

  grep -Fq "never changes active queue settings" "$docs_path" || record_failure "docs missing active queue non-mutation wording"
  grep -Fq "never applies live retuning" "$docs_path" || record_failure "docs missing live retuning non-mutation wording"
  grep -Fq "never mutates \`br\`" "$docs_path" || record_failure "docs missing br non-mutation wording"
  grep -Fq "ambiguous evidence ownership" "$docs_path" || record_failure "docs missing ownership fail-closed wording"
  grep -Fq "incomplete observation windows" "$docs_path" || record_failure "docs missing observation fail-closed wording"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static scorer contract validates"
}

write_fixture_inputs() {
  local input_dir="$1"
  local scenario="$2"
  mkdir -p "$input_dir"

  local observed=900000
  local duration=3600
  local row_count=4
  local metrics='["queue_fidelity_millionths","proof_drift_count","rollback_trigger_count"]'
  local ambiguous=false
  local owners='["BrownCreek"]'
  local drift_class="none"
  local mismatch_class="exact_match"
  local row_score=920000

  case "$scenario" in
    sustained_gain)
      ;;
    regression_detected)
      observed=700000
      drift_class="proof_drift"
      mismatch_class="proof_brownout_miss"
      row_score=480000
      ;;
    inconclusive_drift)
      observed=820000
      ;;
    incomplete_window)
      duration=600
      ;;
    ambiguous_ownership)
      ambiguous=true
      owners='["BrownCreek","CyanOak"]'
      ;;
    missing_metric)
      metrics='["queue_fidelity_millionths","proof_drift_count"]'
      ;;
    *)
      record_failure "unknown fixture scenario ${scenario}"
      return 64
      ;;
  esac

  jq -n \
    --argjson duration "$duration" \
    --argjson metrics "$metrics" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-adoption-receipt.v1",
      adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
      adopted_policy_bundle_id:"swarm-execution-queue-tuning-policy-bundle-smoke",
      source_revision:"selftest",
      generated_at:"2026-05-06T00:00:00Z",
      decision:"admitted",
      operator_decision:{decision:"adopt",approved_by:"human_operator",approved_at:"2026-05-06T00:00:00Z",approval_artifact_path:"approvals/queue-policy-adoption.json",decision_reason:"eligible evidence",adoption_state:"recorded_pending_activation"},
      adopted_candidate:{candidate_id:"raise_proof_health_penalty",expected_fidelity_delta_millionths:240000,source_policy_bundle_id:"swarm-execution-queue-tuning-policy-bundle-smoke",source_promotion_guard_receipt_json:"promotion/promotion_guard_receipt.json",source_canary_verdict_ledger_json:"rollback/canary_verdict_ledger.json"},
      observation_window:{starts_at:"2026-05-06T00:00:00Z",duration_seconds:$duration,minimum_sample_count:3,monitored_metrics:$metrics,stop_on_missing_evidence:true},
      supersession:{supersedes_adoption_receipt_id:null,supersedes_policy_bundle_id:"current-policy-bundle",supersession_reason:"test",previous_policy_retention:"retain_for_rollback",expiry_policy:"score after window"},
      mutation_policy:{receipt_artifact_only:true,records_operator_decision:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
      automation_claim:"none"
    }' >"${input_dir}/adoption_receipt.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-policy-adoption-snapshot-bundle.v1",
    snapshot_id:"queue-policy-adoption-snapshot-smoke",
    adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
    adopted_policy_bundle_id:"swarm-execution-queue-tuning-policy-bundle-smoke",
    candidate_id:"raise_proof_health_penalty",
    source_revision:"selftest",
    generated_at:"2026-05-06T00:00:00Z",
    decision:"admitted",
    normalized_inputs:{
      rollback_comparator_receipt:{current_fidelity_millionths:760000,candidate_expected_fidelity_millionths:1000000,candidate_delta_millionths:240000}
    },
    mutation_policy:{receipt_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
  }' >"${input_dir}/adoption_snapshot_bundle.json"

  jq -n \
    --argjson observed "$observed" \
    --argjson row_count "$row_count" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-fidelity-score-receipt.v1",
      source_revision:"selftest",
      decision:"pass",
      overall_fidelity_millionths:$observed,
      confidence_band:"high",
      summary:{row_count:$row_count,fail_closed_reason_count:0,degraded_input_count:0}
    }' >"${input_dir}/post_adoption_fidelity_score_receipt.json"

  jq -n \
    --arg drift_class "$drift_class" \
    --arg mismatch_class "$mismatch_class" \
    --argjson row_score "$row_score" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-drift-ledger.v1",
      source_revision:"selftest",
      decision:"pass",
      rows:[
        {task_id:"bd-post-adoption-a",drift_class:$drift_class,mismatch_class:$mismatch_class,row_score_millionths:$row_score,remediation:"observe post-adoption fidelity"}
      ],
      fail_closed_reasons:[],
      degraded_inputs:[]
    }' >"${input_dir}/post_adoption_drift_ledger.json"

  jq -n \
    --argjson owners "$owners" \
    --argjson ambiguous "$ambiguous" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-evidence-ownership.v1",
      source_revision:"selftest",
      rows:[
        {artifact_kind:"adoption_receipt_json",owners:$owners,trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:$ambiguous},
        {artifact_kind:"adoption_snapshot_bundle_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
        {artifact_kind:"post_adoption_fidelity_score_receipt_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false},
        {artifact_kind:"post_adoption_drift_ledger_json",owners:["BrownCreek"],trust_state:"accepted",freshness_state:"fresh",ambiguous_owner:false}
      ],
      mutation_policy:{scoring_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false}
    }' >"${input_dir}/evidence_ownership.json"
}

run_scorer_case() {
  local case_name="$1"
  local expected_code="$2"
  local expected_verdict="$3"
  local expected_reason="${4:-}"
  local case_dir="$5"
  local input_dir="${case_dir}/inputs"
  local output_dir="${case_dir}/scorer"
  local exit_code

  write_fixture_inputs "$input_dir" "$case_name"
  set +e
  env SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$scorer" \
      --adoption-receipt-json "${input_dir}/adoption_receipt.json" \
      --adoption-snapshot-bundle-json "${input_dir}/adoption_snapshot_bundle.json" \
      --post-adoption-fidelity-score-receipt-json "${input_dir}/post_adoption_fidelity_score_receipt.json" \
      --post-adoption-drift-ledger-json "${input_dir}/post_adoption_drift_ledger.json" \
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
    --arg expected_verdict "$expected_verdict" \
    '.schema_version == "franken-engine.swarm-execution-queue-policy-sustained-gain-receipt.v1"
     and .verdict == $expected_verdict
     and ((.sustained_gain_receipt_id // "") | length > 0)
     and .mutation_policy.changes_active_queue == false
     and .mutation_policy.applies_live_retuning == false' \
    "${output_dir}/sustained_gain_receipt.json" >/dev/null || record_failure "${case_name} receipt invariant mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-post-adoption-drift-ledger.v1"
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
  ' "${output_dir}/post_adoption_drift_ledger.json" >/dev/null || record_failure "${case_name} ledger invariant mismatch"

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg expected_reason "$expected_reason" '
      any(.fail_closed_reasons[]; .kind == $expected_reason)
    ' "${output_dir}/sustained_gain_receipt.json" >/dev/null || record_failure "${case_name} missing fail-closed reason ${expected_reason}"
  fi
  record_pass "selftest ${case_name}"
}

run_selftest() {
  local tmp_root
  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-policy-sustained-gain.XXXXXX")"

  run_scorer_case "sustained_gain" "0" "sustained_gain" "" "${tmp_root}/sustained_gain"
  run_scorer_case "regression_detected" "0" "regression_detected" "" "${tmp_root}/regression_detected"
  run_scorer_case "inconclusive_drift" "0" "inconclusive_drift" "" "${tmp_root}/inconclusive_drift"
  run_scorer_case "incomplete_window" "42" "fail_closed" "incomplete_observation_window" "${tmp_root}/incomplete_window"
  run_scorer_case "ambiguous_ownership" "42" "fail_closed" "ambiguous_evidence_ownership" "${tmp_root}/ambiguous_ownership"
  run_scorer_case "missing_metric" "42" "fail_closed" "missing_monitored_metrics" "${tmp_root}/missing_metric"

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
