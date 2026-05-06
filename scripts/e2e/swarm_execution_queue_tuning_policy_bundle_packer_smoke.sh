#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
packer="${root_dir}/scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh"
contract_smoke="${root_dir}/scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_PACKER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_tuning_policy_bundle_packer_contract_v1.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-tuning-policy-bundle-packer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-tuning-policy-bundle-packer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_tuning_policy_bundle_packer_smoke.sh [check|selftest]

Validates the advisory-only queue tuning policy bundle packer with deterministic
shell/JQ fixtures for no-improvement, one-clear-improvement, conflicting
frontiers, and incomplete evidence.
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
  if [[ ! -f "$packer" ]]; then
    record_failure "missing packer ${packer}"
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

  bash -n "$packer"
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-tuning-policy-bundle-packer-contract.v1"
    and .bead_id == "bd-j2rny.2"
    and .parent_bead_id == "bd-j2rny"
    and (.depends_on | index("bd-j2rny.1") != null)
    and .script == "scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh"
    and .bundle_schema_version == "franken-engine.swarm-execution-queue-tuning-policy-bundle.v1"
    and .frontier_export_schema_version == "franken-engine.swarm-execution-queue-policy-frontier-export.v1"
    and ([.required_inputs[].field] | index("fidelity_score_receipt_json") != null)
    and ([.required_inputs[].field] | index("drift_ledger_json") != null)
    and ([.required_inputs[].field] | index("counterfactual_backtest_report_json") != null)
    and ([.required_inputs[].field] | index("tuning_plan_json") != null)
    and ([.required_inputs[].field] | index("frontier_json") != null)
    and ([.required_inputs[].field] | index("operator_status_json") != null)
    and (.required_rollback_references | index("--prior-policy-bundle-id") != null)
    and (.required_rollback_references | index("--prior-frontier-json") != null)
    and (.required_rollback_references | index("--rollback-comparator-report-json") != null)
    and (.required_rollback_references | index("--canary-verdict-ledger-json") != null)
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and (.fail_closed_rules | index("automatic live-retuning claims fail closed") != null)
    and (.fail_closed_rules | index("rollback references missing fail closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
  ' "$contract_path" >/dev/null || record_failure "packer contract shape mismatch"

  grep -Fq "advisory-only planning artifact" "$docs_path" || record_failure "docs missing advisory-only planning wording"
  grep -Fq "never changes active queue settings" "$docs_path" || record_failure "docs missing active queue non-mutation wording"
  grep -Fq "reject local fallback proof evidence" "$docs_path" || record_failure "docs missing local fallback rejection wording"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static packer contract validates"
}

write_common_inputs() {
  local case_dir="$1"
  mkdir -p "$case_dir"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-fidelity-score-receipt.v1",
    source_revision:"selftest",
    decision:"pass",
    overall_fidelity_millionths:760000,
    confidence_band:"medium",
    summary:{row_count:1,fail_closed_reason_count:0,degraded_input_count:0}
  }' >"${case_dir}/fidelity_score_receipt.json"

  jq -n '{
    schema_version:"franken-engine.swarm-execution-queue-drift-ledger.v1",
    source_revision:"selftest",
    decision:"pass",
    rows:[
      {
        task_id:"bd-ready-a",
        mismatch_class:"proof_brownout_miss",
        row_score_millionths:480000,
        remediation:"increase proof-health penalty and reject local fallback proof evidence",
        source_row:{task_id:"bd-ready-a",proof_outcome:"brownout"}
      }
    ],
    fail_closed_reasons:[],
    degraded_inputs:[]
  }' >"${case_dir}/drift_ledger.json"

  jq -n '{
    schema_version:"franken-engine.swarm-operator-status-report.v1",
    source_revision:"selftest",
    predictive_dashboard:{
      queue_fidelity:{
        mutation_policy:{changes_active_queue:false,applies_live_retuning:false}
      }
    }
  }' >"${case_dir}/operator_status.json"
}

write_counterfactual_inputs() {
  local case_dir="$1"
  local scenario="$2"

  case "$scenario" in
    no_improvement)
      jq -n '[
        {
          candidate_id:"baseline_current",
          description:"Keep current queue settings",
          impact_weight_delta:0,
          reuse_weight_delta:0,
          friction_weight_delta:0,
          risk_weight_delta:0,
          expected_fidelity_delta_millionths:0,
          confidence_band:"low",
          safety_status:"no_change",
          manual_review_required:false
        },
        {
          candidate_id:"raise_proof_health_penalty",
          description:"Replay with stronger proof-health penalties",
          impact_weight_delta:-30000,
          reuse_weight_delta:0,
          friction_weight_delta:30000,
          risk_weight_delta:140000,
          expected_fidelity_delta_millionths:-10000,
          confidence_band:"low",
          safety_status:"unsafe",
          manual_review_required:false
        }
      ]' >"${case_dir}/candidates.json"
      ;;
    one_clear_improvement)
      jq -n '[
        {
          candidate_id:"raise_proof_health_penalty",
          description:"Replay with stronger proof-health penalties",
          impact_weight_delta:-30000,
          reuse_weight_delta:0,
          friction_weight_delta:30000,
          risk_weight_delta:140000,
          expected_fidelity_delta_millionths:240000,
          confidence_band:"high",
          safety_status:"safe_to_replay",
          manual_review_required:false
        },
        {
          candidate_id:"baseline_current",
          description:"Keep current queue settings",
          impact_weight_delta:0,
          reuse_weight_delta:0,
          friction_weight_delta:0,
          risk_weight_delta:0,
          expected_fidelity_delta_millionths:0,
          confidence_band:"low",
          safety_status:"no_change",
          manual_review_required:false
        }
      ]' >"${case_dir}/candidates.json"
      ;;
    conflicting_frontiers)
      jq -n '[
        {
          candidate_id:"raise_proof_health_penalty",
          description:"Replay with stronger proof-health penalties",
          impact_weight_delta:-30000,
          reuse_weight_delta:0,
          friction_weight_delta:30000,
          risk_weight_delta:140000,
          expected_fidelity_delta_millionths:240000,
          confidence_band:"high",
          safety_status:"safe_to_replay",
          manual_review_required:false
        },
        {
          candidate_id:"raise_owner_friction_penalty",
          description:"Replay with stronger owner-friction weighting",
          impact_weight_delta:0,
          reuse_weight_delta:0,
          friction_weight_delta:120000,
          risk_weight_delta:40000,
          expected_fidelity_delta_millionths:200000,
          confidence_band:"high",
          safety_status:"safe_to_replay",
          manual_review_required:false
        },
        {
          candidate_id:"baseline_current",
          description:"Keep current queue settings",
          impact_weight_delta:0,
          reuse_weight_delta:0,
          friction_weight_delta:0,
          risk_weight_delta:0,
          expected_fidelity_delta_millionths:0,
          confidence_band:"low",
          safety_status:"no_change",
          manual_review_required:false
        }
      ]' >"${case_dir}/candidates.json"
      ;;
    incomplete_evidence)
      jq -n '[]' >"${case_dir}/candidates.json"
      ;;
    *)
      record_failure "unknown scenario: ${scenario}"
      return 1
      ;;
  esac

  jq -n \
    --arg scenario "$scenario" \
    --slurpfile candidates "${case_dir}/candidates.json" '
      ($candidates[0]) as $ranked
      | {
          schema_version:"franken-engine.swarm-execution-queue-counterfactual-backtest-report.v1",
          source_revision:"selftest",
          decision:(if $scenario == "incomplete_evidence" then "pass" elif $scenario == "conflicting_frontiers" then "degraded" else "pass" end),
          baseline_overall_fidelity_millionths:760000,
          evaluated_candidate_count:($ranked | length),
          exact_match_count:0,
          positive_candidate_count:([$ranked[]? | select(.expected_fidelity_delta_millionths > 0)] | length),
          fail_closed_reasons:[],
          candidates:$ranked
        }' >"${case_dir}/counterfactual_backtest_report.json"

  jq -n \
    --arg scenario "$scenario" \
    --slurpfile candidates "${case_dir}/candidates.json" '
      ($candidates[0]) as $ranked
      | {
          schema_version:"franken-engine.swarm-execution-queue-tuning-plan.v1",
          source_revision:"selftest",
          decision:(if $scenario == "conflicting_frontiers" then "degraded" else "pass" end),
          plan_class:(if $scenario == "no_improvement" then "no_improvement"
            elif $scenario == "one_clear_improvement" then "one_clear_improvement"
            elif $scenario == "conflicting_frontiers" then "conflicting_improvements"
            else "one_clear_improvement" end),
          recommended_candidate:($ranked[0] // null),
          ranked_candidates:$ranked,
          operator_notes:["selftest fixture"],
          mutation_policy:{changes_active_queue:false,applies_live_retuning:false,advisory_only:true}
        }' >"${case_dir}/tuning_plan.json"

  jq -n \
    --slurpfile candidates "${case_dir}/candidates.json" '
      ($candidates[0]) as $ranked
      | {
          schema_version:"franken-engine.swarm-execution-queue-counterfactual-frontier.v1",
          source_revision:"selftest",
          frontier:[$ranked[]? | select(.expected_fidelity_delta_millionths >= 0) | {
            candidate_id,
            expected_fidelity_delta_millionths,
            confidence_band,
            safety_status,
            manual_review_required
          }]
        }' >"${case_dir}/frontier.json"
}

run_packer_case() {
  local scenario="$1"
  local expected_exit="$2"
  local expected_decision="$3"
  local expected_candidate="$4"
  local tmp_root case_dir output_dir exit_code bundle_path frontier_path
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-tuning-policy-bundle-packer.XXXXXX")"
  case_dir="${tmp_root}/${scenario}/inputs"
  output_dir="${tmp_root}/${scenario}/output"

  write_common_inputs "$case_dir"
  write_counterfactual_inputs "$case_dir" "$scenario"
  mkdir -p "$output_dir"

  set +e
  SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$packer" \
      --fidelity-score-receipt-json "${case_dir}/fidelity_score_receipt.json" \
      --drift-ledger-json "${case_dir}/drift_ledger.json" \
      --counterfactual-backtest-report-json "${case_dir}/counterfactual_backtest_report.json" \
      --tuning-plan-json "${case_dir}/tuning_plan.json" \
      --frontier-json "${case_dir}/frontier.json" \
      --operator-status-json "${case_dir}/operator_status.json" \
      --prior-policy-bundle-id "current-policy-${scenario}" \
      --prior-frontier-json "rollback/${scenario}/prior_frontier.json" \
      --rollback-comparator-report-json "rollback/${scenario}/comparator_report.json" \
      --canary-verdict-ledger-json "rollback/${scenario}/canary_verdict_ledger.json" \
      --source-revision "selftest-${scenario}" \
      --output-dir "$output_dir" >/dev/null 2>&1
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${scenario} exited ${exit_code}, expected ${expected_exit}"
    return 1
  fi

  bundle_path="${output_dir}/tuning_policy_bundle.json"
  frontier_path="${output_dir}/policy_frontier_export.json"
  jq empty "$bundle_path" "$frontier_path"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_candidate "$expected_candidate" '
      .decision == $expected_decision
      and (.promoted_candidate.candidate_id // "none") == $expected_candidate
      and .mutation_policy.changes_active_queue == false
      and .mutation_policy.applies_live_retuning == false
      and (.evidence_links | length) == 6
    ' "$bundle_path" >/dev/null || record_failure "${scenario} bundle mismatch"

  if [[ "$expected_exit" -eq 0 ]]; then
    bash "$contract_smoke" validate-bundle "$bundle_path" >/dev/null
  fi

  record_pass "selftest ${scenario}"
}

run_selftest() {
  run_check
  run_packer_case "no_improvement" 0 "pass" "baseline_current"
  run_packer_case "one_clear_improvement" 0 "pass" "raise_proof_health_penalty"
  run_packer_case "conflicting_frontiers" 0 "degraded" "raise_proof_health_penalty"
  run_packer_case "incomplete_evidence" 42 "fail_closed" "none"

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
