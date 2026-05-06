#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_TUNING_LIFECYCLE_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-tuning-lifecycle-no-mock-drill}"
run_id="${SWARM_EXECUTION_QUEUE_TUNING_LIFECYCLE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_TUNING_LIFECYCLE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

packer="${root_dir}/scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh"
promotion_guard="${root_dir}/scripts/swarm_execution_queue_tuning_promotion_guard.sh"
rollback_comparator="${root_dir}/scripts/swarm_execution_queue_tuning_rollback_comparator.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_ctrl_xiv_runbook_truth_gate.sh"
contract_path="${root_dir}/docs/swarm_ctrl_xiv_runbook_truth_contract_v1.json"

report_json=""
report_md=""
events_path=""
commands_path=""
failures=0

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_tuning_lifecycle_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the SWARM-CTRL-XIV queue tuning lifecycle surfaces into one
deterministic no-mock drill. The drill uses the real bundle packer, promotion
guard, rollback comparator, and operator-status handoff. It does not mutate br,
Agent Mail, reservations, workers, Cargo targets, or live queue policy.

Options:
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
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

record_pass() {
  printf 'PASS swarm-execution-queue-tuning-lifecycle-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-tuning-lifecycle-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_paths() {
  report_json="${run_dir}/swarm_execution_queue_tuning_lifecycle_no_mock_drill_report.json"
  report_md="${run_dir}/report.md"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
}

quote_command() {
  printf '%q ' "$@"
}

exit_code_is_expected() {
  local actual="$1"
  local expected_csv="$2"
  local expected

  IFS=',' read -r -a expected_list <<<"$expected_csv"
  for expected in "${expected_list[@]}"; do
    if [[ "$actual" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-tuning-lifecycle-no-mock-drill.event.v1" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{schema_version:$schema_version,event_name:"swarm_execution_queue_tuning_lifecycle_no_mock_drill.step",step_id:$step_id,decision:$decision,exit_code:$exit_code,artifact_paths:{stdout_log:$stdout_path,stderr_log:$stderr_path}}' >>"$events_path"
}

run_step() {
  local step="$1"
  local expected_codes="$2"
  shift 2
  local step_dir="${run_dir}/${step}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code decision

  mkdir -p "$step_dir"
  {
    printf '%s: ' "$step"
    quote_command "$@"
    printf '\n'
  } >>"$commands_path"

  set +e
  (cd "$root_dir" && "$@") >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e

  if exit_code_is_expected "$exit_code" "$expected_codes"; then
    decision="pass"
  else
    decision="fail"
  fi
  write_event "$step" "$decision" "$exit_code" "$stdout_path" "$stderr_path"
  if [[ "$decision" != "pass" ]]; then
    printf 'step %s exited %s, expected %s\nstdout=%s\nstderr=%s\n' "$step" "$exit_code" "$expected_codes" "$stdout_path" "$stderr_path" >&2
    return "$exit_code"
  fi
}

write_tuning_inputs() {
  local input_dir="$1"
  local scenario="$2"
  local candidate_delta="$3"
  local plan_class="$4"

  mkdir -p "$input_dir"
  jq -n \
    --arg scenario "$scenario" '{
      schema_version:"franken-engine.swarm-execution-queue-fidelity-score-receipt.v1",
      source_revision:("drill-" + $scenario),
      decision:"pass",
      overall_fidelity_millionths:760000,
      confidence_band:"high",
      summary:{row_count:1,fail_closed_reason_count:0,degraded_input_count:0},
      artifact_paths:{fidelity_score_receipt_json:"fidelity/fidelity_score_receipt.json",drift_ledger_json:"fidelity/drift_ledger.json"}
    }' >"${input_dir}/fidelity_score_receipt.json"

  jq -n \
    --arg scenario "$scenario" '{
      schema_version:"franken-engine.swarm-execution-queue-drift-ledger.v1",
      source_revision:("drill-" + $scenario),
      decision:"pass",
      rows:[{
        task_id:"bd-ready-a",
        recommended_rank:1,
        actual_outcome:"closed",
        fidelity_class:"drifted",
        drift_class:"proof_drift",
        mismatch_class:"proof_brownout_miss",
        row_score_millionths:480000,
        confidence_band:"high",
        remediation:"increase proof-health penalty and reject local fallback proof evidence",
        source_row:{task_id:"bd-ready-a",proof_outcome:"brownout"}
      }],
      fail_closed_reasons:[],
      degraded_inputs:[]
    }' >"${input_dir}/drift_ledger.json"

  jq -n \
    --argjson delta "$candidate_delta" \
    '[
      {
        candidate_id:"raise_proof_health_penalty",
        description:"Replay with stronger proof-health penalties",
        impact_weight_delta:-30000,
        reuse_weight_delta:0,
        friction_weight_delta:30000,
        risk_weight_delta:140000,
        expected_fidelity_delta_millionths:$delta,
        confidence_band:(if $delta > 0 then "high" else "low" end),
        safety_status:(if $delta > 0 then "safe_to_replay" else "worse_than_current" end),
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
    ]' >"${input_dir}/candidates.json"

  jq -n \
    --arg scenario "$scenario" \
    --slurpfile candidates "${input_dir}/candidates.json" '
      ($candidates[0]) as $ranked
      | {
          schema_version:"franken-engine.swarm-execution-queue-counterfactual-backtest-report.v1",
          source_revision:("drill-" + $scenario),
          decision:"pass",
          baseline_overall_fidelity_millionths:760000,
          evaluated_candidate_count:($ranked | length),
          exact_match_count:0,
          positive_candidate_count:([$ranked[]? | select(.expected_fidelity_delta_millionths > 0)] | length),
          fail_closed_reasons:[],
          candidates:$ranked,
          artifact_paths:{counterfactual_backtest_report_json:"counterfactual/counterfactual_backtest_report.json",tuning_plan_json:"counterfactual/tuning_plan.json",frontier_json:"counterfactual/frontier.json"}
        }' >"${input_dir}/counterfactual_backtest_report.json"

  jq -n \
    --arg scenario "$scenario" \
    --arg plan_class "$plan_class" \
    --slurpfile candidates "${input_dir}/candidates.json" '
      ($candidates[0]) as $ranked
      | {
          schema_version:"franken-engine.swarm-execution-queue-tuning-plan.v1",
          source_revision:("drill-" + $scenario),
          decision:"pass",
          plan_class:$plan_class,
          recommended_candidate:$ranked[0],
          ranked_candidates:$ranked,
          operator_notes:["no-mock lifecycle drill fixture; review only"],
          mutation_policy:{changes_active_queue:false,applies_live_retuning:false,advisory_only:true}
        }' >"${input_dir}/tuning_plan.json"

  jq -n \
    --arg scenario "$scenario" \
    --slurpfile candidates "${input_dir}/candidates.json" '
      ($candidates[0]) as $ranked
      | {
          schema_version:"franken-engine.swarm-execution-queue-counterfactual-frontier.v1",
          source_revision:("drill-" + $scenario),
          frontier:[$ranked[]? | select(.expected_fidelity_delta_millionths >= 0) | {candidate_id,expected_fidelity_delta_millionths,confidence_band,safety_status,manual_review_required}]
        }' >"${input_dir}/frontier.json"

  jq -n \
    --arg scenario "$scenario" '{
      schema_version:"franken-engine.swarm-operator-status-report.v1",
      source_revision:("drill-" + $scenario),
      predictive_dashboard:{
        queue_fidelity:{
          mutation_policy:{advisory_only:true,changes_active_queue:false,applies_live_retuning:false}
        }
      }
    }' >"${input_dir}/operator_status_seed.json"
}

write_current_policy_state() {
  local output_path="$1"
  local scenario="$2"
  local freshness="$3"

  jq -n \
    --arg scenario "$scenario" \
    --arg freshness "$freshness" '{
      schema_version:"franken-engine.swarm-execution-queue-current-policy-state.v1",
      source_revision:("drill-" + $scenario),
      current_policy_bundle_id:"current-policy-bundle",
      evidence_freshness:$freshness,
      provenance_state:"consistent",
      current_policy_metrics:{overall_fidelity_millionths:760000},
      rollback_material:{
        prior_frontier_available:true,
        rollback_comparator_available:true,
        canary_verdict_ledger_available:true
      },
      mutation_policy:{changes_active_queue:false,applies_live_retuning:false}
    }' >"$output_path"
}

run_operator_status_handoff() {
  local case_name="$1"
  local input_dir="$2"
  local packer_dir="$3"
  local guard_dir="$4"
  local comparator_dir="$5"
  local output_dir="$6"

  run_step "operator-status-${case_name}" "0" \
    bash "$operator_status" \
      --bead-id bd-j2rny.6 \
      --source-revision "drill-${case_name}" \
      --output-dir "$output_dir" \
      --agent-mail-status ok \
      --rch-status ok \
      --proof-index-status ok \
      --queue-fidelity-score-receipt-json "${input_dir}/fidelity_score_receipt.json" \
      --queue-drift-ledger-json "${input_dir}/drift_ledger.json" \
      --queue-counterfactual-backtest-report-json "${input_dir}/counterfactual_backtest_report.json" \
      --queue-tuning-plan-json "${input_dir}/tuning_plan.json" \
      --queue-tuning-frontier-json "${input_dir}/frontier.json" \
      --queue-tuning-bundle-json "${packer_dir}/tuning_policy_bundle.json" \
      --queue-tuning-promotion-guard-receipt-json "${guard_dir}/promotion_guard_receipt.json" \
      --queue-tuning-rollout-plan-json "${guard_dir}/manual_approval_rollout_plan.json" \
      --queue-tuning-rollback-comparator-receipt-json "${comparator_dir}/rollback_comparator_receipt.json" \
      --queue-tuning-canary-verdict-ledger-json "${comparator_dir}/canary_verdict_ledger.json"
}

write_success_case_summary() {
  local case_name="$1"
  local input_dir="$2"
  local packer_dir="$3"
  local guard_dir="$4"
  local comparator_dir="$5"
  local status_dir="$6"
  local output_path="${run_dir}/${case_name}/case_summary.json"

  jq -n \
    --arg case_id "$case_name" \
    --arg bundle_json "${packer_dir}/tuning_policy_bundle.json" \
    --arg guard_json "${guard_dir}/promotion_guard_receipt.json" \
    --arg rollout_json "${guard_dir}/manual_approval_rollout_plan.json" \
    --arg comparator_json "${comparator_dir}/rollback_comparator_receipt.json" \
    --arg ledger_json "${comparator_dir}/canary_verdict_ledger.json" \
    --arg status_json "${status_dir}/status.json" \
    --arg fidelity_json "${input_dir}/fidelity_score_receipt.json" \
    --slurpfile bundle "${packer_dir}/tuning_policy_bundle.json" \
    --slurpfile guard "${guard_dir}/promotion_guard_receipt.json" \
    --slurpfile rollout "${guard_dir}/manual_approval_rollout_plan.json" \
    --slurpfile comparator "${comparator_dir}/rollback_comparator_receipt.json" \
    --slurpfile ledger "${comparator_dir}/canary_verdict_ledger.json" \
    --slurpfile status "${status_dir}/status.json" '
      ($bundle[0]) as $b
      | ($guard[0]) as $g
      | ($rollout[0]) as $r
      | ($comparator[0]) as $c
      | ($ledger[0]) as $l
      | ($status[0]) as $s
      | {
          case_id:$case_id,
          decision:"pass",
          bundle_decision:($b.decision // "missing"),
          promotion_decision:($g.decision // "missing"),
          rollout_decision:($r.decision // "missing"),
          rollback_verdict:($c.verdict // "missing"),
          canary_action:($l.recommended_action // "missing"),
          operator_readiness:($s.predictive_dashboard.queue_tuning_promotion.readiness // "missing"),
          assertions:{
            bundle_has_evidence_links:(($b.evidence_links // []) | length >= 6),
            promotion_guard_advisory_only:(($g.mutation_policy.changes_active_queue // false) == false and ($g.mutation_policy.applies_live_retuning // false) == false),
            rollout_requires_manual_approval:(($r.manual_approval.required // false) == true),
            rollback_comparator_advisory_only:(($c.mutation_policy.changes_active_queue // false) == false and ($c.mutation_policy.applies_live_retuning // false) == false),
            canary_ledger_advisory_only:(($l.mutation_policy.changes_active_queue // false) == false and ($l.mutation_policy.applies_live_retuning // false) == false),
            operator_status_integrates_bundle:($s.artifact_paths.queue_tuning_bundle_json == $bundle_json),
            operator_status_integrates_guard:($s.artifact_paths.queue_tuning_promotion_guard_receipt_json == $guard_json),
            operator_status_integrates_comparator:($s.artifact_paths.queue_tuning_rollback_comparator_receipt_json == $comparator_json),
            operator_status_integrates_canary:($s.artifact_paths.queue_tuning_canary_verdict_ledger_json == $ledger_json),
            operator_status_integrates_fidelity:($s.artifact_paths.queue_fidelity_score_receipt_json == $fidelity_json),
            operator_status_advisory_only:($s.predictive_dashboard.queue_tuning_promotion.mutation_policy.advisory_only == true and $s.predictive_dashboard.queue_tuning_promotion.mutation_policy.changes_active_queue == false and $s.predictive_dashboard.queue_tuning_promotion.mutation_policy.applies_live_retuning == false)
          },
          artifact_paths:{
            tuning_policy_bundle_json:$bundle_json,
            promotion_guard_receipt_json:$guard_json,
            manual_approval_rollout_plan_json:$rollout_json,
            rollback_comparator_receipt_json:$comparator_json,
            canary_verdict_ledger_json:$ledger_json,
            operator_status_json:$status_json
          }
        }' >"$output_path"
}

write_guard_reject_case_summary() {
  local case_name="$1"
  local packer_dir="$2"
  local guard_dir="$3"
  local output_path="${run_dir}/${case_name}/case_summary.json"

  jq -n \
    --arg case_id "$case_name" \
    --arg bundle_json "${packer_dir}/tuning_policy_bundle.json" \
    --arg guard_json "${guard_dir}/promotion_guard_receipt.json" \
    --arg rollout_json "${guard_dir}/manual_approval_rollout_plan.json" \
    --slurpfile guard "${guard_dir}/promotion_guard_receipt.json" \
    --slurpfile rollout "${guard_dir}/manual_approval_rollout_plan.json" '
      ($guard[0]) as $g
      | ($rollout[0]) as $r
      | {
          case_id:$case_id,
          decision:"fail_closed",
          bundle_decision:"pass",
          promotion_decision:($g.decision // "missing"),
          rollout_decision:($r.decision // "missing"),
          rollback_verdict:"not_run_after_guard_reject",
          canary_action:"not_run_after_guard_reject",
          operator_readiness:"not_published_after_guard_reject",
          assertions:{
            stale_evidence_rejected:(($g.reject_reasons // []) | any(.kind == "stale_evidence")),
            rollout_plan_stays_advisory:(($r.mutation_policy.changes_active_queue // false) == false and ($r.mutation_policy.applies_live_retuning // false) == false),
            comparator_skipped_after_guard_reject:true,
            operator_status_skipped_after_guard_reject:true
          },
          artifact_paths:{
            tuning_policy_bundle_json:$bundle_json,
            promotion_guard_receipt_json:$guard_json,
            manual_approval_rollout_plan_json:$rollout_json
          }
        }' >"$output_path"
}

run_lifecycle_case() {
  local case_name="$1"
  local candidate_delta="$2"
  local plan_class="$3"
  local freshness="$4"
  local expected_guard_codes="$5"
  local case_dir="${run_dir}/${case_name}"
  local input_dir="${case_dir}/inputs"
  local policy_state="${case_dir}/current_policy_state.json"
  local packer_dir="${case_dir}/tuning-policy-bundle"
  local guard_dir="${case_dir}/promotion-guard"
  local comparator_dir="${case_dir}/rollback-comparator"
  local status_dir="${case_dir}/operator-status"

  write_tuning_inputs "$input_dir" "$case_name" "$candidate_delta" "$plan_class"
  write_current_policy_state "$policy_state" "$case_name" "$freshness"

  run_step "bundle-packer-${case_name}" "0" \
    env SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$packer" \
      --fidelity-score-receipt-json "${input_dir}/fidelity_score_receipt.json" \
      --drift-ledger-json "${input_dir}/drift_ledger.json" \
      --counterfactual-backtest-report-json "${input_dir}/counterfactual_backtest_report.json" \
      --tuning-plan-json "${input_dir}/tuning_plan.json" \
      --frontier-json "${input_dir}/frontier.json" \
      --operator-status-json "${input_dir}/operator_status_seed.json" \
      --prior-policy-bundle-id "current-policy-bundle" \
      --prior-frontier-json "${case_dir}/rollback/prior_frontier.json" \
      --rollback-comparator-report-json "${case_dir}/rollback/comparator_report.json" \
      --canary-verdict-ledger-json "${case_dir}/rollback/canary_verdict_ledger.json" \
      --source-revision "drill-${case_name}" \
      --output-dir "$packer_dir"

  run_step "promotion-guard-${case_name}" "$expected_guard_codes" \
    env SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$promotion_guard" \
      --candidate-bundle-json "${packer_dir}/tuning_policy_bundle.json" \
      --current-policy-state-json "$policy_state" \
      --source-revision "drill-${case_name}" \
      --output-dir "$guard_dir"

  if [[ "$expected_guard_codes" == "42" ]]; then
    write_guard_reject_case_summary "$case_name" "$packer_dir" "$guard_dir"
    return 0
  fi

  run_step "rollback-comparator-${case_name}" "0" \
    env SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR_GENERATED_AT="2026-05-06T00:00:00Z" \
    bash "$rollback_comparator" \
      --candidate-bundle-json "${packer_dir}/tuning_policy_bundle.json" \
      --rollout-plan-json "${guard_dir}/manual_approval_rollout_plan.json" \
      --current-policy-state-json "$policy_state" \
      --source-revision "drill-${case_name}" \
      --output-dir "$comparator_dir"

  run_operator_status_handoff "$case_name" "$input_dir" "$packer_dir" "$guard_dir" "$comparator_dir" "$status_dir"
  write_success_case_summary "$case_name" "$input_dir" "$packer_dir" "$guard_dir" "$comparator_dir" "$status_dir"
}

write_manifest() {
  local source_revision
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"

  jq -s \
    --arg schema_version "franken-engine.swarm-execution-queue-tuning-lifecycle-no-mock-drill.v1" \
    --arg bead_id "bd-j2rny.6" \
    --arg parent_bead_id "bd-j2rny" \
    --arg source_revision "$source_revision" \
    --arg run_dir "$run_dir" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    '{
      schema_version:$schema_version,
      bead_id:$bead_id,
      parent_bead_id:$parent_bead_id,
      source_revision:$source_revision,
      decision:(if all(.[]; .decision == "pass" or .decision == "fail_closed") then "pass" else "fail_closed" end),
      covered_cases:map(.case_id),
      case_summaries:.,
      assertions:{
        includes_eligible_canary:(map(.case_id) | index("eligible_canary") != null),
        includes_stale_evidence_reject:(map(.case_id) | index("stale_evidence_reject") != null),
        includes_rollback_required:(map(.case_id) | index("rollback_required") != null),
        eligible_canary_published_to_operator_status:any(.[]; .case_id == "eligible_canary" and .operator_readiness == "ready"),
        stale_evidence_stops_before_comparator:any(.[]; .case_id == "stale_evidence_reject" and .assertions.comparator_skipped_after_guard_reject == true),
        rollback_required_surfaces_to_operator_status:any(.[]; .case_id == "rollback_required" and .operator_readiness == "rollback_required"),
        all_operator_handoffs_advisory_only:all(.[]; (.assertions.operator_status_advisory_only // .assertions.rollout_plan_stays_advisory // true) == true)
      },
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false,
        mutates_br:false,
        sends_agent_mail:false,
        mutates_remote_workers:false,
        rewrites_historical_outcomes:false
      },
      artifact_paths:{
        run_dir:$run_dir,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_md
      }
    }' "${run_dir}"/*/case_summary.json >"$report_json"

  {
    printf '# Swarm Execution Queue Tuning Lifecycle No-Mock Drill\n\n'
    printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$report_json")"
    printf -- "- Cases: \`%s\`\n\n" "$(jq '.covered_cases | length' "$report_json")"
    jq -r '.case_summaries[] | "- `" + .case_id + "`: promotion=`" + .promotion_decision + "` rollback=`" + .rollback_verdict + "` operator=`" + .operator_readiness + "`"' "$report_json"
    printf '\n## Artifacts\n\n'
    jq -r '.case_summaries[] | .case_id as $case | .artifact_paths | to_entries[] | "- `" + $case + "." + .key + "`: `" + .value + "`"' "$report_json"
  } >"$report_md"
}

run_check() {
  refresh_paths
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$packer"
  bash -n "$promotion_guard"
  bash -n "$rollback_comparator"
  bash -n "$operator_status"
  bash -n "$truth_gate"
  jq empty "$contract_path" >/dev/null
  bash "$truth_gate" check >/dev/null
  record_pass "syntax contract and truth gate"
}

run_mode() {
  ensure_run_dir
  printf './scripts/e2e/swarm_execution_queue_tuning_lifecycle_no_mock_drill.sh %q --output-dir %q\n' "$mode" "$run_dir" >"$commands_path"
  run_lifecycle_case "eligible_canary" 240000 "one_clear_improvement" "fresh" "0"
  run_lifecycle_case "stale_evidence_reject" 240000 "one_clear_improvement" "stale" "42"
  run_lifecycle_case "rollback_required" -64000 "no_improvement" "fresh" "0"
  write_manifest

  jq -e '
    .decision == "pass"
    and .assertions.includes_eligible_canary
    and .assertions.includes_stale_evidence_reject
    and .assertions.includes_rollback_required
    and .assertions.eligible_canary_published_to_operator_status
    and .assertions.stale_evidence_stops_before_comparator
    and .assertions.rollback_required_surfaces_to_operator_status
    and .assertions.all_operator_handoffs_advisory_only
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
  ' "$report_json" >/dev/null
  record_pass "drill report ${report_json}"
  printf 'swarm_execution_queue_tuning_lifecycle_no_mock_drill_artifacts=%s\n' "$run_dir"
}

run_selftest() {
  local tmp_parent run_output

  run_check
  tmp_parent="${SWARM_EXECUTION_QUEUE_TUNING_LIFECYCLE_NO_MOCK_DRILL_SELFTEST_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  run_output="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-tuning-lifecycle-no-mock-drill.XXXXXX")"
  bash "${BASH_SOURCE[0]}" run --output-dir "$run_output"
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-tuning-lifecycle-no-mock-drill.v1"
    and .decision == "pass"
    and (.covered_cases | length) == 3
    and any(.case_summaries[]; .case_id == "eligible_canary" and .promotion_decision == "eligible_canary" and .operator_readiness == "ready")
    and any(.case_summaries[]; .case_id == "stale_evidence_reject" and .decision == "fail_closed" and .promotion_decision == "reject")
    and any(.case_summaries[]; .case_id == "rollback_required" and .rollback_verdict == "worse_than_current" and .operator_readiness == "rollback_required")
  ' "${run_output}/swarm_execution_queue_tuning_lifecycle_no_mock_drill_report.json" >/dev/null
  record_pass "selftest report validates"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_mode
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
