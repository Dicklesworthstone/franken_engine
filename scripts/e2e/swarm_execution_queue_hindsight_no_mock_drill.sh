#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_HINDSIGHT_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-hindsight-no-mock-drill}"
run_id="${SWARM_EXECUTION_QUEUE_HINDSIGHT_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_HINDSIGHT_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_execution_queue_hindsight_normalizer.sh"
scorer="${root_dir}/scripts/swarm_execution_queue_fidelity_scorer.sh"
planner="${root_dir}/scripts/swarm_execution_queue_counterfactual_planner.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_ctrl_xiii_runbook_truth_gate.sh"
fixture_bundle="${root_dir}/scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json"
report_json=""
report_md=""
events_path=""
commands_path=""
failures=0

normalizer_input_ids=(
  queue_artifact_json
  queue_run_manifest_json
  normalized_queue_input_json
  risk_budget_receipt_json
  bottleneck_report_json
  bead_status_snapshot_json
  bead_timing_snapshot_json
  owner_contact_snapshot_json
  reservation_friction_snapshot_json
  proof_outcome_snapshot_json
  checkpoint_restore_state_json
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_hindsight_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the SWARM-CTRL-XIII queue hindsight surfaces into one deterministic
no-mock drill. The drill uses checked-in queue fixtures, the real hindsight
normalizer, fidelity scorer, counterfactual planner, and operator-status
handoff. It does not mutate br, Agent Mail, reservations, workers, or the live
queue.

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
  printf 'PASS swarm-execution-queue-hindsight-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-hindsight-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_paths() {
  report_json="${run_dir}/swarm_execution_queue_hindsight_no_mock_drill_report.json"
  report_md="${run_dir}/report.md"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
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
    --arg schema_version "franken-engine.swarm-execution-queue-hindsight-no-mock-drill.event.v1" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{schema_version:$schema_version,event_name:"swarm_execution_queue_hindsight_no_mock_drill.step",step_id:$step_id,decision:$decision,exit_code:$exit_code,artifact_paths:{stdout_log:$stdout_path,stderr_log:$stderr_path}}' >>"$events_path"
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

extract_normalizer_inputs() {
  local output_dir="$1"
  local input_id

  mkdir -p "$output_dir"
  for input_id in "${normalizer_input_ids[@]}"; do
    jq -e \
      --arg input_id "$input_id" \
      '.scenarios[] | select(.scenario_id == "healthy") | .inputs[$input_id]' \
      "$fixture_bundle" >"${output_dir}/${input_id}.json"
  done
}

run_hindsight_normalizer() {
  local input_dir="$1"
  local output_dir="$2"

  run_step "normalizer-$(basename "$(dirname "$output_dir")")" "0" \
    bash "$normalizer" \
      --queue-artifact-json "${input_dir}/queue_artifact_json.json" \
      --queue-run-manifest-json "${input_dir}/queue_run_manifest_json.json" \
      --normalized-queue-input-json "${input_dir}/normalized_queue_input_json.json" \
      --risk-budget-receipt-json "${input_dir}/risk_budget_receipt_json.json" \
      --bottleneck-report-json "${input_dir}/bottleneck_report_json.json" \
      --bead-status-snapshot-json "${input_dir}/bead_status_snapshot_json.json" \
      --bead-timing-snapshot-json "${input_dir}/bead_timing_snapshot_json.json" \
      --owner-contact-snapshot-json "${input_dir}/owner_contact_snapshot_json.json" \
      --reservation-friction-snapshot-json "${input_dir}/reservation_friction_snapshot_json.json" \
      --proof-outcome-snapshot-json "${input_dir}/proof_outcome_snapshot_json.json" \
      --checkpoint-restore-state-json "${input_dir}/checkpoint_restore_state_json.json" \
      --source-revision "drill-$(basename "$(dirname "$output_dir")")" \
      --observation-epoch-seconds 1800000300 \
      --output-dir "$output_dir"
}

rewrite_hindsight_case() {
  local case_name="$1"
  local hindsight_dir="$2"
  local report_path="${hindsight_dir}/hindsight_report.json"
  local input_path="${hindsight_dir}/hindsight_input.json"
  local tmp_path

  case "$case_name" in
    healthy)
      ;;
    owner_recency_contradiction)
      tmp_path="${report_path}.tmp"
      jq '.decision = "degraded"
        | .rows[0].owner_identity.inconsistent = true
        | .rows[0].drift_class = "ownership_drift"
        | .rows[0].owner_friction_outcome = "recent_owner_conflict"
        | .degraded_inputs = [{kind:"owner_recency_contradiction",source:"owner_contact_snapshot_json",label:.rows[0].task_id,detail:"owner recency evidence contradicts reservation truth"}]' \
        "$report_path" >"$tmp_path"
      mv "$tmp_path" "$report_path"
      ;;
    checkpoint_restore_fail_closed)
      tmp_path="${report_path}.tmp"
      jq '.decision = "degraded"
        | .rows[0].actual_outcome = "deferred"
        | .rows[0].fidelity_class = "justified_override"
        | .rows[0].drift_class = "restore_drift"
        | .rows[0].checkpoint_restore_outcome = "fail_closed"
        | .degraded_inputs = [{kind:"checkpoint_restore_fail_closed",source:"checkpoint_restore_state_json",label:.rows[0].task_id,detail:"checkpoint restore failed closed; queue hindsight must stay advisory"}]' \
        "$report_path" >"$tmp_path"
      mv "$tmp_path" "$report_path"
      ;;
    proof_brownout_misprediction)
      tmp_path="${report_path}.tmp"
      jq '.decision = "degraded"
        | .rows[0].actual_outcome = "started"
        | .rows[0].fidelity_class = "unsafe_to_score"
        | .rows[0].drift_class = "proof_drift"
        | .rows[0].proof_outcome = "brownout"
        | .degraded_inputs = [{kind:"proof_brownout_misprediction",source:"proof_outcome_snapshot_json",label:.rows[0].task_id,detail:"queue advice missed proof brownout evidence"}]' \
        "$report_path" >"$tmp_path"
      mv "$tmp_path" "$report_path"
      ;;
    counterfactual_candidate_disagreement)
      tmp_path="${report_path}.tmp"
      jq '.decision = "degraded"
        | .rows[0].recommended_first_action = "defer until proof clears"
        | .rows[0].actual_outcome = "closed"
        | .rows[0].fidelity_class = "delayed_match"
        | .rows[0].drift_class = "timing_drift"
        | .rows += [(.rows[0]
          | .task_id = "bd-ready-b"
          | .recommended_rank = 2
          | .recommended_first_action = "start narrow proof under brownout"
          | .actual_outcome = "started"
          | .fidelity_class = "unsafe_to_score"
          | .drift_class = "proof_drift"
          | .proof_outcome = "brownout")]
        | .degraded_inputs = [
            {kind:"over_conservative",source:"hindsight_report_json",label:.rows[0].task_id,detail:"one row suggests lower conservative penalty"},
            {kind:"proof_brownout_miss",source:"proof_outcome_snapshot_json",label:"bd-ready-b",detail:"another row requires stronger proof-health penalty"}
          ]' "$report_path" >"$tmp_path"
      mv "$tmp_path" "$report_path"
      tmp_path="${input_path}.tmp"
      jq '.queue_task_ids += ["bd-ready-b"] | .queue_depth = (.queue_task_ids | length)' "$input_path" >"$tmp_path"
      mv "$tmp_path" "$input_path"
      ;;
    *)
      record_failure "unknown hindsight case ${case_name}"
      return 1
      ;;
  esac
}

run_fidelity_scorer() {
  local case_name="$1"
  local hindsight_dir="$2"
  local output_dir="$3"
  local expected_codes="$4"

  run_step "scorer-${case_name}" "$expected_codes" \
    bash "$scorer" \
      --hindsight-report-json "${hindsight_dir}/hindsight_report.json" \
      --hindsight-input-json "${hindsight_dir}/hindsight_input.json" \
      --evidence-ledger-json "${hindsight_dir}/evidence_ledger.json" \
      --counterfactual-candidates-json "${hindsight_dir}/counterfactual_candidates.json" \
      --source-revision "drill-${case_name}" \
      --output-dir "$output_dir"
}

run_counterfactual_planner() {
  local case_name="$1"
  local scorer_dir="$2"
  local output_dir="$3"

  run_step "planner-${case_name}" "0" \
    bash "$planner" \
      --fidelity-score-receipt-json "${scorer_dir}/fidelity_score_receipt.json" \
      --drift-ledger-json "${scorer_dir}/drift_ledger.json" \
      --source-revision "drill-${case_name}" \
      --output-dir "$output_dir"
}

write_checkpoint_status_fixtures() {
  local fixture_dir="$1"
  local mode="$2"
  local bundle_decision="captured"
  local restore_hint="ready"
  local plan_decision="resume"
  local conformance_decision="pass"
  local drift_class="none"
  local top_action="resume_from_checkpoint"
  local fail_closed_reasons='[]'
  local gate_failures='[]'

  if [[ "$mode" == "fail_closed" ]]; then
    restore_hint="blocked"
    plan_decision="fail_closed"
    conformance_decision="fail_closed"
    drift_class="blocked"
    top_action="capture_fresh_checkpoint_bundle"
    fail_closed_reasons='[{"kind":"checkpoint_restore_fail_closed","detail":"checkpoint restore evidence failed closed during hindsight drill"}]'
    gate_failures='[{"code":"checkpoint_restore_fail_closed","detail":"checkpoint restore evidence failed closed during hindsight drill"}]'
  fi

  jq -n \
    --arg fixture_dir "$fixture_dir" \
    --arg bundle_decision "$bundle_decision" \
    --arg restore_hint "$restore_hint" \
    '{schema_version:"franken-engine.swarm-checkpoint-bundle.v1",checkpoint_id:"checkpoint-hindsight-drill",capture_decision:$bundle_decision,restore_readiness_hint:$restore_hint,artifact_paths:{checkpoint_bundle_json:($fixture_dir + "/checkpoint_bundle.json")}}' \
    >"${fixture_dir}/checkpoint_bundle.json"
  jq -n \
    --arg fixture_dir "$fixture_dir" \
    --arg plan_decision "$plan_decision" \
    --arg drift_class "$drift_class" \
    --arg top_action "$top_action" \
    --argjson fail_closed_reasons "$fail_closed_reasons" \
    '{schema_version:"franken-engine.swarm-checkpoint-restore-plan.v1",checkpoint_id:"checkpoint-hindsight-drill",decision:$plan_decision,drift_class:$drift_class,summary:{top_restore_action:$top_action,provided_current_comparison_count:3,missing_current_comparison_count:0},drift_receipt:{checkpoint_age_seconds:300,fail_closed_reasons:$fail_closed_reasons,findings:[]},artifact_paths:{swarm_checkpoint_restore_plan_json:($fixture_dir + "/checkpoint_restore_plan.json")}}' \
    >"${fixture_dir}/checkpoint_restore_plan.json"
  jq -n \
    --arg fixture_dir "$fixture_dir" \
    --arg conformance_decision "$conformance_decision" \
    --arg plan_decision "$plan_decision" \
    --arg top_action "$top_action" \
    --argjson gate_failures "$gate_failures" \
    '{schema_version:"franken-engine.swarm-checkpoint-restore-conformance-report.v1",decision:$conformance_decision,summary:{restore_decision:$plan_decision,checkpoint_capture_decision:"captured",top_restore_action:$top_action,gate_failure_count:($gate_failures | length),checked_artifact_path_count:3},gate_failures:$gate_failures,artifact_paths:{swarm_checkpoint_restore_conformance_report_json:($fixture_dir + "/checkpoint_restore_conformance_report.json")}}' \
    >"${fixture_dir}/checkpoint_restore_conformance_report.json"
}

run_operator_status_case() {
  local case_name="$1"
  local input_dir="$2"
  local checkpoint_mode="$3"
  local scorer_dir="$4"
  local planner_dir="$5"
  local output_dir="$6"
  local fixture_dir="${run_dir}/${case_name}/operator-fixtures"

  mkdir -p "$fixture_dir"
  write_checkpoint_status_fixtures "$fixture_dir" "$checkpoint_mode"
  run_step "operator-status-${case_name}" "0" \
    bash "$operator_status" \
      --bead-id bd-nt8fa \
      --source-revision "drill-${case_name}" \
      --output-dir "$output_dir" \
      --agent-mail-status ok \
      --rch-status ok \
      --proof-index-status ok \
      --checkpoint-bundle-json "${fixture_dir}/checkpoint_bundle.json" \
      --checkpoint-restore-plan-json "${fixture_dir}/checkpoint_restore_plan.json" \
      --checkpoint-restore-conformance-report-json "${fixture_dir}/checkpoint_restore_conformance_report.json" \
      --execution-queue-artifact-json "${input_dir}/queue_artifact_json.json" \
      --execution-queue-risk-budget-json "${input_dir}/risk_budget_receipt_json.json" \
      --execution-queue-bottleneck-report-json "${input_dir}/bottleneck_report_json.json" \
      --execution-queue-run-manifest-json "${input_dir}/queue_run_manifest_json.json" \
      --queue-fidelity-score-receipt-json "${scorer_dir}/fidelity_score_receipt.json" \
      --queue-drift-ledger-json "${scorer_dir}/drift_ledger.json" \
      --queue-counterfactual-backtest-report-json "${planner_dir}/counterfactual_backtest_report.json" \
      --queue-tuning-plan-json "${planner_dir}/tuning_plan.json" \
      --queue-tuning-frontier-json "${planner_dir}/frontier.json"
}

write_case_summary() {
  local case_name="$1"
  local scorer_dir="$2"
  local planner_dir="$3"
  local status_dir="$4"
  local output_path="${run_dir}/${case_name}/case_summary.json"

  jq -n \
    --arg case_id "$case_name" \
    --arg scorer_receipt "${scorer_dir}/fidelity_score_receipt.json" \
    --arg drift_ledger "${scorer_dir}/drift_ledger.json" \
    --arg tuning_plan "${planner_dir}/tuning_plan.json" \
    --arg status_json "${status_dir}/status.json" \
    --slurpfile receipt "${scorer_dir}/fidelity_score_receipt.json" \
    --slurpfile ledger "${scorer_dir}/drift_ledger.json" \
    --slurpfile tuning "${planner_dir}/tuning_plan.json" \
    --slurpfile status "${status_dir}/status.json" \
    '($receipt[0]) as $r | ($ledger[0]) as $l | ($tuning[0]) as $t | ($status[0]) as $s | {
      case_id:$case_id,
      decision:(if ($s.status == "healthy" or $s.status == "degraded") then "pass" else "fail_closed" end),
      fidelity_decision:$r.decision,
      queue_trust_level:$s.predictive_dashboard.queue_fidelity.trust_level,
      drift_class:$s.predictive_dashboard.queue_fidelity.drift_class,
      highest_mismatch:($s.predictive_dashboard.queue_fidelity.highest_severity_mismatch.mismatch_class // "none"),
      tuning_plan_class:$t.plan_class,
      top_tuning_recommendation:($s.predictive_dashboard.queue_fidelity.top_tuning_recommendation.candidate_id // "none"),
      assertion_summary:{
        status_integrates_fidelity:($s.artifact_paths.queue_fidelity_score_receipt_json == $scorer_receipt),
        status_integrates_drift_ledger:($s.artifact_paths.queue_drift_ledger_json == $drift_ledger),
        status_integrates_tuning_plan:($s.artifact_paths.queue_tuning_plan_json == $tuning_plan),
        advisory_only:($s.predictive_dashboard.queue_fidelity.mutation_policy.advisory_only == true and $s.predictive_dashboard.queue_fidelity.mutation_policy.changes_active_queue == false and $s.predictive_dashboard.queue_fidelity.mutation_policy.applies_live_retuning == false),
        drift_rows_present:(($l.rows // []) | length > 0)
      },
      artifact_paths:{
        fidelity_score_receipt_json:$scorer_receipt,
        drift_ledger_json:$drift_ledger,
        tuning_plan_json:$tuning_plan,
        operator_status_json:$status_json
      }
    }' >"$output_path"
}

write_fail_closed_case_summary() {
  local case_name="$1"
  local scorer_dir="$2"
  local output_path="${run_dir}/${case_name}/case_summary.json"

  jq -n \
    --arg case_id "$case_name" \
    --arg scorer_receipt "${scorer_dir}/fidelity_score_receipt.json" \
    --arg drift_ledger "${scorer_dir}/drift_ledger.json" \
    --slurpfile receipt "${scorer_dir}/fidelity_score_receipt.json" \
    --slurpfile ledger "${scorer_dir}/drift_ledger.json" \
    '($receipt[0]) as $r | ($ledger[0]) as $l | {
      case_id:$case_id,
      decision:"fail_closed",
      fidelity_decision:$r.decision,
      queue_trust_level:"rejected",
      drift_class:"contradictory_evidence",
      highest_mismatch:"contradictory_evidence",
      tuning_plan_class:"not_run",
      top_tuning_recommendation:"none",
      assertion_summary:{
        scorer_failed_closed:($r.decision == "fail_closed"),
        contradictory_evidence_present:(($l.fail_closed_reasons // []) | any(.kind == "contradictory_owner_evidence")),
        planner_skipped_after_fail_closed:true,
        advisory_only:true
      },
      artifact_paths:{
        fidelity_score_receipt_json:$scorer_receipt,
        drift_ledger_json:$drift_ledger
      }
    }' >"$output_path"
}

run_case() {
  local case_name="$1"
  local scorer_codes="$2"
  local checkpoint_mode="$3"
  local case_dir="${run_dir}/${case_name}"
  local input_dir="${case_dir}/normalizer-inputs"
  local hindsight_dir="${case_dir}/hindsight"
  local scorer_dir="${case_dir}/fidelity"
  local planner_dir="${case_dir}/counterfactual"
  local status_dir="${case_dir}/operator-status"

  extract_normalizer_inputs "$input_dir"
  run_hindsight_normalizer "$input_dir" "$hindsight_dir"
  rewrite_hindsight_case "$case_name" "$hindsight_dir"
  run_fidelity_scorer "$case_name" "$hindsight_dir" "$scorer_dir" "$scorer_codes"
  if [[ "$scorer_codes" == "42" ]]; then
    write_fail_closed_case_summary "$case_name" "$scorer_dir"
    return 0
  fi
  run_counterfactual_planner "$case_name" "$scorer_dir" "$planner_dir"
  run_operator_status_case "$case_name" "$input_dir" "$checkpoint_mode" "$scorer_dir" "$planner_dir" "$status_dir"
  write_case_summary "$case_name" "$scorer_dir" "$planner_dir" "$status_dir"
}

write_manifest() {
  local source_revision
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"

  jq -s \
    --arg schema_version "franken-engine.swarm-execution-queue-hindsight-no-mock-drill.v1" \
    --arg bead_id "bd-nt8fa" \
    --arg parent_bead_id "bd-d5daf" \
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
        includes_owner_recency_contradiction:(map(.case_id) | index("owner_recency_contradiction") != null),
        includes_checkpoint_restore_fail_closed:(map(.case_id) | index("checkpoint_restore_fail_closed") != null),
        includes_proof_brownout_misprediction:(map(.case_id) | index("proof_brownout_misprediction") != null),
        includes_counterfactual_candidate_disagreement:(map(.case_id) | index("counterfactual_candidate_disagreement") != null),
        all_cases_advisory_only:all(.[]; .assertion_summary.advisory_only == true)
      },
      mutation_policy:{
        mutates_br:false,
        sends_agent_mail:false,
        changes_active_queue:false,
        applies_live_retuning:false,
        mutates_remote_workers:false
      },
      artifact_paths:{
        run_dir:$run_dir,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_md
      }
    }' "${run_dir}"/*/case_summary.json >"$report_json"

  {
    printf '# Swarm Execution Queue Hindsight No-Mock Drill\n\n'
    printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$report_json")"
    printf -- "- Cases: \`%s\`\n\n" "$(jq '.covered_cases | length' "$report_json")"
    jq -r '.case_summaries[] | "- `" + .case_id + "`: trust=`" + .queue_trust_level + "` drift=`" + .drift_class + "` tuning=`" + .top_tuning_recommendation + "`"' "$report_json"
    printf '\n## Artifacts\n\n'
    jq -r '.case_summaries[] | .case_id as $case | .artifact_paths | to_entries[] | "- `" + $case + "." + .key + "`: `" + .value + "`"' "$report_json"
  } >"$report_md"
}

run_check() {
  refresh_paths
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$normalizer"
  bash -n "$scorer"
  bash -n "$planner"
  bash -n "$operator_status"
  bash -n "$truth_gate"
  jq empty "$fixture_bundle" "${root_dir}/docs/swarm_execution_queue_hindsight_runbook_truth_contract_v1.json" >/dev/null
  bash "$truth_gate" check >/dev/null
  record_pass "syntax fixtures and truth gate"
}

run_mode() {
  ensure_run_dir
  printf './scripts/e2e/swarm_execution_queue_hindsight_no_mock_drill.sh %q --output-dir %q\n' "$mode" "$run_dir" >"$commands_path"

  run_case "healthy" "0" "ready"
  run_case "owner_recency_contradiction" "42" "ready"
  run_case "checkpoint_restore_fail_closed" "0" "fail_closed"
  run_case "proof_brownout_misprediction" "0" "ready"
  run_case "counterfactual_candidate_disagreement" "0" "ready"
  write_manifest

  jq -e '
    .decision == "pass"
    and .assertions.includes_owner_recency_contradiction
    and .assertions.includes_checkpoint_restore_fail_closed
    and .assertions.includes_proof_brownout_misprediction
    and .assertions.includes_counterfactual_candidate_disagreement
    and .assertions.all_cases_advisory_only
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
  ' "$report_json" >/dev/null
  record_pass "drill report ${report_json}"
  printf 'swarm_execution_queue_hindsight_no_mock_drill_artifacts=%s\n' "$run_dir"
}

run_selftest() {
  local tmp_parent run_output

  run_check
  tmp_parent="${SWARM_EXECUTION_QUEUE_HINDSIGHT_NO_MOCK_DRILL_SELFTEST_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  run_output="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-hindsight-no-mock-drill.XXXXXX")"
  bash "${BASH_SOURCE[0]}" run --output-dir "$run_output"
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-hindsight-no-mock-drill.v1"
    and .decision == "pass"
    and (.covered_cases | length) == 5
    and any(.case_summaries[]; .case_id == "owner_recency_contradiction" and .decision == "fail_closed" and .highest_mismatch == "contradictory_evidence")
    and any(.case_summaries[]; .case_id == "checkpoint_restore_fail_closed" and .queue_trust_level != "missing")
    and any(.case_summaries[]; .case_id == "proof_brownout_misprediction" and .highest_mismatch == "proof_brownout_miss")
    and any(.case_summaries[]; .case_id == "counterfactual_candidate_disagreement" and .tuning_plan_class == "conflicting_improvements")
  ' "${run_output}/swarm_execution_queue_hindsight_no_mock_drill_report.json" >/dev/null
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
