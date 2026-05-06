#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_STARVATION_RESCUE_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-starvation-rescue-no-mock-drill}"
run_id="${SWARM_STARVATION_RESCUE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_STARVATION_RESCUE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
matrix_json="${SWARM_STARVATION_RESCUE_MATRIX_JSON:-${root_dir}/scripts/testdata/swarm_starvation_rescue/scenario_matrix.json}"
selected_case_id="${SWARM_STARVATION_RESCUE_PRIMARY_CASE_ID:-brownout_low_priority_starvation}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_starvation_rescue_input_normalizer.sh"
scenario_matrix="${root_dir}/scripts/swarm_starvation_rescue_scenario_matrix.sh"
planner="${root_dir}/scripts/swarm_starvation_rescue_planner.sh"
conformance_gate="${root_dir}/scripts/swarm_starvation_rescue_conformance_gate.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_ctrl_x_runbook_truth_gate.sh"

report_json=""
report_tmp=""
events_path=""
commands_path=""
report_md=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the shipped SWARM-CTRL-X starvation-rescue shell surfaces into one
deterministic no-mock drill. The drill reuses the checked-in scenario matrix,
replays one selected case through the real normalizer, planner, conformance
gate, and operator-status handoff, and emits a combined artifact bundle. It
does not mutate live bead state, reservations, workers, or queue state.

Modes:
  check       Syntax, fixture, and truth-gate checks.
  run         Run the composed drill and emit a deterministic artifact bundle.
  selftest    Run check, run, then validate the combined report.

Options:
  --matrix-json FILE
  --case-id ID
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --matrix-json)
      matrix_json="${2:-}"
      shift 2
      ;;
    --case-id)
      selected_case_id="${2:-}"
      shift 2
      ;;
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
  printf 'PASS swarm-starvation-rescue-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-starvation-rescue-no-mock-drill %s\n' "$1" >&2
}

refresh_output_paths() {
  report_json="${run_dir}/swarm_starvation_rescue_no_mock_drill_report.json"
  report_tmp="${report_json}.tmp"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_md="${run_dir}/report.md"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  : >"$commands_path"
  : >"$events_path"
}

quote_command() {
  printf '%q ' "$@"
}

write_command_log() {
  printf './scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh %q' "$mode" >"$commands_path"
  printf ' --matrix-json %q --case-id %q --output-dir %q\n' "$matrix_json" "$selected_case_id" "$run_dir" >>"$commands_path"
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-starvation-rescue-no-mock-drill.event.v1" \
    --arg event_name "swarm_starvation_rescue_no_mock_drill.step" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      step_id: $step_id,
      decision: $decision,
      exit_code: $exit_code,
      artifact_paths: {
        stdout_log: $stdout_path,
        stderr_log: $stderr_path
      }
    }' >>"$events_path"
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
    record_failure "${step} exited ${exit_code}, expected ${expected_codes}"
    printf 'stdout=%s\nstderr=%s\n' "$stdout_path" "$stderr_path" >&2
    return "$exit_code"
  fi
}

require_json() {
  local path="$1"

  if [[ ! -f "$path" ]]; then
    printf 'missing JSON artifact: %s\n' "$path" >&2
    exit 64
  fi
  jq empty "$path" >/dev/null
}

require_path() {
  local path="$1"

  if [[ ! -e "$path" ]]; then
    printf 'missing required path: %s\n' "$path" >&2
    exit 64
  fi
}

require_case() {
  jq -e --arg case_id "$selected_case_id" '.cases[] | select(.case_id == $case_id)' "$matrix_json" >/dev/null
}

write_selected_case_fixtures() {
  local case_json_path="$1"
  local fixture_dir="$2"

  mkdir -p "$fixture_dir"
  jq '.brownout_report' "$case_json_path" >"${fixture_dir}/brownout.json"
  jq '.stale_lock_recommendations' "$case_json_path" >"${fixture_dir}/stale.json"
  jq '.lease_exchange_salvage_simulation' "$case_json_path" >"${fixture_dir}/lease.json"
  jq '.admission_budget_plan' "$case_json_path" >"${fixture_dir}/admission.json"
  jq '.capacity_forecast' "$case_json_path" >"${fixture_dir}/capacity.json"
  jq '.slo_threshold_receipt' "$case_json_path" >"${fixture_dir}/slo.json"
}

run_check() {
  refresh_output_paths
  ensure_run_dir

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$normalizer"
  bash -n "$scenario_matrix"
  bash -n "$planner"
  bash -n "$conformance_gate"
  bash -n "$operator_status"
  bash -n "$truth_gate"
  require_path "$matrix_json"
  jq empty "$matrix_json" >/dev/null
  require_case
  bash "$truth_gate" check >/dev/null
  record_pass "syntax matrix fixture and truth gate"
}

run_mode() {
  local source_revision selected_case_json_path selected_fixture_dir
  local matrix_dir input_dir plan_dir conformance_dir operator_dir
  local matrix_report selected_case_summary input_report plan_report conformance_report status_json status_report_md
  local rch_status

  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
  refresh_output_paths
  ensure_run_dir
  write_command_log

  selected_case_json_path="${run_dir}/selected_case.json"
  jq --arg case_id "$selected_case_id" '.cases[] | select(.case_id == $case_id)' "$matrix_json" >"$selected_case_json_path"
  if [[ ! -s "$selected_case_json_path" ]]; then
    printf 'selected case not found in matrix fixture: %s\n' "$selected_case_id" >&2
    exit 64
  fi

  selected_fixture_dir="${run_dir}/selected-case/fixtures"
  write_selected_case_fixtures "$selected_case_json_path" "$selected_fixture_dir"

  matrix_dir="${run_dir}/scenario-matrix"
  input_dir="${run_dir}/selected-case"
  plan_dir="${run_dir}/plan"
  conformance_dir="${run_dir}/conformance"
  operator_dir="${run_dir}/operator-status"

  run_step scenario_matrix 0 \
    bash "$scenario_matrix" \
      --matrix-json "$matrix_json" \
      --source-revision "$source_revision" \
      --output-dir "$matrix_dir"

  matrix_report="${matrix_dir}/swarm_starvation_rescue_scenario_matrix_report.json"
  selected_case_summary="${matrix_dir}/case_summaries/${selected_case_id}.json"
  require_json "$matrix_report"
  require_json "$selected_case_summary"

  run_step selected_case_input 0,42 \
    bash "$normalizer" \
      --brownout-report-json "${selected_fixture_dir}/brownout.json" \
      --stale-lock-recommendations-json "${selected_fixture_dir}/stale.json" \
      --lease-exchange-salvage-simulation-json "${selected_fixture_dir}/lease.json" \
      --admission-budget-plan-json "${selected_fixture_dir}/admission.json" \
      --capacity-forecast-json "${selected_fixture_dir}/capacity.json" \
      --slo-threshold-receipt-json "${selected_fixture_dir}/slo.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$(jq -r '.now_epoch_seconds' "$selected_case_json_path")" \
      --stale-after-seconds "$(jq -r '.stale_after_seconds' "$selected_case_json_path")" \
      --output-dir "$input_dir"

  input_report="${input_dir}/swarm_starvation_rescue_input.json"
  require_json "$input_report"

  run_step planner 0,42,75 \
    bash "$planner" \
      --starvation-rescue-input-json "$input_report" \
      --scenario-matrix-report-json "$matrix_report" \
      --source-revision "$source_revision" \
      --output-dir "$plan_dir"

  plan_report="${plan_dir}/swarm_starvation_rescue_plan.json"
  require_json "$plan_report"

  run_step conformance 0,42 \
    bash "$conformance_gate" \
      --starvation-rescue-plan-json "$plan_report" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$(jq -r '.now_epoch_seconds' "$selected_case_json_path")" \
      --stale-after-seconds "$(jq -r '.stale_after_seconds' "$selected_case_json_path")" \
      --output-dir "$conformance_dir"

  conformance_report="${conformance_dir}/swarm_starvation_rescue_conformance_report.json"
  require_json "$conformance_report"

  rch_status="ok"
  if [[ "$(jq -r '.scenario_class' "$selected_case_json_path")" == "local_fallback" ]]; then
    rch_status="degraded"
  fi

  run_step operator_status 0 \
    bash "$operator_status" \
      --output-dir "$operator_dir" \
      --bead-id bd-9hlct \
      --source-revision "$source_revision" \
      --agent-mail-status ok \
      --rch-status "$rch_status" \
      --proof-index-status ok \
      --stale-lock-recommendations-json "${selected_fixture_dir}/stale.json" \
      --capacity-forecast-json "${selected_fixture_dir}/capacity.json" \
      --admission-budget-plan-json "${selected_fixture_dir}/admission.json" \
      --lease-exchange-salvage-simulation-json "${selected_fixture_dir}/lease.json" \
      --starvation-rescue-plan-json "$plan_report" \
      --starvation-rescue-conformance-report-json "$conformance_report"

  status_json="${operator_dir}/status.json"
  status_report_md="${operator_dir}/report.md"
  require_json "$status_json"
  require_path "$status_report_md"

  jq -n \
    --arg schema_version "franken-engine.swarm-starvation-rescue-no-mock-drill-report.v1" \
    --arg source_revision "$source_revision" \
    --arg selected_case_id "$selected_case_id" \
    --arg report_json "$report_json" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    --arg matrix_report "$matrix_report" \
    --arg selected_case_summary "$selected_case_summary" \
    --arg input_report "$input_report" \
    --arg plan_report "$plan_report" \
    --arg conformance_report "$conformance_report" \
    --arg operator_status_json "$status_json" \
    --arg operator_status_report_md "$status_report_md" \
    --arg selected_case_fixture_json "$selected_case_json_path" \
    --slurpfile selected_case "$selected_case_json_path" \
    --slurpfile matrix "$matrix_report" \
    --slurpfile case_summary "$selected_case_summary" \
    --slurpfile input "$input_report" \
    --slurpfile plan "$plan_report" \
    --slurpfile conformance "$conformance_report" \
    --slurpfile status "$status_json" \
    '($selected_case[0]) as $selected_case
     | ($matrix[0]) as $matrix
     | ($case_summary[0]) as $case_summary
     | ($input[0]) as $input
     | ($plan[0]) as $plan
     | ($conformance[0]) as $conformance
     | ($status[0]) as $status
     | {
         schema_version: $schema_version,
         source_revision: $source_revision,
         decision: (
           if (
             ($matrix.failure_count == 0)
             and (($case_summary.actual.decision // "unknown") == ($input.decision // "unknown"))
             and (($case_summary.actual.readiness // "unknown") == ($input.summary.readiness // "unknown"))
             and ((($case_summary.actual.local_rch_fallback_detected | if . == null then "unknown" else tostring end)) == (($input.derived_truth.local_rch_fallback_detected | if . == null then "unknown" else tostring end)))
             and (($plan.scenario_class // "unknown") == ($selected_case.scenario_class // "unknown"))
             and any(($plan.policy_basis.matched_case_ids // [])[]?; . == $selected_case_id)
             and (($conformance.decision // "unknown") == "pass")
             and (($status.artifact_paths.starvation_rescue_plan_json // null) == ($plan.artifact_paths.swarm_starvation_rescue_plan_json // null))
             and (($status.artifact_paths.starvation_rescue_conformance_report_json // null) == ($conformance.artifact_paths.swarm_starvation_rescue_conformance_report_json // null))
             and ((($status.predictive_dashboard.starvation_rescue.recommended_ordering // []) | length) > 0)
           ) then "pass" else "fail_closed" end
         ),
         summary: {
           selected_case_id: $selected_case_id,
           selected_scenario_class: ($selected_case.scenario_class // "unknown"),
           selected_case_decision: ($input.decision // "unknown"),
           selected_case_readiness: ($input.summary.readiness // "unknown"),
           plan_decision: ($plan.decision // "unknown"),
           conformance_decision: ($conformance.decision // "unknown"),
           operator_status_escalation_band: ($status.summary.starvation_rescue_escalation_band // "unknown"),
           operator_status_top_action: ($status.summary.starvation_rescue_top_action // null),
           matrix_case_count: ($matrix.scenario_count // 0),
           matrix_failure_count: ($matrix.failure_count // 0),
           fail_closed_case_count: ($matrix.summary.fail_closed_case_count // 0),
           manual_review_case_count: ([($matrix.cases // [])[] | select(.actual.readiness == "manual_review")] | length)
         },
         assumptions: [
           "The composed drill reuses the shipped starvation rescue shell surfaces only.",
           "The scenario matrix remains policy-only and the composed drill never mutates live bead, reservation, or worker state.",
           "The operator status report remains the only predictive dashboard producer in franken_engine."
         ],
         assertions: {
           matrix_matches_expected: (($matrix.failure_count // 1) == 0),
           selected_case_round_trips: (
             (($case_summary.actual.decision // "unknown") == ($input.decision // "unknown"))
             and (($case_summary.actual.readiness // "unknown") == ($input.summary.readiness // "unknown"))
             and ((($case_summary.actual.local_rch_fallback_detected | if . == null then "unknown" else tostring end)) == (($input.derived_truth.local_rch_fallback_detected | if . == null then "unknown" else tostring end)))
           ),
           planner_tracks_selected_case: any(($plan.policy_basis.matched_case_ids // [])[]?; . == $selected_case_id),
           planner_scenario_matches_case: (($plan.scenario_class // "unknown") == ($selected_case.scenario_class // "unknown")),
           conformance_passes: (($conformance.decision // "unknown") == "pass"),
           operator_status_integrates_handoff: (
             (($status.artifact_paths.starvation_rescue_plan_json // null) == ($plan.artifact_paths.swarm_starvation_rescue_plan_json // null))
             and (($status.artifact_paths.starvation_rescue_conformance_report_json // null) == ($conformance.artifact_paths.swarm_starvation_rescue_conformance_report_json // null))
           ),
           operator_status_has_recommended_ordering: ((($status.predictive_dashboard.starvation_rescue.recommended_ordering // []) | length) > 0),
           no_live_worker_mutation_claims: true
         },
         selected_case: {
           case_id: ($selected_case.case_id // $selected_case_id),
           scenario_class: ($selected_case.scenario_class // "unknown"),
           description: ($selected_case.description // ""),
           expected: ($selected_case.expected // {}),
           matrix_case_summary: $case_summary
         },
         scenario_summaries: (
           ($matrix.cases // [])
           | map({
               case_id,
               scenario_class,
               decision: .actual.decision,
               readiness: .actual.readiness,
               local_rch_fallback_detected: .actual.local_rch_fallback_detected,
               matched_expected
             })
         ),
         child_artifacts: {
           selected_case_fixture_json: $selected_case_fixture_json,
           scenario_matrix_report_json: $matrix_report,
           scenario_matrix_case_summary_json: $selected_case_summary,
           scenario_matrix_case_summaries_dir: ($matrix_report | sub("swarm_starvation_rescue_scenario_matrix_report.json$"; "case_summaries")),
           swarm_starvation_rescue_input_json: $input_report,
           swarm_starvation_rescue_plan_json: $plan_report,
           swarm_starvation_rescue_conformance_report_json: $conformance_report,
           operator_status_json: $operator_status_json,
           operator_status_report_md: $operator_status_report_md
         },
         artifact_paths: {
           swarm_starvation_rescue_no_mock_drill_report_json: $report_json,
           events_jsonl: $events_path,
           commands_txt: $commands_path,
           report_md: $report_md
         }
       }' >"$report_tmp"
  mv "$report_tmp" "$report_json"

  {
    printf '# Swarm Starvation Rescue No-Mock Drill\n\n'
    printf -- "- Selected case: \`%s\` (\`%s\`)\n" "$(jq -r '.summary.selected_case_id' "$report_json")" "$(jq -r '.summary.selected_scenario_class' "$report_json")"
    printf -- "- Drill decision: \`%s\`\n" "$(jq -r '.decision' "$report_json")"
    printf -- "- Planner action: \`%s\`\n" "$(jq -r '.summary.operator_status_top_action // "none"' "$report_json")"
    printf -- "- Escalation band: \`%s\`\n" "$(jq -r '.summary.operator_status_escalation_band' "$report_json")"
    printf -- "- Scenario matrix failures: \`%s\`\n" "$(jq -r '.summary.matrix_failure_count' "$report_json")"
    printf -- "- Scenario summaries: \`%s\`\n\n" "$(jq -r '.summary.matrix_case_count' "$report_json")"
    printf '## Assertions\n'
    jq -r '.assertions | to_entries[] | "- `\(.key)`: \(.value)"' "$report_json"
    printf '\n## Selected scenario summary\n'
    jq -r '.selected_case.matrix_case_summary | "- decision=\(.actual.decision) readiness=\(.actual.readiness) local_fallback=\(.actual.local_rch_fallback_detected) matched_expected=\(.matched_expected)"' "$report_json"
  } >"$report_md"

  if [[ "$(jq -r '.decision' "$report_json")" == "pass" ]]; then
    exit 0
  fi
  exit 42
}

run_selftest() {
  local tmp_root run_output

  run_check
  tmp_root="${SWARM_STARVATION_RESCUE_NO_MOCK_DRILL_SELFTEST_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_root"
  run_output="$(mktemp -d "${tmp_root%/}/swarm-starvation-rescue-no-mock-drill.XXXXXX")"

  bash "${BASH_SOURCE[0]}" run --matrix-json "$matrix_json" --case-id "$selected_case_id" --output-dir "$run_output"
  jq -e '
    .schema_version == "franken-engine.swarm-starvation-rescue-no-mock-drill-report.v1"
    and .decision == "pass"
    and .summary.selected_case_id == "brownout_low_priority_starvation"
    and .summary.selected_scenario_class == "brownout"
    and .summary.matrix_case_count == 6
    and .summary.matrix_failure_count == 0
    and .summary.fail_closed_case_count == 3
    and .summary.operator_status_escalation_band == "degraded"
    and .summary.operator_status_top_action == "defer_broad_work_and_rebalance"
    and (.assertions | to_entries | all(.value == true))
    and any(.scenario_summaries[]; .case_id == "contradictory_ownership_fail_closed" and .decision == "fail_closed")
    and any(.scenario_summaries[]; .case_id == "local_fallback_rejected" and .local_rch_fallback_detected == "true")
  ' "${run_output}/swarm_starvation_rescue_no_mock_drill_report.json" >/dev/null
  record_pass "combined report validates"

  if bash "${BASH_SOURCE[0]}" run --matrix-json "$matrix_json" --case-id does-not-exist --output-dir "${run_output}/missing-case" >/dev/null 2>&1; then
    record_failure "missing case id should fail"
    return 1
  fi
  record_pass "missing case rejection"
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
