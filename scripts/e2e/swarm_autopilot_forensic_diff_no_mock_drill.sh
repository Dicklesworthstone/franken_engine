#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_AUTOPILOT_FORENSIC_DIFF_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-forensic-diff-drill}"
run_id="${SWARM_AUTOPILOT_FORENSIC_DIFF_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_FORENSIC_DIFF_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-fixture}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

fixtures_json="${root_dir}/scripts/testdata/swarm_autopilot_forensic_diff_no_mock_drill/cases.json"
operator_status_fixtures_json="${root_dir}/scripts/testdata/swarm_autopilot_operator_status/cases.json"
reference_anomaly_cohorts_json=""
comparison_anomaly_cohorts_json=""
reference_replay_index_json=""
comparison_replay_index_json=""
evidence_warehouse_json=""
replay_run_dir=""
scenario_filter=""
source_revision=""

cohort_diff_script="${root_dir}/scripts/swarm_autopilot_cohort_diff_comparator.sh"
replay_recipe_script="${root_dir}/scripts/swarm_autopilot_replay_recipe_composer.sh"
hypothesis_script="${root_dir}/scripts/swarm_autopilot_forensic_hypothesis_scorer.sh"
operator_status_script="${root_dir}/scripts/swarm_autopilot_operator_status_bundle.sh"
truth_gate_script="${root_dir}/scripts/e2e/swarm_autopilot_forensic_diff_truth_gate.sh"

events_path=""
commands_path=""
case_results_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill.sh [fixture|live|replay|check|selftest] [OPTIONS]

Options:
  --fixtures-json FILE
  --operator-status-fixtures-json FILE
  --reference-anomaly-cohorts-json FILE
  --comparison-anomaly-cohorts-json FILE
  --reference-replay-index-json FILE
  --comparison-replay-index-json FILE
  --evidence-warehouse-json FILE
  --replay-run-dir DIR
  --scenario-id ID
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      shift 2
      ;;
    --operator-status-fixtures-json)
      operator_status_fixtures_json="${2:-}"
      shift 2
      ;;
    --reference-anomaly-cohorts-json)
      reference_anomaly_cohorts_json="${2:-}"
      shift 2
      ;;
    --comparison-anomaly-cohorts-json)
      comparison_anomaly_cohorts_json="${2:-}"
      shift 2
      ;;
    --reference-replay-index-json)
      reference_replay_index_json="${2:-}"
      shift 2
      ;;
    --comparison-replay-index-json)
      comparison_replay_index_json="${2:-}"
      shift 2
      ;;
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      shift 2
      ;;
    --scenario-id)
      scenario_filter="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the forensic diff no-mock drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  case_results_path="${run_dir}/case_results.jsonl"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

log_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s\n' "$rendered" >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-forensic-diff-drill.event.v1" \
    --arg event_name "$1" \
    --arg scenario_id "$2" \
    --arg decision "$3" \
    --arg artifact_path "$4" \
    '{schema_version:$schema_version,event_name:$event_name,scenario_id:$scenario_id,decision:$decision,artifact_path:$artifact_path}' \
    >>"$events_path"
}

run_step() {
  local scenario_id="$1"
  local step_id="$2"
  local expected_codes="$3"
  shift 3
  local step_dir="${run_dir}/${scenario_id}/${step_id}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code expected
  mkdir -p "$step_dir"
  log_command "$@"
  set +e
  "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  IFS=',' read -r -a expected_list <<<"$expected_codes"
  for expected in "${expected_list[@]}"; do
    if [[ "$exit_code" == "$expected" ]]; then
      write_event "step_complete" "$scenario_id" "$step_id" "$step_dir"
      return 0
    fi
  done
  printf 'scenario %s step %s expected exit %s, got %s\n' "$scenario_id" "$step_id" "$expected_codes" "$exit_code" >&2
  return "$exit_code"
}

materialize_case_doc() {
  local scenario_id="$1"
  local source_name="$2"
  local output_path="$3"
  jq --arg scenario_id "$scenario_id" --arg source_name "$source_name" '
    def dm($a; $b):
      if (($a | type) == "object") and (($b | type) == "object") then
        reduce (((($a | keys_unsorted) + ($b | keys_unsorted)) | unique[])) as $k ({}; .[$k] = dm($a[$k]; $b[$k]))
      elif $b == null then $a
      else $b
      end;
    . as $root
    | ("base_" + $source_name) as $base_key
    | ($root.cases[] | select(.scenario_id == $scenario_id)) as $case
    | dm($root[$base_key]; (($case.overrides[$source_name] // {})))
  ' "$fixtures_json" >"$output_path"
}

materialize_operator_support() {
  local support_dir="$1"
  mkdir -p "$support_dir"
  while IFS=: read -r field file_name; do
    jq ".$field" "$operator_status_fixtures_json" >"${support_dir}/${file_name}"
  done <<'MAP'
base_operator_intent_policy_json:operator_intent_policy.json
base_brownout_forecaster_json:brownout_forecaster.json
base_resource_lease_plan_json:resource_lease_plan.json
base_resource_scarcity_receipts_json:resource_scarcity_receipts.json
base_recommendation_bundle_json:recommendation_bundle.json
base_dashboard_projection_json:dashboard_projection.json
base_hindsight_chaos_scenarios_json:hindsight_chaos_scenarios.json
base_hindsight_chaos_replay_index_json:hindsight_chaos_replay_index.json
base_warehouse_retention_plan_json:warehouse_retention_plan.json
base_storage_budget_ledger_json:storage_budget_ledger.json
base_promotion_candidates_json:promotion_candidates.json
base_promotion_candidate_receipts_json:promotion_candidate_receipts.json
MAP
}

record_case_result() {
  local scenario_id="$1"
  local scenario_dir="$2"
  local expected_json="$3"

  jq -n \
    --slurpfile expected "$expected_json" \
    --slurpfile diff "${scenario_dir}/cohort_diff/swarm_autopilot_cohort_diff_receipts.json" \
    --slurpfile replay "${scenario_dir}/replay_recipe/swarm_autopilot_replay_recipe_bundle.json" \
    --slurpfile hypothesis "${scenario_dir}/hypothesis/swarm_autopilot_forensic_hypothesis_summary.json" \
    --slurpfile operator "${scenario_dir}/operator_status/swarm_autopilot_operator_status.json" \
    --arg scenario_id "$scenario_id" '
      def codes($x): [
        $x.fail_closed_reasons[]?.code?,
        $x.failure_reasons[]?.code?,
        $x.error_codes[]?
      ] | map(select(type == "string" and length > 0));
      ($expected[0]) as $expected_doc
      | ($diff[0]) as $diff_doc
      | ($replay[0]) as $replay_doc
      | ($hypothesis[0]) as $hypothesis_doc
      | ($operator[0]) as $operator_doc
      | ([codes($diff_doc)[], codes($replay_doc)[], codes($hypothesis_doc)[], codes($operator_doc)[]] | unique) as $error_codes
      | ([$diff_doc.decision, $replay_doc.decision, $hypothesis_doc.decision, $operator_doc.decision]) as $decisions
      | ($diff_doc.cohort_diff_receipts[0].classification_transition // "unknown") as $transition
      | ($replay_doc.replay_recipes[0].replay_mode // "unknown") as $replay_mode
      | ($hypothesis_doc.hypotheses[0].pivot // $hypothesis_doc.suppressed_hypotheses[0].pivot // "none") as $pivot
      | (if any($decisions[]; . == "fail_closed") then "fail_closed"
         elif any($decisions[]; . == "degraded") then "degraded"
         else "pass"
         end) as $decision
      | (if ($error_codes | any(test("LOCAL-FALLBACK|CONTAMINATED"; "i"))) then "contaminated"
         elif ($error_codes | any(test("STALE"; "i"))) then "stale"
         elif (($hypothesis_doc.truth_state // "") == "low_evidence") then "low_evidence"
         elif $decision == "degraded" then "degraded"
         elif $decision == "fail_closed" then "blocked"
         else "confirmed"
         end) as $truth_state
      | {
          scenario_id: $scenario_id,
          decision: $decision,
          truth_state: $truth_state,
          expected_decision: $expected_doc.decision,
          expected_truth_state: ($expected_doc.required_truth_state // null),
          transition: $transition,
          replay_mode: $replay_mode,
          top_hypothesis_pivot: $pivot,
          error_codes: $error_codes,
          component_decisions: {
            cohort_diff: ($diff_doc.decision // "unknown"),
            replay_recipe: ($replay_doc.decision // "unknown"),
            hypothesis: ($hypothesis_doc.decision // "unknown"),
            operator_status: ($operator_doc.decision // "unknown")
          },
          matches_expected: (
            $decision == $expected_doc.decision
            and (((($expected_doc.required_truth_state // "") | length) == 0) or $truth_state == $expected_doc.required_truth_state)
            and (((($expected_doc.required_transition // "") | length) == 0) or $transition == $expected_doc.required_transition)
            and (((($expected_doc.required_replay_mode // "") | length) == 0) or $replay_mode == $expected_doc.required_replay_mode)
            and (((($expected_doc.required_pivot // "") | length) == 0) or $pivot == $expected_doc.required_pivot)
            and (((($expected_doc.required_error_code // "") | length) == 0) or ($error_codes | index($expected_doc.required_error_code) != null))
          )
        }
    ' >>"$case_results_path"
}

copy_primary_outputs() {
  local scenario_dir="$1"
  cp "${scenario_dir}/inputs/evidence_warehouse.json" "${run_dir}/warehouse.json"
  cp "${scenario_dir}/inputs/reference_anomaly_cohorts.json" "${run_dir}/reference_anomaly_cohorts.json"
  cp "${scenario_dir}/inputs/comparison_anomaly_cohorts.json" "${run_dir}/comparison_anomaly_cohorts.json"
  cp "${scenario_dir}/inputs/reference_replay_index.json" "${run_dir}/reference_replay_index.json"
  cp "${scenario_dir}/inputs/comparison_replay_index.json" "${run_dir}/comparison_replay_index.json"
  cp "${scenario_dir}/cohort_diff/swarm_autopilot_cohort_diff_receipts.json" "${run_dir}/cohort_diff_receipts.json"
  cp "${scenario_dir}/cohort_diff/swarm_autopilot_fingerprint_delta_plan.json" "${run_dir}/fingerprint_delta_plan.json"
  cp "${scenario_dir}/replay_recipe/swarm_autopilot_replay_recipe_bundle.json" "${run_dir}/replay_recipe_bundle.json"
  cp "${scenario_dir}/replay_recipe/swarm_autopilot_replay_recipe_index.json" "${run_dir}/replay_recipe_index.json"
  cp "${scenario_dir}/hypothesis/swarm_autopilot_forensic_hypothesis_summary.json" "${run_dir}/forensic_hypothesis_summary.json"
  cp "${scenario_dir}/hypothesis/swarm_autopilot_forensic_hypothesis_evidence.json" "${run_dir}/forensic_hypothesis_evidence.json"
  cp "${scenario_dir}/operator_status/swarm_autopilot_operator_status.json" "${run_dir}/operator_status_bundle.json"
}

run_forensic_case() {
  local scenario_id="$1"
  local scenario_dir="${run_dir}/${scenario_id}"
  local input_dir="${scenario_dir}/inputs"
  local support_dir="${scenario_dir}/operator_support"
  local expected_json="${scenario_dir}/expected.json"
  mkdir -p "$input_dir"

  if [[ "$mode" == "live" ]]; then
    cp "$reference_anomaly_cohorts_json" "${input_dir}/reference_anomaly_cohorts.json"
    cp "$comparison_anomaly_cohorts_json" "${input_dir}/comparison_anomaly_cohorts.json"
    cp "$reference_replay_index_json" "${input_dir}/reference_replay_index.json"
    cp "$comparison_replay_index_json" "${input_dir}/comparison_replay_index.json"
    cp "$evidence_warehouse_json" "${input_dir}/evidence_warehouse.json"
    jq -n '{decision:"pass"}' >"$expected_json"
  else
    materialize_case_doc "$scenario_id" "reference_anomaly_cohorts_json" "${input_dir}/reference_anomaly_cohorts.json"
    materialize_case_doc "$scenario_id" "comparison_anomaly_cohorts_json" "${input_dir}/comparison_anomaly_cohorts.json"
    materialize_case_doc "$scenario_id" "reference_replay_index_json" "${input_dir}/reference_replay_index.json"
    materialize_case_doc "$scenario_id" "comparison_replay_index_json" "${input_dir}/comparison_replay_index.json"
    materialize_case_doc "$scenario_id" "evidence_warehouse_json" "${input_dir}/evidence_warehouse.json"
    jq --arg scenario_id "$scenario_id" '.cases[] | select(.scenario_id == $scenario_id) | .expected' "$fixtures_json" >"$expected_json"
  fi

  run_step "$scenario_id" "cohort_diff" "0,42" \
    bash "$cohort_diff_script" \
      --reference-anomaly-cohorts-json "${input_dir}/reference_anomaly_cohorts.json" \
      --comparison-anomaly-cohorts-json "${input_dir}/comparison_anomaly_cohorts.json" \
      --reference-replay-index-json "${input_dir}/reference_replay_index.json" \
      --comparison-replay-index-json "${input_dir}/comparison_replay_index.json" \
      --source-revision "$source_revision" \
      --output-dir "${scenario_dir}/cohort_diff"

  run_step "$scenario_id" "replay_recipe" "0,42" \
    bash "$replay_recipe_script" \
      --cohort-diff-receipts-json "${scenario_dir}/cohort_diff/swarm_autopilot_cohort_diff_receipts.json" \
      --anomaly-cohorts-json "${input_dir}/comparison_anomaly_cohorts.json" \
      --replay-index-json "${input_dir}/comparison_replay_index.json" \
      --source-revision "$source_revision" \
      --output-dir "${scenario_dir}/replay_recipe"

  run_step "$scenario_id" "hypothesis" "0,42" \
    bash "$hypothesis_script" \
      --cohort-diff-receipts-json "${scenario_dir}/cohort_diff/swarm_autopilot_cohort_diff_receipts.json" \
      --evidence-warehouse-json "${input_dir}/evidence_warehouse.json" \
      --source-revision "$source_revision" \
      --output-dir "${scenario_dir}/hypothesis"

  materialize_operator_support "$support_dir"
  run_step "$scenario_id" "operator_status" "0,42" \
    bash "$operator_status_script" \
      --operator-intent-policy-json "${support_dir}/operator_intent_policy.json" \
      --brownout-forecaster-json "${support_dir}/brownout_forecaster.json" \
      --resource-lease-plan-json "${support_dir}/resource_lease_plan.json" \
      --resource-scarcity-receipts-json "${support_dir}/resource_scarcity_receipts.json" \
      --recommendation-bundle-json "${support_dir}/recommendation_bundle.json" \
      --dashboard-projection-json "${support_dir}/dashboard_projection.json" \
      --hindsight-chaos-scenarios-json "${support_dir}/hindsight_chaos_scenarios.json" \
      --hindsight-chaos-replay-index-json "${support_dir}/hindsight_chaos_replay_index.json" \
      --warehouse-retention-plan-json "${support_dir}/warehouse_retention_plan.json" \
      --storage-budget-ledger-json "${support_dir}/storage_budget_ledger.json" \
      --promotion-candidates-json "${support_dir}/promotion_candidates.json" \
      --promotion-candidate-receipts-json "${support_dir}/promotion_candidate_receipts.json" \
      --anomaly-cohorts-json "${input_dir}/comparison_anomaly_cohorts.json" \
      --cohort-diff-receipts-json "${scenario_dir}/cohort_diff/swarm_autopilot_cohort_diff_receipts.json" \
      --fingerprint-delta-plan-json "${scenario_dir}/cohort_diff/swarm_autopilot_fingerprint_delta_plan.json" \
      --replay-recipe-bundle-json "${scenario_dir}/replay_recipe/swarm_autopilot_replay_recipe_bundle.json" \
      --replay-recipe-index-json "${scenario_dir}/replay_recipe/swarm_autopilot_replay_recipe_index.json" \
      --forensic-hypothesis-summary-json "${scenario_dir}/hypothesis/swarm_autopilot_forensic_hypothesis_summary.json" \
      --forensic-hypothesis-evidence-json "${scenario_dir}/hypothesis/swarm_autopilot_forensic_hypothesis_evidence.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds 1778124000 \
      --stale-after-seconds 1800 \
      --output-dir "${scenario_dir}/operator_status"

  record_case_result "$scenario_id" "$scenario_dir" "$expected_json"
  write_event "case_complete" "$scenario_id" "$(jq -r '.decision' "${scenario_dir}/operator_status/swarm_autopilot_operator_status.json")" "${scenario_dir}/operator_status/swarm_autopilot_operator_status.json"
}

write_run_manifest() {
  jq -n \
    --arg schema_version "franken-engine.swarm-autopilot-forensic-diff-drill-manifest.v1" \
    --arg run_id "$run_id" \
    --arg source_revision "$source_revision" \
    --arg mode "$mode" \
    '{schema_version:$schema_version,run_id:$run_id,source_revision:$source_revision,mode:$mode}' >"${run_dir}/run_manifest.json"
}

run_fixture_mode() {
  ensure_run_dir
  write_run_manifest
  while IFS= read -r scenario_id; do
    if [[ -n "$scenario_filter" && "$scenario_id" != "$scenario_filter" ]]; then
      continue
    fi
    run_forensic_case "$scenario_id"
  done < <(jq -r '.cases[].scenario_id' "$fixtures_json")

  primary_scenario="$(jq -r '.primary_scenario_id' "$fixtures_json")"
  if [[ -n "$scenario_filter" ]]; then
    primary_scenario="$scenario_filter"
  fi
  copy_primary_outputs "${run_dir}/${primary_scenario}"

  set +e
  "$truth_gate_script" --run-dir "$run_dir" --output "${run_dir}/truth_gate_report.json"
  truth_code=$?
  set -e
  exit "$truth_code"
}

run_live_mode() {
  if [[ -z "$reference_anomaly_cohorts_json" || -z "$comparison_anomaly_cohorts_json" || -z "$reference_replay_index_json" || -z "$comparison_replay_index_json" || -z "$evidence_warehouse_json" ]]; then
    printf 'live mode requires reference/comparison cohorts, replay indexes, and evidence warehouse inputs\n' >&2
    exit 64
  fi
  ensure_run_dir
  write_run_manifest
  run_forensic_case "live_forensic_diff"
  copy_primary_outputs "${run_dir}/live_forensic_diff"
  "$truth_gate_script" --run-dir "$run_dir" --output "${run_dir}/truth_gate_report.json"
}

run_replay_mode() {
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay mode requires --replay-run-dir\n' >&2
    exit 64
  fi
  mkdir -p "$run_dir"
  local required
  for required in run_manifest.json case_results.jsonl truth_gate_report.json warehouse.json reference_anomaly_cohorts.json comparison_anomaly_cohorts.json reference_replay_index.json comparison_replay_index.json cohort_diff_receipts.json fingerprint_delta_plan.json replay_recipe_bundle.json replay_recipe_index.json forensic_hypothesis_summary.json forensic_hypothesis_evidence.json operator_status_bundle.json; do
    if [[ ! -s "${replay_run_dir}/${required}" ]]; then
      printf 'replay source missing %s\n' "$required" >&2
      exit 42
    fi
  done
  jq -n \
    --slurpfile prior "${replay_run_dir}/truth_gate_report.json" \
    --arg schema_version "franken-engine.swarm-autopilot-forensic-diff-truth-gate.v1" \
    --arg replay_run_dir "$replay_run_dir" \
    '{
      schema_version: $schema_version,
      decision: (if $prior[0].decision == "pass" then "pass" else "fail_closed" end),
      replay_verified: ($prior[0].decision == "pass"),
      replay_run_dir: $replay_run_dir,
      required_coverage: $prior[0].required_coverage,
      failure_reasons: (if $prior[0].decision == "pass" then [] else [{code:"FE-SWARM-AUTOPILOT-FORENSIC-REPLAY-SOURCE-FAILED",detail:"source truth gate was not pass"}] end)
    }' >"${run_dir}/truth_gate_report.json"
  if jq -e '.decision == "pass" and .replay_verified == true' "${run_dir}/truth_gate_report.json" >/dev/null; then
    exit 0
  fi
  exit 42
}

case "$mode" in
  fixture|selftest)
    run_fixture_mode
    ;;
  live)
    run_live_mode
    ;;
  replay)
    run_replay_mode
    ;;
  check)
    bash -n "${BASH_SOURCE[0]}" "$truth_gate_script"
    jq empty "$fixtures_json" >/dev/null
    jq empty "$operator_status_fixtures_json" >/dev/null
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 64
    ;;
esac
