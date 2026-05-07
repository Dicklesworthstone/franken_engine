#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_OPERATOR_STATUS_BUNDLE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-operator-status}"
run_id="${SWARM_AUTOPILOT_OPERATOR_STATUS_BUNDLE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_OPERATOR_STATUS_BUNDLE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_OPERATOR_STATUS_BUNDLE_SOURCE_REVISION:-unknown}"
operator_intent_policy_json=""
brownout_forecaster_json=""
resource_lease_plan_json=""
resource_scarcity_receipts_json=""
recommendation_bundle_json=""
dashboard_projection_json=""
hindsight_chaos_scenarios_json=""
hindsight_chaos_replay_index_json=""
warehouse_retention_plan_json=""
storage_budget_ledger_json=""
promotion_candidates_json=""
promotion_candidate_receipts_json=""
anomaly_cohorts_json=""
cohort_diff_receipts_json=""
fingerprint_delta_plan_json=""
replay_recipe_bundle_json=""
replay_recipe_index_json=""
forensic_hypothesis_summary_json=""
forensic_hypothesis_evidence_json=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_operator_status_bundle.sh [OPTIONS]

Publish operator-status style autopilot summaries plus a frankentui-compatible
panel bundle from preserved advisory artifacts only.

Required inputs:
  --operator-intent-policy-json FILE
  --brownout-forecaster-json FILE
  --resource-lease-plan-json FILE
  --resource-scarcity-receipts-json FILE
  --recommendation-bundle-json FILE
  --dashboard-projection-json FILE
  --hindsight-chaos-scenarios-json FILE
  --hindsight-chaos-replay-index-json FILE
  --warehouse-retention-plan-json FILE
  --storage-budget-ledger-json FILE
  --promotion-candidates-json FILE
  --promotion-candidate-receipts-json FILE
  --anomaly-cohorts-json FILE
  --cohort-diff-receipts-json FILE
  --fingerprint-delta-plan-json FILE
  --replay-recipe-bundle-json FILE
  --replay-recipe-index-json FILE
  --forensic-hypothesis-summary-json FILE
  --forensic-hypothesis-evidence-json FILE

Optional inputs:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_autopilot_operator_status.json
  swarm_autopilot_frankentui_panels.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  operator status emitted successfully
  42 contradictory, stale, contaminated, or incomplete evidence forced fail_closed
  64 invalid or missing required inputs
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --operator-intent-policy-json)
      operator_intent_policy_json="${2:-}"
      shift 2
      ;;
    --brownout-forecaster-json)
      brownout_forecaster_json="${2:-}"
      shift 2
      ;;
    --resource-lease-plan-json)
      resource_lease_plan_json="${2:-}"
      shift 2
      ;;
    --resource-scarcity-receipts-json)
      resource_scarcity_receipts_json="${2:-}"
      shift 2
      ;;
    --recommendation-bundle-json)
      recommendation_bundle_json="${2:-}"
      shift 2
      ;;
    --dashboard-projection-json)
      dashboard_projection_json="${2:-}"
      shift 2
      ;;
    --hindsight-chaos-scenarios-json)
      hindsight_chaos_scenarios_json="${2:-}"
      shift 2
      ;;
    --hindsight-chaos-replay-index-json)
      hindsight_chaos_replay_index_json="${2:-}"
      shift 2
      ;;
    --warehouse-retention-plan-json)
      warehouse_retention_plan_json="${2:-}"
      shift 2
      ;;
    --storage-budget-ledger-json)
      storage_budget_ledger_json="${2:-}"
      shift 2
      ;;
    --promotion-candidates-json)
      promotion_candidates_json="${2:-}"
      shift 2
      ;;
    --promotion-candidate-receipts-json)
      promotion_candidate_receipts_json="${2:-}"
      shift 2
      ;;
    --anomaly-cohorts-json)
      anomaly_cohorts_json="${2:-}"
      shift 2
      ;;
    --cohort-diff-receipts-json)
      cohort_diff_receipts_json="${2:-}"
      shift 2
      ;;
    --fingerprint-delta-plan-json)
      fingerprint_delta_plan_json="${2:-}"
      shift 2
      ;;
    --replay-recipe-bundle-json)
      replay_recipe_bundle_json="${2:-}"
      shift 2
      ;;
    --replay-recipe-index-json)
      replay_recipe_index_json="${2:-}"
      shift 2
      ;;
    --forensic-hypothesis-summary-json)
      forensic_hypothesis_summary_json="${2:-}"
      shift 2
      ;;
    --forensic-hypothesis-evidence-json)
      forensic_hypothesis_evidence_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
      shift 2
      ;;
    --stale-after-seconds)
      stale_after_seconds="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

for required_path in \
  "$operator_intent_policy_json" \
  "$brownout_forecaster_json" \
  "$resource_lease_plan_json" \
  "$resource_scarcity_receipts_json" \
  "$recommendation_bundle_json" \
  "$dashboard_projection_json" \
  "$hindsight_chaos_scenarios_json" \
  "$hindsight_chaos_replay_index_json" \
  "$warehouse_retention_plan_json" \
  "$storage_budget_ledger_json" \
  "$promotion_candidates_json" \
  "$promotion_candidate_receipts_json" \
  "$anomaly_cohorts_json" \
  "$cohort_diff_receipts_json" \
  "$fingerprint_delta_plan_json" \
  "$replay_recipe_bundle_json" \
  "$replay_recipe_index_json" \
  "$forensic_hypothesis_summary_json" \
  "$forensic_hypothesis_evidence_json"; do
  if [[ -z "$required_path" ]]; then
    printf 'all required autopilot operator-status inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the swarm autopilot operator status bundle\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the swarm autopilot operator status bundle\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'time arguments must be non-negative integers\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
status_path="${run_dir}/swarm_autopilot_operator_status.json"
status_tmp="${status_path}.tmp"
status_core="${run_dir}/swarm_autopilot_operator_status.core.json"
panels_path="${run_dir}/swarm_autopilot_frankentui_panels.json"
panels_tmp="${panels_path}.tmp"
panels_core="${run_dir}/swarm_autopilot_frankentui_panels.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

policy_normalized="${run_dir}/operator_intent_policy.normalized.json"
forecast_normalized="${run_dir}/brownout_forecaster.normalized.json"
lease_plan_normalized="${run_dir}/resource_lease_plan.normalized.json"
receipts_normalized="${run_dir}/resource_scarcity_receipts.normalized.json"
recommendation_normalized="${run_dir}/recommendation_bundle.normalized.json"
dashboard_normalized="${run_dir}/dashboard_projection.normalized.json"
chaos_scenarios_normalized="${run_dir}/hindsight_chaos_scenarios.normalized.json"
chaos_replay_normalized="${run_dir}/hindsight_chaos_replay_index.normalized.json"
retention_plan_normalized="${run_dir}/warehouse_retention_plan.normalized.json"
storage_ledger_normalized="${run_dir}/storage_budget_ledger.normalized.json"
promotion_candidates_normalized="${run_dir}/promotion_candidates.normalized.json"
promotion_receipts_normalized="${run_dir}/promotion_candidate_receipts.normalized.json"
anomaly_cohorts_normalized="${run_dir}/anomaly_cohorts.normalized.json"
cohort_diff_receipts_normalized="${run_dir}/cohort_diff_receipts.normalized.json"
fingerprint_delta_plan_normalized="${run_dir}/fingerprint_delta_plan.normalized.json"
replay_recipe_bundle_normalized="${run_dir}/replay_recipe_bundle.normalized.json"
replay_recipe_index_normalized="${run_dir}/replay_recipe_index.normalized.json"
forensic_hypothesis_summary_normalized="${run_dir}/forensic_hypothesis_summary.normalized.json"
forensic_hypothesis_evidence_normalized="${run_dir}/forensic_hypothesis_evidence.normalized.json"

printf './scripts/swarm_autopilot_operator_status_bundle.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-operator-status.event.v1" \
    --arg trace_id "trace-swarm-autopilot-operator-status-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    --arg evidence_path "$5" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      component:$component,
      event:$event,
      outcome:$outcome,
      error_code:(if $error_code == "" then null else $error_code end),
      evidence_path:$evidence_path
    }' >>"$events_path"
}

append_failure() {
  local code="$1"
  local source_id="$2"
  local detail="$3"
  local remediation_command="$4"
  jq -nc \
    --arg code "$code" \
    --arg source_id "$source_id" \
    --arg detail "$detail" \
    --arg remediation_command "$remediation_command" \
    '{code:$code,source_id:$source_id,detail:$detail,remediation_command:$remediation_command}' \
    >>"$fail_closed_reasons_jsonl"
  write_event "$source_id" "fail_closed_reason" "captured" "$code" "$source_id"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "$label" "input_loaded" "captured" "" "$output_path"
}

snapshot_epoch_for() {
  local file="$1"
  jq -r '
    if (.generated_epoch_seconds? | type) == "number" then
      .generated_epoch_seconds
    elif (.captured_epoch_seconds? | type) == "number" then
      .captured_epoch_seconds
    else
      0
    end
  ' "$file"
}

check_shape() {
  local path="$1"
  local expr="$2"
  local code="$3"
  local source_id="$4"
  local detail="$5"
  local remediation="$6"
  if ! jq -e "$expr" "$path" >/dev/null 2>&1; then
    append_failure "$code" "$source_id" "$detail" "$remediation"
  fi
}

check_staleness() {
  local file="$1"
  local source_id="$2"
  local label="$3"
  local remediation="$4"
  local epoch age

  epoch="$(snapshot_epoch_for "$file")"
  if is_int "$epoch" && (( epoch > 0 )); then
    age=$((now_epoch_seconds - epoch))
    if (( age > stale_after_seconds )); then
      append_failure "FE-SWARM-AUTOPILOT-STATUS-STALE-EVIDENCE" "$source_id" "${label} age ${age}s exceeds ${stale_after_seconds}s" "$remediation"
    fi
  fi
}

normalize_required_json "$operator_intent_policy_json" "$policy_normalized" "operator_intent_policy"
normalize_required_json "$brownout_forecaster_json" "$forecast_normalized" "brownout_forecaster"
normalize_required_json "$resource_lease_plan_json" "$lease_plan_normalized" "resource_lease_plan"
normalize_required_json "$resource_scarcity_receipts_json" "$receipts_normalized" "resource_scarcity_receipts"
normalize_required_json "$recommendation_bundle_json" "$recommendation_normalized" "recommendation_bundle"
normalize_required_json "$dashboard_projection_json" "$dashboard_normalized" "dashboard_projection"
normalize_required_json "$hindsight_chaos_scenarios_json" "$chaos_scenarios_normalized" "hindsight_chaos_scenarios"
normalize_required_json "$hindsight_chaos_replay_index_json" "$chaos_replay_normalized" "hindsight_chaos_replay_index"
normalize_required_json "$warehouse_retention_plan_json" "$retention_plan_normalized" "warehouse_retention_plan"
normalize_required_json "$storage_budget_ledger_json" "$storage_ledger_normalized" "storage_budget_ledger"
normalize_required_json "$promotion_candidates_json" "$promotion_candidates_normalized" "promotion_candidates"
normalize_required_json "$promotion_candidate_receipts_json" "$promotion_receipts_normalized" "promotion_candidate_receipts"
normalize_required_json "$anomaly_cohorts_json" "$anomaly_cohorts_normalized" "anomaly_cohorts"
normalize_required_json "$cohort_diff_receipts_json" "$cohort_diff_receipts_normalized" "cohort_diff_receipts"
normalize_required_json "$fingerprint_delta_plan_json" "$fingerprint_delta_plan_normalized" "fingerprint_delta_plan"
normalize_required_json "$replay_recipe_bundle_json" "$replay_recipe_bundle_normalized" "replay_recipe_bundle"
normalize_required_json "$replay_recipe_index_json" "$replay_recipe_index_normalized" "replay_recipe_index"
normalize_required_json "$forensic_hypothesis_summary_json" "$forensic_hypothesis_summary_normalized" "forensic_hypothesis_summary"
normalize_required_json "$forensic_hypothesis_evidence_json" "$forensic_hypothesis_evidence_normalized" "forensic_hypothesis_evidence"

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$recommendation_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$dashboard_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="unknown"
fi

check_shape "$policy_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.fallback_behavior.mode // "") | (type == "string" and length > 0))
  and ((.verification_summary.safe_mode_active | type) == "boolean")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "operator_intent_policy_json" \
  "operator intent policy is missing fallback behavior or safety markers" \
  "Regenerate the operator intent policy before building operator status."

check_shape "$forecast_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-brownout-forecaster.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.summary.overall_state // "") | (type == "string" and length > 0))
  and ((.summary.brownout_state // "") | (type == "string" and length > 0))
  and ((.artifact_paths.swarm_autopilot_brownout_forecast_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "brownout_forecaster_json" \
  "brownout forecaster is missing summary fields, evidence links, or safety markers" \
  "Regenerate the brownout forecaster before building operator status."

check_shape "$lease_plan_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-resource-lease-plan.v1"
  and ((.allocation_id // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.lease_allocations // null) | type == "array")
  and ((.artifact_paths.plan_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "resource_lease_plan_json" \
  "resource lease plan is missing allocations, evidence links, or safety markers" \
  "Regenerate the resource lease plan before building operator status."

check_shape "$receipts_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-resource-scarcity-receipts.v1"
  and ((.allocation_id // "") | (type == "string" and length > 0))
  and ((.receipts // null) | type == "array")
  and ((.receipts | length) > 0)
  and all(.receipts[]?;
    ((.evidence_paths // null) | type == "array")
    and ((.evidence_paths | length) > 0)
    and ((.rollback_command // "") | (type == "string" and length > 0))
    and ((.remediation_command // "") | (type == "string" and length > 0))
  )
' "FE-SWARM-AUTOPILOT-STATUS-MISSING-EVIDENCE" "resource_scarcity_receipts_json" \
  "resource scarcity receipts are missing evidence links or remediation commands" \
  "Regenerate the resource scarcity receipts before building operator status."

check_shape "$recommendation_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-recommendation-bundle.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.summary.top_action // "") | (type == "string" and length > 0))
  and ((.recommendations // null) | type == "array")
  and ((.recommendations | length) > 0)
  and all(.recommendations[]?;
    ((.action // "") | (type == "string" and length > 0))
    and ((.summary // "") | (type == "string" and length > 0))
    and ((.evidence_paths // null) | type == "array")
    and ((.evidence_paths | length) > 0)
    and ((.rollback_command // "") | (type == "string" and length > 0))
    and ((.remediation_command // "") | (type == "string" and length > 0))
  )
  and ((.artifact_paths.bundle_json // "") | (type == "string" and length > 0))
  and ((.artifact_paths.dashboard_projection_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-MISSING-EVIDENCE" "recommendation_bundle_json" \
  "recommendation bundle is missing top action, evidence links, or safety markers" \
  "Regenerate the recommendation bundle before building operator status."

check_shape "$dashboard_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-dashboard-projection.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.overall_state // "") | (type == "string" and length > 0))
  and ((.top_action.action // "") | (type == "string" and length > 0))
  and ((.summary_cards // null) | type == "array")
  and ((.summary_cards | length) > 0)
  and ((.top_recommendations // null) | type == "array")
  and ((.top_recommendations | length) > 0)
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "dashboard_projection_json" \
  "dashboard projection is missing cards, top action, or safety markers" \
  "Regenerate the dashboard projection before building operator status."

check_shape "$chaos_scenarios_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-scenarios.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.scenarios // null) | type == "array")
  and ((.scenarios | length) > 0)
  and ((.artifact_paths.scenarios_json // "") | (type == "string" and length > 0))
  and ((.artifact_paths.replay_index_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "hindsight_chaos_scenarios_json" \
  "hindsight chaos scenarios are missing scenario rows, evidence links, or safety markers" \
  "Regenerate hindsight chaos scenarios before building operator status."

check_shape "$chaos_replay_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-replay-index.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.replay_entries // null) | type == "array")
  and ((.replay_entries | length) > 0)
  and ((.artifact_paths.replay_index_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "hindsight_chaos_replay_index_json" \
  "hindsight chaos replay index is missing entries, evidence links, or safety markers" \
  "Regenerate hindsight chaos replay index before building operator status."

check_shape "$retention_plan_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-warehouse-retention-plan.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.storage_pressure_state // "") | (type == "string" and length > 0))
  and ((.replay_preserve_sources // null) | type == "array")
  and ((.compaction_candidates // null) | type == "array")
  and ((.artifact_paths.retention_plan_json // "") | (type == "string" and length > 0))
  and ((.artifact_paths.storage_budget_ledger_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "warehouse_retention_plan_json" \
  "warehouse retention plan is missing pressure, replay-preserve, compaction, evidence links, or safety markers" \
  "Regenerate the warehouse retention plan before building operator status."

check_shape "$storage_ledger_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-storage-budget-ledger.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.storage_pressure_state // "") | (type == "string" and length > 0))
  and ((.summary.total_estimated_bytes // null) | type == "number")
  and ((.summary.replay_preserve_count // null) | type == "number")
  and ((.summary.compaction_candidate_count // null) | type == "number")
  and ((.artifact_paths.storage_budget_ledger_json // "") | (type == "string" and length > 0))
  and ((.artifact_paths.retention_plan_json // "") | (type == "string" and length > 0))
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "storage_budget_ledger_json" \
  "storage budget ledger is missing pressure summary or evidence links" \
  "Regenerate the storage budget ledger from the matching retention planner run."

check_shape "$promotion_candidates_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-promotion-candidates.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.candidate_summary.candidate_count // null) | type == "number")
  and ((.candidates // null) | type == "array")
  and ((.artifact_paths.promotion_candidates_json // "") | (type == "string" and length > 0))
  and ((.artifact_paths.promotion_candidate_receipts_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
  and .mutation_policy.promotes_candidates_automatically == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "promotion_candidates_json" \
  "promotion candidate bundle is missing candidate summary, receipt links, or advisory-only safety markers" \
  "Regenerate promotion candidates before building operator status."

check_shape "$promotion_receipts_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-promotion-candidate-receipts.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.receipts // null) | type == "array")
  and ((.artifact_paths.promotion_candidate_receipts_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-MISSING-EVIDENCE" "promotion_candidate_receipts_json" \
  "promotion candidate receipts are missing receipt rows, artifact links, or safety markers" \
  "Regenerate promotion candidate receipts before building operator status."

check_shape "$anomaly_cohorts_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.cohort_summary.total_cohort_count // null) | type == "number")
  and ((.cohorts // null) | type == "array")
  and ((.artifact_paths.anomaly_cohorts_json // "") | (type == "string" and length > 0))
  and ((.artifact_paths.replay_index_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "anomaly_cohorts_json" \
  "anomaly cohort bundle is missing cohort summary, replay links, or safety markers" \
  "Regenerate anomaly cohorts before building operator status."

check_shape "$cohort_diff_receipts_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipts.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.comparison_summary.diff_receipt_count // null) | type == "number")
  and ((.cohort_diff_receipts // null) | type == "array")
  and ((.artifact_paths.cohort_diff_receipts_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "cohort_diff_receipts_json" \
  "cohort diff receipts are missing comparison summary, receipts, evidence links, or safety markers" \
  "Regenerate cohort diff receipts before building operator status."

check_shape "$fingerprint_delta_plan_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-fingerprint-delta-plan.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.fingerprint_delta_summary.diff_receipt_count // null) | type == "number")
  and ((.fingerprint_deltas // null) | type == "array")
  and ((.artifact_paths.fingerprint_delta_plan_json // "") | (type == "string" and length > 0))
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "fingerprint_delta_plan_json" \
  "fingerprint delta plan is missing summary, deltas, or artifact links" \
  "Regenerate fingerprint delta plan from cohort diff receipts."

check_shape "$replay_recipe_bundle_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-replay-recipe-bundle.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.recipe_summary.recipe_count // null) | type == "number")
  and ((.recipe_summary.replay_ready_count // null) | type == "number")
  and ((.replay_recipes // null) | type == "array")
  and ((.artifact_paths.replay_recipe_bundle_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
  and .mutation_policy.approves_replay_automatically == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "replay_recipe_bundle_json" \
  "replay recipe bundle is missing recipe summary, recipes, evidence links, or safety markers" \
  "Regenerate replay recipes before building operator status."

check_shape "$replay_recipe_index_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-replay-recipe-index.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.entries // null) | type == "array")
  and ((.artifact_paths.replay_recipe_index_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "replay_recipe_index_json" \
  "replay recipe index is missing entries, artifact links, or safety markers" \
  "Regenerate replay recipe index before building operator status."

check_shape "$forensic_hypothesis_summary_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-summary.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.hypothesis_summary.hypothesis_count // null) | type == "number")
  and ((.hypotheses // null) | type == "array")
  and ((.artifact_paths.hypothesis_summary_json // "") | (type == "string" and length > 0))
  and ((.artifact_paths.hypothesis_evidence_json // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
  and .mutation_policy.promotes_hypotheses_automatically == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "forensic_hypothesis_summary_json" \
  "forensic hypothesis summary is missing hypothesis summary, evidence links, or safety markers" \
  "Regenerate forensic hypotheses before building operator status."

check_shape "$forensic_hypothesis_evidence_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-evidence.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.hypotheses // null) | type == "array")
  and ((.source_receipts // null) | type == "array")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-STATUS-SCHEMA-DRIFT" "forensic_hypothesis_evidence_json" \
  "forensic hypothesis evidence is missing source receipts, hypotheses, or safety markers" \
  "Regenerate forensic hypothesis evidence before building operator status."

check_staleness "$policy_normalized" "operator_intent_policy_json" "operator intent policy" \
  "Refresh the operator intent policy before building operator status."
check_staleness "$forecast_normalized" "brownout_forecaster_json" "brownout forecaster" \
  "Refresh the brownout forecaster before building operator status."
check_staleness "$lease_plan_normalized" "resource_lease_plan_json" "resource lease plan" \
  "Refresh the resource lease plan before building operator status."
check_staleness "$receipts_normalized" "resource_scarcity_receipts_json" "resource scarcity receipts" \
  "Refresh the resource scarcity receipts before building operator status."
check_staleness "$recommendation_normalized" "recommendation_bundle_json" "recommendation bundle" \
  "Refresh the recommendation bundle before building operator status."
check_staleness "$dashboard_normalized" "dashboard_projection_json" "dashboard projection" \
  "Refresh the dashboard projection before building operator status."
check_staleness "$chaos_scenarios_normalized" "hindsight_chaos_scenarios_json" "hindsight chaos scenarios" \
  "Refresh hindsight chaos scenarios before building operator status."
check_staleness "$chaos_replay_normalized" "hindsight_chaos_replay_index_json" "hindsight chaos replay index" \
  "Refresh hindsight chaos replay index before building operator status."
check_staleness "$retention_plan_normalized" "warehouse_retention_plan_json" "warehouse retention plan" \
  "Refresh the warehouse retention plan before building operator status."
check_staleness "$storage_ledger_normalized" "storage_budget_ledger_json" "storage budget ledger" \
  "Refresh the storage budget ledger before building operator status."
check_staleness "$promotion_candidates_normalized" "promotion_candidates_json" "promotion candidates" \
  "Refresh promotion candidates before building operator status."
check_staleness "$promotion_receipts_normalized" "promotion_candidate_receipts_json" "promotion candidate receipts" \
  "Refresh promotion candidate receipts before building operator status."
check_staleness "$anomaly_cohorts_normalized" "anomaly_cohorts_json" "anomaly cohorts" \
  "Refresh anomaly cohorts before building operator status."
check_staleness "$cohort_diff_receipts_normalized" "cohort_diff_receipts_json" "cohort diff receipts" \
  "Refresh cohort diff receipts before building operator status."
check_staleness "$fingerprint_delta_plan_normalized" "fingerprint_delta_plan_json" "fingerprint delta plan" \
  "Refresh fingerprint delta plan before building operator status."
check_staleness "$replay_recipe_bundle_normalized" "replay_recipe_bundle_json" "replay recipe bundle" \
  "Refresh replay recipe bundle before building operator status."
check_staleness "$replay_recipe_index_normalized" "replay_recipe_index_json" "replay recipe index" \
  "Refresh replay recipe index before building operator status."
check_staleness "$forensic_hypothesis_summary_normalized" "forensic_hypothesis_summary_json" "forensic hypothesis summary" \
  "Refresh forensic hypothesis summary before building operator status."
check_staleness "$forensic_hypothesis_evidence_normalized" "forensic_hypothesis_evidence_json" "forensic hypothesis evidence" \
  "Refresh forensic hypothesis evidence before building operator status."

if ! jq -e --slurpfile receipts "$receipts_normalized" '.allocation_id == $receipts[0].allocation_id' "$lease_plan_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-STATUS-MISSING-EVIDENCE" "resource_scarcity_receipts_json" \
    "resource scarcity receipts do not match the lease plan allocation id" \
    "Regenerate the lease plan and receipts from the same allocator run before building operator status."
fi

for doc in \
  "$policy_normalized" \
  "$forecast_normalized" \
  "$lease_plan_normalized" \
  "$recommendation_normalized" \
  "$retention_plan_normalized" \
  "$promotion_candidates_normalized" \
  "$promotion_receipts_normalized" \
  "$anomaly_cohorts_normalized" \
  "$cohort_diff_receipts_normalized" \
  "$replay_recipe_bundle_normalized" \
  "$replay_recipe_index_normalized" \
  "$forensic_hypothesis_summary_normalized" \
  "$forensic_hypothesis_evidence_normalized"; do
  if jq -e '.decision == "fail_closed"' "$doc" >/dev/null 2>&1; then
    source_id="$(basename "$doc" .normalized.json)_json"
    append_failure "FE-SWARM-AUTOPILOT-STATUS-UPSTREAM-UNTRUSTED" "$source_id" \
      "fail_closed upstream evidence must remain fail_closed in operator status" \
      "Repair the upstream advisory artifact before building operator status."
  fi
done

policy_sha="$(sha256sum "$policy_normalized" | awk '{print $1}')"
forecast_sha="$(sha256sum "$forecast_normalized" | awk '{print $1}')"
lease_plan_sha="$(sha256sum "$lease_plan_normalized" | awk '{print $1}')"
receipts_sha="$(sha256sum "$receipts_normalized" | awk '{print $1}')"
recommendation_sha="$(sha256sum "$recommendation_normalized" | awk '{print $1}')"
dashboard_sha="$(sha256sum "$dashboard_normalized" | awk '{print $1}')"
chaos_scenarios_sha="$(sha256sum "$chaos_scenarios_normalized" | awk '{print $1}')"
chaos_replay_sha="$(sha256sum "$chaos_replay_normalized" | awk '{print $1}')"
retention_plan_sha="$(sha256sum "$retention_plan_normalized" | awk '{print $1}')"
storage_ledger_sha="$(sha256sum "$storage_ledger_normalized" | awk '{print $1}')"
promotion_candidates_sha="$(sha256sum "$promotion_candidates_normalized" | awk '{print $1}')"
promotion_receipts_sha="$(sha256sum "$promotion_receipts_normalized" | awk '{print $1}')"
anomaly_cohorts_sha="$(sha256sum "$anomaly_cohorts_normalized" | awk '{print $1}')"
cohort_diff_receipts_sha="$(sha256sum "$cohort_diff_receipts_normalized" | awk '{print $1}')"
fingerprint_delta_plan_sha="$(sha256sum "$fingerprint_delta_plan_normalized" | awk '{print $1}')"
replay_recipe_bundle_sha="$(sha256sum "$replay_recipe_bundle_normalized" | awk '{print $1}')"
replay_recipe_index_sha="$(sha256sum "$replay_recipe_index_normalized" | awk '{print $1}')"
forensic_hypothesis_summary_sha="$(sha256sum "$forensic_hypothesis_summary_normalized" | awk '{print $1}')"
forensic_hypothesis_evidence_sha="$(sha256sum "$forensic_hypothesis_evidence_normalized" | awk '{print $1}')"

decision="pass"
truth_state="confirmed"
exit_code=0

if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
elif jq -e '.decision == "safe_mode"' "$policy_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "safe_mode"' "$recommendation_normalized" >/dev/null 2>&1; then
  decision="safe_mode"
  truth_state="degraded"
elif jq -e '.truth_state != "confirmed"' "$forecast_normalized" >/dev/null 2>&1 \
  || jq -e '.truth_state != "confirmed"' "$recommendation_normalized" >/dev/null 2>&1 >/dev/null 2>&1 \
  || jq -e '.decision == "degraded"' "$dashboard_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "degraded" or .storage_pressure_state != "normal"' "$retention_plan_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "degraded" or .storage_pressure_state != "normal"' "$storage_ledger_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "degraded" or .truth_state == "insufficient_evidence"' "$promotion_candidates_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "degraded"' "$anomaly_cohorts_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "degraded"' "$cohort_diff_receipts_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "degraded" or .truth_state == "degraded"' "$replay_recipe_bundle_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "degraded" or .truth_state == "degraded" or .truth_state == "low_evidence"' "$forensic_hypothesis_summary_normalized" >/dev/null 2>&1; then
  decision="degraded"
  truth_state="degraded"
fi

jq -n \
  --slurpfile policy "$policy_normalized" \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile lease "$lease_plan_normalized" \
  --slurpfile receipts "$receipts_normalized" \
  --slurpfile recommendation "$recommendation_normalized" \
  --slurpfile dashboard "$dashboard_normalized" \
  --slurpfile chaos_scenarios "$chaos_scenarios_normalized" \
  --slurpfile chaos_replay "$chaos_replay_normalized" \
  --slurpfile retention_plan "$retention_plan_normalized" \
  --slurpfile storage_ledger "$storage_ledger_normalized" \
  --slurpfile promotion_candidates "$promotion_candidates_normalized" \
  --slurpfile promotion_receipts "$promotion_receipts_normalized" \
  --slurpfile anomaly_cohorts "$anomaly_cohorts_normalized" \
  --slurpfile cohort_diff_receipts "$cohort_diff_receipts_normalized" \
  --slurpfile fingerprint_delta_plan "$fingerprint_delta_plan_normalized" \
  --slurpfile replay_recipe_bundle "$replay_recipe_bundle_normalized" \
  --slurpfile replay_recipe_index "$replay_recipe_index_normalized" \
  --slurpfile forensic_hypothesis_summary "$forensic_hypothesis_summary_normalized" \
  --slurpfile forensic_hypothesis_evidence "$forensic_hypothesis_evidence_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg status_path "$status_path" \
  --arg panels_path "$panels_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg policy_sha "$policy_sha" \
  --arg forecast_sha "$forecast_sha" \
  --arg lease_plan_sha "$lease_plan_sha" \
  --arg receipts_sha "$receipts_sha" \
  --arg recommendation_sha "$recommendation_sha" \
  --arg dashboard_sha "$dashboard_sha" \
  --arg chaos_scenarios_sha "$chaos_scenarios_sha" \
  --arg chaos_replay_sha "$chaos_replay_sha" \
  --arg retention_plan_sha "$retention_plan_sha" \
  --arg storage_ledger_sha "$storage_ledger_sha" \
  --arg promotion_candidates_sha "$promotion_candidates_sha" \
  --arg promotion_receipts_sha "$promotion_receipts_sha" \
  --arg anomaly_cohorts_sha "$anomaly_cohorts_sha" \
  --arg cohort_diff_receipts_sha "$cohort_diff_receipts_sha" \
  --arg fingerprint_delta_plan_sha "$fingerprint_delta_plan_sha" \
  --arg replay_recipe_bundle_sha "$replay_recipe_bundle_sha" \
  --arg replay_recipe_index_sha "$replay_recipe_index_sha" \
  --arg forensic_hypothesis_summary_sha "$forensic_hypothesis_summary_sha" \
  --arg forensic_hypothesis_evidence_sha "$forensic_hypothesis_evidence_sha" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  '
  def theme_for($state):
    if $state == "healthy" then "success"
    elif $state == "degraded" or $state == "missing" or $state == "stale" then "warning"
    else "danger"
    end;
  def panel($id; $title; $state; $summary; $rows; $reasons):
    {
      panel_id:$id,
      title:$title,
      display_state:$state,
      semantic_theme_token: theme_for($state),
      focus_order: 0,
      aria_label: ($title + " panel, state " + $state),
      supports_tiny_layout: true,
      summary:$summary,
      rows:$rows,
      visible_reasons:$reasons
    };
  ($policy[0]) as $p |
  ($forecast[0]) as $f |
  ($lease[0]) as $l |
  ($receipts[0]) as $r |
  ($recommendation[0]) as $rb |
  ($dashboard[0]) as $d |
  ($chaos_scenarios[0]) as $cs |
  ($chaos_replay[0]) as $cr |
  ($retention_plan[0]) as $ret |
  ($storage_ledger[0]) as $sl |
  ($promotion_candidates[0]) as $pc |
  ($promotion_receipts[0]) as $pr |
  ($anomaly_cohorts[0]) as $ac |
  ($cohort_diff_receipts[0]) as $cdr |
  ($fingerprint_delta_plan[0]) as $fdp |
  ($replay_recipe_bundle[0]) as $rrb |
  ($replay_recipe_index[0]) as $rri |
  ($forensic_hypothesis_summary[0]) as $fhs |
  ($forensic_hypothesis_evidence[0]) as $fhe |
  ($fail_closed_reasons) as $reasons |
  (
    [
      ($p.artifact_paths.policy_json // ""),
      ($f.artifact_paths.swarm_autopilot_brownout_forecast_json // ""),
      ($l.artifact_paths.plan_json // ""),
      ($l.artifact_paths.receipts_json // ""),
      ($rb.artifact_paths.bundle_json // ""),
      ($rb.artifact_paths.dashboard_projection_json // ""),
      ($cs.artifact_paths.scenarios_json // ""),
      ($cr.artifact_paths.replay_index_json // ""),
      ($ret.artifact_paths.retention_plan_json // ""),
      ($sl.artifact_paths.storage_budget_ledger_json // ""),
      ($pc.artifact_paths.promotion_candidates_json // ""),
      ($pr.artifact_paths.promotion_candidate_receipts_json // ""),
      ($ac.artifact_paths.anomaly_cohorts_json // ""),
      ($cdr.artifact_paths.cohort_diff_receipts_json // ""),
      ($fdp.artifact_paths.fingerprint_delta_plan_json // ""),
      ($rrb.artifact_paths.replay_recipe_bundle_json // ""),
      ($rri.artifact_paths.replay_recipe_index_json // ""),
      ($fhs.artifact_paths.hypothesis_summary_json // ""),
      ($fhs.artifact_paths.hypothesis_evidence_json // "")
    ] | map(select(length > 0)) | unique
  ) as $base_evidence_paths |
  ($rb.summary.top_action // $d.top_action.action // "none") as $top_action |
  ($rb.summary.safe_mode_active // false) as $safe_mode_active |
  (($rb.recommendations | map(select(.action == "preserve_urgent_rch_slack"))) | length) as $preserve_urgent_count |
  (($rb.recommendations | map(select(.action == "defer_lane"))) | length) as $defer_count |
  (($rb.recommendations | map(select(.action == "admit_lane"))) | length) as $admit_count |
  (($rb.recommendations | map(select(.action == "require_human_review"))) | length) as $human_review_count |
  (($cs.scenarios | length) // 0) as $scenario_count |
  (($cr.replay_entries | map(select((.replay_ready // false) == true)) | length) // 0) as $replay_ready_count |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif $truth_state != "confirmed" or ($f.summary.overall_state // "green") != "green" then "degraded"
    else "healthy"
    end
  ) as $forecast_state |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif ($p.decision // "pass") == "safe_mode" then "degraded"
    else "healthy"
    end
  ) as $policy_state |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif ($l.summary.defer_count // 0) > 0 or ($l.summary.cool_count // 0) > 0 then "degraded"
    else "healthy"
    end
  ) as $lease_state |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif $decision == "safe_mode" or ($rb.decision // "pass") == "safe_mode" then "degraded"
    else "healthy"
    end
  ) as $recommendation_state |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif $safe_mode_active then "degraded"
    else "healthy"
    end
  ) as $safe_mode_state |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif $human_review_count > 0 then "degraded"
    else "healthy"
    end
  ) as $operator_action_state |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif (($cs.decision // "pass") != "pass") or (($cr.decision // "pass") != "pass") then "degraded"
    else "healthy"
    end
  ) as $chaos_state |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif (($ret.decision // "pass") != "pass")
      or (($sl.decision // "pass") != "pass")
      or (($pc.decision // "pass") != "pass")
      or (($ac.decision // "pass") != "pass")
      or (($ret.storage_pressure_state // "normal") != "normal")
      or (($sl.storage_pressure_state // "normal") != "normal") then "degraded"
    else "healthy"
    end
  ) as $warehouse_state |
  ($pc.candidates[0].candidate_type // "none") as $top_promotion_candidate_type |
  ($pc.candidates[0].candidate_id // "none") as $top_promotion_candidate_id |
  (
    if $decision == "fail_closed" then "fail_closed"
    elif (($cdr.decision // "pass") != "pass")
      or (($rrb.decision // "pass") != "pass")
      or (($rri.decision // "pass") != "pass")
      or (($fhs.decision // "pass") != "pass")
      or (($fhe.decision // "pass") != "pass")
      or (($rrb.recipe_summary.replay_ready_count // 0) == 0) then "degraded"
    else "healthy"
    end
  ) as $forensic_state |
  ($fhs.hypotheses[0].pivot // "none") as $top_hypothesis_pivot |
  ($fhs.hypotheses[0].confidence_band // "none") as $top_hypothesis_confidence_band |
  [
    panel(
      "forecast_state";
      "Forecast State";
      $forecast_state;
      {
        decision: ($f.decision // "unknown"),
        truth_state: ($f.truth_state // "unknown"),
        overall_state: ($f.summary.overall_state // "unknown"),
        brownout_state: ($f.summary.brownout_state // "unknown")
      };
      [];
      $reasons
    ),
    panel(
      "policy_state";
      "Policy State";
      $policy_state;
      {
        decision: ($p.decision // "unknown"),
        fallback_mode: ($p.fallback_behavior.mode // "unknown"),
        safe_mode_active: ($p.verification_summary.safe_mode_active // false)
      };
      [];
      $reasons
    ),
    panel(
      "lease_scarcity";
      "Lease Scarcity";
      $lease_state;
      {
        overall_state: ($l.summary.overall_state // "unknown"),
        reserve_count: ($l.summary.reserve_count // 0),
        defer_count: ($l.summary.defer_count // 0),
        admit_count: ($l.summary.admit_count // 0)
      };
      ($r.receipts | map({
        lane_id,
        decision,
        reason_codes
      }));
      $reasons
    ),
    panel(
      "recommendation_rank";
      "Recommendation Rank";
      $recommendation_state;
      {
        decision: ($rb.decision // "unknown"),
        overall_state: ($rb.summary.overall_state // "unknown"),
        recommendation_count: ($rb.summary.recommendation_count // 0),
        top_action: $top_action
      };
      ($rb.recommendations | map({
        recommendation_id,
        action,
        lane_id,
        priority
      }));
      $reasons
    ),
    panel(
      "safe_mode_state";
      "Safe Mode";
      $safe_mode_state;
      {
        safe_mode_active: $safe_mode_active,
        bundle_decision: ($rb.decision // "unknown"),
        policy_decision: ($p.decision // "unknown")
      };
      [];
      $reasons
    ),
    panel(
      "required_operator_action";
      "Required Operator Action";
      $operator_action_state;
      {
        top_action: $top_action,
        preserve_urgent_count: $preserve_urgent_count,
        defer_count: $defer_count,
        admit_count: $admit_count,
        human_review_count: $human_review_count
      };
      ($rb.recommendations | .[0:3] | map({
        action,
        lane_id,
        summary
      }));
      $reasons
    ),
    panel(
      "chaos_replay_readiness";
      "Chaos Replay Readiness";
      $chaos_state;
      {
        scenario_count: $scenario_count,
        replay_ready_count: $replay_ready_count,
        chaos_decision: ($cs.decision // "unknown"),
        replay_index_decision: ($cr.decision // "unknown")
      };
      ($cr.replay_entries | map({
        scenario_id,
        replay_ready,
        classification_expectation
      }));
      $reasons
    ),
    panel(
      "warehouse_lifecycle";
      "Warehouse Lifecycle";
      $warehouse_state;
      {
        retention_decision: ($ret.decision // "unknown"),
        storage_pressure_state: ($ret.storage_pressure_state // $sl.storage_pressure_state // "unknown"),
        total_estimated_bytes: ($sl.summary.total_estimated_bytes // $ret.total_estimated_bytes // 0),
        replay_preserve_count: ($sl.summary.replay_preserve_count // (($ret.replay_preserve_sources // []) | length) // 0),
        compaction_candidate_count: ($sl.summary.compaction_candidate_count // (($ret.compaction_candidates // []) | length) // 0),
        promotion_decision: ($pc.decision // "unknown"),
        top_promotion_candidate_type: $top_promotion_candidate_type,
        top_promotion_candidate_id: $top_promotion_candidate_id,
        promotion_candidate_count: ($pc.candidate_summary.candidate_count // 0),
        promotion_receipt_count: (($pr.receipts // []) | length),
        anomaly_decision: ($ac.decision // "unknown"),
        anomaly_total_cohort_count: ($ac.cohort_summary.total_cohort_count // 0),
        anomaly_reference_count: ($ac.cohort_summary.reference_count // 0),
        anomaly_degraded_count: ($ac.cohort_summary.degraded_count // 0),
        anomaly_blocked_count: ($ac.cohort_summary.blocked_count // 0),
        anomaly_contaminated_count: ($ac.cohort_summary.contaminated_count // 0),
        artifact_paths: {
          retention_plan_json: ($ret.artifact_paths.retention_plan_json // ""),
          storage_budget_ledger_json: ($sl.artifact_paths.storage_budget_ledger_json // ""),
          promotion_candidate_receipts_json: ($pr.artifact_paths.promotion_candidate_receipts_json // ""),
          anomaly_cohorts_json: ($ac.artifact_paths.anomaly_cohorts_json // "")
        }
      };
      (
        [
          {kind:"retention_plan", decision:($ret.decision // "unknown"), path:($ret.artifact_paths.retention_plan_json // "")},
          {kind:"storage_budget_ledger", decision:($sl.decision // "unknown"), path:($sl.artifact_paths.storage_budget_ledger_json // "")},
          {kind:"promotion_candidate_receipts", decision:($pr.decision // "unknown"), path:($pr.artifact_paths.promotion_candidate_receipts_json // "")},
          {kind:"anomaly_cohorts", decision:($ac.decision // "unknown"), path:($ac.artifact_paths.anomaly_cohorts_json // "")}
        ]
        + (($pc.candidates // [])[0:3] | map({
            kind:"promotion_candidate",
            candidate_id,
            candidate_type,
            confidence_band,
            recommendation
          }))
        + (($ac.cohorts // [])[0:3] | map({
            kind:"anomaly_cohort",
            cohort_id,
            classification,
            source_count:(.source_ids | length)
          }))
      );
      $reasons
    ),
    panel(
      "forensic_replay";
      "Forensic Replay";
      $forensic_state;
      {
        cohort_diff_decision: ($cdr.decision // "unknown"),
        diff_receipt_count: ($cdr.comparison_summary.diff_receipt_count // 0),
        changed_fingerprint_count: ($cdr.comparison_summary.changed_fingerprint_count // $fdp.fingerprint_delta_summary.changed_fingerprint_count // 0),
        blocked_transition_count: ($cdr.comparison_summary.blocked_transition_count // 0),
        contaminated_transition_count: ($cdr.comparison_summary.contaminated_transition_count // 0),
        replay_recipe_decision: ($rrb.decision // "unknown"),
        replay_recipe_count: ($rrb.recipe_summary.recipe_count // 0),
        replay_ready_count: ($rrb.recipe_summary.replay_ready_count // 0),
        counterexample_count: ($rrb.recipe_summary.counterexample_count // 0),
        quarantine_only_count: ($rrb.recipe_summary.quarantine_only_count // 0),
        hypothesis_decision: ($fhs.decision // "unknown"),
        top_hypothesis_pivot: $top_hypothesis_pivot,
        top_hypothesis_confidence_band: $top_hypothesis_confidence_band,
        hypothesis_count: ($fhs.hypothesis_summary.hypothesis_count // 0),
        artifact_paths: {
          cohort_diff_receipts_json: ($cdr.artifact_paths.cohort_diff_receipts_json // ""),
          replay_recipe_bundle_json: ($rrb.artifact_paths.replay_recipe_bundle_json // ""),
          replay_recipe_index_json: ($rri.artifact_paths.replay_recipe_index_json // ""),
          forensic_hypothesis_summary_json: ($fhs.artifact_paths.hypothesis_summary_json // ""),
          forensic_hypothesis_evidence_json: ($fhs.artifact_paths.hypothesis_evidence_json // "")
        }
      };
      (
        [
          {kind:"cohort_diff_receipts", decision:($cdr.decision // "unknown"), path:($cdr.artifact_paths.cohort_diff_receipts_json // "")},
          {kind:"fingerprint_delta_plan", decision:($fdp.decision // "unknown"), path:($fdp.artifact_paths.fingerprint_delta_plan_json // "")},
          {kind:"replay_recipe_bundle", decision:($rrb.decision // "unknown"), path:($rrb.artifact_paths.replay_recipe_bundle_json // "")},
          {kind:"forensic_hypothesis_summary", decision:($fhs.decision // "unknown"), path:($fhs.artifact_paths.hypothesis_summary_json // "")}
        ]
        + (($cdr.cohort_diff_receipts // [])[0:3] | map({
            kind:"cohort_delta",
            receipt_id,
            classification_transition,
            changed_fingerprint_count:((.changed_fingerprints // []) | length),
            remote_truth_valid
          }))
        + (($rrb.replay_recipes // [])[0:3] | map({
            kind:"replay_recipe",
            recipe_id,
            replay_mode,
            replay_ready,
            expected_classification
          }))
        + (($fhs.hypotheses // [])[0:3] | map({
            kind:"forensic_hypothesis",
            hypothesis_id,
            pivot,
            confidence_band
          }))
      );
      $reasons
    )
  ] as $panels |
  {
    schema_version: "franken-engine.swarm-autopilot-operator-status.v1",
    source_revision: $source_revision,
    generated_epoch_seconds: $now_epoch_seconds,
    decision: $decision,
    truth_state: $truth_state,
    summary: {
      overall_state: (
        if $decision == "fail_closed" then "fail_closed"
        elif $decision == "safe_mode" then "safe_mode"
        elif $decision == "degraded" then "degraded"
        else "healthy"
        end
      ),
      top_action: $top_action,
      safe_mode_active: $safe_mode_active,
      warehouse_lifecycle_state: $warehouse_state,
      storage_pressure_state: ($ret.storage_pressure_state // $sl.storage_pressure_state // "unknown"),
      top_promotion_candidate_type: $top_promotion_candidate_type,
      anomaly_cohort_availability: (
        if (($ac.cohort_summary.total_cohort_count // 0) > 0) then "available" else "missing" end
      ),
      forensic_replay_state: $forensic_state,
      forensic_top_hypothesis_pivot: $top_hypothesis_pivot,
      replay_ready_count: ($rrb.recipe_summary.replay_ready_count // 0),
      degraded_panel_count: ($panels | map(select(.display_state == "degraded" or .display_state == "missing" or .display_state == "stale")) | length),
      fail_closed_panel_count: ($panels | map(select(.display_state == "fail_closed" or .display_state == "blocked")) | length)
    },
    sections: {
      forecast_state: ($panels[] | select(.panel_id == "forecast_state")),
      policy_state: ($panels[] | select(.panel_id == "policy_state")),
      lease_scarcity: ($panels[] | select(.panel_id == "lease_scarcity")),
      recommendation_rank: ($panels[] | select(.panel_id == "recommendation_rank")),
      safe_mode_state: ($panels[] | select(.panel_id == "safe_mode_state")),
      required_operator_action: ($panels[] | select(.panel_id == "required_operator_action")),
      chaos_replay_readiness: ($panels[] | select(.panel_id == "chaos_replay_readiness")),
      warehouse_lifecycle: ($panels[] | select(.panel_id == "warehouse_lifecycle")),
      forensic_replay: ($panels[] | select(.panel_id == "forensic_replay"))
    },
    fail_closed_reasons: $reasons,
    deterministic_replay_hash_basis: {
      operator_intent_policy_sha256: $policy_sha,
      brownout_forecaster_sha256: $forecast_sha,
      resource_lease_plan_sha256: $lease_plan_sha,
      resource_scarcity_receipts_sha256: $receipts_sha,
      recommendation_bundle_sha256: $recommendation_sha,
      dashboard_projection_sha256: $dashboard_sha,
      hindsight_chaos_scenarios_sha256: $chaos_scenarios_sha,
      hindsight_chaos_replay_index_sha256: $chaos_replay_sha,
      warehouse_retention_plan_sha256: $retention_plan_sha,
      storage_budget_ledger_sha256: $storage_ledger_sha,
      promotion_candidates_sha256: $promotion_candidates_sha,
      promotion_candidate_receipts_sha256: $promotion_receipts_sha,
      anomaly_cohorts_sha256: $anomaly_cohorts_sha,
      cohort_diff_receipts_sha256: $cohort_diff_receipts_sha,
      fingerprint_delta_plan_sha256: $fingerprint_delta_plan_sha,
      replay_recipe_bundle_sha256: $replay_recipe_bundle_sha,
      replay_recipe_index_sha256: $replay_recipe_index_sha,
      forensic_hypothesis_summary_sha256: $forensic_hypothesis_summary_sha,
      forensic_hypothesis_evidence_sha256: $forensic_hypothesis_evidence_sha
    },
    renderer_contract: {
      provider: "/dp/frankentui",
      shipped_in_franken_engine: false,
      local_renderer: false,
      no_local_tui_runtime: true,
      handoff_note: "franken_engine emits operator-status JSON and panel data only; any rich interactive renderer belongs in /dp/frankentui."
    },
    artifact_paths: {
      operator_status_json: $status_path,
      panel_bundle_json: $panels_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path,
      warehouse_retention_plan_json: ($ret.artifact_paths.retention_plan_json // ""),
      storage_budget_ledger_json: ($sl.artifact_paths.storage_budget_ledger_json // ""),
      promotion_candidates_json: ($pc.artifact_paths.promotion_candidates_json // ""),
      promotion_candidate_receipts_json: ($pr.artifact_paths.promotion_candidate_receipts_json // ""),
      anomaly_cohorts_json: ($ac.artifact_paths.anomaly_cohorts_json // ""),
      cohort_diff_receipts_json: ($cdr.artifact_paths.cohort_diff_receipts_json // ""),
      fingerprint_delta_plan_json: ($fdp.artifact_paths.fingerprint_delta_plan_json // ""),
      replay_recipe_bundle_json: ($rrb.artifact_paths.replay_recipe_bundle_json // ""),
      replay_recipe_index_json: ($rri.artifact_paths.replay_recipe_index_json // ""),
      forensic_hypothesis_summary_json: ($fhs.artifact_paths.hypothesis_summary_json // ""),
      forensic_hypothesis_evidence_json: ($fhs.artifact_paths.hypothesis_evidence_json // "")
    },
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      reassigns_beads: false,
      releases_reservations: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false,
      mutates_remote_workers: false,
      changes_live_queue_policy: false,
      local_renderer: false
    }
  }
' >"$status_core"

status_hash="$(jq -cS . "$status_core" | sha256sum | awk '{print $1}')"
operator_status_id="autopilot-operator-status-${status_hash:0:16}"

jq \
  --arg operator_status_id "$operator_status_id" \
  '. + {operator_status_id: $operator_status_id}' \
  "$status_core" >"$status_tmp"
mv "$status_tmp" "$status_path"

jq -n \
  --slurpfile status "$status_path" \
  '
  ($status[0]) as $status |
  ([
    $status.sections.forecast_state,
    $status.sections.policy_state,
    $status.sections.lease_scarcity,
    $status.sections.recommendation_rank,
    $status.sections.safe_mode_state,
    $status.sections.required_operator_action,
    $status.sections.chaos_replay_readiness,
    $status.sections.warehouse_lifecycle,
    $status.sections.forensic_replay
  ] | to_entries | map(.value + {focus_order:(.key + 1)})) as $panels |
  {
    schema_version: "franken-engine.swarm-autopilot-frankentui-panels.v1",
    source_revision: $status.source_revision,
    generated_epoch_seconds: $status.generated_epoch_seconds,
    decision: $status.decision,
    truth_state: $status.truth_state,
    renderer_contract: $status.renderer_contract,
    status_bar: {
      title: "SWARM-AUTOPILOT",
      state: $status.summary.overall_state,
      summary: {
        panel_count: ($panels | length),
        degraded_panel_count: $status.summary.degraded_panel_count,
        fail_closed_panel_count: $status.summary.fail_closed_panel_count,
        top_action: $status.summary.top_action
      }
    },
    display_state_policy: {
      allowed: ["healthy","degraded","missing","stale","blocked","fail_closed"],
      missing_telemetry_visible: true,
      hidden_panel_policy: "reject_bundle"
    },
    panels: $panels,
    mutation_policy: $status.mutation_policy
  }
' >"$panels_core"

panels_hash="$(jq -cS . "$panels_core" | sha256sum | awk '{print $1}')"
panel_bundle_id="autopilot-panels-${panels_hash:0:16}"

jq \
  --arg panel_bundle_id "$panel_bundle_id" \
  '. + {panel_bundle_id: $panel_bundle_id}' \
  "$panels_core" >"$panels_tmp"
mv "$panels_tmp" "$panels_path"

jq -r '
  [
    "# Swarm Autopilot Operator Status",
    "",
    "- Decision: " + .decision,
    "- Truth state: " + .truth_state,
    "- Overall state: " + .summary.overall_state,
    "- Top action: " + .summary.top_action,
    ""
  ]
  + (if (.fail_closed_reasons | length) > 0 then
      ["## Fail-Closed Reasons", ""] +
      (.fail_closed_reasons | map("- `" + .code + "` " + .detail))
    else
      ["## Panel States", ""] +
      (.sections | to_entries | map("- `" + .key + "` `" + .value.display_state + "`"))
    end)
  | join("\n")
' "$status_path" >"$report_path"

write_event "swarm_autopilot_operator_status_bundle" "status_emitted" "$decision" "" "$status_path"
write_event "swarm_autopilot_operator_status_bundle" "panels_emitted" "captured" "" "$panels_path"

exit "$exit_code"
