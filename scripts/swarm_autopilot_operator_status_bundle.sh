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
  "$hindsight_chaos_replay_index_json"; do
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

if ! jq -e --slurpfile receipts "$receipts_normalized" '.allocation_id == $receipts[0].allocation_id' "$lease_plan_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-STATUS-MISSING-EVIDENCE" "resource_scarcity_receipts_json" \
    "resource scarcity receipts do not match the lease plan allocation id" \
    "Regenerate the lease plan and receipts from the same allocator run before building operator status."
fi

for doc in "$policy_normalized" "$forecast_normalized" "$lease_plan_normalized" "$recommendation_normalized"; do
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
  || jq -e '.decision == "degraded"' "$dashboard_normalized" >/dev/null 2>&1; then
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
      ($cr.artifact_paths.replay_index_json // "")
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
      chaos_replay_readiness: ($panels[] | select(.panel_id == "chaos_replay_readiness"))
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
      hindsight_chaos_replay_index_sha256: $chaos_replay_sha
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
      report_md: $report_path
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
    $status.sections.chaos_replay_readiness
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
