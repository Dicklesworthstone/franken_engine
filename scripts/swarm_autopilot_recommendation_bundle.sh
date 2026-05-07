#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-recommendation-bundle}"
run_id="${SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE_SOURCE_REVISION:-unknown}"
operator_intent_policy_json=""
brownout_forecaster_json=""
resource_lease_plan_json=""
resource_scarcity_receipts_json=""
control_plane_context_json=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_recommendation_bundle.sh [OPTIONS]

Compose advisory-only recommendation bundles from operator intent policy,
brownout forecasts, resource lease allocations, scarcity receipts, and
control-plane context.

Required inputs:
  --operator-intent-policy-json FILE
  --brownout-forecaster-json FILE
  --resource-lease-plan-json FILE
  --resource-scarcity-receipts-json FILE
  --control-plane-context-json FILE

Optional inputs:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_autopilot_recommendation_bundle.json
  swarm_autopilot_dashboard_projection.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  recommendation bundle emitted successfully
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
    --control-plane-context-json)
      control_plane_context_json="${2:-}"
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
  "$control_plane_context_json"; do
  if [[ -z "$required_path" ]]; then
    printf 'all required recommendation bundle inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the swarm autopilot recommendation bundle\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the swarm autopilot recommendation bundle\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'time arguments must be non-negative integers\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
bundle_path="${run_dir}/swarm_autopilot_recommendation_bundle.json"
bundle_tmp="${bundle_path}.tmp"
bundle_core="${run_dir}/swarm_autopilot_recommendation_bundle.core.json"
dashboard_path="${run_dir}/swarm_autopilot_dashboard_projection.json"
dashboard_tmp="${dashboard_path}.tmp"
dashboard_core="${run_dir}/swarm_autopilot_dashboard_projection.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

policy_normalized="${run_dir}/operator_intent_policy.normalized.json"
forecast_normalized="${run_dir}/brownout_forecaster.normalized.json"
lease_plan_normalized="${run_dir}/resource_lease_plan.normalized.json"
receipts_normalized="${run_dir}/resource_scarcity_receipts.normalized.json"
context_normalized="${run_dir}/control_plane_context.normalized.json"

printf './scripts/swarm_autopilot_recommendation_bundle.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-recommendation-bundle.event.v1" \
    --arg trace_id "trace-swarm-autopilot-recommendation-bundle-${run_id}" \
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
      append_failure "FE-SWARM-AUTOPILOT-RECOMMEND-STALE-EVIDENCE" "$source_id" "${label} age ${age}s exceeds ${stale_after_seconds}s" "$remediation"
    fi
  fi
}

normalize_required_json "$operator_intent_policy_json" "$policy_normalized" "operator_intent_policy"
normalize_required_json "$brownout_forecaster_json" "$forecast_normalized" "brownout_forecaster"
normalize_required_json "$resource_lease_plan_json" "$lease_plan_normalized" "resource_lease_plan"
normalize_required_json "$resource_scarcity_receipts_json" "$receipts_normalized" "resource_scarcity_receipts"
normalize_required_json "$control_plane_context_json" "$context_normalized" "control_plane_context"

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$lease_plan_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$forecast_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="unknown"
fi

check_shape "$policy_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.precedence_order // null) | type == "array")
  and ((.fallback_behavior.mode // "") | (type == "string" and length > 0))
  and ((.fallback_behavior.actions // null) | type == "array")
  and ((.verification_summary.safe_mode_active | type) == "boolean")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-RECOMMEND-SCHEMA-DRIFT" "operator_intent_policy_json" \
  "operator intent policy is missing precedence, fallback behavior, or safety markers" \
  "Regenerate the operator intent policy before building recommendations."

check_shape "$forecast_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-brownout-forecaster.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.summary.overall_state // "") | (type == "string" and length > 0))
  and ((.summary.brownout_state // "") | (type == "string" and length > 0))
  and ((.fail_closed_reasons // null) | type == "array")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-RECOMMEND-SCHEMA-DRIFT" "brownout_forecaster_json" \
  "brownout forecaster is missing state summaries or safety markers" \
  "Regenerate the brownout forecaster before building recommendations."

check_shape "$lease_plan_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-resource-lease-plan.v1"
  and ((.allocation_id // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.lease_allocations // null) | type == "array")
  and ((.lease_allocations | length) > 0)
  and all(.lease_allocations[]?;
    ((.lane_id // "") | (type == "string" and length > 0))
    and ((.decision // "") | (type == "string" and length > 0))
    and ((.resource_class // "") | (type == "string" and length > 0))
    and ((.reason_codes // null) | type == "array")
    and ((.evidence_paths // null) | type == "array")
    and ((.rollback_command // "") | (type == "string" and length > 0))
    and ((.remediation_command // "") | (type == "string" and length > 0))
  )
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-RECOMMEND-SCHEMA-DRIFT" "resource_lease_plan_json" \
  "resource lease plan is missing allocations or safety markers" \
  "Regenerate the resource lease allocator plan before building recommendations."

check_shape "$receipts_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-resource-scarcity-receipts.v1"
  and ((.allocation_id // "") | (type == "string" and length > 0))
  and ((.receipts // null) | type == "array")
  and ((.receipts | length) > 0)
  and all(.receipts[]?;
    ((.receipt_id // "") | (type == "string" and length > 0))
    and ((.lane_id // "") | (type == "string" and length > 0))
    and ((.decision // "") | (type == "string" and length > 0))
    and ((.reason_codes // null) | type == "array")
    and ((.evidence_paths // null) | type == "array")
    and ((.rollback_command // "") | (type == "string" and length > 0))
    and ((.remediation_command // "") | (type == "string" and length > 0))
  )
' "FE-SWARM-AUTOPILOT-RECOMMEND-SCHEMA-DRIFT" "resource_scarcity_receipts_json" \
  "resource scarcity receipts are missing required fields" \
  "Regenerate the scarcity receipts before building recommendations."

check_shape "$context_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-control-plane-context.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.telemetry_freshness_state // "") | (type == "string" and length > 0))
  and ((.agent_mail_state // "") | (type == "string" and length > 0))
  and ((.dirty_tree_state // "") | (type == "string" and length > 0))
  and ((.reservation_state // "") | (type == "string" and length > 0))
  and ((.local_fallback_state // "") | (type == "string" and length > 0))
  and ((.human_review_reasons // null) | type == "array")
  and ((.dashboard_preferences.include_summary_cards | type) == "boolean")
  and ((.dashboard_preferences.include_top_recommendations | type) == "boolean")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-RECOMMEND-SCHEMA-DRIFT" "control_plane_context_json" \
  "control-plane context is missing telemetry, reservation, dirty-tree, or safety markers" \
  "Refresh the control-plane context before building recommendations."

check_staleness "$policy_normalized" "operator_intent_policy_json" "operator intent policy" \
  "Refresh the operator intent policy before building recommendations."
check_staleness "$forecast_normalized" "brownout_forecaster_json" "brownout forecaster" \
  "Refresh the brownout forecaster before building recommendations."
check_staleness "$lease_plan_normalized" "resource_lease_plan_json" "resource lease plan" \
  "Refresh the resource lease plan before building recommendations."
check_staleness "$receipts_normalized" "resource_scarcity_receipts_json" "resource scarcity receipts" \
  "Refresh the resource scarcity receipts before building recommendations."
check_staleness "$context_normalized" "control_plane_context_json" "control-plane context" \
  "Refresh the control-plane context before building recommendations."

if ! jq -e '.allocation_id == input_filename' /dev/null >/dev/null 2>&1; then
  :
fi

if ! jq -e --slurpfile receipts "$receipts_normalized" '.allocation_id == $receipts[0].allocation_id' "$lease_plan_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-RECOMMEND-LEASE-MISMATCH" "resource_scarcity_receipts_json" \
    "resource scarcity receipts do not match the lease allocation id" \
    "Regenerate plan and receipts from the same allocator run before building recommendations."
fi

if jq -e '.decision == "fail_closed"' "$policy_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-RECOMMEND-UPSTREAM-UNTRUSTED" "operator_intent_policy_json" \
    "fail_closed policy inputs are not promotable into recommendation bundles" \
    "Repair policy conflicts before building recommendations."
fi
if jq -e '.decision == "fail_closed"' "$forecast_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-RECOMMEND-UPSTREAM-UNTRUSTED" "brownout_forecaster_json" \
    "fail_closed forecast inputs are not promotable into recommendation bundles" \
    "Repair forecast evidence before building recommendations."
fi
if jq -e '.decision == "fail_closed"' "$lease_plan_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-RECOMMEND-UPSTREAM-UNTRUSTED" "resource_lease_plan_json" \
    "fail_closed lease plans are not promotable into recommendation bundles" \
    "Repair allocator inputs before building recommendations."
fi
if jq -e '
  (.local_fallback_state // "") == "contaminated"
' "$context_normalized" >/dev/null 2>&1 \
  || jq -e '
    (.fail_closed_reasons // []) | any(
      ((.code // "") | test("LOCAL-FALLBACK|local fallback"; "i"))
      or ((.detail // "") | test("LOCAL-FALLBACK|local fallback|contaminated"; "i"))
    )
  ' "$forecast_normalized" >/dev/null 2>&1 \
  || jq -e '
    (.fail_closed_reasons // []) | any(
      ((.code // "") | test("LOCAL-FALLBACK|local fallback"; "i"))
      or ((.detail // "") | test("LOCAL-FALLBACK|local fallback|contaminated"; "i"))
    )
  ' "$lease_plan_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-RECOMMEND-LOCAL-FALLBACK" "local_fallback_state" \
    "local fallback contamination is present in required recommendation evidence" \
    "Discard contaminated local-fallback captures before building recommendations."
fi

policy_sha="$(sha256sum "$policy_normalized" | awk '{print $1}')"
forecast_sha="$(sha256sum "$forecast_normalized" | awk '{print $1}')"
lease_plan_sha="$(sha256sum "$lease_plan_normalized" | awk '{print $1}')"
receipts_sha="$(sha256sum "$receipts_normalized" | awk '{print $1}')"
context_sha="$(sha256sum "$context_normalized" | awk '{print $1}')"

decision="pass"
truth_state="confirmed"
exit_code=0

if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
elif jq -e '
  (.decision == "safe_mode")
  or (.truth_state != "confirmed")
  or (.telemetry_freshness_state == "stale")
  or (.agent_mail_state == "missing")
  or (.dirty_tree_state == "unknown_dirty")
  or (.reservation_state == "active_reservations")
' "$context_normalized" >/dev/null 2>&1 \
  || jq -e '.decision == "safe_mode"' "$policy_normalized" >/dev/null 2>&1; then
  decision="safe_mode"
  truth_state="degraded"
elif jq -e '
  (.truth_state != "confirmed")
' "$forecast_normalized" >/dev/null 2>&1 \
  || jq -e '.truth_state != "confirmed"' "$lease_plan_normalized" >/dev/null 2>&1; then
  truth_state="degraded"
fi

jq -n \
  --slurpfile policy "$policy_normalized" \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile lease "$lease_plan_normalized" \
  --slurpfile receipts "$receipts_normalized" \
  --slurpfile context "$context_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg bundle_path "$bundle_path" \
  --arg dashboard_path "$dashboard_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg policy_sha "$policy_sha" \
  --arg forecast_sha "$forecast_sha" \
  --arg lease_plan_sha "$lease_plan_sha" \
  --arg receipts_sha "$receipts_sha" \
  --arg context_sha "$context_sha" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  '
  ($policy[0]) as $p |
  ($forecast[0]) as $f |
  ($lease[0]) as $l |
  ($receipts[0]) as $r |
  ($context[0]) as $c |
  ($c.human_review_reasons // []) as $human_review_reasons |
  (($human_review_reasons | length) > 0 or ($c.reservation_state == "conflicted")) as $human_review_required |
  (
    [
      ($p.artifact_paths.policy_json // ""),
      ($f.artifact_paths.swarm_autopilot_brownout_forecast_json // ""),
      ($l.artifact_paths.plan_json // ""),
      ($l.artifact_paths.receipts_json // ""),
      ($c.artifact_paths.control_plane_context_json // "")
    ] | map(select(length > 0)) | unique
  ) as $base_evidence_paths |
  (
    if $decision == "fail_closed" then
      [
        {
          priority: 110,
          action: "refresh_evidence",
          lane_id: null,
          summary: "Refresh contaminated or contradictory evidence before producing operator guidance.",
          reason_codes: ["fail_closed_evidence"],
          evidence_paths: $base_evidence_paths,
          rollback_command: "# operator: do not apply any autopilot recommendations while evidence is fail_closed",
          remediation_command: "Refresh the contradicted or contaminated evidence bundle before re-running the recommendation generator."
        }
      ]
    else
      (
        ($l.lease_allocations | map(
          . as $alloc |
          {
            priority: (
              if $alloc.decision == "reserve" then 100
              elif $alloc.decision == "defer" then 80
              elif $alloc.decision == "rebalance" then 75
              elif $alloc.decision == "cool" then 70
              else 50
              end
            ),
            action: (
              if $alloc.decision == "reserve" then "preserve_urgent_rch_slack"
              elif $alloc.decision == "defer" then "defer_lane"
              elif $alloc.decision == "rebalance" then "rebalance_fair_share"
              elif $alloc.decision == "cool" then "cool_proof_cache"
              elif $decision == "safe_mode" then "defer_lane"
              else "admit_lane"
              end
            ),
            lane_id: $alloc.lane_id,
            summary: (
              if $alloc.decision == "reserve" then "Preserve urgent RCH slack for " + $alloc.lane_id + "."
              elif $alloc.decision == "defer" then "Defer " + $alloc.lane_id + " until pressure cools."
              elif $alloc.decision == "rebalance" then "Rebalance fair-share access for " + $alloc.lane_id + "."
              elif $alloc.decision == "cool" then "Cool proof-cache activity for " + $alloc.lane_id + "."
              elif $decision == "safe_mode" then "Safe mode defers " + $alloc.lane_id + " until telemetry and coordination evidence recover."
              else "Admit " + $alloc.lane_id + " under current bounded evidence."
              end
            ),
            reason_codes: (
              ($alloc.reason_codes // [])
              + (if $decision == "safe_mode" and $alloc.decision == "admit" then ["safe_mode_active"] else [] end)
            ),
            evidence_paths: ($alloc.evidence_paths // []),
            rollback_command: $alloc.rollback_command,
            remediation_command: $alloc.remediation_command
          }
        ))
        + (if $decision == "safe_mode" then
            [
              {
                priority: 115,
                action: "refresh_evidence",
                lane_id: null,
                summary: "Refresh telemetry and coordination evidence before promoting normal admission advice.",
                reason_codes: ["safe_mode_active", "refresh_control_plane_evidence"],
                evidence_paths: $base_evidence_paths,
                rollback_command: "# operator: clear safe mode after telemetry and coordination recover",
                remediation_command: "Re-run the recommendation bundle after telemetry freshness and coordination evidence return to confirmed."
              }
            ]
          else
            []
          end)
        + (if $human_review_required or ($c.agent_mail_state == "missing") or ($c.dirty_tree_state == "unknown_dirty") or ($c.reservation_state == "active_reservations") then
            [
              {
                priority: 105,
                action: "require_human_review",
                lane_id: null,
                summary: "Require human review because coordination or dirty-tree evidence is incomplete or conflicting.",
                reason_codes: (
                  ["human_review_required"]
                  + (if $c.agent_mail_state == "missing" then ["agent_mail_missing"] else [] end)
                  + (if $c.dirty_tree_state == "unknown_dirty" then ["unknown_dirty_tree"] else [] end)
                  + (if $c.reservation_state == "active_reservations" then ["active_reservations"] else [] end)
                  + (if $c.reservation_state == "conflicted" then ["reservation_conflict"] else [] end)
                ),
                evidence_paths: $base_evidence_paths,
                rollback_command: "# operator: clear the human-review hold after coordination evidence is resolved",
                remediation_command: "Resolve reservation, Agent Mail, or dirty-tree ambiguity before applying normal autopilot guidance."
              }
            ]
          else
            []
          end)
      )
    end
  ) as $recommendation_seed |
  (
    $recommendation_seed
    | sort_by(-.priority, .action, (.lane_id // ""))
    | to_entries
    | map(.value + {
        recommendation_id: ("recommendation-" + ((.key + 1) | tostring)),
        deterministic_decision_id: (
          "decision-"
          + (
              (
                (.value.action // "")
                + "|"
                + (.value.lane_id // "global")
                + "|"
                + ((.value.reason_codes // []) | join(","))
              ) | @base64
            )
        )
      })
  ) as $recommendations |
  ($recommendations[0].action // "none") as $top_action |
  {
    schema_version: "franken-engine.swarm-autopilot-recommendation-bundle.v1",
    source_revision: $source_revision,
    generated_epoch_seconds: $now_epoch_seconds,
    decision: $decision,
    truth_state: $truth_state,
    summary: {
      overall_state: (
        if $decision == "fail_closed" then "fail_closed"
        elif $human_review_required then "human_review_required"
        elif $decision == "safe_mode" then "safe_mode"
        else "normal"
        end
      ),
      top_action: $top_action,
      recommendation_count: ($recommendations | length),
      safe_mode_active: ($decision == "safe_mode"),
      human_review_required: $human_review_required,
      admit_count: ($recommendations | map(select(.action == "admit_lane")) | length),
      defer_count: ($recommendations | map(select(.action == "defer_lane")) | length),
      preserve_urgent_count: ($recommendations | map(select(.action == "preserve_urgent_rch_slack")) | length),
      cool_count: ($recommendations | map(select(.action == "cool_proof_cache")) | length),
      rebalance_count: ($recommendations | map(select(.action == "rebalance_fair_share")) | length),
      refresh_evidence_count: ($recommendations | map(select(.action == "refresh_evidence")) | length),
      human_review_count: ($recommendations | map(select(.action == "require_human_review")) | length)
    },
    resolved_inputs: {
      operator_intent_policy_json: "provided",
      brownout_forecaster_json: "provided",
      resource_lease_plan_json: "provided",
      resource_scarcity_receipts_json: "provided",
      control_plane_context_json: "provided"
    },
    fail_closed_reasons: $fail_closed_reasons,
    deterministic_replay_hash_basis: {
      operator_intent_policy_sha256: $policy_sha,
      brownout_forecaster_sha256: $forecast_sha,
      resource_lease_plan_sha256: $lease_plan_sha,
      resource_scarcity_receipts_sha256: $receipts_sha,
      control_plane_context_sha256: $context_sha
    },
    recommendations: $recommendations,
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
      changes_live_queue_policy: false
    }
  }
' >"$bundle_core"

bundle_hash="$(jq -cS . "$bundle_core" | sha256sum | awk '{print $1}')"
recommendation_bundle_id="recommendation-bundle-${bundle_hash:0:16}"

jq \
  --arg recommendation_bundle_id "$recommendation_bundle_id" \
  --arg bundle_path "$bundle_path" \
  --arg dashboard_path "$dashboard_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '. + {
    recommendation_bundle_id: $recommendation_bundle_id,
    artifact_paths: {
      bundle_json: $bundle_path,
      dashboard_projection_json: $dashboard_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' "$bundle_core" >"$bundle_tmp"
mv "$bundle_tmp" "$bundle_path"

jq -n \
  --slurpfile bundle "$bundle_path" \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile context "$context_normalized" \
  '
  ($bundle[0]) as $bundle |
  ($forecast[0]) as $forecast |
  ($context[0]) as $context |
  ($bundle.recommendations[0].action // "none") as $top_action |
  {
    schema_version: "franken-engine.swarm-autopilot-dashboard-projection.v1",
    source_revision: $bundle.source_revision,
    generated_epoch_seconds: $bundle.generated_epoch_seconds,
    decision: $bundle.decision,
    truth_state: $bundle.truth_state,
    overall_state: $bundle.summary.overall_state,
    top_action: {
      action: $top_action,
      lane_id: ($bundle.recommendations[0].lane_id // null)
    },
    summary_cards: [
      {card_id: "decision", value: $bundle.decision},
      {card_id: "overall_state", value: $bundle.summary.overall_state},
      {card_id: "brownout_state", value: ($forecast.summary.brownout_state // "unknown")},
      {card_id: "evidence_freshness", value: ($context.telemetry_freshness_state // "unknown")},
      {card_id: "top_action", value: $top_action}
    ],
    top_recommendations: ($bundle.recommendations | .[0:3]),
    mutation_policy: $bundle.mutation_policy
  }
' >"$dashboard_core"

dashboard_hash="$(jq -cS . "$dashboard_core" | sha256sum | awk '{print $1}')"
dashboard_projection_id="dashboard-projection-${dashboard_hash:0:16}"

jq \
  --arg dashboard_projection_id "$dashboard_projection_id" \
  '. + {dashboard_projection_id: $dashboard_projection_id}' \
  "$dashboard_core" >"$dashboard_tmp"
mv "$dashboard_tmp" "$dashboard_path"

jq -r '
  [
    "# Swarm Autopilot Recommendation Bundle",
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
      ["## Recommendations", ""] +
      (.recommendations | map("- `" + .action + "` " + (.summary // "")))
    end)
  | join("\n")
' "$bundle_path" >"$report_path"

write_event "swarm_autopilot_recommendation_bundle" "bundle_emitted" "$decision" "" "$bundle_path"
write_event "swarm_autopilot_recommendation_bundle" "dashboard_projection_emitted" "captured" "" "$dashboard_path"

exit "$exit_code"
