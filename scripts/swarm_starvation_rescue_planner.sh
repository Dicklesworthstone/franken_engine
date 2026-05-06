#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_STARVATION_RESCUE_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-starvation-rescue-plan}"
run_id="${SWARM_STARVATION_RESCUE_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_STARVATION_RESCUE_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

starvation_rescue_input_json=""
scenario_matrix_report_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_starvation_rescue_planner.sh \
  --starvation-rescue-input-json FILE \
  --scenario-matrix-report-json FILE \
  [OPTIONS]

Consumes the normalized starvation-rescue input plus the approved scenario
matrix policy and emits a dry-run rescue/arbitration receipt. This script is
report-only: it does not mutate beads, reservations, or worker state.

Required:
  --starvation-rescue-input-json FILE
  --scenario-matrix-report-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_starvation_rescue_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  advisory plan published
  42 fail-closed due to missing policy coverage or blocked input truth
  75 manual review required before any rescue action
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --starvation-rescue-input-json)
      starvation_rescue_input_json="${2:-}"
      shift 2
      ;;
    --scenario-matrix-report-json)
      scenario_matrix_report_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
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

if [[ -z "$starvation_rescue_input_json" || -z "$scenario_matrix_report_json" ]]; then
  printf 'swarm starvation rescue planner requires both primary JSON inputs\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm starvation rescue planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm starvation rescue planning\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
for required_path in "$starvation_rescue_input_json" "$scenario_matrix_report_json"; do
  if [[ ! -f "$required_path" ]]; then
    printf 'missing required planner input: %s\n' "$required_path" >&2
    exit 64
  fi
  if ! jq empty "$required_path" >/dev/null 2>&1; then
    printf 'invalid planner input JSON: %s\n' "$required_path" >&2
    exit 64
  fi
done

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_starvation_rescue_plan.json"
plan_tmp="${plan_path}.tmp"
core_path="${run_dir}/swarm_starvation_rescue_plan.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md_path="${run_dir}/report.md"
fail_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"
input_normalized="${run_dir}/swarm_starvation_rescue_input.normalized.json"
matrix_normalized="${run_dir}/swarm_starvation_rescue_scenario_matrix.normalized.json"

printf './scripts/swarm_starvation_rescue_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-starvation-rescue-planner.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      detail: $detail,
      source_revision: $source_revision
    }' >>"$events_path"
}

append_failure() {
  jq -nc \
    --arg kind "$1" \
    --arg detail "$2" \
    '{kind:$kind,detail:$detail}' >>"$fail_reasons_jsonl"
}

jq -cS . "$starvation_rescue_input_json" >"$input_normalized"
jq -cS . "$scenario_matrix_report_json" >"$matrix_normalized"

if ! jq -e '
  .schema_version == "franken-engine.swarm-starvation-rescue-input.v1"
  and has("decision")
  and has("summary")
  and (.normalized_inputs | type == "object")
' "$input_normalized" >/dev/null 2>&1; then
  append_failure "invalid_rescue_input" "normalized rescue input missing required fields"
fi

if ! jq -e '
  .schema_version == "franken-engine.swarm-starvation-rescue-scenario-matrix-report.v1"
  and (.required_scenario_classes | type == "array")
  and (.cases | type == "array" and length > 0)
  and (.failure_count | type == "number")
' "$matrix_normalized" >/dev/null 2>&1; then
  append_failure "invalid_scenario_matrix_report" "scenario matrix report missing required fields"
fi

matrix_failure_count="$(jq -r '.failure_count // 0' "$matrix_normalized")"
if [[ "$matrix_failure_count" != "0" ]]; then
  append_failure "scenario_matrix_not_green" "scenario matrix report failure_count=${matrix_failure_count}"
fi

write_event "swarm_starvation_rescue_planner.inputs_loaded" "loaded normalized rescue input and scenario policy"

jq -n \
  --slurpfile input "$input_normalized" \
  --slurpfile matrix "$matrix_normalized" \
  --slurpfile fail_rows "$fail_reasons_jsonl" \
  --arg schema_version "franken-engine.swarm-starvation-rescue-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg input_path "$starvation_rescue_input_json" \
  --arg matrix_path "$scenario_matrix_report_json" \
  '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def has_fail_kind($input; $kind):
    any(($input.fail_closed_reasons // [])[]?; low(.kind // "") == $kind);
  def scenario_class($input):
    if low($input.decision) == "fail_closed" and has_fail_kind($input; "local_rch_fallback_admitted") then
      "local_fallback"
    elif low($input.decision) == "fail_closed" and has_fail_kind($input; "stale_required_input") then
      "stale_telemetry"
    elif low($input.decision) == "fail_closed" and has_fail_kind($input; "contradictory_ownership") then
      "ownership_contradiction"
    elif (($input.summary.manual_review_count // 0) > 0)
      or (low($input.derived_truth.lease_decision // "unknown") == "manual_review_required") then
      "salvage_pinned"
    elif (($input.summary.brownout_finding_count // 0) > 0)
      or (($input.summary.starvation_finding_count // 0) > 0) then
      "brownout"
    else
      "healthy"
    end;
  ($input[0]) as $input_doc |
  ($matrix[0]) as $matrix_doc |
  ($fail_rows // []) as $prefail |
  (scenario_class($input_doc)) as $scenario |
  ($matrix_doc.required_scenario_classes // []) as $required_classes |
  ([($matrix_doc.cases // [])[] | select(.scenario_class == $scenario and .matched_expected == true)]) as $matched_cases |
  (($input_doc.fail_closed_reasons // []) + $prefail
    + (if any($required_classes[]?; . == $scenario) then [] else [{kind:"missing_policy_coverage", detail:("required scenario class missing: " + $scenario)}] end)
    + (if (($matched_cases | length) > 0) then [] else [{kind:"scenario_policy_not_matched", detail:("no green matrix case for scenario class " + $scenario)}] end)
  ) as $failures |
  (if (($failures | length) > 0) or low($input_doc.decision) == "fail_closed" then "fail_closed"
    elif (($input_doc.summary.manual_review_count // 0) > 0) or (($input_doc.summary.contact_first_count // 0) > 0) then "manual_review_required"
    else "advisory"
    end) as $decision |
  (if $decision == "fail_closed" then 42 elif $decision == "manual_review_required" then 75 else 0 end) as $exit_code |
  def recommendation_rows:
    if $decision == "fail_closed" then
      [
        {
          rank: 1,
          action: (
            if has_fail_kind($input_doc; "local_rch_fallback_admitted") then "reject_local_fallback_and_refresh_forecast"
            elif has_fail_kind($input_doc; "stale_required_input") then "refresh_stale_inputs_before_rescue"
            elif has_fail_kind($input_doc; "contradictory_ownership") then "manual_ownership_review"
            else "refresh_inputs_before_rescue"
            end
          ),
          score_millionths: 1000000,
          fairness_reason: "Planner cannot rank rescue actions until blocked input truth is repaired.",
          starvation_severity: (if ($input_doc.summary.brownout_finding_count // 0) > 0 then "brownout" else "blocked" end),
          ownership_risk: (if ($input_doc.summary.ownership_fail_closed_count // 0) > 0 then "contradictory" else "unknown" end),
          salvage_pressure: (if low($input_doc.derived_truth.lease_decision // "unknown") == "manual_review_required" then "pinned" else "unknown" end),
          required_next_actions: [
            "Do not mutate bead or reservation state from this plan.",
            "Repair the blocked input truth first and rerun the planner."
          ]
        }
      ]
    elif $decision == "manual_review_required" then
      [
        {
          rank: 1,
          action: "preserve_pinned_evidence",
          score_millionths: 950000,
          fairness_reason: "Manual confirmation and evidence preservation outrank any automated rebalance while ownership or salvage pressure remains active.",
          starvation_severity: (if ($input_doc.summary.starvation_finding_count // 0) > 0 then "elevated" else "contained" end),
          ownership_risk: "contact_first",
          salvage_pressure: "pinned_or_manual_review",
          required_next_actions: [
            "Contact the current owner before attempting lease exchange or reopen.",
            "Keep proof artifacts pinned until manual review clears."
          ]
        },
        {
          rank: 2,
          action: "contact_owner_before_exchange",
          score_millionths: 830000,
          fairness_reason: "Fairness cannot override explicit owner-contact requirements.",
          starvation_severity: "contained",
          ownership_risk: "contact_first",
          salvage_pressure: "unchanged",
          required_next_actions: [
            "Send a coordination packet with the current rescue evidence bundle."
          ]
        }
      ]
    elif $scenario == "brownout" then
      [
        {
          rank: 1,
          action: "defer_broad_work_and_rebalance",
          score_millionths: 910000,
          fairness_reason: "Queue brownout and low-priority starvation require narrowing heavy work before reopening additional claims.",
          starvation_severity: "brownout",
          ownership_risk: "low",
          salvage_pressure: "unchanged",
          required_next_actions: [
            "Keep only protected or narrow work admitted.",
            "Rotate broad deferred work behind the next healthy window."
          ]
        },
        {
          rank: 2,
          action: "reopen_one_stale_claim_after_pressure_cools",
          score_millionths: 770000,
          fairness_reason: "Safe-to-reopen opportunities should be consumed only after brownout pressure cools.",
          starvation_severity: "elevated",
          ownership_risk: "low",
          salvage_pressure: "unchanged",
          required_next_actions: [
            "Recheck brownout and admission signals before widening scope."
          ]
        }
      ]
    else
      [
        {
          rank: 1,
          action: "reopen_stale_claim_then_rebalance",
          score_millionths: 900000,
          fairness_reason: "Fresh rescue inputs and stale-reclaimable claims allow a bounded reopen-first rescue posture.",
          starvation_severity: "low",
          ownership_risk: "low",
          salvage_pressure: "unchanged",
          required_next_actions: [
            "Reopen only evidence-supported stale claims.",
            "Rebalance deferred work after the reopen lands."
          ]
        },
        {
          rank: 2,
          action: "monitor_queue_and_keep_fair_share",
          score_millionths: 700000,
          fairness_reason: "No brownout or manual-review pressure is active, so ongoing queue hygiene is sufficient.",
          starvation_severity: "low",
          ownership_risk: "low",
          salvage_pressure: "unchanged",
          required_next_actions: [
            "Keep the next proof batch narrow and fairness-bounded."
          ]
        }
      ]
    end;
  (recommendation_rows) as $recommendations |
  {
    schema_version: $schema_version,
    source_revision: $source_revision,
    decision: $decision,
    exit_code: $exit_code,
    scenario_class: $scenario,
    summary: {
      recommendation_count: ($recommendations | length),
      top_recommendation_action: ($recommendations[0].action // null),
      readiness: ($input_doc.summary.readiness // "unknown"),
      brownout_finding_count: ($input_doc.summary.brownout_finding_count // 0),
      starvation_finding_count: ($input_doc.summary.starvation_finding_count // 0),
      safe_to_reopen_count: ($input_doc.summary.safe_to_reopen_count // 0),
      contact_first_count: ($input_doc.summary.contact_first_count // 0),
      lease_exchange_candidate_count: ($input_doc.summary.lease_exchange_candidate_count // 0),
      manual_review_count: ($input_doc.summary.manual_review_count // 0),
      ownership_fail_closed_count: ($input_doc.summary.ownership_fail_closed_count // 0)
    },
    assumptions: [
      "The normalized starvation-rescue input remains the only live rescue truth consumed here.",
      "The scenario matrix report is policy-only; the planner never mutates live worker or tracker state.",
      "Fairness and ownership safety outrank rescue throughput when those signals conflict."
    ],
    policy_basis: {
      matrix_schema_version: ($matrix_doc.matrix_schema_version // $matrix_doc.schema_version // null),
      matched_case_ids: ($matched_cases | map(.case_id)),
      matched_case_count: ($matched_cases | length),
      required_scenario_classes: $required_classes
    },
    recommendations: $recommendations,
    fail_closed_reasons: $failures,
    resolved_inputs: [
      {input:"starvation_rescue_input_json", path:$input_path, schema_version:($input_doc.schema_version // null)},
      {input:"scenario_matrix_report_json", path:$matrix_path, schema_version:($matrix_doc.schema_version // null)}
    ]
  }' >"$core_path"

plan_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
plan_id="swarm-starvation-rescue-plan-${plan_hash:0:16}"

jq \
  --arg plan_id "$plan_id" \
  --arg plan_hash "$plan_hash" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md_path "$report_md_path" \
  --arg contract_json "docs/swarm_starvation_rescue_planner_contract_v1.json" \
  '
  . + {
    plan_id: $plan_id,
    hash_basis: {
      plan_hash: $plan_hash
    },
    artifact_paths: {
      swarm_starvation_rescue_plan_json: $plan_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md_path
    },
    contract_paths: {
      planner_contract_json: $contract_json
    }
  }' "$core_path" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

write_event "swarm_starvation_rescue_planner.completed" \
  "$(jq -r '.decision + " / top_action=" + (.summary.top_recommendation_action // "none")' "$plan_path")"

{
  printf '# Swarm Starvation Rescue Plan\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$plan_path")"
  printf -- "- Scenario class: \`%s\`\n" "$(jq -r '.scenario_class' "$plan_path")"
  printf -- "- Top recommendation: \`%s\`\n" "$(jq -r '.summary.top_recommendation_action' "$plan_path")"
  printf -- "- Recommendation count: \`%s\`\n" "$(jq -r '.summary.recommendation_count' "$plan_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$plan_path")" -ne 0 ]]; then
    printf '\n## Fail-closed reasons\n'
    jq -r '.fail_closed_reasons[] | "- [" + .kind + "] " + .detail' "$plan_path"
  fi
} >"$report_md_path"

printf 'swarm_starvation_rescue_plan=%s\n' "$plan_path"
case "$(jq -r '.decision' "$plan_path")" in
  advisory)
    exit 0
    ;;
  manual_review_required)
    exit 75
    ;;
  *)
    exit 42
    ;;
esac
