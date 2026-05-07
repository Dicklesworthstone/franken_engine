#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_CAPABILITY_AFFINITY_OUTCOME_LEDGER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-capability-affinity-outcome-ledger}"
run_id="${SWARM_CAPABILITY_AFFINITY_OUTCOME_LEDGER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CAPABILITY_AFFINITY_OUTCOME_LEDGER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_CAPABILITY_AFFINITY_OUTCOME_LEDGER_SOURCE_REVISION:-unknown}"
capability_affinity_routing_advisory_json=""
routing_outcome_samples_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_capability_affinity_routing_outcome_ledger.sh [OPTIONS]

Records planned versus observed capability-affinity routing outcomes from the
advisory planner output plus checked-in observed routing samples. This script
is fixture-fed and advisory-only. It does not update beads, release
reservations, send Agent Mail, run Cargo or RCH, mutate remote workers,
reroute live tasks automatically, or change live queue policy.

Required inputs:
  --capability-affinity-routing-advisory-json FILE
  --routing-outcome-samples-json FILE

Other options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_capability_affinity_routing_outcome_ledger.json
  swarm_capability_affinity_routing_outcome_sources.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  ledger is replayable; decision may be pass or degraded
  42 fail-closed due to malformed or contaminated evidence
  75 blocked due to capability or toolchain mismatch receipts
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --capability-affinity-routing-advisory-json)
      capability_affinity_routing_advisory_json="${2:-}"
      shift 2
      ;;
    --routing-outcome-samples-json)
      routing_outcome_samples_json="${2:-}"
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

if [[ -z "$capability_affinity_routing_advisory_json" || -z "$routing_outcome_samples_json" ]]; then
  printf 'advisory JSON and routing outcome samples JSON are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for capability-affinity routing outcome ledgers\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for capability-affinity routing outcome ledgers\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
ledger_path="${run_dir}/swarm_capability_affinity_routing_outcome_ledger.json"
ledger_tmp="${ledger_path}.tmp"
sources_path="${run_dir}/swarm_capability_affinity_routing_outcome_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
source_rows_jsonl="${run_dir}/source_rows.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

advisory_normalized="${run_dir}/capability_affinity_routing_advisory.normalized.json"
routing_outcome_samples_normalized="${run_dir}/routing_outcome_samples.normalized.json"
task_outcomes_json="${run_dir}/task_outcomes.json"

printf './scripts/swarm_capability_affinity_routing_outcome_ledger.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$source_rows_jsonl"
: >"$degraded_reasons_jsonl"
: >"$blocked_reasons_jsonl"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-capability-affinity-routing-outcome-ledger.event.v1" \
    --arg component "swarm_capability_affinity_routing_outcome_ledger" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

append_reason() {
  local path="$1"
  local code="$2"
  local source_id="$3"
  local detail="$4"
  jq -nc --arg code "$code" --arg source_id "$source_id" --arg detail "$detail" \
    '{code:$code,source_id:$source_id,detail:$detail}' >>"$path"
}

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ ! -f "$input" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
  write_event "input.loaded" "provided" "$label" "$input"
}

check_shape() {
  local file="$1"
  local expr="$2"
  local source_id="$3"
  local detail="$4"
  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    append_reason "$fail_closed_reasons_jsonl" "malformed_required_shape" "$source_id" "$detail"
  fi
}

append_source_row() {
  local source_id="$1"
  local artifact_path="$2"
  local schema_version="$3"
  local trust_state="$4"
  jq -nc \
    --arg source_id "$source_id" \
    --arg artifact_path "$artifact_path" \
    --arg schema_version "$schema_version" \
    --arg trust_state "$trust_state" \
    '{source_id:$source_id,required:true,provided:true,artifact_path:$artifact_path,schema_version:$schema_version,trust_state:$trust_state}' \
    >>"$source_rows_jsonl"
}

normalize_required_json "$capability_affinity_routing_advisory_json" "$advisory_normalized" "capability affinity routing advisory"
normalize_required_json "$routing_outcome_samples_json" "$routing_outcome_samples_normalized" "routing outcome samples"

check_shape "$advisory_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.worker_affinity_summary.routing_mode // "") | (type == "string" and length > 0))
  and ((.worker_affinity_summary.advised_worker_ids // null) | type == "array")
  and ((.reason_codes // null) | type == "array")
  and ((.capability_coverage_summary.missing_required_capability_task_ids // null) | type == "array")
  and ((.toolchain_parity_summary.toolchain_mismatch_task_ids // null) | type == "array")
  and ((.mutation_policy.advisory_only | type) == "boolean")
  and ((.mutation_policy.runs_cargo | type) == "boolean")
  and ((.mutation_policy.runs_rch | type) == "boolean")
' "capability_affinity_routing_advisory_json" "advisory lacks required routing, reason-code, or mutation-policy fields"

check_shape "$routing_outcome_samples_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.samples // null) | type == "array")
  and ((.samples | length) > 0)
  and all(.samples[]?;
    ((.task_id // "") | (type == "string" and length > 0))
    and ((.recommended_worker_id // "") | (type == "string" and length > 0))
    and ((.observed_worker_id // "") | (type == "string" and length > 0))
    and ((.observed_outcome // "") | (type == "string" and length > 0))
  )
' "routing_outcome_samples_json" "routing outcome samples lack required task, worker, or outcome fields"

advisory_truth_state="$(jq -r '.truth_state // "unknown"' "$advisory_normalized")"
advisory_decision="$(jq -r '.decision // "unknown"' "$advisory_normalized")"
routing_mode="$(jq -r '.worker_affinity_summary.routing_mode // "unknown"' "$advisory_normalized")"
reason_codes_json="$(jq -c '.reason_codes // []' "$advisory_normalized")"
advised_worker_ids_json="$(jq -c '.worker_affinity_summary.advised_worker_ids // []' "$advisory_normalized")"
missing_required_capability_task_ids_json="$(jq -c '.capability_coverage_summary.missing_required_capability_task_ids // []' "$advisory_normalized")"
toolchain_mismatch_task_ids_json="$(jq -c '.toolchain_parity_summary.toolchain_mismatch_task_ids // []' "$advisory_normalized")"

task_outcomes_filter='
  .samples
  | map(
      . + {
        outcome_classification:
          (if .observed_outcome == "matched_recommended_route" then "match"
           elif .observed_outcome == "matched_broader_cohort" then "broader_match"
           elif .observed_outcome == "mismatched_route" then "mismatch"
           elif .observed_outcome == "capability_gap_observed" then "capability_gap"
           elif .observed_outcome == "toolchain_drift_observed" then "toolchain_drift"
           elif .observed_outcome == "local_fallback_contaminated" then "contaminated"
           else "mismatch"
           end)
      }
    )
'
jq "$task_outcomes_filter" "$routing_outcome_samples_normalized" >"$task_outcomes_json"

matched_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "match" or .outcome_classification == "broader_match") | .task_id] | unique' "$task_outcomes_json")"
mismatched_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "mismatch") | .task_id] | unique' "$task_outcomes_json")"
capability_gap_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "capability_gap") | .task_id] | unique' "$task_outcomes_json")"
toolchain_drift_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "toolchain_drift") | .task_id] | unique' "$task_outcomes_json")"
contamination_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "contaminated") | .task_id] | unique' "$task_outcomes_json")"

if [[ "$advisory_truth_state" == "contaminated" || "$advisory_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "capability_affinity_routing_advisory_json" "upstream advisory is already contaminated"
fi
if jq -e 'length > 0' <<<"$contamination_task_ids_json" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "routing_outcome_samples_json" "routing outcome samples record local fallback contamination"
fi
if jq -e 'length > 0' <<<"$toolchain_drift_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "observed_toolchain_drift" "routing_outcome_samples_json" "observed routing outcomes record toolchain drift"
fi
if jq -e 'length > 0' <<<"$capability_gap_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "observed_capability_gap" "routing_outcome_samples_json" "observed routing outcomes record missing required capability coverage"
fi
if [[ "$advisory_decision" == "blocked" || "$advisory_truth_state" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "blocked_upstream_advisory" "capability_affinity_routing_advisory_json" "blocked advisory remains blocked in the outcome ledger"
fi
if jq -e 'length > 0' <<<"$mismatched_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "observed_route_mismatch" "routing_outcome_samples_json" "observed routing outcomes drifted away from the advised cohort"
fi
if jq -e '[.[] | select(.outcome_classification == "broader_match")] | length > 0' "$task_outcomes_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "matched_broader_cohort" "routing_outcome_samples_json" "observed routing matched a broader fallback cohort"
fi
if jq -e '((.reason_codes // []) | map(select(. == "broader_cohort_fallback" or . == "watch_workers_present" or . == "rehab_candidates_present")) | length > 0)' "$advisory_normalized" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "exclusion_reason_recorded" "capability_affinity_routing_advisory_json" "upstream advisory preserved broader-fallback or exclusion reasons"
fi

decision="$advisory_decision"
truth_state="$advisory_truth_state"
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="contaminated"
elif [[ -s "$blocked_reasons_jsonl" ]]; then
  decision="blocked"
  truth_state="blocked"
elif [[ "$advisory_decision" == "degraded" || "$advisory_truth_state" == "degraded" || -s "$degraded_reasons_jsonl" ]]; then
  decision="degraded"
  truth_state="degraded"
else
  decision="pass"
  truth_state="confirmed"
fi

upstream_reason_codes_json="$(jq -c '.reason_codes // []' "$advisory_normalized")"
local_degraded_codes_json="$(jq -c -s 'map(.code) | unique' "$degraded_reasons_jsonl")"
local_blocked_codes_json="$(jq -c -s 'map(.code) | unique' "$blocked_reasons_jsonl")"
local_fail_closed_codes_json="$(jq -c -s 'map(.code) | unique' "$fail_closed_reasons_jsonl")"
observed_reason_codes_json="$(jq -c '[.[] | .observed_outcome] | unique' "$task_outcomes_json")"

reason_codes_json="$(
  jq -cn \
    --argjson upstream "$upstream_reason_codes_json" \
    --argjson local_degraded "$local_degraded_codes_json" \
    --argjson local_blocked "$local_blocked_codes_json" \
    --argjson local_fail_closed "$local_fail_closed_codes_json" \
    --argjson observed "$observed_reason_codes_json" '
    ($upstream + $local_degraded + $local_blocked + $local_fail_closed + $observed) | unique
  '
)"

advisory_schema_version="$(jq -r '.schema_version // "unknown"' "$advisory_normalized")"
outcome_schema_version="$(jq -r '.schema_version // "unknown"' "$routing_outcome_samples_normalized")"
append_source_row "capability_affinity_routing_advisory_json" "$advisory_normalized" "$advisory_schema_version" "$advisory_truth_state"
append_source_row "routing_outcome_samples_json" "$routing_outcome_samples_normalized" "$outcome_schema_version" "provided"

outcome_ledger_id="$(
  jq -cn \
    --arg source_revision "$source_revision" \
    --arg truth_state "$truth_state" \
    --arg decision "$decision" \
    --argjson reason_codes "$reason_codes_json" \
    --argjson matched_task_ids "$matched_task_ids_json" \
    --argjson mismatched_task_ids "$mismatched_task_ids_json" \
    --argjson capability_gap_task_ids "$capability_gap_task_ids_json" \
    --argjson toolchain_drift_task_ids "$toolchain_drift_task_ids_json" \
    --argjson contamination_task_ids "$contamination_task_ids_json" \
    '{source_revision:$source_revision,truth_state:$truth_state,decision:$decision,reason_codes:$reason_codes,matched_task_ids:$matched_task_ids,mismatched_task_ids:$mismatched_task_ids,capability_gap_task_ids:$capability_gap_task_ids,toolchain_drift_task_ids:$toolchain_drift_task_ids,contamination_task_ids:$contamination_task_ids}' \
    | jq -cS . | sha256sum | awk '{print "caol-" substr($1,1,16)}'
)"

jq -n \
  --arg schema_version "franken-engine.swarm-capability-affinity-routing-outcome-sources.v1" \
  --slurpfile source_rows "$source_rows_jsonl" \
  '{schema_version:$schema_version,source_artifacts:$source_rows}' >"$sources_path"

jq -n \
  --arg schema_version "franken-engine.swarm-capability-affinity-routing-outcome-ledger.v1" \
  --arg source_schema_version "franken-engine.swarm-capability-affinity-routing-outcome-sources.v1" \
  --arg outcome_ledger_id "$outcome_ledger_id" \
  --arg source_revision "$source_revision" \
  --arg truth_state "$truth_state" \
  --arg decision "$decision" \
  --arg routing_mode "$routing_mode" \
  --arg ledger_path "$ledger_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson planned_advised_worker_ids "$advised_worker_ids_json" \
  --argjson upstream_missing_required_capability_task_ids "$missing_required_capability_task_ids_json" \
  --argjson upstream_toolchain_mismatch_task_ids "$toolchain_mismatch_task_ids_json" \
  --argjson matched_task_ids "$matched_task_ids_json" \
  --argjson mismatched_task_ids "$mismatched_task_ids_json" \
  --argjson capability_gap_task_ids "$capability_gap_task_ids_json" \
  --argjson toolchain_drift_task_ids "$toolchain_drift_task_ids_json" \
  --argjson contamination_task_ids "$contamination_task_ids_json" \
  --slurpfile degraded_reasons "$degraded_reasons_jsonl" \
  --slurpfile blocked_reasons "$blocked_reasons_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --slurpfile task_outcomes "$task_outcomes_json" \
  --slurpfile source_rows "$source_rows_jsonl" \
  '{
    schema_version:$schema_version,
    source_schema_version:$source_schema_version,
    outcome_ledger_id:$outcome_ledger_id,
    source_revision:$source_revision,
    truth_state:$truth_state,
    decision:$decision,
    routing_mode:$routing_mode,
    reason_codes:$reason_codes,
    planned_advised_worker_ids:$planned_advised_worker_ids,
    upstream_missing_required_capability_task_ids:$upstream_missing_required_capability_task_ids,
    upstream_toolchain_mismatch_task_ids:$upstream_toolchain_mismatch_task_ids,
    matched_task_ids:$matched_task_ids,
    mismatched_task_ids:$mismatched_task_ids,
    capability_gap_task_ids:$capability_gap_task_ids,
    toolchain_drift_task_ids:$toolchain_drift_task_ids,
    contamination_task_ids:$contamination_task_ids,
    degraded_reasons:$degraded_reasons,
    blocked_reasons:$blocked_reasons,
    fail_closed_reasons:$fail_closed_reasons,
    task_outcomes:$task_outcomes[0],
    source_artifacts:$source_rows,
    artifact_paths:{
      outcome_ledger_json:$ledger_path,
      sources_json:$sources_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      summary_md:$summary_path
    },
    mutation_policy:{
      advisory_only:true,
      proof_only:true,
      fixture_fed_only:true,
      mutates_br:false,
      reassigns_beads:false,
      releases_reservations:false,
      sends_agent_mail:false,
      runs_cargo:false,
      runs_rch:false,
      mutates_remote_workers:false,
      changes_live_queue_policy:false,
      reroutes_tasks_automatically:false
    }
  }' >"$ledger_tmp"
mv "$ledger_tmp" "$ledger_path"

{
  printf '# Capability Affinity Routing Outcome Ledger\n'
  printf '\n'
  printf -- "- outcome_ledger_id: \`%s\`\n" "$outcome_ledger_id"
  printf -- "- truth_state: \`%s\`\n" "$truth_state"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- routing_mode: \`%s\`\n" "$routing_mode"
  printf -- "- planned_advised_worker_ids: \`%s\`\n" "$advised_worker_ids_json"
  printf -- "- matched_task_ids: \`%s\`\n" "$matched_task_ids_json"
  printf -- "- mismatched_task_ids: \`%s\`\n" "$mismatched_task_ids_json"
  printf -- "- capability_gap_task_ids: \`%s\`\n" "$capability_gap_task_ids_json"
  printf -- "- toolchain_drift_task_ids: \`%s\`\n" "$toolchain_drift_task_ids_json"
  printf -- "- contamination_task_ids: \`%s\`\n" "$contamination_task_ids_json"
  printf -- "- reason_codes: \`%s\`\n" "$reason_codes_json"
} >"$summary_path"

write_event "ledger.decided" "$decision" "$routing_mode" "$ledger_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
if [[ "$decision" == "blocked" ]]; then
  exit 75
fi
exit 0
