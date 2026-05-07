#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_CAPABILITY_AFFINITY_ROUTING_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-capability-affinity-routing}"
run_id="${SWARM_CAPABILITY_AFFINITY_ROUTING_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CAPABILITY_AFFINITY_ROUTING_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_CAPABILITY_AFFINITY_ROUTING_SOURCE_REVISION:-unknown}"
worker_capability_toolchain_input_json=""
routing_outcome_samples_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_capability_affinity_queue_routing_planner.sh [OPTIONS]

Builds deterministic capability-affinity queue-routing advice from the
normalized worker capability/toolchain input bundle. This script is
fixture-fed and advisory-only. It does not update beads, release reservations,
send Agent Mail, run Cargo or RCH, mutate remote workers, reroute live tasks
automatically, or change live queue policy.

Required input:
  --worker-capability-toolchain-input-json FILE

Optional input:
  --routing-outcome-samples-json FILE

Other options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  capability_affinity_queue_routing_advisory.json
  capability_affinity_queue_routing_sources.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  routing advice is replayable; decision may be pass or degraded
  42 fail-closed due to malformed or contaminated evidence
  75 blocked due to capability or toolchain mismatch
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --worker-capability-toolchain-input-json)
      worker_capability_toolchain_input_json="${2:-}"
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

if [[ -z "$worker_capability_toolchain_input_json" ]]; then
  printf 'worker capability toolchain input is required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for capability-affinity queue-routing planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for capability-affinity queue-routing planning\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
advisory_path="${run_dir}/capability_affinity_queue_routing_advisory.json"
advisory_tmp="${advisory_path}.tmp"
sources_path="${run_dir}/capability_affinity_queue_routing_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
source_rows_jsonl="${run_dir}/source_rows.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

worker_input_normalized="${run_dir}/worker_capability_toolchain_input.normalized.json"
routing_outcome_samples_normalized="${run_dir}/routing_outcome_samples.normalized.json"

printf './scripts/swarm_capability_affinity_queue_routing_planner.sh' >"$commands_path"
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
    --arg schema_version "franken-engine.capability-affinity-queue-routing-planner.event.v1" \
    --arg component "swarm_capability_affinity_queue_routing_planner" \
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

normalize_optional_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ -z "$input" ]]; then
    printf '{}\n' >"$output"
    write_event "input.loaded" "missing_optional" "$label" "$output"
    printf 'missing'
    return
  fi
  if [[ ! -f "$input" ]]; then
    printf 'missing optional %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid optional %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
  write_event "input.loaded" "provided" "$label" "$input"
  printf 'provided'
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
  local required="$2"
  local provided="$3"
  local artifact_path="$4"
  local schema_version="$5"
  local trust_state="$6"
  jq -nc \
    --arg source_id "$source_id" \
    --argjson required "$required" \
    --argjson provided "$provided" \
    --arg artifact_path "$artifact_path" \
    --arg schema_version "$schema_version" \
    --arg trust_state "$trust_state" \
    '{source_id:$source_id,required:$required,provided:$provided,artifact_path:$artifact_path,schema_version:$schema_version,trust_state:$trust_state}' \
    >>"$source_rows_jsonl"
}

json_length() {
  jq 'length' <<<"$1"
}

normalize_required_json "$worker_capability_toolchain_input_json" "$worker_input_normalized" "worker capability toolchain input"
routing_outcome_samples_status="$(normalize_optional_json "$routing_outcome_samples_json" "$routing_outcome_samples_normalized" "routing outcome samples")"

check_shape "$worker_input_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.topology_context.preferred_worker_ids // null) | type == "array")
  and ((.rehabilitation_context.excluded_worker_ids // null) | type == "array")
  and ((.capability_context.required_capabilities // null) | type == "array")
  and ((.capability_context.coverage_confirmed_task_ids // null) | type == "array")
  and ((.capability_context.missing_required_capability_task_ids // null) | type == "array")
  and ((.toolchain_context.required_toolchain_fingerprints // null) | type == "array")
  and ((.toolchain_context.toolchain_mismatch_task_ids // null) | type == "array")
  and ((.routing_hints.routing_mode // "") | (type == "string" and length > 0))
  and ((.routing_hints.advised_worker_ids // null) | type == "array")
  and ((.source_artifacts // null) | type == "array")
  and ((.mutation_policy.advisory_only | type) == "boolean")
  and ((.mutation_policy.runs_cargo | type) == "boolean")
  and ((.mutation_policy.runs_rch | type) == "boolean")
' "worker_capability_toolchain_input_json" "worker capability toolchain input lacks required advisory fields"

if [[ "$routing_outcome_samples_status" == "provided" ]]; then
  check_shape "$routing_outcome_samples_normalized" '
    type == "object"
    and ((.schema_version // "") | (type == "string" and length > 0))
    and ((.samples // null) | type == "array")
    and all(.samples[]?;
      ((.task_id // "") | (type == "string" and length > 0))
      and ((.recommended_worker_id // "") | (type == "string" and length > 0))
      and ((.observed_worker_id // "") | (type == "string" and length > 0))
      and ((.observed_outcome // "") | (type == "string" and length > 0))
    )
  ' "routing_outcome_samples_json" "routing outcome samples lack required task or worker fields"
fi

input_truth_state="$(jq -r '.truth_state // "unknown"' "$worker_input_normalized")"
input_decision="$(jq -r '.decision // "unknown"' "$worker_input_normalized")"
routing_mode="$(jq -r '.routing_hints.routing_mode // "unknown"' "$worker_input_normalized")"
recommended_topology_class="$(jq -r '.topology_context.recommended_topology_class // "portable_fallback"' "$worker_input_normalized")"
preferred_worker_ids_json="$(jq -c '.topology_context.preferred_worker_ids // []' "$worker_input_normalized")"
excluded_worker_ids_json="$(jq -c '.rehabilitation_context.excluded_worker_ids // []' "$worker_input_normalized")"
watch_worker_ids_json="$(jq -c '.rehabilitation_context.watch_worker_ids // []' "$worker_input_normalized")"
rehab_candidate_worker_ids_json="$(jq -c '.rehabilitation_context.rehab_candidate_worker_ids // []' "$worker_input_normalized")"
required_capabilities_json="$(jq -c '.capability_context.required_capabilities // []' "$worker_input_normalized")"
coverage_confirmed_task_ids_json="$(jq -c '.capability_context.coverage_confirmed_task_ids // []' "$worker_input_normalized")"
missing_required_capability_task_ids_json="$(jq -c '.capability_context.missing_required_capability_task_ids // []' "$worker_input_normalized")"
required_toolchain_fingerprints_json="$(jq -c '.toolchain_context.required_toolchain_fingerprints // []' "$worker_input_normalized")"
toolchain_mismatch_task_ids_json="$(jq -c '.toolchain_context.toolchain_mismatch_task_ids // []' "$worker_input_normalized")"
broader_fallback_task_ids_json="$(jq -c '.routing_hints.broader_fallback_task_ids // []' "$worker_input_normalized")"
advised_worker_ids_json="$(jq -c '.routing_hints.advised_worker_ids // []' "$worker_input_normalized")"
task_count="$(jq '.queue_context.task_count // 0' "$worker_input_normalized")"

upstream_degraded_codes_json="$(jq -c '[.degraded_reasons[]?.code] | unique' "$worker_input_normalized")"
upstream_blocked_codes_json="$(jq -c '[.blocked_reasons[]?.code] | unique' "$worker_input_normalized")"
upstream_fail_closed_codes_json="$(jq -c '[.fail_closed_reasons[]?.code] | unique' "$worker_input_normalized")"

if [[ "$input_decision" == "pass" ]]; then
  if jq -e 'length > 0' <<<"$missing_required_capability_task_ids_json" >/dev/null \
    || jq -e 'length > 0' <<<"$toolchain_mismatch_task_ids_json" >/dev/null; then
    append_reason "$fail_closed_reasons_jsonl" "contradictory_input_state" "worker_capability_toolchain_input_json" "pass input still reports blocked task sets"
  fi
  case "$routing_mode" in
    blocked_*|fail_closed)
      append_reason "$fail_closed_reasons_jsonl" "contradictory_input_state" "worker_capability_toolchain_input_json" "pass input cannot use blocked or fail_closed routing mode"
      ;;
  esac
fi
if [[ "$input_decision" == "blocked" ]]; then
  case "$routing_mode" in
    blocked_*)
      ;;
    *)
      append_reason "$fail_closed_reasons_jsonl" "contradictory_input_state" "worker_capability_toolchain_input_json" "blocked input must preserve a blocked routing mode"
      ;;
  esac
fi
if [[ "$input_decision" == "fail_closed" && "$input_truth_state" != "contaminated" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "contradictory_input_state" "worker_capability_toolchain_input_json" "fail_closed input must preserve contaminated truth"
fi

outcome_sample_count=0
outcome_mismatch_task_ids_json='[]'
if [[ "$routing_outcome_samples_status" == "provided" ]]; then
  outcome_sample_count="$(jq '.samples | length' "$routing_outcome_samples_normalized")"
  outcome_mismatch_task_ids_json="$(jq -c '[.samples[]? | select((.observed_outcome // "") != "matched_recommended_route") | .task_id] | unique' "$routing_outcome_samples_normalized")"
  if jq -e 'length > 0' <<<"$outcome_mismatch_task_ids_json" >/dev/null; then
    append_reason "$degraded_reasons_jsonl" "outcome_samples_observed_mismatch" "routing_outcome_samples_json" "routing outcome samples show drift away from the recommended cohort"
  fi
else
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "routing_outcome_samples_json" "routing outcome samples are missing"
fi

preferred_worker_count="$(json_length "$preferred_worker_ids_json")"
excluded_worker_count="$(json_length "$excluded_worker_ids_json")"
watch_worker_count="$(json_length "$watch_worker_ids_json")"
rehab_candidate_worker_count="$(json_length "$rehab_candidate_worker_ids_json")"
missing_capability_count="$(json_length "$missing_required_capability_task_ids_json")"
toolchain_mismatch_count="$(json_length "$toolchain_mismatch_task_ids_json")"
broader_fallback_count="$(json_length "$broader_fallback_task_ids_json")"

capability_coverage_score=100
if (( missing_capability_count > 0 )); then
  capability_coverage_score=0
fi

toolchain_parity_score=100
if (( toolchain_mismatch_count > 0 )); then
  toolchain_parity_score=0
fi

preferred_locality_score=100
preferred_rehabilitation_score=100
if (( preferred_worker_count == 0 )); then
  preferred_locality_score=0
fi
if (( excluded_worker_count > 0 )); then
  preferred_rehabilitation_score=40
fi
if (( broader_fallback_count > 0 )); then
  preferred_locality_score=55
  preferred_rehabilitation_score=40
fi

advisory_locality_score=100
case "$routing_mode" in
  capability_affinity_confirmed)
    advisory_locality_score=100
    ;;
  broader_cohort_fallback)
    advisory_locality_score=70
    ;;
  blocked_*|fail_closed)
    advisory_locality_score=0
    ;;
  *)
    advisory_locality_score=50
    ;;
esac

advisory_rehabilitation_score=100
if (( watch_worker_count > 0 || rehab_candidate_worker_count > 0 )); then
  advisory_rehabilitation_score=70
fi
if (( broader_fallback_count > 0 )); then
  advisory_rehabilitation_score=80
fi
case "$routing_mode" in
  blocked_*|fail_closed)
    advisory_rehabilitation_score=0
    ;;
esac

case "$input_decision" in
  blocked|fail_closed)
    preferred_locality_score=0
    preferred_rehabilitation_score=0
    ;;
esac

preferred_total_score=$(( (35 * capability_coverage_score + 30 * toolchain_parity_score + 20 * preferred_locality_score + 15 * preferred_rehabilitation_score) / 100 ))
advisory_total_score=$(( (35 * capability_coverage_score + 30 * toolchain_parity_score + 20 * advisory_locality_score + 15 * advisory_rehabilitation_score) / 100 ))

confidence_score=100
case "$input_truth_state" in
  degraded)
    confidence_score=70
    ;;
  blocked|contaminated)
    confidence_score=0
    ;;
esac
if [[ "$routing_outcome_samples_status" == "missing" && "$confidence_score" -gt 70 ]]; then
  confidence_score=70
fi
if jq -e 'length > 0' <<<"$outcome_mismatch_task_ids_json" >/dev/null && [[ "$confidence_score" -gt 60 ]]; then
  confidence_score=60
fi

decision="$input_decision"
truth_state="$input_truth_state"
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="contaminated"
elif [[ "$input_decision" == "fail_closed" || "$input_truth_state" == "contaminated" ]]; then
  decision="fail_closed"
  truth_state="contaminated"
elif [[ "$input_decision" == "blocked" || "$input_truth_state" == "blocked" ]]; then
  decision="blocked"
  truth_state="blocked"
elif [[ "$input_decision" == "degraded" || "$input_truth_state" == "degraded" || -s "$degraded_reasons_jsonl" ]]; then
  decision="degraded"
  truth_state="degraded"
else
  decision="pass"
  truth_state="confirmed"
fi

local_degraded_codes_json="$(jq -c -s 'map(.code) | unique' "$degraded_reasons_jsonl")"
local_blocked_codes_json="$(jq -c -s 'map(.code) | unique' "$blocked_reasons_jsonl")"
local_fail_closed_codes_json="$(jq -c -s 'map(.code) | unique' "$fail_closed_reasons_jsonl")"

reason_codes_json="$(jq -cn \
  --argjson upstream_degraded "$upstream_degraded_codes_json" \
  --argjson upstream_blocked "$upstream_blocked_codes_json" \
  --argjson upstream_fail_closed "$upstream_fail_closed_codes_json" \
  --argjson local_degraded "$local_degraded_codes_json" \
  --argjson local_blocked "$local_blocked_codes_json" \
  --argjson local_fail_closed "$local_fail_closed_codes_json" \
  --argjson missing_required_capability_task_ids "$missing_required_capability_task_ids_json" \
  --argjson toolchain_mismatch_task_ids "$toolchain_mismatch_task_ids_json" \
  --arg routing_mode "$routing_mode" \
  --arg routing_outcome_samples_status "$routing_outcome_samples_status" \
  --argjson outcome_mismatch_task_ids "$outcome_mismatch_task_ids_json" '
  (
    $upstream_degraded
    + $upstream_blocked
    + $upstream_fail_closed
    + $local_degraded
    + $local_blocked
    + $local_fail_closed
    + (if ($missing_required_capability_task_ids | length) == 0 then ["capability_coverage_confirmed"] else [] end)
    + (if ($toolchain_mismatch_task_ids | length) == 0 then ["toolchain_parity_confirmed"] else [] end)
    + (if $routing_mode == "capability_affinity_confirmed" then ["preferred_cohort_confirmed"] elif $routing_mode == "broader_cohort_fallback" then ["broader_cohort_fallback"] else [] end)
    + (if $routing_outcome_samples_status == "missing" then ["missing_optional_source"] else [] end)
    + (if ($outcome_mismatch_task_ids | length) > 0 then ["outcome_samples_observed_mismatch"] else [] end)
  ) | unique
')"

worker_input_schema_version="$(jq -r '.schema_version // "unknown"' "$worker_input_normalized")"
routing_outcome_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$routing_outcome_samples_normalized")"
append_source_row "worker_capability_toolchain_input_json" true true "$worker_input_normalized" "$worker_input_schema_version" "$input_truth_state"
append_source_row "routing_outcome_samples_json" false "$([[ "$routing_outcome_samples_status" == "provided" ]] && printf true || printf false)" "$routing_outcome_samples_normalized" "$routing_outcome_schema_version" "$routing_outcome_samples_status"

routing_advisory_id="$(
  jq -cn \
    --arg source_revision "$source_revision" \
    --arg routing_mode "$routing_mode" \
    --arg truth_state "$truth_state" \
    --arg decision "$decision" \
    --argjson advised_worker_ids "$advised_worker_ids_json" \
    --argjson required_capabilities "$required_capabilities_json" \
    --argjson required_toolchain_fingerprints "$required_toolchain_fingerprints_json" \
    '{source_revision:$source_revision,routing_mode:$routing_mode,truth_state:$truth_state,decision:$decision,advised_worker_ids:$advised_worker_ids,required_capabilities:$required_capabilities,required_toolchain_fingerprints:$required_toolchain_fingerprints}' \
    | jq -cS . | sha256sum | awk '{print "car-" substr($1,1,16)}'
)"

jq -n \
  --arg schema_version "franken-engine.capability-affinity-queue-routing-sources.v1" \
  --slurpfile source_rows "$source_rows_jsonl" \
  '{schema_version:$schema_version,source_artifacts:$source_rows}' >"$sources_path"

jq -n \
  --arg schema_version "franken-engine.capability-affinity-queue-routing-advisory.v1" \
  --arg source_schema_version "franken-engine.capability-affinity-queue-routing-sources.v1" \
  --arg routing_advisory_id "$routing_advisory_id" \
  --arg source_revision "$source_revision" \
  --arg truth_state "$truth_state" \
  --arg decision "$decision" \
  --arg routing_mode "$routing_mode" \
  --arg recommended_topology_class "$recommended_topology_class" \
  --arg advisory_path "$advisory_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --argjson task_count "$task_count" \
  --argjson preferred_worker_ids "$preferred_worker_ids_json" \
  --argjson advised_worker_ids "$advised_worker_ids_json" \
  --argjson excluded_worker_ids "$excluded_worker_ids_json" \
  --argjson watch_worker_ids "$watch_worker_ids_json" \
  --argjson rehab_candidate_worker_ids "$rehab_candidate_worker_ids_json" \
  --argjson required_capabilities "$required_capabilities_json" \
  --argjson coverage_confirmed_task_ids "$coverage_confirmed_task_ids_json" \
  --argjson missing_required_capability_task_ids "$missing_required_capability_task_ids_json" \
  --argjson required_toolchain_fingerprints "$required_toolchain_fingerprints_json" \
  --argjson toolchain_mismatch_task_ids "$toolchain_mismatch_task_ids_json" \
  --argjson broader_fallback_task_ids "$broader_fallback_task_ids_json" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson confidence_score "$confidence_score" \
  --argjson outcome_sample_count "$outcome_sample_count" \
  --argjson preferred_capability_score "$capability_coverage_score" \
  --argjson preferred_toolchain_score "$toolchain_parity_score" \
  --argjson preferred_locality_score "$preferred_locality_score" \
  --argjson preferred_rehabilitation_score "$preferred_rehabilitation_score" \
  --argjson preferred_total_score "$preferred_total_score" \
  --argjson advisory_capability_score "$capability_coverage_score" \
  --argjson advisory_toolchain_score "$toolchain_parity_score" \
  --argjson advisory_locality_score "$advisory_locality_score" \
  --argjson advisory_rehabilitation_score "$advisory_rehabilitation_score" \
  --argjson advisory_total_score "$advisory_total_score" \
  --slurpfile degraded_reasons "$degraded_reasons_jsonl" \
  --slurpfile blocked_reasons "$blocked_reasons_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --slurpfile source_rows "$source_rows_jsonl" \
  '{
    schema_version:$schema_version,
    source_schema_version:$source_schema_version,
    routing_advisory_id:$routing_advisory_id,
    source_revision:$source_revision,
    truth_state:$truth_state,
    decision:$decision,
    reason_codes:$reason_codes,
    worker_affinity_summary:{
      task_count:$task_count,
      routing_mode:$routing_mode,
      recommended_topology_class:$recommended_topology_class,
      preferred_worker_ids:$preferred_worker_ids,
      advised_worker_ids:$advised_worker_ids,
      excluded_worker_ids:$excluded_worker_ids,
      watch_worker_ids:$watch_worker_ids,
      rehab_candidate_worker_ids:$rehab_candidate_worker_ids,
      broader_fallback_task_ids:$broader_fallback_task_ids,
      preferred_cohort_score:{
        capability_coverage_score:$preferred_capability_score,
        toolchain_parity_score:$preferred_toolchain_score,
        locality_compatibility_score:$preferred_locality_score,
        rehabilitation_exclusion_score:$preferred_rehabilitation_score,
        total_score:$preferred_total_score
      },
      advisory_cohort_score:{
        capability_coverage_score:$advisory_capability_score,
        toolchain_parity_score:$advisory_toolchain_score,
        locality_compatibility_score:$advisory_locality_score,
        rehabilitation_exclusion_score:$advisory_rehabilitation_score,
        total_score:$advisory_total_score
      },
      confidence_score:$confidence_score
    },
    capability_coverage_summary:{
      required_capabilities:$required_capabilities,
      coverage_confirmed_task_ids:$coverage_confirmed_task_ids,
      missing_required_capability_task_ids:$missing_required_capability_task_ids,
      score:$preferred_capability_score
    },
    toolchain_parity_summary:{
      required_toolchain_fingerprints:$required_toolchain_fingerprints,
      toolchain_mismatch_task_ids:$toolchain_mismatch_task_ids,
      score:$preferred_toolchain_score
    },
    supporting_evidence_summary:{
      routing_outcome_samples_present:($outcome_sample_count > 0),
      routing_outcome_sample_count:$outcome_sample_count
    },
    degraded_reasons:$degraded_reasons,
    blocked_reasons:$blocked_reasons,
    fail_closed_reasons:$fail_closed_reasons,
    source_artifacts:$source_rows,
    artifact_paths:{
      advisory_json:$advisory_path,
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
  }' >"$advisory_tmp"
mv "$advisory_tmp" "$advisory_path"

{
  printf '# Capability Affinity Queue Routing Advisory\n'
  printf '\n'
  printf -- "- routing_advisory_id: \`%s\`\n" "$routing_advisory_id"
  printf -- "- truth_state: \`%s\`\n" "$truth_state"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- routing_mode: \`%s\`\n" "$routing_mode"
  printf -- "- recommended_topology_class: \`%s\`\n" "$recommended_topology_class"
  printf -- "- confidence_score: \`%s\`\n" "$confidence_score"
  printf -- "- preferred_worker_ids: \`%s\`\n" "$preferred_worker_ids_json"
  printf -- "- advised_worker_ids: \`%s\`\n" "$advised_worker_ids_json"
  printf -- "- reason_codes: \`%s\`\n" "$reason_codes_json"
  printf -- "- preferred_cohort_total_score: \`%s\`\n" "$preferred_total_score"
  printf -- "- advisory_cohort_total_score: \`%s\`\n" "$advisory_total_score"
  printf -- "- missing_required_capability_task_ids: \`%s\`\n" "$missing_required_capability_task_ids_json"
  printf -- "- toolchain_mismatch_task_ids: \`%s\`\n" "$toolchain_mismatch_task_ids_json"
  printf -- "- broader_fallback_task_ids: \`%s\`\n" "$broader_fallback_task_ids_json"
  printf -- "- routing_outcome_samples_status: \`%s\`\n" "$routing_outcome_samples_status"
} >"$summary_path"

write_event "routing.decided" "$decision" "$routing_mode" "$advisory_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
if [[ "$decision" == "blocked" ]]; then
  exit 75
fi
exit 0
