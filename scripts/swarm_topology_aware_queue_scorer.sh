#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_TOPOLOGY_AWARE_QUEUE_SCORER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-aware-queue-scorer}"
run_id="${SWARM_TOPOLOGY_AWARE_QUEUE_SCORER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_AWARE_QUEUE_SCORER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_TOPOLOGY_AWARE_QUEUE_SCORER_SOURCE_REVISION:-unknown}"
topology_queue_signal_input_json=""
proof_cache_locality_plan_json=""
queue_artifact_json=""
bottleneck_report_json=""
locality_outcome_samples_json=""
placement_adoption_history_json=""
operator_status_snapshot_json=""
resource_envelope_json=""
tail_latency_locality_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_topology_aware_queue_scorer.sh [OPTIONS]

Builds deterministic topology-aware queue advice from shipped locality queue
signals, proof-cache locality planning, queue artifacts, bottleneck truth, and
later locality outcomes. This script is fixture-fed and advisory-only. It does
not update beads, release reservations, send Agent Mail, run Cargo or RCH,
mutate remote workers, pin workers automatically, or change live queue policy.

Required:
  --topology-queue-signal-input-json FILE
  --proof-cache-locality-plan-json FILE
  --queue-artifact-json FILE
  --bottleneck-report-json FILE
  --locality-outcome-samples-json FILE

Optional:
  --placement-adoption-history-json FILE
  --operator-status-snapshot-json FILE
  --resource-envelope-json FILE
  --tail-latency-locality-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  queue_advisory_bundle.json
  queue_advisory_sources.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  advisory emitted; decision may be pass or degraded
  42 fail-closed due to malformed or contaminated evidence
  75 blocked due to contradictory locality evidence
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --topology-queue-signal-input-json)
      topology_queue_signal_input_json="${2:-}"
      shift 2
      ;;
    --proof-cache-locality-plan-json)
      proof_cache_locality_plan_json="${2:-}"
      shift 2
      ;;
    --queue-artifact-json)
      queue_artifact_json="${2:-}"
      shift 2
      ;;
    --bottleneck-report-json)
      bottleneck_report_json="${2:-}"
      shift 2
      ;;
    --locality-outcome-samples-json)
      locality_outcome_samples_json="${2:-}"
      shift 2
      ;;
    --placement-adoption-history-json)
      placement_adoption_history_json="${2:-}"
      shift 2
      ;;
    --operator-status-snapshot-json)
      operator_status_snapshot_json="${2:-}"
      shift 2
      ;;
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
      shift 2
      ;;
    --tail-latency-locality-json)
      tail_latency_locality_json="${2:-}"
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

if [[ -z "$topology_queue_signal_input_json" || -z "$proof_cache_locality_plan_json" || -z "$queue_artifact_json" || -z "$bottleneck_report_json" || -z "$locality_outcome_samples_json" ]]; then
  printf 'topology queue signal input, proof cache locality plan, queue artifact, bottleneck report, and locality outcome samples are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for topology-aware queue scoring\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for topology-aware queue scoring\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
bundle_path="${run_dir}/queue_advisory_bundle.json"
bundle_tmp="${bundle_path}.tmp"
sources_path="${run_dir}/queue_advisory_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
source_rows_jsonl="${run_dir}/source_rows.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

topology_signal_normalized="${run_dir}/topology_queue_signal_input.normalized.json"
locality_plan_normalized="${run_dir}/proof_cache_locality_plan.normalized.json"
queue_artifact_normalized="${run_dir}/queue_artifact.normalized.json"
bottleneck_report_normalized="${run_dir}/bottleneck_report.normalized.json"
locality_outcome_samples_normalized="${run_dir}/locality_outcome_samples.normalized.json"
placement_adoption_history_normalized="${run_dir}/placement_adoption_history.normalized.json"
operator_status_snapshot_normalized="${run_dir}/operator_status_snapshot.normalized.json"
resource_envelope_normalized="${run_dir}/resource_envelope.normalized.json"
tail_latency_locality_normalized="${run_dir}/tail_latency_locality.normalized.json"

printf './scripts/swarm_topology_aware_queue_scorer.sh' >"$commands_path"
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
    --arg schema_version "franken-engine.swarm-topology-aware-queue-scorer.event.v1" \
    --arg component "swarm_topology_aware_queue_scorer" \
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

normalize_required_json "$topology_queue_signal_input_json" "$topology_signal_normalized" "topology queue signal input"
normalize_required_json "$proof_cache_locality_plan_json" "$locality_plan_normalized" "proof cache locality plan"
normalize_required_json "$queue_artifact_json" "$queue_artifact_normalized" "queue artifact"
normalize_required_json "$bottleneck_report_json" "$bottleneck_report_normalized" "bottleneck report"
normalize_required_json "$locality_outcome_samples_json" "$locality_outcome_samples_normalized" "locality outcome samples"
placement_adoption_history_status="$(normalize_optional_json "$placement_adoption_history_json" "$placement_adoption_history_normalized" "placement adoption history")"
operator_status_snapshot_status="$(normalize_optional_json "$operator_status_snapshot_json" "$operator_status_snapshot_normalized" "operator status snapshot")"
resource_envelope_status="$(normalize_optional_json "$resource_envelope_json" "$resource_envelope_normalized" "resource envelope")"
tail_latency_locality_status="$(normalize_optional_json "$tail_latency_locality_json" "$tail_latency_locality_normalized" "tail latency locality")"

check_shape "$topology_signal_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.locality_context.preferred_worker_ids // null) | type == "array")
  and ((.locality_context.preferred_numa_nodes // null) | type == "array")
  and ((.rehabilitation_context.excluded_worker_ids // null) | type == "array")
  and ((.queue_signal_hints.rank_bias_mode // "") | (type == "string" and length > 0))
  and ((.queue_signal_hints.usable_preferred_worker_ids // null) | type == "array")
  and ((.source_artifacts // null) | type == "array")
  and ((.mutation_policy.advisory_only | type) == "boolean")
  and ((.mutation_policy.runs_cargo | type) == "boolean")
  and ((.mutation_policy.runs_rch | type) == "boolean")
' "topology_queue_signal_input_json" "topology queue signal input lacks required locality or mutation-policy fields"

check_shape "$locality_plan_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.recommendations // null) | type == "array")
  and ((.topology_summary.recommended_topology_class // "") | (type == "string" and length > 0))
  and ((.proof_cache_summary.proof_cache_decision // "") | (type == "string" and length > 0))
  and ((.mutation_policy.advisory_only | type) == "boolean")
  and ((.mutation_policy.runs_cargo | type) == "boolean")
  and ((.mutation_policy.runs_rch | type) == "boolean")
' "proof_cache_locality_plan_json" "proof cache locality plan lacks required recommendation or mutation-policy fields"

check_shape "$queue_artifact_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and (((.queue_artifact.queue // .queue // null)) | type == "array")
' "queue_artifact_json" "queue artifact lacks queue rows"

check_shape "$bottleneck_report_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
' "bottleneck_report_json" "bottleneck report lacks schema version"

check_shape "$locality_outcome_samples_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.samples // null) | type == "array")
  and all(.samples[]?; ((.task_id // "") | type == "string" and length > 0) and ((.observed_outcome // "") | type == "string" and length > 0))
' "locality_outcome_samples_json" "locality outcome samples lack required task or outcome fields"

topology_decision="$(jq -r '.decision // "unknown"' "$topology_signal_normalized")"
topology_truth_state="$(jq -r '.truth_state // "unknown"' "$topology_signal_normalized")"
rank_bias_mode="$(jq -r '.queue_signal_hints.rank_bias_mode // "portable_fallback"' "$topology_signal_normalized")"
proof_transport_state="$(jq -r '.queue_context.proof_transport_state // "unknown"' "$topology_signal_normalized")"
task_count="$(jq '.queue_context.task_count // 0' "$topology_signal_normalized")"
validation_commands_json="$(jq -c '.queue_context.validation_commands // []' "$topology_signal_normalized")"
preferred_worker_ids_json="$(jq -c '.locality_context.preferred_worker_ids // []' "$topology_signal_normalized")"
usable_preferred_worker_ids_json="$(jq -c '.queue_signal_hints.usable_preferred_worker_ids // []' "$topology_signal_normalized")"
preferred_numa_nodes_json="$(jq -c '.locality_context.preferred_numa_nodes // []' "$topology_signal_normalized")"
excluded_worker_ids_json="$(jq -c '.rehabilitation_context.excluded_worker_ids // []' "$topology_signal_normalized")"
hot_cache_reuse_confidence_millionths="$(jq '.queue_signal_hints.hot_cache_reuse_confidence_millionths // 0' "$topology_signal_normalized")"
locality_confidence_millionths="$(jq '.queue_signal_hints.locality_confidence_millionths // 0' "$topology_signal_normalized")"
locality_plan_decision="$(jq -r '.decision // "unknown"' "$locality_plan_normalized")"
plan_worker_id="$(jq -r '.worker_id // empty' "$locality_plan_normalized")"
plan_target_dir="$(jq -r '.target_dir // empty' "$locality_plan_normalized")"
recommended_topology_class="$(jq -r '.topology_summary.recommended_topology_class // .locality_context.recommended_topology_class // "unknown"' "$locality_plan_normalized")"
warm_cache_residency_state="$(jq -r '.topology_summary.warm_cache_residency_state // "unknown"' "$locality_plan_normalized")"
proof_cache_decision="$(jq -r '.proof_cache_summary.proof_cache_decision // "unknown"' "$locality_plan_normalized")"
locality_plan_action="$(jq -r '.recommendations[0].action // "none"' "$locality_plan_normalized")"
resource_memory_available_bytes="$(jq -r '.memory_pressure.available_bytes // .capacity_budget.memory_available_bytes // empty' "$resource_envelope_normalized")"
queue_row_count="$(jq '((.queue_artifact.queue // .queue // []) | length)' "$queue_artifact_normalized")"
bottleneck_count="$(jq '(.bottleneck_count // (.bottlenecks | length) // (.bottleneck_ids | length) // 0)' "$bottleneck_report_normalized")"
critical_bottleneck_count="$(jq '(.critical_bottleneck_count // 0)' "$bottleneck_report_normalized")"
risk_remaining_millionths="$(jq '(.queue_artifact.risk_budget.remaining_millionths // .risk_budget.remaining_millionths // 0)' "$queue_artifact_normalized")"
risk_consumed_millionths="$(jq '(.queue_artifact.risk_budget.consumed_millionths // .risk_budget.consumed_millionths // 0)' "$queue_artifact_normalized")"
risk_conservative_mode="$(jq -r '(.queue_artifact.risk_budget.conservative_mode // .risk_budget.conservative_mode // false)' "$queue_artifact_normalized")"

confirmed_task_ids_json="$(jq -c '[.samples[]? | select((.observed_outcome // "") == "hot_cache_reuse_confirmed") | .task_id] | unique' "$locality_outcome_samples_normalized")"
missed_task_ids_json="$(jq -c '[.samples[]? | select((.observed_outcome // "") == "cache_reuse_missed") | .task_id] | unique' "$locality_outcome_samples_normalized")"
drift_task_ids_json="$(jq -c '[.samples[]? | select((.observed_outcome // "") == "locality_drift_observed") | .task_id] | unique' "$locality_outcome_samples_normalized")"
contamination_task_ids_json="$(jq -c '[.samples[]? | select((.observed_outcome // "") == "local_fallback_contaminated") | .task_id] | unique' "$locality_outcome_samples_normalized")"
drained_avoided_task_ids_json="$(jq -c '[.samples[]? | select((.observed_outcome // "") == "drained_worker_avoided") | .task_id] | unique' "$locality_outcome_samples_normalized")"
probe_avoided_task_ids_json="$(jq -c '[.samples[]? | select((.observed_outcome // "") == "probe_required_worker_avoided") | .task_id] | unique' "$locality_outcome_samples_normalized")"

if jq -e '((.mutation_policy.runs_cargo // false) or (.mutation_policy.runs_rch // false) or (.mutation_policy.mutates_remote_workers // false) or (.mutation_policy.changes_live_queue_policy // false) or (.mutation_policy.pins_workers_automatically // false))' "$topology_signal_normalized" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "unsafe_mutation_policy" "topology_queue_signal_input_json" "topology queue signal input claims live mutation or heavy execution authority"
fi
if jq -e '((.mutation_policy.runs_cargo // false) or (.mutation_policy.runs_rch // false) or (.mutation_policy.mutates_remote_workers // false) or (.mutation_policy.changes_live_queue_policy // false) or (.mutation_policy.pins_workers_automatically // false))' "$locality_plan_normalized" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "unsafe_mutation_policy" "proof_cache_locality_plan_json" "proof cache locality plan claims live mutation or heavy execution authority"
fi
if jq -e '
  (.queue_context.validation_commands // [])
  | any(.[]?; (type != "string") or (contains("rch exec --") | not) or (contains("CARGO_TARGET_DIR=") | not))
' "$topology_signal_normalized" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "unsafe_command_broadening" "topology_queue_signal_input_json" "validation commands must preserve rch exec -- env and explicit CARGO_TARGET_DIR policy"
fi

if [[ "$topology_decision" == "fail_closed" || "$topology_truth_state" == "contaminated" || "$rank_bias_mode" == "fail_closed" || "$proof_transport_state" == "local_fallback_detected" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "topology_queue_signal_input_json" "topology queue signal input records local fallback contamination"
fi
if [[ "$locality_plan_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "proof_cache_locality_plan_json" "proof cache locality plan is already fail-closed"
fi
if jq -e 'length > 0' <<<"$contamination_task_ids_json" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "locality_outcome_samples_json" "locality outcome samples record local fallback contamination"
fi

if [[ "$topology_decision" == "blocked" || "$topology_truth_state" == "blocked" || "$rank_bias_mode" == "blocked_contradictory_locality" || "$locality_plan_decision" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_locality" "topology_queue_signal_input_json" "topology queue signal or locality plan blocks confident locality advice"
fi
if jq -e 'length > 0' <<<"$drift_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "contradictory_locality" "locality_outcome_samples_json" "locality outcome samples record contradictory execution paths"
fi
if [[ -n "$resource_memory_available_bytes" && "$resource_memory_available_bytes" -lt 68719476736 ]]; then
  append_reason "$blocked_reasons_jsonl" "memory_headroom_too_low" "resource_envelope_json" "resource envelope reports less than 64 GiB available memory for topology-aware proof admission"
fi

if [[ "$topology_decision" == "degraded" || "$topology_truth_state" == "degraded" || "$locality_plan_decision" == "degraded" || "$placement_adoption_history_status" == "missing" || "$operator_status_snapshot_status" == "missing" || "$resource_envelope_status" == "missing" || "$tail_latency_locality_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "telemetry_gap" "optional_support" "optional support evidence is missing or upstream locality evidence is degraded"
fi
if [[ -z "$plan_target_dir" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_target_dir_evidence" "proof_cache_locality_plan_json" "proof cache locality plan did not select a target directory"
fi
if jq -e 'length > 0' <<<"$missed_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "cache_reuse_outcome_missed" "locality_outcome_samples_json" "locality outcome samples record missed cache reuse"
fi
if jq -e 'length > 0' <<<"$confirmed_task_ids_json" >/dev/null && [[ "$rank_bias_mode" == "prefer_hot_cache_locality" ]]; then
  :
fi
if jq -e 'length > 0' <<<"$excluded_worker_ids_json" >/dev/null || jq -e 'length > 0' <<<"$drained_avoided_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "drained_worker_excluded" "topology_queue_signal_input_json" "drained or probe-required workers were excluded from preferred locality advice"
fi
if jq -e 'length > 0' <<<"$probe_avoided_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "probe_required_worker_excluded" "locality_outcome_samples_json" "probe-required workers were excluded from preferred locality advice"
fi

queue_artifact_schema_version="$(jq -r '.schema_version // "unknown"' "$queue_artifact_normalized")"
bottleneck_report_schema_version="$(jq -r '.schema_version // "unknown"' "$bottleneck_report_normalized")"
locality_outcome_schema_version="$(jq -r '.schema_version // "unknown"' "$locality_outcome_samples_normalized")"

jq -c '.source_artifacts // [] | .[]' "$topology_signal_normalized" >>"$source_rows_jsonl"
append_source_row "topology_queue_signal_input_json" true true "$topology_queue_signal_input_json" "$(jq -r '.schema_version // "unknown"' "$topology_signal_normalized")" "$topology_truth_state"
append_source_row "proof_cache_locality_plan_json" true true "$proof_cache_locality_plan_json" "$(jq -r '.schema_version // "unknown"' "$locality_plan_normalized")" "$locality_plan_decision"
append_source_row "queue_artifact_json" true true "$queue_artifact_json" "$queue_artifact_schema_version" "provided"
append_source_row "bottleneck_report_json" true true "$bottleneck_report_json" "$bottleneck_report_schema_version" "provided"
append_source_row "locality_outcome_samples_json" true true "$locality_outcome_samples_json" "$locality_outcome_schema_version" "provided"
append_source_row "placement_adoption_history_json" false "$([[ "$placement_adoption_history_status" == "provided" ]] && printf true || printf false)" "$placement_adoption_history_normalized" "$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$placement_adoption_history_normalized")" "$placement_adoption_history_status"
append_source_row "operator_status_snapshot_json" false "$([[ "$operator_status_snapshot_status" == "provided" ]] && printf true || printf false)" "$operator_status_snapshot_normalized" "$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$operator_status_snapshot_normalized")" "$operator_status_snapshot_status"
append_source_row "resource_envelope_json" false "$([[ "$resource_envelope_status" == "provided" ]] && printf true || printf false)" "$resource_envelope_normalized" "$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$resource_envelope_normalized")" "$resource_envelope_status"
append_source_row "tail_latency_locality_json" false "$([[ "$tail_latency_locality_status" == "provided" ]] && printf true || printf false)" "$tail_latency_locality_normalized" "$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$tail_latency_locality_normalized")" "$tail_latency_locality_status"

decision="pass"
truth_state="confirmed"
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="contaminated"
elif [[ -s "$blocked_reasons_jsonl" ]]; then
  decision="blocked"
  truth_state="blocked"
elif [[ -s "$degraded_reasons_jsonl" ]]; then
  decision="degraded"
  truth_state="degraded"
fi
admission_decision="admit"
case "$decision" in
  degraded)
    admission_decision="narrow"
    ;;
  blocked)
    admission_decision="defer"
    ;;
  fail_closed)
    admission_decision="fail_closed"
    ;;
esac

reason_codes_json="$(jq -nc \
  --arg rank_bias_mode "$rank_bias_mode" \
  --argjson excluded_worker_ids "$excluded_worker_ids_json" \
  --argjson confirmed_task_ids "$confirmed_task_ids_json" \
  --argjson missed_task_ids "$missed_task_ids_json" \
  --argjson drained_avoided_task_ids "$drained_avoided_task_ids_json" \
  --argjson probe_avoided_task_ids "$probe_avoided_task_ids_json" \
  --slurpfile degraded "$degraded_reasons_jsonl" \
  --slurpfile blocked "$blocked_reasons_jsonl" \
  --slurpfile failclosed "$fail_closed_reasons_jsonl" '
  (
    ($degraded[0:] | map(.code))
    + ($blocked[0:] | map(.code))
    + ($failclosed[0:] | map(.code))
    + (if $rank_bias_mode == "prefer_hot_cache_locality" then ["hot_cache_reuse_preferred"] else [] end)
    + (if $rank_bias_mode == "prefer_numa_locality" then ["numa_locality_preferred"] else [] end)
    + (if ($confirmed_task_ids | length) > 0 then ["cache_reuse_outcome_confirmed"] else [] end)
    + (if ($missed_task_ids | length) > 0 then ["cache_reuse_outcome_missed"] else [] end)
    + (if (($excluded_worker_ids | length) > 0 or ($drained_avoided_task_ids | length) > 0) then ["drained_worker_excluded"] else [] end)
    + (if ($probe_avoided_task_ids | length) > 0 then ["probe_required_worker_excluded"] else [] end)
  ) | unique | sort
')"

queue_advisory_id="$(
  jq -cn \
    --arg source_revision "$source_revision" \
    --arg decision "$decision" \
    --arg truth_state "$truth_state" \
    --argjson reason_codes "$reason_codes_json" \
    --argjson preferred_worker_ids "$usable_preferred_worker_ids_json" \
    --arg rank_bias_mode "$rank_bias_mode" \
    '{source_revision:$source_revision,decision:$decision,truth_state:$truth_state,reason_codes:$reason_codes,preferred_worker_ids:$preferred_worker_ids,rank_bias_mode:$rank_bias_mode}' \
    | jq -cS . | sha256sum | awk '{print "tqa-" substr($1,1,16)}'
)"

jq -n \
  --arg schema_version "franken-engine.swarm-topology-aware-queue-advisory-sources.v1" \
  --slurpfile source_rows "$source_rows_jsonl" \
  '{schema_version:$schema_version,source_artifacts:$source_rows}' >"$sources_path"

jq -n \
  --arg schema_version "franken-engine.swarm-topology-aware-queue-advisory.v1" \
  --arg source_schema_version "franken-engine.swarm-topology-aware-queue-advisory-sources.v1" \
  --arg queue_advisory_id "$queue_advisory_id" \
  --arg source_revision "$source_revision" \
  --arg truth_state "$truth_state" \
  --arg decision "$decision" \
  --arg admission_decision "$admission_decision" \
  --arg rank_bias_mode "$rank_bias_mode" \
  --arg plan_worker_id "$plan_worker_id" \
  --arg plan_target_dir "$plan_target_dir" \
  --arg recommended_topology_class "$recommended_topology_class" \
  --arg warm_cache_residency_state "$warm_cache_residency_state" \
  --arg proof_cache_decision "$proof_cache_decision" \
  --arg locality_plan_action "$locality_plan_action" \
  --arg proof_transport_state "$proof_transport_state" \
  --arg bundle_path "$bundle_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --argjson preferred_worker_ids "$preferred_worker_ids_json" \
  --argjson usable_preferred_worker_ids "$usable_preferred_worker_ids_json" \
  --argjson preferred_numa_nodes "$preferred_numa_nodes_json" \
  --argjson excluded_worker_ids "$excluded_worker_ids_json" \
  --argjson validation_commands "$validation_commands_json" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson confirmed_task_ids "$confirmed_task_ids_json" \
  --argjson missed_task_ids "$missed_task_ids_json" \
  --argjson drift_task_ids "$drift_task_ids_json" \
  --argjson contamination_task_ids "$contamination_task_ids_json" \
  --argjson drained_avoided_task_ids "$drained_avoided_task_ids_json" \
  --argjson probe_avoided_task_ids "$probe_avoided_task_ids_json" \
  --argjson task_count "$task_count" \
  --argjson queue_row_count "$queue_row_count" \
  --argjson bottleneck_count "$bottleneck_count" \
  --argjson critical_bottleneck_count "$critical_bottleneck_count" \
  --argjson risk_remaining_millionths "$risk_remaining_millionths" \
  --argjson risk_consumed_millionths "$risk_consumed_millionths" \
  --argjson risk_conservative_mode "$risk_conservative_mode" \
  --argjson hot_cache_reuse_confidence_millionths "$hot_cache_reuse_confidence_millionths" \
  --argjson locality_confidence_millionths "$locality_confidence_millionths" \
  --slurpfile degraded_reasons "$degraded_reasons_jsonl" \
  --slurpfile blocked_reasons "$blocked_reasons_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --slurpfile source_rows "$source_rows_jsonl" '
  {
    schema_version:$schema_version,
    source_schema_version:$source_schema_version,
    queue_advisory_id:$queue_advisory_id,
    source_revision:$source_revision,
    truth_state:$truth_state,
    decision:$decision,
    admission_decision:$admission_decision,
    reason_codes:$reason_codes,
    worker_exclusions:{
      excluded_worker_ids:$excluded_worker_ids,
      excluded_worker_count:($excluded_worker_ids | length),
      drained_avoided_task_ids:$drained_avoided_task_ids,
      probe_avoided_task_ids:$probe_avoided_task_ids
    },
    locality_bias_summary:{
      rank_bias_mode:$rank_bias_mode,
      preferred_worker_ids:$preferred_worker_ids,
      usable_preferred_worker_ids:$usable_preferred_worker_ids,
      preferred_numa_nodes:$preferred_numa_nodes,
      advised_worker_id:($plan_worker_id | if . == "" then null else . end),
      advised_target_dir:($plan_target_dir | if . == "" then null else . end),
      recommended_topology_class:$recommended_topology_class,
      warm_cache_residency_state:$warm_cache_residency_state,
      proof_cache_decision:$proof_cache_decision,
      locality_plan_action:$locality_plan_action,
      hot_cache_reuse_confidence_millionths:$hot_cache_reuse_confidence_millionths,
      locality_confidence_millionths:$locality_confidence_millionths
    },
    risk_budget_summary:{
      task_count:$task_count,
      queue_row_count:$queue_row_count,
      bottleneck_count:$bottleneck_count,
      critical_bottleneck_count:$critical_bottleneck_count,
      risk_budget:{
        remaining_millionths:$risk_remaining_millionths,
        consumed_millionths:$risk_consumed_millionths,
        conservative_mode:$risk_conservative_mode
      },
      queue_risk_budget_state:(if $risk_conservative_mode then "conservative" else "normal" end),
      proof_transport_state:$proof_transport_state
    },
    selected_command_policy:{
      selected_commands:$validation_commands,
      command_count:($validation_commands | length),
      requires_rch_exec_env:true,
      requires_cargo_target_dir:true,
      preserves_validation_planner_commands:true,
      runs_selected_commands:false,
      unsafe_broadening_fail_closed:true
    },
    feedback_summary:{
      locality_outcome_sample_count:($confirmed_task_ids | length) + ($missed_task_ids | length) + ($drift_task_ids | length) + ($contamination_task_ids | length) + ($drained_avoided_task_ids | length) + ($probe_avoided_task_ids | length),
      confirmed_task_ids:$confirmed_task_ids,
      missed_cache_reuse_task_ids:$missed_task_ids,
      drift_task_ids:$drift_task_ids,
      contamination_task_ids:$contamination_task_ids
    },
    degraded_reasons:$degraded_reasons,
    blocked_reasons:$blocked_reasons,
    fail_closed_reasons:$fail_closed_reasons,
    source_artifacts:$source_rows,
    artifact_paths:{
      advisory_bundle_json:$bundle_path,
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
      pins_workers_automatically:false
    }
  }' >"$bundle_tmp"
mv "$bundle_tmp" "$bundle_path"

{
  printf '# Topology Aware Queue Advisory\n'
  printf '\n'
  printf -- "- queue_advisory_id: \`%s\`\n" "$queue_advisory_id"
  printf -- "- truth_state: \`%s\`\n" "$truth_state"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- admission_decision: \`%s\`\n" "$admission_decision"
  printf -- "- rank_bias_mode: \`%s\`\n" "$rank_bias_mode"
  printf -- "- advised_worker_id: \`%s\`\n" "${plan_worker_id:-none}"
  printf -- "- recommended_topology_class: \`%s\`\n" "$recommended_topology_class"
  printf -- "- reason_codes: \`%s\`\n" "$reason_codes_json"
  printf -- "- excluded_worker_ids: \`%s\`\n" "$excluded_worker_ids_json"
} >"$summary_path"

write_event "queue_advisory.emitted" "$decision" "$rank_bias_mode" "$bundle_path"

case "$decision" in
  fail_closed)
    exit 42
    ;;
  blocked)
    exit 75
    ;;
  *)
    exit 0
    ;;
esac
