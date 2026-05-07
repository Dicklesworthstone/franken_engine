#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-aware-queue-fidelity-ledger}"
run_id="${SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER_SOURCE_REVISION:-unknown}"
queue_advisory_bundle_json=""
placement_evidence_ledger_json=""
queue_artifact_json=""
bottleneck_report_json=""
locality_outcome_samples_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_topology_aware_queue_fidelity_ledger.sh [OPTIONS]

Compares the topology-aware queue advisory against the emitted queue artifact,
bottleneck report, placement evidence ledger, and later locality outcomes. This
script is fixture-fed and advisory-only. It does not update beads, release
reservations, send Agent Mail, run Cargo or RCH, mutate remote workers, pin
workers automatically, or change live queue policy.

Required:
  --queue-advisory-bundle-json FILE
  --placement-evidence-ledger-json FILE
  --queue-artifact-json FILE
  --bottleneck-report-json FILE
  --locality-outcome-samples-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_topology_aware_queue_fidelity_receipt.json
  swarm_topology_aware_queue_drift_ledger.json
  swarm_topology_aware_queue_fidelity_sources.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  ledger emitted; decision may be pass or degraded
  42 fail-closed due to malformed or contaminated evidence
  75 blocked due to contradictory locality or placement evidence
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --queue-advisory-bundle-json)
      queue_advisory_bundle_json="${2:-}"
      shift 2
      ;;
    --placement-evidence-ledger-json)
      placement_evidence_ledger_json="${2:-}"
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

if [[ -z "$queue_advisory_bundle_json" || -z "$placement_evidence_ledger_json" || -z "$queue_artifact_json" || -z "$bottleneck_report_json" || -z "$locality_outcome_samples_json" ]]; then
  printf 'queue advisory, placement evidence ledger, queue artifact, bottleneck report, and locality outcome samples are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for topology-aware queue fidelity ledgers\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for topology-aware queue fidelity ledgers\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
receipt_path="${run_dir}/swarm_topology_aware_queue_fidelity_receipt.json"
receipt_tmp="${receipt_path}.tmp"
drift_ledger_path="${run_dir}/swarm_topology_aware_queue_drift_ledger.json"
drift_ledger_tmp="${drift_ledger_path}.tmp"
sources_path="${run_dir}/swarm_topology_aware_queue_fidelity_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
source_rows_jsonl="${run_dir}/source_rows.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"
task_outcomes_json="${run_dir}/task_outcomes.json"

queue_advisory_normalized="${run_dir}/queue_advisory_bundle.normalized.json"
placement_evidence_normalized="${run_dir}/placement_evidence_ledger.normalized.json"
queue_artifact_normalized="${run_dir}/queue_artifact.normalized.json"
bottleneck_report_normalized="${run_dir}/bottleneck_report.normalized.json"
locality_outcome_samples_normalized="${run_dir}/locality_outcome_samples.normalized.json"

printf './scripts/swarm_topology_aware_queue_fidelity_ledger.sh' >"$commands_path"
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
    --arg schema_version "franken-engine.swarm-topology-aware-queue-fidelity-ledger.event.v1" \
    --arg component "swarm_topology_aware_queue_fidelity_ledger" \
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

normalize_required_json "$queue_advisory_bundle_json" "$queue_advisory_normalized" "queue advisory bundle"
normalize_required_json "$placement_evidence_ledger_json" "$placement_evidence_normalized" "placement evidence ledger"
normalize_required_json "$queue_artifact_json" "$queue_artifact_normalized" "queue artifact"
normalize_required_json "$bottleneck_report_json" "$bottleneck_report_normalized" "bottleneck report"
normalize_required_json "$locality_outcome_samples_json" "$locality_outcome_samples_normalized" "locality outcome samples"

check_shape "$queue_advisory_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.reason_codes // null) | type == "array")
  and ((.worker_exclusions.excluded_worker_ids // null) | type == "array")
  and ((.locality_bias_summary.rank_bias_mode // "") | (type == "string" and length > 0))
  and ((.locality_bias_summary.preferred_worker_ids // null) | type == "array")
  and ((.locality_bias_summary.usable_preferred_worker_ids // null) | type == "array")
  and ((.locality_bias_summary.preferred_numa_nodes // null) | type == "array")
  and ((.mutation_policy.advisory_only | type) == "boolean")
  and ((.mutation_policy.runs_cargo | type) == "boolean")
  and ((.mutation_policy.runs_rch | type) == "boolean")
' "queue_advisory_bundle_json" "queue advisory bundle lacks required truth, locality, or mutation-policy fields"

check_shape "$placement_evidence_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.adoption_history // null) | type == "array")
  and ((.mutation_policy.advisory_only | type) == "boolean")
  and ((.mutation_policy.runs_cargo | type) == "boolean")
  and ((.mutation_policy.runs_rch | type) == "boolean")
' "placement_evidence_ledger_json" "placement evidence ledger lacks required adoption history or mutation-policy fields"

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
  and all(.samples[]?;
    ((.task_id // "") | (type == "string" and length > 0))
    and ((.observed_worker_id // "") | (type == "string" and length > 0))
    and ((.observed_outcome // "") | (type == "string" and length > 0))
  )
' "locality_outcome_samples_json" "locality outcome samples lack required task, worker, or outcome fields"

advisory_decision="$(jq -r '.decision // "unknown"' "$queue_advisory_normalized")"
advisory_truth_state="$(jq -r '.truth_state // "unknown"' "$queue_advisory_normalized")"
rank_bias_mode="$(jq -r '.locality_bias_summary.rank_bias_mode // "portable_fallback"' "$queue_advisory_normalized")"
warm_cache_residency_state="$(jq -r '.locality_bias_summary.warm_cache_residency_state // "unknown"' "$queue_advisory_normalized")"
recommended_topology_class="$(jq -r '.locality_bias_summary.recommended_topology_class // "unknown"' "$queue_advisory_normalized")"
preferred_worker_ids_json="$(jq -c '.locality_bias_summary.usable_preferred_worker_ids // .locality_bias_summary.preferred_worker_ids // []' "$queue_advisory_normalized")"
placement_decision="$(jq -r '.decision // "unknown"' "$placement_evidence_normalized")"
placement_adoption_status="$(jq -r '.adoption_history[0].adoption_status // .receipts[0].adoption_status // "unknown"' "$placement_evidence_normalized")"
placement_expected_worker_ids_json="$(jq -c '.adoption_history[0].expected_worker_ids // .receipts[0].recommended_worker_ids // []' "$placement_evidence_normalized")"
placement_observed_worker_ids_json="$(jq -c '.adoption_history[0].observed.worker_ids // .receipts[0].adoption_observation.worker_ids // []' "$placement_evidence_normalized")"
placement_observation_present_json="$(jq '((.adoption_history[0].observed // .receipts[0].adoption_observation // null) != null)' "$placement_evidence_normalized")"
queue_task_ids_json="$(jq -c '((.queue_artifact.queue // .queue // []) | map(.task_id // .id // .bead_id // empty | tostring) | map(select(length > 0)) | unique)' "$queue_artifact_normalized")"
queue_task_count="$(jq '((.queue_artifact.queue // .queue // []) | map(.task_id // .id // .bead_id // empty | tostring) | map(select(length > 0)) | unique | length)' "$queue_artifact_normalized")"
bottleneck_task_ids_json="$(jq -c '((.bottlenecks // []) | map(.task_id // .id // .bead_id // empty | tostring) | map(select(length > 0)) | unique)' "$bottleneck_report_normalized")"
critical_bottleneck_count="$(jq '(.critical_bottleneck_count // 0)' "$bottleneck_report_normalized")"
duplicate_sample_task_ids_json="$(jq -c '[.samples[]? | .task_id | select(type == "string" and length > 0)] | sort | group_by(.) | map(select(length > 1) | .[0])' "$locality_outcome_samples_normalized")"
unknown_sample_task_ids_json="$(jq -c --argjson queue_task_ids "$queue_task_ids_json" '[.samples[]? | (.task_id // empty | tostring) | select(length > 0) | select($queue_task_ids | index(.) == null)] | unique' "$locality_outcome_samples_normalized")"

if jq -e '((.mutation_policy.runs_cargo // false) or (.mutation_policy.runs_rch // false) or (.mutation_policy.mutates_remote_workers // false) or (.mutation_policy.changes_live_queue_policy // false) or (.mutation_policy.pins_workers_automatically // false))' "$queue_advisory_normalized" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "unsafe_mutation_policy" "queue_advisory_bundle_json" "queue advisory claims live mutation or heavy execution authority"
fi
if jq -e '((.mutation_policy.runs_cargo // false) or (.mutation_policy.runs_rch // false) or (.mutation_policy.mutates_remote_workers // false) or (.mutation_policy.changes_live_queue_policy // false) or (.mutation_policy.pins_workers_automatically // false))' "$placement_evidence_normalized" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "unsafe_mutation_policy" "placement_evidence_ledger_json" "placement evidence ledger claims live mutation or heavy execution authority"
fi
if [[ "$advisory_decision" == "fail_closed" || "$advisory_truth_state" == "contaminated" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "queue_advisory_bundle_json" "queue advisory already records contaminated locality truth"
fi
if [[ "$placement_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "placement_evidence_ledger_json" "placement evidence ledger is already fail-closed"
fi
if jq -e 'length > 0' <<<"$duplicate_sample_task_ids_json" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "malformed_required_shape" "locality_outcome_samples_json" "locality outcome samples contain duplicate task ids"
fi
if jq -e 'length > 0' <<<"$unknown_sample_task_ids_json" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "unknown_task_reference" "locality_outcome_samples_json" "locality outcome samples reference tasks absent from the queue artifact"
fi

jq -n \
  --slurpfile advisory "$queue_advisory_normalized" \
  --slurpfile placement "$placement_evidence_normalized" \
  --slurpfile queue_doc "$queue_artifact_normalized" \
  --slurpfile bottleneck_doc "$bottleneck_report_normalized" \
  --slurpfile outcomes_doc "$locality_outcome_samples_normalized" '
  def queue_task_id:
    (.task_id // .id // .bead_id // empty) | tostring;

  ($advisory[0]) as $a
  | ($placement[0]) as $p
  | (($queue_doc[0].queue_artifact.queue // $queue_doc[0].queue // [])) as $queue_rows
  | (($bottleneck_doc[0].bottlenecks // []) | map(queue_task_id) | map(select(length > 0)) | unique) as $bottleneck_ids
  | (($outcomes_doc[0].samples // [])) as $samples
  | (($a.locality_bias_summary.usable_preferred_worker_ids // $a.locality_bias_summary.preferred_worker_ids // [])) as $preferred_worker_ids
  | (($a.locality_bias_summary.preferred_numa_nodes // [])) as $preferred_numa_nodes
  | (($a.worker_exclusions.excluded_worker_ids // [])) as $excluded_worker_ids
  | (($a.locality_bias_summary.warm_cache_residency_state // "unknown")) as $warm_cache_state
  | (($a.locality_bias_summary.rank_bias_mode // "portable_fallback")) as $rank_bias_mode
  | (($p.adoption_history[0].expected_worker_ids // $p.receipts[0].recommended_worker_ids // [])) as $placement_expected_worker_ids
  | (($p.adoption_history[0].observed.worker_ids // $p.receipts[0].adoption_observation.worker_ids // [])) as $placement_observed_worker_ids
  | (($queue_rows | map(queue_task_id) | map(select(length > 0)) | unique)) as $queue_task_ids
  | [
      $queue_task_ids[] as $task_id
      | (($queue_rows[] | select((queue_task_id) == $task_id))) as $queue_row
      | ($samples | map(select(((.task_id // empty) | tostring) == $task_id))) as $task_samples
      | if ($task_samples | length) == 0 then
          {
            task_id: $task_id,
            queue_rank: ($queue_row.rank // null),
            recommended_first_action: ($queue_row.first_action // null),
            advised_worker_ids: $preferred_worker_ids,
            advised_numa_nodes: $preferred_numa_nodes,
            excluded_worker_ids: $excluded_worker_ids,
            placement_expected_worker_ids: $placement_expected_worker_ids,
            placement_observed_worker_ids: $placement_observed_worker_ids,
            observed_worker_id: null,
            observed_numa_node: null,
            observed_outcome: "missing",
            bottlenecked: ($bottleneck_ids | index($task_id) != null),
            outcome_classification: "missing_outcome_evidence"
          }
        else
          ($task_samples[0]) as $sample
          | {
              task_id: $task_id,
              queue_rank: ($queue_row.rank // null),
              recommended_first_action: ($queue_row.first_action // null),
              advised_worker_ids: $preferred_worker_ids,
              advised_numa_nodes: $preferred_numa_nodes,
              excluded_worker_ids: $excluded_worker_ids,
              placement_expected_worker_ids: $placement_expected_worker_ids,
              placement_observed_worker_ids: $placement_observed_worker_ids,
              observed_worker_id: ($sample.observed_worker_id // null),
              observed_numa_node: ($sample.observed_numa_node // null),
              observed_outcome: ($sample.observed_outcome // "unknown"),
              bottlenecked: ($bottleneck_ids | index($task_id) != null),
              outcome_classification:
                if ($sample.observed_outcome // "") == "local_fallback_contaminated" then "contaminated_local_fallback"
                elif ($excluded_worker_ids | index($sample.observed_worker_id // "")) != null then "observed_excluded_worker_used"
                elif ($sample.observed_outcome // "") == "locality_drift_observed" then "locality_drift"
                elif ($sample.observed_outcome // "") == "drained_worker_avoided" then "drained_worker_avoidance_confirmed"
                elif ($sample.observed_outcome // "") == "probe_required_worker_avoided" then "probe_required_worker_avoidance_confirmed"
                elif ($sample.observed_outcome // "") == "cache_reuse_missed" then
                  if ($warm_cache_state == "hot" or $warm_cache_state == "warm" or $rank_bias_mode == "prefer_hot_cache_locality") then "cache_reuse_missed" else "cache_cold_no_reuse_credit" end
                elif ($sample.observed_outcome // "") == "hot_cache_reuse_confirmed" then
                  if (($preferred_worker_ids | index($sample.observed_worker_id // "")) != null or ($preferred_numa_nodes | index($sample.observed_numa_node)) != null) then "matched_locality_advisory" else "unexpected_hot_cache_reuse" end
                elif (($preferred_worker_ids | length) == 0 and ($excluded_worker_ids | index($sample.observed_worker_id // "")) == null) then "matched_locality_advisory"
                elif (($preferred_worker_ids | index($sample.observed_worker_id // "")) != null or ($preferred_numa_nodes | index($sample.observed_numa_node)) != null) then "matched_locality_advisory"
                else "observed_locality_unclassified"
                end
            }
        end
    ]' >"$task_outcomes_json"

matched_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "matched_locality_advisory" or .outcome_classification == "cache_cold_no_reuse_credit") | .task_id] | unique' "$task_outcomes_json")"
cache_cold_no_reuse_credit_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "cache_cold_no_reuse_credit") | .task_id] | unique' "$task_outcomes_json")"
cache_reuse_confirmed_task_ids_json="$(jq -c '[.[] | select(.observed_outcome == "hot_cache_reuse_confirmed") | .task_id] | unique' "$task_outcomes_json")"
cache_reuse_missed_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "cache_reuse_missed") | .task_id] | unique' "$task_outcomes_json")"
locality_drift_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "locality_drift") | .task_id] | unique' "$task_outcomes_json")"
drained_worker_avoidance_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "drained_worker_avoidance_confirmed") | .task_id] | unique' "$task_outcomes_json")"
probe_required_worker_avoidance_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "probe_required_worker_avoidance_confirmed") | .task_id] | unique' "$task_outcomes_json")"
excluded_worker_violation_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "observed_excluded_worker_used") | .task_id] | unique' "$task_outcomes_json")"
missing_outcome_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "missing_outcome_evidence") | .task_id] | unique' "$task_outcomes_json")"
contamination_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "contaminated_local_fallback") | .task_id] | unique' "$task_outcomes_json")"
unexpected_hot_cache_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "unexpected_hot_cache_reuse") | .task_id] | unique' "$task_outcomes_json")"
unclassified_task_ids_json="$(jq -c '[.[] | select(.outcome_classification == "observed_locality_unclassified") | .task_id] | unique' "$task_outcomes_json")"
sampled_task_count="$(jq 'map(select(.observed_outcome != "missing")) | length' "$task_outcomes_json")"
receipt_expected_advised_intersection_json="$(jq -n --argjson preferred_worker_ids "$preferred_worker_ids_json" --argjson placement_expected_worker_ids "$placement_expected_worker_ids_json" '[ $preferred_worker_ids[] | select($placement_expected_worker_ids | index(.) != null) ] | unique')"
receipt_worker_mismatch_task_ids_json="$(jq -c --argjson placement_observed_worker_ids "$placement_observed_worker_ids_json" '[.[] | select(.observed_worker_id != null) | select(($placement_observed_worker_ids | length) > 0 and (.observed_worker_id as $worker_id | ($placement_observed_worker_ids | index($worker_id) == null))) | .task_id] | unique' "$task_outcomes_json")"
critical_bottleneck_impacted_task_ids_json="$(jq -n --argjson bottleneck_task_ids "$bottleneck_task_ids_json" --argjson locality_drift_task_ids "$locality_drift_task_ids_json" --argjson excluded_worker_violation_task_ids "$excluded_worker_violation_task_ids_json" --argjson cache_reuse_missed_task_ids "$cache_reuse_missed_task_ids_json" '
  (
    $locality_drift_task_ids
    + $excluded_worker_violation_task_ids
    + $cache_reuse_missed_task_ids
  ) as $risk_task_ids
  | [$risk_task_ids[] | select($bottleneck_task_ids | index(.) != null)] | unique
')"

if jq -e 'length > 0' <<<"$contamination_task_ids_json" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "locality_outcome_samples_json" "locality outcome samples record local fallback contamination"
fi
if [[ "$advisory_decision" == "blocked" || "$advisory_truth_state" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_receipt" "queue_advisory_bundle_json" "queue advisory is already blocked"
fi
if [[ "$placement_decision" == "blocked" || "$placement_adoption_status" == "drifted" || "$placement_adoption_status" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_receipt" "placement_evidence_ledger_json" "placement evidence ledger records drifted or blocked adoption"
fi
if jq -e 'length > 0' <<<"$locality_drift_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "locality_drift_observed" "locality_outcome_samples_json" "locality outcome samples record contradictory locality drift"
fi
if jq -e 'length > 0' <<<"$excluded_worker_violation_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "observed_excluded_worker_used" "locality_outcome_samples_json" "observed outcomes used an excluded worker"
fi
if jq -e 'length > 0' <<<"$unexpected_hot_cache_task_ids_json" >/dev/null || jq -e 'length > 0' <<<"$unclassified_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "contradictory_receipt" "locality_outcome_samples_json" "observed outcomes do not match the advisory cohort or expected locality class"
fi
if jq -e 'length > 0' <<<"$receipt_worker_mismatch_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "contradictory_receipt" "placement_evidence_ledger_json" "observed outcome worker ids do not match the placement receipt observation"
fi
if jq -e '($preferred_worker_ids | length) > 0 and ($placement_expected_worker_ids | length) > 0 and ($intersection | length) == 0' \
  --argjson preferred_worker_ids "$preferred_worker_ids_json" \
  --argjson placement_expected_worker_ids "$placement_expected_worker_ids_json" \
  --argjson intersection "$receipt_expected_advised_intersection_json" \
  -n >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "contradictory_receipt" "placement_evidence_ledger_json" "placement expected workers contradict the advisory preferred workers"
fi

if [[ "$advisory_decision" == "degraded" || "$advisory_truth_state" == "degraded" ]]; then
  append_reason "$degraded_reasons_jsonl" "partial_upstream_evidence" "queue_advisory_bundle_json" "queue advisory is already degraded and must remain conservative"
fi
if [[ "$placement_decision" == "degraded" || "$placement_adoption_status" == "expired" || "$placement_adoption_status" == "manual_review" || "$placement_adoption_status" == "pending_observation" ]]; then
  append_reason "$degraded_reasons_jsonl" "partial_receipt_evidence" "placement_evidence_ledger_json" "placement evidence is degraded, expired, or pending observation"
fi
if jq -e 'length > 0' <<<"$missing_outcome_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "missing_outcome_evidence" "locality_outcome_samples_json" "some queued tasks have no outcome samples"
fi
if jq -e 'length > 0' <<<"$cache_reuse_missed_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "cache_reuse_outcome_missed" "locality_outcome_samples_json" "cache reuse was expected but the outcome did not confirm it"
fi
if jq -e 'length > 0' <<<"$drained_worker_avoidance_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "drained_worker_avoidance_confirmed" "locality_outcome_samples_json" "drained worker avoidance succeeded but remains conservative evidence"
fi
if jq -e 'length > 0' <<<"$probe_required_worker_avoidance_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "probe_required_worker_avoidance_confirmed" "locality_outcome_samples_json" "probe-required worker avoidance succeeded but remains conservative evidence"
fi

queue_advisory_schema_version="$(jq -r '.schema_version // "unknown"' "$queue_advisory_normalized")"
placement_evidence_schema_version="$(jq -r '.schema_version // "unknown"' "$placement_evidence_normalized")"
queue_artifact_schema_version="$(jq -r '.schema_version // "unknown"' "$queue_artifact_normalized")"
bottleneck_report_schema_version="$(jq -r '.schema_version // "unknown"' "$bottleneck_report_normalized")"
locality_outcome_schema_version="$(jq -r '.schema_version // "unknown"' "$locality_outcome_samples_normalized")"

append_source_row "queue_advisory_bundle_json" "$queue_advisory_bundle_json" "$queue_advisory_schema_version" "$advisory_truth_state"
append_source_row "placement_evidence_ledger_json" "$placement_evidence_ledger_json" "$placement_evidence_schema_version" "$placement_decision"
append_source_row "queue_artifact_json" "$queue_artifact_json" "$queue_artifact_schema_version" "provided"
append_source_row "bottleneck_report_json" "$bottleneck_report_json" "$bottleneck_report_schema_version" "provided"
append_source_row "locality_outcome_samples_json" "$locality_outcome_samples_json" "$locality_outcome_schema_version" "provided"

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

locality_match_rate_millionths="$(jq -n --argjson matched_task_ids "$matched_task_ids_json" --argjson queue_task_count "$queue_task_count" 'if $queue_task_count == 0 then 0 else ((($matched_task_ids | length) * 1000000) / $queue_task_count | floor) end')"
evidence_completeness_rate_millionths="$(jq -n --argjson sampled_task_count "$sampled_task_count" --argjson queue_task_count "$queue_task_count" 'if $queue_task_count == 0 then 0 else (($sampled_task_count * 1000000) / $queue_task_count | floor) end')"
contradiction_rate_millionths="$(jq -n \
  --argjson locality_drift_task_ids "$locality_drift_task_ids_json" \
  --argjson excluded_worker_violation_task_ids "$excluded_worker_violation_task_ids_json" \
  --argjson receipt_worker_mismatch_task_ids "$receipt_worker_mismatch_task_ids_json" \
  --argjson sampled_task_count "$sampled_task_count" '
  (($locality_drift_task_ids | length) + ($excluded_worker_violation_task_ids | length) + ($receipt_worker_mismatch_task_ids | length)) as $contradictions
  | if $sampled_task_count == 0 then 0 else (($contradictions * 1000000) / $sampled_task_count | floor) end
')"

cache_reuse_confirmation_rate_millionths="null"
if [[ "$warm_cache_residency_state" == "hot" || "$warm_cache_residency_state" == "warm" || "$rank_bias_mode" == "prefer_hot_cache_locality" ]]; then
  cache_reuse_confirmation_rate_millionths="$(jq -n \
    --argjson confirmed "$cache_reuse_confirmed_task_ids_json" \
    --argjson missed "$cache_reuse_missed_task_ids_json" '
    (($confirmed | length) + ($missed | length)) as $expected
    | if $expected == 0 then 0 else ((($confirmed | length) * 1000000) / $expected | floor) end
  ')"
fi

drained_worker_avoidance_rate_millionths="null"
if jq -e '($confirmed | length) + ($blocked | length) > 0' \
  --argjson confirmed "$drained_worker_avoidance_task_ids_json" \
  --argjson blocked "$excluded_worker_violation_task_ids_json" \
  -n >/dev/null; then
  drained_worker_avoidance_rate_millionths="$(jq -n \
    --argjson confirmed "$drained_worker_avoidance_task_ids_json" \
    --argjson blocked "$excluded_worker_violation_task_ids_json" '
    (($confirmed | length) + ($blocked | length)) as $denom
    | if $denom == 0 then 0 else ((($confirmed | length) * 1000000) / $denom | floor) end
  ')"
fi

confidence_band="high"
if [[ "$decision" == "fail_closed" ]]; then
  confidence_band="contaminated"
elif [[ "$decision" == "blocked" ]]; then
  confidence_band="blocked"
elif [[ "$decision" == "degraded" ]]; then
  confidence_band="low"
elif jq -e --argjson locality_match_rate_millionths "$locality_match_rate_millionths" --argjson evidence_completeness_rate_millionths "$evidence_completeness_rate_millionths" '
  $locality_match_rate_millionths < 1000000 or $evidence_completeness_rate_millionths < 1000000
' -n >/dev/null; then
  confidence_band="medium"
fi

reason_codes_json="$(jq -nc \
  --argjson matched_task_ids "$matched_task_ids_json" \
  --argjson cache_cold_no_reuse_credit_task_ids "$cache_cold_no_reuse_credit_task_ids_json" \
  --argjson cache_reuse_confirmed_task_ids "$cache_reuse_confirmed_task_ids_json" \
  --argjson cache_reuse_missed_task_ids "$cache_reuse_missed_task_ids_json" \
  --argjson locality_drift_task_ids "$locality_drift_task_ids_json" \
  --argjson drained_worker_avoidance_task_ids "$drained_worker_avoidance_task_ids_json" \
  --argjson probe_required_worker_avoidance_task_ids "$probe_required_worker_avoidance_task_ids_json" \
  --argjson excluded_worker_violation_task_ids "$excluded_worker_violation_task_ids_json" \
  --slurpfile degraded "$degraded_reasons_jsonl" \
  --slurpfile blocked "$blocked_reasons_jsonl" \
  --slurpfile failclosed "$fail_closed_reasons_jsonl" '
  (
    ($degraded[0:] | map(.code))
    + ($blocked[0:] | map(.code))
    + ($failclosed[0:] | map(.code))
    + (if ($matched_task_ids | length) > 0 then ["matched_locality_advisory"] else [] end)
    + (if ($cache_cold_no_reuse_credit_task_ids | length) > 0 then ["cache_cold_no_reuse_credit"] else [] end)
    + (if ($cache_reuse_confirmed_task_ids | length) > 0 then ["cache_reuse_outcome_confirmed"] else [] end)
    + (if ($cache_reuse_missed_task_ids | length) > 0 then ["cache_reuse_outcome_missed"] else [] end)
    + (if ($locality_drift_task_ids | length) > 0 then ["locality_drift_observed"] else [] end)
    + (if ($drained_worker_avoidance_task_ids | length) > 0 then ["drained_worker_avoidance_confirmed"] else [] end)
    + (if ($probe_required_worker_avoidance_task_ids | length) > 0 then ["probe_required_worker_avoidance_confirmed"] else [] end)
    + (if ($excluded_worker_violation_task_ids | length) > 0 then ["observed_excluded_worker_used"] else [] end)
  ) | unique | sort
')"

receipt_id="$(
  jq -cn \
    --arg source_revision "$source_revision" \
    --arg decision "$decision" \
    --arg truth_state "$truth_state" \
    --argjson reason_codes "$reason_codes_json" \
    --arg rank_bias_mode "$rank_bias_mode" \
    --arg recommended_topology_class "$recommended_topology_class" \
    '{source_revision:$source_revision,decision:$decision,truth_state:$truth_state,reason_codes:$reason_codes,rank_bias_mode:$rank_bias_mode,recommended_topology_class:$recommended_topology_class}' \
    | jq -cS . | sha256sum | awk '{print "stqf-" substr($1,1,16)}'
)"

jq -n \
  --arg schema_version "franken-engine.swarm-topology-aware-queue-fidelity-sources.v1" \
  --slurpfile source_rows "$source_rows_jsonl" \
  '{schema_version:$schema_version,source_artifacts:$source_rows}' >"$sources_path"

jq -n \
  --arg schema_version "franken-engine.swarm-topology-aware-queue-fidelity-receipt.v1" \
  --arg source_schema_version "franken-engine.swarm-topology-aware-queue-fidelity-sources.v1" \
  --arg fidelity_receipt_id "$receipt_id" \
  --arg source_revision "$source_revision" \
  --arg truth_state "$truth_state" \
  --arg decision "$decision" \
  --arg confidence_band "$confidence_band" \
  --arg rank_bias_mode "$rank_bias_mode" \
  --arg warm_cache_residency_state "$warm_cache_residency_state" \
  --arg recommended_topology_class "$recommended_topology_class" \
  --arg receipt_path "$receipt_path" \
  --arg drift_ledger_path "$drift_ledger_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --argjson matched_task_ids "$matched_task_ids_json" \
  --argjson cache_cold_no_reuse_credit_task_ids "$cache_cold_no_reuse_credit_task_ids_json" \
  --argjson cache_reuse_confirmed_task_ids "$cache_reuse_confirmed_task_ids_json" \
  --argjson cache_reuse_missed_task_ids "$cache_reuse_missed_task_ids_json" \
  --argjson locality_drift_task_ids "$locality_drift_task_ids_json" \
  --argjson drained_worker_avoidance_task_ids "$drained_worker_avoidance_task_ids_json" \
  --argjson probe_required_worker_avoidance_task_ids "$probe_required_worker_avoidance_task_ids_json" \
  --argjson excluded_worker_violation_task_ids "$excluded_worker_violation_task_ids_json" \
  --argjson missing_outcome_task_ids "$missing_outcome_task_ids_json" \
  --argjson contamination_task_ids "$contamination_task_ids_json" \
  --argjson critical_bottleneck_impacted_task_ids "$critical_bottleneck_impacted_task_ids_json" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson queue_task_count "$queue_task_count" \
  --argjson sampled_task_count "$sampled_task_count" \
  --argjson locality_match_rate_millionths "$locality_match_rate_millionths" \
  --argjson cache_reuse_confirmation_rate_millionths "$cache_reuse_confirmation_rate_millionths" \
  --argjson drained_worker_avoidance_rate_millionths "$drained_worker_avoidance_rate_millionths" \
  --argjson contradiction_rate_millionths "$contradiction_rate_millionths" \
  --argjson evidence_completeness_rate_millionths "$evidence_completeness_rate_millionths" \
  --argjson critical_bottleneck_count "$critical_bottleneck_count" \
  --argjson placement_observation_present "$placement_observation_present_json" \
  --slurpfile degraded_reasons "$degraded_reasons_jsonl" \
  --slurpfile blocked_reasons "$blocked_reasons_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --slurpfile source_rows "$source_rows_jsonl" \
  --slurpfile task_outcomes "$task_outcomes_json" '
  {
    schema_version:$schema_version,
    source_schema_version:$source_schema_version,
    fidelity_receipt_id:$fidelity_receipt_id,
    source_revision:$source_revision,
    truth_state:$truth_state,
    decision:$decision,
    confidence_band:$confidence_band,
    reason_codes:$reason_codes,
    matched_task_ids:$matched_task_ids,
    cache_cold_no_reuse_credit_task_ids:$cache_cold_no_reuse_credit_task_ids,
    cache_reuse_confirmed_task_ids:$cache_reuse_confirmed_task_ids,
    cache_reuse_missed_task_ids:$cache_reuse_missed_task_ids,
    locality_drift_task_ids:$locality_drift_task_ids,
    drained_worker_avoidance_task_ids:$drained_worker_avoidance_task_ids,
    probe_required_worker_avoidance_task_ids:$probe_required_worker_avoidance_task_ids,
    excluded_worker_violation_task_ids:$excluded_worker_violation_task_ids,
    missing_outcome_task_ids:$missing_outcome_task_ids,
    contamination_task_ids:$contamination_task_ids,
    aggregate_metrics:{
      task_count:$queue_task_count,
      sampled_task_count:$sampled_task_count,
      locality_match_rate_millionths:$locality_match_rate_millionths,
      cache_reuse_confirmation_rate_millionths:$cache_reuse_confirmation_rate_millionths,
      drained_worker_avoidance_rate_millionths:$drained_worker_avoidance_rate_millionths,
      contradiction_rate_millionths:$contradiction_rate_millionths,
      evidence_completeness_rate_millionths:$evidence_completeness_rate_millionths,
      critical_bottleneck_count:$critical_bottleneck_count,
      critical_bottleneck_impacted_task_ids:$critical_bottleneck_impacted_task_ids,
      placement_observation_present:$placement_observation_present,
      confidence_band:$confidence_band
    },
    task_outcomes:$task_outcomes,
    degraded_reasons:$degraded_reasons,
    blocked_reasons:$blocked_reasons,
    fail_closed_reasons:$fail_closed_reasons,
    source_artifacts:$source_rows,
    artifact_paths:{
      fidelity_receipt_json:$receipt_path,
      drift_ledger_json:$drift_ledger_path,
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
  }' >"$receipt_tmp"
mv "$receipt_tmp" "$receipt_path"

drift_ledger_id="$(
  jq -cn \
    --arg source_revision "$source_revision" \
    --arg decision "$decision" \
    --argjson reason_codes "$reason_codes_json" \
    --argjson matched_task_ids "$matched_task_ids_json" \
    '{source_revision:$source_revision,decision:$decision,reason_codes:$reason_codes,matched_task_ids:$matched_task_ids}' \
    | jq -cS . | sha256sum | awk '{print "stqd-" substr($1,1,16)}'
)"

jq -n \
  --arg schema_version "franken-engine.swarm-topology-aware-queue-drift-ledger.v1" \
  --arg drift_ledger_id "$drift_ledger_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg fidelity_receipt_id "$receipt_id" \
  --arg drift_ledger_path "$drift_ledger_path" \
  --arg receipt_path "$receipt_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --argjson matched_task_ids "$matched_task_ids_json" \
  --argjson locality_drift_task_ids "$locality_drift_task_ids_json" \
  --argjson excluded_worker_violation_task_ids "$excluded_worker_violation_task_ids_json" \
  --argjson missing_outcome_task_ids "$missing_outcome_task_ids_json" \
  --argjson contamination_task_ids "$contamination_task_ids_json" \
  --slurpfile task_outcomes "$task_outcomes_json" '
  {
    schema_version:$schema_version,
    drift_ledger_id:$drift_ledger_id,
    source_revision:$source_revision,
    decision:$decision,
    truth_state:$truth_state,
    fidelity_receipt_id:$fidelity_receipt_id,
    task_outcomes:$task_outcomes,
    summary:{
      matched_count:($matched_task_ids | length),
      drift_count:($locality_drift_task_ids | length),
      excluded_worker_violation_count:($excluded_worker_violation_task_ids | length),
      missing_outcome_count:($missing_outcome_task_ids | length),
      contamination_count:($contamination_task_ids | length)
    },
    artifact_paths:{
      swarm_topology_aware_queue_drift_ledger_json:$drift_ledger_path,
      swarm_topology_aware_queue_fidelity_receipt_json:$receipt_path,
      swarm_topology_aware_queue_fidelity_sources_json:$sources_path,
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
  }' >"$drift_ledger_tmp"
mv "$drift_ledger_tmp" "$drift_ledger_path"

{
  printf '# Topology Aware Queue Fidelity Ledger\n'
  printf '\n'
  printf -- "- fidelity_receipt_id: \`%s\`\n" "$receipt_id"
  printf -- "- truth_state: \`%s\`\n" "$truth_state"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- confidence_band: \`%s\`\n" "$confidence_band"
  printf -- "- rank_bias_mode: \`%s\`\n" "$rank_bias_mode"
  printf -- "- recommended_topology_class: \`%s\`\n" "$recommended_topology_class"
  printf -- "- reason_codes: \`%s\`\n" "$reason_codes_json"
  printf -- "- matched_task_ids: \`%s\`\n" "$matched_task_ids_json"
  printf -- "- critical_bottleneck_impacted_task_ids: \`%s\`\n" "$critical_bottleneck_impacted_task_ids_json"
} >"$summary_path"

write_event "fidelity_ledger.emitted" "$decision" "$rank_bias_mode" "$receipt_path"

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
