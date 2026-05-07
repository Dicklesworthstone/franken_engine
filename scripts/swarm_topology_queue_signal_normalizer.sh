#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_TOPOLOGY_QUEUE_SIGNAL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-queue-signal}"
run_id="${SWARM_TOPOLOGY_QUEUE_SIGNAL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_QUEUE_SIGNAL_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_TOPOLOGY_QUEUE_SIGNAL_SOURCE_REVISION:-unknown}"
execution_queue_input_json=""
topology_placement_input_json=""
rehabilitation_ledger_json=""
placement_adoption_history_json=""
operator_status_snapshot_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_topology_queue_signal_normalizer.sh [OPTIONS]

Normalizes queue readiness, topology placement, and rehabilitation evidence
into advisory topology-aware queue signals. This script is fixture-fed and
advisory-only. It does not update beads, release reservations, send Agent Mail,
run Cargo or RCH, mutate remote workers, or change live queue policy.

Required snapshots:
  --execution-queue-input-json FILE
  --topology-placement-input-json FILE
  --rehabilitation-ledger-json FILE

Optional snapshots:
  --placement-adoption-history-json FILE
  --operator-status-snapshot-json FILE

Other options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_topology_queue_signal_input.json
  swarm_topology_queue_signal_sources.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  input is replayable; decision may be pass or degraded
  42 fail-closed due to malformed required evidence or local-fallback contamination
  75 blocked due to contradictory locality evidence
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --execution-queue-input-json)
      execution_queue_input_json="${2:-}"
      shift 2
      ;;
    --topology-placement-input-json)
      topology_placement_input_json="${2:-}"
      shift 2
      ;;
    --rehabilitation-ledger-json)
      rehabilitation_ledger_json="${2:-}"
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

if [[ -z "$execution_queue_input_json" || -z "$topology_placement_input_json" || -z "$rehabilitation_ledger_json" ]]; then
  printf 'execution queue input, topology placement input, and rehabilitation ledger are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm topology queue signal normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm topology queue signal normalization\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
input_path="${run_dir}/swarm_topology_queue_signal_input.json"
input_tmp="${input_path}.tmp"
core_path="${run_dir}/swarm_topology_queue_signal_input.core.json"
sources_path="${run_dir}/swarm_topology_queue_signal_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
source_rows_jsonl="${run_dir}/source_rows.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

execution_queue_input_normalized="${run_dir}/execution_queue_input.normalized.json"
topology_placement_input_normalized="${run_dir}/topology_placement_input.normalized.json"
rehabilitation_ledger_normalized="${run_dir}/rehabilitation_ledger.normalized.json"
placement_adoption_history_normalized="${run_dir}/placement_adoption_history.normalized.json"
operator_status_snapshot_normalized="${run_dir}/operator_status_snapshot.normalized.json"

printf './scripts/swarm_topology_queue_signal_normalizer.sh' >"$commands_path"
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
    --arg schema_version "franken-engine.swarm-topology-queue-signal-normalizer.event.v1" \
    --arg component "swarm_topology_queue_signal_normalizer" \
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

normalize_required_json "$execution_queue_input_json" "$execution_queue_input_normalized" "execution queue input"
normalize_required_json "$topology_placement_input_json" "$topology_placement_input_normalized" "topology placement input"
normalize_required_json "$rehabilitation_ledger_json" "$rehabilitation_ledger_normalized" "rehabilitation ledger"
placement_adoption_history_status="$(normalize_optional_json "$placement_adoption_history_json" "$placement_adoption_history_normalized" "placement adoption history")"
operator_status_snapshot_status="$(normalize_optional_json "$operator_status_snapshot_json" "$operator_status_snapshot_normalized" "operator status snapshot")"

check_shape "$execution_queue_input_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.tasks // null) | type == "array")
  and ((.tasks | length) > 0)
  and all(.tasks[]?;
    ((.task_id // "") | (type == "string" and length > 0))
    and ((.proof_transport.state // "") | (type == "string" and length > 0))
    and ((.proof_transport.local_fallback_detected | type) == "boolean")
  )
' "execution_queue_input_json" "queue input lacks task ids or proof transport state"

check_shape "$topology_placement_input_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.placement_hints.preferred_worker_ids // null) | type == "array")
  and ((.placement_hints.preferred_numa_nodes // null) | type == "array")
  and ((.warm_cache_residency.state // "") | (type == "string" and length > 0))
' "topology_placement_input_json" "topology placement input lacks truth or placement hints"

check_shape "$rehabilitation_ledger_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.workers // null) | type == "array")
  and all(.workers[]?;
    ((.worker_id // "") | (type == "string" and length > 0))
    and ((.classification // "") | (type == "string" and length > 0))
  )
' "rehabilitation_ledger_json" "rehabilitation ledger lacks worker classifications"

queue_local_fallback_detected="$(jq -e '[.tasks[]? | select(.proof_transport.local_fallback_detected == true)] | length > 0' "$execution_queue_input_normalized" >/dev/null && printf true || printf false)"
topology_truth_state="$(jq -r '.truth_state // "unknown"' "$topology_placement_input_normalized")"
topology_decision="$(jq -r '.decision // "unknown"' "$topology_placement_input_normalized")"
rehab_decision="$(jq -r '.decision // "unknown"' "$rehabilitation_ledger_normalized")"

if [[ "$queue_local_fallback_detected" == "true" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "execution_queue_input_json" "queue proof transport detected local fallback contamination"
fi
if [[ "$topology_truth_state" == "contaminated" || "$topology_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "topology_input_untrusted" "topology_placement_input_json" "topology placement input is contaminated or fail_closed"
fi
if [[ "$rehab_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "rehabilitation_input_untrusted" "rehabilitation_ledger_json" "rehabilitation ledger is fail_closed"
fi
if [[ "$topology_truth_state" == "blocked" || "$topology_decision" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_locality" "topology_placement_input_json" "topology placement input is already blocked"
fi

if [[ "$placement_adoption_history_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "placement_adoption_history_json" "placement adoption history is missing"
fi
if [[ "$operator_status_snapshot_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "operator_status_snapshot_json" "operator status snapshot is missing"
fi

preferred_worker_ids_json="$(jq -c '.placement_hints.preferred_worker_ids // []' "$topology_placement_input_normalized")"
preferred_numa_nodes_json="$(jq -c '.placement_hints.preferred_numa_nodes // []' "$topology_placement_input_normalized")"
excluded_worker_ids_json="$(jq -c '[.workers[]? | select(.classification as $classification | (["probe_required","drain_recommended","drained"] | index($classification)) != null) | .worker_id] | unique' "$rehabilitation_ledger_normalized")"
watch_worker_ids_json="$(jq -c '[.workers[]? | select(.classification == "watch") | .worker_id] | unique' "$rehabilitation_ledger_normalized")"
rehab_candidate_worker_ids_json="$(jq -c '[.workers[]? | select(.classification == "rehab_candidate") | .worker_id] | unique' "$rehabilitation_ledger_normalized")"

usable_preferred_worker_ids_json="$(jq -cn \
  --argjson preferred "$preferred_worker_ids_json" \
  --argjson excluded "$excluded_worker_ids_json" \
  '$preferred | map(select(($excluded | index(.)) | not))'
)"

if jq -e 'length > 0' <<<"$excluded_worker_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "excluded_preferred_workers" "rehabilitation_ledger_json" "rehabilitation exclusions removed one or more preferred workers from queue advice"
fi
if jq -e 'length > 0' <<<"$watch_worker_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "watch_workers_present" "rehabilitation_ledger_json" "watch-classified workers keep locality advice in degraded mode"
fi

decision="pass"
truth_state="confirmed"
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="contaminated"
elif [[ -s "$blocked_reasons_jsonl" ]]; then
  decision="blocked"
  truth_state="blocked"
elif [[ -s "$degraded_reasons_jsonl" ]] || [[ "$topology_truth_state" == "degraded" ]] || [[ "$rehab_decision" == "degraded" ]]; then
  decision="degraded"
  truth_state="degraded"
fi

rank_bias_mode="portable_fallback"
hot_cache_reuse_confidence_millionths=250000
locality_confidence_millionths=450000
warm_cache_state="$(jq -r '.warm_cache_residency.state // "missing_optional"' "$topology_placement_input_normalized")"
recommended_topology_class="$(jq -r '.placement_hints.recommended_topology_class // "portable_fallback"' "$topology_placement_input_normalized")"
if [[ "$decision" == "fail_closed" ]]; then
  rank_bias_mode="fail_closed"
  hot_cache_reuse_confidence_millionths=0
  locality_confidence_millionths=0
elif [[ "$decision" == "blocked" ]]; then
  rank_bias_mode="blocked_contradictory_locality"
  hot_cache_reuse_confidence_millionths=0
  locality_confidence_millionths=0
elif [[ "$warm_cache_state" == "hot" ]] && jq -e 'length > 0' <<<"$usable_preferred_worker_ids_json" >/dev/null; then
  rank_bias_mode="prefer_hot_cache_locality"
  hot_cache_reuse_confidence_millionths=950000
  locality_confidence_millionths=900000
elif [[ "$recommended_topology_class" == "numa_local" || "$recommended_topology_class" == "numa_local_hot_cache" ]] && jq -e 'length > 0' <<<"$preferred_numa_nodes_json" >/dev/null; then
  rank_bias_mode="prefer_numa_locality"
  hot_cache_reuse_confidence_millionths=650000
  locality_confidence_millionths=820000
fi

queue_proof_transport_state="$(jq -r '
  if any(.tasks[]?; .proof_transport.local_fallback_detected == true) then "local_fallback_contaminated"
  elif any(.tasks[]?; (.proof_transport.state // "") != "remote_only_ok") then "degraded"
  else "remote_only_ok"
  end
' "$execution_queue_input_normalized")"

queue_task_count="$(jq '[.tasks[]?] | length' "$execution_queue_input_normalized")"
rehab_exclusion_count="$(jq 'length' <<<"$excluded_worker_ids_json")"

queue_schema_version="$(jq -r '.schema_version // "unknown"' "$execution_queue_input_normalized")"
topology_schema_version="$(jq -r '.schema_version // "unknown"' "$topology_placement_input_normalized")"
rehab_schema_version="$(jq -r '.schema_version // "unknown"' "$rehabilitation_ledger_normalized")"
adoption_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$placement_adoption_history_normalized")"
operator_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$operator_status_snapshot_normalized")"

append_source_row "execution_queue_input_json" true true "$execution_queue_input_normalized" "$queue_schema_version" "$queue_proof_transport_state"
append_source_row "topology_placement_input_json" true true "$topology_placement_input_normalized" "$topology_schema_version" "$topology_truth_state"
append_source_row "rehabilitation_ledger_json" true true "$rehabilitation_ledger_normalized" "$rehab_schema_version" "$rehab_decision"
append_source_row "placement_adoption_history_json" false "$([[ "$placement_adoption_history_status" == "provided" ]] && printf true || printf false)" "$placement_adoption_history_normalized" "$adoption_schema_version" "$placement_adoption_history_status"
append_source_row "operator_status_snapshot_json" false "$([[ "$operator_status_snapshot_status" == "provided" ]] && printf true || printf false)" "$operator_status_snapshot_normalized" "$operator_schema_version" "$operator_status_snapshot_status"

jq -n \
  --arg schema_version "franken-engine.swarm-topology-queue-signal-input.v1" \
  --arg source_schema_version "franken-engine.swarm-topology-queue-signal-sources.v1" \
  --arg source_revision "$source_revision" \
  --arg truth_state "$truth_state" \
  --arg decision "$decision" \
  --arg rank_bias_mode "$rank_bias_mode" \
  --arg queue_proof_transport_state "$queue_proof_transport_state" \
  --arg recommended_topology_class "$recommended_topology_class" \
  --arg warm_cache_state "$warm_cache_state" \
  --arg input_path "$input_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson queue_task_count "$queue_task_count" \
  --argjson rehab_exclusion_count "$rehab_exclusion_count" \
  --argjson hot_cache_reuse_confidence_millionths "$hot_cache_reuse_confidence_millionths" \
  --argjson locality_confidence_millionths "$locality_confidence_millionths" \
  --argjson preferred_worker_ids "$preferred_worker_ids_json" \
  --argjson usable_preferred_worker_ids "$usable_preferred_worker_ids_json" \
  --argjson excluded_worker_ids "$excluded_worker_ids_json" \
  --argjson watch_worker_ids "$watch_worker_ids_json" \
  --argjson rehab_candidate_worker_ids "$rehab_candidate_worker_ids_json" \
  --argjson preferred_numa_nodes "$preferred_numa_nodes_json" \
  --slurpfile queue "$execution_queue_input_normalized" \
  --slurpfile topology "$topology_placement_input_normalized" \
  --slurpfile rehab "$rehabilitation_ledger_normalized" \
  --slurpfile source_rows "$source_rows_jsonl" \
  --slurpfile degraded_reasons "$degraded_reasons_jsonl" \
  --slurpfile blocked_reasons "$blocked_reasons_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  '{
    schema_version:$schema_version,
    source_schema_version:$source_schema_version,
    source_revision:$source_revision,
    truth_state:$truth_state,
    decision:$decision,
    queue_context:{
      task_count:$queue_task_count,
      proof_transport_state:$queue_proof_transport_state
    },
    locality_context:{
      recommended_topology_class:$recommended_topology_class,
      warm_cache_residency_state:$warm_cache_state,
      preferred_numa_nodes:$preferred_numa_nodes,
      preferred_worker_ids:$preferred_worker_ids
    },
    rehabilitation_context:{
      excluded_worker_ids:$excluded_worker_ids,
      watch_worker_ids:$watch_worker_ids,
      rehab_candidate_worker_ids:$rehab_candidate_worker_ids,
      exclusion_count:$rehab_exclusion_count
    },
    queue_signal_hints:{
      rank_bias_mode:$rank_bias_mode,
      hot_cache_reuse_confidence_millionths:$hot_cache_reuse_confidence_millionths,
      locality_confidence_millionths:$locality_confidence_millionths,
      usable_preferred_worker_ids:$usable_preferred_worker_ids
    },
    degraded_reasons:$degraded_reasons,
    blocked_reasons:$blocked_reasons,
    fail_closed_reasons:$fail_closed_reasons,
    source_artifacts:$source_rows,
    artifact_paths:{
      input_json:$input_path,
      sources_json:$sources_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_path
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
  }' >"$core_path"

queue_signal_input_id="swarm-topology-queue-signal-$(jq -cS 'del(.artifact_paths,.source_artifacts)' "$core_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg queue_signal_input_id "$queue_signal_input_id" '. + {queue_signal_input_id:$queue_signal_input_id}' "$core_path" >"$input_tmp"
mv "$input_tmp" "$input_path"
jq '.source_artifacts' "$input_path" >"$sources_path"

write_event "normalized_input.written" "$decision" "$rank_bias_mode" "$input_path"

{
  printf '# Swarm Topology Queue Signal Normalization\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Truth state: \`%s\`\n" "$truth_state"
  printf -- "- Rank bias mode: \`%s\`\n" "$rank_bias_mode"
  printf -- "- Usable preferred workers: \`%s\`\n" "$(jq -r '.queue_signal_hints.usable_preferred_worker_ids | join(",")' "$input_path")"
  printf -- "- Excluded workers: \`%s\`\n" "$(jq -r '.rehabilitation_context.excluded_worker_ids | join(",")' "$input_path")"
  if [[ "$(jq '.degraded_reasons | length' "$input_path")" -ne 0 ]]; then
    printf '\n## Degraded Reasons\n'
    jq -r '.degraded_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$input_path"
  fi
  if [[ "$(jq '.blocked_reasons | length' "$input_path")" -ne 0 ]]; then
    printf '\n## Blocked Reasons\n'
    jq -r '.blocked_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$input_path"
  fi
  if [[ "$(jq '.fail_closed_reasons | length' "$input_path")" -ne 0 ]]; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$input_path"
  fi
} >"$report_path"

printf 'swarm_topology_queue_signal_input_json=%s\n' "$input_path"
printf 'swarm_topology_queue_signal_sources_json=%s\n' "$sources_path"
printf 'swarm_topology_queue_signal_report_md=%s\n' "$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
if [[ "$decision" == "blocked" ]]; then
  exit 75
fi
exit 0
