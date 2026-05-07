#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_WORKER_CAPABILITY_TOOLCHAIN_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-worker-capability-toolchain}"
run_id="${SWARM_WORKER_CAPABILITY_TOOLCHAIN_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_WORKER_CAPABILITY_TOOLCHAIN_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_WORKER_CAPABILITY_TOOLCHAIN_SOURCE_REVISION:-unknown}"
execution_queue_input_json=""
topology_queue_signal_input_json=""
rehabilitation_ledger_json=""
rch_remote_compile_stall_bundle_json=""
worker_capability_snapshot_json=""
worker_toolchain_snapshot_json=""
resource_envelope_json=""
operator_status_snapshot_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_worker_capability_toolchain_normalizer.sh [OPTIONS]

Normalizes queue readiness, topology queue signals, rehabilitation evidence,
remote-stall contamination evidence, and worker capability/toolchain snapshots
into advisory capability-aware routing input. This script is fixture-fed and
advisory-only. It does not update beads, release reservations, send Agent Mail,
run Cargo or RCH, mutate remote workers, reroute live tasks automatically, or
change live queue policy.

Required snapshots:
  --execution-queue-input-json FILE
  --topology-queue-signal-input-json FILE
  --rehabilitation-ledger-json FILE
  --rch-remote-compile-stall-bundle-json FILE
  --worker-capability-snapshot-json FILE
  --worker-toolchain-snapshot-json FILE

Optional snapshots:
  --resource-envelope-json FILE
  --operator-status-snapshot-json FILE

Other options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_worker_capability_toolchain_input.json
  swarm_worker_capability_toolchain_sources.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  input is replayable; decision may be pass or degraded
  42 fail-closed due to malformed required evidence or local-fallback contamination
  75 blocked due to capability or toolchain mismatch
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --execution-queue-input-json)
      execution_queue_input_json="${2:-}"
      shift 2
      ;;
    --topology-queue-signal-input-json)
      topology_queue_signal_input_json="${2:-}"
      shift 2
      ;;
    --rehabilitation-ledger-json)
      rehabilitation_ledger_json="${2:-}"
      shift 2
      ;;
    --rch-remote-compile-stall-bundle-json)
      rch_remote_compile_stall_bundle_json="${2:-}"
      shift 2
      ;;
    --worker-capability-snapshot-json)
      worker_capability_snapshot_json="${2:-}"
      shift 2
      ;;
    --worker-toolchain-snapshot-json)
      worker_toolchain_snapshot_json="${2:-}"
      shift 2
      ;;
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
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

if [[ -z "$execution_queue_input_json" || -z "$topology_queue_signal_input_json" || -z "$rehabilitation_ledger_json" || -z "$rch_remote_compile_stall_bundle_json" || -z "$worker_capability_snapshot_json" || -z "$worker_toolchain_snapshot_json" ]]; then
  printf 'queue, topology, rehabilitation, stall bundle, capability snapshot, and toolchain snapshot are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm worker capability/toolchain normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm worker capability/toolchain normalization\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
input_path="${run_dir}/swarm_worker_capability_toolchain_input.json"
input_tmp="${input_path}.tmp"
core_path="${run_dir}/swarm_worker_capability_toolchain_input.core.json"
sources_path="${run_dir}/swarm_worker_capability_toolchain_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
source_rows_jsonl="${run_dir}/source_rows.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

execution_queue_input_normalized="${run_dir}/execution_queue_input.normalized.json"
topology_queue_signal_input_normalized="${run_dir}/topology_queue_signal_input.normalized.json"
rehabilitation_ledger_normalized="${run_dir}/rehabilitation_ledger.normalized.json"
rch_remote_compile_stall_bundle_normalized="${run_dir}/rch_remote_compile_stall_bundle.normalized.json"
worker_capability_snapshot_normalized="${run_dir}/worker_capability_snapshot.normalized.json"
worker_toolchain_snapshot_normalized="${run_dir}/worker_toolchain_snapshot.normalized.json"
resource_envelope_normalized="${run_dir}/resource_envelope.normalized.json"
operator_status_snapshot_normalized="${run_dir}/operator_status_snapshot.normalized.json"

printf './scripts/swarm_worker_capability_toolchain_normalizer.sh' >"$commands_path"
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
    --arg schema_version "franken-engine.swarm-worker-capability-toolchain-normalizer.event.v1" \
    --arg component "swarm_worker_capability_toolchain_normalizer" \
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
normalize_required_json "$topology_queue_signal_input_json" "$topology_queue_signal_input_normalized" "topology queue signal input"
normalize_required_json "$rehabilitation_ledger_json" "$rehabilitation_ledger_normalized" "rehabilitation ledger"
normalize_required_json "$rch_remote_compile_stall_bundle_json" "$rch_remote_compile_stall_bundle_normalized" "rch remote compile stall bundle"
normalize_required_json "$worker_capability_snapshot_json" "$worker_capability_snapshot_normalized" "worker capability snapshot"
normalize_required_json "$worker_toolchain_snapshot_json" "$worker_toolchain_snapshot_normalized" "worker toolchain snapshot"
resource_envelope_status="$(normalize_optional_json "$resource_envelope_json" "$resource_envelope_normalized" "resource envelope")"
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

check_shape "$topology_queue_signal_input_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.queue_signal_hints.usable_preferred_worker_ids // null) | type == "array")
' "topology_queue_signal_input_json" "topology queue signal input lacks truth or preferred workers"

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

check_shape "$rch_remote_compile_stall_bundle_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.local_fallback_observed | type) == "boolean")
  and ((.stall_subject.worker_id // "") | (type == "string" and length > 0))
' "rch_remote_compile_stall_bundle_json" "stall bundle lacks truth or worker subject"

check_shape "$worker_capability_snapshot_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.workers // null) | type == "array")
  and ((.task_requirements // null) | type == "array")
  and all(.workers[]?;
    ((.worker_id // "") | (type == "string" and length > 0))
    and ((.observed_capabilities // null) | type == "array")
  )
  and all(.task_requirements[]?;
    ((.task_id // "") | (type == "string" and length > 0))
    and ((.required_capabilities // null) | type == "array")
  )
' "worker_capability_snapshot_json" "worker capability snapshot lacks workers or task requirements"

check_shape "$worker_toolchain_snapshot_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.workers // null) | type == "array")
  and ((.task_requirements // null) | type == "array")
  and all(.workers[]?;
    ((.worker_id // "") | (type == "string" and length > 0))
    and ((.observed_toolchain_fingerprint // "") | (type == "string" and length > 0))
  )
  and all(.task_requirements[]?;
    ((.task_id // "") | (type == "string" and length > 0))
    and ((.required_toolchain_fingerprint // "") | (type == "string" and length > 0))
  )
' "worker_toolchain_snapshot_json" "worker toolchain snapshot lacks workers or task requirements"

queue_local_fallback_detected="$(jq -e '[.tasks[]? | select(.proof_transport.local_fallback_detected == true)] | length > 0' "$execution_queue_input_normalized" >/dev/null && printf true || printf false)"
topology_truth_state="$(jq -r '.truth_state // "unknown"' "$topology_queue_signal_input_normalized")"
topology_decision="$(jq -r '.decision // "unknown"' "$topology_queue_signal_input_normalized")"
rehab_decision="$(jq -r '.decision // "unknown"' "$rehabilitation_ledger_normalized")"
stall_truth_state="$(jq -r '.truth_state // "unknown"' "$rch_remote_compile_stall_bundle_normalized")"
stall_local_fallback_observed="$(jq -r '.local_fallback_observed // false' "$rch_remote_compile_stall_bundle_normalized")"

if [[ "$queue_local_fallback_detected" == "true" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contaminated" "execution_queue_input_json" "queue proof transport detected local fallback contamination"
fi
if [[ "$stall_local_fallback_observed" == "true" || "$stall_truth_state" == "contaminated" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "remote_stall_contaminated" "rch_remote_compile_stall_bundle_json" "remote stall bundle is contaminated by local fallback evidence"
fi
if [[ "$rehab_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "rehabilitation_input_untrusted" "rehabilitation_ledger_json" "rehabilitation ledger is fail_closed"
fi
if [[ "$topology_truth_state" == "blocked" || "$topology_decision" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "topology_signal_blocked" "topology_queue_signal_input_json" "topology queue signal input is already blocked"
fi

if [[ "$resource_envelope_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "resource_envelope_json" "resource envelope is missing"
fi
if [[ "$operator_status_snapshot_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "operator_status_snapshot_json" "operator status snapshot is missing"
fi

preferred_worker_ids_json="$(jq -c '.queue_signal_hints.usable_preferred_worker_ids // []' "$topology_queue_signal_input_normalized")"
recommended_topology_class="$(jq -r '.locality_context.recommended_topology_class // "portable_fallback"' "$topology_queue_signal_input_normalized")"
excluded_worker_ids_json="$(jq -c '[.workers[]? | select(.classification as $classification | (["probe_required","drain_recommended","drained"] | index($classification)) != null) | .worker_id] | unique' "$rehabilitation_ledger_normalized")"
watch_worker_ids_json="$(jq -c '[.workers[]? | select(.classification == "watch") | .worker_id] | unique' "$rehabilitation_ledger_normalized")"
rehab_candidate_worker_ids_json="$(jq -c '[.workers[]? | select(.classification == "rehab_candidate") | .worker_id] | unique' "$rehabilitation_ledger_normalized")"

routing_analysis_path="${run_dir}/routing_analysis.json"
jq -n \
  --argjson preferred "$preferred_worker_ids_json" \
  --argjson excluded "$excluded_worker_ids_json" \
  --slurpfile queue "$execution_queue_input_normalized" \
  --slurpfile capabilities "$worker_capability_snapshot_normalized" \
  --slurpfile toolchains "$worker_toolchain_snapshot_normalized" \
  '
  def queue_tasks: ($queue[0].tasks // []);
  def task_ids: (queue_tasks | map(.task_id));
  def preferred_workers: $preferred;
  def excluded_workers: $excluded;
  def usable_preferred: preferred_workers | map(. as $worker_id | select((excluded_workers | index($worker_id)) | not));
  def all_workers: (($capabilities[0].workers // []) | map(.worker_id) | unique);
  def broader_workers: all_workers | map(. as $worker_id | select((excluded_workers | index($worker_id)) | not));
  def worker_caps($id):
    (($capabilities[0].workers // [])
      | map(select(.worker_id == $id) | (.observed_capabilities // []))
      | if length == 0 then [] else add end
      | unique);
  def task_caps($task_id):
    (($capabilities[0].task_requirements // [])
      | map(select(.task_id == $task_id) | (.required_capabilities // []))
      | if length == 0 then null else add end
      | if . == null then null else unique end);
  def worker_tool($id):
    (($toolchains[0].workers // [])
      | map(select(.worker_id == $id) | .observed_toolchain_fingerprint)
      | if length == 0 then null else .[0] end);
  def task_tool($task_id):
    (($toolchains[0].task_requirements // [])
      | map(select(.task_id == $task_id) | .required_toolchain_fingerprint)
      | if length == 0 then null else .[0] end);
  def covers_caps($id; $caps):
    if $caps == null then false else (($caps - worker_caps($id)) | length == 0) end;
  def matches_tool($id; $tool):
    if $tool == null then false else (worker_tool($id) == $tool) end;
  def viable_workers($worker_ids; $task_id):
    [ $worker_ids[]? | select(covers_caps(.; task_caps($task_id)) and matches_tool(.; task_tool($task_id))) ];
  def capability_only_workers($worker_ids; $task_id):
    [ $worker_ids[]? | select(covers_caps(.; task_caps($task_id))) ];
  {
    usable_preferred_worker_ids: usable_preferred,
    broader_candidate_worker_ids: broader_workers,
    task_analysis: [
      task_ids[] as $task_id
      | {
          task_id: $task_id,
          required_capabilities: (task_caps($task_id) // []),
          required_toolchain_fingerprint: (task_tool($task_id) // "unknown"),
          preferred_viable_workers: viable_workers(usable_preferred; $task_id),
          broader_viable_workers: viable_workers(broader_workers; $task_id),
          broader_capability_only_workers: capability_only_workers(broader_workers; $task_id),
          capability_requirement_present: (task_caps($task_id) != null),
          toolchain_requirement_present: (task_tool($task_id) != null)
        }
    ]
  }
  ' >"$routing_analysis_path"

missing_required_capability_task_ids_json="$(jq -c '[.task_analysis[] | select((.capability_requirement_present | not) or (.broader_capability_only_workers | length) == 0) | .task_id] | unique' "$routing_analysis_path")"
toolchain_mismatch_task_ids_json="$(jq -c '[.task_analysis[] | select(.capability_requirement_present and .toolchain_requirement_present and (.broader_capability_only_workers | length) > 0 and (.broader_viable_workers | length) == 0) | .task_id] | unique' "$routing_analysis_path")"
broader_fallback_task_ids_json="$(jq -c '[.task_analysis[] | select((.preferred_viable_workers | length) == 0 and (.broader_viable_workers | length) > 0) | .task_id] | unique' "$routing_analysis_path")"
coverage_confirmed_task_ids_json="$(jq -c '[.task_analysis[] | select((.preferred_viable_workers | length) > 0) | .task_id] | unique' "$routing_analysis_path")"
preferred_viable_worker_ids_json="$(jq -c '[.task_analysis[].preferred_viable_workers[]?] | unique' "$routing_analysis_path")"
broader_viable_worker_ids_json="$(jq -c '[.task_analysis[].broader_viable_workers[]?] | unique' "$routing_analysis_path")"
required_capabilities_json="$(jq -c '[.task_analysis[].required_capabilities[]?] | unique' "$routing_analysis_path")"
required_toolchain_fingerprints_json="$(jq -c '[.task_analysis[].required_toolchain_fingerprint] | unique' "$routing_analysis_path")"

if jq -e 'length > 0' <<<"$missing_required_capability_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "missing_required_capability" "worker_capability_snapshot_json" "no non-excluded worker covers the required capabilities for one or more tasks"
fi
if jq -e 'length > 0' <<<"$toolchain_mismatch_task_ids_json" >/dev/null; then
  append_reason "$blocked_reasons_jsonl" "toolchain_fingerprint_mismatch" "worker_toolchain_snapshot_json" "non-excluded workers cover capabilities but do not satisfy the required toolchain fingerprint"
fi
if jq -e 'length > 0' <<<"$broader_fallback_task_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "broader_cohort_fallback" "rehabilitation_ledger_json" "preferred workers were excluded so a broader non-preferred cohort carried the advisory"
fi
if jq -e 'length > 0' <<<"$watch_worker_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "watch_workers_present" "rehabilitation_ledger_json" "watch-classified workers keep the routing advice in degraded mode"
fi
if jq -e 'length > 0' <<<"$rehab_candidate_worker_ids_json" >/dev/null; then
  append_reason "$degraded_reasons_jsonl" "rehab_candidates_present" "rehabilitation_ledger_json" "rehab-candidate workers keep the routing advice in degraded mode"
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

routing_mode="portable_fallback"
advised_worker_ids_json="$preferred_viable_worker_ids_json"
if [[ "$decision" == "fail_closed" ]]; then
  routing_mode="fail_closed"
  advised_worker_ids_json='[]'
elif [[ "$decision" == "blocked" ]]; then
  advised_worker_ids_json='[]'
  if jq -e 'length > 0' <<<"$toolchain_mismatch_task_ids_json" >/dev/null; then
    routing_mode="blocked_toolchain_mismatch"
  else
    routing_mode="blocked_missing_required_capability"
  fi
elif jq -e 'length > 0' <<<"$broader_fallback_task_ids_json" >/dev/null; then
  routing_mode="broader_cohort_fallback"
  advised_worker_ids_json="$broader_viable_worker_ids_json"
else
  routing_mode="capability_affinity_confirmed"
fi

queue_proof_transport_state="$(jq -r '
  if any(.tasks[]?; .proof_transport.local_fallback_detected == true) then "local_fallback_contaminated"
  elif any(.tasks[]?; (.proof_transport.state // "") != "remote_only_ok") then "degraded"
  else "remote_only_ok"
  end
' "$execution_queue_input_normalized")"

queue_task_count="$(jq '[.tasks[]?] | length' "$execution_queue_input_normalized")"
queue_schema_version="$(jq -r '.schema_version // "unknown"' "$execution_queue_input_normalized")"
topology_schema_version="$(jq -r '.schema_version // "unknown"' "$topology_queue_signal_input_normalized")"
rehab_schema_version="$(jq -r '.schema_version // "unknown"' "$rehabilitation_ledger_normalized")"
stall_schema_version="$(jq -r '.schema_version // "unknown"' "$rch_remote_compile_stall_bundle_normalized")"
capability_schema_version="$(jq -r '.schema_version // "unknown"' "$worker_capability_snapshot_normalized")"
toolchain_schema_version="$(jq -r '.schema_version // "unknown"' "$worker_toolchain_snapshot_normalized")"
resource_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$resource_envelope_normalized")"
operator_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$operator_status_snapshot_normalized")"

append_source_row "execution_queue_input_json" true true "$execution_queue_input_normalized" "$queue_schema_version" "$queue_proof_transport_state"
append_source_row "topology_queue_signal_input_json" true true "$topology_queue_signal_input_normalized" "$topology_schema_version" "$topology_truth_state"
append_source_row "rehabilitation_ledger_json" true true "$rehabilitation_ledger_normalized" "$rehab_schema_version" "$rehab_decision"
append_source_row "rch_remote_compile_stall_bundle_json" true true "$rch_remote_compile_stall_bundle_normalized" "$stall_schema_version" "$stall_truth_state"
append_source_row "worker_capability_snapshot_json" true true "$worker_capability_snapshot_normalized" "$capability_schema_version" "provided"
append_source_row "worker_toolchain_snapshot_json" true true "$worker_toolchain_snapshot_normalized" "$toolchain_schema_version" "provided"
append_source_row "resource_envelope_json" false "$([[ "$resource_envelope_status" == "provided" ]] && printf true || printf false)" "$resource_envelope_normalized" "$resource_schema_version" "$resource_envelope_status"
append_source_row "operator_status_snapshot_json" false "$([[ "$operator_status_snapshot_status" == "provided" ]] && printf true || printf false)" "$operator_status_snapshot_normalized" "$operator_schema_version" "$operator_status_snapshot_status"

jq -n \
  --arg schema_version "franken-engine.swarm-worker-capability-toolchain-input.v1" \
  --arg source_schema_version "franken-engine.swarm-worker-capability-toolchain-sources.v1" \
  --arg source_revision "$source_revision" \
  --arg truth_state "$truth_state" \
  --arg decision "$decision" \
  --arg queue_proof_transport_state "$queue_proof_transport_state" \
  --arg recommended_topology_class "$recommended_topology_class" \
  --arg routing_mode "$routing_mode" \
  --arg input_path "$input_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson queue_task_count "$queue_task_count" \
  --argjson preferred_worker_ids "$preferred_worker_ids_json" \
  --argjson excluded_worker_ids "$excluded_worker_ids_json" \
  --argjson watch_worker_ids "$watch_worker_ids_json" \
  --argjson rehab_candidate_worker_ids "$rehab_candidate_worker_ids_json" \
  --argjson required_capabilities "$required_capabilities_json" \
  --argjson required_toolchain_fingerprints "$required_toolchain_fingerprints_json" \
  --argjson advised_worker_ids "$advised_worker_ids_json" \
  --argjson coverage_confirmed_task_ids "$coverage_confirmed_task_ids_json" \
  --argjson missing_required_capability_task_ids "$missing_required_capability_task_ids_json" \
  --argjson toolchain_mismatch_task_ids "$toolchain_mismatch_task_ids_json" \
  --argjson broader_fallback_task_ids "$broader_fallback_task_ids_json" \
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
    topology_context:{
      recommended_topology_class:$recommended_topology_class,
      preferred_worker_ids:$preferred_worker_ids
    },
    rehabilitation_context:{
      excluded_worker_ids:$excluded_worker_ids,
      watch_worker_ids:$watch_worker_ids,
      rehab_candidate_worker_ids:$rehab_candidate_worker_ids
    },
    capability_context:{
      required_capabilities:$required_capabilities,
      coverage_confirmed_task_ids:$coverage_confirmed_task_ids,
      missing_required_capability_task_ids:$missing_required_capability_task_ids
    },
    toolchain_context:{
      required_toolchain_fingerprints:$required_toolchain_fingerprints,
      toolchain_mismatch_task_ids:$toolchain_mismatch_task_ids
    },
    routing_hints:{
      routing_mode:$routing_mode,
      advised_worker_ids:$advised_worker_ids,
      broader_fallback_task_ids:$broader_fallback_task_ids
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
      reroutes_tasks_automatically:false
    }
  }' >"$core_path"

routing_input_id="swarm-worker-capability-toolchain-$(jq -cS 'del(.artifact_paths,.source_artifacts)' "$core_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg routing_input_id "$routing_input_id" '. + {routing_input_id:$routing_input_id}' "$core_path" >"$input_tmp"
mv "$input_tmp" "$input_path"
jq '.source_artifacts' "$input_path" >"$sources_path"

write_event "normalized_input.written" "$decision" "$routing_mode" "$input_path"

{
  printf '# Swarm Worker Capability Toolchain Normalization\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Truth state: \`%s\`\n" "$truth_state"
  printf -- "- Routing mode: \`%s\`\n" "$routing_mode"
  printf -- "- Advised workers: \`%s\`\n" "$(jq -r '.routing_hints.advised_worker_ids | join(",")' "$input_path")"
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

printf 'swarm_worker_capability_toolchain_input_json=%s\n' "$input_path"
printf 'swarm_worker_capability_toolchain_sources_json=%s\n' "$sources_path"
printf 'swarm_worker_capability_toolchain_report_md=%s\n' "$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
if [[ "$decision" == "blocked" ]]; then
  exit 75
fi
exit 0
