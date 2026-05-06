#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_TOPOLOGY_PLACEMENT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-placement}"
run_id="${SWARM_TOPOLOGY_PLACEMENT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_PLACEMENT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bead_id="${SWARM_TOPOLOGY_PLACEMENT_BEAD_ID:-bd-3ynhq}"
source_revision="${SWARM_TOPOLOGY_PLACEMENT_SOURCE_REVISION:-unknown}"
reference_time="${SWARM_TOPOLOGY_PLACEMENT_REFERENCE_TIME:-}"
max_snapshot_age_seconds="${SWARM_TOPOLOGY_PLACEMENT_MAX_SNAPSHOT_AGE_SECONDS:-3600}"

host_topology_json=""
numa_evidence_json=""
worker_inventory_json=""
cache_residency_json=""
resource_envelope_json=""
execution_queue_input_json=""
tail_latency_evidence_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_topology_placement_normalizer.sh [OPTIONS]

Normalizes explicit topology, NUMA, worker, cache-residency, and queue-context
snapshots into the SWARM-SCALE-II topology-aware placement input. This script
is fixture-fed and advisory-only. It does not query live br, Agent Mail, rch,
Cargo, workers, or target directories.

Required snapshots:
  --host-topology-json FILE
  --numa-evidence-json FILE
  --worker-inventory-json FILE

Optional snapshots:
  --cache-residency-json FILE
  --resource-envelope-json FILE
  --execution-queue-input-json FILE
  --tail-latency-evidence-json FILE

Other options:
  --bead-id ID
  --source-revision REV
  --reference-time RFC3339
  --max-snapshot-age-seconds N
  --output-dir DIR

Artifacts:
  swarm_topology_placement_input.json
  swarm_topology_placement_sources.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  input is replayable; decision may be pass or degraded
  42 fail-closed due to malformed required topology, stale required topology,
     warm-cache claims without residency evidence, or local-fallback
     contamination
  64 invalid option or malformed threshold
  75 truthful locality evidence blocks confident placement advice
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --reference-time)
      reference_time="${2:-}"
      shift 2
      ;;
    --max-snapshot-age-seconds)
      max_snapshot_age_seconds="${2:-}"
      shift 2
      ;;
    --host-topology-json)
      host_topology_json="${2:-}"
      shift 2
      ;;
    --numa-evidence-json)
      numa_evidence_json="${2:-}"
      shift 2
      ;;
    --worker-inventory-json)
      worker_inventory_json="${2:-}"
      shift 2
      ;;
    --cache-residency-json)
      cache_residency_json="${2:-}"
      shift 2
      ;;
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
      shift 2
      ;;
    --execution-queue-input-json)
      execution_queue_input_json="${2:-}"
      shift 2
      ;;
    --tail-latency-evidence-json)
      tail_latency_evidence_json="${2:-}"
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
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

if [[ -z "$host_topology_json" || -z "$numa_evidence_json" || -z "$worker_inventory_json" ]]; then
  printf 'host topology, NUMA evidence, and worker inventory are required\n' >&2
  exit 64
fi
if ! is_int "$max_snapshot_age_seconds"; then
  printf 'max snapshot age must be a non-negative integer, got: %s\n' "$max_snapshot_age_seconds" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm topology placement normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm topology placement normalization\n' >&2
  exit 2
fi
if [[ -n "$reference_time" ]] && ! date -u -d "$reference_time" +%s >/dev/null 2>&1; then
  printf 'reference time must be parseable by date -u -d: %s\n' "$reference_time" >&2
  exit 64
fi

if [[ -n "$reference_time" ]]; then
  reference_epoch_seconds="$(date -u -d "$reference_time" +%s)"
else
  reference_epoch_seconds="$(date -u +%s)"
  reference_time="$(date -u -d "@${reference_epoch_seconds}" +%Y-%m-%dT%H:%M:%SZ)"
fi

mkdir -p "$run_dir"
input_path="${run_dir}/swarm_topology_placement_input.json"
input_tmp="${input_path}.tmp"
core_path="${run_dir}/swarm_topology_placement_input.core.json"
sources_path="${run_dir}/swarm_topology_placement_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
source_rows_jsonl="${run_dir}/source_rows.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

host_topology_normalized="${run_dir}/host_topology.normalized.json"
numa_evidence_normalized="${run_dir}/numa_evidence.normalized.json"
worker_inventory_normalized="${run_dir}/worker_inventory.normalized.json"
cache_residency_normalized="${run_dir}/cache_residency.normalized.json"
resource_envelope_normalized="${run_dir}/resource_envelope.normalized.json"
execution_queue_input_normalized="${run_dir}/execution_queue_input.normalized.json"
tail_latency_evidence_normalized="${run_dir}/tail_latency_evidence.normalized.json"

printf './scripts/swarm_topology_placement_normalizer.sh' >"$commands_path"
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
    --arg schema_version "franken-engine.swarm-topology-placement-normalizer.event.v1" \
    --arg component "swarm_topology_placement_normalizer" \
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
  jq -nc \
    --arg code "$code" \
    --arg source_id "$source_id" \
    --arg detail "$detail" \
    '{code:$code,source_id:$source_id,detail:$detail}' >>"$path"
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
  write_event "input.loaded" "provided" "$label" "$input_path"
}

normalize_optional_json() {
  local input_path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  if [[ -z "$input_path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    write_event "input.loaded" "missing_optional" "$label" "$output_path"
    printf 'missing'
    return
  fi
  if [[ ! -f "$input_path" ]]; then
    printf 'missing optional %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid optional %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "input.loaded" "provided" "$label" "$input_path"
  printf 'provided'
}

check_shape() {
  local file="$1"
  local expr="$2"
  local source_id="$3"
  local code="$4"
  local detail="$5"
  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    append_reason "$fail_closed_reasons_jsonl" "$code" "$source_id" "$detail"
  fi
}

observed_epoch_from_file() {
  local file="$1"
  jq -r '
    def parse_epoch:
      if type == "number" then .
      elif type == "string" and test("^[0-9]+$") then tonumber
      elif type == "string" then (fromdateiso8601? // empty)
      else empty end;
    (.observed_at // .generated_epoch_seconds // empty) | parse_epoch
  ' "$file"
}

freshness_state_for() {
  local status="$1"
  local observed_epoch="$2"
  local required="$3"
  if [[ "$status" == "missing" ]]; then
    printf '%s' "missing_optional"
  elif [[ -z "$observed_epoch" ]]; then
    if [[ "$required" == "true" ]]; then
      printf '%s' "unknown"
    else
      printf '%s' "missing_optional"
    fi
  elif (( reference_epoch_seconds - observed_epoch > max_snapshot_age_seconds )); then
    printf '%s' "stale"
  else
    printf '%s' "fresh"
  fi
}

append_source_row() {
  local source_id="$1"
  local required="$2"
  local provided="$3"
  local artifact_path="$4"
  local schema_version="$5"
  local observed_epoch="$6"
  local freshness_state="$7"
  local trust_state="$8"
  jq -nc \
    --arg source_id "$source_id" \
    --arg artifact_path "$artifact_path" \
    --arg schema_version "$schema_version" \
    --arg trust_state "$trust_state" \
    --arg freshness_state "$freshness_state" \
    --argjson required "$required" \
    --argjson provided "$provided" \
    --argjson observed_epoch_seconds "${observed_epoch:-null}" \
    '{
      source_id:$source_id,
      required:$required,
      provided:$provided,
      artifact_path:$artifact_path,
      schema_version:$schema_version,
      observed_epoch_seconds:$observed_epoch_seconds,
      freshness_state:$freshness_state,
      trust_state:$trust_state
    }' >>"$source_rows_jsonl"
}

host_topology_status="provided"
numa_evidence_status="provided"
worker_inventory_status="provided"
cache_residency_status="$(normalize_optional_json "$cache_residency_json" '{}' "$cache_residency_normalized" 'cache residency')"
resource_envelope_status="$(normalize_optional_json "$resource_envelope_json" '{}' "$resource_envelope_normalized" 'resource envelope')"
execution_queue_input_status="$(normalize_optional_json "$execution_queue_input_json" '{}' "$execution_queue_input_normalized" 'execution queue input')"
tail_latency_evidence_status="$(normalize_optional_json "$tail_latency_evidence_json" '{}' "$tail_latency_evidence_normalized" 'tail latency evidence')"

normalize_required_json "$host_topology_json" "$host_topology_normalized" 'host topology'
normalize_required_json "$numa_evidence_json" "$numa_evidence_normalized" 'NUMA evidence'
normalize_required_json "$worker_inventory_json" "$worker_inventory_normalized" 'worker inventory'

check_shape "$host_topology_normalized" '
  type == "object"
  and ((.host_id // "") | type == "string" and length > 0)
  and ((.topology_id // "") | type == "string" and length > 0)
  and ((.architecture // "") | type == "string" and length > 0)
  and ((.cpu_logical_cores // null) | type == "number")
  and ((.cpu_physical_cores // null) | type == "number")
  and ((.numa_nodes // null) | type == "number")
  and ((.observed_at // "") | type == "string" and length > 0)
' "host_topology_json" "malformed_topology_snapshot" "host topology lacks required fields"

check_shape "$numa_evidence_normalized" '
  type == "object"
  and ((.host_id // "") | type == "string" and length > 0)
  and ((.node_count // null) | type == "number")
  and ((.local_access_fraction_millionths // null) | type == "number")
  and ((.latency_penalty_millionths // null) | type == "number")
  and ((.preferred_numa_nodes // []) | type == "array")
  and ((.observed_at // "") | type == "string" and length > 0)
' "numa_evidence_json" "malformed_topology_snapshot" "NUMA evidence lacks required fields"

check_shape "$worker_inventory_normalized" '
  type == "object"
  and ((.host_id // "") | type == "string" and length > 0)
  and ((.workers // null) | type == "array")
  and ((.observed_at // "") | type == "string" and length > 0)
  and all(.workers[]?;
    ((.worker_id // "") | type == "string" and length > 0)
    and ((.numa_node // null) | type == "number")
  )
' "worker_inventory_json" "malformed_topology_snapshot" "worker inventory lacks required fields"

if [[ "$cache_residency_status" == "provided" ]]; then
  check_shape "$cache_residency_normalized" '
    type == "object"
    and ((.host_id // "") | type == "string" and length > 0)
    and ((.hot_worker_ids // []) | type == "array")
    and ((.target_dirs // []) | type == "array")
    and ((.observed_at // "") | type == "string" and length > 0)
  ' "cache_residency_json" "malformed_topology_snapshot" "cache residency hint is malformed"
fi
if [[ "$resource_envelope_status" == "provided" ]]; then
  check_shape "$resource_envelope_normalized" '
    type == "object"
    and ((.decision // "") | type == "string" and length > 0)
    and ((.host_identity.host_id // "") | type == "string" and length > 0)
    and ((.observed_at // "") | type == "string" and length > 0)
  ' "resource_envelope_json" "malformed_topology_snapshot" "resource envelope context is malformed"
fi
if [[ "$execution_queue_input_status" == "provided" ]]; then
  check_shape "$execution_queue_input_normalized" '
    type == "object"
    and ((.decision // "") | type == "string" and length > 0)
    and (((.generated_epoch_seconds // null) | type == "number") or ((.generated_epoch_seconds // "") | type == "string" and length > 0))
  ' "execution_queue_input_json" "malformed_topology_snapshot" "execution queue context is malformed"
fi
if [[ "$tail_latency_evidence_status" == "provided" ]]; then
  check_shape "$tail_latency_evidence_normalized" '
    type == "object"
    and ((.decision // "") | type == "string" and length > 0)
    and ((.observed_at // "") | type == "string" and length > 0)
  ' "tail_latency_evidence_json" "malformed_topology_snapshot" "tail latency locality context is malformed"
fi

host_id="$(jq -r '.host_id // ""' "$host_topology_normalized")"
topology_id="$(jq -r '.topology_id // ""' "$host_topology_normalized")"
architecture="$(jq -r '.architecture // ""' "$host_topology_normalized")"
cpu_logical_cores="$(jq -r '.cpu_logical_cores // 0' "$host_topology_normalized")"
cpu_physical_cores="$(jq -r '.cpu_physical_cores // 0' "$host_topology_normalized")"
numa_nodes="$(jq -r '.numa_nodes // 0' "$host_topology_normalized")"

numa_host_id="$(jq -r '.host_id // ""' "$numa_evidence_normalized")"
node_count="$(jq -r '.node_count // 0' "$numa_evidence_normalized")"
local_access_fraction_millionths="$(jq -r '.local_access_fraction_millionths // 0' "$numa_evidence_normalized")"
latency_penalty_millionths="$(jq -r '.latency_penalty_millionths // 0' "$numa_evidence_normalized")"
preferred_numa_nodes_json="$(jq -c '.preferred_numa_nodes // []' "$numa_evidence_normalized")"

worker_host_id="$(jq -r '.host_id // ""' "$worker_inventory_normalized")"
worker_count="$(jq '(.workers // []) | length' "$worker_inventory_normalized")"
ready_worker_count="$(jq '[.workers[]? | select((.state // "ready") == "ready")] | length' "$worker_inventory_normalized")"
claimed_hot_cache_workers_json="$(jq -c '.claimed_hot_cache_workers // []' "$worker_inventory_normalized")"
claimed_hot_cache_workers_count="$(jq '(.claimed_hot_cache_workers // []) | length' "$worker_inventory_normalized")"

cache_host_id=""
cache_truth_state="missing_optional"
cache_hot_worker_ids_json='[]'
cache_target_dirs_json='[]'
cache_hot_worker_count=0
if [[ "$cache_residency_status" == "provided" ]]; then
  cache_host_id="$(jq -r '.host_id // ""' "$cache_residency_normalized")"
  cache_truth_state="$(jq -r '.truth_state // "confirmed"' "$cache_residency_normalized")"
  cache_hot_worker_ids_json="$(jq -c '.hot_worker_ids // []' "$cache_residency_normalized")"
  cache_target_dirs_json="$(jq -c '.target_dirs // []' "$cache_residency_normalized")"
  cache_hot_worker_count="$(jq '(.hot_worker_ids // []) | length' "$cache_residency_normalized")"
fi

resource_envelope_host_id=""
resource_envelope_decision="missing_optional"
if [[ "$resource_envelope_status" == "provided" ]]; then
  resource_envelope_host_id="$(jq -r '.host_identity.host_id // ""' "$resource_envelope_normalized")"
  resource_envelope_decision="$(jq -r '.decision // "unknown"' "$resource_envelope_normalized")"
fi

execution_queue_decision="missing_optional"
execution_queue_proof_transport_state="missing_optional"
if [[ "$execution_queue_input_status" == "provided" ]]; then
  execution_queue_decision="$(jq -r '.decision // "unknown"' "$execution_queue_input_normalized")"
  execution_queue_proof_transport_state="$(jq -r '.proof_transport_state // "unknown"' "$execution_queue_input_normalized")"
fi

tail_latency_decision="missing_optional"
tail_latency_locality_domain="missing_optional"
if [[ "$tail_latency_evidence_status" == "provided" ]]; then
  tail_latency_decision="$(jq -r '.decision // "unknown"' "$tail_latency_evidence_normalized")"
  tail_latency_locality_domain="$(jq -r '.locality_domain // "unknown"' "$tail_latency_evidence_normalized")"
fi

host_observed_epoch="$(observed_epoch_from_file "$host_topology_normalized")"
numa_observed_epoch="$(observed_epoch_from_file "$numa_evidence_normalized")"
worker_observed_epoch="$(observed_epoch_from_file "$worker_inventory_normalized")"
cache_observed_epoch="$(observed_epoch_from_file "$cache_residency_normalized")"
resource_observed_epoch="$(observed_epoch_from_file "$resource_envelope_normalized")"
queue_observed_epoch="$(observed_epoch_from_file "$execution_queue_input_normalized")"
tail_observed_epoch="$(observed_epoch_from_file "$tail_latency_evidence_normalized")"

host_freshness_state="$(freshness_state_for "$host_topology_status" "$host_observed_epoch" true)"
numa_freshness_state="$(freshness_state_for "$numa_evidence_status" "$numa_observed_epoch" true)"
worker_freshness_state="$(freshness_state_for "$worker_inventory_status" "$worker_observed_epoch" true)"
cache_freshness_state="$(freshness_state_for "$cache_residency_status" "$cache_observed_epoch" false)"
resource_freshness_state="$(freshness_state_for "$resource_envelope_status" "$resource_observed_epoch" false)"
queue_freshness_state="$(freshness_state_for "$execution_queue_input_status" "$queue_observed_epoch" false)"
tail_freshness_state="$(freshness_state_for "$tail_latency_evidence_status" "$tail_observed_epoch" false)"

for tuple in \
  "host_topology_json:$host_observed_epoch:$host_freshness_state:host topology" \
  "numa_evidence_json:$numa_observed_epoch:$numa_freshness_state:NUMA evidence" \
  "worker_inventory_json:$worker_observed_epoch:$worker_freshness_state:worker inventory"
do
  IFS=':' read -r source_id observed_epoch freshness_state label <<<"$tuple"
  if [[ -z "$observed_epoch" ]]; then
    append_reason "$fail_closed_reasons_jsonl" "missing_required_topology_snapshot" "$source_id" "${label} lacks a parseable observed timestamp"
  elif [[ "$freshness_state" == "stale" ]]; then
    append_reason "$fail_closed_reasons_jsonl" "stale_required_topology_snapshot" "$source_id" "${label} is stale relative to reference time"
  fi
done

if jq -e --argjson max_nodes "$numa_nodes" '
  any(.workers[]?;
    ((.numa_node | floor) != .numa_node)
    or (.numa_node < 0)
    or (.numa_node >= $max_nodes)
  )
' "$worker_inventory_normalized" >/dev/null 2>&1; then
  append_reason "$fail_closed_reasons_jsonl" "malformed_topology_snapshot" "worker_inventory_json" "worker inventory references an out-of-range NUMA node"
fi

if [[ ! ( "$host_id" == "$numa_host_id" && "$host_id" == "$worker_host_id" ) ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_locality_evidence" "required_topology" "required topology snapshots disagree on host identity"
fi
if [[ "$numa_nodes" != "$node_count" ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_locality_evidence" "required_topology" "host topology NUMA count disagrees with NUMA evidence node count"
fi
if [[ "$cache_residency_status" == "provided" && "$cache_host_id" != "$host_id" ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_locality_evidence" "cache_residency_json" "cache residency snapshot host does not match required topology host"
fi
if [[ "$resource_envelope_status" == "provided" && "$resource_envelope_host_id" != "$host_id" ]]; then
  append_reason "$blocked_reasons_jsonl" "contradictory_locality_evidence" "resource_envelope_json" "resource envelope host does not match required topology host"
fi

if [[ "$cache_residency_status" != "provided" && "$claimed_hot_cache_workers_count" -gt 0 ]]; then
  append_reason "$fail_closed_reasons_jsonl" "warm_cache_claim_without_residency_evidence" "worker_inventory_json" "worker inventory claims hot-cache workers without a residency snapshot"
fi
if [[ "$cache_residency_status" == "provided" && "$cache_freshness_state" == "stale" && "$claimed_hot_cache_workers_count" -gt 0 ]]; then
  append_reason "$fail_closed_reasons_jsonl" "warm_cache_claim_without_residency_evidence" "cache_residency_json" "hot-cache worker claims rely on stale residency evidence"
fi

if [[ "$cache_residency_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "cache_residency_json" "cache residency hints are missing"
elif [[ "$cache_freshness_state" == "stale" ]]; then
  append_reason "$degraded_reasons_jsonl" "stale_optional_source" "cache_residency_json" "cache residency hints are stale"
fi
if [[ "$resource_envelope_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "resource_envelope_json" "resource envelope context is missing"
elif [[ "$resource_freshness_state" == "stale" ]]; then
  append_reason "$degraded_reasons_jsonl" "stale_optional_source" "resource_envelope_json" "resource envelope context is stale"
fi
if [[ "$execution_queue_input_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "execution_queue_input_json" "execution queue context is missing"
elif [[ "$queue_freshness_state" == "stale" ]]; then
  append_reason "$degraded_reasons_jsonl" "stale_optional_source" "execution_queue_input_json" "execution queue context is stale"
fi
if [[ "$tail_latency_evidence_status" == "missing" ]]; then
  append_reason "$degraded_reasons_jsonl" "missing_optional_source" "tail_latency_evidence_json" "tail latency locality context is missing"
elif [[ "$tail_freshness_state" == "stale" ]]; then
  append_reason "$degraded_reasons_jsonl" "stale_optional_source" "tail_latency_evidence_json" "tail latency locality context is stale"
fi

if [[ "$resource_envelope_decision" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "resource_envelope_blocks_locality" "resource_envelope_json" "resource envelope already blocks additional placement confidence"
fi
if [[ "$tail_latency_decision" == "blocked" ]]; then
  append_reason "$blocked_reasons_jsonl" "tail_latency_blocks_locality" "tail_latency_evidence_json" "tail latency locality context is already blocked"
fi
if [[ "$execution_queue_decision" == "fail_closed" ]]; then
  append_reason "$degraded_reasons_jsonl" "queue_context_untrusted" "execution_queue_input_json" "execution queue context is present but not trustworthy"
fi

if [[ "$cache_truth_state" == "contaminated" ]] \
  || [[ "$resource_envelope_decision" == "fail_closed" ]] \
  || [[ "$execution_queue_proof_transport_state" == *local*fallback* ]] \
  || jq -e '.local_fallback_detected == true' "$tail_latency_evidence_normalized" >/dev/null 2>&1
then
  append_reason "$fail_closed_reasons_jsonl" "rch_local_fallback_contaminates_locality" "optional_context" "local fallback contamination invalidates remote-only placement evidence"
fi

cache_residency_provided=false
resource_envelope_provided=false
execution_queue_input_provided=false
tail_latency_evidence_provided=false
if [[ "$cache_residency_status" == "provided" ]]; then
  cache_residency_provided=true
fi
if [[ "$resource_envelope_status" == "provided" ]]; then
  resource_envelope_provided=true
fi
if [[ "$execution_queue_input_status" == "provided" ]]; then
  execution_queue_input_provided=true
fi
if [[ "$tail_latency_evidence_status" == "provided" ]]; then
  tail_latency_evidence_provided=true
fi

host_schema_version="$(jq -r '.schema_version // "unknown"' "$host_topology_normalized")"
numa_schema_version="$(jq -r '.schema_version // "unknown"' "$numa_evidence_normalized")"
worker_schema_version="$(jq -r '.schema_version // "unknown"' "$worker_inventory_normalized")"
cache_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$cache_residency_normalized")"
resource_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$resource_envelope_normalized")"
queue_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$execution_queue_input_normalized")"
tail_schema_version="$(jq -r '.schema_version // (if type == "object" and length == 0 then "missing_optional" else "unknown" end)' "$tail_latency_evidence_normalized")"

append_source_row "host_topology_json" true true "$host_topology_normalized" "$host_schema_version" "$host_observed_epoch" "$host_freshness_state" "primary"
append_source_row "numa_evidence_json" true true "$numa_evidence_normalized" "$numa_schema_version" "$numa_observed_epoch" "$numa_freshness_state" "primary"
append_source_row "worker_inventory_json" true true "$worker_inventory_normalized" "$worker_schema_version" "$worker_observed_epoch" "$worker_freshness_state" "primary"
append_source_row "cache_residency_json" false "$cache_residency_provided" "$cache_residency_normalized" "$cache_schema_version" "$cache_observed_epoch" "$cache_freshness_state" "$cache_truth_state"
append_source_row "resource_envelope_json" false "$resource_envelope_provided" "$resource_envelope_normalized" "$resource_schema_version" "$resource_observed_epoch" "$resource_freshness_state" "$resource_envelope_decision"
append_source_row "execution_queue_input_json" false "$execution_queue_input_provided" "$execution_queue_input_normalized" "$queue_schema_version" "$queue_observed_epoch" "$queue_freshness_state" "$execution_queue_decision"
append_source_row "tail_latency_evidence_json" false "$tail_latency_evidence_provided" "$tail_latency_evidence_normalized" "$tail_schema_version" "$tail_observed_epoch" "$tail_freshness_state" "$tail_latency_decision"

fail_closed_count="$(wc -l <"$fail_closed_reasons_jsonl" | tr -d ' ')"
blocked_count="$(wc -l <"$blocked_reasons_jsonl" | tr -d ' ')"
degraded_count="$(wc -l <"$degraded_reasons_jsonl" | tr -d ' ')"

truth_state="confirmed"
decision="pass"
if [[ "$fail_closed_count" -gt 0 ]]; then
  if grep -Fq '"code":"rch_local_fallback_contaminates_locality"' "$fail_closed_reasons_jsonl"; then
    truth_state="contaminated"
  else
    truth_state="blocked"
  fi
  decision="fail_closed"
elif [[ "$blocked_count" -gt 0 ]]; then
  truth_state="blocked"
  decision="blocked"
elif [[ "$degraded_count" -gt 0 ]]; then
  truth_state="degraded"
  decision="degraded"
fi

preferred_ready_workers_json="$(jq -c --argjson nodes "$preferred_numa_nodes_json" '
  [.workers[]?
    | select((.state // "ready") == "ready")
    | .numa_node as $node
    | select(($nodes | index($node)) != null)
    | .worker_id
  ]
' "$worker_inventory_normalized")"

recommended_topology_class="portable_fallback"
if [[ "$decision" == "fail_closed" ]]; then
  recommended_topology_class="unknown"
elif [[ "$decision" == "blocked" ]]; then
  recommended_topology_class="contradictory_locality"
elif [[ "$local_access_fraction_millionths" -ge 950000 && "$cache_hot_worker_count" -gt 0 ]]; then
  recommended_topology_class="numa_local_hot_cache"
elif [[ "$local_access_fraction_millionths" -ge 900000 ]]; then
  recommended_topology_class="numa_local"
elif [[ "$cache_hot_worker_count" -gt 0 ]]; then
  recommended_topology_class="hot_cache_preferring"
fi

preferred_worker_ids_json="$preferred_ready_workers_json"
if [[ "$cache_hot_worker_count" -gt 0 ]]; then
  preferred_worker_ids_json="$cache_hot_worker_ids_json"
fi

warm_cache_residency_state="missing_optional"
if [[ "$cache_residency_status" == "provided" ]]; then
  if [[ "$cache_freshness_state" == "stale" ]]; then
    warm_cache_residency_state="stale"
  elif [[ "$cache_hot_worker_count" -gt 0 ]]; then
    warm_cache_residency_state="hot"
  else
    warm_cache_residency_state="cold"
  fi
fi

jq -n \
  --arg schema_version "franken-engine.swarm-topology-placement-input.v1" \
  --arg source_schema_version "franken-engine.swarm-topology-placement-sources.v1" \
  --arg source_revision "$source_revision" \
  --arg bead_id "$bead_id" \
  --arg reference_time "$reference_time" \
  --arg truth_state "$truth_state" \
  --arg decision "$decision" \
  --arg topology_id "$topology_id" \
  --arg host_id "$host_id" \
  --arg architecture "$architecture" \
  --arg recommended_topology_class "$recommended_topology_class" \
  --arg warm_cache_residency_state "$warm_cache_residency_state" \
  --arg resource_envelope_decision "$resource_envelope_decision" \
  --arg execution_queue_decision "$execution_queue_decision" \
  --arg execution_queue_proof_transport_state "$execution_queue_proof_transport_state" \
  --arg tail_latency_decision "$tail_latency_decision" \
  --arg tail_latency_locality_domain "$tail_latency_locality_domain" \
  --arg input_path "$input_path" \
  --arg sources_path "$sources_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson reference_epoch_seconds "$reference_epoch_seconds" \
  --argjson cpu_logical_cores "$cpu_logical_cores" \
  --argjson cpu_physical_cores "$cpu_physical_cores" \
  --argjson numa_nodes "$numa_nodes" \
  --argjson node_count "$node_count" \
  --argjson local_access_fraction_millionths "$local_access_fraction_millionths" \
  --argjson latency_penalty_millionths "$latency_penalty_millionths" \
  --argjson worker_count "$worker_count" \
  --argjson ready_worker_count "$ready_worker_count" \
  --argjson preferred_numa_nodes "$preferred_numa_nodes_json" \
  --argjson claimed_hot_cache_workers "$claimed_hot_cache_workers_json" \
  --argjson preferred_worker_ids "$preferred_worker_ids_json" \
  --argjson hot_worker_ids "$cache_hot_worker_ids_json" \
  --argjson hot_target_dirs "$cache_target_dirs_json" \
  --slurpfile sources "$source_rows_jsonl" \
  --slurpfile degraded_reasons "$degraded_reasons_jsonl" \
  --slurpfile blocked_reasons "$blocked_reasons_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    bead_id:$bead_id,
    reference_time:$reference_time,
    reference_epoch_seconds:$reference_epoch_seconds,
    truth_state:$truth_state,
    decision:$decision,
    host_identity:{
      host_id:$host_id,
      topology_id:$topology_id,
      architecture:$architecture,
      cpu_logical_cores:$cpu_logical_cores,
      cpu_physical_cores:$cpu_physical_cores,
      numa_nodes:$numa_nodes
    },
    numa_summary:{
      node_count:$node_count,
      preferred_numa_nodes:$preferred_numa_nodes,
      local_access_fraction_millionths:$local_access_fraction_millionths,
      latency_penalty_millionths:$latency_penalty_millionths
    },
    worker_inventory:{
      worker_count:$worker_count,
      ready_worker_count:$ready_worker_count,
      claimed_hot_cache_workers:$claimed_hot_cache_workers
    },
    warm_cache_residency:{
      state:$warm_cache_residency_state,
      hot_worker_ids:$hot_worker_ids,
      hot_target_dirs:$hot_target_dirs
    },
    context:{
      resource_envelope_decision:$resource_envelope_decision,
      execution_queue_decision:$execution_queue_decision,
      execution_queue_proof_transport_state:$execution_queue_proof_transport_state,
      tail_latency_decision:$tail_latency_decision,
      tail_latency_locality_domain:$tail_latency_locality_domain
    },
    placement_hints:{
      recommended_topology_class:$recommended_topology_class,
      preferred_numa_nodes:$preferred_numa_nodes,
      preferred_worker_ids:$preferred_worker_ids
    },
    degraded_reasons:$degraded_reasons,
    blocked_reasons:$blocked_reasons,
    fail_closed_reasons:$fail_closed_reasons,
    source_artifacts:{
      schema_version:$source_schema_version,
      rows:$sources
    },
    artifact_paths:{
      input_json:$input_path,
      sources_json:$sources_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_path
    },
    mutation_policy:{
      fixture_fed_only:true,
      proof_only:true,
      advisory_only:true,
      mutates_br:false,
      reassigns_beads:false,
      releases_reservations:false,
      sends_agent_mail:false,
      queries_live_agent_mail:false,
      runs_cargo:false,
      runs_rch:false,
      mutates_remote_workers:false,
      changes_live_queue_policy:false,
      pins_workers_automatically:false,
      rebinds_hosts_automatically:false
    }
  }' >"$core_path"

placement_input_id="swarm-topology-placement-$(jq -cS 'del(.artifact_paths,.source_artifacts)' "$core_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg placement_input_id "$placement_input_id" '. + {placement_input_id:$placement_input_id}' "$core_path" >"$input_tmp"
mv "$input_tmp" "$input_path"
jq '.source_artifacts' "$input_path" >"$sources_path"

write_event "artifact.written" "ok" "normalized topology placement input" "$input_path"

{
  printf '# Swarm Topology Placement Normalization\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Truth state: \`%s\`\n" "$truth_state"
  printf -- "- Host: \`%s\` (\`%s\`)\n" "$host_id" "$topology_id"
  printf -- "- Recommended topology class: \`%s\`\n" "$recommended_topology_class"
  printf -- "- Preferred workers: \`%s\`\n" "$(jq -r '.placement_hints.preferred_worker_ids | join(",")' "$input_path")"
  printf -- "- Warm-cache state: \`%s\`\n\n" "$warm_cache_residency_state"

  if [[ "$degraded_count" -gt 0 ]]; then
    printf '## Degraded Reasons\n'
    jq -r '.degraded_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$input_path"
    printf '\n'
  fi
  if [[ "$blocked_count" -gt 0 ]]; then
    printf '## Blocked Reasons\n'
    jq -r '.blocked_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$input_path"
    printf '\n'
  fi
  if [[ "$fail_closed_count" -gt 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$input_path"
    printf '\n'
  fi
} >"$report_path"

printf 'swarm_topology_placement_input_json=%s\n' "$input_path"
printf 'swarm_topology_placement_sources_json=%s\n' "$sources_path"
printf 'swarm_topology_placement_report_md=%s\n' "$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
if [[ "$decision" == "blocked" ]]; then
  exit 75
fi
exit 0
