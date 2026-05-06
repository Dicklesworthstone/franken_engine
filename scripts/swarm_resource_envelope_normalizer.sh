#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_RESOURCE_ENVELOPE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-resource-envelope}"
run_id="${SWARM_RESOURCE_ENVELOPE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RESOURCE_ENVELOPE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bead_id="${SWARM_RESOURCE_ENVELOPE_BEAD_ID:-bd-3q66g}"
source_revision="${SWARM_RESOURCE_ENVELOPE_SOURCE_REVISION:-unknown}"
reference_time="${SWARM_RESOURCE_ENVELOPE_REFERENCE_TIME:-}"
max_snapshot_age_seconds="${SWARM_RESOURCE_ENVELOPE_MAX_SNAPSHOT_AGE_SECONDS:-3600}"
min_memory_available_bytes="${SWARM_RESOURCE_ENVELOPE_MIN_MEMORY_AVAILABLE_BYTES:-34359738368}"
min_target_dir_available_bytes="${SWARM_RESOURCE_ENVELOPE_MIN_TARGET_DIR_AVAILABLE_BYTES:-10737418240}"
min_remote_rch_slots="${SWARM_RESOURCE_ENVELOPE_MIN_REMOTE_RCH_SLOTS:-1}"

host_topology_json=""
memory_pressure_json=""
disk_pressure_json=""
rch_queue_status_json=""
rch_build_slot_json=""
proof_cache_plan_json=""
warm_target_prefetch_roi_json=""
archive_pressure_scoreboard_json=""
br_ready_json=""
br_in_progress_json=""
br_sync_status_json=""
bv_actionable_plan_json=""
agent_mail_file_reservations_json=""
declared_write_set_json=""
causal_trace_summary_json=""
validation_cost_hints_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_resource_envelope_normalizer.sh [OPTIONS]

Normalizes explicit host, RCH, bead, reservation, causal-trace, and validation
snapshots into the SWARM-SCALE-I resource envelope. This script is fixture-fed
only. It does not query live br, Agent Mail, rch, cargo, ps, df, or workers.

Required core snapshots:
  --host-topology-json FILE
  --memory-pressure-json FILE
  --disk-pressure-json FILE
  --rch-queue-status-json FILE

Optional snapshots:
  --rch-build-slot-json FILE
  --proof-cache-plan-json FILE
  --warm-target-prefetch-roi-json FILE
  --archive-pressure-scoreboard-json FILE
  --br-ready-json FILE
  --br-in-progress-json FILE
  --br-sync-status-json FILE
  --bv-actionable-plan-json FILE
  --agent-mail-file-reservations-json FILE
  --declared-write-set-json FILE
  --causal-trace-summary-json FILE
  --validation-cost-hints-json FILE

Other options:
  --bead-id ID
  --source-revision REV
  --reference-time RFC3339
  --max-snapshot-age-seconds N
  --min-memory-available-bytes N
  --min-target-dir-available-bytes N
  --min-remote-rch-slots N
  --output-dir DIR

Artifacts:
  swarm_resource_envelope_input.json
  swarm_resource_envelope_sources.json
  swarm_resource_envelope.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  envelope is replayable; decision may be pass or degraded
  42 fail-closed anomaly detected
  64 invalid option or malformed threshold
  75 trustworthy capacity evidence is blocked/saturated
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
    --min-memory-available-bytes)
      min_memory_available_bytes="${2:-}"
      shift 2
      ;;
    --min-target-dir-available-bytes)
      min_target_dir_available_bytes="${2:-}"
      shift 2
      ;;
    --min-remote-rch-slots)
      min_remote_rch_slots="${2:-}"
      shift 2
      ;;
    --host-topology-json)
      host_topology_json="${2:-}"
      shift 2
      ;;
    --memory-pressure-json)
      memory_pressure_json="${2:-}"
      shift 2
      ;;
    --disk-pressure-json)
      disk_pressure_json="${2:-}"
      shift 2
      ;;
    --rch-queue-status-json)
      rch_queue_status_json="${2:-}"
      shift 2
      ;;
    --rch-build-slot-json)
      rch_build_slot_json="${2:-}"
      shift 2
      ;;
    --proof-cache-plan-json)
      proof_cache_plan_json="${2:-}"
      shift 2
      ;;
    --warm-target-prefetch-roi-json)
      warm_target_prefetch_roi_json="${2:-}"
      shift 2
      ;;
    --archive-pressure-scoreboard-json)
      archive_pressure_scoreboard_json="${2:-}"
      shift 2
      ;;
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
    --br-sync-status-json)
      br_sync_status_json="${2:-}"
      shift 2
      ;;
    --bv-actionable-plan-json)
      bv_actionable_plan_json="${2:-}"
      shift 2
      ;;
    --agent-mail-file-reservations-json)
      agent_mail_file_reservations_json="${2:-}"
      shift 2
      ;;
    --declared-write-set-json)
      declared_write_set_json="${2:-}"
      shift 2
      ;;
    --causal-trace-summary-json)
      causal_trace_summary_json="${2:-}"
      shift 2
      ;;
    --validation-cost-hints-json)
      validation_cost_hints_json="${2:-}"
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

for threshold in max_snapshot_age_seconds min_memory_available_bytes min_target_dir_available_bytes min_remote_rch_slots; do
  value="${!threshold}"
  if ! is_int "$value"; then
    printf '%s must be a non-negative integer, got: %s\n' "$threshold" "$value" >&2
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm resource envelope normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm resource envelope normalization\n' >&2
  exit 2
fi
if [[ -n "$reference_time" ]] && ! date -u -d "$reference_time" +%s >/dev/null 2>&1; then
  printf 'reference time must be parseable by date -u -d: %s\n' "$reference_time" >&2
  exit 64
fi

mkdir -p "$run_dir"
input_path="${run_dir}/swarm_resource_envelope_input.json"
sources_path="${run_dir}/swarm_resource_envelope_sources.json"
envelope_path="${run_dir}/swarm_resource_envelope.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
blocked_reasons_jsonl="${run_dir}/blocked_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"
source_entries_jsonl="${run_dir}/source_entries.jsonl"

host_topology_normalized="${run_dir}/host_topology.normalized.json"
memory_pressure_normalized="${run_dir}/memory_pressure.normalized.json"
disk_pressure_normalized="${run_dir}/disk_pressure.normalized.json"
rch_queue_status_normalized="${run_dir}/rch_queue_status.normalized.json"
rch_build_slot_normalized="${run_dir}/rch_build_slot.normalized.json"
proof_cache_plan_normalized="${run_dir}/proof_cache_plan.normalized.json"
warm_target_prefetch_roi_normalized="${run_dir}/warm_target_prefetch_roi.normalized.json"
archive_pressure_scoreboard_normalized="${run_dir}/archive_pressure_scoreboard.normalized.json"
br_ready_normalized="${run_dir}/br_ready.normalized.json"
br_in_progress_normalized="${run_dir}/br_in_progress.normalized.json"
br_sync_status_normalized="${run_dir}/br_sync_status.normalized.json"
bv_actionable_plan_normalized="${run_dir}/bv_actionable_plan.normalized.json"
agent_mail_file_reservations_normalized="${run_dir}/agent_mail_file_reservations.normalized.json"
declared_write_set_normalized="${run_dir}/declared_write_set.normalized.json"
causal_trace_summary_normalized="${run_dir}/causal_trace_summary.normalized.json"
validation_cost_hints_normalized="${run_dir}/validation_cost_hints.normalized.json"

printf './scripts/swarm_resource_envelope_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$degraded_reasons_jsonl"
: >"$blocked_reasons_jsonl"
: >"$fail_closed_reasons_jsonl"
: >"$source_entries_jsonl"

emit_event() {
  local event="$1"
  local detail="$2"
  jq -cn --arg event "$event" --arg detail "$detail" \
    '{schema_version:"franken-engine.swarm-resource-envelope-normalizer-event.v1", event:$event, detail:$detail}' >>"$events_path"
}

record_problem() {
  local decision="$1"
  local code="$2"
  local message="$3"
  local source_id="$4"
  local output

  case "$decision" in
    degraded) output="$degraded_reasons_jsonl" ;;
    blocked) output="$blocked_reasons_jsonl" ;;
    fail_closed) output="$fail_closed_reasons_jsonl" ;;
    pass|"") return ;;
    *)
      printf 'unknown problem decision: %s\n' "$decision" >&2
      exit 64
      ;;
  esac

  jq -cn \
    --arg code "$code" \
    --arg message "$message" \
    --arg source_id "$source_id" \
    '{code:$code, message:$message, source_id:$source_id}' >>"$output"
  emit_event "$decision" "${source_id}:${code}"
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

write_default_json() {
  local default_json="$1"
  local output="$2"
  printf '%s\n' "$default_json" | jq -cS . >"$output"
}

append_source_entry() {
  local source_id="$1"
  local source_path="$2"
  local normalized_path="$3"
  local required="$4"
  local status="$5"
  local missing_decision="$6"
  local observed_at

  observed_at="$(jq -r 'if type == "object" then ((.observed_at // .timestamp // .captured_at // "") | tostring) else "" end' "$normalized_path")"
  jq -cn \
    --arg source_id "$source_id" \
    --arg source_path "$source_path" \
    --arg normalized_path "$normalized_path" \
    --arg content_hash "sha256:$(hash_file "$normalized_path")" \
    --arg status "$status" \
    --arg missing_decision "$missing_decision" \
    --arg observed_at "$observed_at" \
    --argjson required "$required" \
    '{
      source_id:$source_id,
      source_path:(if $source_path == "" then null else $source_path end),
      normalized_path:$normalized_path,
      content_hash:$content_hash,
      required:$required,
      status:$status,
      missing_decision:$missing_decision,
      observed_at:$observed_at
    }' >>"$source_entries_jsonl"
}

normalize_source_json() {
  local source_id="$1"
  local input="$2"
  local output="$3"
  local required="$4"
  local missing_decision="$5"
  local default_json="$6"
  local missing_code="$7"
  local label="$8"
  local status="provided"

  if [[ -z "$input" ]]; then
    write_default_json "$default_json" "$output"
    status="missing"
    record_problem "$missing_decision" "$missing_code" "${label} was not supplied" "$source_id"
  elif [[ ! -f "$input" ]]; then
    write_default_json "$default_json" "$output"
    status="missing"
    record_problem "$missing_decision" "$missing_code" "${label} path does not exist: ${input}" "$source_id"
  elif ! jq -cS . "$input" >"$output"; then
    write_default_json "$default_json" "$output"
    status="malformed"
    record_problem "$missing_decision" "$missing_code" "${label} was malformed JSON" "$source_id"
  else
    emit_event "source_loaded" "$source_id"
  fi

  append_source_entry "$source_id" "$input" "$output" "$required" "$status" "$missing_decision"
}

epoch_seconds() {
  date -u -d "$1" +%s 2>/dev/null
}

check_required_snapshot_freshness() {
  local source_id="$1"
  local normalized_path="$2"
  local observed_at
  local observed_epoch
  local reference_epoch
  local age

  observed_at="$(jq -r 'if type == "object" then ((.observed_at // .timestamp // .captured_at // "") | tostring) else "" end' "$normalized_path")"
  if [[ -z "$observed_at" || "$observed_at" == "null" ]]; then
    record_problem "fail_closed" "stale_required_capacity_snapshot" "${source_id} lacks observed_at evidence" "$source_id"
    return
  fi
  if ! observed_epoch="$(epoch_seconds "$observed_at")"; then
    record_problem "fail_closed" "stale_required_capacity_snapshot" "${source_id} observed_at is not parseable: ${observed_at}" "$source_id"
    return
  fi
  if [[ -z "$reference_time" ]]; then
    return
  fi
  reference_epoch="$(epoch_seconds "$reference_time")"
  age=$((reference_epoch - observed_epoch))
  if (( age < -300 )); then
    record_problem "fail_closed" "stale_required_capacity_snapshot" "${source_id} observed_at is in the future relative to reference time" "$source_id"
  elif (( age > max_snapshot_age_seconds )); then
    record_problem "fail_closed" "stale_required_capacity_snapshot" "${source_id} is stale by ${age} seconds" "$source_id"
  fi
}

normalize_source_json \
  "host_topology_json" \
  "$host_topology_json" \
  "$host_topology_normalized" \
  "true" \
  "fail_closed" \
  '{"schema_version":"franken-engine.host-topology-snapshot.v1","missing":true}' \
  "missing_required_host_identity" \
  "host topology snapshot"
normalize_source_json \
  "memory_pressure_json" \
  "$memory_pressure_json" \
  "$memory_pressure_normalized" \
  "true" \
  "fail_closed" \
  '{"schema_version":"franken-engine.memory-pressure-snapshot.v1","missing":true}' \
  "missing_required_capacity_snapshot" \
  "memory pressure snapshot"
normalize_source_json \
  "disk_pressure_json" \
  "$disk_pressure_json" \
  "$disk_pressure_normalized" \
  "true" \
  "fail_closed" \
  '{"schema_version":"franken-engine.disk-pressure-snapshot.v1","filesystems":[],"target_dirs":[],"missing":true}' \
  "missing_required_capacity_snapshot" \
  "disk pressure snapshot"
normalize_source_json \
  "rch_queue_status_json" \
  "$rch_queue_status_json" \
  "$rch_queue_status_normalized" \
  "true" \
  "blocked" \
  '{"schema_version":"franken-engine.rch-queue-status-snapshot.v1","workers":[],"build_slots":{},"missing":true}' \
  "rch_required_snapshot_missing" \
  "RCH queue/status snapshot"
normalize_source_json "rch_build_slot_json" "$rch_build_slot_json" "$rch_build_slot_normalized" "false" "degraded" '{"leases":[]}' "optional_snapshot_missing" "RCH build-slot snapshot"
normalize_source_json "proof_cache_plan_json" "$proof_cache_plan_json" "$proof_cache_plan_normalized" "false" "degraded" '{"proof_cache_decision":"missing"}' "optional_snapshot_missing" "proof cache plan"
normalize_source_json "warm_target_prefetch_roi_json" "$warm_target_prefetch_roi_json" "$warm_target_prefetch_roi_normalized" "false" "degraded" '{"advisory":"missing"}' "optional_snapshot_missing" "warm-target prefetch ROI advisory"
normalize_source_json "archive_pressure_scoreboard_json" "$archive_pressure_scoreboard_json" "$archive_pressure_scoreboard_normalized" "false" "degraded" '{"scoreboard_status":"missing"}' "optional_snapshot_missing" "archive pressure scoreboard"
normalize_source_json "br_ready_json" "$br_ready_json" "$br_ready_normalized" "false" "degraded" '[]' "optional_snapshot_missing" "br ready snapshot"
normalize_source_json "br_in_progress_json" "$br_in_progress_json" "$br_in_progress_normalized" "false" "degraded" '{"issues":[]}' "optional_snapshot_missing" "br in-progress snapshot"
normalize_source_json "br_sync_status_json" "$br_sync_status_json" "$br_sync_status_normalized" "false" "degraded" '{}' "optional_snapshot_missing" "br sync status snapshot"
normalize_source_json "bv_actionable_plan_json" "$bv_actionable_plan_json" "$bv_actionable_plan_normalized" "false" "degraded" '{"plan":{"tracks":[]}}' "optional_snapshot_missing" "bv actionable plan snapshot"
normalize_source_json "agent_mail_file_reservations_json" "$agent_mail_file_reservations_json" "$agent_mail_file_reservations_normalized" "false" "degraded" '{"reservations":[]}' "optional_snapshot_missing" "Agent Mail file reservations snapshot"
normalize_source_json "declared_write_set_json" "$declared_write_set_json" "$declared_write_set_normalized" "false" "degraded" '{"paths":[]}' "optional_snapshot_missing" "declared write set snapshot"
normalize_source_json "causal_trace_summary_json" "$causal_trace_summary_json" "$causal_trace_summary_normalized" "false" "degraded" '{"decision":"missing","anomalies":[]}' "optional_snapshot_missing" "causal trace summary"
normalize_source_json "validation_cost_hints_json" "$validation_cost_hints_json" "$validation_cost_hints_normalized" "false" "degraded" '{"commands":[]}' "optional_snapshot_missing" "validation cost hints snapshot"

check_required_snapshot_freshness "host_topology_json" "$host_topology_normalized"
check_required_snapshot_freshness "memory_pressure_json" "$memory_pressure_normalized"
check_required_snapshot_freshness "disk_pressure_json" "$disk_pressure_normalized"
check_required_snapshot_freshness "rch_queue_status_json" "$rch_queue_status_normalized"

if ! jq -e '
  type == "object"
  and ((.host_id // .hostname // "") | tostring | length > 0)
  and ((.cpu_logical_cores // 0) | type == "number")
  and ((.cpu_physical_cores // 0) | type == "number")
  and ((.numa_nodes // 0) | type == "number")
  and (.cpu_logical_cores >= .cpu_physical_cores)
  and (.cpu_physical_cores > 0)
  and (.numa_nodes > 0)
' "$host_topology_normalized" >/dev/null; then
  record_problem "fail_closed" "missing_required_host_identity" "host topology lacks coherent host identity or CPU topology" "host_topology_json"
fi

if ! jq -e '
  type == "object"
  and ((.total_bytes // 0) | type == "number")
  and ((.available_bytes // 0) | type == "number")
  and (.total_bytes > 0)
  and (.available_bytes >= 0)
  and (.available_bytes <= .total_bytes)
' "$memory_pressure_normalized" >/dev/null; then
  record_problem "fail_closed" "contradictory_cpu_or_memory_capacity" "memory totals are missing, non-numeric, or contradictory" "memory_pressure_json"
fi

if jq -e '.telemetry_complete? == false' "$memory_pressure_normalized" >/dev/null; then
  record_problem "degraded" "memory_or_disk_optional_telemetry_missing" "memory pressure snapshot reports incomplete optional telemetry" "memory_pressure_json"
fi

if jq -e '(.available_bytes // 0) < $min' --argjson min "$min_memory_available_bytes" "$memory_pressure_normalized" >/dev/null; then
  record_problem "blocked" "memory_pressure_below_safe_budget" "available memory is below the configured safety budget" "memory_pressure_json"
fi

if ! jq -e '
  type == "object"
  and ((.target_dirs // []) | type == "array")
  and ((.target_dirs // []) | length > 0)
  and all(.target_dirs[]; ((.available_bytes // .free_bytes // -1) | type == "number") and ((.available_bytes // .free_bytes // -1) >= 0))
' "$disk_pressure_normalized" >/dev/null; then
  record_problem "fail_closed" "target_dir_pressure_exceeds_safe_budget" "disk snapshot lacks coherent target-dir pressure evidence" "disk_pressure_json"
fi

if jq -e '.telemetry_complete? == false' "$disk_pressure_normalized" >/dev/null; then
  record_problem "degraded" "memory_or_disk_optional_telemetry_missing" "disk pressure snapshot reports incomplete optional telemetry" "disk_pressure_json"
fi

if jq -e '
  [(.target_dirs // [])[] | (.available_bytes // .free_bytes // 0)] as $bytes
  | ($bytes | length) == 0 or (($bytes | min) < $min)
' --argjson min "$min_target_dir_available_bytes" "$disk_pressure_normalized" >/dev/null; then
  record_problem "blocked" "target_dir_pressure_exceeds_safe_budget" "target-dir free bytes are below the configured safety budget" "disk_pressure_json"
fi

# rch-policy-waive: local_fallback_not_rejected reason=Fixture scanner rejects preserved fallback markers only
fallback_pattern='local fallback|\[RCH\] local|running locally'
if jq -s -e '
  any(.[]; ([.. | objects | select(.local_fallback_detected? == true)] | length > 0)
    or ([.. | scalars | tostring | select(test($fallback_pattern; "i"))] | length > 0))
' --arg fallback_pattern "$fallback_pattern" "$rch_queue_status_normalized" "$rch_build_slot_normalized" >/dev/null; then
  record_problem "fail_closed" "rch_local_fallback_contaminates_capacity" "RCH snapshots contain a local fallback marker" "rch_queue_status_json"
fi

if jq -e '
  def num($v): if ($v | type) == "number" then $v elif ($v | type) == "string" then ($v | tonumber? // 0) else 0 end;
  (.build_slots // {}) as $slots
  | ([.workers[]? | num(.slots_total // .slot_count // .total_slots // 0)] | add // 0) as $worker_total
  | num($slots.total // 0) as $slot_total
  | num($slots.available // 0) as $available
  | num($slots.active // 0) as $active
  | (($slot_total > 0 and $worker_total > 0 and $slot_total != $worker_total)
      or ($available > $slot_total)
      or ($active > $slot_total)
      or (($active + $available) > $slot_total))
' "$rch_queue_status_normalized" >/dev/null; then
  record_problem "fail_closed" "rch_slot_snapshot_contradiction" "RCH worker and build-slot counts are contradictory" "rch_queue_status_json"
fi

if jq -e '
  def num($v): if ($v | type) == "number" then $v elif ($v | type) == "string" then ($v | tonumber? // 0) else 0 end;
  (.build_slots // {}) as $slots
  | (num($slots.available // 0) < $min)
' --argjson min "$min_remote_rch_slots" "$rch_queue_status_normalized" >/dev/null; then
  record_problem "blocked" "rch_slots_saturated" "available remote RCH slots are below the configured minimum" "rch_queue_status_json"
fi

if jq -e '
  def num($v): if ($v | type) == "number" then $v elif ($v | type) == "string" then ($v | tonumber? // 0) else 0 end;
  ($host[0].cpu_logical_cores // 0) as $cores
  | (num($host[0].load_average_1m // 0) >= num($cores))
' --slurpfile host "$host_topology_normalized" "$host_topology_normalized" >/dev/null; then
  record_problem "blocked" "cpu_capacity_saturated" "CPU load is at or above logical core count" "host_topology_json"
fi

if jq -e '
  def reservation_rows:
    if type == "array" then .
    elif type == "object" and has("reservations") then .reservations
    elif type == "object" and has("granted") then .granted
    else [] end;
  def write_paths($w):
    if ($w | type) == "array" then $w
    elif ($w | type) == "object" and ($w | has("paths")) then $w.paths
    else [] end;
  (reservation_rows | length > 0) and ((write_paths($write[0]) | length) == 0)
' --slurpfile write "$declared_write_set_normalized" "$agent_mail_file_reservations_normalized" >/dev/null; then
  record_problem "fail_closed" "reservation_pressure_without_write_set" "reservation pressure was supplied without a declared write set" "agent_mail_file_reservations_json"
fi

if jq -e '
  ((.decision // "") | test("fail_closed|contaminated"; "i"))
  or ([.. | objects | select(((.severity // .decision // "") | test("fail_closed|contaminated"; "i")))] | length > 0)
' "$causal_trace_summary_normalized" >/dev/null; then
  record_problem "fail_closed" "causal_trace_contamination_blocks_admission" "causal trace summary contains contaminated or fail-closed evidence" "causal_trace_summary_json"
fi

if jq -e '
  def command_rows:
    if type == "array" then .
    elif type == "object" and has("commands") then .commands
    elif type == "object" and has("validations") then .validations
    else [] end;
  [command_rows[]
    | select((.cost_class // .command_kind // .kind // "") | test("heavy|cargo|rch|build|clippy|test"; "i"))
    | select((.budget_class // .budget_id // .cost_budget // "") == "")
  ] | length > 0
' "$validation_cost_hints_normalized" >/dev/null; then
  record_problem "fail_closed" "heavy_command_missing_budget" "heavy validation command lacks an explicit budget classification" "validation_cost_hints_json"
fi

for normalized_path in \
  "$host_topology_normalized" \
  "$memory_pressure_normalized" \
  "$disk_pressure_normalized" \
  "$rch_queue_status_normalized" \
  "$rch_build_slot_normalized" \
  "$proof_cache_plan_normalized" \
  "$warm_target_prefetch_roi_normalized" \
  "$archive_pressure_scoreboard_normalized" \
  "$br_ready_normalized" \
  "$br_in_progress_normalized" \
  "$br_sync_status_normalized" \
  "$bv_actionable_plan_normalized" \
  "$agent_mail_file_reservations_normalized" \
  "$declared_write_set_normalized" \
  "$causal_trace_summary_normalized" \
  "$validation_cost_hints_normalized"
do
  if jq -e '
    [.. | scalars | tostring
      | select(test("mutates live workers|runs cargo|runs rch|releases reservations|reassigns beads|deletes target directories|repairs stalled builds automatically|changes live queue policy"; "i"))
    ] | length > 0
  ' "$normalized_path" >/dev/null; then
    record_problem "fail_closed" "unsafe_live_mutation_claim" "source snapshot contains unsafe live-mutation wording" "$(basename "$normalized_path" .normalized.json)_json"
  fi
done

jq -s . "$degraded_reasons_jsonl" >"${run_dir}/degraded_reasons.json"
jq -s . "$blocked_reasons_jsonl" >"${run_dir}/blocked_reasons.json"
jq -s . "$fail_closed_reasons_jsonl" >"${run_dir}/fail_closed_reasons.json"

degraded_count="$(jq 'length' "${run_dir}/degraded_reasons.json")"
blocked_count="$(jq 'length' "${run_dir}/blocked_reasons.json")"
fail_count="$(jq 'length' "${run_dir}/fail_closed_reasons.json")"

decision="pass"
exit_code=0
if [[ "$fail_count" -gt 0 ]]; then
  decision="fail_closed"
  exit_code=42
elif [[ "$blocked_count" -gt 0 ]]; then
  decision="blocked"
  exit_code=75
elif [[ "$degraded_count" -gt 0 ]]; then
  decision="degraded"
fi

jq -s \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  '{
    schema_version:"franken-engine.swarm-resource-envelope-sources.v1",
    bead_id:$bead_id,
    source_revision:$source_revision,
    sources:.
  }' "$source_entries_jsonl" >"$sources_path"

source_fingerprint="$(jq -r '[.sources[] | .source_id + "=" + .content_hash] | sort | join("|")' "$sources_path")"
envelope_id="swarm-resource-envelope-$(printf '%s' "$source_fingerprint" | sha256sum | awk '{print substr($1,1,16)}')"
observed_at="$(jq -r '[.sources[] | select((.observed_at // "") != "") | .observed_at] | sort | last // ""' "$sources_path")"

# shellcheck disable=SC2094
jq -n \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg reference_time "$reference_time" \
  --arg max_snapshot_age_seconds "$max_snapshot_age_seconds" \
  --arg min_memory_available_bytes "$min_memory_available_bytes" \
  --arg min_target_dir_available_bytes "$min_target_dir_available_bytes" \
  --arg min_remote_rch_slots "$min_remote_rch_slots" \
  --arg host_topology_json "$host_topology_json" \
  --arg memory_pressure_json "$memory_pressure_json" \
  --arg disk_pressure_json "$disk_pressure_json" \
  --arg rch_queue_status_json "$rch_queue_status_json" \
  --arg rch_build_slot_json "$rch_build_slot_json" \
  --arg proof_cache_plan_json "$proof_cache_plan_json" \
  --arg warm_target_prefetch_roi_json "$warm_target_prefetch_roi_json" \
  --arg archive_pressure_scoreboard_json "$archive_pressure_scoreboard_json" \
  --arg br_ready_json "$br_ready_json" \
  --arg br_in_progress_json "$br_in_progress_json" \
  --arg br_sync_status_json "$br_sync_status_json" \
  --arg bv_actionable_plan_json "$bv_actionable_plan_json" \
  --arg agent_mail_file_reservations_json "$agent_mail_file_reservations_json" \
  --arg declared_write_set_json "$declared_write_set_json" \
  --arg causal_trace_summary_json "$causal_trace_summary_json" \
  --arg validation_cost_hints_json "$validation_cost_hints_json" \
  '{
    schema_version:"franken-engine.swarm-resource-envelope-input.v1",
    bead_id:$bead_id,
    source_revision:$source_revision,
    thresholds:{
      reference_time:(if $reference_time == "" then null else $reference_time end),
      max_snapshot_age_seconds:($max_snapshot_age_seconds | tonumber),
      min_memory_available_bytes:($min_memory_available_bytes | tonumber),
      min_target_dir_available_bytes:($min_target_dir_available_bytes | tonumber),
      min_remote_rch_slots:($min_remote_rch_slots | tonumber)
    },
    source_paths:{
      host_topology_json:$host_topology_json,
      memory_pressure_json:$memory_pressure_json,
      disk_pressure_json:$disk_pressure_json,
      rch_queue_status_json:$rch_queue_status_json,
      rch_build_slot_json:$rch_build_slot_json,
      proof_cache_plan_json:$proof_cache_plan_json,
      warm_target_prefetch_roi_json:$warm_target_prefetch_roi_json,
      archive_pressure_scoreboard_json:$archive_pressure_scoreboard_json,
      br_ready_json:$br_ready_json,
      br_in_progress_json:$br_in_progress_json,
      br_sync_status_json:$br_sync_status_json,
      bv_actionable_plan_json:$bv_actionable_plan_json,
      agent_mail_file_reservations_json:$agent_mail_file_reservations_json,
      declared_write_set_json:$declared_write_set_json,
      causal_trace_summary_json:$causal_trace_summary_json,
      validation_cost_hints_json:$validation_cost_hints_json
    }
  }' >"$input_path"

# shellcheck disable=SC2094
jq -n \
  --slurpfile host "$host_topology_normalized" \
  --slurpfile memory "$memory_pressure_normalized" \
  --slurpfile disk "$disk_pressure_normalized" \
  --slurpfile rch "$rch_queue_status_normalized" \
  --slurpfile proof "$proof_cache_plan_normalized" \
  --slurpfile br_ready "$br_ready_normalized" \
  --slurpfile br_in_progress "$br_in_progress_normalized" \
  --slurpfile reservations "$agent_mail_file_reservations_normalized" \
  --slurpfile causal "$causal_trace_summary_normalized" \
  --slurpfile validation "$validation_cost_hints_normalized" \
  --slurpfile degraded "${run_dir}/degraded_reasons.json" \
  --slurpfile blocked "${run_dir}/blocked_reasons.json" \
  --slurpfile fail_closed "${run_dir}/fail_closed_reasons.json" \
  --arg schema_version "franken-engine.swarm-resource-envelope.v1" \
  --arg envelope_id "$envelope_id" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg observed_at "$observed_at" \
  --arg decision "$decision" \
  --arg input_json "$input_path" \
  --arg sources_json "$sources_path" \
  --arg envelope_json "$envelope_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_path" \
  --argjson min_memory_available_bytes "$min_memory_available_bytes" \
  --argjson min_target_dir_available_bytes "$min_target_dir_available_bytes" \
  --argjson min_remote_rch_slots "$min_remote_rch_slots" \
  '
  def num($v): if ($v | type) == "number" then $v elif ($v | type) == "string" then ($v | tonumber? // 0) else 0 end;
  def rows($x; $field):
    if ($x | type) == "array" then $x
    elif ($x | type) == "object" and ($x | has($field)) then $x[$field]
    elif ($x | type) == "object" and ($x | has("issues")) then $x.issues
    else [] end;
  def min_or_zero($items): if ($items | length) == 0 then 0 else ($items | min) end;
  ($host[0]) as $h
  | ($memory[0]) as $m
  | ($disk[0]) as $d
  | ($rch[0]) as $r
  | ([($d.target_dirs // [])[] | num(.available_bytes // .free_bytes // 0)] | min_or_zero(.)) as $target_dir_available
  | (num($r.build_slots.total // 0)) as $rch_total
  | (num($r.build_slots.available // 0)) as $rch_available
  | (num($r.build_slots.active // 0)) as $rch_active
  | (if $decision == "pass" then "ready"
     elif $decision == "degraded" then "ready_degraded"
     elif $decision == "blocked" then "defer"
     else "not_ready" end) as $readiness
  | {
      schema_version:$schema_version,
      envelope_id:$envelope_id,
      bead_id:$bead_id,
      source_revision:$source_revision,
      observed_at:$observed_at,
      decision:$decision,
      readiness:$readiness,
      host_identity:{
        host_id:($h.host_id // $h.hostname // null),
        hostname:($h.hostname // null),
        architecture:($h.architecture // $h.arch // null),
        observed_at:($h.observed_at // null)
      },
      cpu_topology:{
        logical_cores:num($h.cpu_logical_cores // 0),
        physical_cores:num($h.cpu_physical_cores // 0),
        numa_nodes:num($h.numa_nodes // 0),
        load_average_1m:num($h.load_average_1m // 0)
      },
      memory_pressure:{
        total_bytes:num($m.total_bytes // 0),
        available_bytes:num($m.available_bytes // 0),
        swap_available_bytes:num($m.swap_available_bytes // 0),
        telemetry_complete:(if $m | has("telemetry_complete") then $m.telemetry_complete else true end),
        below_safe_budget:(num($m.available_bytes // 0) < $min_memory_available_bytes)
      },
      disk_pressure:{
        filesystems:($d.filesystems // []),
        target_dir_count:(($d.target_dirs // []) | length),
        telemetry_complete:(if $d | has("telemetry_complete") then $d.telemetry_complete else true end)
      },
      target_dir_pressure:{
        target_dirs:($d.target_dirs // []),
        min_available_bytes:$target_dir_available,
        below_safe_budget:($target_dir_available < $min_target_dir_available_bytes)
      },
      rch_slots:{
        workers:($r.workers // []),
        worker_count:(($r.workers // []) | length),
        build_slots:($r.build_slots // {}),
        total:$rch_total,
        active:$rch_active,
        available:$rch_available,
        below_required_remote_slots:($rch_available < $min_remote_rch_slots),
        queue_depth:num($r.queue_depth // 0)
      },
      proof_cache:{
        decision:($proof[0].proof_cache_decision // $proof[0].decision // "missing"),
        snapshot:$proof[0]
      },
      queue_pressure:{
        ready_count:(rows($br_ready[0]; "issues") | length),
        in_progress_count:(rows($br_in_progress[0]; "issues") | length),
        ready_preview:(rows($br_ready[0]; "issues") | map({id:(.id // null), priority:(.priority // null), status:(.status // null)}) | .[0:8])
      },
      reservation_pressure:{
        reservation_count:(rows($reservations[0]; "reservations") | length),
        holders:(rows($reservations[0]; "reservations") | map(.agent_name // .holder // empty) | unique)
      },
      causal_trace_pressure:{
        decision:($causal[0].decision // "missing"),
        anomaly_count:(rows($causal[0]; "anomalies") | length)
      },
      validation_cost_pressure:{
        command_count:(rows($validation[0]; "commands") | length),
        heavy_command_count:([rows($validation[0]; "commands")[] | select((.cost_class // .command_kind // .kind // "") | test("heavy|cargo|rch|build|clippy|test"; "i"))] | length)
      },
      capacity_budget:{
        script_lane_limit:(if ($decision == "fail_closed" or $decision == "blocked") then 0 else ([1, (num($h.cpu_logical_cores // 0) / 8 | floor)] | max) end),
        proof_lane_limit:(if ($decision == "fail_closed" or $decision == "blocked") then 0 else ([0, $rch_available] | max) end),
        build_lane_limit:(if ($decision == "fail_closed" or $decision == "blocked") then 0 else ([$rch_available, ([1, (num($h.cpu_logical_cores // 0) / 16 | floor)] | max)] | min) end),
        remote_rch_slot_limit:(if ($decision == "fail_closed" or $decision == "blocked") then 0 else $rch_available end),
        memory_bytes_budget:([0, (num($m.available_bytes // 0) - $min_memory_available_bytes)] | max),
        target_dir_bytes_budget:([0, ($target_dir_available - $min_target_dir_available_bytes)] | max),
        defer_reasons:($blocked[0] | map(.code))
      },
      degraded_reasons:$degraded[0],
      blocked_reasons:$blocked[0],
      fail_closed_reasons:$fail_closed[0],
      artifact_paths:{
        input_json:$input_json,
        sources_json:$sources_json,
        envelope_json:$envelope_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        report_md:$report_md
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
        deletes_target_dirs:false,
        repairs_stalled_builds:false,
        changes_live_queue_policy:false
      }
    }
  ' >"$envelope_path"

{
  printf '# Swarm Resource Envelope\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Readiness: \`%s\`\n" "$(jq -r '.readiness' "$envelope_path")"
  printf -- "- Bead: \`%s\`\n" "$bead_id"
  printf -- "- Envelope: \`%s\`\n" "$envelope_id"
  printf -- "- Degraded reasons: \`%s\`\n" "$degraded_count"
  printf -- "- Blocked reasons: \`%s\`\n" "$blocked_count"
  printf -- "- Fail-closed reasons: \`%s\`\n" "$fail_count"
} >"$report_path"

emit_event "normalization_complete" "$decision"
printf 'swarm_resource_envelope=%s\n' "$envelope_path"
printf 'swarm_resource_envelope_sources=%s\n' "$sources_path"

exit "$exit_code"
