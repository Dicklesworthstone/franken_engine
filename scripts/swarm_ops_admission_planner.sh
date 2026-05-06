#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_OPS_ADMISSION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-ops-admission}"
run_id="${SWARM_OPS_ADMISSION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPS_ADMISSION_RUN_DIR:-${artifact_root}/${run_id}}"
state_snapshot_json=""
source_revision="${SWARM_OPS_ADMISSION_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_ops_admission_planner.sh --state-snapshot-json FILE [OPTIONS]

Consumes a SWARM-OPS state snapshot and emits an advisory-only admission plan.
The planner never starts work, runs Cargo, runs RCH, mutates beads, or releases
reservations. Candidate lanes and capacity fields must already be present in
the snapshot; missing budget fields fail closed.

Options:
  --state-snapshot-json FILE
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --state-snapshot-json)
      state_snapshot_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$state_snapshot_json" ]]; then
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm ops admission planning\n' >&2
  exit 2
fi
jq empty "$state_snapshot_json" >/dev/null

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/plan.json"
plan_tmp="${plan_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
report_path="${run_dir}/report.md"

: >"$events_path"
printf './scripts/swarm_ops_admission_planner.sh --state-snapshot-json %q --output-dir %q\n' \
  "$state_snapshot_json" "$run_dir" >"$commands_path"

write_event() {
  local component="$1"
  local event="$2"
  local outcome="$3"
  local error_code="$4"
  local evidence_path="$5"
  jq -cn \
    --arg schema_version "franken-engine.swarm-ops-admission-event.v1" \
    --arg trace_id "trace-swarm-ops-admission-${run_id}" \
    --arg component "$component" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      evidence_path: $evidence_path
    }' >>"$events_path"
}

write_event "swarm_ops_admission_planner" "input_loaded" "captured" "" "$state_snapshot_json"

jq -n \
  --slurpfile state "$state_snapshot_json" \
  --arg schema_version "franken-engine.swarm-ops-admission-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg state_snapshot_json "$state_snapshot_json" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg trace_ids_path "$trace_ids_path" \
  --arg report_path "$report_path" '
    def min2($a; $b): if $a < $b then $a else $b end;
    def required_lane_fields_present($lane):
      ($lane | has("lane_id"))
      and ($lane | has("priority"))
      and ($lane | has("lane_class"))
      and ($lane | has("cpu_slots"))
      and ($lane | has("memory_bytes"))
      and ($lane | has("rch_slots"))
      and ($lane | has("target_dir_bytes"));
    def conflict_for($lane; $conflicts):
      any(($lane.write_paths // [])[];
        . as $path | any($conflicts[]?; (.path_pattern == $path) or ($path | startswith(.path_pattern))));
    def conflict_holders($lane; $conflicts):
      [($lane.write_paths // [])[] as $path
       | $conflicts[]?
       | select((.path_pattern == $path) or ($path | startswith(.path_pattern)))
       | .holder] | unique | sort;
    def advisory_command($lane; $decision; $reason):
      "# advisory-only " + $decision + " " + $lane.lane_id + " reason=" + $reason;

    ($state[0]) as $s
    | ($s.capacity_envelope // {}) as $cap
    | ($s.candidate_lanes // []) as $raw_lanes
    | ($raw_lanes | sort_by(.priority, .lane_id)) as $lanes
    | ($s.reservation_conflicts // []) as $conflicts
    | ([
        if ($s.decision == "fail_closed" or (($s.fail_closed_reasons // []) | length > 0)) then
          if (($s.fail_closed_reasons // []) | index("stale_bv_due_to_br_sync") != null) then "stale_br_bv_state" else "upstream_state_fail_closed" end
        else empty end,
        if (($s.degraded_reasons // []) | index("active_rch_stall") != null) or (($s.components.rch.active_stall_count // 0) > 0) then "active_rch_stale_progress" else empty end,
        if (($s.blocked_reasons // []) | index("dirty_unowned_files") != null) or (($s.components.git.unowned_dirty_count // 0) > 0) then "unknown_dirty_files" else empty end,
        if (($s.components.rch.state // "") == "missing") then "missing_worker_telemetry" else empty end,
        if ($lanes | length) == 0 then "insufficient_per_lane_budget_fields" else empty end,
        if any($lanes[]?; required_lane_fields_present(.) | not) then "insufficient_per_lane_budget_fields" else empty end,
        if (($cap.total_cpu_slots // null) == null) or (($cap.total_memory_bytes // null) == null) or (($cap.total_rch_slots // null) == null) or (($cap.target_dir_available_bytes // null) == null) then "insufficient_capacity_budget_fields" else empty end
      ] | unique | sort) as $fail_closed_reasons
    | (($cap.max_parallel_heavy_lanes // (min2((($cap.total_cpu_slots // 0) / 8 | floor); ($cap.total_rch_slots // 0)))) | tonumber) as $max_heavy
    | (if (($cap.total_rch_slots // 0) <= 0) or (($s.components.rch.state // "") == "degraded") then true else false end) as $rch_brownout
    | (if (($cap.target_dir_available_bytes // 0) < (($cap.min_target_dir_available_bytes // 0))) then true else false end) as $disk_pressure
    | (reduce $lanes[] as $lane (
        {cpu_used:0, memory_used:0, rch_used:0, heavy_admitted:0, admitted_lanes:[], deferred_lanes:[], blocked_lanes:[]};
        if ($fail_closed_reasons | length) > 0 then
          .blocked_lanes += [$lane + {decision:"blocked", reason:($fail_closed_reasons[0]), advisory_command: advisory_command($lane; "blocked"; $fail_closed_reasons[0])}]
        elif conflict_for($lane; $conflicts) then
          .blocked_lanes += [$lane + {decision:"blocked", reason:"reservation_conflict", conflict_holders: conflict_holders($lane; $conflicts), advisory_command: advisory_command($lane; "blocked"; "reservation_conflict")}]
        elif $rch_brownout then
          .deferred_lanes += [$lane + {decision:"defer", reason:"rch_brownout", advisory_command: advisory_command($lane; "defer"; "rch_brownout")}]
        elif $disk_pressure and (($lane.target_dir_bytes // 0) > 0) then
          .deferred_lanes += [$lane + {decision:"defer", reason:"target_dir_disk_pressure", advisory_command: advisory_command($lane; "defer"; "target_dir_disk_pressure")}]
        elif ((.cpu_used + $lane.cpu_slots) <= ($cap.total_cpu_slots // 0)
              and (.memory_used + $lane.memory_bytes) <= ($cap.total_memory_bytes // 0)
              and (.rch_used + $lane.rch_slots) <= ($cap.total_rch_slots // 0)
              and (if $lane.lane_class == "heavy" then (.heavy_admitted < $max_heavy) else true end)) then
          .cpu_used += $lane.cpu_slots
          | .memory_used += $lane.memory_bytes
          | .rch_used += $lane.rch_slots
          | .heavy_admitted += (if $lane.lane_class == "heavy" then 1 else 0 end)
          | .admitted_lanes += [$lane + {decision:"admit", reason:"within_capacity", advisory_command: advisory_command($lane; "admit"; "within_capacity")}]
        else
          .deferred_lanes += [$lane + {decision:"defer", reason:"capacity_budget_exceeded", advisory_command: advisory_command($lane; "defer"; "capacity_budget_exceeded")}]
        end
      )) as $result
    | ((if $rch_brownout then ["rch_brownout"] else [] end)
       + (if $disk_pressure then ["target_dir_disk_pressure"] else [] end)
       + (if any($result.deferred_lanes[]?; .reason == "capacity_budget_exceeded") then ["capacity_budget_exceeded"] else [] end)
      | unique | sort) as $degraded_reasons
    | (if any($result.blocked_lanes[]?; .reason == "reservation_conflict") then ["reservation_conflict"] else [] end) as $blocked_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($blocked_reasons | length) > 0 then "blocked"
       elif (($degraded_reasons | length) > 0) or (($result.deferred_lanes | length) > 0) then "degraded"
       else "pass"
       end) as $decision
    | {
        schema_version: $schema_version,
        source_revision: $source_revision,
        decision: $decision,
        fail_closed_reasons: $fail_closed_reasons,
        blocked_reasons: $blocked_reasons,
        degraded_reasons: $degraded_reasons,
        capacity_envelope: ($cap + {max_parallel_heavy_lanes:$max_heavy}),
        admitted_lanes: $result.admitted_lanes,
        deferred_lanes: $result.deferred_lanes,
        blocked_lanes: $result.blocked_lanes,
        summary: {
          candidate_count: ($lanes | length),
          admitted_count: ($result.admitted_lanes | length),
          deferred_count: ($result.deferred_lanes | length),
          blocked_count: ($result.blocked_lanes | length),
          admitted_heavy_count: ($result.admitted_lanes | map(select(.lane_class == "heavy")) | length)
        },
        operator_commands: (($result.admitted_lanes + $result.deferred_lanes + $result.blocked_lanes) | map(.advisory_command)),
        artifact_paths: {
          state_snapshot_json: $state_snapshot_json,
          plan_json: $plan_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          trace_ids_json: $trace_ids_path,
          report_md: $report_path
        }
      }
  ' >"$plan_tmp"
cp "$plan_tmp" "$plan_path"

jq '{
  schema_version: "franken-engine.swarm-ops-admission-trace-ids.v1",
  trace_ids: ((.admitted_lanes + .deferred_lanes + .blocked_lanes)
    | map({lane_id, trace_id: ("trace-swarm-ops-admission-" + .lane_id)}))
}' "$plan_path" >"$trace_ids_path"

decision="$(jq -r '.decision' "$plan_path")"
reason="$(jq -r '(.fail_closed_reasons + .blocked_reasons + .degraded_reasons)[0] // ""' "$plan_path")"
case "$reason" in
  stale_br_bv_state) error_code="FE-SWARM-OPS-STALE-BV" ;;
  active_rch_stale_progress) error_code="FE-SWARM-OPS-RCH-STALL" ;;
  unknown_dirty_files) error_code="FE-SWARM-OPS-DIRTY-UNOWNED" ;;
  missing_worker_telemetry) error_code="FE-SWARM-OPS-RCH-MISSING" ;;
  insufficient_per_lane_budget_fields|insufficient_capacity_budget_fields) error_code="FE-SWARM-OPS-BUDGET-MISSING" ;;
  reservation_conflict) error_code="FE-SWARM-OPS-RESERVATION-CONFLICT" ;;
  rch_brownout) error_code="FE-SWARM-OPS-RCH-BROWNOUT" ;;
  target_dir_disk_pressure) error_code="FE-SWARM-OPS-DISK-PRESSURE" ;;
  capacity_budget_exceeded) error_code="FE-SWARM-OPS-CAPACITY" ;;
  *) error_code="" ;;
esac
write_event "swarm_ops_admission_planner" "plan_emitted" "$decision" "$error_code" "$plan_path"

cat >"$report_path" <<EOF
# SWARM OPS ADMISSION PLAN

- decision: ${decision}
- reason: ${reason:-none}
- plan: ${plan_path}
- trace ids: ${trace_ids_path}
- events: ${events_path}
- commands: ${commands_path}
EOF

printf 'swarm ops admission plan: %s\n' "$plan_path"
