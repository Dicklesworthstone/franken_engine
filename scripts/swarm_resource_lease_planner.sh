#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_RESOURCE_LEASE_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-resource-lease-planner}"
run_id="${SWARM_RESOURCE_LEASE_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RESOURCE_LEASE_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

agent_id=""
bead_id=""
requested_command=""
estimated_cpu_slots="1"
estimated_memory_class="small"
target_dir=""
lease_ttl_seconds="1800"
max_cpu_slots="8"
reservation_snapshot_json=""
br_snapshot_json=""
rch_workers_json=""
dirty_files_json=""
rch_fallback_detected="false"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_resource_lease_planner.sh --agent-id ID --bead-id ID --requested-command CMD --target-dir DIR [OPTIONS]

Inputs are deterministic JSON fixtures; this gate does not query live Agent Mail,
live br, live rch, or mutate repository state.

Required:
  --agent-id ID
  --bead-id ID
  --requested-command CMD
  --target-dir DIR

Optional:
  --output-dir DIR
  --estimated-cpu-slots N
  --estimated-memory-class small|medium|large|xlarge
  --lease-ttl-seconds N
  --max-cpu-slots N
  --reservation-snapshot-json FILE
  --br-snapshot-json FILE
  --rch-workers-json FILE
  --dirty-files-json FILE
  --rch-fallback-detected true|false

Writes resource_lease_plan.json, events.jsonl, commands.txt, and report.md.
Exit codes: 0 admitted/admitted-narrow, 42 denied/fail-closed, 75 deferred.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --agent-id)
      agent_id="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --requested-command)
      requested_command="${2:-}"
      shift 2
      ;;
    --target-dir)
      target_dir="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --estimated-cpu-slots)
      estimated_cpu_slots="${2:-}"
      shift 2
      ;;
    --estimated-memory-class)
      estimated_memory_class="${2:-}"
      shift 2
      ;;
    --lease-ttl-seconds)
      lease_ttl_seconds="${2:-}"
      shift 2
      ;;
    --max-cpu-slots)
      max_cpu_slots="${2:-}"
      shift 2
      ;;
    --reservation-snapshot-json)
      reservation_snapshot_json="${2:-}"
      shift 2
      ;;
    --br-snapshot-json)
      br_snapshot_json="${2:-}"
      shift 2
      ;;
    --rch-workers-json)
      rch_workers_json="${2:-}"
      shift 2
      ;;
    --dirty-files-json)
      dirty_files_json="${2:-}"
      shift 2
      ;;
    --rch-fallback-detected)
      rch_fallback_detected="${2:-}"
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

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

if [[ -z "$agent_id" || -z "$bead_id" || -z "$requested_command" || -z "$target_dir" ]]; then
  printf 'resource lease planner requires --agent-id, --bead-id, --requested-command, and --target-dir\n' >&2
  usage
  exit 64
fi
if ! is_int "$estimated_cpu_slots" || ! is_int "$max_cpu_slots" || ! is_int "$lease_ttl_seconds"; then
  printf 'estimated cpu slots, max cpu slots, and lease ttl must be non-negative integers\n' >&2
  exit 64
fi
case "$estimated_memory_class" in
  small|medium|large|xlarge) ;;
  *)
    printf 'estimated memory class must be small, medium, large, or xlarge\n' >&2
    exit 64
    ;;
esac
case "$rch_fallback_detected" in
  true|false) ;;
  *)
    printf 'rch fallback detected must be true or false\n' >&2
    exit 64
    ;;
esac

mkdir -p "$run_dir"
plan_path="${run_dir}/resource_lease_plan.json"
plan_tmp="${plan_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
safe_alternatives_jsonl="${run_dir}/safe_alternatives.jsonl"
findings_jsonl="${run_dir}/findings.jsonl"
reservation_normalized="${run_dir}/reservation_snapshot.normalized.json"
br_normalized="${run_dir}/br_snapshot.normalized.json"
workers_normalized="${run_dir}/rch_workers.normalized.json"
dirty_normalized="${run_dir}/dirty_files.normalized.json"
: >"$events_path"
: >"$safe_alternatives_jsonl"
: >"$findings_jsonl"

printf './scripts/swarm_resource_lease_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"

  if [[ -z "$path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'resource lease planner missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'resource lease planner invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

reservation_snapshot_status="$(json_input "$reservation_snapshot_json" '{"reservations":[]}' "$reservation_normalized" 'reservation snapshot')"
br_snapshot_status="$(json_input "$br_snapshot_json" '{"beads":[]}' "$br_normalized" 'br snapshot')"
workers_snapshot_status="$(json_input "$rch_workers_json" '{"workers":[]}' "$workers_normalized" 'rch worker snapshot')"
dirty_snapshot_status="$(json_input "$dirty_files_json" '[]' "$dirty_normalized" 'dirty files snapshot')"

add_alt() {
  jq -nc --arg value "$1" '$value' >>"$safe_alternatives_jsonl"
}

add_finding() {
  local severity="$1"
  local code="$2"
  local message="$3"
  jq -nc --arg severity "$severity" --arg code "$code" --arg message "$message" \
    '{severity: $severity, code: $code, message: $message}' >>"$findings_jsonl"
}

is_heavy_rust="false"
if [[ "$requested_command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
  is_heavy_rust="true"
fi

rch_wrapped="false"
if [[ "$requested_command" == *"rch exec -- env"* && "$requested_command" == *"CARGO_TARGET_DIR="* ]]; then
  rch_wrapped="true"
fi

target_dir_conflict="false"
if jq -e --arg target "$target_dir" --arg agent "$agent_id" '
  [
    .. | objects
    | select(
        ((.target_dir? // .path? // .path_pattern? // "") == $target)
        and ((.agent_id? // .agent_name? // .holder? // "") != $agent)
      )
  ] | length > 0
' "$reservation_normalized" >/dev/null; then
  target_dir_conflict="true"
fi

dirty_target_conflict="false"
if jq -e --arg target "$target_dir" '
  [
    .. | objects
    | select((.target_dir? // .path? // "") == $target)
  ] | length > 0
' "$dirty_normalized" >/dev/null; then
  dirty_target_conflict="true"
fi

worker_available="false"
if jq -e --argjson cpu "$estimated_cpu_slots" --arg mem "$estimated_memory_class" '
  def rank($m):
    if $m == "small" then 1
    elif $m == "medium" then 2
    elif $m == "large" then 3
    elif $m == "xlarge" then 4
    else 0 end;
  any(.workers[]?;
    ((.status // "") == "idle" or (.status // "") == "available" or (.status // "") == "ok")
    and ((.cpu_slots_available // .available_cpu_slots // 0) >= $cpu)
    and (rank(.memory_class // "small") >= rank($mem))
  )
' "$workers_normalized" >/dev/null; then
  worker_available="true"
fi

assigned_worker="none"
if [[ "$worker_available" == "true" ]]; then
  assigned_worker="$(jq -r --argjson cpu "$estimated_cpu_slots" --arg mem "$estimated_memory_class" '
    def rank($m):
      if $m == "small" then 1
      elif $m == "medium" then 2
      elif $m == "large" then 3
      elif $m == "xlarge" then 4
      else 0 end;
    first(.workers[]?
      | select(
          ((.status // "") == "idle" or (.status // "") == "available" or (.status // "") == "ok")
          and ((.cpu_slots_available // .available_cpu_slots // 0) >= $cpu)
          and (rank(.memory_class // "small") >= rank($mem))
        )
      | (.worker_id // .id // "unknown-worker")
    ) // "none"
  ' "$workers_normalized")"
fi

lease_decision="admit"
reason="lease admitted"

if (( estimated_cpu_slots > max_cpu_slots )); then
  lease_decision="deny"
  reason="requested CPU slots exceed the per-agent lease budget"
  add_finding "error" "cpu_over_budget" "$reason"
  add_alt "Split the proof into narrower lanes or request fewer CPU slots."
elif [[ "$is_heavy_rust" == "true" && "$rch_wrapped" != "true" ]]; then
  lease_decision="deny"
  reason="heavy Cargo command is not rch-target-dir wrapped"
  add_finding "error" "heavy_cargo_not_rch_wrapped" "$reason"
  add_alt "Use: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_<bead> cargo test ..."
elif [[ "$is_heavy_rust" == "true" && "$rch_fallback_detected" == "true" ]]; then
  lease_decision="fail_closed"
  reason="rch local fallback marker was observed for a heavy command"
  add_finding "error" "rch_local_fallback" "$reason"
  add_alt "Stop the heavy proof and retry only after remote routing is healthy."
elif [[ "$target_dir_conflict" == "true" || "$dirty_target_conflict" == "true" ]]; then
  lease_decision="defer"
  reason="requested target directory conflicts with active reservation or dirty state"
  add_finding "warning" "target_dir_conflict" "$reason"
  add_alt "${target_dir}-${agent_id}-${bead_id}"
elif [[ "$is_heavy_rust" == "true" && "$workers_snapshot_status" == "provided" && "$worker_available" != "true" ]]; then
  lease_decision="defer"
  reason="no rch worker has the requested CPU and memory lease available"
  add_finding "warning" "all_workers_busy" "$reason"
  add_alt "Run shell/docs gates now and retry the heavy proof when a worker is idle."
elif [[ "$reservation_snapshot_status" == "missing" ]]; then
  lease_decision="admit_narrow"
  reason="Agent Mail reservation snapshot missing; lease is degraded and limited to narrow work"
  add_finding "warning" "missing_agent_mail_snapshot" "$reason"
  add_alt "Capture file_reservation_paths output before starting heavy validation."
elif [[ "$is_heavy_rust" == "true" && "$workers_snapshot_status" == "missing" ]]; then
  lease_decision="admit_narrow"
  reason="rch worker snapshot missing; heavy proof lease is degraded"
  add_finding "warning" "missing_rch_worker_snapshot" "$reason"
  add_alt "Capture rch worker health before starting heavy validation."
elif [[ "$br_snapshot_status" == "missing" || "$dirty_snapshot_status" == "missing" ]]; then
  lease_decision="admit_narrow"
  reason="br or dirty-worktree snapshot missing; lease is visible degraded mode"
  add_finding "warning" "missing_local_snapshot" "$reason"
  add_alt "Capture br and git dirty snapshots before widening validation."
else
  add_finding "info" "lease_admitted" "$reason"
fi

safe_alternatives_json="$(jq -s 'unique' "$safe_alternatives_jsonl")"
findings_json="$(jq -s '.' "$findings_jsonl")"

jq -n \
  --arg schema_version "franken-engine.swarm-resource-lease-plan.v1" \
  --arg agent_id "$agent_id" \
  --arg bead_id "$bead_id" \
  --arg requested_command "$requested_command" \
  --arg estimated_memory_class "$estimated_memory_class" \
  --arg target_dir "$target_dir" \
  --arg lease_decision "$lease_decision" \
  --arg reason "$reason" \
  --arg assigned_worker "$assigned_worker" \
  --arg reservation_snapshot_status "$reservation_snapshot_status" \
  --arg br_snapshot_status "$br_snapshot_status" \
  --arg workers_snapshot_status "$workers_snapshot_status" \
  --arg dirty_snapshot_status "$dirty_snapshot_status" \
  --argjson estimated_cpu_slots "$estimated_cpu_slots" \
  --argjson max_cpu_slots "$max_cpu_slots" \
  --argjson lease_ttl_seconds "$lease_ttl_seconds" \
  --argjson is_heavy_rust "$is_heavy_rust" \
  --argjson rch_wrapped "$rch_wrapped" \
  --argjson rch_fallback_detected "$rch_fallback_detected" \
  --argjson target_dir_conflict "$target_dir_conflict" \
  --argjson worker_available "$worker_available" \
  --argjson safe_alternatives "$safe_alternatives_json" \
  --argjson findings "$findings_json" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '{
    schema_version: $schema_version,
    agent_id: $agent_id,
    bead_id: $bead_id,
    requested_command: $requested_command,
    estimated_cpu_slots: $estimated_cpu_slots,
    estimated_memory_class: $estimated_memory_class,
    target_dir: $target_dir,
    lease_decision: $lease_decision,
    lease_ttl_seconds: $lease_ttl_seconds,
    reason: $reason,
    safe_alternatives: $safe_alternatives,
    assigned_worker: $assigned_worker,
    max_cpu_slots: $max_cpu_slots,
    command_class: {
      heavy_rust: $is_heavy_rust,
      rch_wrapped: $rch_wrapped,
      rch_fallback_detected: $rch_fallback_detected
    },
    snapshot_status: {
      reservations: $reservation_snapshot_status,
      br: $br_snapshot_status,
      rch_workers: $workers_snapshot_status,
      dirty_files: $dirty_snapshot_status
    },
    conflicts: {
      target_dir: $target_dir_conflict,
      worker_available: $worker_available
    },
    findings: $findings,
    artifact_paths: {
      resource_lease_plan_json: $plan_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

jq -nc \
  --arg schema_version "franken-engine.swarm-resource-lease-event.v1" \
  --arg event_name "swarm_resource_lease_planner.decision" \
  --arg agent_id "$agent_id" \
  --arg bead_id "$bead_id" \
  --arg lease_decision "$lease_decision" \
  --arg reason "$reason" \
  '{
    schema_version: $schema_version,
    event_name: $event_name,
    agent_id: $agent_id,
    bead_id: $bead_id,
    lease_decision: $lease_decision,
    reason: $reason
  }' >>"$events_path"

{
  printf '# Swarm Resource Lease Plan\n\n'
  printf "%s\n" "- Agent: \`${agent_id}\`"
  printf "%s\n" "- Bead: \`${bead_id}\`"
  printf "%s\n" "- Decision: \`${lease_decision}\`"
  printf "%s\n" "- Reason: ${reason}"
  printf "%s\n" "- Target dir: \`${target_dir}\`"
  printf "%s\n" "- Assigned worker: \`${assigned_worker}\`"
} >"$report_path"

case "$lease_decision" in
  admit|admit_narrow)
    exit 0
    ;;
  defer)
    exit 75
    ;;
  deny|fail_closed)
    exit 42
    ;;
  *)
    exit 42
    ;;
esac
