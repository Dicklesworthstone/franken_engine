#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_key="${SWARM_OPS_STATE_PROJECT_KEY:-$root_dir}"
agent_name="${AGENT_NAME:-${SWARM_OPS_STATE_AGENT_NAME:-BrownCreek}}"
artifact_root="${SWARM_OPS_STATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-ops-state}"
run_id="${SWARM_OPS_STATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPS_STATE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_OPS_STATE_SOURCE_REVISION:-}"

br_ready_json=""
br_in_progress_json=""
br_sync_status_json=""
bv_plan_txt=""
agent_mail_agents_json=""
agent_mail_inbox_json=""
agent_mail_reservations_txt=""
rch_status_json=""
rch_queue_json=""
git_status_txt=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_ops_state_snapshot_capture.sh [OPTIONS]

Captures live br, bv, Agent Mail, RCH, and git state into raw snapshots plus a
deterministic normalized SWARM-OPS state summary. With no fixture paths, the
script runs the real local CLIs. Fixture paths are accepted for replayable smoke
tests and are copied into the raw snapshot directory before normalization.

Options:
  --output-dir DIR
  --project-key PATH
  --agent-name NAME
  --source-revision REV
  --br-ready-json FILE
  --br-in-progress-json FILE
  --br-sync-status-json FILE
  --bv-plan-txt FILE
  --agent-mail-agents-json FILE
  --agent-mail-inbox-json FILE
  --agent-mail-reservations-txt FILE
  --rch-status-json FILE
  --rch-queue-json FILE
  --git-status-txt FILE
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --project-key)
      project_key="${2:-}"
      shift 2
      ;;
    --agent-name)
      agent_name="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
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
    --bv-plan-txt)
      bv_plan_txt="${2:-}"
      shift 2
      ;;
    --agent-mail-agents-json)
      agent_mail_agents_json="${2:-}"
      shift 2
      ;;
    --agent-mail-inbox-json)
      agent_mail_inbox_json="${2:-}"
      shift 2
      ;;
    --agent-mail-reservations-txt)
      agent_mail_reservations_txt="${2:-}"
      shift 2
      ;;
    --rch-status-json)
      rch_status_json="${2:-}"
      shift 2
      ;;
    --rch-queue-json)
      rch_queue_json="${2:-}"
      shift 2
      ;;
    --git-status-txt)
      git_status_txt="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm ops state snapshot capture\n' >&2
  exit 2
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

raw_dir="${run_dir}/raw"
mkdir -p "$raw_dir"

events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
snapshot_path="${run_dir}/swarm_ops_state_snapshot.json"
snapshot_tmp="${snapshot_path}.tmp"

: >"$events_path"
: >"$commands_path"

log_command() {
  printf '%s\n' "$1" >>"$commands_path"
}

write_event() {
  local component="$1"
  local event="$2"
  local outcome="$3"
  local error_code="$4"
  local evidence_path="$5"
  jq -cn \
    --arg schema_version "franken-engine.swarm-ops-state-event.v1" \
    --arg trace_id "trace-swarm-ops-state-${run_id}" \
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

copy_fixture_json() {
  local label="$1"
  local fixture="$2"
  local output="$3"
  cp "$fixture" "$output"
  jq empty "$output" >/dev/null
  log_command "fixture ${label}: ${fixture}"
  write_event "$label" "fixture_copied" "captured" "" "${output#"$root_dir"/}"
}

copy_fixture_text() {
  local label="$1"
  local fixture="$2"
  local output="$3"
  cp "$fixture" "$output"
  log_command "fixture ${label}: ${fixture}"
  write_event "$label" "fixture_copied" "captured" "" "${output#"$root_dir"/}"
}

capture_json_command() {
  local label="$1"
  local output="$2"
  shift 2
  local raw_output="${output}.raw"
  local stderr_path="${output}.stderr"
  local exit_code stderr_excerpt

  log_command "$*"
  set +e
  "$@" >"$raw_output" 2>"$stderr_path"
  exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]] && jq empty "$raw_output" >/dev/null 2>&1; then
    cp "$raw_output" "$output"
    write_event "$label" "live_capture" "captured" "" "${output#"$root_dir"/}"
  else
    stderr_excerpt="$(sed -n '1,20p' "$stderr_path" | tr '\n' ' ')"
    jq -n \
      --arg component "$label" \
      --argjson exit_code "$exit_code" \
      --arg stderr_excerpt "$stderr_excerpt" \
      --arg raw_output "$raw_output" \
      --arg stderr_path "$stderr_path" \
      '{
        capture_error: true,
        component: $component,
        exit_code: $exit_code,
        stderr_excerpt: $stderr_excerpt,
        raw_output_path: $raw_output,
        stderr_path: $stderr_path
      }' >"$output"
    write_event "$label" "live_capture" "degraded" "FE-SWARM-OPS-CAPTURE-ERROR" "${output#"$root_dir"/}"
  fi
}

capture_text_command() {
  local label="$1"
  local output="$2"
  shift 2
  local stderr_path="${output}.stderr"
  local exit_code stderr_excerpt

  log_command "$*"
  set +e
  "$@" >"$output" 2>"$stderr_path"
  exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    write_event "$label" "live_capture" "captured" "" "${output#"$root_dir"/}"
  else
    stderr_excerpt="$(sed -n '1,20p' "$stderr_path" | tr '\n' ' ')"
    {
      printf 'CAPTURE_ERROR component=%s exit_code=%s\n' "$label" "$exit_code"
      printf 'stderr=%s\n' "$stderr_excerpt"
    } >"$output"
    write_event "$label" "live_capture" "degraded" "FE-SWARM-OPS-CAPTURE-ERROR" "${output#"$root_dir"/}"
  fi
}

capture_or_copy_json() {
  local label="$1"
  local fixture="$2"
  local output="$3"
  shift 3
  if [[ -n "$fixture" ]]; then
    copy_fixture_json "$label" "$fixture" "$output"
  else
    capture_json_command "$label" "$output" "$@"
  fi
}

capture_or_copy_text() {
  local label="$1"
  local fixture="$2"
  local output="$3"
  shift 3
  if [[ -n "$fixture" ]]; then
    copy_fixture_text "$label" "$fixture" "$output"
  else
    capture_text_command "$label" "$output" "$@"
  fi
}

capture_or_copy_json "br_ready" "$br_ready_json" "${raw_dir}/br_ready.json" br ready --json
capture_or_copy_json "br_in_progress" "$br_in_progress_json" "${raw_dir}/br_in_progress.json" br list --status=in_progress --json
capture_or_copy_json "br_sync_status" "$br_sync_status_json" "${raw_dir}/br_sync_status.json" br sync --status --json
capture_or_copy_text "bv_plan" "$bv_plan_txt" "${raw_dir}/bv_actionable_plan.txt" bv --recipe actionable --robot-plan
capture_or_copy_json "agent_mail_agents" "$agent_mail_agents_json" "${raw_dir}/agent_mail_agents.json" am agents list --project "$project_key" --json
capture_or_copy_json "agent_mail_inbox" "$agent_mail_inbox_json" "${raw_dir}/agent_mail_inbox.json" am mail inbox --project "$project_key" --agent "$agent_name" --limit 20 --json
capture_or_copy_text "agent_mail_reservations" "$agent_mail_reservations_txt" "${raw_dir}/agent_mail_reservations.txt" am file_reservations active "$project_key" --limit 100
capture_or_copy_json "rch_status" "$rch_status_json" "${raw_dir}/rch_status.json" rch status --workers --jobs --json
capture_or_copy_json "rch_queue" "$rch_queue_json" "${raw_dir}/rch_queue.json" rch queue --json
capture_or_copy_text "git_status" "$git_status_txt" "${raw_dir}/git_status.txt" git -C "$root_dir" status --short

jq -n \
  --arg schema_version "franken-engine.swarm-ops-state-snapshot.v1" \
  --arg source_revision "$source_revision" \
  --arg project_key "$project_key" \
  --arg agent_name "$agent_name" \
  --arg raw_dir "$raw_dir" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg snapshot_path "$snapshot_path" \
  --slurpfile br_ready "${raw_dir}/br_ready.json" \
  --slurpfile br_in_progress "${raw_dir}/br_in_progress.json" \
  --slurpfile br_sync "${raw_dir}/br_sync_status.json" \
  --rawfile bv_plan "${raw_dir}/bv_actionable_plan.txt" \
  --slurpfile agent_mail_agents "${raw_dir}/agent_mail_agents.json" \
  --slurpfile agent_mail_inbox "${raw_dir}/agent_mail_inbox.json" \
  --rawfile agent_mail_reservations "${raw_dir}/agent_mail_reservations.txt" \
  --slurpfile rch_status "${raw_dir}/rch_status.json" \
  --slurpfile rch_queue "${raw_dir}/rch_queue.json" \
  --rawfile git_status "${raw_dir}/git_status.txt" '
    def scalar_strings($value): [$value | .. | strings];
    def has_capture_error($value):
      if ($value | type) == "object" then (($value.capture_error // false) == true) else false end;
    def path_from_status($line):
      ($line | sub("^[ MARCUD?!]{1,2}[ ]+"; "") | sub("^\""; "") | sub("\"$"; ""));
    def dirty_class($path):
      if ($path | startswith(".beads/")) then "tracker"
      elif ($path | startswith("scripts/swarm_ops_state_snapshot_capture.sh")) then "owned"
      elif ($path | startswith("scripts/e2e/swarm_ops_state_snapshot_capture_smoke.sh")) then "owned"
      elif ($path | startswith("scripts/testdata/swarm_ops_state_snapshot/")) then "owned"
      else "unowned"
      end;
    def rch_texts: (scalar_strings($rch_status[0]) + scalar_strings($rch_queue[0]));

    ($br_sync[0]) as $sync
    | ($rch_status[0]) as $status
    | ($rch_queue[0]) as $queue
    | ($git_status | split("\n") | map(select(length > 0)) | sort) as $git_lines
    | ($git_lines | map({raw: ., path: path_from_status(.), class: dirty_class(path_from_status(.))})) as $dirty_files
    | ([($status.jobs[]? // empty), ($queue.jobs[]? // empty), ($queue.running[]? // empty)]
       | map(select((.stale_progress // false) == true
                    or ((.progress_age_seconds // 0) >= 600)
                    or (((.state // "") | tostring | test("stall|stale|frozen"; "i")))))) as $stall_jobs
    | ((($sync.db_newer // false) == true)
       or (($sync.jsonl_newer // false) == true)
       or (($sync.dirty_count // 0) > 0)
       or (($sync.capture_error // false) == true)) as $br_stale
    | ((has_capture_error($agent_mail_agents[0]))
       or (has_capture_error($agent_mail_inbox[0]))
       or ($agent_mail_reservations | test("^CAPTURE_ERROR"; "m"))) as $mail_missing
    | ((has_capture_error($status))
       or (has_capture_error($queue))
       or any(rch_texts[]; test("degraded|drained|unhealthy|offline"; "i"))) as $rch_degraded
    | (any(rch_texts[]; test("local fallback|local_fallback"; "i"))) as $rch_local_fallback
    | ($dirty_files | map(select(.class == "unowned"))) as $unowned_dirty
    | ((if $br_stale then ["stale_bv_due_to_br_sync"] else [] end)
       + (if $rch_local_fallback then ["rch_local_fallback"] else [] end)) as $fail_closed_reasons
    | (if ($unowned_dirty | length) > 0 then ["dirty_unowned_files"] else [] end) as $blocked_reasons
    | ((if $mail_missing then ["agent_mail_unavailable"] else [] end)
       + (if ($stall_jobs | length) > 0 then ["active_rch_stall"] elif $rch_degraded then ["rch_degraded"] else [] end)) as $degraded_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($blocked_reasons | length) > 0 then "blocked"
       elif ($degraded_reasons | length) > 0 then "degraded"
       else "pass"
       end) as $decision
    | {
        schema_version: $schema_version,
        source_revision: $source_revision,
        project_key: $project_key,
        agent_name: $agent_name,
        decision: $decision,
        fail_closed_reasons: $fail_closed_reasons,
        blocked_reasons: $blocked_reasons,
        degraded_reasons: $degraded_reasons,
        components: {
          br: {
            ready_count: (($br_ready[0] | if type == "array" then length else (.issues // [] | length) end) // 0),
            in_progress_count: (($br_in_progress[0] | if type == "array" then length else (.issues // [] | length) end) // 0),
            sync_status: $sync,
            bv_plan_state: (if $br_stale then "stale_due_to_br_sync" else "fresh" end)
          },
          agent_mail: {
            state: (if $mail_missing then "degraded" else "captured" end),
            agents_capture_error: has_capture_error($agent_mail_agents[0]),
            inbox_capture_error: has_capture_error($agent_mail_inbox[0]),
            reservation_capture_error: ($agent_mail_reservations | test("^CAPTURE_ERROR"; "m"))
          },
          rch: {
            state: (if $rch_local_fallback then "fail_closed" elif ($stall_jobs | length) > 0 then "stalled" elif $rch_degraded then "degraded" else "captured" end),
            active_stall_count: ($stall_jobs | length),
            local_fallback_observed: $rch_local_fallback
          },
          git: {
            dirty_file_count: ($dirty_files | length),
            tracker_only_dirty: (($dirty_files | length) > 0 and (($dirty_files | map(select(.class != "tracker")) | length) == 0)),
            owned_dirty_count: ($dirty_files | map(select(.class == "owned")) | length),
            unowned_dirty_count: ($unowned_dirty | length),
            dirty_files: $dirty_files
          }
        },
        raw_snapshots: {
          br_ready_json: ($raw_dir + "/br_ready.json"),
          br_in_progress_json: ($raw_dir + "/br_in_progress.json"),
          br_sync_status_json: ($raw_dir + "/br_sync_status.json"),
          bv_actionable_plan_txt: ($raw_dir + "/bv_actionable_plan.txt"),
          agent_mail_agents_json: ($raw_dir + "/agent_mail_agents.json"),
          agent_mail_inbox_json: ($raw_dir + "/agent_mail_inbox.json"),
          agent_mail_reservations_txt: ($raw_dir + "/agent_mail_reservations.txt"),
          rch_status_json: ($raw_dir + "/rch_status.json"),
          rch_queue_json: ($raw_dir + "/rch_queue.json"),
          git_status_txt: ($raw_dir + "/git_status.txt")
        },
        artifact_paths: {
          swarm_ops_state_snapshot_json: $snapshot_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_path
        },
        bv_plan_excerpt: ($bv_plan | split("\n") | map(select(length > 0)) | .[0:20])
      }
  ' >"$snapshot_tmp"
cp "$snapshot_tmp" "$snapshot_path"

decision="$(jq -r '.decision' "$snapshot_path")"
reason="$(jq -r '(.fail_closed_reasons + .blocked_reasons + .degraded_reasons)[0] // ""' "$snapshot_path")"
case "$reason" in
  stale_bv_due_to_br_sync) error_code="FE-SWARM-OPS-STALE-BV" ;;
  rch_local_fallback) error_code="FE-SWARM-OPS-RCH-LOCAL-FALLBACK" ;;
  dirty_unowned_files) error_code="FE-SWARM-OPS-DIRTY-UNOWNED" ;;
  agent_mail_unavailable) error_code="FE-SWARM-OPS-MAIL-MISSING" ;;
  active_rch_stall) error_code="FE-SWARM-OPS-RCH-STALL" ;;
  rch_degraded) error_code="FE-SWARM-OPS-RCH-DEGRADED" ;;
  *) error_code="" ;;
esac
write_event "swarm_ops_state_snapshot" "summary_normalized" "$decision" "$error_code" "${snapshot_path#"$root_dir"/}"

cat >"$report_path" <<EOF
# SWARM OPS STATE SNAPSHOT

- decision: ${decision}
- reason: ${reason:-none}
- snapshot: ${snapshot_path}
- events: ${events_path}
- commands: ${commands_path}
EOF

printf 'swarm ops state snapshot: %s\n' "$snapshot_path"
