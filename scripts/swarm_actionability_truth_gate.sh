#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_ACTIONABILITY_TRUTH_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-actionability-truth-gate}"
run_id="${SWARM_ACTIONABILITY_TRUTH_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_ACTIONABILITY_TRUTH_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

collect_live=false
br_ready_json=""
br_open_json=""
br_in_progress_json=""
br_blocked_json=""
bv_robot_plan_json=""
agent_mail_snapshot_json=""
git_status_snapshot_json=""
source_freshness_json=""
source_revision=""
generated_epoch_seconds="$(date -u +%s)"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_actionability_truth_gate.sh \
  --br-ready-json FILE \
  --br-open-json FILE \
  --br-in-progress-json FILE \
  --br-blocked-json FILE \
  --bv-robot-plan-json FILE \
  --git-status-snapshot-json FILE \
  --source-freshness-json FILE \
  [OPTIONS]

Evaluate preserved br/bv/mail/git snapshots and emit a deterministic
actionability report. The gate is advisory only and proof only: it must not
claim beads, mutate tracker state, release reservations, send Agent Mail,
change git state, run Cargo/RCH, or mutate remote workers.

Required:
  --br-ready-json FILE
  --br-open-json FILE
  --br-in-progress-json FILE
  --br-blocked-json FILE
  --bv-robot-plan-json FILE
  --git-status-snapshot-json FILE
  --source-freshness-json FILE

Optional:
  --agent-mail-snapshot-json FILE
  --collect-live
  --source-revision REV
  --generated-epoch-seconds N
  --output-dir DIR

Artifacts:
  actionability_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  report emitted with decision safe_to_claim, defer, or observe_only
  42 report emitted with decision fail_closed
  64 invalid arguments, missing required inputs, or malformed JSON
EOF
}

is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-open-json)
      br_open_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
    --br-blocked-json)
      br_blocked_json="${2:-}"
      shift 2
      ;;
    --bv-robot-plan-json)
      bv_robot_plan_json="${2:-}"
      shift 2
      ;;
    --agent-mail-snapshot-json)
      agent_mail_snapshot_json="${2:-}"
      shift 2
      ;;
    --git-status-snapshot-json)
      git_status_snapshot_json="${2:-}"
      shift 2
      ;;
    --source-freshness-json)
      source_freshness_json="${2:-}"
      shift 2
      ;;
    --collect-live)
      collect_live=true
      shift
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-epoch-seconds|--now-epoch-seconds)
      generated_epoch_seconds="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm actionability truth gate\n' >&2
  exit 2
fi
if ! is_int "$generated_epoch_seconds"; then
  printf 'generated epoch seconds must be a non-negative integer\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_path="${run_dir}/actionability_report.json"
report_tmp="${report_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
markdown_path="${run_dir}/report.md"
reasons_jsonl="${run_dir}/reasons.jsonl"

br_ready_normalized="${run_dir}/br_ready.normalized.json"
br_open_normalized="${run_dir}/br_open.normalized.json"
br_in_progress_normalized="${run_dir}/br_in_progress.normalized.json"
br_blocked_normalized="${run_dir}/br_blocked.normalized.json"
bv_plan_normalized="${run_dir}/bv_robot_plan.normalized.json"
agent_mail_normalized="${run_dir}/agent_mail_snapshot.normalized.json"
git_status_normalized="${run_dir}/git_status_snapshot.normalized.json"
source_freshness_normalized="${run_dir}/source_freshness.normalized.json"

printf './scripts/swarm_actionability_truth_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-actionability-truth-gate.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    --argjson generated_epoch_seconds "$generated_epoch_seconds" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      detail: $detail,
      source_revision: $source_revision,
      generated_epoch_seconds: $generated_epoch_seconds
    }' >>"$events_path"
}

append_reason() {
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    '{code:$code,source_id:$source_id,detail:$detail}' >>"$reasons_jsonl"
}

collect_live_json() {
  local label="$1"
  local output_path="$2"
  case "$label" in
    br_ready_json)
      br ready --json | jq -cS . >"$output_path"
      ;;
    br_open_json)
      br list --status=open --json | jq -cS . >"$output_path"
      ;;
    br_in_progress_json)
      br list --status=in_progress --json | jq -cS . >"$output_path"
      ;;
    br_blocked_json)
      br list --status=blocked --json | jq -cS . >"$output_path"
      ;;
    bv_robot_plan_json)
      if bv --recipe actionable --robot-plan --json >"${output_path}.raw" 2>/dev/null; then
        jq -cS . "${output_path}.raw" >"$output_path"
      elif bv --recipe actionable --robot-plan >"${output_path}.raw" 2>/dev/null && jq empty "${output_path}.raw" >/dev/null 2>&1; then
        jq -cS . "${output_path}.raw" >"$output_path"
      else
        printf 'live collection failed for %s\n' "$label" >&2
        rm -f "${output_path}.raw"
        exit 64
      fi
      rm -f "${output_path}.raw"
      ;;
    git_status_snapshot_json)
      git -C "$root_dir" status --short --branch \
        | jq -Rs '
            split("\n") as $lines
            | {
                branch: (
                  ($lines[0] // "")
                  | sub("^## "; "")
                  | split("...")[0]
                ),
                dirty_paths: [
                  $lines[1:][]?
                  | select(length >= 4)
                  | .[3:]
                  | select(length > 0)
                ]
              }
          ' >"$output_path"
      ;;
    *)
      printf 'unsupported live collector for %s\n' "$label" >&2
      exit 64
      ;;
  esac
}

load_json() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  local required="$5"

  if [[ -n "$path" ]]; then
    if [[ ! -f "$path" ]]; then
      printf 'missing %s JSON: %s\n' "$label" "$path" >&2
      exit 64
    fi
    if ! jq empty "$path" >/dev/null 2>&1; then
      printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
      exit 64
    fi
    jq -cS . "$path" >"$output_path"
    printf 'provided'
    return
  fi

  if [[ "$collect_live" == true && "$required" == "true" ]]; then
    collect_live_json "$label" "$output_path"
    printf 'collected_live'
    return
  fi

  if [[ "$required" == "true" ]]; then
    printf 'missing required %s JSON\n' "$label" >&2
    exit 64
  fi

  printf '%s\n' "$default_json" >"$output_path"
  printf 'missing'
}

check_shape() {
  local file="$1"
  local expr="$2"
  local code="$3"
  local source_id="$4"
  local detail="$5"
  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    append_reason "$code" "$source_id" "$detail"
  fi
}

br_ready_status="$(load_json "$br_ready_json" '[]' "$br_ready_normalized" 'br_ready_json' true)"
br_open_status="$(load_json "$br_open_json" '{"issues":[]}' "$br_open_normalized" 'br_open_json' true)"
br_in_progress_status="$(load_json "$br_in_progress_json" '{"issues":[]}' "$br_in_progress_normalized" 'br_in_progress_json' true)"
br_blocked_status="$(load_json "$br_blocked_json" '{"issues":[]}' "$br_blocked_normalized" 'br_blocked_json' true)"
bv_plan_status="$(load_json "$bv_robot_plan_json" '{"plan":{"tracks":[]}}' "$bv_plan_normalized" 'bv_robot_plan_json' true)"
agent_mail_status="$(load_json "$agent_mail_snapshot_json" 'null' "$agent_mail_normalized" 'agent_mail_snapshot_json' false)"
git_status_status="$(load_json "$git_status_snapshot_json" '{"branch":"unknown","dirty_paths":[]}' "$git_status_normalized" 'git_status_snapshot_json' true)"

if [[ -n "$source_freshness_json" ]]; then
  if [[ ! -f "$source_freshness_json" ]]; then
    printf 'missing source_freshness_json: %s\n' "$source_freshness_json" >&2
    exit 64
  fi
  if ! jq empty "$source_freshness_json" >/dev/null 2>&1; then
    printf 'invalid source_freshness_json: %s\n' "$source_freshness_json" >&2
    exit 64
  fi
  jq -cS . "$source_freshness_json" >"$source_freshness_normalized"
  source_freshness_status="provided"
elif [[ "$collect_live" == true ]]; then
  missing_optional_sources='[]'
  if [[ "$agent_mail_status" == "missing" ]]; then
    missing_optional_sources='["agent_mail_snapshot_json"]'
  fi
  jq -n \
    --argjson missing_optional_sources "$missing_optional_sources" \
    '{
      db_newer: false,
      all_sources_fresh: true,
      missing_optional_sources: $missing_optional_sources,
      collected_live: true
    }' >"$source_freshness_normalized"
  source_freshness_status="generated_live"
else
  printf 'missing required source_freshness_json\n' >&2
  exit 64
fi

check_shape "$br_ready_normalized" '(type == "array") or (type == "object" and ((.issues // null) | type == "array"))' \
  "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "br_ready_json" "br ready snapshot must be an array or object with issues[]"
check_shape "$br_open_normalized" '(type == "array") or (type == "object" and ((.issues // null) | type == "array"))' \
  "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "br_open_json" "br open snapshot must be an array or object with issues[]"
check_shape "$br_in_progress_normalized" '(type == "array") or (type == "object" and ((.issues // null) | type == "array"))' \
  "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "br_in_progress_json" "br in-progress snapshot must be an array or object with issues[]"
check_shape "$br_blocked_normalized" '(type == "array") or (type == "object" and ((.issues // null) | type == "array"))' \
  "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "br_blocked_json" "br blocked snapshot must be an array or object with issues[]"
check_shape "$bv_plan_normalized" '(type == "object" and ((.plan.tracks // null) | type == "array"))' \
  "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "bv_robot_plan_json" "bv robot plan snapshot must expose plan.tracks[]"
check_shape "$git_status_normalized" '(type == "object" and ((.dirty_paths // null) | type == "array"))' \
  "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "git_status_snapshot_json" "git status snapshot must expose dirty_paths[]"
check_shape "$source_freshness_normalized" '(type == "object" and (.db_newer | type == "boolean") and (.all_sources_fresh | type == "boolean"))' \
  "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "source_freshness_json" "source freshness snapshot must expose db_newer/all_sources_fresh booleans"
if [[ "$agent_mail_status" != "missing" ]]; then
  check_shape "$agent_mail_normalized" '(type == "null") or (type == "object" and (((.agents // []) | type == "array") and ((.active_reservations // []) | type == "array")))' \
    "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" "agent_mail_snapshot_json" "Agent Mail snapshot must be null or expose agents[] and active_reservations[]"
fi

write_event \
  "inputs_loaded" \
  "br_ready=${br_ready_status} br_open=${br_open_status} br_in_progress=${br_in_progress_status} br_blocked=${br_blocked_status} bv_plan=${bv_plan_status} agent_mail=${agent_mail_status} git_status=${git_status_status} source_freshness=${source_freshness_status}"

jq_filter="$(cat <<'JQ'
def issue_array:
  if type == "array" then .
  elif type == "object" and ((.issues // null) | type == "array") then .issues
  else []
  end;

def unique_codes:
  map(select(type == "string" and length > 0)) | unique | sort;

def bv_items:
  (.plan.tracks // []) | map(.items // []) | add // [];

def reservation_array:
  if . == null then [] else (.active_reservations // []) end;

def dirty_match($pattern; $path):
  if ($pattern | type) != "string" or ($path | type) != "string" or ($pattern | length) == 0 or ($path | length) == 0 then
    false
  elif ($pattern | endswith("*")) then
    $path | startswith($pattern[0:-1])
  else
    ($path == $pattern) or ($path | startswith($pattern + "/"))
  end;

def overlaps_dirty($reservation; $dirty_paths):
  (($reservation.path_pattern // $reservation.path // $reservation.file // "") as $pattern
  | any($dirty_paths[]?; dirty_match($pattern; .)));

def states_for($id; $ready; $open; $in_progress; $blocked; $bv; $reservations; $dirty_paths; $stale):
  [
    if $stale then "stale_source" else empty end,
    if any($ready[]?; .id == $id) then "ready" else empty end,
    if any($open[]?; .id == $id) then "open_blocked" else empty end,
    if any($in_progress[]?; .id == $id) then "in_progress" else empty end,
    if any($blocked[]?; .id == $id) then "blocked" else empty end,
    if any($reservations[]?; ((.bead_id // .candidate_id // .id // "") == $id) and ((.exclusive // true) == true)) then "reserved" else empty end,
    if any($reservations[]?; overlaps_dirty(.; $dirty_paths)) then "dirty_overlap" else empty end,
    if any($bv[]?; .id == $id) | not and any($ready[]?; .id == $id) | not and any($open[]?; .id == $id) | not and any($in_progress[]?; .id == $id) | not and any($blocked[]?; .id == $id) | not then "missing_source" else empty end
  ] | unique;

def reason_codes_for($id; $ready; $open; $in_progress; $blocked; $bv; $reservations; $dirty_paths; $stale):
  (
    any($ready[]?; .id == $id) as $is_ready
    | any($in_progress[]?; .id == $id) as $is_in_progress
    | any($blocked[]?; .id == $id) as $is_blocked
    | any($bv[]?; .id == $id) as $is_bv_actionable
    | any($reservations[]?; ((.bead_id // .candidate_id // .id // "") == $id) and ((.exclusive // true) == true)) as $is_reserved
    | any($reservations[]?; overlaps_dirty(.; $dirty_paths)) as $has_dirty_overlap
    | [
        if $stale then "FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE" else empty end,
        if $is_blocked and $is_bv_actionable then "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE" else empty end,
        if $is_in_progress and $is_bv_actionable then "FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE" else empty end,
        if $is_reserved then "FE-SWARM-ACTIONABILITY-ACTIVE-RESERVATION" else empty end,
        if $has_dirty_overlap then "FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP" else empty end,
        if (($is_ready and ($is_bv_actionable | not)) or (($is_bv_actionable and ($is_ready | not) and ($is_blocked | not) and ($is_in_progress | not)))) then
          "FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE"
        else
          empty
        end
      ] | unique_codes
  );

def candidate_decision($states; $reasons):
  if ($reasons | index("FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE")) != null then
    "fail_closed"
  elif ($reasons | index("FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE")) != null then
    "fail_closed"
  elif ($reasons | index("FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE")) != null then
    "fail_closed"
  elif ($states | index("in_progress")) != null then
    "defer"
  elif ($states | index("reserved")) != null or ($states | index("dirty_overlap")) != null then
    "defer"
  elif ($states | index("ready")) != null then
    "safe_to_claim"
  else
    "observe_only"
  end;

($br_ready[0] | issue_array) as $ready
| ($br_open[0] | issue_array) as $open
| ($br_in_progress[0] | issue_array) as $in_progress
| ($br_blocked[0] | issue_array) as $blocked
| ($bv_plan[0] | bv_items) as $bv
| $agent_mail[0] as $mail
| ($mail | reservation_array) as $reservations
| ($git_status[0].dirty_paths // []) as $dirty_paths
| $source_freshness[0] as $freshness
| (($freshness.db_newer // false) or (($freshness.all_sources_fresh // true) | not)) as $stale_sources
| (
    (($ready + $open + $in_progress + $blocked + $bv) | map(.id) | map(select(type == "string" and length > 0)) | unique | sort)
  ) as $candidate_ids
| (
    $candidate_ids
    | map(
        . as $id
        | (states_for($id; $ready; $open; $in_progress; $blocked; $bv; $reservations; $dirty_paths; $stale_sources)) as $states
        | (reason_codes_for($id; $ready; $open; $in_progress; $blocked; $bv; $reservations; $dirty_paths; $stale_sources)) as $reasons
        | {
            candidate_id: $id,
            decision: candidate_decision($states; $reasons),
            states: $states,
            reason_codes: $reasons,
            evidence: {
              in_br_ready: any($ready[]?; .id == $id),
              in_br_open: any($open[]?; .id == $id),
              in_br_in_progress: any($in_progress[]?; .id == $id),
              in_br_blocked: any($blocked[]?; .id == $id),
              in_bv_actionable: any($bv[]?; .id == $id),
              dirty_paths: $dirty_paths,
              active_reservations: [
                $reservations[]?
                | select(((.bead_id // .candidate_id // .id // "") == $id) or overlaps_dirty(.; $dirty_paths))
              ],
              assignees: (
                ($open + $in_progress + $blocked)
                | map(select(.id == $id) | .assignee // empty)
                | map(select(type == "string" and length > 0))
                | unique
              )
            }
          }
      )
  ) as $candidate_reports
| (
    [
      (if (($freshness.missing_optional_sources // []) | index("agent_mail_snapshot_json")) != null then
        {
          code: "FE-SWARM-ACTIONABILITY-MISSING-SOURCE",
          source_id: "agent_mail_snapshot_json",
          detail: "optional Agent Mail snapshot missing; ownership evidence is incomplete"
        }
      else
        empty
      end)
    ]
    + ($raw_reasons | map({code: .code, source_id: .source_id, detail: .detail}))
    + (
      $candidate_reports
      | map(
          .reason_codes[]
          | {
              code: .,
              source_id: .,
              detail: (
                if . == "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE" then "blocked bead advertised as actionable in bv"
                elif . == "FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE" then "in-progress bead advertised as actionable in bv"
                elif . == "FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE" then "br ready and bv actionable disagree on claimability"
                elif . == "FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE" then "source freshness metadata reports stale exported state"
                elif . == "FE-SWARM-ACTIONABILITY-ACTIVE-RESERVATION" then "active reservation conflicts with claim safety"
                elif . == "FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP" then "dirty worktree overlaps reserved or claimed surface"
                elif . == "FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE" then "required source shape is malformed"
                else "actionability guard detected an unsafe condition"
                end
              )
            }
        )
      )
  ) as $all_reasons
| ($all_reasons | unique_by(.code + "|" + .source_id + "|" + .detail)) as $deduped_reasons
| (
    if any($candidate_reports[]?; .decision == "fail_closed") then "fail_closed"
    elif any($candidate_reports[]?; .decision == "safe_to_claim") then "safe_to_claim"
    elif any($candidate_reports[]?; .decision == "defer") then "defer"
    elif (($freshness.missing_optional_sources // []) | index("agent_mail_snapshot_json")) != null then "observe_only"
    else "observe_only"
    end
  ) as $decision
| (
    if $decision == "fail_closed" then ($candidate_reports | map(select(.decision == "fail_closed")) | .[0].candidate_id)
    elif $decision == "safe_to_claim" then ($candidate_reports | map(select(.decision == "safe_to_claim")) | .[0].candidate_id)
    elif $decision == "defer" then ($candidate_reports | map(select(.decision == "defer")) | .[0].candidate_id)
    else null
    end
  ) as $primary_candidate_id
| {
    schema_version: $schema_version,
    source_revision: $source_revision,
    generated_epoch_seconds: $generated_epoch_seconds,
    decision: $decision,
    primary_candidate_id: $primary_candidate_id,
    candidate_summary: {
      candidate_count: ($candidate_reports | length),
      ready_count: ($candidate_reports | map(select(.states | index("ready") != null)) | length),
      in_progress_count: ($candidate_reports | map(select(.states | index("in_progress") != null)) | length),
      blocked_count: ($candidate_reports | map(select(.states | index("blocked") != null)) | length),
      reservation_count: ($candidate_reports | map(select(.states | index("reserved") != null)) | length),
      dirty_overlap_count: ($candidate_reports | map(select(.states | index("dirty_overlap") != null)) | length)
    },
    candidate_reports: $candidate_reports,
    fail_closed_reasons: $deduped_reasons,
    remediation_commands: (
      [
        if any($deduped_reasons[]?; .code == "FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE") then "br ready --json" else empty end,
        if any($deduped_reasons[]?; .code == "FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE") then "bv --recipe actionable --robot-plan" else empty end,
        if any($deduped_reasons[]?; .code == "FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE") then "br sync --status --json" else empty end,
        if any($deduped_reasons[]?; .code == "FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE") then "br list --status=in_progress --json" else empty end,
        if any($deduped_reasons[]?; .code == "FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP") then "git status --short --branch" else empty end
      ] | unique
    ),
    source_freshness: $freshness,
    artifact_paths: {
      actionability_report_json: $report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $markdown_path
    },
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      mutates_br: false,
      claims_beads: false,
      reopens_beads: false,
      closes_beads: false,
      reassigns_beads: false,
      releases_reservations: false,
      sends_agent_mail: false,
      mutates_git: false,
      runs_cargo: false,
      runs_rch: false,
      mutates_remote_workers: false,
      changes_live_queue_policy: false
    }
  }
JQ
)"

jq -n \
  --arg schema_version "franken-engine.swarm-actionability-truth-gate.v1" \
  --arg source_revision "$source_revision" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg markdown_path "$markdown_path" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --slurpfile br_ready "$br_ready_normalized" \
  --slurpfile br_open "$br_open_normalized" \
  --slurpfile br_in_progress "$br_in_progress_normalized" \
  --slurpfile br_blocked "$br_blocked_normalized" \
  --slurpfile bv_plan "$bv_plan_normalized" \
  --slurpfile agent_mail "$agent_mail_normalized" \
  --slurpfile git_status "$git_status_normalized" \
  --slurpfile source_freshness "$source_freshness_normalized" \
  --slurpfile raw_reasons "$reasons_jsonl" \
  "$jq_filter" >"$report_tmp"
mv "$report_tmp" "$report_path"

decision="$(jq -r '.decision' "$report_path")"
primary_candidate_id="$(jq -r '.primary_candidate_id // ""' "$report_path")"

write_event "report_written" "decision=${decision} primary_candidate_id=${primary_candidate_id:-none}"
if [[ "$decision" == "fail_closed" ]]; then
  write_event "fail_closed" "actionability gate refused to nominate a safe claim"
fi

jq -r '
  [
    "# SWARM_ACTIONABILITY_TRUTH_GATE",
    "",
    "- decision: `\(.decision)`",
    "- primary candidate: `\(.primary_candidate_id // "none")`",
    "- fail-closed reasons: " + (
      if (.fail_closed_reasons | length) == 0 then
        "`none`"
      else
        (.fail_closed_reasons | map("`\(.code)`") | join(", "))
      end
    ),
    "",
    "## Summary",
    "- candidate count: \(.candidate_summary.candidate_count)",
    "- ready count: \(.candidate_summary.ready_count)",
    "- in-progress count: \(.candidate_summary.in_progress_count)",
    "- blocked count: \(.candidate_summary.blocked_count)",
    "- reservation count: \(.candidate_summary.reservation_count)",
    "- dirty overlap count: \(.candidate_summary.dirty_overlap_count)"
  ] | join("\n")
' "$report_path" >"$markdown_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
