#!/usr/bin/env bash
set -euo pipefail

artifact_root="${STALE_LOCK_RECOMMENDER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-stale-lock-recommender}"
run_id="${STALE_LOCK_RECOMMENDER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${STALE_LOCK_RECOMMENDER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

in_progress_json=""
agent_profiles_json=""
thread_timestamps_json=""
file_reservations_json=""
git_activity_json=""
now_epoch_seconds="$(date -u +%s)"
stale_owner_seconds="21600"
recent_activity_seconds="3600"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/stale_lock_stalled_bead_recommender.sh --in-progress-json FILE [OPTIONS]

Builds evidence packets for likely abandoned in-progress beads. The recommender
never runs br update, never steals reservations, and never mutates the worktree.

Required:
  --in-progress-json FILE          Fixture from br list --status=in_progress --json.

Optional Agent Mail / activity snapshots:
  --agent-profiles-json FILE       Agent Mail list_agents output.
  --thread-timestamps-json FILE    Inbox/thread message timestamp snapshot.
  --file-reservations-json FILE    Active file reservation snapshot.
  --git-activity-json FILE         Optional recent git/touched-path snapshot.

Options:
  --output-dir DIR
  --now-epoch-seconds N
  --stale-owner-seconds N          Owner inactivity threshold.
  --recent-activity-seconds N      Recent mail/git activity window.

Writes stale_lock_recommendations.json, events.jsonl, commands.txt, and report.md.
Exit code 0 means a recommendation packet was produced.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --in-progress-json)
      in_progress_json="${2:-}"
      shift 2
      ;;
    --agent-profiles-json)
      agent_profiles_json="${2:-}"
      shift 2
      ;;
    --thread-timestamps-json)
      thread_timestamps_json="${2:-}"
      shift 2
      ;;
    --file-reservations-json)
      file_reservations_json="${2:-}"
      shift 2
      ;;
    --git-activity-json)
      git_activity_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
      shift 2
      ;;
    --stale-owner-seconds)
      stale_owner_seconds="${2:-}"
      shift 2
      ;;
    --recent-activity-seconds)
      recent_activity_seconds="${2:-}"
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

if [[ -z "$in_progress_json" ]]; then
  printf 'stale lock recommender requires --in-progress-json\n' >&2
  usage
  exit 64
fi
if ! is_int "$now_epoch_seconds" ||
  ! is_int "$stale_owner_seconds" ||
  ! is_int "$recent_activity_seconds"; then
  printf 'now/stale/recent thresholds must be non-negative integers\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
recommendations_path="${run_dir}/stale_lock_recommendations.json"
recommendations_tmp="${recommendations_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
in_progress_normalized="${run_dir}/in_progress.normalized.json"
agents_normalized="${run_dir}/agent_profiles.normalized.json"
threads_normalized="${run_dir}/thread_timestamps.normalized.json"
reservations_normalized="${run_dir}/file_reservations.normalized.json"
git_normalized="${run_dir}/git_activity.normalized.json"
: >"$events_path"

printf './scripts/stale_lock_stalled_bead_recommender.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

required_json_input() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'stale lock recommender missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'stale lock recommender invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
}

optional_json_input() {
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
    printf 'stale lock recommender missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'stale lock recommender invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

required_json_input "$in_progress_json" "$in_progress_normalized" "in-progress bead snapshot"
agent_mail_profile_status="$(optional_json_input "$agent_profiles_json" '{"agents":[]}' "$agents_normalized" 'agent profiles')"
agent_mail_thread_status="$(optional_json_input "$thread_timestamps_json" '{"messages":[]}' "$threads_normalized" 'thread timestamps')"
agent_mail_reservation_status="$(optional_json_input "$file_reservations_json" '{"reservations":[]}' "$reservations_normalized" 'file reservations')"
git_activity_status="$(optional_json_input "$git_activity_json" '{"activity":[]}' "$git_normalized" 'git activity')"

jq -n \
  --slurpfile in_progress "$in_progress_normalized" \
  --slurpfile agents "$agents_normalized" \
  --slurpfile threads "$threads_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile git_activity "$git_normalized" \
  --arg schema_version "franken-engine.stale-lock-recommendations.v1" \
  --arg agent_mail_profile_status "$agent_mail_profile_status" \
  --arg agent_mail_thread_status "$agent_mail_thread_status" \
  --arg agent_mail_reservation_status "$agent_mail_reservation_status" \
  --arg git_activity_status "$git_activity_status" \
  --arg recommendations_path "$recommendations_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_owner_seconds "$stale_owner_seconds" \
  --argjson recent_activity_seconds "$recent_activity_seconds" \
  '
  def arr($x; $name): if ($x | type) == "array" then $x else ($x[$name] // []) end;
  def epoch:
    if . == null then 0
    elif type == "number" then .
    elif type == "string" then
      (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601? // 0)
    else 0 end;
  def in_progress_rows: arr($in_progress[0]; "issues");
  def agent_rows: arr($agents[0]; "agents");
  def thread_rows: arr($threads[0]; "messages");
  def reservation_rows: arr($reservations[0]; "reservations");
  def git_rows: arr($git_activity[0]; "activity");
  def owner($issue): ($issue.assignee // $issue.owner // "");
  def priority($issue): (($issue.priority // 3) | tonumber);
  def profile_for($name):
    first(agent_rows[]? | select((.name // .agent_name // "") == $name)) // {};
  def last_active_epoch($profile):
    ($profile.last_active_epoch_seconds // $profile.last_active_ts // $profile.last_seen // 0) | epoch;
  def recent_threads($issue; $owner):
    [
      thread_rows[]?
      | ((.created_epoch_seconds // .created_ts // .updated_epoch_seconds // .updated_ts // 0) | epoch) as $ts
      | select($ts >= ($now_epoch_seconds - $recent_activity_seconds))
      | select(
          ((.thread_id // "") == ($issue.id // ""))
          or ((.subject // "") | contains($issue.id // ""))
          or ((.from // .sender // "") == $owner)
          or ((.to // []) | tostring | contains($owner))
        )
    ];
  def active_reservations($issue; $owner):
    [
      reservation_rows[]?
      | ((.expires_epoch_seconds // .expires_ts // 0) | epoch) as $expires
      | select($expires == 0 or $expires >= $now_epoch_seconds)
      | select(
          ((.bead_id // "") == ($issue.id // ""))
          or ((.agent_id // .agent_name // .holder // "") == $owner)
      )
    ];
  def recent_git_activity($issue; $owner):
    [
      git_rows[]?
      | ((.touched_epoch_seconds // .committed_epoch_seconds // .created_epoch_seconds // .ts // 0) | epoch) as $ts
      | select($ts >= ($now_epoch_seconds - $recent_activity_seconds))
      | select(
          ((.bead_id // "") == ($issue.id // ""))
          or ((.agent_id // .agent_name // .author // "") == $owner)
      )
    ];
  def degraded_reasons:
    [
      if $agent_mail_profile_status == "missing" then "agent_profiles_missing" else empty end,
      if $agent_mail_thread_status == "missing" then "thread_timestamps_missing" else empty end,
      if $agent_mail_reservation_status == "missing" then "file_reservations_missing" else empty end,
      if $git_activity_status == "missing" then "git_activity_missing" else empty end
    ];
  def recommendation_for($issue):
    (owner($issue)) as $owner
    | (profile_for($owner)) as $profile
    | (last_active_epoch($profile)) as $last_active
    | (if $last_active == 0 then 999999999 else ($now_epoch_seconds - $last_active) end) as $inactive_seconds
    | (active_reservations($issue; $owner)) as $reservations
    | (recent_threads($issue; $owner)) as $threads
    | (recent_git_activity($issue; $owner)) as $git_recent
    | (degraded_reasons) as $degraded
    | (priority($issue) <= 1) as $high_priority
    | ($inactive_seconds >= $stale_owner_seconds) as $owner_stale
    | ($reservations | length) as $reservation_count
    | ($threads | length) as $thread_count
    | ($git_recent | length) as $git_count
    | (
        ($degraded | length) == 0
        and ($owner != "")
        and $owner_stale
        and ($reservation_count == 0)
        and ($thread_count == 0)
        and ($git_count == 0)
        and ($high_priority | not)
      ) as $safe
    | {
        bead_id: ($issue.id // ""),
        title: ($issue.title // ""),
        priority: priority($issue),
        assignee: $owner,
        safe_to_reopen: $safe,
        contact_first: ($safe | not),
        recommendation: (
          if $safe then "safe_to_reopen"
          elif ($degraded | length) > 0 then "manual_confirmation_required"
          elif $high_priority then "contact_first_high_priority"
          elif ($reservation_count > 0) then "contact_first_active_reservation"
          elif ($thread_count > 0) then "contact_first_recent_thread"
          elif ($git_count > 0) then "contact_first_recent_git_activity"
          elif ($owner_stale | not) then "owner_active"
          else "contact_first"
          end
        ),
        evidence: {
          now_epoch_seconds: $now_epoch_seconds,
          owner_last_active_epoch_seconds: $last_active,
          owner_inactive_seconds: $inactive_seconds,
          stale_owner_threshold_seconds: $stale_owner_seconds,
          active_reservations_count: $reservation_count,
          recent_thread_count: $thread_count,
          recent_git_activity_count: $git_count,
          high_priority_requires_contact: $high_priority,
          degraded_reasons: $degraded,
          active_reservations: ($reservations | map({path_pattern:(.path_pattern // .path // ""), holder:(.agent_id // .agent_name // .holder // ""), bead_id:(.bead_id // ""), expires_ts:(.expires_ts // "")})),
          recent_threads: ($threads | map({thread_id:(.thread_id // ""), subject:(.subject // ""), from:(.from // .sender // ""), created_ts:(.created_ts // "")})),
          recent_git_activity: ($git_recent | map({path:(.path // ""), bead_id:(.bead_id // ""), agent_id:(.agent_id // .agent_name // .author // ""), touched_ts:(.touched_ts // "")}))
        },
        suggested_br_commands: (
          if $safe then
            ["br update " + ($issue.id // "") + " --status open --assignee \"\""]
          else
            []
          end
        ),
        contact_commands: [
          "fetch inbox and thread messages for " + ($issue.id // ""),
          "send Agent Mail contact-first message to " + (if $owner == "" then "current assignee" else $owner end)
        ]
      };
  (in_progress_rows | map(recommendation_for(.)) | sort_by([(.safe_to_reopen | not), .priority, .bead_id])) as $recommendations
  | {
      schema_version: $schema_version,
      generated_epoch_seconds: $now_epoch_seconds,
      stale_owner_seconds: $stale_owner_seconds,
      recent_activity_seconds: $recent_activity_seconds,
      snapshot_status: {
        agent_profiles: $agent_mail_profile_status,
        thread_timestamps: $agent_mail_thread_status,
        file_reservations: $agent_mail_reservation_status,
        git_activity: $git_activity_status
      },
      stale_lock_recommendations: $recommendations,
      safe_to_reopen: [$recommendations[] | select(.safe_to_reopen) | .bead_id],
      contact_first: [$recommendations[] | select(.contact_first) | .bead_id],
      evidence: [$recommendations[] | {bead_id, evidence}],
      artifact_paths: {
        stale_lock_recommendations_json: $recommendations_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }
  ' >"$recommendations_tmp"
mv "$recommendations_tmp" "$recommendations_path"

jq -c '
  .stale_lock_recommendations[]
  | {
      schema_version: "franken-engine.stale-lock-recommendation-event.v1",
      event_name: "stale_lock_recommender.recommendation",
      bead_id,
      assignee,
      safe_to_reopen,
      contact_first,
      recommendation
    }
' "$recommendations_path" >>"$events_path"

{
  printf '# Stale Lock Recommendations\n\n'
  printf "%s\n" "- Recommendations: \`$(jq '.stale_lock_recommendations | length' "$recommendations_path")\`"
  printf "%s\n" "- Safe to reopen: \`$(jq '.safe_to_reopen | length' "$recommendations_path")\`"
  printf "%s\n" "- Contact first: \`$(jq '.contact_first | length' "$recommendations_path")\`"
} >"$report_path"
