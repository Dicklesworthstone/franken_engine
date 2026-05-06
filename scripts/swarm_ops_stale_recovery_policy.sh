#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_OPS_STALE_RECOVERY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-ops-stale-recovery}"
run_id="${SWARM_OPS_STALE_RECOVERY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPS_STALE_RECOVERY_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

in_progress_json=""
agent_profiles_json=""
mail_activity_json=""
file_reservations_json=""
git_activity_json=""
now_epoch_seconds="$(date -u +%s)"
stale_owner_seconds="21600"
recent_activity_seconds="3600"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_ops_stale_recovery_policy.sh --in-progress-json FILE [OPTIONS]

Builds SWARM-OPS stale bead and reservation recovery receipts. The policy is
advisory-only: it never runs br update, never force-releases reservations, never
sends Agent Mail, and never mutates the worktree.

Required:
  --in-progress-json FILE

Optional evidence snapshots:
  --agent-profiles-json FILE
  --mail-activity-json FILE
  --file-reservations-json FILE
  --git-activity-json FILE

Options:
  --output-dir DIR
  --now-epoch-seconds N
  --stale-owner-seconds N
  --recent-activity-seconds N

Artifacts:
  recovery_receipts.json
  events.jsonl
  commands.txt
  report.md
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
    --mail-activity-json)
      mail_activity_json="${2:-}"
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
  printf 'swarm ops stale recovery policy requires --in-progress-json\n' >&2
  usage
  exit 64
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_owner_seconds" || ! is_int "$recent_activity_seconds"; then
  printf 'now/stale/recent thresholds must be non-negative integers\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm ops stale recovery policy\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
receipts_path="${run_dir}/recovery_receipts.json"
receipts_tmp="${receipts_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
in_progress_normalized="${run_dir}/in_progress.normalized.json"
agents_normalized="${run_dir}/agent_profiles.normalized.json"
mail_normalized="${run_dir}/mail_activity.normalized.json"
reservations_normalized="${run_dir}/file_reservations.normalized.json"
git_normalized="${run_dir}/git_activity.normalized.json"
: >"$events_path"

printf './scripts/swarm_ops_stale_recovery_policy.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

required_json_input() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'swarm ops stale recovery policy missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq empty "$path" >/dev/null
  jq -c . "$path" >"$output_path"
}

optional_json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  if [[ -z "$path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'missing'
    printf '%s\n' "$default_json" >"$output_path"
    return 0
  fi
  jq empty "$path" >/dev/null
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

required_json_input "$in_progress_json" "$in_progress_normalized" "in-progress bead"
agent_profiles_status="$(optional_json_input "$agent_profiles_json" '{"agents":[]}' "$agents_normalized")"
mail_activity_status="$(optional_json_input "$mail_activity_json" '{"messages":[]}' "$mail_normalized")"
file_reservations_status="$(optional_json_input "$file_reservations_json" '{"reservations":[]}' "$reservations_normalized")"
git_activity_status="$(optional_json_input "$git_activity_json" '{"activity":[]}' "$git_normalized")"

jq -n \
  --slurpfile in_progress "$in_progress_normalized" \
  --slurpfile agents "$agents_normalized" \
  --slurpfile mail "$mail_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile git_activity "$git_normalized" \
  --arg schema_version "franken-engine.swarm-ops-stale-recovery-receipts.v1" \
  --arg event_schema_version "franken-engine.swarm-ops-stale-recovery-event.v1" \
  --arg agent_profiles_status "$agent_profiles_status" \
  --arg mail_activity_status "$mail_activity_status" \
  --arg file_reservations_status "$file_reservations_status" \
  --arg git_activity_status "$git_activity_status" \
  --arg receipts_path "$receipts_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_owner_seconds "$stale_owner_seconds" \
  --argjson recent_activity_seconds "$recent_activity_seconds" '
    def arr($x; $name): if ($x | type) == "array" then $x else ($x[$name] // []) end;
    def epoch:
      if . == null then 0
      elif type == "number" then .
      elif type == "string" then (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601? // 0)
      else 0 end;
    def issues: arr($in_progress[0]; "issues");
    def agents: arr($agents[0]; "agents");
    def messages: arr($mail[0]; "messages");
    def reservations: arr($reservations[0]; "reservations");
    def git_rows: arr($git_activity[0]; "activity");
    def owner($issue): ($issue.assignee // $issue.owner // "");
    def profile_for($name): first(agents[]? | select((.name // .agent_name // "") == $name)) // {};
    def last_active($profile): ($profile.last_active_epoch_seconds // $profile.last_active_ts // $profile.last_seen // 0) | epoch;
    def msg_epoch($m): ($m.created_epoch_seconds // $m.created_ts // $m.updated_epoch_seconds // $m.updated_ts // 0) | epoch;
    def reservation_expiry($r): ($r.expires_epoch_seconds // $r.expires_ts // 0) | epoch;
    def git_epoch($g): ($g.touched_epoch_seconds // $g.committed_epoch_seconds // $g.created_epoch_seconds // $g.ts // 0) | epoch;
    def owner_messages($issue; $name):
      [messages[]?
       | select(
           ((.thread_id // "") == ($issue.id // ""))
           or ((.subject // "") | contains($issue.id // ""))
           or ((.from // .sender // "") == $name)
           or ((.to // []) | tostring | contains($name))
         )];
    def recent_owner_messages($issue; $name):
      [owner_messages($issue; $name)[] | select((msg_epoch(.) >= ($now_epoch_seconds - $recent_activity_seconds)) and (msg_epoch(.) <= $now_epoch_seconds))];
    def contradictory_mail($issue; $name):
      [owner_messages($issue; $name)[]
       | select((.contradictory // false) == true or (msg_epoch(.) > $now_epoch_seconds))];
    def matching_reservations($issue; $name):
      [reservations[]?
       | select(
           ((.bead_id // "") == ($issue.id // ""))
           or ((.agent_id // .agent_name // .holder // "") == $name)
         )];
    def active_reservations($issue; $name):
      [matching_reservations($issue; $name)[] | select((reservation_expiry(.) == 0) or (reservation_expiry(.) >= $now_epoch_seconds))];
    def expired_reservations($issue; $name):
      [matching_reservations($issue; $name)[] | select((reservation_expiry(.) > 0) and (reservation_expiry(.) < $now_epoch_seconds))];
    def recent_git($issue; $name):
      [git_rows[]?
       | select((git_epoch(.) >= ($now_epoch_seconds - $recent_activity_seconds)) and (git_epoch(.) <= $now_epoch_seconds))
       | select(((.bead_id // "") == ($issue.id // "")) or ((.agent_id // .agent_name // .author // "") == $name))];
    def missing_evidence:
      [
        if $agent_profiles_status == "missing" then "agent_profiles_missing" else empty end,
        if $mail_activity_status == "missing" then "mail_activity_missing" else empty end,
        if $file_reservations_status == "missing" then "file_reservations_missing" else empty end,
        if $git_activity_status == "missing" then "git_activity_missing" else empty end
      ];
    def mail_template($issue; $name; $class):
      {
        to: [$name],
        subject: ("[" + ($issue.id // "unknown") + "] stale ownership recovery check"),
        ack_required: true,
        body_md: ("Please acknowledge whether you are still actively working `" + ($issue.id // "unknown") + "`. The SWARM-OPS stale recovery policy classified this as `" + $class + "` and will not auto-reopen or force-release reservations.")
      };
    def receipt_for($issue):
      (owner($issue)) as $name
      | (profile_for($name)) as $profile
      | (last_active($profile)) as $last_active_epoch
      | (if $last_active_epoch == 0 then 999999999 else ($now_epoch_seconds - $last_active_epoch) end) as $inactive_seconds
      | (recent_owner_messages($issue; $name)) as $recent_mail
      | (contradictory_mail($issue; $name)) as $contradictions
      | (active_reservations($issue; $name)) as $active_res
      | (expired_reservations($issue; $name)) as $expired_res
      | (recent_git($issue; $name)) as $recent_git_rows
      | (missing_evidence) as $missing
      | ($inactive_seconds >= $stale_owner_seconds) as $owner_stale
      | (
          if ($missing | length) > 0 then "manual-review"
          elif ($contradictions | length) > 0 then "manual-review"
          elif (($active_res | length) > 0 and (($recent_mail | length) > 0 or ($owner_stale | not))) then "blocked-by-active-agent"
          elif (($owner_stale | not) or (($recent_mail | length) > 0 and ($owner_stale | not))) then "healthy"
          elif (($recent_git_rows | length) > 0 or ($recent_mail | length) > 0) then "needs-contact"
          elif ($owner_stale and (($active_res | length) == 0)) then "safe-to-reopen"
          else "needs-contact"
          end
        ) as $class
      | (
          if ($missing | length) > 0 then "incomplete_activity_evidence"
          elif ($contradictions | length) > 0 then "contradictory_mail_state"
          elif $class == "blocked-by-active-agent" then "active_agent_or_reservation"
          elif $class == "healthy" then "owner_recently_active"
          elif $class == "needs-contact" then "recent_activity_requires_ack"
          elif $class == "safe-to-reopen" and (($expired_res | length) > 0) then "stale_owner_only_expired_reservations"
          elif $class == "safe-to-reopen" then "stale_owner_no_recent_activity"
          else "manual_review"
          end
        ) as $reason
      | {
          bead_id: ($issue.id // ""),
          title: ($issue.title // ""),
          assignee: $name,
          classification: $class,
          reason_code: $reason,
          evidence: {
            now_epoch_seconds: $now_epoch_seconds,
            owner_last_active_epoch_seconds: $last_active_epoch,
            owner_inactive_seconds: $inactive_seconds,
            stale_owner_threshold_seconds: $stale_owner_seconds,
            recent_activity_threshold_seconds: $recent_activity_seconds,
            recent_mail_count: ($recent_mail | length),
            active_reservation_count: ($active_res | length),
            expired_reservation_count: ($expired_res | length),
            recent_git_activity_count: ($recent_git_rows | length),
            missing_evidence: $missing,
            contradictory_mail_count: ($contradictions | length)
          },
          suggested_operator_commands: (
            if $class == "safe-to-reopen" then
              ["br update " + ($issue.id // "") + " --status open --assignee \"\""]
            else []
            end
          ),
          force_release_commands: (
            if $class == "safe-to-reopen" and (($active_res | length) > 0) then
              ($active_res | map("am file_reservations release <project> --reservation-id " + ((.id // .file_reservation_id // "") | tostring)))
            else []
            end
          ),
          agent_mail_notification_template: (if $class == "healthy" or $name == "" then null else mail_template($issue; $name; $class) end),
          mutation_policy: {
            advisory_only: true,
            mutates_br: false,
            reopens_beads: false,
            force_releases_reservations: false,
            sends_agent_mail: false
          }
        };
    (issues | map(receipt_for(.)) | sort_by(.classification, .bead_id)) as $receipts
    | {
        schema_version: $schema_version,
        generated_epoch_seconds: $now_epoch_seconds,
        stale_owner_seconds: $stale_owner_seconds,
        recent_activity_seconds: $recent_activity_seconds,
        decision: (
          if any($receipts[]?; .classification == "manual-review" and (.reason_code == "incomplete_activity_evidence" or .reason_code == "contradictory_mail_state")) then "fail_closed"
          elif any($receipts[]?; .classification == "blocked-by-active-agent") then "blocked"
          elif any($receipts[]?; .classification == "needs-contact") then "degraded"
          else "pass" end
        ),
        snapshot_status: {
          agent_profiles: $agent_profiles_status,
          mail_activity: $mail_activity_status,
          file_reservations: $file_reservations_status,
          git_activity: $git_activity_status
        },
        recovery_receipts: $receipts,
        summary: {
          total: ($receipts | length),
          healthy: ($receipts | map(select(.classification == "healthy")) | length),
          needs_contact: ($receipts | map(select(.classification == "needs-contact")) | length),
          safe_to_reopen: ($receipts | map(select(.classification == "safe-to-reopen")) | length),
          manual_review: ($receipts | map(select(.classification == "manual-review")) | length),
          blocked_by_active_agent: ($receipts | map(select(.classification == "blocked-by-active-agent")) | length)
        },
        artifact_paths: {
          recovery_receipts_json: $receipts_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_path
        }
      }
  ' >"$receipts_tmp"
mv "$receipts_tmp" "$receipts_path"

jq -c --arg schema_version "franken-engine.swarm-ops-stale-recovery-event.v1" '
  .recovery_receipts[]
  | {
      schema_version: $schema_version,
      trace_id: ("trace-stale-recovery-" + .bead_id),
      component: "swarm_ops_stale_recovery_policy",
      event: "receipt_emitted",
      outcome: .classification,
      error_code: (if .classification == "manual-review" then .reason_code else null end),
      evidence_path: ("recovery_receipts.json#" + .bead_id)
    }
' "$receipts_path" >>"$events_path"

{
  printf '# SWARM OPS STALE RECOVERY POLICY\n\n'
  printf -- "- decision: \`%s\`\n" "$(jq -r '.decision' "$receipts_path")"
  printf -- "- receipts: \`%s\`\n" "$(jq '.summary.total' "$receipts_path")"
  printf -- "- safe to reopen: \`%s\`\n" "$(jq '.summary.safe_to_reopen' "$receipts_path")"
  printf -- "- needs contact: \`%s\`\n" "$(jq '.summary.needs_contact' "$receipts_path")"
  printf -- "- manual review: \`%s\`\n" "$(jq '.summary.manual_review' "$receipts_path")"
  printf -- "- blocked by active agent: \`%s\`\n" "$(jq '.summary.blocked_by_active_agent' "$receipts_path")"
} >"$report_path"

printf 'swarm ops stale recovery receipts: %s\n' "$receipts_path"
