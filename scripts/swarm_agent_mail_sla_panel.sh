#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_AGENT_MAIL_SLA_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-agent-mail-sla}"
run_id="${SWARM_AGENT_MAIL_SLA_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_MAIL_SLA_RUN_DIR:-${artifact_root}/${run_id}}"
now_ts="${SWARM_AGENT_MAIL_SLA_NOW_TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
source_revision="${SWARM_AGENT_MAIL_SLA_SOURCE_REVISION:-}"
ack_sla_seconds="900"
inactive_sla_seconds="3600"
original_args=("$@")

mail_snapshot_json=""
br_in_progress_json=""
reservation_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_agent_mail_sla_panel.sh [OPTIONS]

Builds a read-only Agent Mail response/reservation SLA panel from exported
snapshots. It never sends mail, acknowledges messages, releases reservations,
changes contact policy, queries live MCP, mutates br, runs Cargo, or invokes rch.

Options:
  --mail-snapshot-json FILE
  --br-in-progress-json FILE
  --file-reservations-json FILE
  --now-ts ISO8601_Z
  --ack-sla-seconds N
  --inactive-sla-seconds N
  --source-revision REV
  --output-dir DIR

Artifacts:
  agent_mail_sla_report.json
  agent_mail_sla_panel.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   healthy or degraded-only panel emitted
  42  blocked/fail-closed SLA diagnostics found
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --mail-snapshot-json)
      mail_snapshot_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
    --file-reservations-json)
      reservation_json="${2:-}"
      shift 2
      ;;
    --now-ts)
      now_ts="${2:-}"
      shift 2
      ;;
    --ack-sla-seconds)
      ack_sla_seconds="${2:-}"
      shift 2
      ;;
    --inactive-sla-seconds)
      inactive_sla_seconds="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for Agent Mail SLA panel\n' >&2
  exit 2
fi
for numeric_value in "$ack_sla_seconds" "$inactive_sla_seconds"; do
  if ! [[ "$numeric_value" =~ ^[0-9]+$ ]]; then
    printf 'invalid numeric SLA value: %s\n' "$numeric_value" >&2
    exit 64
  fi
done
now_epoch="$(date -u -d "$now_ts" +%s 2>/dev/null || true)"
if [[ -z "$now_epoch" ]]; then
  printf 'invalid --now-ts: %s\n' "$now_ts" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

validate_optional_json() {
  local path="$1"
  local label="$2"
  if [[ -n "$path" ]]; then
    if [[ ! -f "$path" ]]; then
      printf '%s not found: %s\n' "$label" "$path" >&2
      exit 64
    fi
    if ! jq empty "$path" >/dev/null 2>&1; then
      printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
      exit 64
    fi
  fi
}

validate_optional_json "$mail_snapshot_json" "mail snapshot"
validate_optional_json "$br_in_progress_json" "br in-progress"
validate_optional_json "$reservation_json" "reservation snapshot"

mkdir -p "$run_dir"
report_json="${run_dir}/agent_mail_sla_report.json"
panel_md="${run_dir}/agent_mail_sla_panel.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
report_tmp="${report_json}.tmp"

for artifact_path in "$report_json" "$panel_md" "$events_path" "$commands_path" "$report_md" "$report_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_agent_mail_sla_panel.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

mail_arg=()
if [[ -n "$mail_snapshot_json" ]]; then
  mail_arg=(--slurpfile mail "$mail_snapshot_json")
else
  mail_arg=(--argjson mail '[]')
fi
br_arg=()
if [[ -n "$br_in_progress_json" ]]; then
  br_arg=(--slurpfile br "$br_in_progress_json")
else
  br_arg=(--argjson br '[]')
fi
res_arg=()
if [[ -n "$reservation_json" ]]; then
  res_arg=(--slurpfile extra_reservations "$reservation_json")
else
  res_arg=(--argjson extra_reservations '[]')
fi

jq -n \
  "${mail_arg[@]}" \
  "${br_arg[@]}" \
  "${res_arg[@]}" \
  --arg schema_version "franken-engine.agent-mail-sla-report.v1" \
  --arg source_revision "$source_revision" \
  --arg now_ts "$now_ts" \
  --argjson now_epoch "$now_epoch" \
  --argjson ack_sla_seconds "$ack_sla_seconds" \
  --argjson inactive_sla_seconds "$inactive_sla_seconds" \
  --arg mail_snapshot_json "$mail_snapshot_json" \
  --arg br_in_progress_json "$br_in_progress_json" \
  --arg reservation_json "$reservation_json" \
  --arg report_json "$report_json" \
  --arg panel_md "$panel_md" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def epoch($value):
    if ($value // "") == "" then null
    else (($value | sub("\\.[0-9]+(?=Z$)"; "") | fromdateiso8601?) // null)
    end;
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def diag($severity; $code; $agent; $thread; $bead; $detail; $action; $confidence):
    {
      severity:$severity,
      code:$code,
      agent_name:(if ($agent // "") == "" then null else $agent end),
      thread_id:(if ($thread // "") == "" then null else $thread end),
      bead_id:(if ($bead // "") == "" then null else $bead end),
      detail:$detail,
      recommended_manual_action:$action,
      confidence:$confidence,
      message_age_seconds:null,
      reservation_expired_seconds:null,
      agent_inactive_seconds:null,
      reservation_path:null,
      br_assignee:null
    };
  def mail_doc:
    if ($mail | type) == "array" and ($mail | length) > 0 then $mail[0] else null end;
  def br_doc:
    if ($br | type) == "array" and ($br | length) > 0 then $br[0] else {} end;
  def extra_res_doc:
    if ($extra_reservations | type) == "array" and ($extra_reservations | length) > 0 then $extra_reservations[0] else {} end;
  def agent_rows:
    arr(mail_doc.agents // []);
  def message_rows:
    arr(mail_doc.messages // mail_doc.inbox // []);
  def reservation_rows:
    arr(mail_doc.reservations // []) + arr(extra_res_doc.reservations // extra_res_doc.file_reservations // []);
  def br_rows:
    arr(br_doc.issues // br_doc.in_progress // []);
  def agent_map:
    reduce agent_rows[] as $a ({}; .[$a.name // $a.agent_name // ""] = $a);
  def in_progress_assignee($bead):
    ([br_rows[] | select((.id // "") == $bead) | .assignee][0] // null);
  def agent_age_seconds($agent):
    epoch(agent_map[$agent].last_active_ts // agent_map[$agent].last_seen_ts // "") as $seen
    | if $seen == null then null else ($now_epoch - $seen) end;
  def message_age($m):
    epoch($m.created_ts // $m.created_at // "") as $created
    | if $created == null then null else ($now_epoch - $created) end;
  def reservation_expiry_age($r):
    epoch($r.expires_ts // $r.expires_at // "") as $expires
    | if $expires == null then null else ($now_epoch - $expires) end;

  (
    (if mail_doc == null then [
      diag("warning"; "missing_mail_snapshot"; null; null; null; "Agent Mail snapshot is missing"; "Export Agent Mail snapshot before trusting response SLA panel."; "high")
    ] else [] end)
    + [message_rows[] as $m
    | (message_age($m)) as $age
    | select(($m.ack_required // false) == true and (($m.acknowledged // $m.acknowledged_at // false) == false) and ($age != null and $age > $ack_sla_seconds))
    | diag("error"; "stale_ack_required_thread"; ($m.to_agent // $m.recipient // ""); ($m.thread_id // ""); ($m.bead_id // ""); "ack-required message age " + ($age | tostring) + "s exceeds SLA"; "Manually ping recipient or reassign the bead after coordination."; "high")
      + {message_age_seconds:$age}]
    + [reservation_rows[] as $r
    | (reservation_expiry_age($r)) as $expiry_age
    | select($expiry_age != null and $expiry_age > 0)
    | diag("error"; "expired_reservation"; ($r.agent // $r.agent_name // ""); null; ($r.bead_id // ""); "reservation expired " + ($expiry_age | tostring) + "s ago for " + ($r.path_pattern // $r.path // "unknown path"); "Ask holder to release or refresh reservation; do not bypass blindly."; "high")
      + {reservation_expired_seconds:$expiry_age, reservation_path:($r.path_pattern // $r.path // null)}]
    + [reservation_rows[] as $r
    | ($r.bead_id // "") as $bead
    | ($r.agent // $r.agent_name // "") as $reservation_agent
    | (in_progress_assignee($bead)) as $assignee
    | select($bead != "" and $reservation_agent != "" and ($assignee // "") != "" and $reservation_agent != $assignee)
    | diag("error"; "contradictory_ownership_reservation"; $reservation_agent; null; $bead; "reservation holder " + $reservation_agent + " differs from br assignee " + $assignee; "Resolve bead ownership and reservation authority before acting on this snapshot."; "high")
      + {reservation_path:($r.path_pattern // $r.path // null), br_assignee:$assignee}]
    + [reservation_rows[] as $r
    | ($r.agent // $r.agent_name // "") as $agent
    | (agent_age_seconds($agent)) as $age
    | select($age != null and $age > $inactive_sla_seconds and (($r.released_ts // null) == null))
    | diag("error"; "inactive_assignee_active_reservation"; $agent; null; ($r.bead_id // ""); "agent inactive for " + ($age | tostring) + "s while reservation is active"; "Coordinate before force-release; cite reservation path and bead id."; "medium")
      + {agent_inactive_seconds:$age, reservation_path:($r.path_pattern // $r.path // null)}]
    + [message_rows[] as $m
    | ($m.to_agent // $m.recipient // "") as $agent
    | (agent_map[$agent].contact_policy // $m.contact_policy // "") as $policy
    | select($policy == "block_all" or ($policy == "contacts_only" and (($m.contact_allowed // false) == false)))
    | diag("warning"; "contact_policy_blocked_recipient"; $agent; ($m.thread_id // ""); ($m.bead_id // ""); "recipient contact policy blocks or may block the thread"; "Request contact approval or route through an existing contact."; "medium")]
  ) as $diagnostics
  | {
      schema_version:$schema_version,
      source_revision:$source_revision,
      evaluated_at:$now_ts,
      mail_snapshot_json:(if $mail_snapshot_json == "" then null else $mail_snapshot_json end),
      br_in_progress_json:(if $br_in_progress_json == "" then null else $br_in_progress_json end),
      reservation_json:(if $reservation_json == "" then null else $reservation_json end),
      decision:(if any($diagnostics[]; .severity == "error") then "blocked" elif any($diagnostics[]; .severity == "warning") then "degraded" else "pass" end),
      agents: agent_rows,
      message_count:(message_rows | length),
      reservation_count:(reservation_rows | length),
      diagnostics:$diagnostics,
      diagnostic_counts:{
        total:($diagnostics | length),
        errors:($diagnostics | map(select(.severity == "error")) | length),
        warnings:($diagnostics | map(select(.severity == "warning")) | length)
      },
      artifact_paths:{
        agent_mail_sla_report_json:$report_json,
        agent_mail_sla_panel_md:$panel_md,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_md
      },
      non_mutation_attestation:{
        fixture_fed_only:true,
        sends_agent_mail:false,
        acknowledges_messages:false,
        releases_reservations:false,
        changes_contact_policy:false,
        queries_live_mcp:false,
        mutates_br:false,
        runs_cargo:false,
        runs_rch:false
      }
    }
' >"$report_tmp"
mv "$report_tmp" "$report_json"

jq -r '
  "# Agent Mail SLA Panel",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Agents: `" + ((.agents | length) | tostring) + "`"),
  ("- Messages: `" + (.message_count | tostring) + "`"),
  ("- Reservations: `" + (.reservation_count | tostring) + "`"),
  "",
  "| Severity | Code | Agent | Thread | Bead | Message age | Reservation expired | Action | Confidence |",
  "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
  (if (.diagnostics | length) == 0 then
    "| info | healthy | - | - | - | - | - | No manual action required. | high |"
  else
    (.diagnostics[]
      | "| " + .severity + " | `" + .code + "` | `" + (.agent_name // "-") + "` | `" + (.thread_id // "-") + "` | `" + (.bead_id // "-") + "` | `" + ((.message_age_seconds // "-") | tostring) + "` | `" + ((.reservation_expired_seconds // "-") | tostring) + "` | " + .recommended_manual_action + " | `" + .confidence + "` |")
  end)
' "$report_json" >"$panel_md"

jq -r '
  "# Agent Mail SLA Report",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Errors: `" + (.diagnostic_counts.errors | tostring) + "`"),
  ("- Warnings: `" + (.diagnostic_counts.warnings | tostring) + "`"),
  "",
  "## Diagnostics",
  "",
  (if (.diagnostics | length) == 0 then
    "none"
  else
    (.diagnostics[]
      | "- `" + .severity + "` `" + .code + "` `" + (.agent_name // "unknown") + "`: " + .detail)
  end)
' "$report_json" >"$report_md"

jq -c '
  if (.diagnostics | length) == 0 then
    [{
      schema_version:"franken-engine.agent-mail-sla.event.v1",
      component:"swarm_agent_mail_sla_panel",
      event:"sla_panel_passed",
      severity:"info",
      code:null,
      agent_name:null,
      thread_id:null,
      bead_id:null
    }]
  else
    [.diagnostics[]
      | {
          schema_version:"franken-engine.agent-mail-sla.event.v1",
          component:"swarm_agent_mail_sla_panel",
          event:"sla_diagnostic",
          severity,
          code,
          agent_name,
          thread_id,
          bead_id
        }]
  end
  | .[]
' "$report_json" >"$events_path"

printf 'agent_mail_sla_report=%s\n' "$report_json"
printf 'agent_mail_sla_panel=%s\n' "$panel_md"
printf 'agent_mail_sla_events=%s\n' "$events_path"

if jq -e '.decision == "blocked"' "$report_json" >/dev/null; then
  exit 42
fi
exit 0
