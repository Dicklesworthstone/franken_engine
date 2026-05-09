#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_STALLED_OWNERSHIP_REOPEN_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-stalled-ownership-reopen}"
run_id="${SWARM_STALLED_OWNERSHIP_REOPEN_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_STALLED_OWNERSHIP_REOPEN_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_STALLED_OWNERSHIP_REOPEN_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_stalled_ownership_reopen_recommender.sh --input-json FILE [OPTIONS]

Builds advisory stalled-ownership reopen receipts from saved br, Agent Mail
SLA, reservation, git-activity, dirty-overlap, and live snapshot evidence. It
never runs br reopen, reassigns beads, releases reservations, sends Agent Mail,
edits files, runs Cargo, or invokes rch.

Required:
  --input-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  stalled_ownership_reopen_recommendations.json
  reopen_receipts.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   recommendations emitted with pass or degraded decision
  42  missing/contradictory required evidence forced fail_closed
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
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

if [[ -z "$input_json" ]]; then
  printf 'missing required --input-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "$input_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for stalled ownership reopen recommender\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for stalled ownership reopen recommender\n' >&2
  exit 2
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
recommendations_path="${run_dir}/stalled_ownership_reopen_recommendations.json"
receipts_path="${run_dir}/reopen_receipts.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"
recommendations_tmp="${recommendations_path}.tmp"

for artifact_path in \
  "$recommendations_path" \
  "$receipts_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$normalized_input" \
  "$recommendations_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"

printf './scripts/swarm_stalled_ownership_reopen_recommender.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg recommendations_path "$recommendations_path" \
  --arg receipts_path "$receipts_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def src: $input[0];
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def epoch($value):
    if ($value // "") == "" then null
    else (($value | sub("\\.[0-9]+(?=Z$)"; "") | fromdateiso8601?) // null)
    end;
  def reason($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def br_doc: (src.br_in_progress // src.br_snapshot // {});
  def br_present:
    if (br_doc | has("present")) then br_doc.present == true else true end;
  def issues: arr(br_doc.issues // br_doc.in_progress // []);
  def mail_doc: (src.agent_mail_sla_report // {});
  def mail_decision: (mail_doc.decision // "missing");
  def mail_diagnostics: arr(mail_doc.diagnostics // []);
  def agents: arr(mail_doc.agents // src.agents // []);
  def git_rows: arr(src.git_activity // []);
  def dirty_rows: arr(src.dirty_overlap // []);
  def reservation_rows:
    if (src.file_reservations | type) == "array" then src.file_reservations
    else arr(src.file_reservations.reservations // src.file_reservations.file_reservations // [])
    end;
  def live_doc: (src.live_snapshot_bundle // {});
  def agent_map:
    reduce agents[] as $a ({}; .[$a.name // $a.agent_name // ""] = $a);
  def git_epochs($agent):
    [git_rows[] | select((.agent // .agent_name // "") == $agent) | epoch(.last_activity_ts // .last_commit_ts // "")];
  def latest_agent_epoch($agent):
    ([epoch(agent_map[$agent].last_active_ts // agent_map[$agent].last_seen_ts // "")] + git_epochs($agent)
      | map(select(. != null)) | max // null);
  def issue_epoch($issue): epoch($issue.updated_at // $issue.created_at // "");
  def latest_activity_epoch($issue):
    ([issue_epoch($issue), latest_agent_epoch($issue.assignee // "")] | map(select(. != null)) | max // null);
  def expired_reservation_beads:
    ([mail_diagnostics[] | select((.code // "") == "expired_reservation") | .bead_id]
      + [reservation_rows[] as $r
         | epoch($r.expires_ts // $r.expires_at // "") as $expires
         | select($expires != null and $expires < (src.now_epoch // 0))
         | $r.bead_id])
    | map(select(. != null and . != ""));
  def dirty_for($bead):
    [dirty_rows[] | select((.bead_id // "") == $bead or (arr(.bead_ids // []) | index($bead) != null))];
  def live_contradictions: arr(live_doc.contradictory_ownership // live_doc.contradictory_ownership_evidence // []);
  def has_contradictory_ownership:
    (any(mail_diagnostics[]?; (.code // "") == "contradictory_ownership_reservation")
      or ((live_contradictions | length) > 0));
  def manual_reopen_command($id):
    "br reopen " + $id + " --reason \"stalled ownership evidence: assignee inactive beyond threshold\"";
  def recommendation($issue):
    ($issue.id // "") as $id
    | ($issue.assignee // "") as $assignee
    | (src.inactivity_threshold_seconds // 3600) as $threshold
    | (latest_activity_epoch($issue)) as $latest
    | (if $latest == null then null else ((src.now_epoch // 0) - $latest) end) as $age
    | (dirty_for($id)) as $dirty
    | (expired_reservation_beads | index($id) != null) as $expired
    | (if mail_decision == "missing" then
        {
          recommendation:"manual_review",
          reason_code:"mail_unavailable",
          reason_not_to_act:"Agent Mail SLA evidence is missing; do not reopen from br state alone.",
          manual_br_command:null
        }
      elif ($dirty | length) > 0 then
        {
          recommendation:"manual_review",
          reason_code:"dirty_overlap",
          reason_not_to_act:"Dirty file overlap exists for this bead or assignee.",
          manual_br_command:null
        }
      elif $expired then
        {
          recommendation:"manual_review",
          reason_code:"expired_reservation",
          reason_not_to_act:"Expired reservation evidence requires manual release/ownership review first.",
          manual_br_command:null
        }
      elif $age == null then
        {
          recommendation:"manual_review",
          reason_code:"unknown_activity",
          reason_not_to_act:"No reliable updated_at, Agent Mail, or git activity timestamp was available.",
          manual_br_command:null
        }
      elif $age > $threshold then
        {
          recommendation:"recommend_reopen",
          reason_code:"stale_owner_safe_to_reopen",
          reason_not_to_act:null,
          manual_br_command:manual_reopen_command($id)
        }
      else
        {
          recommendation:"keep_assigned",
          reason_code:"active_owner",
          reason_not_to_act:"Owner has recent br, Agent Mail, or git activity within threshold.",
          manual_br_command:null
        }
      end) as $verdict
    | {
        bead_id:$id,
        title:($issue.title // null),
        assignee:(if $assignee == "" then null else $assignee end),
        latest_activity_ts:(if $latest == null then null else ($latest | strftime("%Y-%m-%dT%H:%M:%SZ")) end),
        inactivity_seconds:$age,
        inactivity_threshold_seconds:$threshold,
        evidence_hash:$input_hash,
        evidence_sources:{
          br_snapshot:(br_doc.source_path // src.br_in_progress_path // null),
          agent_mail_sla_report:(mail_doc.artifact_paths.agent_mail_sla_report_json // src.agent_mail_sla_report_path // null),
          file_reservations:(src.file_reservations_path // null),
          git_activity:(src.git_activity_path // null),
          live_snapshot_bundle:(live_doc.path // src.live_snapshot_bundle_path // null)
        }
      } + $verdict;

  ([]
    + (if br_present then [] else [
        reason("missing_br_snapshot"; "br_in_progress";
          "required br in-progress snapshot is missing";
          "Export br in-progress JSON before recommending reopen commands.")
      ] end)
    + (if has_contradictory_ownership then [
        reason("contradictory_ownership_evidence"; "agent_mail_sla_report";
          "Agent Mail or live snapshot evidence reports contradictory ownership";
          "Resolve ownership and reservations before recommending br reopen.")
      ] else [] end)
  ) as $fail_closed_reasons
  | ([]
    + (if mail_decision == "missing" then [
        reason("mail_unavailable"; "agent_mail_sla_report";
          "Agent Mail SLA report is missing";
          "Generate the Agent Mail SLA panel before trusting stale-owner recommendations.")
      ] else [] end)
    + (if ((if (live_doc | has("present")) then live_doc.present == true else true end) | not) then [
        reason("missing_live_snapshot_bundle"; "live_snapshot_bundle";
          "live read-only snapshot bundle is absent";
          "Provide a fresh live snapshot bundle or downgrade to manual review.")
      ] else [] end)
    + (if (live_doc.freshness // "fresh") != "fresh" then [
        reason("stale_live_snapshot_bundle"; "live_snapshot_bundle";
          "live read-only snapshot bundle is stale";
          "Refresh snapshot evidence before acting.")
      ] else [] end)
    + (if mail_decision == "degraded" then [
        reason("degraded_agent_mail_sla"; "agent_mail_sla_report";
          "Agent Mail SLA report is degraded";
          "Treat reopen recommendations as manual-review guidance.")
      ] else [] end)
  ) as $degraded_reasons
  | (if ($fail_closed_reasons | length) > 0 then []
     else [issues[] | recommendation(.)] end) as $recommendations
  | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
     elif (($degraded_reasons | length) > 0 or any($recommendations[]?; .recommendation == "manual_review")) then "degraded"
     else "pass" end) as $decision
  | {
      schema_version:"franken-engine.stalled-ownership-reopen-recommendations.v1",
      source_revision:$source_revision,
      input_json:$input_json,
      normalized_input:$normalized_input,
      evidence_hash:$input_hash,
      evaluated_at:(src.now_ts // ((src.now_epoch // 0) | strftime("%Y-%m-%dT%H:%M:%SZ"))),
      decision:$decision,
      fail_closed_reasons:$fail_closed_reasons,
      degraded_reasons:$degraded_reasons,
      recommendations:$recommendations,
      artifact_paths:{
        stalled_ownership_reopen_recommendations_json:$recommendations_path,
        reopen_receipts_md:$receipts_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path
      },
      non_mutation_attestation:{
        advisory_only:true,
        runs_br_reopen:false,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        edits_files:false,
        runs_cargo:false,
        runs_rch:false
      }
    }
' >"$recommendations_tmp"
mv "$recommendations_tmp" "$recommendations_path"

jq -r '
  "# Stalled Ownership Reopen Receipts",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Evidence hash: `" + .evidence_hash + "`"),
  "",
  "| Bead | Assignee | Recommendation | Inactive seconds | Manual command | Reason |",
  "| --- | --- | --- | --- | --- | --- |",
  (if (.recommendations | length) == 0 then
    "| - | - | - | - | - | No recommendation rows emitted. |"
  else
    (.recommendations[]
      | "| `" + .bead_id + "` | `" + (.assignee // "-") + "` | `" + .recommendation + "` | `" + ((.inactivity_seconds // "-") | tostring) + "` | `" + (.manual_br_command // "-") + "` | " + (.reason_not_to_act // .reason_code) + " |")
  end)
' "$recommendations_path" >"$receipts_path"

jq -r '
  "# Stalled Ownership Reopen Report",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Fail-closed reasons: `" + ((.fail_closed_reasons | length) | tostring) + "`"),
  ("- Degraded reasons: `" + ((.degraded_reasons | length) | tostring) + "`"),
  ("- Recommendations: `" + ((.recommendations | length) | tostring) + "`"),
  "",
  "## Recommendations",
  "",
  (if (.recommendations | length) == 0 then
    "none"
  else
    (.recommendations[]
      | "- `" + .bead_id + "` `" + .recommendation + "` `" + .reason_code + "`")
  end)
' "$recommendations_path" >"$report_path"

jq -c '
  if (.recommendations | length) == 0 then
    [.fail_closed_reasons[]?
      | {
          schema_version:"franken-engine.stalled-ownership-reopen.event.v1",
          component:"swarm_stalled_ownership_reopen_recommender",
          event:"reopen_recommender_blocked",
          severity:"error",
          code,
          bead_id:null,
          recommendation:null
        }]
  else
    [.recommendations[]
      | {
          schema_version:"franken-engine.stalled-ownership-reopen.event.v1",
          component:"swarm_stalled_ownership_reopen_recommender",
          event:"reopen_recommendation",
          severity:(if .recommendation == "recommend_reopen" then "info" elif .recommendation == "manual_review" then "warning" else "info" end),
          code:.reason_code,
          bead_id,
          recommendation
        }]
  end
  | .[]
' "$recommendations_path" >"$events_path"

printf 'stalled_ownership_reopen_recommendations=%s\n' "$recommendations_path"
printf 'reopen_receipts=%s\n' "$receipts_path"
printf 'stalled_ownership_reopen_events=%s\n' "$events_path"

if jq -e '.decision == "fail_closed"' "$recommendations_path" >/dev/null; then
  exit 42
fi
exit 0
