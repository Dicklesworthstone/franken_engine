#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_AGENT_MAIL_OUTAGE_BRIDGE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-agent-mail-outage-bridge}"
run_id="${SWARM_AGENT_MAIL_OUTAGE_BRIDGE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_MAIL_OUTAGE_BRIDGE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_AGENT_MAIL_OUTAGE_BRIDGE_SOURCE_REVISION:-}"
generated_epoch_seconds="${SWARM_AGENT_MAIL_OUTAGE_BRIDGE_GENERATED_EPOCH_SECONDS:-$(date -u +%s)}"
original_args=("$@")

mail_health_json=""
mail_bootstrap_json=""
agent_profiles_json=""
br_in_progress_json=""
git_status_json=""
file_reservations_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_agent_mail_outage_continuity_bridge.sh --br-in-progress-json FILE [OPTIONS]

Builds a read-only Agent Mail outage continuity report from preserved JSON
snapshots. The bridge never sends Agent Mail, repairs the mailbox DB, mutates br,
releases reservations, runs Cargo, invokes rch, or changes worker/queue state.

Required:
  --br-in-progress-json FILE       br list --status=in_progress --json snapshot.

Optional:
  --mail-health-json FILE          Agent Mail health_check output or captured error JSON.
  --mail-bootstrap-json FILE       macro_start_session/register failure or success JSON.
  --agent-profiles-json FILE       Agent Mail list_agents output when available.
  --git-status-json FILE           Dirty path snapshot.
  --file-reservations-json FILE    Agent Mail reservation snapshot when available.
  --source-revision REV
  --generated-epoch-seconds N
  --output-dir DIR

Artifacts:
  mail_outage_continuity_bridge.json
  soft_lock_receipts.jsonl
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   healthy or degraded continuity report emitted
  42  blocked report emitted
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --mail-health-json)
      mail_health_json="${2:-}"
      shift 2
      ;;
    --mail-bootstrap-json)
      mail_bootstrap_json="${2:-}"
      shift 2
      ;;
    --agent-profiles-json)
      agent_profiles_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
    --git-status-json)
      git_status_json="${2:-}"
      shift 2
      ;;
    --file-reservations-json)
      file_reservations_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-epoch-seconds)
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for Agent Mail outage continuity bridge\n' >&2
  exit 2
fi
if [[ -z "$br_in_progress_json" ]]; then
  printf 'bridge requires --br-in-progress-json\n' >&2
  usage
  exit 64
fi
if ! [[ "$generated_epoch_seconds" =~ ^[0-9]+$ ]]; then
  printf 'generated epoch seconds must be a non-negative integer\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

validate_required_json() {
  local path="$1"
  local label="$2"
  if [[ ! -f "$path" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

validate_optional_json() {
  local path="$1"
  local label="$2"
  if [[ -n "$path" ]]; then
    if [[ ! -f "$path" ]]; then
      printf 'missing %s JSON: %s\n' "$label" "$path" >&2
      exit 64
    fi
    if ! jq empty "$path" >/dev/null 2>&1; then
      printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
      exit 64
    fi
  fi
}

validate_required_json "$br_in_progress_json" "br in-progress"
validate_optional_json "$mail_health_json" "mail health"
validate_optional_json "$mail_bootstrap_json" "mail bootstrap"
validate_optional_json "$agent_profiles_json" "agent profiles"
validate_optional_json "$git_status_json" "git status"
validate_optional_json "$file_reservations_json" "file reservations"

mkdir -p "$run_dir"
report_json="${run_dir}/mail_outage_continuity_bridge.json"
soft_locks_jsonl="${run_dir}/soft_lock_receipts.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
report_tmp="${report_json}.tmp"

for artifact_path in "$report_json" "$soft_locks_jsonl" "$events_path" "$commands_path" "$report_md" "$report_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_agent_mail_outage_continuity_bridge.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

mail_health_arg=(--argjson mail_health null)
if [[ -n "$mail_health_json" ]]; then
  mail_health_arg=(--slurpfile mail_health "$mail_health_json")
fi
mail_bootstrap_arg=(--argjson mail_bootstrap null)
if [[ -n "$mail_bootstrap_json" ]]; then
  mail_bootstrap_arg=(--slurpfile mail_bootstrap "$mail_bootstrap_json")
fi
agent_profiles_arg=(--argjson agent_profiles null)
if [[ -n "$agent_profiles_json" ]]; then
  agent_profiles_arg=(--slurpfile agent_profiles "$agent_profiles_json")
fi
git_status_arg=(--argjson git_status null)
if [[ -n "$git_status_json" ]]; then
  git_status_arg=(--slurpfile git_status "$git_status_json")
fi
reservations_arg=(--argjson file_reservations null)
if [[ -n "$file_reservations_json" ]]; then
  reservations_arg=(--slurpfile file_reservations "$file_reservations_json")
fi

jq -n \
  "${mail_health_arg[@]}" \
  "${mail_bootstrap_arg[@]}" \
  "${agent_profiles_arg[@]}" \
  --slurpfile br_in_progress "$br_in_progress_json" \
  "${git_status_arg[@]}" \
  "${reservations_arg[@]}" \
  --arg schema_version "franken-engine.agent-mail-outage-continuity-bridge.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --arg mail_health_json "$mail_health_json" \
  --arg mail_bootstrap_json "$mail_bootstrap_json" \
  --arg agent_profiles_json "$agent_profiles_json" \
  --arg br_in_progress_json "$br_in_progress_json" \
  --arg git_status_json "$git_status_json" \
  --arg file_reservations_json "$file_reservations_json" \
  --arg report_json "$report_json" \
  --arg soft_locks_jsonl "$soft_locks_jsonl" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def doc($x):
    if ($x | type) == "array" and ($x | length) > 0 then $x[0]
    elif $x == null then null
    else $x end;
  def rows($doc; $name):
    if $doc == null then []
    elif ($doc | type) == "array" then $doc
    elif (($doc[$name] // null) | type) == "array" then $doc[$name]
    elif (($doc.issues // null) | type) == "array" then $doc.issues
    elif (($doc.agents // null) | type) == "array" then $doc.agents
    elif (($doc.reservations // null) | type) == "array" then $doc.reservations
    elif (($doc.dirty_paths // null) | type) == "array" then $doc.dirty_paths
    else [] end;
  def low($v): ($v // "" | tostring | ascii_downcase);
  def text_has($doc; $pattern): (($doc // {}) | tostring | test($pattern; "i"));
  def health_state($h):
    if $h == null then "missing"
    elif (($h.healthy // false) == true) or ((low($h.status) | IN("green","healthy","ok","pass"))) then "healthy"
    elif text_has($h; "missing required tables|no such table|schema|corrupt|red") then "corrupt"
    else "degraded" end;
  def bootstrap_state($b):
    if $b == null then "missing"
    elif (($b.ok // false) == true) or ((low($b.status) | IN("green","healthy","ok","pass","success"))) then "healthy"
    elif text_has($b; "database error|missing required tables|no such table|schema|corrupt|failed|error") then "failed"
    else "degraded" end;
  def owner($issue): ($issue.assignee // $issue.owner // "");
  def issue_id($issue): ($issue.id // $issue.issue_id // "");
  def dirty_path_rows($doc):
    rows($doc; "dirty_paths")
    | map(if type == "string" then {path:., status:"modified"} else . end);
  def reason($code; $severity; $detail; $action):
    {code:$code, severity:$severity, detail:$detail, recommended_manual_action:$action};

  (doc($mail_health)) as $health
  | (doc($mail_bootstrap)) as $bootstrap
  | (doc($agent_profiles)) as $profiles
  | (doc($br_in_progress)) as $br_doc
  | (doc($git_status)) as $git_doc
  | (doc($file_reservations)) as $reservation_doc
  | (rows($br_doc; "issues")) as $br_rows
  | (rows($profiles; "agents")) as $agent_rows
  | (rows($reservation_doc; "reservations")) as $reservation_rows
  | (dirty_path_rows($git_doc)) as $dirty_rows
  | (health_state($health)) as $health_state
  | (bootstrap_state($bootstrap)) as $bootstrap_state
  | ([
      if $health_state == "corrupt" then
        reason("FE-IW3-MAIL-DB-CORRUPT"; "degraded"; "Agent Mail health evidence indicates corrupt or missing schema state."; "Use br assignee/status as the soft lock and do not run am doctor repair from this bridge.")
      elif $health_state == "missing" then
        reason("FE-IW3-MAIL-SNAPSHOT-MISSING"; "degraded"; "No Agent Mail health snapshot was supplied."; "Record the missing mail evidence and rely on br soft locks until a read-only snapshot exists.")
      elif $health_state == "degraded" then
        reason("FE-IW3-MAIL-DEGRADED"; "degraded"; "Agent Mail health is degraded."; "Keep coordination in br and preserve the degraded health evidence.")
      else empty end,
      if $bootstrap_state == "failed" then
        reason("FE-IW3-MAIL-BOOTSTRAP-FAILED"; "degraded"; "Agent Mail bootstrap or macro_start_session failed."; "Do not retry repair loops here; continue with br soft-lock continuity.")
      elif $bootstrap_state == "degraded" then
        reason("FE-IW3-MAIL-BOOTSTRAP-DEGRADED"; "degraded"; "Agent Mail bootstrap evidence is degraded."; "Preserve the bootstrap artifact and avoid assuming contact delivery.")
      else empty end,
      if ($br_rows | length) == 0 and $health_state != "healthy" then
        reason("FE-IW3-BR-SOFT-LOCK-MISSING"; "blocked"; "Mail is unavailable and no br in-progress snapshot exists."; "Capture br list --status=in_progress --json before claiming continuity.")
      else empty end
    ]) as $reasons
  | (if any($reasons[]?; .severity == "blocked") then "blocked"
     elif ($reasons | length) > 0 then "degraded"
     else "healthy" end) as $decision
  | ($br_rows | map({
      issue_id: issue_id(.),
      title: (.title // ""),
      status: (.status // ""),
      assignee: owner(.),
      updated_at: (.updated_at // null),
      soft_lock_state: (if (owner(.) == "") then "unowned_observe_only" else "claimed_by_br_assignee" end),
      reservation_authority: "br_soft_lock",
      recommended_manual_action: (
        if (owner(.) == "") then
          "Do not infer ownership from missing Agent Mail; run br show before any claim."
        else
          "Treat the br assignee and status as the current soft lock until Agent Mail recovers."
        end
      )
    })) as $soft_locks
  | {
      schema_version:$schema_version,
      source_revision:$source_revision,
      generated_epoch_seconds:$generated_epoch_seconds,
      decision:$decision,
      mail_health_state:$health_state,
      mail_bootstrap_state:$bootstrap_state,
      degraded_reasons:($reasons | map(select(.severity == "degraded"))),
      blocked_reasons:($reasons | map(select(.severity == "blocked"))),
      source_status:{
        mail_health:(if $health == null then "missing" else "provided" end),
        mail_bootstrap:(if $bootstrap == null then "missing" else "provided" end),
        agent_profiles:(if $profiles == null then "missing" else "provided" end),
        br_in_progress:"provided",
        git_status:(if $git_doc == null then "missing" else "provided" end),
        file_reservations:(if $reservation_doc == null then "missing" else "provided" end)
      },
      summary:{
        br_in_progress_count:($br_rows | length),
        agent_profile_count:($agent_rows | length),
        file_reservation_count:($reservation_rows | length),
        dirty_path_count:($dirty_rows | length),
        soft_lock_count:($soft_locks | length)
      },
      soft_lock_receipts:$soft_locks,
      dirty_paths:$dirty_rows,
      recommended_actions:([
        "Do not run am doctor repair from this bridge.",
        "Do not send Agent Mail or assume acknowledgements were delivered.",
        "Use br show plus br list --status=in_progress --json immediately before claiming work.",
        "Record Agent Mail outage state as degraded evidence, not as a green coordination proof."
      ]),
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_first:true,
        mutates_br:false,
        claims_beads:false,
        closes_beads:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        repairs_agent_mail_db:false,
        queries_live_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_git:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      },
      artifact_paths:{
        report_json:$report_json,
        soft_locks_jsonl:$soft_locks_jsonl,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_md
      },
      source_paths:{
        mail_health_json:(if $mail_health_json == "" then null else $mail_health_json end),
        mail_bootstrap_json:(if $mail_bootstrap_json == "" then null else $mail_bootstrap_json end),
        agent_profiles_json:(if $agent_profiles_json == "" then null else $agent_profiles_json end),
        br_in_progress_json:$br_in_progress_json,
        git_status_json:(if $git_status_json == "" then null else $git_status_json end),
        file_reservations_json:(if $file_reservations_json == "" then null else $file_reservations_json end)
      }
    }
  ' >"$report_tmp"

mv "$report_tmp" "$report_json"
jq -c '.soft_lock_receipts[]?' "$report_json" >"$soft_locks_jsonl"
jq -c '
  {
    schema_version:"franken-engine.agent-mail-outage-continuity-event.v1",
    event:"bridge_report_emitted",
    decision:.decision,
    mail_health_state:.mail_health_state,
    mail_bootstrap_state:.mail_bootstrap_state,
    soft_lock_count:.summary.soft_lock_count,
    source_revision:.source_revision
  },
  (.degraded_reasons[]? | {
    schema_version:"franken-engine.agent-mail-outage-continuity-event.v1",
    event:"degraded_reason",
    code:.code,
    detail:.detail
  }),
  (.blocked_reasons[]? | {
    schema_version:"franken-engine.agent-mail-outage-continuity-event.v1",
    event:"blocked_reason",
    code:.code,
    detail:.detail
  })
' "$report_json" >"$events_path"
jq -r '
  "# Agent Mail Outage Continuity Bridge\n\n"
  + "- decision: `" + .decision + "`\n"
  + "- mail health: `" + .mail_health_state + "`\n"
  + "- mail bootstrap: `" + .mail_bootstrap_state + "`\n"
  + "- br in-progress rows: `" + (.summary.br_in_progress_count | tostring) + "`\n"
  + "- soft locks: `" + (.summary.soft_lock_count | tostring) + "`\n\n"
  + "## Reasons\n\n"
  + (if ((.degraded_reasons + .blocked_reasons) | length) == 0 then "No degraded or blocked reasons.\n"
     else ((.degraded_reasons + .blocked_reasons) | map("- `" + .code + "`: " + .detail) | join("\n")) + "\n" end)
  + "\n## Soft Locks\n\n"
  + (if (.soft_lock_receipts | length) == 0 then "No br soft-lock rows were present.\n"
     else (.soft_lock_receipts | map("- `" + .issue_id + "` `" + .status + "` `" + (.assignee // "") + "`: " + .recommended_manual_action) | join("\n")) + "\n" end)
' "$report_json" >"$report_md"

decision="$(jq -r '.decision' "$report_json")"
printf 'mail_outage_continuity_bridge_report=%s\n' "$report_json"
printf 'mail_outage_continuity_bridge_decision=%s\n' "$decision"
if [[ "$decision" == "blocked" ]]; then
  exit 42
fi
