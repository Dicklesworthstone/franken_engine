#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CONTINUITY_DOCTOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-continuity-doctor}"
run_id="${SWARM_CONTINUITY_DOCTOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CONTINUITY_DOCTOR_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_CONTINUITY_DOCTOR_SOURCE_REVISION:-}"
generated_epoch_seconds="${SWARM_CONTINUITY_DOCTOR_GENERATED_EPOCH_SECONDS:-$(date -u +%s)}"
original_args=("$@")

br_ready_json=""
br_in_progress_json=""
mail_health_json=""
mail_bootstrap_json=""
agent_profiles_json=""
git_status_json=""
file_reservations_json=""
rch_status_json=""
rch_queue_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_continuity_doctor.sh --br-ready-json FILE --br-in-progress-json FILE [OPTIONS]

Builds a fixture-fed, advisory-only continuity doctor report from preserved br,
Agent Mail, git, reservation, and rch snapshots. The doctor never repairs Agent
Mail, mutates br, releases reservations, runs Cargo, invokes rch, or changes
worker state.

Required:
  --br-ready-json FILE
  --br-in-progress-json FILE

Optional:
  --mail-health-json FILE
  --mail-bootstrap-json FILE
  --agent-profiles-json FILE
  --git-status-json FILE
  --file-reservations-json FILE
  --rch-status-json FILE
  --rch-queue-json FILE
  --source-revision REV
  --generated-epoch-seconds N
  --output-dir DIR

Artifacts:
  run_manifest.json
  swarm_continuity_doctor_report.json
  events.jsonl
  commands.txt
  report.md
  mail_outage_bridge/

Exit codes:
  0   healthy or degraded continuity report emitted
  42  blocked continuity report emitted
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
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
    --git-status-json)
      git_status_json="${2:-}"
      shift 2
      ;;
    --file-reservations-json)
      file_reservations_json="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm continuity doctor\n' >&2
  exit 2
fi
if [[ -z "$br_ready_json" || -z "$br_in_progress_json" ]]; then
  printf 'swarm continuity doctor requires --br-ready-json and --br-in-progress-json\n' >&2
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

validate_json() {
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
    validate_json "$path" "$label"
  fi
}

validate_json "$br_ready_json" "br ready"
validate_json "$br_in_progress_json" "br in-progress"
validate_optional_json "$mail_health_json" "mail health"
validate_optional_json "$mail_bootstrap_json" "mail bootstrap"
validate_optional_json "$agent_profiles_json" "agent profiles"
validate_optional_json "$git_status_json" "git status"
validate_optional_json "$file_reservations_json" "file reservations"
validate_optional_json "$rch_status_json" "rch status"
validate_optional_json "$rch_queue_json" "rch queue"

mkdir -p "$run_dir"

run_manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_json="${run_dir}/swarm_continuity_doctor_report.json"
report_md="${run_dir}/report.md"
bridge_dir="${run_dir}/mail_outage_bridge"

for artifact_path in "$run_manifest_path" "$events_path" "$commands_path" "$report_json" "$report_md"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_continuity_doctor.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event_name="$1"
  local detail="$2"
  local outcome="$3"
  local evidence_path="$4"
  jq -nc \
    --arg schema_version "franken-engine.swarm-continuity-doctor-event.v1" \
    --arg event_name "$event_name" \
    --arg detail "$detail" \
    --arg outcome "$outcome" \
    --arg evidence_path "$evidence_path" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      detail: $detail,
      outcome: $outcome,
      evidence_path: (if $evidence_path == "" then null else $evidence_path end),
      source_revision: $source_revision
    }' >>"$events_path"
}

write_event "doctor_started" "validated preserved snapshot inputs" "started" ""

bridge_cmd=(
  "${root_dir}/scripts/swarm_agent_mail_outage_continuity_bridge.sh"
  --br-in-progress-json "$br_in_progress_json"
  --source-revision "$source_revision"
  --generated-epoch-seconds "$generated_epoch_seconds"
  --output-dir "$bridge_dir"
)
if [[ -n "$mail_health_json" ]]; then
  bridge_cmd+=(--mail-health-json "$mail_health_json")
fi
if [[ -n "$mail_bootstrap_json" ]]; then
  bridge_cmd+=(--mail-bootstrap-json "$mail_bootstrap_json")
fi
if [[ -n "$agent_profiles_json" ]]; then
  bridge_cmd+=(--agent-profiles-json "$agent_profiles_json")
fi
if [[ -n "$git_status_json" ]]; then
  bridge_cmd+=(--git-status-json "$git_status_json")
fi
if [[ -n "$file_reservations_json" ]]; then
  bridge_cmd+=(--file-reservations-json "$file_reservations_json")
fi

printf './scripts/swarm_agent_mail_outage_continuity_bridge.sh' >>"$commands_path"
for arg in "${bridge_cmd[@]:1}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

set +e
"${bridge_cmd[@]}" >"${run_dir}/mail_outage_bridge.stdout" 2>"${run_dir}/mail_outage_bridge.stderr"
bridge_exit_code=$?
set -e

if [[ "$bridge_exit_code" -eq 0 || "$bridge_exit_code" -eq 42 ]]; then
  write_event "mail_bridge_completed" "mail outage bridge emitted continuity artifacts" "captured" "mail_outage_bridge/mail_outage_continuity_bridge.json"
else
  write_event "mail_bridge_failed" "mail outage bridge failed before emitting trusted artifacts" "blocked" "mail_outage_bridge.stderr"
fi

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
rch_status_arg=(--argjson rch_status null)
if [[ -n "$rch_status_json" ]]; then
  rch_status_arg=(--slurpfile rch_status "$rch_status_json")
fi
rch_queue_arg=(--argjson rch_queue null)
if [[ -n "$rch_queue_json" ]]; then
  rch_queue_arg=(--slurpfile rch_queue "$rch_queue_json")
fi
bridge_report_arg=(--argjson bridge_report null)
if [[ -f "${bridge_dir}/mail_outage_continuity_bridge.json" ]]; then
  bridge_report_arg=(--slurpfile bridge_report "${bridge_dir}/mail_outage_continuity_bridge.json")
fi

jq -n \
  --slurpfile br_ready "$br_ready_json" \
  --slurpfile br_in_progress "$br_in_progress_json" \
  "${mail_health_arg[@]}" \
  "${mail_bootstrap_arg[@]}" \
  "${agent_profiles_arg[@]}" \
  "${git_status_arg[@]}" \
  "${reservations_arg[@]}" \
  "${rch_status_arg[@]}" \
  "${rch_queue_arg[@]}" \
  "${bridge_report_arg[@]}" \
  --arg schema_version "franken-engine.swarm-continuity-doctor-report.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --argjson bridge_exit_code "$bridge_exit_code" \
  --arg br_ready_json "$br_ready_json" \
  --arg br_in_progress_json "$br_in_progress_json" \
  --arg mail_health_json "$mail_health_json" \
  --arg mail_bootstrap_json "$mail_bootstrap_json" \
  --arg agent_profiles_json "$agent_profiles_json" \
  --arg git_status_json "$git_status_json" \
  --arg file_reservations_json "$file_reservations_json" \
  --arg rch_status_json "$rch_status_json" \
  --arg rch_queue_json "$rch_queue_json" \
  --arg bridge_report_json "${bridge_dir}/mail_outage_continuity_bridge.json" \
  '
  def doc($x):
    if $x == null then null
    elif ($x | type) == "array" then ($x[0] // null)
    else $x
    end;
  def all_strings($x): [$x | .. | strings];
  def has_text($x; $re): any(all_strings($x)[]?; test($re; "i"));
  def issues($x):
    if ($x | type) == "array" then $x
    elif ($x | type) == "object" and (($x.issues // null) | type) == "array" then $x.issues
    else []
    end;
  def mail_state($mh):
    if $mh == null then "missing"
    elif (($mh.healthy // false) == true)
      or ((($mh.status // "") | ascii_downcase) == "green")
      or ((($mh.health_level // "") | ascii_downcase) == "green")
    then "healthy"
    elif ((($mh.recovery.mode // "") | ascii_downcase) == "corrupt")
      or ((($mh.health_level // "") | ascii_downcase) == "red")
      or ((($mh.status // "") | ascii_downcase) == "red")
      or ((($mh.status // "") | ascii_downcase) == "error")
      or has_text($mh; "schema missing|required health_check tables|corrupt")
    then "corrupt"
    elif has_text($mh; "degraded|read_only|read-only")
    then "degraded_read_only"
    else "degraded"
    end;
  def bootstrap_state($mb):
    if $mb == null then "missing"
    elif ((($mb.status // "") | ascii_downcase) == "success") then "healthy"
    elif has_text($mb; "database error|try again|failed|error") then "failed"
    else "degraded"
    end;
  def rch_state($rs; $rq):
    if $rs == null and $rq == null then "missing"
    elif has_text([$rs, $rq]; "local fallback|local_fallback|\\[RCH\\] local|running locally") then "local_fallback"
    elif has_text([$rs, $rq]; "degraded|unhealthy|offline|drained|timeout|stalled|failed") then "degraded"
    else "healthy"
    end;
  def dirty_paths($gs):
    if $gs == null then []
    elif (($gs.dirty_paths // null) | type) == "array" then $gs.dirty_paths
    elif (($gs.paths // null) | type) == "array" then $gs.paths
    elif (($gs.files // null) | type) == "array" then $gs.files
    else []
    end;
  def reservation_state($fr):
    if $fr == null then "missing"
    elif (($fr.conflicts // []) | length) > 0 then "conflict"
    elif has_text($fr; "conflict|expired|stale") then "uncertain"
    else "captured"
    end;
  def finding($severity; $code; $component; $detail; $evidence):
    {
      severity: $severity,
      code: $code,
      component: $component,
      detail: $detail,
      evidence_path: (if $evidence == "" then null else $evidence end)
    };
  (doc($br_ready)) as $ready_doc
  | (doc($br_in_progress)) as $progress_doc
  | (doc($mail_health)) as $mh
  | (doc($mail_bootstrap)) as $mb
  | (doc($agent_profiles)) as $ap
  | (doc($git_status)) as $gs
  | (doc($file_reservations)) as $fr
  | (doc($rch_status)) as $rs
  | (doc($rch_queue)) as $rq
  | (doc($bridge_report)) as $bridge
  | (issues($ready_doc)) as $ready_issues
  | (issues($progress_doc)) as $in_progress_issues
  | (mail_state($mh)) as $mail_state
  | (bootstrap_state($mb)) as $bootstrap_state
  | (rch_state($rs; $rq)) as $rch_state
  | (dirty_paths($gs)) as $dirty_paths
  | (reservation_state($fr)) as $reservation_state
  | ([ $in_progress_issues[]? | select((.assignee // "") == "") ]) as $unowned_in_progress
  | (
      []
      + (if $bridge_exit_code != 0 and $bridge_exit_code != 42 then
          [finding("blocked"; "FE-SWARM-CONTINUITY-BRIDGE-FAILED"; "agent_mail_bridge"; "mail outage bridge failed before emitting a trusted report"; "mail_outage_bridge.stderr")]
        else [] end)
      + (if $mail_state == "corrupt" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-MAIL-CORRUPT"; "agent_mail"; "Agent Mail health is red or corrupt; partial reads must not be treated as healthy"; $mail_health_json)]
        elif $mail_state == "missing" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-MAIL-MISSING"; "agent_mail"; "Agent Mail health snapshot is missing"; "")]
        elif $mail_state == "degraded_read_only" or $mail_state == "degraded" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-MAIL-DEGRADED"; "agent_mail"; "Agent Mail is degraded or read-only"; $mail_health_json)]
        else [] end)
      + (if $bootstrap_state == "failed" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-MAIL-BOOTSTRAP-FAILED"; "agent_mail"; "Agent Mail bootstrap or registration failed"; $mail_bootstrap_json)]
        else [] end)
      + (if $ap != null and $mail_state != "healthy" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-PARTIAL-MAIL-READ"; "agent_mail"; "Agent profile data is present while mail health is not healthy"; $agent_profiles_json)]
        else [] end)
      + (if $rch_state == "local_fallback" then
          [finding("blocked"; "FE-SWARM-CONTINUITY-RCH-LOCAL-FALLBACK"; "rch"; "RCH snapshot indicates local fallback contamination"; ($rch_status_json // $rch_queue_json))]
        elif $rch_state == "degraded" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-RCH-DEGRADED"; "rch"; "RCH snapshot indicates degraded, stalled, timed-out, or unhealthy workers"; ($rch_status_json // $rch_queue_json))]
        elif $rch_state == "missing" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-RCH-MISSING"; "rch"; "RCH status and queue snapshots are missing"; "")]
        else [] end)
      + (if ($dirty_paths | length) > 0 then
          [finding("degraded"; "FE-SWARM-CONTINUITY-DIRTY-PATHS"; "git"; ("dirty paths visible: " + (($dirty_paths | length) | tostring)); $git_status_json)]
        else [] end)
      + (if $reservation_state == "missing" then
          [finding("degraded"; "FE-SWARM-CONTINUITY-RESERVATIONS-MISSING"; "reservations"; "file reservation snapshot is missing"; "")]
        elif $reservation_state == "conflict" or $reservation_state == "uncertain" then
          [finding("blocked"; "FE-SWARM-CONTINUITY-RESERVATIONS-CONFLICT"; "reservations"; "file reservation snapshot indicates conflict or uncertainty"; $file_reservations_json)]
        else [] end)
      + (if ($unowned_in_progress | length) > 0 then
          [finding("degraded"; "FE-SWARM-CONTINUITY-UNOWNED-IN-PROGRESS"; "br"; "in-progress beads without assignees require manual review"; $br_in_progress_json)]
        else [] end)
    ) as $findings
  | (if any($findings[]?; .severity == "blocked") then "blocked"
     elif ($findings | length) > 0 then "degraded"
     else "healthy"
     end) as $decision
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: $decision,
      states: {
        mail_health: $mail_state,
        mail_bootstrap: $bootstrap_state,
        rch: $rch_state,
        reservations: $reservation_state,
        bridge_decision: ($bridge.decision // "missing")
      },
      summary: {
        ready_count: ($ready_issues | length),
        in_progress_count: ($in_progress_issues | length),
        unowned_in_progress_count: ($unowned_in_progress | length),
        dirty_path_count: ($dirty_paths | length),
        finding_count: ($findings | length),
        bridge_exit_code: $bridge_exit_code
      },
      findings: $findings,
      recommended_actions: (
        if $decision == "healthy" then
          ["Continue normal bead/rch workflow; retain this report as continuity evidence."]
        elif any($findings[]?; .code == "FE-SWARM-CONTINUITY-MAIL-CORRUPT") then
          ["Use br assignee state as the soft lock and capture fresh mail health before relying on Agent Mail writes."]
        elif any($findings[]?; .code == "FE-SWARM-CONTINUITY-RCH-LOCAL-FALLBACK") then
          ["Reject local fallback proof and refresh remote worker capacity before admitting heavy Cargo work."]
        else
          ["Proceed with advisory-only coordination and refresh degraded snapshots before promoting automation."]
        end
      ),
      mutation_policy: {
        advisory_only: true,
        proof_only: true,
        fixture_fed_first: true,
        repairs_agent_mail_db: false,
        sends_agent_mail: false,
        mutates_br: false,
        claims_beads: false,
        closes_beads: false,
        reassigns_beads: false,
        releases_reservations: false,
        runs_cargo: false,
        runs_rch: false,
        mutates_git: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false
      },
      artifact_paths: {
        run_manifest_json: "run_manifest.json",
        continuity_report_json: "swarm_continuity_doctor_report.json",
        events_jsonl: "events.jsonl",
        commands_txt: "commands.txt",
        report_md: "report.md",
        mail_outage_bridge_dir: "mail_outage_bridge",
        mail_outage_bridge_report_json: "mail_outage_bridge/mail_outage_continuity_bridge.json"
      },
      source_paths: {
        br_ready_json: $br_ready_json,
        br_in_progress_json: $br_in_progress_json,
        mail_health_json: (if $mail_health_json == "" then null else $mail_health_json end),
        mail_bootstrap_json: (if $mail_bootstrap_json == "" then null else $mail_bootstrap_json end),
        agent_profiles_json: (if $agent_profiles_json == "" then null else $agent_profiles_json end),
        git_status_json: (if $git_status_json == "" then null else $git_status_json end),
        file_reservations_json: (if $file_reservations_json == "" then null else $file_reservations_json end),
        rch_status_json: (if $rch_status_json == "" then null else $rch_status_json end),
        rch_queue_json: (if $rch_queue_json == "" then null else $rch_queue_json end),
        bridge_report_json: $bridge_report_json
      }
    }
  ' >"$report_json"

decision="$(jq -r '.decision' "$report_json")"
write_event "doctor_completed" "continuity doctor emitted report" "$decision" "swarm_continuity_doctor_report.json"

jq -n \
  --arg schema_version "franken-engine.swarm-continuity-doctor-run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --arg decision "$decision" \
  --arg report_json "swarm_continuity_doctor_report.json" \
  --arg events_jsonl "events.jsonl" \
  --arg commands_txt "commands.txt" \
  --arg report_md "report.md" \
  --arg bridge_dir "mail_outage_bridge" \
  --slurpfile report "$report_json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    generated_epoch_seconds: $generated_epoch_seconds,
    decision: $decision,
    artifact_paths: {
      continuity_report_json: $report_json,
      events_jsonl: $events_jsonl,
      commands_txt: $commands_txt,
      report_md: $report_md,
      mail_outage_bridge_dir: $bridge_dir
    },
    source_paths: $report[0].source_paths,
    mutation_policy: $report[0].mutation_policy
  }' >"$run_manifest_path"

{
  printf '# Swarm Continuity Doctor\n\n'
  printf -- '%s\n' "- Decision: \`${decision}\`"
  printf -- '%s\n' "- Findings: \`$(jq '.summary.finding_count' "$report_json")\`"
  printf -- '%s\n' "- Ready beads: \`$(jq '.summary.ready_count' "$report_json")\`"
  printf -- '%s\n' "- In-progress beads: \`$(jq '.summary.in_progress_count' "$report_json")\`"
  printf -- '%s\n' "- Mail health: \`$(jq -r '.states.mail_health' "$report_json")\`"
  printf -- '%s\n\n' "- RCH state: \`$(jq -r '.states.rch' "$report_json")\`"
  if [[ "$(jq '.findings | length' "$report_json")" -gt 0 ]]; then
    printf '## Findings\n\n'
    jq -r '.findings[] | "- `" + .code + "` (" + .severity + "): " + .detail' "$report_json"
    printf '\n'
  fi
  printf '## Artifacts\n\n'
  printf -- '%s\n' "- \`run_manifest.json\`"
  printf -- '%s\n' "- \`swarm_continuity_doctor_report.json\`"
  printf -- '%s\n' "- \`events.jsonl\`"
  printf -- '%s\n' "- \`commands.txt\`"
  printf -- '%s\n' "- \`mail_outage_bridge/\`"
} >"$report_md"

case "$decision" in
  blocked)
    exit 42
    ;;
  healthy|degraded)
    exit 0
    ;;
  *)
    exit 42
    ;;
esac
