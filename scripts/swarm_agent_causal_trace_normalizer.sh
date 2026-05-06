#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_AGENT_CAUSAL_TRACE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-agent-causal-trace}"
run_id="${SWARM_AGENT_CAUSAL_TRACE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_CAUSAL_TRACE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bead_id=""
agent_name=""
source_revision=""
br_issue_json=""
br_ready_json=""
br_sync_status_json=""
bv_actionable_plan_json=""
agent_mail_profiles_json=""
agent_mail_messages_json=""
file_reservations_json=""
declared_write_set_json=""
git_status_json=""
git_closeout_commits_json=""
rch_validation_artifacts_json=""
validation_commands_json=""
operator_status_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_agent_causal_trace_normalizer.sh --bead-id ID --agent-name NAME --br-issue-json FILE [OPTIONS]

Normalizes preserved br, Agent Mail, reservation, git, RCH, and validation
fixtures into the SWARM-CTRL-XVI causal trace event spine. This script is
fixture-fed only. It does not query live br, Agent Mail, rch, git, or cargo.

Required:
  --bead-id ID
  --agent-name NAME
  --br-issue-json FILE

Optional:
  --br-ready-json FILE
  --br-sync-status-json FILE
  --bv-actionable-plan-json FILE
  --agent-mail-profiles-json FILE
  --agent-mail-messages-json FILE
  --file-reservations-json FILE
  --declared-write-set-json FILE
  --git-status-json FILE
  --git-closeout-commits-json FILE
  --rch-validation-artifacts-json FILE
  --validation-commands-json FILE
  --operator-status-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_agent_causal_trace_input.json
  swarm_agent_causal_trace_sources.json
  swarm_agent_causal_trace_events.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  normalized trace is replayable; decision may be pass or degraded
  42 fail-closed anomaly detected
  64 invalid required input or malformed JSON
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      bead_id="${2:-}"
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
    --br-issue-json)
      br_issue_json="${2:-}"
      shift 2
      ;;
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-sync-status-json)
      br_sync_status_json="${2:-}"
      shift 2
      ;;
    --bv-actionable-plan-json)
      bv_actionable_plan_json="${2:-}"
      shift 2
      ;;
    --agent-mail-profiles-json)
      agent_mail_profiles_json="${2:-}"
      shift 2
      ;;
    --agent-mail-messages-json)
      agent_mail_messages_json="${2:-}"
      shift 2
      ;;
    --file-reservations-json)
      file_reservations_json="${2:-}"
      shift 2
      ;;
    --declared-write-set-json)
      declared_write_set_json="${2:-}"
      shift 2
      ;;
    --git-status-json)
      git_status_json="${2:-}"
      shift 2
      ;;
    --git-closeout-commits-json)
      git_closeout_commits_json="${2:-}"
      shift 2
      ;;
    --rch-validation-artifacts-json)
      rch_validation_artifacts_json="${2:-}"
      shift 2
      ;;
    --validation-commands-json)
      validation_commands_json="${2:-}"
      shift 2
      ;;
    --operator-status-json)
      operator_status_json="${2:-}"
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

if [[ -z "$bead_id" || -z "$agent_name" || -z "$br_issue_json" ]]; then
  printf 'swarm agent causal trace normalizer requires --bead-id, --agent-name, and --br-issue-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm agent causal trace normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm agent causal trace normalization\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
trace_input_path="${run_dir}/swarm_agent_causal_trace_input.json"
sources_path="${run_dir}/swarm_agent_causal_trace_sources.json"
events_json_path="${run_dir}/swarm_agent_causal_trace_events.json"
events_json_tmp="${events_json_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

br_issue_normalized="${run_dir}/br_issue.normalized.json"
br_issue_core="${run_dir}/br_issue.core.json"
br_ready_normalized="${run_dir}/br_ready.normalized.json"
br_sync_status_normalized="${run_dir}/br_sync_status.normalized.json"
bv_plan_normalized="${run_dir}/bv_actionable_plan.normalized.json"
profiles_normalized="${run_dir}/agent_mail_profiles.normalized.json"
messages_normalized="${run_dir}/agent_mail_messages.normalized.json"
reservations_normalized="${run_dir}/file_reservations.normalized.json"
write_set_normalized="${run_dir}/declared_write_set.normalized.json"
git_status_normalized="${run_dir}/git_status.normalized.json"
git_commits_normalized="${run_dir}/git_closeout_commits.normalized.json"
rch_artifacts_normalized="${run_dir}/rch_validation_artifacts.normalized.json"
validation_commands_normalized="${run_dir}/validation_commands.normalized.json"
operator_status_normalized="${run_dir}/operator_status.normalized.json"

printf './scripts/swarm_agent_causal_trace_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$degraded_reasons_jsonl"
: >"$fail_closed_reasons_jsonl"

emit_event() {
  local event="$1"
  local detail="$2"
  jq -cn --arg event "$event" --arg detail "$detail" \
    '{schema_version:"franken-engine.swarm-agent-causal-trace-normalizer-event.v1", event:$event, detail:$detail}' >>"$events_path"
}

record_degraded() {
  local code="$1"
  local message="$2"
  jq -cn --arg code "$code" --arg message "$message" '{code:$code, message:$message}' >>"$degraded_reasons_jsonl"
}

record_fail_closed() {
  local code="$1"
  local message="$2"
  jq -cn --arg code "$code" --arg message "$message" '{code:$code, message:$message}' >>"$fail_closed_reasons_jsonl"
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ -z "$input" || ! -f "$input" ]]; then
    printf '%s is required and must exist\n' "$label" >&2
    exit 64
  fi
  if ! jq -cS . "$input" >"$output"; then
    printf '%s must be valid JSON\n' "$label" >&2
    exit 64
  fi
  emit_event "source_loaded" "$label"
}

normalize_optional_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  local default_json="$4"
  if [[ -z "$input" ]]; then
    printf '%s\n' "$default_json" | jq -cS . >"$output"
    record_degraded "optional_snapshot_missing" "${label} was not supplied"
    return
  fi
  if [[ ! -f "$input" ]]; then
    printf '%s\n' "$default_json" | jq -cS . >"$output"
    record_degraded "optional_snapshot_missing" "${label} path does not exist: ${input}"
    return
  fi
  if ! jq -cS . "$input" >"$output"; then
    printf '%s\n' "$default_json" | jq -cS . >"$output"
    record_degraded "optional_snapshot_malformed" "${label} was malformed JSON"
    return
  fi
  emit_event "source_loaded" "$label"
}

normalize_required_json "$br_issue_json" "$br_issue_normalized" "br issue snapshot"
normalize_optional_json "$br_ready_json" "$br_ready_normalized" "br ready/list snapshot" '{"issues":[]}'
normalize_optional_json "$br_sync_status_json" "$br_sync_status_normalized" "br sync status snapshot" '{}'
normalize_optional_json "$bv_actionable_plan_json" "$bv_plan_normalized" "bv actionable plan snapshot" '{}'
normalize_optional_json "$agent_mail_profiles_json" "$profiles_normalized" "Agent Mail profiles snapshot" '{"agents":[]}'
normalize_optional_json "$agent_mail_messages_json" "$messages_normalized" "Agent Mail messages snapshot" '{"messages":[]}'
normalize_optional_json "$file_reservations_json" "$reservations_normalized" "file reservations snapshot" '{"reservations":[]}'
normalize_optional_json "$declared_write_set_json" "$write_set_normalized" "declared write set snapshot" '{"paths":[]}'
normalize_optional_json "$git_status_json" "$git_status_normalized" "git status snapshot" '{"paths":[]}'
normalize_optional_json "$git_closeout_commits_json" "$git_commits_normalized" "git closeout commits snapshot" '{"commits":[]}'
normalize_optional_json "$rch_validation_artifacts_json" "$rch_artifacts_normalized" "RCH validation artifact snapshot" '{"artifacts":[]}'
normalize_optional_json "$validation_commands_json" "$validation_commands_normalized" "validation command transcript snapshot" '{"commands":[]}'
normalize_optional_json "$operator_status_json" "$operator_status_normalized" "operator status snapshot" '{}'

jq 'if type == "array" then .[0] elif (type == "object" and has("issues")) then .issues[0] else . end' \
  "$br_issue_normalized" >"$br_issue_core"

if ! jq -e 'type == "object" and ((.id // "") | length > 0)' "$br_issue_core" >/dev/null; then
  printf 'br issue snapshot must contain one issue object\n' >&2
  exit 64
fi
if [[ "$(jq -r '.id // ""' "$br_issue_core")" != "$bead_id" ]]; then
  record_fail_closed "br_issue_mismatch" "br issue snapshot id does not match requested bead id"
fi

issue_status="$(jq -r '.status // "unknown"' "$br_issue_core")"
issue_assignee="$(jq -r '.assignee // ""' "$br_issue_core")"
if [[ "$issue_assignee" != "" && "$issue_assignee" != "$agent_name" && ( "$issue_status" == "in_progress" || "$issue_status" == "closed" ) ]]; then
  record_fail_closed "stale_owner_recent_activity_conflict" "bead assignee ${issue_assignee} does not match tracing agent ${agent_name}"
fi

if jq -e '
  def rows:
    if type == "array" then .
    elif type == "object" and has("messages") then .messages
    elif type == "object" and has("result") then .result
    else [] end;
  [rows[]
    | select(((.thread_id // "") == $bead) or ((.subject // "") | contains($bead)))
    | select((.ack_required // false) == true)
    | select(((.acknowledged // false) != true) and (((.ack_ts // .acknowledged_at // .acknowledged_at_utc // "") | length) == 0))
  ] | length > 0
' --arg bead "$bead_id" "$messages_normalized" >/dev/null; then
  record_fail_closed "ack_required_message_unacknowledged" "ack_required message in bead thread lacks acknowledgement evidence"
fi

if jq -e '
  [.. | objects | select(.local_fallback_detected? == true)] | length > 0
  or ([.. | scalars | tostring | select(test("local fallback|\\[RCH\\] local"; "i"))] | length > 0) # reject local fallback marker
' "$rch_artifacts_normalized" >/dev/null; then
  record_fail_closed "local_rch_fallback_contaminates_remote_proof" "RCH validation snapshot contains local fallback evidence"
fi

commit_count="$(jq '
  if type == "array" then length
  elif type == "object" and has("commits") then (.commits | length)
  elif type == "object" and has("commit") then 1
  else 0 end
' "$git_commits_normalized")"
validation_count="$(jq '
  if type == "array" then length
  elif type == "object" and has("commands") then (.commands | length)
  elif type == "object" and has("validations") then (.validations | length)
  else 0 end
' "$validation_commands_normalized")"
if [[ "$issue_status" == "closed" && "$commit_count" -eq 0 ]]; then
  record_fail_closed "closed_bead_missing_commit" "closed bead lacks linked closeout commit evidence"
fi
if [[ "$issue_status" == "closed" && "$validation_count" -eq 0 ]]; then
  record_fail_closed "closed_bead_missing_validation_evidence" "closed bead lacks validation command evidence"
fi

if jq -e '
  def reservation_rows:
    if type == "array" then .
    elif type == "object" and has("reservations") then .reservations
    elif type == "object" and has("granted") then .granted
    else [] end;
  def write_paths($w):
    if ($w | type) == "array" then $w
    elif ($w | type) == "object" and ($w | has("paths")) then $w.paths
    else [] end;
  ($write[0] | write_paths(.)) as $paths
  | [reservation_rows[]
      | select(((.agent_name // .holder // "") == $agent) or ((.bead_id // "") == $bead))
      | (.path_pattern // .path // "") as $p
      | select(($p | length) > 0)
      | select(($paths | index($p)) == null)
    ] | length > 0
' --arg bead "$bead_id" --arg agent "$agent_name" --slurpfile write "$write_set_normalized" "$reservations_normalized" >/dev/null; then
  record_fail_closed "reservation_without_matching_bead_scope" "reservation path is outside the declared bead write set"
fi

if jq -e '
  def status_rows:
    if type == "array" then .
    elif type == "object" and has("paths") then .paths
    elif type == "object" and has("dirty_files") then .dirty_files
    else [] end;
  def reservation_rows($r):
    if ($r | type) == "array" then $r
    elif ($r | type) == "object" and ($r | has("reservations")) then $r.reservations
    elif ($r | type) == "object" and ($r | has("granted")) then $r.granted
    else [] end;
  ($reservations[0] | reservation_rows(.)) as $rs
  | [status_rows[]
      | (if type == "string" then {path:.} else . end) as $row
      | ($row.path // $row.file // "") as $p
      | select(($p | length) > 0)
      | select([$rs[] | (.path_pattern // .path // "")] | index($p) == null)
    ] | length > 0
' --slurpfile reservations "$reservations_normalized" "$git_status_normalized" >/dev/null; then
  record_fail_closed "missing_reservation_for_dirty_path" "git dirty path lacks matching reservation evidence"
fi

jq -n \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  --arg br_issue_json "$br_issue_json" \
  --arg br_ready_json "$br_ready_json" \
  --arg br_sync_status_json "$br_sync_status_json" \
  --arg bv_actionable_plan_json "$bv_actionable_plan_json" \
  --arg agent_mail_profiles_json "$agent_mail_profiles_json" \
  --arg agent_mail_messages_json "$agent_mail_messages_json" \
  --arg file_reservations_json "$file_reservations_json" \
  --arg declared_write_set_json "$declared_write_set_json" \
  --arg git_status_json "$git_status_json" \
  --arg git_closeout_commits_json "$git_closeout_commits_json" \
  --arg rch_validation_artifacts_json "$rch_validation_artifacts_json" \
  --arg validation_commands_json "$validation_commands_json" \
  --arg operator_status_json "$operator_status_json" \
  '{
    schema_version:"franken-engine.swarm-agent-causal-trace-input.v1",
    bead_id:$bead_id,
    agent_name:$agent_name,
    source_revision:$source_revision,
    source_paths:{
      br_issue_json:$br_issue_json,
      br_ready_json:$br_ready_json,
      br_sync_status_json:$br_sync_status_json,
      bv_actionable_plan_json:$bv_actionable_plan_json,
      agent_mail_profiles_json:$agent_mail_profiles_json,
      agent_mail_messages_json:$agent_mail_messages_json,
      file_reservations_json:$file_reservations_json,
      declared_write_set_json:$declared_write_set_json,
      git_status_json:$git_status_json,
      git_closeout_commits_json:$git_closeout_commits_json,
      rch_validation_artifacts_json:$rch_validation_artifacts_json,
      validation_commands_json:$validation_commands_json,
      operator_status_json:$operator_status_json
    }
  }' >"$trace_input_path"

source_entries_jsonl="${run_dir}/source_entries.jsonl"
: >"$source_entries_jsonl"
for source_id in \
  br_issue_json br_ready_json br_sync_status_json bv_actionable_plan_json \
  agent_mail_profiles_json agent_mail_messages_json file_reservations_json \
  declared_write_set_json git_status_json git_closeout_commits_json \
  rch_validation_artifacts_json validation_commands_json operator_status_json
do
  normalized_var="${source_id}"
  normalized_path=""
  case "$source_id" in
    br_issue_json) normalized_path="$br_issue_normalized" ;;
    br_ready_json) normalized_path="$br_ready_normalized" ;;
    br_sync_status_json) normalized_path="$br_sync_status_normalized" ;;
    bv_actionable_plan_json) normalized_path="$bv_plan_normalized" ;;
    agent_mail_profiles_json) normalized_path="$profiles_normalized" ;;
    agent_mail_messages_json) normalized_path="$messages_normalized" ;;
    file_reservations_json) normalized_path="$reservations_normalized" ;;
    declared_write_set_json) normalized_path="$write_set_normalized" ;;
    git_status_json) normalized_path="$git_status_normalized" ;;
    git_closeout_commits_json) normalized_path="$git_commits_normalized" ;;
    rch_validation_artifacts_json) normalized_path="$rch_artifacts_normalized" ;;
    validation_commands_json) normalized_path="$validation_commands_normalized" ;;
    operator_status_json) normalized_path="$operator_status_normalized" ;;
  esac
  jq -cn \
    --arg source_id "$source_id" \
    --arg normalized_path "$normalized_path" \
    --arg content_hash "sha256:$(hash_file "$normalized_path")" \
    '{source_id:$source_id, normalized_path:$normalized_path, content_hash:$content_hash}' >>"$source_entries_jsonl"
  unset "$normalized_var"
done

jq -s \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  '{
    schema_version:"franken-engine.swarm-agent-causal-trace-sources.v1",
    bead_id:$bead_id,
    agent_name:$agent_name,
    source_revision:$source_revision,
    sources:.
  }' "$source_entries_jsonl" >"$sources_path"

degraded_reasons_json="${run_dir}/degraded_reasons.json"
fail_closed_reasons_json="${run_dir}/fail_closed_reasons.json"
jq -s . "$degraded_reasons_jsonl" >"$degraded_reasons_json"
jq -s . "$fail_closed_reasons_jsonl" >"$fail_closed_reasons_json"

fail_count="$(jq 'length' "$fail_closed_reasons_json")"
degraded_count="$(jq 'length' "$degraded_reasons_json")"
decision="pass"
if [[ "$fail_count" -gt 0 ]]; then
  decision="fail_closed"
elif [[ "$degraded_count" -gt 0 ]]; then
  decision="degraded"
fi

jq -n \
  --slurpfile issue "$br_issue_core" \
  --slurpfile profiles "$profiles_normalized" \
  --slurpfile messages "$messages_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile commits "$git_commits_normalized" \
  --slurpfile validations "$validation_commands_normalized" \
  --slurpfile rch "$rch_artifacts_normalized" \
  --slurpfile degraded "$degraded_reasons_json" \
  --slurpfile fail_closed "$fail_closed_reasons_json" \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" '
  def rows($x; $field):
    if ($x | type) == "array" then $x
    elif ($x | type) == "object" and ($x | has($field)) then $x[$field]
    elif ($x | type) == "object" and ($x | has("result")) then $x.result
    else [] end;
  def event($type; $source; $idx; $row):
    {
      event_id: ($type + "-" + ($idx | tostring)),
      event_type: $type,
      bead_id: $bead_id,
      agent_name: ($row.agent_name // $row.name // $row.from // $agent_name),
      thread_id: ($row.thread_id // $bead_id),
      source_revision: $source_revision,
      source_path: $source,
      artifact_path: ($row.artifact_path // $row.path // $row.path_pattern // ""),
      content_hash: ($row.content_hash // $row.sha256 // ""),
      observed_at: ($row.created_ts // $row.updated_at // $row.last_active_ts // ""),
      decision: ($row.decision // $row.status // $decision),
      degraded_reasons: $degraded[0],
      fail_closed_reasons: $fail_closed[0],
      payload: $row
    };
  [
    event("bead_state"; "br_issue_json"; 0; $issue[0])
  ]
  + ([rows($profiles[0]; "agents") | to_entries[] | event("agent_profile"; "agent_mail_profiles_json"; .key; .value)])
  + ([rows($messages[0]; "messages") | to_entries[] | event("mail_message"; "agent_mail_messages_json"; .key; .value)])
  + ([rows($reservations[0]; "reservations") | to_entries[] | event("file_reservation"; "file_reservations_json"; .key; .value)])
  + ([rows($commits[0]; "commits") | to_entries[] | event("git_commit"; "git_closeout_commits_json"; .key; .value)])
  + ([rows($validations[0]; "commands") | to_entries[] | event("validation_command"; "validation_commands_json"; .key; .value)])
  + ([rows($rch[0]; "artifacts") | to_entries[] | event("rch_proof_artifact"; "rch_validation_artifacts_json"; .key; .value)])
  | {
      schema_version:"franken-engine.swarm-agent-causal-trace-event-set.v1",
      bead_id:$bead_id,
      agent_name:$agent_name,
      source_revision:$source_revision,
      decision:$decision,
      degraded_reasons:$degraded[0],
      fail_closed_reasons:$fail_closed[0],
      events:.
    }
' >"$events_json_tmp"
mv "$events_json_tmp" "$events_json_path"

jq -n \
  --arg decision "$decision" \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg trace_input_json "$trace_input_path" \
  --arg sources_json "$sources_path" \
  --arg normalized_events_json "$events_json_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_path" \
  --slurpfile degraded "$degraded_reasons_json" \
  --slurpfile fail_closed "$fail_closed_reasons_json" \
  '{
    schema_version:"franken-engine.swarm-agent-causal-trace-normalizer-summary.v1",
    decision:$decision,
    bead_id:$bead_id,
    agent_name:$agent_name,
    degraded_reasons:$degraded[0],
    fail_closed_reasons:$fail_closed[0],
    artifact_paths:{
      trace_input_json:$trace_input_json,
      sources_json:$sources_json,
      normalized_events_json:$normalized_events_json,
      events_jsonl:$events_jsonl,
      commands_txt:$commands_txt,
      report_md:$report_md
    },
    mutation_policy:{
      fixture_fed_only:true,
      mutates_br:false,
      releases_reservations:false,
      sends_agent_mail:false,
      runs_cargo:false,
      runs_rch:false,
      mutates_remote_workers:false,
      changes_live_queue_policy:false
    }
  }' >"${run_dir}/swarm_agent_causal_trace_normalizer_summary.json"

{
  printf '# Swarm Agent Causal Trace Normalizer\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Bead: \`%s\`\n" "$bead_id"
  printf -- "- Agent: \`%s\`\n" "$agent_name"
  printf -- "- Events: \`%s\`\n" "$(jq '.events | length' "$events_json_path")"
  printf -- "- Degraded reasons: \`%s\`\n" "$degraded_count"
  printf -- "- Fail-closed reasons: \`%s\`\n" "$fail_count"
} >"$report_path"

emit_event "normalization_complete" "$decision"
printf 'swarm_agent_causal_trace_normalizer_summary=%s\n' "${run_dir}/swarm_agent_causal_trace_normalizer_summary.json"
printf 'swarm_agent_causal_trace_events=%s\n' "$events_json_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
