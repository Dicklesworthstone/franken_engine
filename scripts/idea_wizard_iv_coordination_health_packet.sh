#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_IV_COORDINATION_HEALTH_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iw4-coordination-health}"
run_id="${IDEA_WIZARD_IV_COORDINATION_HEALTH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_IV_COORDINATION_HEALTH_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_IV_COORDINATION_HEALTH_SOURCE_REVISION:-}"
generated_epoch_seconds="${IDEA_WIZARD_IV_COORDINATION_HEALTH_GENERATED_EPOCH_SECONDS:-$(date -u +%s)}"
original_args=("$@")

mail_health_json=""
mail_bootstrap_json=""
agent_profiles_json=""
br_in_progress_json=""
git_status_json=""
file_reservations_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_iv_coordination_health_packet.sh --br-in-progress-json FILE [OPTIONS]

Emit coordination_health_packet.json from Agent Mail health-shaped evidence and
the existing swarm Agent Mail outage bridge. This adapter is advisory only and
never repairs Agent Mail or mutates coordination state.

Options:
  --mail-health-json FILE
  --mail-bootstrap-json FILE
  --agent-profiles-json FILE
  --br-in-progress-json FILE
  --git-status-json FILE
  --file-reservations-json FILE
  --source-revision REV
  --generated-epoch-seconds N
  --output-dir DIR
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

if [[ -z "$br_in_progress_json" ]]; then
  printf 'coordination health packet requires --br-in-progress-json\n' >&2
  usage
  exit 64
fi
if ! [[ "$generated_epoch_seconds" =~ ^[0-9]+$ ]]; then
  printf 'generated epoch seconds must be a non-negative integer\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
packet_path="${run_dir}/coordination_health_packet.json"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
bridge_dir="${run_dir}/agent_mail_outage_bridge"
bridge_stdout="${run_dir}/agent_mail_outage_bridge.stdout"
bridge_stderr="${run_dir}/agent_mail_outage_bridge.stderr"

: >"$events_path"
printf './scripts/idea_wizard_iv_coordination_health_packet.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-iv-coordination-health.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

emit_fail_closed_packet() {
  local reason_code="$1"
  local detail="$2"
  local action="$3"

  jq -n \
    --arg schema_version "franken-engine.idea-wizard-iv-coordination-health-packet.v1" \
    --arg source_revision "$source_revision" \
    --argjson generated_epoch_seconds "$generated_epoch_seconds" \
    --arg reason_code "$reason_code" \
    --arg detail "$detail" \
    --arg action "$action" \
    --arg packet_path "$packet_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_path "$report_path" \
    '{
      schema_version:$schema_version,
      source_revision:$source_revision,
      generated_epoch_seconds:$generated_epoch_seconds,
      decision:"fail_closed",
      health_level:"unknown",
      diagnosis:"malformed_or_missing_required_coordination_source",
      degraded_reasons:[],
      blocked_reasons:[{code:$reason_code,severity:"blocked",detail:$detail,recommended_manual_action:$action}],
      safe_next_actions:[$action, "Use br status/comments as the only coordination fallback until a valid health packet exists."],
      contact_limitations:["Agent Mail delivery and acknowledgements are not proven."],
      fallback_lock:{authority:"br_soft_lock", status:"unverified"},
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        mutates_br:false,
        sends_agent_mail:false,
        repairs_agent_mail_db:false,
        releases_reservations:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_git:false
      },
      artifact_paths:{
        coordination_health_packet_json:$packet_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path
      }
    }' >"$packet_path"

  jq -n \
    --arg schema_version "franken-engine.idea-wizard-iv-coordination-health.run-manifest.v1" \
    --arg source_revision "$source_revision" \
    --arg decision "fail_closed" \
    --arg packet_path "$packet_path" \
    '{schema_version:$schema_version,source_revision:$source_revision,decision:$decision,artifacts:{coordination_health_packet_json:$packet_path}}' >"$manifest_path"

  {
    printf '# IDEA-WIZARD-IV Coordination Health Packet\n\n'
    printf -- "- decision: \`fail_closed\`\n"
    printf -- "- reason: \`%s\`\n" "$reason_code"
    printf -- "- action: %s\n" "$action"
  } >"$report_path"
}

validate_json_if_supplied() {
  local path="$1"
  local label="$2"
  if [[ -z "$path" ]]; then
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    write_event "input_validation" "fail_closed" "${label} JSON is missing"
    emit_fail_closed_packet "FE-IW4-${label}-MISSING" "${label} JSON does not exist: ${path}" "Capture a valid ${label} JSON snapshot before using this packet as evidence."
    exit 42
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    write_event "input_validation" "fail_closed" "${label} JSON is malformed"
    emit_fail_closed_packet "FE-IW4-${label}-MALFORMED" "${label} JSON is malformed: ${path}" "Capture a valid ${label} JSON snapshot before using this packet as evidence."
    exit 42
  fi
}

validate_json_if_supplied "$mail_health_json" "MAIL-HEALTH"
validate_json_if_supplied "$mail_bootstrap_json" "MAIL-BOOTSTRAP"
validate_json_if_supplied "$agent_profiles_json" "AGENT-PROFILES"
validate_json_if_supplied "$git_status_json" "GIT-STATUS"
validate_json_if_supplied "$file_reservations_json" "FILE-RESERVATIONS"
validate_json_if_supplied "$br_in_progress_json" "BR-IN-PROGRESS"

bridge_args=(
  --br-in-progress-json "$br_in_progress_json"
  --source-revision "$source_revision"
  --generated-epoch-seconds "$generated_epoch_seconds"
  --output-dir "$bridge_dir"
)
[[ -n "$mail_health_json" ]] && bridge_args+=(--mail-health-json "$mail_health_json")
[[ -n "$mail_bootstrap_json" ]] && bridge_args+=(--mail-bootstrap-json "$mail_bootstrap_json")
[[ -n "$agent_profiles_json" ]] && bridge_args+=(--agent-profiles-json "$agent_profiles_json")
[[ -n "$git_status_json" ]] && bridge_args+=(--git-status-json "$git_status_json")
[[ -n "$file_reservations_json" ]] && bridge_args+=(--file-reservations-json "$file_reservations_json")

write_event "bridge_start" "started" "invoking Agent Mail outage continuity bridge"
set +e
"$root_dir/scripts/swarm_agent_mail_outage_continuity_bridge.sh" "${bridge_args[@]}" >"$bridge_stdout" 2>"$bridge_stderr"
bridge_status=$?
set -e
if [[ "$bridge_status" -ne 0 && "$bridge_status" -ne 42 ]]; then
  write_event "bridge_complete" "fail_closed" "bridge exited unexpectedly"
  cat "$bridge_stderr" >&2
  exit "$bridge_status"
fi

bridge_report="${bridge_dir}/mail_outage_continuity_bridge.json"
if [[ ! -f "$bridge_report" ]]; then
  write_event "bridge_complete" "fail_closed" "bridge did not emit report"
  emit_fail_closed_packet "FE-IW4-MAIL-BRIDGE-MISSING-REPORT" "The Agent Mail outage bridge did not emit its report." "Preserve stderr and rerun after the bridge emits a report."
  exit 42
fi

bridge_decision="$(jq -r '.decision' "$bridge_report")"
if [[ "$bridge_decision" == "blocked" || "$bridge_status" -eq 42 ]]; then
  packet_decision="fail_closed"
else
  packet_decision="$bridge_decision"
fi

jq -n \
  --slurpfile bridge "$bridge_report" \
  --arg schema_version "franken-engine.idea-wizard-iv-coordination-health-packet.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --arg decision "$packet_decision" \
  --arg packet_path "$packet_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg bridge_report "$bridge_report" '
    ($bridge[0] // {}) as $b
    | {
        schema_version:$schema_version,
        source_revision:$source_revision,
        generated_epoch_seconds:$generated_epoch_seconds,
        decision:$decision,
        health_level:($b.mail_health_state // "unknown"),
        bootstrap_state:($b.mail_bootstrap_state // "unknown"),
        diagnosis:(
          if $decision == "healthy" then "agent_mail_available"
          elif $decision == "degraded" then "agent_mail_degraded_use_br_soft_lock"
          else "coordination_evidence_insufficient_fail_closed"
          end
        ),
        degraded_reasons:($b.degraded_reasons // []),
        blocked_reasons:($b.blocked_reasons // []),
        safe_next_actions:(
          ($b.recommended_actions // [])
          + ["Attach this packet to the active bead when Agent Mail cannot carry the coordination update."]
        ),
        contact_limitations:[
          "Agent Mail delivery and acknowledgements are not proven unless health and bootstrap states are healthy.",
          "This packet does not request contact approval or acknowledge any message."
        ],
        fallback_lock:{
          authority:"br_soft_lock",
          br_in_progress_count:($b.summary.br_in_progress_count // 0),
          soft_lock_count:($b.summary.soft_lock_count // 0),
          soft_lock_receipts:($b.soft_lock_receipts // [])
        },
        mutation_policy:{
          advisory_only:true,
          proof_only:true,
          mutates_br:false,
          sends_agent_mail:false,
          repairs_agent_mail_db:false,
          releases_reservations:false,
          runs_cargo:false,
          runs_rch:false,
          mutates_git:false,
          mutates_remote_workers:false
        },
        source_bridge_artifacts:{
          report_json:$bridge_report,
          soft_locks_jsonl:($b.artifact_paths.soft_locks_jsonl // null),
          events_jsonl:($b.artifact_paths.events_jsonl // null),
          commands_txt:($b.artifact_paths.commands_txt // null),
          report_md:($b.artifact_paths.report_md // null)
        },
        artifact_paths:{
          coordination_health_packet_json:$packet_path,
          run_manifest_json:$manifest_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          report_md:$report_path
        }
      }' >"$packet_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-coordination-health.run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$packet_decision" \
  --arg packet_path "$packet_path" \
  --arg bridge_report "$bridge_report" \
  '{schema_version:$schema_version,source_revision:$source_revision,decision:$decision,artifacts:{coordination_health_packet_json:$packet_path,bridge_report_json:$bridge_report}}' >"$manifest_path"

{
  printf '# IDEA-WIZARD-IV Coordination Health Packet\n\n'
  printf -- "- decision: \`%s\`\n" "$packet_decision"
  printf -- "- health: \`%s\`\n" "$(jq -r '.health_level' "$packet_path")"
  printf -- "- bootstrap: \`%s\`\n" "$(jq -r '.bootstrap_state' "$packet_path")"
  printf -- "- soft locks: \`%s\`\n" "$(jq '.fallback_lock.soft_lock_count' "$packet_path")"
  printf '\n## Actions\n\n'
  jq -r '.safe_next_actions[]? | "- " + .' "$packet_path"
} >"$report_path"

write_event "packet_complete" "$packet_decision" "coordination health packet emitted"
printf 'coordination_health_packet=%s\n' "$packet_path"
if [[ "$packet_decision" == "fail_closed" ]]; then
  exit 42
fi
