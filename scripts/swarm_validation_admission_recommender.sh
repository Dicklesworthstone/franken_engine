#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="${SWARM_VALIDATION_ADMISSION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
artifact_root="${SWARM_VALIDATION_ADMISSION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-validation-admission}"
run_dir="${SWARM_VALIDATION_ADMISSION_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bead_id=""
agent_id="${AGENT_NAME:-unknown}"
command_class="focused_lib_test"
ps_snapshot=""
br_snapshot_json=""
dirty_files_json=""
matrix_json="${root_dir}/docs/swarm_proof_command_preflight_contract_v1.json"
max_active_processes=2

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_validation_admission_recommender.sh --bead-id ID --ps-snapshot FILE --br-snapshot-json FILE --dirty-files-json FILE [OPTIONS]

Options:
  --agent-id ID             Agent claiming the validation lane.
  --command-class CLASS     source_only, focused_lib_test, focused_integration_test,
                            package_all_targets, clippy_all_targets, or release_gate.
  --matrix-json FILE        Warm-target command matrix JSON.
  --max-active-processes N  Max active cargo/rustc/rch lines before contention mode.
  --output-dir DIR          Artifact directory.

The recommender reads snapshots only. It never invokes cargo, rch, br, pgrep,
ps, or git on behalf of the caller.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --agent-id)
      agent_id="${2:-}"
      shift 2
      ;;
    --command-class)
      command_class="${2:-}"
      shift 2
      ;;
    --ps-snapshot)
      ps_snapshot="${2:-}"
      shift 2
      ;;
    --br-snapshot-json)
      br_snapshot_json="${2:-}"
      shift 2
      ;;
    --dirty-files-json)
      dirty_files_json="${2:-}"
      shift 2
      ;;
    --matrix-json)
      matrix_json="${2:-}"
      shift 2
      ;;
    --max-active-processes)
      max_active_processes="${2:-}"
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

if [[ -z "$bead_id" ]]; then
  printf 'missing --bead-id\n' >&2
  usage
  exit 64
fi
if ! [[ "$max_active_processes" =~ ^[0-9]+$ ]]; then
  printf 'max active processes must be numeric: %s\n' "$max_active_processes" >&2
  exit 64
fi

mkdir -p "$run_dir"
recommendation_path="${run_dir}/recommendation.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
findings_jsonl="${run_dir}/findings.jsonl"
: >"$events_path"
: >"$findings_jsonl"

printf './scripts/swarm_validation_admission_recommender.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

safe_token() {
  tr -c '[:alnum:]' '_' <<<"$1" | sed -E 's/_+$//; s/^_+//'
}

json_quote() {
  jq -Rn --arg value "$1" '$value'
}

emit_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  jq -nc \
    --arg schema_version "franken-engine.swarm-validation-admission-recommender.event.v1" \
    --arg component "swarm_validation_admission_recommender" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg bead_id "$bead_id" \
    '{schema_version: $schema_version, component: $component, event: $event, outcome: $outcome, detail: $detail, bead_id: $bead_id}' >>"$events_path"
}

emit_finding() {
  local severity="$1"
  local reason_code="$2"
  local evidence="$3"
  local remediation="$4"
  jq -nc \
    --arg severity "$severity" \
    --arg reason_code "$reason_code" \
    --arg evidence "$evidence" \
    --arg remediation "$remediation" \
    '{severity: $severity, reason_code: $reason_code, evidence: $evidence, remediation: $remediation}' >>"$findings_jsonl"
}

emit_event "recommendation.started" "ok" "$command_class"

process_inspection_available="false"
active_process_count="null"
active_all_targets_count="null"
active_focused_count="null"
if [[ -z "$ps_snapshot" || ! -r "$ps_snapshot" ]]; then
  emit_finding "blocker" "process_inspection_unavailable" "ps snapshot is missing or unreadable" "Capture pgrep -af 'cargo|rustc|rch exec' or ps output before admitting heavy validation."
else
  process_inspection_available="true"
  active_process_count="$(grep -Eic 'cargo|rustc|rch exec' "$ps_snapshot" || true)"
  active_all_targets_count="$(grep -Eic 'cargo (check|clippy) .*--all-targets|cargo (check|clippy) --all-targets' "$ps_snapshot" || true)"
  active_focused_count="$(grep -Eic 'cargo test .*--(lib|test)|cargo test .*(-p|--package)' "$ps_snapshot" || true)"
fi

matrix_class_found="false"
target_template=""
recommended_command_shape=""
if [[ -z "$matrix_json" || ! -r "$matrix_json" ]]; then
  emit_finding "blocker" "matrix_unavailable" "warm-target matrix JSON is missing or unreadable" "Refresh docs/swarm_proof_command_preflight_contract_v1.json before recommending validation."
elif ! jq empty "$matrix_json" >/dev/null 2>&1; then
  emit_finding "blocker" "matrix_invalid_json" "warm-target matrix JSON failed jq parsing" "Fix the matrix JSON before recommending validation."
else
  if jq -e --arg class "$command_class" '.warm_target_command_matrix[] | select(.class == $class)' "$matrix_json" >/dev/null; then
    matrix_class_found="true"
    target_template="$(jq -r --arg class "$command_class" '.warm_target_command_matrix[] | select(.class == $class) | .target_dir_template // ""' "$matrix_json")"
    recommended_command_shape="$(jq -r --arg class "$command_class" '.warm_target_command_matrix[] | select(.class == $class) | .canonical_command_shape' "$matrix_json")"
  else
    emit_finding "blocker" "unknown_command_class" "command class is not present in warm-target matrix" "Use a class from warm_target_command_matrix before scheduling validation."
  fi
fi

safe_bead="$(safe_token "$bead_id")"
recommended_target_dir=""
if [[ -n "$target_template" ]]; then
  recommended_target_dir="${target_template//<safe_bead_id>/$safe_bead}"
  recommended_target_dir="${recommended_target_dir//<intent>/$command_class}"
  recommended_target_dir="${recommended_target_dir//<test_name>/$command_class}"
fi

bead_owner_state="unknown"
bead_assignee=""
if [[ -z "$br_snapshot_json" || ! -r "$br_snapshot_json" ]]; then
  emit_finding "blocker" "bead_snapshot_unavailable" "br in-progress snapshot is missing or unreadable" "Capture br list --status=in_progress --json before recommending validation."
elif ! jq empty "$br_snapshot_json" >/dev/null 2>&1; then
  emit_finding "blocker" "bead_snapshot_invalid_json" "br snapshot failed jq parsing" "Fix or recapture the br snapshot before recommending validation."
else
  bead_assignee="$(
    jq -r --arg bead_id "$bead_id" '
      ((.issues // .) | flatten | map(select(.id == $bead_id)) | first | .assignee) // ""
    ' "$br_snapshot_json"
  )"
  if [[ -z "$bead_assignee" || "$bead_assignee" == "$agent_id" ]]; then
    bead_owner_state="owned_or_unassigned"
  else
    bead_owner_state="owned_by_other"
    emit_finding "blocker" "bead_owned_by_other_agent" "bead is assigned to ${bead_assignee}" "Coordinate with the bead assignee or pick a different validation lane."
  fi
fi

dirty_file_count="null"
dirty_overlap_count="null"
if [[ -z "$dirty_files_json" || ! -r "$dirty_files_json" ]]; then
  emit_finding "blocker" "dirty_snapshot_unavailable" "dirty files snapshot is missing or unreadable" "Capture dirty-file evidence before admitting validation."
elif ! jq empty "$dirty_files_json" >/dev/null 2>&1; then
  emit_finding "blocker" "dirty_snapshot_invalid_json" "dirty files snapshot failed jq parsing" "Fix or recapture the dirty files snapshot before recommending validation."
else
  dirty_file_count="$(jq '(.files // .) | length' "$dirty_files_json")"
  dirty_overlap_count="$(jq '[((.files // .)[]?) | select((.overlap == true) or (.state == "overlap"))] | length' "$dirty_files_json")"
  if [[ "$dirty_overlap_count" -gt 0 ]]; then
    emit_finding "blocker" "dirty_overlap" "dirty snapshot contains overlap entries" "Coordinate on dirty overlapping paths before admitting validation."
  fi
fi

blocker_count="$(jq -s '[.[] | select(.severity == "blocker")] | length' "$findings_jsonl")"
recommendation="validation_blocked"
reason_code="blocked_by_missing_or_conflicting_evidence"
exit_code=42

if [[ "$blocker_count" -eq 0 ]]; then
  if [[ "$command_class" == "source_only" ]]; then
    recommendation="run_source_only_now"
    reason_code="source_only_non_heavy"
    exit_code=0
  elif [[ "$active_all_targets_count" -gt 0 && "$command_class" =~ ^(package_all_targets|clippy_all_targets|release_gate)$ ]]; then
    recommendation="wait_existing_all_targets"
    reason_code="active_all_targets_in_progress"
    exit_code=75
  elif [[ "$active_all_targets_count" -gt 0 ]]; then
    recommendation="run_source_only_now"
    reason_code="active_all_targets_preserve_capacity"
    exit_code=0
  elif [[ "$active_process_count" -gt "$max_active_processes" ]]; then
    recommendation="run_source_only_now"
    reason_code="high_contention_use_source_only"
    exit_code=0
  elif [[ "$command_class" =~ ^(focused_lib_test|focused_integration_test)$ ]]; then
    recommendation="run_focused_rch_now"
    reason_code="idle_focused_proof_lane_available"
    exit_code=0
  else
    recommendation="validation_blocked"
    reason_code="no_focused_proof_selected"
    emit_finding "blocker" "no_focused_proof_selected" "requested class is not a focused or source-only proof" "Choose a focused proof class before launching new heavy validation."
    exit_code=42
  fi
fi

jq -n \
  --arg schema_version "franken-engine.swarm-validation-admission-recommender.v1" \
  --arg bead_id "$bead_id" \
  --arg agent_id "$agent_id" \
  --arg command_class "$command_class" \
  --arg recommendation "$recommendation" \
  --arg reason_code "$reason_code" \
  --arg process_inspection_available "$process_inspection_available" \
  --arg matrix_class_found "$matrix_class_found" \
  --arg bead_owner_state "$bead_owner_state" \
  --arg bead_assignee "$bead_assignee" \
  --arg recommended_target_dir "$recommended_target_dir" \
  --arg recommended_command_shape "$recommended_command_shape" \
  --arg recommendation_path "$recommendation_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson max_active_processes "$max_active_processes" \
  --argjson active_process_count "$active_process_count" \
  --argjson active_all_targets_count "$active_all_targets_count" \
  --argjson active_focused_count "$active_focused_count" \
  --argjson dirty_file_count "$dirty_file_count" \
  --argjson dirty_overlap_count "$dirty_overlap_count" \
  --slurpfile findings "$findings_jsonl" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    agent_id: $agent_id,
    command_class: $command_class,
    recommendation: $recommendation,
    reason_code: $reason_code,
    recommended_target_dir: (if $recommended_target_dir == "" then null else $recommended_target_dir end),
    recommended_command_shape: (if $recommended_command_shape == "" then null else $recommended_command_shape end),
    signals: {
      process_inspection_available: ($process_inspection_available == "true"),
      active_process_count: $active_process_count,
      active_all_targets_count: $active_all_targets_count,
      active_focused_count: $active_focused_count,
      max_active_processes: $max_active_processes,
      matrix_class_found: ($matrix_class_found == "true"),
      bead_owner_state: $bead_owner_state,
      bead_assignee: (if $bead_assignee == "" then null else $bead_assignee end),
      dirty_file_count: $dirty_file_count,
      dirty_overlap_count: $dirty_overlap_count
    },
    findings: ($findings | sort_by(.severity, .reason_code)),
    artifact_paths: {
      recommendation_json: $recommendation_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' >"$recommendation_path"

emit_event "recommendation.completed" "$recommendation" "$reason_code"

{
  printf '# Swarm Validation Admission Recommendation\n\n'
  printf -- "- bead_id: \`%s\`\n" "$bead_id"
  printf -- "- command_class: \`%s\`\n" "$command_class"
  printf -- "- recommendation: \`%s\`\n" "$recommendation"
  printf -- "- reason_code: \`%s\`\n" "$reason_code"
  if [[ -n "$recommended_target_dir" ]]; then
    printf -- "- recommended_target_dir: \`%s\`\n" "$recommended_target_dir"
  fi
} >"$report_path"

printf 'swarm_validation_admission_recommendation=%s\n' "$recommendation_path"
exit "$exit_code"
