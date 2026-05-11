#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_IV_ZERO_READY_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iw4-zero-ready-drill}"
run_id="${IDEA_WIZARD_IV_ZERO_READY_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_IV_ZERO_READY_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_IV_ZERO_READY_DRILL_SOURCE_REVISION:-}"
generated_at_utc="${IDEA_WIZARD_IV_ZERO_READY_DRILL_GENERATED_AT_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
bead_id="${IDEA_WIZARD_IV_ZERO_READY_DRILL_BEAD_ID:-bd-aqijn}"
original_args=("$@")

br_ready_json=""
br_list_json=""
issues_jsonl=""
br_in_progress_json=""
mail_health_json=""
rch_status_json=""
git_status_json=""
queue_depth_json=""
target_dir_heatmap_json=""
proof_cache_locality_json=""
pressure_metrics_json=""
archive_pressure_json=""
resource_envelope_json=""
declare -a changed_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_iv_zero_ready_saturation_drill.sh --br-ready-json FILE --br-in-progress-json FILE --mail-health-json FILE --rch-status-json FILE --git-status-json FILE (--br-list-json FILE | --issues-jsonl FILE) --changed-path PATH [OPTIONS]

Run the IDEA-WIZARD-IV zero-ready saturation drill from preserved snapshots.
The drill is advisory only and never runs Cargo or RCH.

Required:
  --br-ready-json FILE
  --br-in-progress-json FILE
  --mail-health-json FILE
  --rch-status-json FILE
  --git-status-json FILE
  --br-list-json FILE | --issues-jsonl FILE
  --changed-path PATH

Optional resource inputs:
  --queue-depth-json FILE
  --target-dir-heatmap-json FILE
  --proof-cache-locality-json FILE
  --pressure-metrics-json FILE
  --archive-pressure-json FILE
  --resource-envelope-json FILE

Other options:
  --source-revision REV
  --generated-at-utc TIMESTAMP
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-ready-json) br_ready_json="${2:-}"; shift 2 ;;
    --br-list-json) br_list_json="${2:-}"; shift 2 ;;
    --issues-jsonl) issues_jsonl="${2:-}"; shift 2 ;;
    --br-in-progress-json) br_in_progress_json="${2:-}"; shift 2 ;;
    --mail-health-json) mail_health_json="${2:-}"; shift 2 ;;
    --rch-status-json) rch_status_json="${2:-}"; shift 2 ;;
    --git-status-json) git_status_json="${2:-}"; shift 2 ;;
    --queue-depth-json) queue_depth_json="${2:-}"; shift 2 ;;
    --target-dir-heatmap-json) target_dir_heatmap_json="${2:-}"; shift 2 ;;
    --proof-cache-locality-json) proof_cache_locality_json="${2:-}"; shift 2 ;;
    --pressure-metrics-json) pressure_metrics_json="${2:-}"; shift 2 ;;
    --archive-pressure-json) archive_pressure_json="${2:-}"; shift 2 ;;
    --resource-envelope-json) resource_envelope_json="${2:-}"; shift 2 ;;
    --changed-path) changed_paths+=("${2:-}"); shift 2 ;;
    --source-revision) source_revision="${2:-}"; shift 2 ;;
    --generated-at-utc) generated_at_utc="${2:-}"; shift 2 ;;
    --output-dir) run_dir="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage; exit 64 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for zero-ready saturation drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi
if [[ -z "$br_ready_json" || -z "$br_in_progress_json" || -z "$mail_health_json" || -z "$rch_status_json" || -z "$git_status_json" ]]; then
  printf 'zero-ready drill requires br-ready, br-in-progress, mail-health, rch-status, and git-status JSON\n' >&2
  usage
  exit 64
fi
if [[ -z "$br_list_json" && -z "$issues_jsonl" ]]; then
  printf 'zero-ready drill requires --br-list-json or --issues-jsonl\n' >&2
  usage
  exit 64
fi
if [[ "${#changed_paths[@]}" -eq 0 ]]; then
  printf 'zero-ready drill requires at least one --changed-path\n' >&2
  usage
  exit 64
fi

validate_json_if_supplied() {
  local path="$1"
  local label="$2"
  if [[ -z "$path" ]]; then
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf '%s JSON not found: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf '%s JSON is malformed: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

validate_json_if_supplied "$br_ready_json" "br-ready"
validate_json_if_supplied "$br_list_json" "br-list"
validate_json_if_supplied "$br_in_progress_json" "br-in-progress"
validate_json_if_supplied "$mail_health_json" "mail-health"
validate_json_if_supplied "$rch_status_json" "rch-status"
validate_json_if_supplied "$git_status_json" "git-status"
validate_json_if_supplied "$queue_depth_json" "queue-depth"
validate_json_if_supplied "$target_dir_heatmap_json" "target-dir-heatmap"
validate_json_if_supplied "$proof_cache_locality_json" "proof-cache-locality"
validate_json_if_supplied "$pressure_metrics_json" "pressure-metrics"
validate_json_if_supplied "$archive_pressure_json" "archive-pressure"
validate_json_if_supplied "$resource_envelope_json" "resource-envelope"
if [[ -n "$issues_jsonl" ]]; then
  if [[ ! -f "$issues_jsonl" ]]; then
    printf 'issues JSONL not found: %s\n' "$issues_jsonl" >&2
    exit 64
  fi
  if ! jq empty "$issues_jsonl" >/dev/null 2>&1; then
    printf 'issues JSONL is malformed: %s\n' "$issues_jsonl" >&2
    exit 64
  fi
fi

mkdir -p "$run_dir/step_logs"
report_path="${run_dir}/saturation_convergence_report.json"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"

for artifact_path in "$report_path" "$manifest_path" "$events_path" "$commands_path" "$trace_ids_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_iv_zero_ready_saturation_drill.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n\n# child step commands are logged under step_logs/\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-iv-zero-ready-drill.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

run_step() {
  local step_id="$1"
  shift
  local log_path="${run_dir}/step_logs/${step_id}.log"
  {
    printf 'command:'
    printf ' %q' "$@"
    printf '\n\n'
  } >"$log_path"
  set +e
  "$@" >>"$log_path" 2>&1
  local status=$?
  set -e
  printf '\nexit_status=%s\n' "$status" >>"$log_path"
  write_event "$step_id" "$status" "$log_path"
  return 0
}

write_event "drill_start" "started" "running child packet steps"

closed_dir="${run_dir}/closed_bead_proof"
coord_dir="${run_dir}/coordination_health"
validation_dir="${run_dir}/validation_impact"
heatmap_dir="${run_dir}/resource_heatmap"

closed_args=("$root_dir/scripts/idea_wizard_iv_closed_bead_proof_integrity.sh" --source-revision "$source_revision" --output-dir "$closed_dir")
if [[ -n "$br_list_json" ]]; then
  closed_args+=(--br-list-json "$br_list_json")
else
  closed_args+=(--issues-jsonl "$issues_jsonl" --max-beads 200 --recent-git-limit 200)
fi
run_step "step_000" "${closed_args[@]}"

run_step "step_001" \
  "$root_dir/scripts/idea_wizard_iv_coordination_health_packet.sh" \
  --br-in-progress-json "$br_in_progress_json" \
  --mail-health-json "$mail_health_json" \
  --source-revision "$source_revision" \
  --generated-epoch-seconds 1800000000 \
  --output-dir "$coord_dir"

validation_args=("$root_dir/scripts/idea_wizard_iv_validation_impact_planner.sh" --bead-id "$bead_id" --source-revision "$source_revision" --output-dir "$validation_dir")
for changed_path in "${changed_paths[@]}"; do
  validation_args+=(--changed-path "$changed_path")
done
export SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE="${SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE-}"
SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE="${SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE-}" run_step "step_002" "${validation_args[@]}"

heatmap_args=("$root_dir/scripts/idea_wizard_iv_resource_proof_heatmap.sh" --rch-status-json "$rch_status_json" --validation-impact-plan-json "${validation_dir}/validation_impact_plan.json" --source-revision "$source_revision" --output-dir "$heatmap_dir")
[[ -n "$queue_depth_json" ]] && heatmap_args+=(--queue-depth-json "$queue_depth_json")
[[ -n "$target_dir_heatmap_json" ]] && heatmap_args+=(--target-dir-heatmap-json "$target_dir_heatmap_json")
[[ -n "$proof_cache_locality_json" ]] && heatmap_args+=(--proof-cache-locality-json "$proof_cache_locality_json")
[[ -n "$pressure_metrics_json" ]] && heatmap_args+=(--pressure-metrics-json "$pressure_metrics_json")
[[ -n "$archive_pressure_json" ]] && heatmap_args+=(--archive-pressure-json "$archive_pressure_json")
[[ -n "$resource_envelope_json" ]] && heatmap_args+=(--resource-envelope-json "$resource_envelope_json")
run_step "step_003" "${heatmap_args[@]}"

jq -n \
  --slurpfile br_ready "$br_ready_json" \
  --slurpfile git_status "$git_status_json" \
  --arg schema_version "franken-engine.idea-wizard-iv-zero-ready-saturation-report.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg closed_report "${closed_dir}/closed_bead_proof_integrity.json" \
  --arg coord_report "${coord_dir}/coordination_health_packet.json" \
  --arg validation_report "${validation_dir}/validation_impact_plan.json" \
  --arg heatmap_report "${heatmap_dir}/resource_proof_heatmap.json" \
  --arg run_dir "$run_dir" \
  --arg report_path "$report_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg trace_ids_path "$trace_ids_path" '
    def rows($v): if ($v | type) == "array" then $v elif ($v.issues | type) == "array" then $v.issues else [] end;
    def read_json($path): try (input_filename as $ignore | {}) catch {};
    def reason($code; $detail; $action): {code:$code,detail:$detail,recommended_action:$action};
    ($br_ready[0] // []) as $ready_doc
    | ($git_status[0] // {}) as $git
    | (rows($ready_doc) | length) as $ready_count
    | ([
        {surface_id:"closed_bead_proof_integrity", path:$closed_report, required:true},
        {surface_id:"coordination_health_packet", path:$coord_report, required:true},
        {surface_id:"validation_impact_plan", path:$validation_report, required:true},
        {surface_id:"resource_proof_heatmap", path:$heatmap_report, required:true}
      ]) as $children
    | $children as $child_paths
    | {
        schema_version:$schema_version,
        bead_id:$bead_id,
        source_revision:$source_revision,
        generated_at_utc:$generated_at_utc,
        br_ready_count:$ready_count,
        git_status:$git,
        child_reports:$child_paths,
        artifact_paths:{
          run_dir:$run_dir,
          saturation_convergence_report_json:$report_path,
          run_manifest_json:$manifest_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          trace_ids_json:$trace_ids_path,
          step_logs_dir:($run_dir + "/step_logs")
        }
      }
  ' >"${report_path}.base"

jq -n \
  --slurpfile base "${report_path}.base" \
  --slurpfile closed "${closed_dir}/closed_bead_proof_integrity.json" \
  --slurpfile coord "${coord_dir}/coordination_health_packet.json" \
  --slurpfile validation "${validation_dir}/validation_impact_plan.json" \
  --slurpfile heatmap "${heatmap_dir}/resource_proof_heatmap.json" '
    def reason($code; $detail; $action): {code:$code,detail:$detail,recommended_action:$action};
    ($base[0]) as $b
    | ($closed[0] // {}) as $closed_report
    | ($coord[0] // {}) as $coord_report
    | ($validation[0] // {}) as $validation_report
    | ($heatmap[0] // {}) as $heatmap_report
    | ([
        if ($b.br_ready_count != 0) then reason("FE-IW4-NONZERO-READY-QUEUE"; "ready queue is not empty"; "Do not classify this as zero-ready saturation.") else empty end,
        if (($b.git_status.tracked_dirty // false) == true) then reason("FE-IW4-DIRTY-TRACKED-WORKTREE"; "tracked worktree evidence is dirty"; "Commit, stash, or explicitly classify tracked changes before replay.") else empty end,
        if (($closed_report.schema_version // "") == "") then reason("FE-IW4-MISSING-CLOSED-BEAD-PROOF"; "closed bead proof packet is missing or malformed"; "Regenerate the closed-bead proof packet.") else empty end,
        if (($coord_report.schema_version // "") == "") then reason("FE-IW4-MISSING-COORDINATION-HEALTH"; "coordination packet is missing or malformed"; "Regenerate the coordination health packet.") else empty end,
        if (($validation_report.schema_version // "") == "") then reason("FE-IW4-MISSING-VALIDATION-IMPACT"; "validation-impact packet is missing or malformed"; "Regenerate the validation-impact packet.") else empty end,
        if (($heatmap_report.schema_version // "") == "") then reason("FE-IW4-MISSING-RESOURCE-HEATMAP"; "resource heatmap packet is missing or malformed"; "Regenerate the resource heatmap packet.") else empty end,
        if (($heatmap_report.decision // "") == "fail_closed") then reason("FE-IW4-RESOURCE-HEATMAP-FAIL-CLOSED"; "resource heatmap failed closed"; "Resolve resource contamination before replay.") else empty end,
        if (($validation_report.decision // "") == "fail_closed") then reason("FE-IW4-VALIDATION-IMPACT-FAIL-CLOSED"; "validation impact plan failed closed"; "Resolve validation command mapping before replay.") else empty end
      ]) as $fail_closed
    | ([
        if (($coord_report.decision // "") | IN("degraded","fail_closed")) then reason("FE-IW4-MAIL-OUTAGE-HIDDEN"; "coordination health is degraded"; "Keep br soft-lock fallback visible.") else empty end,
        if (($closed_report.decision // "") == "degraded") then reason("FE-IW4-WEAK-CLOSED-BEAD-PROOF"; "closed bead proof integrity is degraded"; "Inspect weak closeout evidence before claiming saturation.") else empty end,
        if (($validation_report.decision // "") == "degraded") then reason("FE-IW4-VALIDATION-MAP-MISSING"; "validation impact plan is degraded"; "Use recommended focused proof before green saturation.") else empty end,
        if (($heatmap_report.decision // "") == "degraded") then reason("FE-IW4-RESOURCE-PRESSURE-BLOCKED"; "resource proof heatmap is degraded"; "Follow defer or pressure guidance before broad proof.") else empty end
      ]) as $degraded
    | $b + {
        decision:(if ($fail_closed | length) > 0 then "fail_closed" elif ($degraded | length) > 0 then "degraded" else "green" end),
        classification:(if ($fail_closed | length) > 0 then "tracker_blind_spot"
          elif any($degraded[]?; .code == "FE-IW4-MAIL-OUTAGE-HIDDEN") then "coordination_degraded"
          elif any($degraded[]?; .code == "FE-IW4-WEAK-CLOSED-BEAD-PROOF") then "proof_integrity_gap"
          elif any($degraded[]?; .code == "FE-IW4-VALIDATION-MAP-MISSING") then "validation_map_missing"
          elif any($degraded[]?; .code == "FE-IW4-RESOURCE-PRESSURE-BLOCKED") then "resource_pressure_blocked"
          else "true_saturation" end),
        child_reports:[
          {surface_id:"closed_bead_proof_integrity", path:$b.child_reports[0].path, decision:($closed_report.decision // "missing"), classification:($closed_report.classification // null)},
          {surface_id:"coordination_health_packet", path:$b.child_reports[1].path, decision:($coord_report.decision // "missing"), health_level:($coord_report.health_level // null)},
          {surface_id:"validation_impact_plan", path:$b.child_reports[2].path, decision:($validation_report.decision // "missing"), proof_sufficiency:($validation_report.proof_sufficiency // null)},
          {surface_id:"resource_proof_heatmap", path:$b.child_reports[3].path, decision:($heatmap_report.decision // "missing"), classification:($heatmap_report.classification // null)}
        ],
        degraded_reasons:$degraded,
        fail_closed_reasons:$fail_closed,
        mutation_policy:{advisory_only:true,proof_only:true,mutates_br:false,sends_agent_mail:false,repairs_agent_mail_db:false,runs_cargo:false,runs_rch:false,mutates_git:false},
        rch_policy:{runs_rch:false,emits_commands_only:true,required_heavy_cargo_prefix:"rch exec -- env CARGO_TARGET_DIR="}
      }
  ' >"$report_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-zero-ready-drill.run-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$(jq -r '.decision' "$report_path")" \
  --arg report_path "$report_path" \
  '{schema_version:$schema_version,bead_id:$bead_id,source_revision:$source_revision,decision:$decision,artifacts:{saturation_convergence_report_json:$report_path}}' >"$manifest_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-zero-ready-drill.trace-ids.v1" \
  --arg trace_id "iw4-zero-ready-drill-${run_id}" \
  --arg bead_id "$bead_id" \
  '{schema_version:$schema_version,trace_id:$trace_id,bead_id:$bead_id}' >"$trace_ids_path"

write_event "drill_complete" "$(jq -r '.decision' "$report_path")" "saturation convergence report emitted"
printf 'saturation_convergence_report=%s\n' "$report_path"
if [[ "$(jq -r '.decision' "$report_path")" == "fail_closed" ]]; then
  exit 42
fi
