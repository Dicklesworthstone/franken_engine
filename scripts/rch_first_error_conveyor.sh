#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_FIRST_ERROR_CONVEYOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-first-error-conveyor}"
run_id="${RCH_FIRST_ERROR_CONVEYOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_FIRST_ERROR_CONVEYOR_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

clusters_json=""
profile_json=""
source_revision="${RCH_FIRST_ERROR_CONVEYOR_SOURCE_REVISION:-}"
case_id_override=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_first_error_conveyor.sh --clusters-json FILE --profile-json FILE [OPTIONS]

Composes preserved compile-blocker clusters with proof-isolation profile output
into an advisory ordered first-error plan. The conveyor is fixture-fed and
advisory-only: it does not run Cargo/rch, mutate beads, send Agent Mail, edit
files, or touch workers.

Required:
  --clusters-json FILE
  --profile-json FILE

Options:
  --source-revision REV
  --case-id ID
  --output-dir DIR

Artifacts:
  first_error_conveyor_plan.json
  proposed_commands.txt
  run_manifest.json
  events.jsonl
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --clusters-json)
      clusters_json="${2:-}"
      shift 2
      ;;
    --profile-json)
      profile_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id_override="${2:-}"
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

if [[ -z "$clusters_json" || -z "$profile_json" ]]; then
  printf 'first error conveyor requires --clusters-json and --profile-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for first error conveyor planning\n' >&2
  exit 2
fi
for input_path in "$clusters_json" "$profile_json"; do
  if [[ ! -f "$input_path" ]]; then
    printf 'input JSON not found: %s\n' "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid input JSON: %s\n' "$input_path" >&2
    exit 64
  fi
done
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/first_error_conveyor_plan.json"
plan_tmp="${plan_path}.tmp"
commands_path="${run_dir}/proposed_commands.txt"
manifest_path="${run_dir}/run_manifest.json"
manifest_tmp="${manifest_path}.tmp"
events_path="${run_dir}/events.jsonl"
invocation_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
clusters_normalized_path="${run_dir}/clusters.normalized.json"
profile_normalized_path="${run_dir}/profile.normalized.json"

for artifact_path in \
  "$plan_path" \
  "$plan_tmp" \
  "$commands_path" \
  "$manifest_path" \
  "$manifest_tmp" \
  "$events_path" \
  "$invocation_path" \
  "$report_path" \
  "$clusters_normalized_path" \
  "$profile_normalized_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/rch_first_error_conveyor.sh' >"$invocation_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$invocation_path"
done
printf '\n' >>"$invocation_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  local evidence_path="$4"

  jq -nc \
    --arg schema_version "franken-engine.rch-first-error-conveyor.event.v1" \
    --arg component "rch_first_error_conveyor" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: $schema_version,
      component: $component,
      event: $event,
      outcome: $outcome,
      detail: $detail,
      evidence_path: $evidence_path
    }' >>"$events_path"
}

jq -cS . "$clusters_json" >"$clusters_normalized_path"
jq -cS . "$profile_json" >"$profile_normalized_path"

case_id="$(jq -r '.case_id // ""' "$clusters_normalized_path")"
if [[ -n "$case_id_override" ]]; then
  case_id="$case_id_override"
fi

jq -n \
  --slurpfile clusters "$clusters_normalized_path" \
  --slurpfile profile "$profile_normalized_path" \
  --arg schema_version "franken-engine.rch-first-error-conveyor-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg case_id "$case_id" \
  --arg clusters_json "$clusters_json" \
  --arg profile_json "$profile_json" \
  --arg plan_path "$plan_path" \
  --arg commands_path "$commands_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg invocation_path "$invocation_path" \
  --arg report_path "$report_path" '
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def disposition($cluster; $profile_decision; $cluster_decision):
    if $profile_decision == "fail_closed" or $cluster_decision == "fail_closed" then "insufficient_evidence"
    elif ($cluster.disposition // "") == "block_current_bead" then "block_current_bead"
    elif ($cluster.disposition // "") == "file_follow_up" then "new_bead_candidate"
    else "insufficient_evidence"
    end;
  def rank($disp):
    if $disp == "block_current_bead" then 0
    elif $disp == "new_bead_candidate" then 10
    elif $disp == "duplicate_existing_bead" then 20
    elif $disp == "defer_active_owner" then 30
    else 40 end;
  def reasons($cluster; $profile_doc; $disp):
    ([
      if $disp == "block_current_bead" then "target_relevant_first_error" else empty end,
      if $disp == "new_bead_candidate" then "unrelated_current_head_follow_up" else empty end,
      if $disp == "insufficient_evidence" then "insufficient_or_contaminated_evidence" else empty end,
      if ($profile_doc.decision // "") == "degraded" then "proof_profile_degraded" else empty end,
      if ($profile_doc.evidence_health.local_fallback_observed // false) == true then "local_fallback_contamination" else empty end,
      if ($profile_doc.evidence_health.transcript_truncated // false) == true then "truncated_output" else empty end
    ] + arr($profile_doc.evidence_health.fail_closed_reasons) | unique);
  def manual_command($cluster; $disp):
    if $disp == "new_bead_candidate" then
      "# review before running: br create " + ((($cluster.proposed_bead.title // "Compile blocker follow-up") | @sh))
      + " -t " + ((($cluster.proposed_bead.issue_type // "bug") | @sh))
      + " -p " + ((($cluster.proposed_bead.priority // 2) | tostring | @sh))
      + " --description " + ((($cluster.proposed_bead.body_md // "Review preserved first-error evidence before filing.") | @sh))
    elif $disp == "block_current_bead" then
      "# block current bead until first error is fixed: " + (($cluster.proposed_bead.title // "current bead blocker") | @sh)
    else
      "# no source-fix bead recommended: insufficient evidence"
    end;
  ($clusters[0]) as $cluster_doc
  | ($profile[0]) as $profile_doc
  | (($cluster_doc.clusters // []) | to_entries | map(
      .value as $cluster
      | disposition($cluster; ($profile_doc.decision // "unknown"); ($cluster_doc.decision // "unknown")) as $disp
      | {
          source_index: .key,
          recommendation_id: ("first-error-" + ((.key + 1) | tostring)),
          disposition: $disp,
          rank: rank($disp),
          title: ($cluster.proposed_bead.title // "Compile blocker follow-up"),
          file_path: ($cluster.file_path // null),
          error_family: ($cluster.error_family // "unknown"),
          error_codes: arr($cluster.error_codes),
          profile_decision: ($profile_doc.decision // "unknown"),
          proof_strength: ($profile_doc.classification.proof_strength // "unknown"),
          target_relevance: ($profile_doc.classification.target_relevance // "unknown"),
          reason_codes: reasons($cluster; $profile_doc; $disp),
          evidence_paths: {
            clusters_json: $clusters_json,
            profile_json: $profile_json
          },
          proposed_command: manual_command($cluster; $disp)
        }
    ) | sort_by(.rank, .source_index, .title)) as $recommendations
  | ([($cluster_doc.decision // ""), ($profile_doc.decision // "")] | map(select(. == "fail_closed")) | length > 0) as $has_fail_closed_input
  | {
      schema_version: $schema_version,
      case_id: (if $case_id == "" then null else $case_id end),
      source_revision: $source_revision,
      decision: (
        if $has_fail_closed_input then "fail_closed"
        elif ($recommendations | length) == 0 then "no_action"
        elif any($recommendations[]; .disposition == "block_current_bead") then "block_current_bead"
        else "recommend_follow_up" end
      ),
      summary: {
        recommendation_count: ($recommendations | length),
        block_current_bead_count: ($recommendations | map(select(.disposition == "block_current_bead")) | length),
        new_bead_candidate_count: ($recommendations | map(select(.disposition == "new_bead_candidate")) | length),
        insufficient_evidence_count: ($recommendations | map(select(.disposition == "insufficient_evidence")) | length)
      },
      recommendations: $recommendations,
      source_decisions: {
        cluster_decision: ($cluster_doc.decision // "unknown"),
        profile_decision: ($profile_doc.decision // "unknown")
      },
      input_artifacts: {
        clusters_json: $clusters_json,
        profile_json: $profile_json
      },
      artifact_paths: {
        first_error_conveyor_plan_json: $plan_path,
        proposed_commands_txt: $commands_path,
        run_manifest_json: $manifest_path,
        events_jsonl: $events_path,
        commands_txt: $invocation_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        runs_cargo: false,
        runs_rch: false,
        creates_beads: false,
        mutates_br: false,
        sends_agent_mail: false,
        changes_workers: false
      }
    }' >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

jq -r '
  "# Review-only first-error recommendations",
  "",
  "Do not paste blindly. These commands are comments or draft br commands for manual review.",
  "",
  (.recommendations[]? | .proposed_command)
' "$plan_path" >"$commands_path"

jq -n \
  --arg schema_version "franken-engine.rch-first-error-conveyor-run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg plan_path "$plan_path" \
  --arg commands_path "$commands_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg invocation_path "$invocation_path" \
  --arg report_path "$report_path" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    artifact_paths: {
      first_error_conveyor_plan_json: $plan_path,
      proposed_commands_txt: $commands_path,
      run_manifest_json: $manifest_path,
      events_jsonl: $events_path,
      commands_txt: $invocation_path,
      report_md: $report_path
    },
    mutation_policy: {
      fixture_fed_only: true,
      advisory_only: true,
      runs_cargo: false,
      runs_rch: false,
      creates_beads: false,
      mutates_br: false,
      sends_agent_mail: false,
      mutates_remote_workers: false
    }
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

jq -r '
  "# RCH First Error Conveyor Report",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Recommendations: `" + (.summary.recommendation_count | tostring) + "`"),
  ("- Block current bead: `" + (.summary.block_current_bead_count | tostring) + "`"),
  ("- New bead candidates: `" + (.summary.new_bead_candidate_count | tostring) + "`"),
  ("- Insufficient evidence: `" + (.summary.insufficient_evidence_count | tostring) + "`"),
  "",
  "## Recommendations",
  "",
  (if (.recommendations | length) == 0 then "none" else (.recommendations[] | "- `" + .recommendation_id + "` `" + .disposition + "` " + .title) end)
' "$plan_path" >"$report_path"

write_event "input.loaded" "ok" "normalized cluster and profile artifacts" "$clusters_json"
write_event "plan.emitted" "$(jq -r '.decision' "$plan_path")" "emitted first-error conveyor plan" "$plan_path"

printf 'first_error_conveyor_plan=%s\n' "$plan_path"
printf 'first_error_conveyor_report=%s\n' "$report_path"

if jq -e '.decision == "fail_closed"' "$plan_path" >/dev/null; then
  exit 42
fi
exit 0
