#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CONTROL_SURFACE_INTAKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-intake}"
run_id="${SWARM_CONTROL_SURFACE_INTAKE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CONTROL_SURFACE_INTAKE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

proposal_json=""
catalog_json=""
br_snapshot_json=""
source_revision="${SWARM_CONTROL_SURFACE_INTAKE_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_control_surface_intake_guard.sh --proposal-json FILE --catalog-json FILE [OPTIONS]

Classify proposed future swarm-control work against the normalized
control-surface catalog. The guard is advisory only and never creates beads,
updates dependencies, sends mail, runs Cargo/RCH, or mutates git.

Required:
  --proposal-json FILE
  --catalog-json FILE

Optional:
  --br-snapshot-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  intake_guard_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  report emitted
  42 unsafe or duplicate proposal rejected
  64 invalid arguments or malformed input JSON
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --proposal-json)
      proposal_json="${2:-}"
      shift 2
      ;;
    --catalog-json)
      catalog_json="${2:-}"
      shift 2
      ;;
    --br-snapshot-json)
      br_snapshot_json="${2:-}"
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
  printf 'jq is required for control-surface intake guarding\n' >&2
  exit 2
fi
if [[ -z "$proposal_json" || -z "$catalog_json" ]]; then
  printf '--proposal-json and --catalog-json are required\n' >&2
  usage
  exit 64
fi
for input in "$proposal_json" "$catalog_json" "$br_snapshot_json"; do
  if [[ -n "$input" ]]; then
    if [[ ! -f "$input" ]]; then
      printf 'input file does not exist: %s\n' "$input" >&2
      exit 64
    fi
    if ! jq empty "$input" >/dev/null 2>&1; then
      printf 'input is not valid JSON: %s\n' "$input" >&2
      exit 64
    fi
  fi
done
if ! jq -e '(.surfaces | type == "array")' "$catalog_json" >/dev/null; then
  printf 'catalog JSON must contain surfaces array\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_path="${run_dir}/intake_guard_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
markdown_path="${run_dir}/report.md"

: >"$events_path"
printf './scripts/swarm_control_surface_intake_guard.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-control-surface-intake.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

matches_path="${run_dir}/matched_surfaces.json"
jq -n \
  --slurpfile catalog "$catalog_json" \
  --slurpfile proposal "$proposal_json" \
  '
  def arr($x): if $x == null then [] else $x end;
  def intersect($a; $b): [$a[] as $x | select($b | index($x))];
  ($catalog[0].surfaces // []) as $surfaces
  | ($proposal[0].intent_tags // []) as $intent_tags
  | ($proposal[0].symptom_tags // []) as $symptom_tags
  | [
      $surfaces[]
      | . as $surface
      | (intersect(arr($surface.intent_tags); $intent_tags)) as $matched_intents
      | (intersect(arr($surface.symptom_tags); $symptom_tags)) as $matched_symptoms
      | (($matched_intents | length) * 10 + ($matched_symptoms | length) * 5) as $score
      | select($score > 0)
      | {
          surface_id: $surface.surface_id,
          owning_bead_id: $surface.owning_bead_id,
          score: $score,
          matched_intent_tags: $matched_intents,
          matched_symptom_tags: $matched_symptoms,
          upstream_surface_ids: ($surface.upstream_surface_ids // []),
          downstream_surface_ids: ($surface.downstream_surface_ids // []),
          validation_commands: ($surface.validation_commands // [])
        }
    ]
  | sort_by([-.score, .surface_id])
  ' >"$matches_path"

title="$(jq -r '.title // "untitled proposal"' "$proposal_json")"
description="$(jq -r '.description // ""' "$proposal_json")"
acceptance_count="$(jq '(.acceptance_criteria // []) | length' "$proposal_json")"
relationship_hint="$(jq -r '.relationship_hint // ""' "$proposal_json")"
parent_hint="$(jq -r '.parent_hint // ""' "$proposal_json")"
match_count="$(jq 'length' "$matches_path")"
top_surface="$(jq -r '.[0].surface_id // ""' "$matches_path")"
top_owner="$(jq -r '.[0].owning_bead_id // ""' "$matches_path")"
top_score="$(jq -r '.[0].score // 0' "$matches_path")"

unsafe=false
if jq -e '
  ((.mutation_claims // []) | any(test("mutate|release reservation|send agent mail|run cargo|run rch|change queue"; "i")))
  or ((.description // "") | test("mutate live|release reservations|send Agent Mail|run Cargo|run RCH|change queue policy"; "i"))
' "$proposal_json" >/dev/null; then
  unsafe=true
fi

if [[ "$unsafe" == "true" ]]; then
  recommended_action="duplicate_reject"
  decision_reason="unsafe live-mutation claim"
  exit_code=42
elif [[ "$acceptance_count" -eq 0 ]]; then
  recommended_action="needs_manual_review"
  decision_reason="missing acceptance criteria"
  exit_code=0
elif [[ "$relationship_hint" == "successor" && "$match_count" -gt 0 ]]; then
  recommended_action="extend_existing"
  decision_reason="proposal is a successor to an existing catalog surface"
  exit_code=0
elif [[ -n "$parent_hint" && "$match_count" -gt 0 ]]; then
  recommended_action="make_child_of"
  decision_reason="proposal names a parent or child relationship"
  exit_code=0
elif [[ "$top_score" -ge 20 ]]; then
  recommended_action="duplicate_reject"
  decision_reason="proposal strongly overlaps an existing catalog surface"
  exit_code=42
elif [[ "$match_count" -gt 0 ]]; then
  recommended_action="make_child_of"
  decision_reason="proposal partially overlaps an existing catalog surface"
  exit_code=0
else
  recommended_action="create_new"
  decision_reason="no existing surface matched the proposed tags"
  exit_code=0
fi

suggestions_path="${run_dir}/suggestions.json"
jq -n \
  --arg recommended_action "$recommended_action" \
  --arg title "$title" \
  --arg top_owner "$top_owner" \
  --arg top_surface "$top_surface" \
  '
  if $recommended_action == "create_new" then
    ["br create --type task --priority=2 " + ($title | @sh)]
  elif $recommended_action == "extend_existing" then
    ["br create --type task --priority=2 " + ($title | @sh), "br dep add <new-bead-id> " + $top_owner]
  elif $recommended_action == "make_child_of" then
    ["br create --type task --priority=2 " + ($title | @sh), "br dep add <new-bead-id> " + $top_owner]
  elif $recommended_action == "duplicate_reject" then
    ["Do not create a new bead; attach evidence to " + $top_owner + " or document why " + $top_surface + " is not applicable."]
  else
    ["Add acceptance criteria and rerun the intake guard."]
  end
  ' >"$suggestions_path"

bead_matches_path="${run_dir}/bead_matches.json"
if [[ -n "$br_snapshot_json" ]]; then
  jq -n --slurpfile snapshot "$br_snapshot_json" --arg title "$title" '
    [($snapshot[0].issues // $snapshot[0] // [])[]?
     | select((.title // "") == $title)
     | {id,title,status}]
  ' >"$bead_matches_path"
else
  jq -n '[]' >"$bead_matches_path"
fi

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-control-surface-intake-guard-report.v1" \
  --arg source_revision "$source_revision" \
  --arg title "$title" \
  --arg description "$description" \
  --arg recommended_action "$recommended_action" \
  --arg decision_reason "$decision_reason" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$markdown_path" \
  --arg report_json "$report_path" \
  --slurpfile matched_surfaces "$matches_path" \
  --slurpfile matched_beads "$bead_matches_path" \
  --slurpfile suggestions "$suggestions_path" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    proposal: {title:$title, description:$description},
    recommended_action: $recommended_action,
    decision_reason: $decision_reason,
    matched_surfaces: $matched_surfaces[0],
    matched_beads: $matched_beads[0],
    dependency_suggestions: (
      [$matched_surfaces[0][]? | select(.owning_bead_id != null) | {depends_on_id:.owning_bead_id,surface_id:.surface_id}]
    ),
    br_command_suggestions: $suggestions[0],
    artifact_paths: {
      intake_guard_report_json: $report_json,
      events_jsonl: $events_jsonl,
      commands_txt: $commands_txt,
      report_md: $report_md
    },
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false
    }
  }' >"$report_path"

{
  printf '# Swarm Control-Surface Intake Guard\n\n'
  printf -- "- recommended_action: \`%s\`\n" "$recommended_action"
  printf -- "- reason: \`%s\`\n" "$decision_reason"
  printf -- "- matched_surfaces: \`%s\`\n" "$match_count"
  printf -- "- report: \`%s\`\n" "$report_path"
} >"$markdown_path"

write_event "intake_report_emitted" "$recommended_action"
exit "$exit_code"
