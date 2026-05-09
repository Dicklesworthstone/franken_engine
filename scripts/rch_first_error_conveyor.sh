#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_FIRST_ERROR_CONVEYOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-first-error-conveyor}"
run_id="${RCH_FIRST_ERROR_CONVEYOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_FIRST_ERROR_CONVEYOR_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

clusters_json=""
profile_json=""
beads_json=""
reservations_json=""
announcements_json=""
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
  --beads-json FILE           Read-only bead ownership snapshot
  --reservations-json FILE    Read-only Agent Mail reservation snapshot
  --announcements-json FILE   Read-only recent announcement snapshot
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
    --beads-json)
      beads_json="${2:-}"
      shift 2
      ;;
    --reservations-json)
      reservations_json="${2:-}"
      shift 2
      ;;
    --announcements-json)
      announcements_json="${2:-}"
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
for input_path in "$beads_json" "$reservations_json" "$announcements_json"; do
  if [[ -z "$input_path" ]]; then
    continue
  fi
  if [[ ! -f "$input_path" ]]; then
    printf 'ownership snapshot JSON not found: %s\n' "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid ownership snapshot JSON: %s\n' "$input_path" >&2
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
beads_normalized_path="${run_dir}/beads.normalized.json"
reservations_normalized_path="${run_dir}/reservations.normalized.json"
announcements_normalized_path="${run_dir}/announcements.normalized.json"

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
  "$profile_normalized_path" \
  "$beads_normalized_path" \
  "$reservations_normalized_path" \
  "$announcements_normalized_path"; do
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
if [[ -n "$beads_json" ]]; then
  jq -cS . "$beads_json" >"$beads_normalized_path"
else
  printf '{"schema_version":"franken-engine.rch-first-error-conveyor-beads-snapshot.v1","beads":[],"health":{"contradictory_evidence":false,"fail_closed_reasons":[]}}\n' >"$beads_normalized_path"
fi
if [[ -n "$reservations_json" ]]; then
  jq -cS . "$reservations_json" >"$reservations_normalized_path"
else
  printf '{"schema_version":"franken-engine.rch-first-error-conveyor-reservations-snapshot.v1","reservations":[],"health":{"contradictory_evidence":false,"fail_closed_reasons":[]}}\n' >"$reservations_normalized_path"
fi
if [[ -n "$announcements_json" ]]; then
  jq -cS . "$announcements_json" >"$announcements_normalized_path"
else
  printf '{"schema_version":"franken-engine.rch-first-error-conveyor-announcements-snapshot.v1","announcements":[],"health":{"contradictory_evidence":false,"fail_closed_reasons":[]}}\n' >"$announcements_normalized_path"
fi

case_id="$(jq -r '.case_id // ""' "$clusters_normalized_path")"
if [[ -n "$case_id_override" ]]; then
  case_id="$case_id_override"
fi

jq -n \
  --slurpfile clusters "$clusters_normalized_path" \
  --slurpfile profile "$profile_normalized_path" \
  --slurpfile beads "$beads_normalized_path" \
  --slurpfile reservations "$reservations_normalized_path" \
  --slurpfile announcements "$announcements_normalized_path" \
  --arg schema_version "franken-engine.rch-first-error-conveyor-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg case_id "$case_id" \
  --arg clusters_json "$clusters_json" \
  --arg profile_json "$profile_json" \
  --arg beads_json "$beads_json" \
  --arg reservations_json "$reservations_json" \
  --arg announcements_json "$announcements_json" \
  --arg plan_path "$plan_path" \
  --arg commands_path "$commands_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg invocation_path "$invocation_path" \
  --arg report_path "$report_path" '
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def scalar($value): if $value == null then "" else ($value | tostring) end;
  def lower($value): scalar($value) | ascii_downcase;
  def first_code($value):
    if (arr($value.error_codes) | length) > 0 then arr($value.error_codes)[0]
    else ($value.error_code // "")
    end;
  def dedupe_key($value):
    if scalar($value.dedupe_key) != "" then lower($value.dedupe_key)
    else [
      lower($value.file_path),
      lower(first_code($value)),
      lower($value.error_family),
      lower($value.symbol // $value.test_name),
      lower($value.command_target // $value.package_target // $value.test_target)
    ] | join("|")
    end;
  def freshness($value):
    if scalar($value.freshness) != "" then scalar($value.freshness)
    elif ($value.stale // false) == true then "stale"
    elif ($value.fresh // false) == true then "fresh"
    else "fresh"
    end;
  def current_status($status): (["open", "blocked", "in_progress"] | index($status)) != null;
  def path_matches($pattern; $path):
    scalar($pattern) as $pattern_s
    | scalar($path) as $path_s
    | ($pattern_s != "" and $path_s != "" and (
        $pattern_s == $path_s
        or (($pattern_s | endswith("*")) and ($path_s | startswith($pattern_s[0:-1])))
      ));
  def health_fail_closed($doc):
    (($doc.health.contradictory_evidence // false) == true)
    or (($doc.health.fail_closed // false) == true);
  def health_reasons($doc):
    (arr($doc.health.fail_closed_reasons)
      + [if ($doc.health.contradictory_evidence // false) == true then "contradictory_ownership_evidence" else empty end]
      + [if ($doc.health.fail_closed // false) == true then "ownership_snapshot_fail_closed" else empty end]
    );
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
  def manual_command($cluster; $disp; $evidence):
    if $disp == "new_bead_candidate" then
      "# review before running: br create " + ((($cluster.proposed_bead.title // "Compile blocker follow-up") | @sh))
      + " -t " + ((($cluster.proposed_bead.issue_type // "bug") | @sh))
      + " -p " + ((($cluster.proposed_bead.priority // 2) | tostring | @sh))
      + " --description " + ((($cluster.proposed_bead.body_md // "Review preserved first-error evidence before filing.") | @sh))
    elif $disp == "block_current_bead" then
      "# block current bead until first error is fixed: " + (($cluster.proposed_bead.title // "current bead blocker") | @sh)
    elif $disp == "duplicate_existing_bead" then
      "# duplicate existing bead; inspect before filing: "
      + ((if ($evidence.matched_beads | length) > 0 then ($evidence.matched_beads | map(.id) | join(",")) else "unknown" end) | @sh)
    elif $disp == "defer_active_owner" then
      "# defer active owner or reservation; inspect before filing: "
      + (([
          ($evidence.active_reservations | map(.id | tostring)[]?),
          ($evidence.recent_announcements | map(.id | tostring)[]?)
        ] | join(",")) | @sh)
    else
      "# no source-fix bead recommended: insufficient evidence"
    end;
  ($clusters[0]) as $cluster_doc
  | ($profile[0]) as $profile_doc
  | ($beads[0]) as $beads_doc
  | ($reservations[0]) as $reservations_doc
  | ($announcements[0]) as $announcements_doc
  | (health_fail_closed($beads_doc) or health_fail_closed($reservations_doc) or health_fail_closed($announcements_doc)) as $ownership_fail_closed
  | (health_reasons($beads_doc) + health_reasons($reservations_doc) + health_reasons($announcements_doc) | unique) as $ownership_fail_reasons
  | (arr($beads_doc.beads) | map(. + {dedupe_key: dedupe_key(.), freshness: freshness(.), owner_kind: "bead"})) as $bead_records
  | (arr($reservations_doc.reservations) | map(. + {dedupe_key: dedupe_key(.), freshness: freshness(.), owner_kind: "reservation"})) as $reservation_records
  | (arr($announcements_doc.announcements) | map(. + {dedupe_key: dedupe_key(.), freshness: freshness(.), owner_kind: "announcement"})) as $announcement_records
  | (($cluster_doc.clusters // []) | to_entries | map(
      .value as $cluster
      | dedupe_key($cluster) as $cluster_key
      | scalar($cluster.file_path) as $cluster_path
      | disposition($cluster; ($profile_doc.decision // "unknown"); ($cluster_doc.decision // "unknown")) as $base_disp
      | ($bead_records | map(select(current_status(.status // "") and .dedupe_key == $cluster_key))) as $matching_current_beads
      | ($matching_current_beads | map(select(.freshness != "stale"))) as $fresh_matching_beads
      | ($matching_current_beads | map(select(.freshness == "stale"))) as $stale_matching_beads
      | ($reservation_records | map(select(
          ((.active // true) != false)
          and .freshness != "stale"
          and (
            (scalar(.dedupe_key) != "" and .dedupe_key == $cluster_key)
            or path_matches(.path_pattern; $cluster_path)
          )
        ))) as $fresh_reservations
      | ($announcement_records | map(select(
          .freshness != "stale"
          and (
            (scalar(.dedupe_key) != "" and .dedupe_key == $cluster_key)
            or (arr(.file_paths) | index($cluster_path) != null)
          )
        ))) as $fresh_announcements
      | (if $ownership_fail_closed then "insufficient_evidence"
         elif ($fresh_matching_beads | length) > 0 then "duplicate_existing_bead"
         elif (($fresh_reservations | length) + ($fresh_announcements | length)) > 0 then "defer_active_owner"
         else $base_disp
         end) as $disp
      | {
          dedupe_key: $cluster_key,
          matched_beads: ($fresh_matching_beads | map({id, status, title, freshness, dedupe_key})),
          stale_beads: ($stale_matching_beads | map({id, status, title, freshness, dedupe_key})),
          active_reservations: ($fresh_reservations | map({id, holder, agent_name, path_pattern, freshness, dedupe_key})),
          recent_announcements: ($fresh_announcements | map({id, message_id, from, sender, subject, freshness, dedupe_key})),
          ownership_fail_reasons: (if $ownership_fail_closed then $ownership_fail_reasons else [] end)
        } as $ownership_evidence
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
          dedupe_key: $cluster_key,
          reason_codes: (
            reasons($cluster; $profile_doc; $disp)
            + (if $ownership_fail_closed then $ownership_fail_reasons else [] end)
            + (if ($fresh_matching_beads | length) > 0 then ["duplicate_existing_bead"] else [] end)
            + (if (($fresh_reservations | length) + ($fresh_announcements | length)) > 0 then ["active_owner_present"] else [] end)
            + (if ($stale_matching_beads | length) > 0 then ["stale_owner_manual_reopen_candidate"] else [] end)
            | unique
          ),
          ownership_evidence: $ownership_evidence,
          evidence_paths: {
            clusters_json: $clusters_json,
            profile_json: $profile_json,
            beads_json: (if $beads_json == "" then null else $beads_json end),
            reservations_json: (if $reservations_json == "" then null else $reservations_json end),
            announcements_json: (if $announcements_json == "" then null else $announcements_json end)
          },
          proposed_command: manual_command($cluster; $disp; $ownership_evidence)
        }
    ) | sort_by(.rank, .source_index, .title)) as $recommendations
  | ([($cluster_doc.decision // ""), ($profile_doc.decision // "")] | map(select(. == "fail_closed")) | length > 0 or $ownership_fail_closed) as $has_fail_closed_input
  | {
      schema_version: $schema_version,
      case_id: (if $case_id == "" then null else $case_id end),
      source_revision: $source_revision,
      decision: (
        if $has_fail_closed_input then "fail_closed"
        elif ($recommendations | length) == 0 then "no_action"
        elif any($recommendations[]; .disposition == "block_current_bead") then "block_current_bead"
        elif any($recommendations[]; .disposition == "new_bead_candidate") then "recommend_follow_up"
        elif any($recommendations[]; .disposition == "defer_active_owner") then "defer_active_owner"
        elif any($recommendations[]; .disposition == "duplicate_existing_bead") then "dedupe_suppressed"
        else "no_action" end
      ),
      summary: {
        recommendation_count: ($recommendations | length),
        block_current_bead_count: ($recommendations | map(select(.disposition == "block_current_bead")) | length),
        new_bead_candidate_count: ($recommendations | map(select(.disposition == "new_bead_candidate")) | length),
        duplicate_existing_bead_count: ($recommendations | map(select(.disposition == "duplicate_existing_bead")) | length),
        defer_active_owner_count: ($recommendations | map(select(.disposition == "defer_active_owner")) | length),
        insufficient_evidence_count: ($recommendations | map(select(.disposition == "insufficient_evidence")) | length)
      },
      recommendations: $recommendations,
      source_decisions: {
        cluster_decision: ($cluster_doc.decision // "unknown"),
        profile_decision: ($profile_doc.decision // "unknown"),
        ownership_fail_closed: $ownership_fail_closed
      },
      input_artifacts: {
        clusters_json: $clusters_json,
        profile_json: $profile_json,
        beads_json: (if $beads_json == "" then null else $beads_json end),
        reservations_json: (if $reservations_json == "" then null else $reservations_json end),
        announcements_json: (if $announcements_json == "" then null else $announcements_json end)
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
  ("- Duplicate existing beads: `" + (.summary.duplicate_existing_bead_count | tostring) + "`"),
  ("- Deferred active owners: `" + (.summary.defer_active_owner_count | tostring) + "`"),
  ("- Insufficient evidence: `" + (.summary.insufficient_evidence_count | tostring) + "`"),
  "",
  "## Recommendations",
  "",
  (if (.recommendations | length) == 0 then "none" else (.recommendations[] | "- `" + .recommendation_id + "` `" + .disposition + "` " + .title) end)
' "$plan_path" >"$report_path"

write_event "input.loaded" "ok" "normalized cluster, profile, and ownership artifacts" "$clusters_json"
write_event "plan.emitted" "$(jq -r '.decision' "$plan_path")" "emitted first-error conveyor plan" "$plan_path"

printf 'first_error_conveyor_plan=%s\n' "$plan_path"
printf 'first_error_conveyor_report=%s\n' "$report_path"

if jq -e '.decision == "fail_closed"' "$plan_path" >/dev/null; then
  exit 42
fi
exit 0
