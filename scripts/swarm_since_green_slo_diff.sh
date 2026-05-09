#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_SINCE_GREEN_SLO_DIFF_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-since-green-slo-diff}"
run_id="${SWARM_SINCE_GREEN_SLO_DIFF_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_SINCE_GREEN_SLO_DIFF_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_SINCE_GREEN_SLO_DIFF_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_since_green_slo_diff.sh --input-json FILE [OPTIONS]

Compares a preserved known-good evidence bundle with a current bundle and emits
an advisory what-changed-since-green SLO diff. The command never reruns proofs,
mutates claims, edits docs, promotes evidence, or invokes Cargo/rch.

Required:
  --input-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  since_green_diff.json
  downgrade_summary.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   diff emitted with pass or degraded decision
  42  missing green baseline or contaminated current evidence forced fail_closed
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
  printf 'jq is required for swarm since-green SLO diff\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm since-green SLO diff\n' >&2
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
diff_path="${run_dir}/since_green_diff.json"
downgrade_path="${run_dir}/downgrade_summary.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"
diff_tmp="${diff_path}.tmp"

for artifact_path in \
  "$diff_path" \
  "$downgrade_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$normalized_input" \
  "$diff_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"

printf './scripts/swarm_since_green_slo_diff.sh' >"$commands_path"
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
  --arg diff_path "$diff_path" \
  --arg downgrade_path "$downgrade_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def src: $input[0];
  def green: (src.green_bundle // {});
  def current: (src.current_bundle // {});
  def reason($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def artifact_by_id($items; $id): [$items[]? | select((.artifact_id // "") == $id)][0] // null;
  def changed_artifacts:
    [green.artifacts[]? as $green_art
      | (artifact_by_id((current.artifacts // []); ($green_art.artifact_id // ""))) as $current_art
      | if $current_art == null then
          {
            artifact_id: ($green_art.artifact_id // "unknown_artifact"),
            green_hash: ($green_art.hash // null),
            current_hash: null,
            green_schema_version: ($green_art.schema_version // null),
            current_schema_version: null,
            green_decision: ($green_art.decision // null),
            current_decision: null,
            change_kind: "missing_current_artifact",
            path: ($green_art.path // null),
            likely_owning_bead: ($green_art.owning_bead // green.owning_bead // null),
            owning_surface: ($green_art.owning_surface // null)
          }
        elif (($green_art.hash // "") != ($current_art.hash // "")
              or ($green_art.schema_version // "") != ($current_art.schema_version // "")
              or ($green_art.decision // "") != ($current_art.decision // "")) then
          {
            artifact_id: ($green_art.artifact_id // "unknown_artifact"),
            green_hash: ($green_art.hash // null),
            current_hash: ($current_art.hash // null),
            green_schema_version: ($green_art.schema_version // null),
            current_schema_version: ($current_art.schema_version // null),
            green_decision: ($green_art.decision // null),
            current_decision: ($current_art.decision // null),
            change_kind: (
              if (($green_art.schema_version // "") != ($current_art.schema_version // "")) then "schema_drift"
              elif (($green_art.decision // "") != ($current_art.decision // "")) then "decision_transition"
              else "hash_change" end
            ),
            path: ($current_art.path // $green_art.path // null),
            likely_owning_bead: ($current_art.owning_bead // green.owning_bead // null),
            owning_surface: ($current_art.owning_surface // $green_art.owning_surface // null)
          }
        else empty end];

  (changed_artifacts) as $changes
  | ([]
    + (if ((green.present // false) == true) then [] else [
        reason("missing_green_baseline"; "green_bundle";
          "known-good baseline bundle is missing";
          "Restore or declare the preserved green evidence bundle before comparing current state.")
      ] end)
    + (if ((current.local_fallback_detected // false) == true) then [
        reason("local_fallback_in_current"; "current_bundle";
          "current bundle contains local fallback contamination";
          "Discard the contaminated current bundle and capture remote-only evidence.")
      ] else [] end)
  ) as $fail_closed_reasons
  | ([]
    + (if ((current.freshness // "fresh") == "fresh") then [] else [
        reason("stale_current_bundle"; "current_bundle";
          "current evidence bundle is stale";
          "Refresh current evidence before using it for observed claims.")
      ] end)
    + ([$changes[] | select(.change_kind == "schema_drift")
        | reason("schema_drift"; (.artifact_id // "artifact");
            "artifact schema version changed since green";
            "Review schema migration before comparing decisions.")])
    + (if ((current.claim_state // "ok") == "downgrade_required") then [
        reason("claim_downgrade_required"; "claim_freshness";
          "claim freshness evidence requires downgrade";
          "Use downgrade wording until fresh passing proof is available.")
      ] else [] end)
    + (if any($changes[]?; (.current_decision // "pass") | IN("degraded", "fail", "fail_closed", "blocked", "contaminated")) then [
        reason("current_decision_regressed"; "artifact_doctor";
          "one or more current artifacts regressed from the green decision";
          "Inspect the first bad artifact before claiming recovery.")
      ] else [] end)
  ) as $degraded_reasons
  | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
     elif ($degraded_reasons | length) > 0 then "degraded"
     else "pass" end) as $decision
  | (($fail_closed_reasons + $degraded_reasons)[0] // null) as $first_bad
  | ($changes[0] // {}) as $first_change
  | {
      schema_version: "franken-engine.swarm-since-green-slo-diff.v1",
      component: "swarm_since_green_slo_diff",
      source_revision: $source_revision,
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      decision: $decision,
      decision_transition: ((green.decision // "missing") + " -> " + (current.decision // "missing")),
      green_bundle_id: (green.bundle_id // null),
      current_bundle_id: (current.bundle_id // null),
      fail_closed_reasons: $fail_closed_reasons,
      degraded_reasons: $degraded_reasons,
      changed_artifacts: $changes,
      changed_artifact_count: ($changes | length),
      first_bad_evidence: (if $first_bad == null then null else {
        code: $first_bad.code,
        source_id: $first_bad.source_id,
        detail: $first_bad.detail,
        artifact_id: ($first_change.artifact_id // null),
        path: ($first_change.path // null)
      } end),
      likely_owning_bead: ($first_change.likely_owning_bead // current.owning_bead // green.owning_bead // null),
      owning_surface: ($first_change.owning_surface // current.owning_surface // green.owning_surface // null),
      next_inspection_commands: [
        ("jq -S . " + (green.path // "GREEN_BUNDLE/run_manifest.json")),
        ("jq -S . " + (current.path // "CURRENT_BUNDLE/run_manifest.json")),
        (if (($first_change.path // "") | length) > 0 then "jq -S . " + $first_change.path else "jq -S . CURRENT_BUNDLE/artifact.json" end),
        "git log --oneline -- scripts README.md docs | sed -n 1,20p"
      ],
      artifact_paths: {
        since_green_diff_json: $diff_path,
        downgrade_summary_md: $downgrade_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        reads_saved_files_only: true,
        reruns_proofs: false,
        mutates_claims: false,
        edits_docs: false,
        promotes_evidence: false,
        runs_cargo: false,
        runs_rch: false
      }
    }
' >"$diff_tmp"
mv "$diff_tmp" "$diff_path"

jq -c '
  if (.decision == "fail_closed") then
    [.fail_closed_reasons[]
      | {
          schema_version: "franken-engine.swarm-since-green-slo-diff.event.v1",
          component: "swarm_since_green_slo_diff",
          event: "fail_closed_reason",
          outcome: "fail_closed",
          error_code: .code,
          source_id: .source_id,
          detail: .detail
        }]
  elif (.decision == "degraded") then
    [.degraded_reasons[]
      | {
          schema_version: "franken-engine.swarm-since-green-slo-diff.event.v1",
          component: "swarm_since_green_slo_diff",
          event: "degraded_reason",
          outcome: "degraded",
          error_code: .code,
          source_id: .source_id,
          detail: .detail
        }]
  else
    [{
      schema_version: "franken-engine.swarm-since-green-slo-diff.event.v1",
      component: "swarm_since_green_slo_diff",
      event: "since_green_diff_passed",
      outcome: "pass",
      error_code: null,
      source_id: null,
      detail: "current bundle matches green SLO evidence"
    }]
  end
  | .[]
' "$diff_path" >"$events_path"

jq -r '
  "# Since-Green Downgrade Summary",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Transition: `" + .decision_transition + "`"),
  ("- Likely owning bead: `" + (.likely_owning_bead // "unknown") + "`"),
  ("- Owning surface: `" + (.owning_surface // "unknown") + "`"),
  "",
  "## First Bad Evidence",
  "",
  (if .first_bad_evidence == null then
    "none"
  else
    "- `" + .first_bad_evidence.code + "` `" + .first_bad_evidence.source_id + "`: " + .first_bad_evidence.detail
  end),
  "",
  "## Next Inspection Commands",
  "",
  (.next_inspection_commands[] | "- `" + . + "`")
' "$diff_path" >"$downgrade_path"

jq -r '
  "# Swarm Since-Green SLO Diff",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Changed artifacts: `" + (.changed_artifact_count | tostring) + "`"),
  ("- Transition: `" + .decision_transition + "`"),
  "",
  "## Changed Artifacts",
  "",
  (if (.changed_artifacts | length) == 0 then
    "none"
  else
    (.changed_artifacts[]
      | "- `" + .artifact_id + "` `" + .change_kind + "` green=`" + ((.green_hash // "missing") | tostring) + "` current=`" + ((.current_hash // "missing") | tostring) + "`")
  end)
' "$diff_path" >"$report_path"

printf 'since_green_diff=%s\n' "$diff_path"
printf 'downgrade_summary=%s\n' "$downgrade_path"

if jq -e '.decision == "fail_closed"' "$diff_path" >/dev/null; then
  exit 42
fi
exit 0
