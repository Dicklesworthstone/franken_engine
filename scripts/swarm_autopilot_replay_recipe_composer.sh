#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_REPLAY_RECIPE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-replay-recipe}"
run_id="${SWARM_AUTOPILOT_REPLAY_RECIPE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_REPLAY_RECIPE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_REPLAY_RECIPE_SOURCE_REVISION:-unknown}"
cohort_diff_receipts_json=""
anomaly_cohorts_json=""
replay_index_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_replay_recipe_composer.sh [OPTIONS]

Compose deterministic replay recipes from cohort diff receipts, anomaly cohorts,
and replay indexes. The composer is advisory only and proof only. It never
mutates beads, reservations, Agent Mail, workers, live queue policy, Cargo, or
RCH.

Required inputs:
  --cohort-diff-receipts-json FILE
  --anomaly-cohorts-json FILE
  --replay-index-json FILE

Optional inputs:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_autopilot_replay_recipe_bundle.json
  swarm_autopilot_replay_recipe_index.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   replay recipes emitted and safe to inspect
  42  stale diff, incomplete replay index, contaminated baseline, or missing evidence failed closed
  64  invalid command-line arguments
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --cohort-diff-receipts-json)
      cohort_diff_receipts_json="${2:-}"
      shift 2
      ;;
    --anomaly-cohorts-json)
      anomaly_cohorts_json="${2:-}"
      shift 2
      ;;
    --replay-index-json)
      replay_index_json="${2:-}"
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

if [[ -z "$cohort_diff_receipts_json" || -z "$anomaly_cohorts_json" || -z "$replay_index_json" ]]; then
  printf 'cohort diff receipts, anomaly cohorts, and replay index JSON inputs are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the replay recipe composer\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the replay recipe composer\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
bundle_path="${run_dir}/swarm_autopilot_replay_recipe_bundle.json"
bundle_tmp="${bundle_path}.tmp"
recipe_index_path="${run_dir}/swarm_autopilot_replay_recipe_index.json"
recipe_index_tmp="${recipe_index_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
diff_normalized="${run_dir}/cohort_diff_receipts.normalized.json"
cohorts_normalized="${run_dir}/anomaly_cohorts.normalized.json"
replay_normalized="${run_dir}/replay_index.normalized.json"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

printf './scripts/swarm_autopilot_replay_recipe_composer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-replay-recipe.event.v1" \
    --arg trace_id "trace-swarm-autopilot-replay-recipe-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    --arg evidence_path "$5" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      component:$component,
      event:$event,
      outcome:$outcome,
      error_code:(if $error_code == "" then null else $error_code end),
      evidence_path:$evidence_path
    }' >>"$events_path"
}

append_failure() {
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    --arg remediation_command "$4" \
    '{code:$code,source_id:$source_id,detail:$detail,remediation_command:$remediation_command}' \
    >>"$fail_closed_reasons_jsonl"
  write_event "replay_recipe_composer" "fail_closed_reason_recorded" "fail_closed" "$1" "$2"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "$label" "input_loaded" "captured" "" "$output_path"
}

check_shape() {
  local path="$1"
  local expr="$2"
  local code="$3"
  local source_id="$4"
  local detail="$5"
  local remediation="$6"
  if ! jq -e "$expr" "$path" >/dev/null 2>&1; then
    append_failure "$code" "$source_id" "$detail" "$remediation"
  fi
}

normalize_required_json "$cohort_diff_receipts_json" "$diff_normalized" "cohort_diff_receipts"
normalize_required_json "$anomaly_cohorts_json" "$cohorts_normalized" "anomaly_cohorts"
normalize_required_json "$replay_index_json" "$replay_normalized" "replay_index"

check_shape "$diff_normalized" '
  .schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipts.v1"
  and ((.cohort_diff_receipts // null) | type == "array")
  and ((.cohort_diff_receipts | length) > 0)
  and all(.cohort_diff_receipts[]?;
    ((.receipt_id // "") | length) > 0
    and ((.reference_cohort_id // "") | length) > 0
    and ((.comparison_cohort_id // "") | length) > 0
    and ((.classification_transition // "") | length) > 0
    and ((.raw_artifact_paths // null) | type == "object")
  )
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-SCHEMA-DRIFT" "cohort_diff_receipts_json" \
  "cohort diff receipts lack required fields or safety markers" \
  "Regenerate cohort diff receipts before composing replay recipes."

check_shape "$cohorts_normalized" '
  .schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1"
  and ((.cohorts // null) | type == "array")
  and ((.cohorts | length) > 0)
  and all(.cohorts[]?; ((.cohort_id // "") | length) > 0 and ((.classification // "") | length) > 0 and ((.raw_artifact_paths // null) | type == "object"))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-SCHEMA-DRIFT" "anomaly_cohorts_json" \
  "anomaly cohort bundle lacks cohort ids, classifications, raw paths, or safety markers" \
  "Regenerate anomaly cohorts before composing replay recipes."

check_shape "$replay_normalized" '
  .schema_version == "franken-engine.swarm-autopilot-replay-index.v1"
  and ((.entries // null) | type == "array")
  and ((.entries | length) > 0)
  and all(.entries[]?; ((.cohort_id // "") | length) > 0 and ((.classification // "") | length) > 0 and ((.evidence_refs // null) | type == "object"))
' "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-SCHEMA-DRIFT" "replay_index_json" \
  "replay index lacks entries, cohort ids, classifications, or evidence references" \
  "Regenerate replay indexes before composing replay recipes."

if jq -e '
  (.decision == "fail_closed" and ((.fail_closed_reasons // []) | any((.code // "") | test("STALE"; "i"))))
  or ([.freshness?, .cohort_diff_receipts[]?.freshness?, .cohort_diff_receipts[]?.reason_codes[]?] | map(tostring) | any(test("stale"; "i")))
' "$diff_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-STALE-DIFF" "cohort_diff_receipts_json" \
    "cohort diff receipts are stale or were produced from stale material" \
    "Refresh cohort diff receipts before composing replay recipes."
fi

if jq -e -n --slurpfile diff "$diff_normalized" --slurpfile replay "$replay_normalized" '
  ($diff[0].cohort_diff_receipts // []) as $receipts
  | ($replay[0].entries // []) as $entries
  | any($receipts[];
      .comparison_cohort_id as $cohort_id
      | ([ $entries[] | select(.cohort_id == $cohort_id and ((.evidence_refs // {}) | length > 0)) ] | length) == 0
    )
' >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-INCOMPLETE-INDEX" "replay_index_json" \
    "one or more comparison cohorts lack replay-index entries with evidence references" \
    "Regenerate replay indexes with evidence_refs for every comparison cohort."
fi

if jq -e '
  any(.cohort_diff_receipts[]?;
    (.classification_transition | test("to_contaminated$"))
    or (.remote_truth_valid == false and (.classification_transition | test("to_reference$")))
  )
' "$diff_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-CONTAMINATED-BASELINE" "cohort_diff_receipts_json" \
    "contaminated evidence cannot be selected as a remote-only replay baseline" \
    "Keep contaminated comparison cohorts quarantined and compose only non-mutating inspection recipes."
fi

if jq -e '
  any(.cohort_diff_receipts[]?; ((.raw_artifact_paths.reference // {}) | length) == 0 or ((.raw_artifact_paths.comparison // {}) | length) == 0)
' "$diff_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-MISSING-EVIDENCE" "cohort_diff_receipts_json" \
    "one or more diff receipts lack raw reference or comparison artifact paths" \
    "Regenerate cohort diff receipts with raw artifact paths preserved."
fi

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // "unknown"' "$diff_normalized")"
fi

decision="pass"
truth_state="confirmed"
exit_code=0
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
elif jq -e '.decision == "degraded"' "$diff_normalized" >/dev/null; then
  truth_state="degraded"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-replay-recipe-bundle.v1" \
  --arg bead_id "bd-00ofm.3" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg cohort_diff_receipts_json "$cohort_diff_receipts_json" \
  --arg anomaly_cohorts_json "$anomaly_cohorts_json" \
  --arg replay_index_json "$replay_index_json" \
  --arg bundle_path "$bundle_path" \
  --arg recipe_index_path "$recipe_index_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile diff "$diff_normalized" \
  --slurpfile cohorts "$cohorts_normalized" \
  --slurpfile replay "$replay_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  def stable_id($prefix; $value): ($prefix + "-" + (($value // "unknown") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase));
  def replay_entry($entries; $cohort_id): ([ $entries[] | select(.cohort_id == $cohort_id) ][0] // {});
  ($diff[0]) as $d
  | ($cohorts[0]) as $c
  | ($replay[0]) as $r
  | ($r.entries // []) as $entries
  | ($fail_closed_reasons | unique_by([.code, .source_id, .detail])) as $failures
  | ($d.cohort_diff_receipts // [] | map(. as $receipt
      | (replay_entry($entries; $receipt.comparison_cohort_id)) as $entry
      | ($receipt.classification_transition | split("_to_") | .[1] // "unknown") as $comparison_classification
      | (if $comparison_classification == "reference" then "reference_baseline_replay"
         elif $comparison_classification == "contaminated" then "quarantine_only"
         else "counterexample_replay"
         end) as $recipe_mode
      | {
          recipe_id:stable_id("replay-recipe"; $receipt.receipt_id),
          receipt_id:$receipt.receipt_id,
          replay_mode:$recipe_mode,
          replay_ready:(($decision != "fail_closed") and ($recipe_mode != "quarantine_only") and (($entry.evidence_refs // {}) | length > 0)),
          reference_cohort_id:$receipt.reference_cohort_id,
          comparison_cohort_id:$receipt.comparison_cohort_id,
          expected_classification:$comparison_classification,
          classification_transition:$receipt.classification_transition,
          comparison_pivots:{
            added_fingerprints:($receipt.added_fingerprints // []),
            removed_fingerprints:($receipt.removed_fingerprints // []),
            changed_fingerprints:($receipt.changed_fingerprints // []),
            worker_deltas:($receipt.worker_deltas // []),
            toolchain_deltas:($receipt.toolchain_deltas // []),
            topology_deltas:($receipt.topology_deltas // [])
          },
          evidence_paths:{
            diff_receipts_json:$cohort_diff_receipts_json,
            anomaly_cohorts_json:$anomaly_cohorts_json,
            replay_index_json:$replay_index_json,
            reference_raw_artifacts:($receipt.raw_artifact_paths.reference // {}),
            comparison_raw_artifacts:($receipt.raw_artifact_paths.comparison // {}),
            replay_evidence_refs:($entry.evidence_refs // {})
          },
          safe_rerun_instruction:(
            if $recipe_mode == "reference_baseline_replay" then
              "Replay the reference cohort as a baseline only; do not promote or mutate live policy from this recipe."
            elif $recipe_mode == "quarantine_only" then
              "Do not run contaminated evidence as a remote-only baseline; keep it quarantined for inspection."
            else
              "Replay the comparison cohort as a bounded counterexample; keep queue policy and worker state unchanged."
            end
          )
        }
    )) as $recipes
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$decision,
      truth_state:$truth_state,
      source_decision:($d.decision // "unknown"),
      warehouse_hashes:{
        reference:($d.reference_warehouse_hash // $c.warehouse_hash // "unknown"),
        comparison:($d.comparison_warehouse_hash // "unknown")
      },
      recipe_summary:{
        recipe_count:($recipes | length),
        replay_ready_count:($recipes | map(select(.replay_ready == true)) | length),
        reference_baseline_count:($recipes | map(select(.replay_mode == "reference_baseline_replay")) | length),
        counterexample_count:($recipes | map(select(.replay_mode == "counterexample_replay")) | length),
        quarantine_only_count:($recipes | map(select(.replay_mode == "quarantine_only")) | length)
      },
      replay_recipes:$recipes,
      fail_closed_reasons:$failures,
      artifact_paths:{
        replay_recipe_bundle_json:$bundle_path,
        replay_recipe_index_json:$recipe_index_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        cohort_diff_receipts_json:$cohort_diff_receipts_json,
        anomaly_cohorts_json:$anomaly_cohorts_json,
        replay_index_json:$replay_index_json
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        approves_replay_automatically:false,
        promotes_evidence_automatically:false
      }
    }' >"$bundle_tmp"
mv "$bundle_tmp" "$bundle_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-replay-recipe-index.v1" \
  --arg bead_id "bd-00ofm.3" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg recipe_index_path "$recipe_index_path" \
  --arg bundle_path "$bundle_path" \
  --slurpfile bundle "$bundle_path" '
  ($bundle[0]) as $doc
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$decision,
      entries:($doc.replay_recipes | map({
        recipe_id,
        receipt_id,
        replay_mode,
        replay_ready,
        reference_cohort_id,
        comparison_cohort_id,
        expected_classification,
        evidence_paths,
        safe_rerun_instruction
      })),
      fail_closed_reasons:$doc.fail_closed_reasons,
      artifact_paths:{
        replay_recipe_index_json:$recipe_index_path,
        replay_recipe_bundle_json:$bundle_path
      },
      mutation_policy:$doc.mutation_policy
    }' >"$recipe_index_tmp"
mv "$recipe_index_tmp" "$recipe_index_path"

{
  printf '# SWARM_AUTOPILOT_REPLAY_RECIPE_COMPOSER\n\n'
  printf -- "- decision: \`%s\`\n" "$(jq -r '.decision' "$bundle_path")"
  printf -- "- recipe_count: \`%s\`\n" "$(jq -r '.recipe_summary.recipe_count' "$bundle_path")"
  printf -- "- replay_ready_count: \`%s\`\n" "$(jq -r '.recipe_summary.replay_ready_count' "$bundle_path")"
  printf '\n## Recipes\n'
  jq -r '.replay_recipes[] | "- `\(.recipe_id)` mode=`\(.replay_mode)` ready=`\(.replay_ready)` expected=`\(.expected_classification)`"' "$bundle_path"
  if jq -e '.fail_closed_reasons | length > 0' "$bundle_path" >/dev/null; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `\(.code)` from `\(.source_id)`: \(.detail)"' "$bundle_path"
  fi
} >"$report_path"

write_event "replay_recipe_composer" "recipe_bundle_emitted" "$decision" "" "$bundle_path"
write_event "replay_recipe_composer" "recipe_index_emitted" "$decision" "" "$recipe_index_path"

exit "$exit_code"
