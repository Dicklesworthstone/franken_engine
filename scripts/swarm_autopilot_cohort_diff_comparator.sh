#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_COHORT_DIFF_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-cohort-diff}"
run_id="${SWARM_AUTOPILOT_COHORT_DIFF_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_COHORT_DIFF_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_COHORT_DIFF_SOURCE_REVISION:-unknown}"
reference_anomaly_cohorts_json=""
comparison_anomaly_cohorts_json=""
reference_replay_index_json=""
comparison_replay_index_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_cohort_diff_comparator.sh [OPTIONS]

Compare healthy reference cohorts against degraded, blocked, or contaminated
cohorts and emit deterministic forensic diff receipts plus a fingerprint delta
plan. The comparator is advisory only and proof only. It never mutates beads,
reservations, Agent Mail, workers, live queue policy, or remote execution state,
and it never runs Cargo or RCH.

Required inputs:
  --reference-anomaly-cohorts-json FILE
  --comparison-anomaly-cohorts-json FILE
  --reference-replay-index-json FILE
  --comparison-replay-index-json FILE

Optional inputs:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_autopilot_cohort_diff_receipts.json
  swarm_autopilot_fingerprint_delta_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   diff emitted; decision may be pass or degraded
  42  malformed, stale, contradictory, missing-path, or contaminated reference
      material prevented a truthful comparison
  64  invalid command-line arguments
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --reference-anomaly-cohorts-json)
      reference_anomaly_cohorts_json="${2:-}"
      shift 2
      ;;
    --comparison-anomaly-cohorts-json)
      comparison_anomaly_cohorts_json="${2:-}"
      shift 2
      ;;
    --reference-replay-index-json)
      reference_replay_index_json="${2:-}"
      shift 2
      ;;
    --comparison-replay-index-json)
      comparison_replay_index_json="${2:-}"
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

if [[ -z "$reference_anomaly_cohorts_json" || -z "$comparison_anomaly_cohorts_json" || -z "$reference_replay_index_json" || -z "$comparison_replay_index_json" ]]; then
  printf 'reference/comparison cohort and replay-index JSON inputs are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the cohort diff comparator\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the cohort diff comparator\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
receipts_path="${run_dir}/swarm_autopilot_cohort_diff_receipts.json"
receipts_tmp="${receipts_path}.tmp"
delta_plan_path="${run_dir}/swarm_autopilot_fingerprint_delta_plan.json"
delta_plan_tmp="${delta_plan_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
reference_cohorts_normalized="${run_dir}/reference_anomaly_cohorts.normalized.json"
comparison_cohorts_normalized="${run_dir}/comparison_anomaly_cohorts.normalized.json"
reference_replay_normalized="${run_dir}/reference_replay_index.normalized.json"
comparison_replay_normalized="${run_dir}/comparison_replay_index.normalized.json"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

printf './scripts/swarm_autopilot_cohort_diff_comparator.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-cohort-diff.event.v1" \
    --arg trace_id "trace-swarm-autopilot-cohort-diff-${run_id}" \
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
    '{
      code:$code,
      source_id:$source_id,
      detail:$detail,
      remediation_command:$remediation_command
    }' >>"$fail_closed_reasons_jsonl"
  write_event "cohort_diff_comparator" "fail_closed_reason_recorded" "fail_closed" "$1" "$source_id"
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

normalize_required_json "$reference_anomaly_cohorts_json" "$reference_cohorts_normalized" "reference_anomaly_cohorts"
normalize_required_json "$comparison_anomaly_cohorts_json" "$comparison_cohorts_normalized" "comparison_anomaly_cohorts"
normalize_required_json "$reference_replay_index_json" "$reference_replay_normalized" "reference_replay_index"
normalize_required_json "$comparison_replay_index_json" "$comparison_replay_normalized" "comparison_replay_index"

for pair in \
  "${reference_cohorts_normalized}:reference_anomaly_cohorts_json" \
  "${comparison_cohorts_normalized}:comparison_anomaly_cohorts_json"; do
  path="${pair%%:*}"
  source_id="${pair#*:}"
  check_shape "$path" '
    .schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1"
    and ((.cohorts // null) | type == "array")
    and ((.cohorts | length) > 0)
    and (((.warehouse_hash // "") | type) == "string" and (.warehouse_hash | length) > 0)
    and (.mutation_policy.advisory_only == true)
    and (.mutation_policy.runs_cargo == false)
    and (.mutation_policy.runs_rch == false)
    and all(.cohorts[]; ((.cohort_id // "") | length) > 0 and ((.classification // "") | length) > 0 and ((.fingerprints // null) | type == "array"))
  ' "FE-SWARM-AUTOPILOT-COHORT-DIFF-SCHEMA-DRIFT" "$source_id" \
    "anomaly cohort bundle lacks required schema, cohorts, fingerprints, or safety markers" \
    "Regenerate anomaly cohorts with scripts/swarm_autopilot_anomaly_cohort_packer.sh before diffing."
done

for pair in \
  "${reference_replay_normalized}:reference_replay_index_json" \
  "${comparison_replay_normalized}:comparison_replay_index_json"; do
  path="${pair%%:*}"
  source_id="${pair#*:}"
  check_shape "$path" '
    .schema_version == "franken-engine.swarm-autopilot-replay-index.v1"
    and ((.entries // null) | type == "array")
    and ((.entries | length) > 0)
    and all(.entries[]; ((.cohort_id // "") | length) > 0 and ((.evidence_refs // null) | type == "object"))
  ' "FE-SWARM-AUTOPILOT-COHORT-DIFF-SCHEMA-DRIFT" "$source_id" \
    "replay index lacks required entries or evidence references" \
    "Regenerate replay indexes with scripts/swarm_autopilot_anomaly_cohort_packer.sh before diffing."
done

if jq -e '
  .cohorts
  | any(
      (.classification == "contaminated")
      or (.remote_truth_valid == false)
      or ([.failure_modes[]?] | any(test("local_fallback|contaminated"; "i")))
    )
' "$reference_cohorts_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-COHORT-DIFF-CONTAMINATED-REFERENCE" "reference_anomaly_cohorts_json" \
    "reference anomaly cohorts contain contaminated or non-remote truth material" \
    "Use a healthy reference cohort as the baseline before computing forensic diffs."
fi

if jq -e '
  [.cohorts[]?.freshness?, .cohorts[]?.source_freshness?, .cohorts[]?.failure_modes[]?]
  | map(tostring)
  | any(test("stale"; "i"))
' "$reference_cohorts_normalized" >/dev/null \
  || jq -e '
    [.entries[]?.freshness?, .entries[]?.failure_mode?]
    | map(tostring)
    | any(test("stale"; "i"))
  ' "$reference_replay_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-COHORT-DIFF-STALE-REFERENCE" "reference_material" \
    "reference cohorts or replay entries contain stale markers" \
    "Refresh stale reference cohorts and replay indexes before computing forensic diffs."
fi
if jq -e '
  [.cohorts[]?.freshness?, .cohorts[]?.source_freshness?, .cohorts[]?.failure_modes[]?]
  | map(tostring)
  | any(test("stale"; "i"))
' "$comparison_cohorts_normalized" >/dev/null \
  || jq -e '
    [.entries[]?.freshness?, .entries[]?.failure_mode?]
    | map(tostring)
    | any(test("stale"; "i"))
  ' "$comparison_replay_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-COHORT-DIFF-STALE-REFERENCE" "comparison_material" \
    "comparison cohorts or replay entries contain stale markers" \
    "Refresh stale comparison cohorts and replay indexes before computing forensic diffs."
fi

for pair in \
  "${reference_cohorts_normalized}:reference_anomaly_cohorts_json" \
  "${comparison_cohorts_normalized}:comparison_anomaly_cohorts_json"; do
  path="${pair%%:*}"
  source_id="${pair#*:}"
  if jq -e '
    .cohorts | any(
      ((.raw_artifact_paths // {}) | length) == 0
      or ((.fingerprints // []) | any(((.sha256 // "") | length) == 0))
    )
  ' "$path" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-COHORT-DIFF-MISSING-RAW-PATH" "$source_id" \
      "one or more cohorts lack raw artifact paths or fingerprints" \
      "Regenerate anomaly cohorts with raw artifact paths and stable fingerprints preserved."
  fi
done

for pair in \
  "${reference_replay_normalized}:reference_replay_index_json" \
  "${comparison_replay_normalized}:comparison_replay_index_json"; do
  path="${pair%%:*}"
  source_id="${pair#*:}"
  if jq -e '.entries | any(((.evidence_refs // {}) | length) == 0)' "$path" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-COHORT-DIFF-MISSING-RAW-PATH" "$source_id" \
      "one or more replay-index entries lack evidence_refs" \
      "Regenerate replay indexes with raw evidence references preserved."
  fi
done

for pair in \
  "${reference_cohorts_normalized}:reference_anomaly_cohorts_json" \
  "${comparison_cohorts_normalized}:comparison_anomaly_cohorts_json"; do
  path="${pair%%:*}"
  source_id="${pair#*:}"
  if jq -e '
    .cohorts
    | group_by(.cohort_id)
    | any((map(.classification) | unique | length) > 1)
  ' "$path" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-COHORT-DIFF-CONTRADICTORY-COHORT" "$source_id" \
      "the same cohort_id resolves to multiple classifications" \
      "Split contradictory cohort identities before computing forensic diffs."
  fi
done

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // "unknown"' "$comparison_cohorts_normalized")"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-cohort-diff-receipts.v1" \
  --arg bead_id "bd-00ofm.2" \
  --arg source_revision "$source_revision" \
  --arg reference_anomaly_cohorts_json "$reference_anomaly_cohorts_json" \
  --arg comparison_anomaly_cohorts_json "$comparison_anomaly_cohorts_json" \
  --arg reference_replay_index_json "$reference_replay_index_json" \
  --arg comparison_replay_index_json "$comparison_replay_index_json" \
  --arg receipts_path "$receipts_path" \
  --arg delta_plan_path "$delta_plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile reference "$reference_cohorts_normalized" \
  --slurpfile comparison "$comparison_cohorts_normalized" \
  --slurpfile reference_replay "$reference_replay_normalized" \
  --slurpfile comparison_replay "$comparison_replay_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  def setdiff($a; $b): [$a[] | select(. as $x | ($b | index($x) | not))];
  def stable_id($prefix; $value): ($prefix + "-" + (($value // "unknown") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase));
  def fp_map($cohort): ($cohort.fingerprints // [] | map({key:.source_id, value:.sha256}) | from_entries);
  def fp_source_ids($cohort): ($cohort.fingerprints // [] | map(.source_id) | unique | sort);
  def delta_strings($left; $right): setdiff(($right // []); ($left // []));
  ($reference[0]) as $ref_doc
  | ($comparison[0]) as $cmp_doc
  | ($reference_replay[0]) as $ref_replay
  | ($comparison_replay[0]) as $cmp_replay
  | ($ref_doc.cohorts[0]) as $ref
  | ($cmp_doc.cohorts // []) as $comparisons
  | ($fail_closed_reasons | unique_by([.code, .source_id, .detail])) as $failures
  | ($comparisons | map(. as $cmp
      | (fp_map($ref)) as $ref_fp
      | (fp_map($cmp)) as $cmp_fp
      | (fp_source_ids($ref)) as $ref_ids
      | (fp_source_ids($cmp)) as $cmp_ids
      | {
          receipt_id:stable_id("cohort-diff"; ($ref.cohort_id + "-to-" + $cmp.cohort_id)),
          reference_cohort_id:$ref.cohort_id,
          comparison_cohort_id:$cmp.cohort_id,
          classification_transition:(($ref.classification // "unknown") + "_to_" + ($cmp.classification // "unknown")),
          added_fingerprints:setdiff($cmp_ids; $ref_ids),
          removed_fingerprints:setdiff($ref_ids; $cmp_ids),
          changed_fingerprints:([$cmp_ids[] | select(($ref_fp[.] // null) != null and ($ref_fp[.] != $cmp_fp[.]))]),
          worker_deltas:delta_strings($ref.worker_ids; $cmp.worker_ids),
          toolchain_deltas:delta_strings($ref.toolchain_targets; $cmp.toolchain_targets),
          topology_deltas:delta_strings($ref.topology_classes; $cmp.topology_classes),
          source_ids:(($ref.source_ids // []) + ($cmp.source_ids // []) | unique | sort),
          raw_artifact_paths:{
            reference:($ref.raw_artifact_paths // {}),
            comparison:($cmp.raw_artifact_paths // {}),
            reference_replay_index:($ref_replay.artifact_paths.replay_index_json // $reference_replay_index_json),
            comparison_replay_index:($cmp_replay.artifact_paths.replay_index_json // $comparison_replay_index_json)
          },
          remote_truth_valid:(($ref.remote_truth_valid // true) and ($cmp.remote_truth_valid // true) and (($cmp.classification // "") != "contaminated"))
        }
    )) as $receipts
  | (if ($failures | length) > 0 then "fail_closed"
     elif any($comparisons[]; (.classification // "") != "reference") then "degraded"
     else "pass"
     end) as $decision
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      reference_warehouse_hash:($ref_doc.warehouse_hash // "unknown"),
      comparison_warehouse_hash:($cmp_doc.warehouse_hash // "unknown"),
      decision:$decision,
      comparison_summary:{
        reference_cohort_id:($ref.cohort_id // "unknown"),
        comparison_cohort_count:($comparisons | length),
        diff_receipt_count:($receipts | length),
        added_fingerprint_count:($receipts | map(.added_fingerprints | length) | add // 0),
        removed_fingerprint_count:($receipts | map(.removed_fingerprints | length) | add // 0),
        changed_fingerprint_count:($receipts | map(.changed_fingerprints | length) | add // 0),
        blocked_transition_count:($receipts | map(select(.classification_transition | test("blocked"))) | length),
        contaminated_transition_count:($receipts | map(select(.classification_transition | test("contaminated"))) | length)
      },
      cohort_diff_receipts:$receipts,
      fail_closed_reasons:$failures,
      remediation_commands:(
        if $decision == "fail_closed" then
          ($failures | map(.remediation_command) | unique)
        elif any($comparisons[]; (.classification // "") == "contaminated") then
          ["Keep contaminated comparison cohorts isolated from healthy reference material and refuse remote-only baseline selection."]
        elif any($comparisons[]; (.classification // "") == "blocked") then
          ["Inspect blocked locality or topology deltas before composing replay recipes."]
        elif $decision == "degraded" then
          ["Review degraded cohort diffs before promotion or replay recipe composition."]
        else
          ["Reference comparison is healthy; preserve diff receipts for future replay checks."]
        end
      ),
      artifact_paths:{
        cohort_diff_receipts_json:$receipts_path,
        fingerprint_delta_plan_json:$delta_plan_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        reference_anomaly_cohorts_json:$reference_anomaly_cohorts_json,
        comparison_anomaly_cohorts_json:$comparison_anomaly_cohorts_json,
        reference_replay_index_json:$reference_replay_index_json,
        comparison_replay_index_json:$comparison_replay_index_json
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
    }' >"$receipts_tmp"
mv "$receipts_tmp" "$receipts_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-fingerprint-delta-plan.v1" \
  --arg bead_id "bd-00ofm.2" \
  --arg source_revision "$source_revision" \
  --arg delta_plan_path "$delta_plan_path" \
  --arg receipts_path "$receipts_path" \
  --slurpfile receipts "$receipts_path" '
  ($receipts[0]) as $doc
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$doc.decision,
      reference_warehouse_hash:$doc.reference_warehouse_hash,
      comparison_warehouse_hash:$doc.comparison_warehouse_hash,
      fingerprint_delta_summary:$doc.comparison_summary,
      fingerprint_deltas:($doc.cohort_diff_receipts | map({
        receipt_id,
        reference_cohort_id,
        comparison_cohort_id,
        added_fingerprints,
        removed_fingerprints,
        changed_fingerprints,
        worker_deltas,
        toolchain_deltas,
        topology_deltas,
        remote_truth_valid
      })),
      fail_closed_reasons:$doc.fail_closed_reasons,
      artifact_paths:{
        fingerprint_delta_plan_json:$delta_plan_path,
        cohort_diff_receipts_json:$receipts_path
      }
    }' >"$delta_plan_tmp"
mv "$delta_plan_tmp" "$delta_plan_path"

{
  printf '# SWARM_AUTOPILOT_COHORT_DIFF_COMPARATOR\n\n'
  printf -- "- decision: \`%s\`\n" "$(jq -r '.decision' "$receipts_path")"
  printf -- "- diff_receipt_count: \`%s\`\n" "$(jq -r '.comparison_summary.diff_receipt_count' "$receipts_path")"
  printf -- "- changed_fingerprint_count: \`%s\`\n" "$(jq -r '.comparison_summary.changed_fingerprint_count' "$receipts_path")"
  printf '\n## Receipts\n'
  jq -r '.cohort_diff_receipts[] | "- `\(.receipt_id)` transition=`\(.classification_transition)` changed=`\(.changed_fingerprints | length)` remote_truth_valid=`\(.remote_truth_valid)`"' "$receipts_path"
  if jq -e '.fail_closed_reasons | length > 0' "$receipts_path" >/dev/null; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `\(.code)` from `\(.source_id)`: \(.detail)"' "$receipts_path"
  fi
  printf '\n## Remediation Commands\n'
  jq -r '.remediation_commands[] | "- \(. )"' "$receipts_path"
} >"$report_path"

write_event "cohort_diff_comparator" "diff_receipts_emitted" "$(jq -r '.decision' "$receipts_path")" "" "$receipts_path"
write_event "cohort_diff_comparator" "fingerprint_delta_plan_emitted" "$(jq -r '.decision' "$receipts_path")" "" "$delta_plan_path"

if [[ "$(jq -r '.decision' "$receipts_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
