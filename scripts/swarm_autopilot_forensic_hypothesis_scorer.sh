#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_HYPOTHESIS_SCORER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-forensic-hypothesis}"
run_id="${SWARM_AUTOPILOT_HYPOTHESIS_SCORER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_HYPOTHESIS_SCORER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_HYPOTHESIS_SCORER_SOURCE_REVISION:-unknown}"
cohort_diff_receipts_json=""
evidence_warehouse_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_forensic_hypothesis_scorer.sh [OPTIONS]

Rank bounded forensic hypotheses from cohort diff receipts and warehouse rows.
The scorer is advisory only and proof only. It never mutates beads,
reservations, Agent Mail, workers, live queue policy, Cargo, or RCH.

Required inputs:
  --cohort-diff-receipts-json FILE
  --evidence-warehouse-json FILE

Optional inputs:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_autopilot_forensic_hypothesis_summary.json
  swarm_autopilot_forensic_hypothesis_evidence.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   hypotheses emitted; decision may be pass or degraded
  42  stale, contradictory, or contaminated evidence failed closed
  64  invalid command-line arguments
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --cohort-diff-receipts-json)
      cohort_diff_receipts_json="${2:-}"
      shift 2
      ;;
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
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

if [[ -z "$cohort_diff_receipts_json" || -z "$evidence_warehouse_json" ]]; then
  printf 'cohort diff receipts and evidence warehouse JSON inputs are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the forensic hypothesis scorer\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
summary_path="${run_dir}/swarm_autopilot_forensic_hypothesis_summary.json"
summary_tmp="${summary_path}.tmp"
evidence_path="${run_dir}/swarm_autopilot_forensic_hypothesis_evidence.json"
evidence_tmp="${evidence_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
diff_normalized="${run_dir}/cohort_diff_receipts.normalized.json"
warehouse_normalized="${run_dir}/evidence_warehouse.normalized.json"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

printf './scripts/swarm_autopilot_forensic_hypothesis_scorer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-forensic-hypothesis.event.v1" \
    --arg trace_id "trace-swarm-autopilot-forensic-hypothesis-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    --arg evidence_path "$5" \
    '{schema_version:$schema_version,trace_id:$trace_id,component:$component,event:$event,outcome:$outcome,error_code:(if $error_code == "" then null else $error_code end),evidence_path:$evidence_path}' \
    >>"$events_path"
}

append_failure() {
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    --arg remediation_command "$4" \
    '{code:$code,source_id:$source_id,detail:$detail,remediation_command:$remediation_command}' \
    >>"$fail_closed_reasons_jsonl"
  write_event "forensic_hypothesis_scorer" "fail_closed_reason_recorded" "fail_closed" "$1" "$2"
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
normalize_required_json "$evidence_warehouse_json" "$warehouse_normalized" "evidence_warehouse"

check_shape "$diff_normalized" '
  .schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipts.v1"
  and ((.cohort_diff_receipts // null) | type == "array")
  and ((.cohort_diff_receipts | length) > 0)
  and all(.cohort_diff_receipts[]?; ((.receipt_id // "") | length) > 0 and ((.source_ids // null) | type == "array"))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-HYPOTHESIS-SCHEMA-DRIFT" "cohort_diff_receipts_json" \
  "cohort diff receipts lack required receipts, source ids, or safety markers" \
  "Regenerate cohort diff receipts before scoring forensic hypotheses."

check_shape "$warehouse_normalized" '
  .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
  and ((.artifact_rows // null) | type == "array")
  and ((.artifact_rows | length) > 0)
  and all(.artifact_rows[]?; ((.source_id // "") | length) > 0 and ((.decision // "") | length) > 0)
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-HYPOTHESIS-SCHEMA-DRIFT" "evidence_warehouse_json" \
  "warehouse rows lack source ids, decisions, or safety markers" \
  "Regenerate the evidence warehouse before scoring forensic hypotheses."

if jq -e '
  (.decision == "fail_closed" and ((.fail_closed_reasons // []) | any((.code // "") | test("STALE"; "i"))))
  or ([.freshness?, .cohort_diff_receipts[]?.freshness?, .cohort_diff_receipts[]?.reason_codes[]?] | map(tostring) | any(test("stale"; "i")))
' "$diff_normalized" >/dev/null \
  || jq -e '([.source_freshness?, .artifact_rows[]?.freshness?, .fail_closed_reasons[]?.detail?] | map(tostring) | any(test("stale"; "i")))' "$warehouse_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-HYPOTHESIS-STALE-EVIDENCE" "source_material" \
    "diff receipts or warehouse rows contain stale evidence" \
    "Refresh diff receipts and warehouse rows before scoring hypotheses."
fi

if jq -e '
  any(.cohort_diff_receipts[]?; (.classification_transition | test("contaminated$")) or (.remote_truth_valid == false))
' "$diff_normalized" >/dev/null \
  || jq -e '((.fail_closed_reasons // []) | any(((.code // "") + " " + (.detail // "")) | test("LOCAL-FALLBACK|contaminated"; "i")))' "$warehouse_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-HYPOTHESIS-CONTAMINATED-EVIDENCE" "source_material" \
    "contaminated evidence cannot support promoted forensic hypotheses" \
    "Quarantine contaminated evidence and score only remote-truth material."
fi

if jq -e '
  any(.cohort_diff_receipts[]?; ((.reason_codes // []) | any(test("contradict"; "i"))))
' "$diff_normalized" >/dev/null \
  || jq -e 'any(.artifact_rows[]?; ((.failure_mode // "") + " " + (.decision // "")) | test("contradict"; "i"))' "$warehouse_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-HYPOTHESIS-CONTRADICTORY-EVIDENCE" "source_material" \
    "contradictory locality or warehouse evidence prevents trustworthy hypothesis ranking" \
    "Resolve contradictory evidence before scoring forensic hypotheses."
fi

decision="pass"
truth_state="confirmed"
exit_code=0
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
elif jq -e 'all(.cohort_diff_receipts[]?; ((.topology_deltas // []) | length) == 0 and ((.toolchain_deltas // []) | length) == 0 and ((.worker_deltas // []) | length) == 0 and ((.changed_fingerprints // []) | length) == 0)' "$diff_normalized" >/dev/null; then
  decision="degraded"
  truth_state="low_evidence"
elif jq -e '.decision == "degraded"' "$diff_normalized" >/dev/null; then
  truth_state="degraded"
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // "unknown"' "$diff_normalized")"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-forensic-hypothesis-summary.v1" \
  --arg bead_id "bd-00ofm.4" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg summary_path "$summary_path" \
  --arg evidence_path "$evidence_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg cohort_diff_receipts_json "$cohort_diff_receipts_json" \
  --arg evidence_warehouse_json "$evidence_warehouse_json" \
  --slurpfile diff "$diff_normalized" \
  --slurpfile warehouse "$warehouse_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  def stable_id($prefix; $value): ($prefix + "-" + (($value // "unknown") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase));
  def band($score): if $score >= 800000 then "high" elif $score >= 600000 then "medium" else "low" end;
  ($diff[0]) as $d
  | ($warehouse[0]) as $w
  | ($fail_closed_reasons | unique_by([.code, .source_id, .detail])) as $failures
  | ($d.cohort_diff_receipts // []) as $receipts
  | (
      [
        ($receipts[]? | select(((.topology_deltas // []) | length) > 0) | {
          hypothesis_id: stable_id("hypothesis"; .receipt_id + "-topology-drift"),
          pivot:"topology_drift",
          confidence_millionths:850000,
          confidence_band:band(850000),
          supporting_source_ids:(.source_ids // []),
          supporting_receipts:[.receipt_id],
          counterevidence:[],
          rationale:"Topology class changed between reference and comparison cohort.",
          remediation_suggestion:"Replay topology-sensitive counterexamples before changing queue policy."
        }),
        ($receipts[]? | select(((.toolchain_deltas // []) | length) > 0) | {
          hypothesis_id: stable_id("hypothesis"; .receipt_id + "-toolchain-skew"),
          pivot:"toolchain_skew",
          confidence_millionths:760000,
          confidence_band:band(760000),
          supporting_source_ids:(.source_ids // []),
          supporting_receipts:[.receipt_id],
          counterevidence:[],
          rationale:"Toolchain target changed between reference and comparison cohort.",
          remediation_suggestion:"Replay with pinned toolchain before promoting diagnosis."
        }),
        ($receipts[]? | select(((.worker_deltas // []) | length) > 0) | {
          hypothesis_id: stable_id("hypothesis"; .receipt_id + "-worker-locality"),
          pivot:"worker_locality_shift",
          confidence_millionths:700000,
          confidence_band:band(700000),
          supporting_source_ids:(.source_ids // []),
          supporting_receipts:[.receipt_id],
          counterevidence:[],
          rationale:"Worker placement changed between reference and comparison cohort.",
          remediation_suggestion:"Inspect worker locality and stale-progress evidence before reranking."
        }),
        ($receipts[]? | select(((.changed_fingerprints // []) | length) > 0) | {
          hypothesis_id: stable_id("hypothesis"; .receipt_id + "-fingerprint-delta"),
          pivot:"evidence_fingerprint_delta",
          confidence_millionths:650000,
          confidence_band:band(650000),
          supporting_source_ids:(.changed_fingerprints // []),
          supporting_receipts:[.receipt_id],
          counterevidence:[],
          rationale:"Replay evidence fingerprints changed between cohorts.",
          remediation_suggestion:"Compare raw artifacts for changed fingerprints before replay approval."
        })
      ] | flatten
    ) as $ranked
  | (if (($ranked | length) == 0 and $decision != "fail_closed") then [{
      hypothesis_id:"hypothesis-insufficient-evidence",
      pivot:"insufficient_evidence",
      confidence_millionths:250000,
      confidence_band:"low",
      supporting_source_ids:($receipts | map(.source_ids // []) | flatten | unique),
      supporting_receipts:($receipts | map(.receipt_id)),
      counterevidence:["no topology, toolchain, worker, or fingerprint deltas were present"],
      rationale:"Available diff receipts are coherent but too sparse for a strong causal claim.",
      remediation_suggestion:"Collect richer cohort diffs or warehouse rows before ranking root-cause pivots."
    }] else $ranked end) as $hypotheses
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$decision,
      truth_state:$truth_state,
      hypothesis_summary:{
        hypothesis_count:($hypotheses | length),
        promoted_count:(if $decision == "fail_closed" then 0 else ($hypotheses | map(select(.pivot != "insufficient_evidence")) | length) end),
        low_evidence_count:($hypotheses | map(select(.pivot == "insufficient_evidence")) | length),
        topology_drift_count:($hypotheses | map(select(.pivot == "topology_drift")) | length),
        toolchain_skew_count:($hypotheses | map(select(.pivot == "toolchain_skew")) | length),
        worker_locality_shift_count:($hypotheses | map(select(.pivot == "worker_locality_shift")) | length)
      },
      hypotheses:(if $decision == "fail_closed" then [] else ($hypotheses | sort_by(-.confidence_millionths, .pivot)) end),
      suppressed_hypotheses:(if $decision == "fail_closed" then $hypotheses else [] end),
      fail_closed_reasons:$failures,
      artifact_paths:{
        hypothesis_summary_json:$summary_path,
        hypothesis_evidence_json:$evidence_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        cohort_diff_receipts_json:$cohort_diff_receipts_json,
        evidence_warehouse_json:$evidence_warehouse_json
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
        promotes_hypotheses_automatically:false
      }
    }' >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-forensic-hypothesis-evidence.v1" \
  --arg bead_id "bd-00ofm.4" \
  --arg source_revision "$source_revision" \
  --slurpfile summary "$summary_path" \
  --slurpfile diff "$diff_normalized" \
  --slurpfile warehouse "$warehouse_normalized" \
  '($summary[0]) as $s | {schema_version:$schema_version,bead_id:$bead_id,source_revision:$source_revision,decision:$s.decision,hypotheses:$s.hypotheses,suppressed_hypotheses:$s.suppressed_hypotheses,source_receipts:$diff[0].cohort_diff_receipts,warehouse_rows:$warehouse[0].artifact_rows,fail_closed_reasons:$s.fail_closed_reasons,mutation_policy:$s.mutation_policy}' \
  >"$evidence_tmp"
mv "$evidence_tmp" "$evidence_path"

{
  printf '# SWARM_AUTOPILOT_FORENSIC_HYPOTHESIS_SCORER\n\n'
  printf -- "- decision: \`%s\`\n" "$(jq -r '.decision' "$summary_path")"
  printf -- "- hypothesis_count: \`%s\`\n" "$(jq -r '.hypothesis_summary.hypothesis_count' "$summary_path")"
  printf '\n## Hypotheses\n'
  jq -r '.hypotheses[]? | "- `\(.hypothesis_id)` pivot=`\(.pivot)` confidence=`\(.confidence_band)`"' "$summary_path"
  if jq -e '.fail_closed_reasons | length > 0' "$summary_path" >/dev/null; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `\(.code)` from `\(.source_id)`: \(.detail)"' "$summary_path"
  fi
} >"$report_path"

write_event "forensic_hypothesis_scorer" "hypothesis_summary_emitted" "$decision" "" "$summary_path"
write_event "forensic_hypothesis_scorer" "hypothesis_evidence_emitted" "$decision" "" "$evidence_path"

exit "$exit_code"
