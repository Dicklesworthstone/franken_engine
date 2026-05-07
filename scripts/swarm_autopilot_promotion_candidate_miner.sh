#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_PROMOTION_MINER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-promotion-miner}"
run_id="${SWARM_AUTOPILOT_PROMOTION_MINER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_PROMOTION_MINER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_PROMOTION_MINER_SOURCE_REVISION:-unknown}"
evidence_warehouse_json=""
hindsight_chaos_scenarios_json=""
minimum_evidence_count="2"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_promotion_candidate_miner.sh [OPTIONS]

Mine advisory-only promotion candidates from warehouse evidence and hindsight
chaos outcomes. The miner never mutates beads, reservations, Agent Mail,
workers, live queue policy, Cargo, or RCH.

Required inputs:
  --evidence-warehouse-json FILE
  --hindsight-chaos-scenarios-json FILE

Optional inputs:
  --minimum-evidence-count N
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_autopilot_promotion_candidates.json
  swarm_autopilot_promotion_candidate_receipts.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   candidates emitted; decision may be pass or degraded
  42  stale, contradictory, contaminated, or malformed evidence failed closed
  64  invalid command-line arguments
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
      shift 2
      ;;
    --hindsight-chaos-scenarios-json)
      hindsight_chaos_scenarios_json="${2:-}"
      shift 2
      ;;
    --minimum-evidence-count)
      minimum_evidence_count="${2:-}"
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

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

if [[ -z "$evidence_warehouse_json" || -z "$hindsight_chaos_scenarios_json" ]]; then
  printf 'evidence warehouse and hindsight chaos scenario JSON inputs are required\n' >&2
  usage
  exit 64
fi
if ! is_int "$minimum_evidence_count"; then
  printf 'minimum evidence count must be a non-negative integer\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the promotion candidate miner\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the promotion candidate miner\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
candidates_path="${run_dir}/swarm_autopilot_promotion_candidates.json"
candidates_tmp="${candidates_path}.tmp"
receipts_path="${run_dir}/swarm_autopilot_promotion_candidate_receipts.json"
receipts_tmp="${receipts_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
warehouse_normalized="${run_dir}/evidence_warehouse.normalized.json"
hindsight_normalized="${run_dir}/hindsight_chaos_scenarios.normalized.json"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

printf './scripts/swarm_autopilot_promotion_candidate_miner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-promotion-candidate.event.v1" \
    --arg trace_id "trace-swarm-autopilot-promotion-candidate-${run_id}" \
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
  write_event "promotion_candidate_miner" "fail_closed_reason_recorded" "fail_closed" "$1" "$2"
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

normalize_required_json "$evidence_warehouse_json" "$warehouse_normalized" "evidence_warehouse"
normalize_required_json "$hindsight_chaos_scenarios_json" "$hindsight_normalized" "hindsight_chaos_scenarios"

check_shape "$warehouse_normalized" '
  .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
  and ((.artifact_rows // null) | type == "array")
  and ((.artifact_rows | length) > 0)
  and all(.artifact_rows[]?; ((.source_id // "") | length) > 0 and ((.decision // "") | length) > 0 and ((.artifact_path // .raw_artifact_path // .source_path // "") | length) > 0)
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-PROMOTION-SCHEMA-DRIFT" "evidence_warehouse_json" \
  "warehouse rows lack source ids, decisions, artifact paths, or safety markers" \
  "Regenerate warehouse evidence before mining promotion candidates."

check_shape "$hindsight_normalized" '
  .schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-scenarios.v1"
  and ((.scenarios // null) | type == "array")
  and ((.scenarios | length) > 0)
  and all(.scenarios[]?; ((.scenario_id // "") | length) > 0 and ((.scenario_hash // "") | length) > 0 and ((.source_artifacts // null) | type == "object"))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-PROMOTION-SCHEMA-DRIFT" "hindsight_chaos_scenarios_json" \
  "hindsight scenario bundle lacks scenario ids, hashes, source artifacts, or safety markers" \
  "Regenerate hindsight chaos scenarios before mining promotion candidates."

if jq -e '([.source_freshness?, .artifact_rows[]?.freshness?, .fail_closed_reasons[]?.detail?] | map(tostring) | any(test("stale"; "i")))' "$warehouse_normalized" >/dev/null \
  || jq -e '([.source_freshness?, .scenarios[]?.freshness?, .fail_closed_reasons[]?.detail?] | map(tostring) | any(test("stale"; "i")))' "$hindsight_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-PROMOTION-STALE-HINDSIGHT" "source_material" \
    "warehouse or hindsight source material is stale" \
    "Refresh warehouse rows and hindsight scenarios before mining promotion candidates."
fi

if jq -e 'any(.artifact_rows[]?; ((.decision // "") + " " + (.failure_mode // "")) | test("contradict|blocked"; "i"))' "$warehouse_normalized" >/dev/null \
  || jq -e 'any(.scenarios[]?; ((.reason_codes // []) | map(tostring) | any(test("contradict|blocked"; "i"))))' "$hindsight_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-PROMOTION-CONTRADICTORY-HINDSIGHT" "source_material" \
    "contradictory warehouse or hindsight outcomes block promotion truth" \
    "Resolve contradictory outcomes before suggesting promotion candidates."
fi

if jq -e '((.fail_closed_reasons // []) | any(((.code // "") + " " + (.detail // "")) | test("LOCAL-FALLBACK|contaminated"; "i")))' "$warehouse_normalized" >/dev/null \
  || jq -e '(.decision == "fail_closed" and ((.fail_closed_reasons // []) | any((.code // "") | test("LOCAL-FALLBACK|CONTAMINATED"; "i")))) or any(.scenarios[]?; (.perturbation_type // "") | test("local_fallback|contaminated"; "i"))' "$hindsight_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-PROMOTION-CONTAMINATED" "source_material" \
    "contaminated hindsight or local fallback material cannot support promotion suggestions" \
    "Quarantine contaminated captures and mine only remote-truth outcomes."
fi

warehouse_count="$(jq '.artifact_rows | length' "$warehouse_normalized")"
hindsight_count="$(jq '.scenarios | length' "$hindsight_normalized")"
decision="pass"
truth_state="confirmed"
exit_code=0
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
elif (( warehouse_count < minimum_evidence_count || hindsight_count < minimum_evidence_count )); then
  decision="degraded"
  truth_state="insufficient_evidence"
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // "unknown"' "$warehouse_normalized")"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-promotion-candidates.v1" \
  --arg bead_id "bd-gra1z.3" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg candidates_path "$candidates_path" \
  --arg receipts_path "$receipts_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg evidence_warehouse_json "$evidence_warehouse_json" \
  --arg hindsight_chaos_scenarios_json "$hindsight_chaos_scenarios_json" \
  --argjson minimum_evidence_count "$minimum_evidence_count" \
  --slurpfile warehouse "$warehouse_normalized" \
  --slurpfile hindsight "$hindsight_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  def stable_id($prefix; $value): ($prefix + "-" + (($value // "unknown") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase));
  def band($score): if $score >= 800000 then "high" elif $score >= 600000 then "medium" else "low" end;
  ($warehouse[0]) as $w
  | ($hindsight[0]) as $h
  | ($fail_closed_reasons | unique_by([.code, .source_id, .detail])) as $failures
  | ($w.artifact_rows // []) as $rows
  | ($h.scenarios // []) as $scenarios
  | ([$rows[]? | select((.decision // "") == "pass") | .source_id] | unique) as $healthy_sources
  | ([$scenarios[]? | select(.replay_ready == true and ((.reason_codes // []) | index("stable_non_promotion") == null)) | .scenario_id] | unique) as $replayable_scenarios
  | ([$scenarios[]? | select((.reason_codes // []) | index("stable_non_promotion") != null) | .scenario_id] | unique) as $stable_non_promotions
  | (
      if $decision == "fail_closed" then []
      elif (($healthy_sources | length) >= $minimum_evidence_count and ($replayable_scenarios | length) >= $minimum_evidence_count) then [{
        candidate_id:"promotion-candidate-repeated-stable-advisory",
        candidate_type:"promotion_candidate",
        confidence_millionths:850000,
        confidence_band:band(850000),
        required_evidence_count:$minimum_evidence_count,
        observed_evidence_count:(($healthy_sources | length) + ($replayable_scenarios | length)),
        supporting_source_ids:$healthy_sources,
        supporting_scenarios:$replayable_scenarios,
        contradictory_outcome_reasons:[],
        source_artifact_paths:($w.artifact_paths // {}) + ($h.artifact_paths // {}),
        recommendation:"queue for human promotion review; do not promote automatically"
      }]
      elif (($stable_non_promotions | length) > 0) then [{
        candidate_id:"promotion-candidate-stable-non-promotion",
        candidate_type:"stable_non_promotion",
        confidence_millionths:650000,
        confidence_band:band(650000),
        required_evidence_count:$minimum_evidence_count,
        observed_evidence_count:($stable_non_promotions | length),
        supporting_source_ids:$healthy_sources,
        supporting_scenarios:$stable_non_promotions,
        contradictory_outcome_reasons:[],
        source_artifact_paths:($w.artifact_paths // {}) + ($h.artifact_paths // {}),
        recommendation:"preserve as stable non-promotion recommendation"
      }]
      else [{
        candidate_id:"promotion-candidate-insufficient-evidence",
        candidate_type:"degraded_insufficient_evidence",
        confidence_millionths:250000,
        confidence_band:"low",
        required_evidence_count:$minimum_evidence_count,
        observed_evidence_count:(($healthy_sources | length) + ($replayable_scenarios | length)),
        supporting_source_ids:$healthy_sources,
        supporting_scenarios:$replayable_scenarios,
        contradictory_outcome_reasons:["not enough repeated healthy warehouse rows and replayable hindsight scenarios"],
        source_artifact_paths:($w.artifact_paths // {}) + ($h.artifact_paths // {}),
        recommendation:"collect more warehouse and hindsight evidence before promotion review"
      }]
      end
    ) as $candidates
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$decision,
      truth_state:$truth_state,
      candidate_summary:{
        candidate_count:($candidates | length),
        promotion_candidate_count:($candidates | map(select(.candidate_type == "promotion_candidate")) | length),
        stable_non_promotion_count:($candidates | map(select(.candidate_type == "stable_non_promotion")) | length),
        degraded_insufficient_evidence_count:($candidates | map(select(.candidate_type == "degraded_insufficient_evidence")) | length),
        required_evidence_count:$minimum_evidence_count,
        warehouse_row_count:($rows | length),
        scenario_count:($scenarios | length)
      },
      candidates:$candidates,
      fail_closed_reasons:$failures,
      artifact_paths:{
        promotion_candidates_json:$candidates_path,
        promotion_candidate_receipts_json:$receipts_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        evidence_warehouse_json:$evidence_warehouse_json,
        hindsight_chaos_scenarios_json:$hindsight_chaos_scenarios_json
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
        promotes_candidates_automatically:false
      }
    }' >"$candidates_tmp"
mv "$candidates_tmp" "$candidates_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-promotion-candidate-receipts.v1" \
  --arg bead_id "bd-gra1z.3" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg receipts_path "$receipts_path" \
  --arg candidates_path "$candidates_path" \
  --slurpfile candidates "$candidates_path" '
  ($candidates[0]) as $doc
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$decision,
      receipts:($doc.candidates | map({
        receipt_id:("receipt-" + .candidate_id),
        candidate_id,
        candidate_type,
        confidence_band,
        required_evidence_count,
        observed_evidence_count,
        supporting_source_ids,
        supporting_scenarios,
        contradictory_outcome_reasons,
        recommendation
      })),
      fail_closed_reasons:$doc.fail_closed_reasons,
      artifact_paths:{
        promotion_candidate_receipts_json:$receipts_path,
        promotion_candidates_json:$candidates_path
      },
      mutation_policy:$doc.mutation_policy
    }' >"$receipts_tmp"
mv "$receipts_tmp" "$receipts_path"

{
  printf '# SWARM_AUTOPILOT_PROMOTION_CANDIDATE_MINER\n\n'
  printf -- "- decision: \`%s\`\n" "$(jq -r '.decision' "$candidates_path")"
  printf -- "- candidate_count: \`%s\`\n" "$(jq -r '.candidate_summary.candidate_count' "$candidates_path")"
  printf '\n## Candidates\n'
  jq -r '.candidates[]? | "- `\(.candidate_id)` type=`\(.candidate_type)` confidence=`\(.confidence_band)`"' "$candidates_path"
  if jq -e '.fail_closed_reasons | length > 0' "$candidates_path" >/dev/null; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `\(.code)` from `\(.source_id)`: \(.detail)"' "$candidates_path"
  fi
} >"$report_path"

write_event "promotion_candidate_miner" "promotion_candidates_emitted" "$decision" "" "$candidates_path"
write_event "promotion_candidate_miner" "promotion_candidate_receipts_emitted" "$decision" "" "$receipts_path"

exit "$exit_code"
