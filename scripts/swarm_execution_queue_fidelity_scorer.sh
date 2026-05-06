#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_FIDELITY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-fidelity}"
run_id="${SWARM_EXECUTION_QUEUE_FIDELITY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_FIDELITY_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

hindsight_report_json=""
hindsight_input_json=""
evidence_ledger_json=""
counterfactual_candidates_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_fidelity_scorer.sh \
  --hindsight-report-json FILE \
  --hindsight-input-json FILE \
  --evidence-ledger-json FILE \
  --counterfactual-candidates-json FILE \
  [OPTIONS]

Scores SWARM-CTRL-XIII hindsight rows against the original queue advice and
emits a deterministic drift ledger. This scorer is advisory-only: it does not
update beads, reopen work, rewrite historical outcomes, send Agent Mail, run
Cargo, mutate workers, or change the active queue.

Artifacts:
  fidelity_score_receipt.json
  drift_ledger.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  scoring completed; decision may be pass or degraded
  42 fail-closed due to malformed hindsight artifacts or contradictory evidence
  64 usage or missing tool/file errors
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --hindsight-report-json)
      hindsight_report_json="${2:-}"
      shift 2
      ;;
    --hindsight-input-json)
      hindsight_input_json="${2:-}"
      shift 2
      ;;
    --evidence-ledger-json)
      evidence_ledger_json="${2:-}"
      shift 2
      ;;
    --counterfactual-candidates-json)
      counterfactual_candidates_json="${2:-}"
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

for path in "$hindsight_report_json" "$hindsight_input_json" "$evidence_ledger_json" "$counterfactual_candidates_json"; do
  if [[ -z "$path" ]]; then
    printf 'all required fidelity scorer JSON inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm execution queue fidelity scoring\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm execution queue fidelity scoring\n' >&2
  exit 64
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
receipt_path="${run_dir}/fidelity_score_receipt.json"
drift_ledger_path="${run_dir}/drift_ledger.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
bundle_path="${run_dir}/fidelity_bundle.core.json"

hindsight_report_normalized="${run_dir}/hindsight_report.normalized.json"
hindsight_input_normalized="${run_dir}/hindsight_input.normalized.json"
evidence_ledger_normalized="${run_dir}/evidence_ledger.normalized.json"
counterfactual_candidates_normalized="${run_dir}/counterfactual_candidates.normalized.json"

printf './scripts/swarm_execution_queue_fidelity_scorer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-fidelity.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

json_input() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'required fidelity scorer input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required fidelity scorer input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$hindsight_report_json" "$hindsight_report_normalized" "hindsight_report_json"
json_input "$hindsight_input_json" "$hindsight_input_normalized" "hindsight_input_json"
json_input "$evidence_ledger_json" "$evidence_ledger_normalized" "evidence_ledger_json"
json_input "$counterfactual_candidates_json" "$counterfactual_candidates_normalized" "counterfactual_candidates_json"

jq -n \
  --arg source_revision "$source_revision" \
  --arg receipt_path "$receipt_path" \
  --arg drift_ledger_path "$drift_ledger_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile hindsight_report "$hindsight_report_normalized" \
  --slurpfile hindsight_input "$hindsight_input_normalized" \
  --slurpfile evidence_ledger "$evidence_ledger_normalized" \
  --slurpfile candidates_doc "$counterfactual_candidates_normalized" '
    def id_of:
      if type == "object" then (.task_id // .bead_id // .id // "") else "" end | tostring;

    def duplicates($rows):
      [$rows[]? | id_of | select(length > 0)]
      | sort
      | group_by(.)
      | map(select(length > 1) | .[0]);

    def bounded($n):
      if $n < 0 then 0 elif $n > 1000000 then 1000000 else $n end;

    def avg_millionths($values):
      if ($values | length) == 0 then 0
      else ((($values | add) / ($values | length)) | floor)
      end;

    def row_score($row):
      if ($row.fidelity_class // "") == "matched" and ($row.drift_class // "") == "none" then 1000000
      elif ($row.fidelity_class // "") == "justified_override" then 820000
      elif ($row.fidelity_class // "") == "delayed_match" then 760000
      elif ($row.drift_class // "") == "proof_drift" then 480000
      elif ($row.drift_class // "") == "ownership_drift" then 420000
      elif ($row.fidelity_class // "") == "insufficient_evidence" then 320000
      elif ($row.fidelity_class // "") == "unsafe_to_score" then 0
      else 220000
      end;

    def mismatch_class($row):
      (($row.recommended_first_action // "") | tostring | ascii_downcase) as $action
      | (($row.actual_outcome // "") | tostring) as $actual
      | if (($row.owner_identity.inconsistent // false) == true) or (($row.reservation_holders // []) | length) > 1 then "contradictory_evidence"
        elif ($row.proof_outcome // "" | test("brownout|degraded|failed|unavailable")) then "proof_brownout_miss"
        elif ($row.owner_friction_outcome // "" | test("stale|contact|friction")) then "stale_owner_miss"
        elif ($action | test("defer|conservative|brownout")) and ($actual == "closed" or $actual == "started") then "over_conservative"
        elif ($row.fidelity_class // "") == "justified_override" then "conservative_but_correct"
        elif ($row.fidelity_class // "") == "insufficient_evidence" then "missing_outcome"
        elif (($row.rank_delta // 0) != 0) then "ranking_drift"
        elif (($row.actual_start_delta_seconds // 0) > 3600) then "timing_drift"
        elif ($row.fidelity_class // "") == "matched" and ($row.drift_class // "") == "none" then "exact_match"
        else "unclassified_drift"
        end;

    def remediation($class):
      if $class == "exact_match" then "keep current queue weights for this evidence shape"
      elif $class == "conservative_but_correct" then "preserve conservative fallback and keep restore/proof evidence visible"
      elif $class == "over_conservative" then "lower conservative-mode penalty in counterfactual replay before changing policy"
      elif $class == "stale_owner_miss" then "increase owner-friction weight and require contact recency evidence"
      elif $class == "proof_brownout_miss" then "increase proof-health penalty and reject local fallback proof evidence"
      elif $class == "missing_outcome" then "require stronger aftermath capture before scoring this row"
      elif $class == "contradictory_evidence" then "fail closed and reconcile owner or reservation evidence"
      elif $class == "ranking_drift" then "replay ranking weights against hindsight inputs"
      elif $class == "timing_drift" then "adjust start-order timing tolerance in replay"
      else "inspect hindsight row before trusting aggregate score"
      end;

    def confidence($score):
      if $score >= 900000 then "high"
      elif $score >= 650000 then "medium"
      elif $score >= 350000 then "low"
      else "insufficient_evidence"
      end;

    ($hindsight_report[0]) as $report
    | ($hindsight_input[0]) as $input
    | ($evidence_ledger[0]) as $ledger
    | ($candidates_doc[0]) as $candidates
    | (($report.rows // []) | if type == "array" then . else [] end) as $rows
    | (($input.queue_task_ids // []) | if type == "array" then . else [] end) as $queue_ids
    | ($rows | map(
        mismatch_class(.) as $class
        | row_score(.) as $score
        | {
            task_id: .task_id,
            recommended_rank: .recommended_rank,
            actual_outcome: .actual_outcome,
            fidelity_class: .fidelity_class,
            drift_class: .drift_class,
            mismatch_class: $class,
            row_score_millionths: $score,
            confidence_band: confidence($score),
            remediation: remediation($class),
            source_row: .
          }
      )) as $ledger_rows
    | (
        (if ($report.schema_version // "") != "franken-engine.swarm-execution-queue-hindsight-report.v1" then [{kind:"bad_schema",source:"hindsight_report_json",label:"schema_version",detail:"unexpected hindsight report schema"}] else [] end)
        + (if ($input.schema_version // "") != "franken-engine.swarm-execution-queue-hindsight-input.v1" then [{kind:"bad_schema",source:"hindsight_input_json",label:"schema_version",detail:"unexpected hindsight input schema"}] else [] end)
        + (if ($ledger.schema_version // "") != "franken-engine.swarm-execution-queue-hindsight-evidence-ledger.v1" then [{kind:"bad_schema",source:"evidence_ledger_json",label:"schema_version",detail:"unexpected evidence ledger schema"}] else [] end)
        + (if (($report.decision // "") == "fail_closed") then [{kind:"upstream_fail_closed",source:"hindsight_report_json",label:"decision",detail:"upstream hindsight report already failed closed"}] else [] end)
        + (($report.fail_closed_reasons // []) | map({kind:"upstream_fail_closed_reason",source:(.source // "hindsight_report_json"),label:(.label // "unknown"),detail:(.detail // .kind // "upstream fail-closed reason")}))
        + (duplicates($rows) | map({kind:"duplicate_task_id",source:"hindsight_report_json",label:.,detail:"hindsight report repeats task_id"}))
        + ([$rows[]? | select((.task_id // "") as $id | ($queue_ids | index($id)) == null) | {kind:"unknown_task_reference",source:"hindsight_report_json",label:(.task_id // "unknown"),detail:"scored row is absent from hindsight input queue_task_ids"}])
        + ([$rows[]? | select(((.recommended_first_action // "") | tostring | length) == 0) | {kind:"missing_first_action",source:"hindsight_report_json",label:(.task_id // "unknown"),detail:"hindsight row lacks recommended_first_action"}])
        + ([$rows[]? | select((.owner_identity.inconsistent // false) == true) | {kind:"contradictory_owner_evidence",source:"hindsight_report_json",label:.task_id,detail:"owner identity evidence is contradictory"}])
        + ([$rows[]? | select(((.reservation_holders // []) | length) > 1) | {kind:"contradictory_reservation_evidence",source:"hindsight_report_json",label:.task_id,detail:"reservation holder evidence is contradictory"}])
        + ([($ledger.rows // [])[]? | select((.trust_state // "") == "rejected" or (.freshness_state // "") == "stale") | {kind:"untrusted_evidence",source:"evidence_ledger_json",label:(.source_id // .artifact_id // "unknown"),detail:"evidence ledger contains rejected or stale required evidence"}])
      ) as $fail_closed_reasons
    | ([$ledger_rows[]? | select(.mismatch_class != "exact_match") | {kind:.mismatch_class,source:"drift_ledger",label:.task_id,detail:.remediation}]) as $degraded_inputs
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($degraded_inputs | length) > 0 then "degraded"
       else "pass"
       end) as $decision
    | ([ $ledger_rows[]? | .row_score_millionths ]) as $row_scores
    | (avg_millionths($row_scores)) as $overall
    | ([$ledger_rows[]? | select(.recommended_rank != null and (.source_row.rank_delta // 0) == 0)] | length) as $rank_matches
    | ([$ledger_rows[]? | select(.source_row.actual_outcome == "deferred" or .source_row.actual_outcome == "blocked")] | length) as $deferred_rows
    | ([$ledger_rows[]? | select(.source_row.proof_outcome | test("brownout|degraded|failed|unavailable"))] | length) as $proof_bad_rows
    | {
        drift_ledger: {
          schema_version: "franken-engine.swarm-execution-queue-drift-ledger.v1",
          source_revision: $source_revision,
          decision: $decision,
          rows: $ledger_rows,
          fail_closed_reasons: $fail_closed_reasons,
          degraded_inputs: $degraded_inputs
        },
        fidelity_score_receipt: {
          schema_version: "franken-engine.swarm-execution-queue-fidelity-score-receipt.v1",
          source_revision: $source_revision,
          decision: $decision,
          overall_fidelity_millionths: $overall,
          confidence_band: confidence($overall),
          component_scores: {
            start_order_agreement_millionths: (if ($ledger_rows | length) == 0 then 0 else (($rank_matches * 1000000 / ($ledger_rows | length)) | floor | bounded(.)) end),
            defer_correctness_millionths: (if $deferred_rows == 0 then 1000000 else ([$ledger_rows[]? | select(.source_row.actual_outcome == "deferred" or .source_row.actual_outcome == "blocked") | if .mismatch_class == "conservative_but_correct" then 1000000 else 300000 end] | avg_millionths(.)) end),
            proof_health_prediction_millionths: (if $proof_bad_rows == 0 then 1000000 else ([$ledger_rows[]? | select(.source_row.proof_outcome | test("brownout|degraded|failed|unavailable")) | .row_score_millionths] | avg_millionths(.)) end),
            owner_friction_prediction_millionths: (avg_millionths([$ledger_rows[]? | if .mismatch_class == "stale_owner_miss" then 420000 elif .mismatch_class == "exact_match" then 1000000 else 700000 end])),
            conservative_mode_appropriateness_millionths: (avg_millionths([$ledger_rows[]? | if .mismatch_class == "conservative_but_correct" then 900000 elif .mismatch_class == "over_conservative" then 360000 else 800000 end]))
          },
          summary: {
            row_count: ($ledger_rows | length),
            exact_match_count: ([$ledger_rows[]? | select(.mismatch_class == "exact_match")] | length),
            conservative_but_correct_count: ([$ledger_rows[]? | select(.mismatch_class == "conservative_but_correct")] | length),
            over_conservative_count: ([$ledger_rows[]? | select(.mismatch_class == "over_conservative")] | length),
            stale_owner_miss_count: ([$ledger_rows[]? | select(.mismatch_class == "stale_owner_miss")] | length),
            proof_brownout_miss_count: ([$ledger_rows[]? | select(.mismatch_class == "proof_brownout_miss")] | length),
            counterfactual_candidate_count: (($candidates.candidates // []) | length),
            fail_closed_reason_count: ($fail_closed_reasons | length),
            degraded_input_count: ($degraded_inputs | length)
          },
          artifact_paths: {
            fidelity_score_receipt_json: $receipt_path,
            drift_ledger_json: $drift_ledger_path,
            events_jsonl: $events_path,
            commands_txt: $commands_path,
            report_md: $report_path
          }
        }
      }
  ' >"$bundle_path"

jq '.drift_ledger' "$bundle_path" >"$drift_ledger_path"
jq '.fidelity_score_receipt' "$bundle_path" >"$receipt_path"

receipt_id="swarm-execution-queue-fidelity-$(jq -cS 'del(.artifact_paths)' "$receipt_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_receipt="${receipt_path}.tmp"
jq --arg receipt_id "$receipt_id" '. + {receipt_id:$receipt_id}' "$receipt_path" >"$tmp_receipt"
mv "$tmp_receipt" "$receipt_path"

write_event "fidelity_score.written" "$(jq -r '.decision + " / rows=" + (.summary.row_count | tostring)' "$receipt_path")"

{
  printf '# Swarm Execution Queue Fidelity Score\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$receipt_path")"
  printf -- "- Overall fidelity: \`%s\`\n" "$(jq '.overall_fidelity_millionths' "$receipt_path")"
  printf -- "- Confidence: \`%s\`\n" "$(jq -r '.confidence_band' "$receipt_path")"
  printf -- "- Rows: \`%s\`\n" "$(jq '.summary.row_count' "$receipt_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n" "$(jq '.summary.fail_closed_reason_count' "$receipt_path")"
  printf -- "- Degraded inputs: \`%s\`\n\n" "$(jq '.summary.degraded_input_count' "$receipt_path")"

  if [[ "$(jq '.fail_closed_reasons | length' "$drift_ledger_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$drift_ledger_path"
    printf '\n'
  fi

  printf '## Drift Ledger\n'
  jq -r '.rows[] | "- `" + .task_id + "` `" + .mismatch_class + "` `" + (.row_score_millionths | tostring) + "`: " + .remediation' "$drift_ledger_path"
} >"$report_path"

printf 'fidelity_score_receipt_json=%s\n' "$receipt_path"
printf 'drift_ledger_json=%s\n' "$drift_ledger_path"
printf 'fidelity_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$receipt_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
