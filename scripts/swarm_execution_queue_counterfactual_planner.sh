#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-counterfactual}"
run_id="${SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fidelity_score_receipt_json=""
drift_ledger_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_counterfactual_planner.sh \
  --fidelity-score-receipt-json FILE \
  --drift-ledger-json FILE \
  [OPTIONS]

Builds an advisory-only counterfactual queue backtest and tuning plan from the
SWARM-CTRL-XIII fidelity receipt and drift ledger. It does not update beads,
change live queue weights, rewrite historical outcomes, send Agent Mail, run
Cargo, mutate workers, or apply retuning automatically.

Artifacts:
  counterfactual_backtest_report.json
  tuning_plan.json
  frontier.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  planner completed; decision may be pass or degraded
  42 fail-closed due to incomplete evidence or automatic live-retuning claims
  64 usage or missing tool/file errors
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fidelity-score-receipt-json)
      fidelity_score_receipt_json="${2:-}"
      shift 2
      ;;
    --drift-ledger-json)
      drift_ledger_json="${2:-}"
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

if [[ -z "$fidelity_score_receipt_json" || -z "$drift_ledger_json" ]]; then
  printf 'fidelity receipt and drift ledger are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for counterfactual queue planning\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for counterfactual queue planning\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
backtest_report_path="${run_dir}/counterfactual_backtest_report.json"
tuning_plan_path="${run_dir}/tuning_plan.json"
frontier_path="${run_dir}/frontier.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
bundle_path="${run_dir}/counterfactual_bundle.core.json"
receipt_normalized="${run_dir}/fidelity_score_receipt.normalized.json"
ledger_normalized="${run_dir}/drift_ledger.normalized.json"

printf './scripts/swarm_execution_queue_counterfactual_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-counterfactual.event.v1" \
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
    printf 'required counterfactual planner input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required counterfactual planner input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$fidelity_score_receipt_json" "$receipt_normalized" "fidelity_score_receipt_json"
json_input "$drift_ledger_json" "$ledger_normalized" "drift_ledger_json"

jq -n \
  --arg source_revision "$source_revision" \
  --arg backtest_report_path "$backtest_report_path" \
  --arg tuning_plan_path "$tuning_plan_path" \
  --arg frontier_path "$frontier_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile receipt "$receipt_normalized" \
  --slurpfile ledger "$ledger_normalized" '
    def bounded($n): if $n < -1000000 then -1000000 elif $n > 1000000 then 1000000 else $n end;
    def count_class($rows; $class): [$rows[]? | select(.mismatch_class == $class)] | length;
    def confidence($delta; $evidence):
      if $evidence == "insufficient" then "insufficient_evidence"
      elif $delta >= 180000 then "high"
      elif $delta > 0 then "medium"
      else "low"
      end;
    def safety($delta; $manual):
      if $manual then "manual_review"
      elif $delta > 0 then "safe_to_replay"
      elif $delta == 0 then "no_change"
      else "unsafe"
      end;

    ($receipt[0]) as $receipt_doc
    | ($ledger[0]) as $ledger_doc
    | (($ledger_doc.rows // []) | if type == "array" then . else [] end) as $rows
    | (count_class($rows; "over_conservative")) as $over
    | (count_class($rows; "stale_owner_miss")) as $owner
    | (count_class($rows; "proof_brownout_miss")) as $proof
    | (count_class($rows; "missing_outcome")) as $missing
    | (count_class($rows; "conservative_but_correct")) as $conservative_ok
    | (count_class($rows; "exact_match")) as $exact
    | (
        (if ($receipt_doc.schema_version // "") != "franken-engine.swarm-execution-queue-fidelity-score-receipt.v1" then [{kind:"bad_schema",source:"fidelity_score_receipt_json",label:"schema_version",detail:"unexpected fidelity receipt schema"}] else [] end)
        + (if ($ledger_doc.schema_version // "") != "franken-engine.swarm-execution-queue-drift-ledger.v1" then [{kind:"bad_schema",source:"drift_ledger_json",label:"schema_version",detail:"unexpected drift ledger schema"}] else [] end)
        + (if (($receipt_doc.decision // "") == "fail_closed" or ($ledger_doc.decision // "") == "fail_closed") then [{kind:"upstream_fail_closed",source:"fidelity_score_receipt_json",label:"decision",detail:"upstream fidelity score already failed closed"}] else [] end)
        + (($ledger_doc.fail_closed_reasons // []) | map({kind:"upstream_fail_closed_reason",source:(.source // "drift_ledger_json"),label:(.label // "unknown"),detail:(.detail // .kind // "upstream fail-closed reason")}))
        + (if ($rows | length) == 0 then [{kind:"empty_drift_ledger",source:"drift_ledger_json",label:"rows",detail:"drift ledger has no rows to backtest"}] else [] end)
        + ([$rows[]? | select(((.task_id // "") | length) == 0 or ((.mismatch_class // "") | length) == 0 or ((.row_score_millionths // null) == null)) | {kind:"incomplete_candidate_field",source:"drift_ledger_json",label:(.task_id // "unknown"),detail:"counterfactual candidate depends on missing row fields"}])
        + ([$rows[]? | select((.source_row.auto_apply // false) == true or (.source_row.live_retuning // false) == true) | {kind:"automatic_live_retuning_claim",source:"drift_ledger_json",label:.task_id,detail:"planner input claims live retuning can be automatic"}])
      ) as $fail_closed_reasons
    | [
        {
          candidate_id:"baseline_current",
          description:"Keep current queue settings",
          impact_weight_delta:0,
          reuse_weight_delta:0,
          friction_weight_delta:0,
          risk_weight_delta:0,
          expected_fidelity_delta_millionths:0,
          improves_scenarios:["exact_match"],
          worsens_scenarios:[],
          manual_review_required:false
        },
        {
          candidate_id:"lower_conservative_penalty",
          description:"Replay with a lower conservative-mode penalty for over-conservative closes",
          impact_weight_delta:80000,
          reuse_weight_delta:0,
          friction_weight_delta:-40000,
          risk_weight_delta:-60000,
          expected_fidelity_delta_millionths:(($over * 220000) - ($conservative_ok * 90000) | bounded(.)),
          improves_scenarios:(if $over > 0 then ["over_conservative"] else [] end),
          worsens_scenarios:(if $conservative_ok > 0 then ["conservative_but_correct"] else [] end),
          manual_review_required:($conservative_ok > 0)
        },
        {
          candidate_id:"raise_owner_friction_penalty",
          description:"Replay with stronger owner-friction weighting",
          impact_weight_delta:0,
          reuse_weight_delta:0,
          friction_weight_delta:120000,
          risk_weight_delta:40000,
          expected_fidelity_delta_millionths:(($owner * 200000) | bounded(.)),
          improves_scenarios:(if $owner > 0 then ["stale_owner_miss"] else [] end),
          worsens_scenarios:[],
          manual_review_required:false
        },
        {
          candidate_id:"raise_proof_health_penalty",
          description:"Replay with stronger proof-brownout and proof-health penalties",
          impact_weight_delta:-30000,
          reuse_weight_delta:0,
          friction_weight_delta:30000,
          risk_weight_delta:140000,
          expected_fidelity_delta_millionths:(($proof * 240000) | bounded(.)),
          improves_scenarios:(if $proof > 0 then ["proof_brownout_miss"] else [] end),
          worsens_scenarios:[],
          manual_review_required:false
        },
        {
          candidate_id:"require_aftermath_evidence",
          description:"Require stronger aftermath capture before tuning low-evidence rows",
          impact_weight_delta:0,
          reuse_weight_delta:0,
          friction_weight_delta:60000,
          risk_weight_delta:90000,
          expected_fidelity_delta_millionths:(($missing * 120000) | bounded(.)),
          improves_scenarios:(if $missing > 0 then ["missing_outcome"] else [] end),
          worsens_scenarios:[],
          manual_review_required:true
        }
      ] as $candidates
    | ($candidates | map(. + {
        confidence_band: confidence(.expected_fidelity_delta_millionths; if $missing > 0 and .candidate_id == "require_aftermath_evidence" then "insufficient" else "ok" end),
        safety_status: safety(.expected_fidelity_delta_millionths; .manual_review_required)
      }) | sort_by((0 - .expected_fidelity_delta_millionths), .candidate_id)) as $ranked
    | ([$ranked[]? | select(.expected_fidelity_delta_millionths > 0)]) as $positive
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($missing > 0) then "degraded"
       elif ($positive | length) == 0 then "pass"
       elif ($positive | length) > 1 then "degraded"
       else "pass"
       end) as $decision
    | {
        counterfactual_backtest_report: {
          schema_version:"franken-engine.swarm-execution-queue-counterfactual-backtest-report.v1",
          source_revision:$source_revision,
          decision:$decision,
          baseline_overall_fidelity_millionths:($receipt_doc.overall_fidelity_millionths // 0),
          evaluated_candidate_count:($ranked | length),
          exact_match_count:$exact,
          positive_candidate_count:($positive | length),
          fail_closed_reasons:$fail_closed_reasons,
          candidates:$ranked,
          artifact_paths:{
            counterfactual_backtest_report_json:$backtest_report_path,
            tuning_plan_json:$tuning_plan_path,
            frontier_json:$frontier_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            report_md:$report_path
          }
        },
        tuning_plan: {
          schema_version:"franken-engine.swarm-execution-queue-tuning-plan.v1",
          source_revision:$source_revision,
          decision:$decision,
          plan_class:(if ($fail_closed_reasons | length) > 0 then "fail_closed"
            elif ($positive | length) == 0 then "no_improvement"
            elif ($positive | length) == 1 and (($positive[0].manual_review_required // false) | not) then "one_clear_improvement"
            elif ($missing > 0) then "insufficient_evidence"
            else "conflicting_improvements"
            end),
          recommended_candidate:($positive[0] // $ranked[0] // null),
          ranked_candidates:$ranked,
          operator_notes:(
            if ($fail_closed_reasons | length) > 0 then ["fail closed before replay; reconcile input evidence"]
            elif ($positive | length) == 0 then ["current weights remain best for this fixture set"]
            elif ($positive | length) == 1 then ["replay the recommended candidate before any policy change"]
            else ["multiple candidates improve different scenarios; keep manual review"]
            end
          ),
          mutation_policy:{
            changes_active_queue:false,
            applies_live_retuning:false,
            advisory_only:true
          }
        },
        frontier: {
          schema_version:"franken-engine.swarm-execution-queue-counterfactual-frontier.v1",
          source_revision:$source_revision,
          frontier:[$ranked[]? | select(.expected_fidelity_delta_millionths >= 0) | {
            candidate_id,
            expected_fidelity_delta_millionths,
            confidence_band,
            safety_status,
            manual_review_required
          }]
        }
      }
  ' >"$bundle_path"

jq '.counterfactual_backtest_report' "$bundle_path" >"$backtest_report_path"
jq '.tuning_plan' "$bundle_path" >"$tuning_plan_path"
jq '.frontier' "$bundle_path" >"$frontier_path"

plan_id="swarm-execution-queue-counterfactual-$(jq -cS 'del(.artifact_paths)' "$backtest_report_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_plan="${tuning_plan_path}.tmp"
jq --arg plan_id "$plan_id" '. + {plan_id:$plan_id}' "$tuning_plan_path" >"$tmp_plan"
mv "$tmp_plan" "$tuning_plan_path"

write_event "counterfactual_plan.written" "$(jq -r '.decision + " / class=" + .plan_class' "$tuning_plan_path")"

{
  printf '# Swarm Execution Queue Counterfactual Plan\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$tuning_plan_path")"
  printf -- "- Plan class: \`%s\`\n" "$(jq -r '.plan_class' "$tuning_plan_path")"
  printf -- "- Recommended candidate: \`%s\`\n" "$(jq -r '.recommended_candidate.candidate_id // "none"' "$tuning_plan_path")"
  printf -- "- Evaluated candidates: \`%s\`\n\n" "$(jq '.ranked_candidates | length' "$tuning_plan_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$backtest_report_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$backtest_report_path"
    printf '\n'
  fi
  printf '## Frontier\n'
  jq -r '.frontier[] | "- `" + .candidate_id + "` delta=`" + (.expected_fidelity_delta_millionths | tostring) + "` status=`" + .safety_status + "`"' "$frontier_path"
} >"$report_path"

printf 'counterfactual_backtest_report_json=%s\n' "$backtest_report_path"
printf 'tuning_plan_json=%s\n' "$tuning_plan_path"
printf 'frontier_json=%s\n' "$frontier_path"
printf 'counterfactual_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$tuning_plan_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
