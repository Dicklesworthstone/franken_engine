#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-tuning-rollback-comparator}"
run_id="${SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR_RUN_DIR:-${artifact_root}/${run_id}}"
generated_at="${SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
original_args=("$@")

candidate_bundle_json=""
rollout_plan_json=""
current_policy_state_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_tuning_rollback_comparator.sh \
  --candidate-bundle-json FILE \
  --rollout-plan-json FILE \
  --current-policy-state-json FILE \
  [OPTIONS]

Compares an advisory queue tuning bundle against current policy evidence and
emits rollback readiness plus a canary verdict ledger. It never updates beads,
changes live queue weights, sends Agent Mail, mutates workers, rewrites history,
or applies retuning automatically.

Artifacts:
  rollback_comparator_receipt.json
  canary_verdict_ledger.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  comparator completed; verdict may be better, worse, or ambiguous
  42 fail-closed due to missing evidence, mismatched rollback refs, or unsafe mutation claims
  64 usage or missing tool/file errors
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --candidate-bundle-json)
      candidate_bundle_json="${2:-}"
      shift 2
      ;;
    --rollout-plan-json)
      rollout_plan_json="${2:-}"
      shift 2
      ;;
    --current-policy-state-json)
      current_policy_state_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-at)
      generated_at="${2:-}"
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

if [[ -z "$candidate_bundle_json" || -z "$rollout_plan_json" || -z "$current_policy_state_json" ]]; then
  printf 'candidate bundle, rollout plan, and current policy state JSON inputs are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for tuning rollback comparison\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for tuning rollback comparison\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
receipt_path="${run_dir}/rollback_comparator_receipt.json"
ledger_path="${run_dir}/canary_verdict_ledger.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
core_path="${run_dir}/rollback_comparator.core.json"
bundle_normalized="${run_dir}/candidate_bundle.normalized.json"
rollout_normalized="${run_dir}/rollout_plan.normalized.json"
state_normalized="${run_dir}/current_policy_state.normalized.json"

printf './scripts/swarm_execution_queue_tuning_rollback_comparator.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-tuning-rollback-comparator.event.v1" \
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
    printf 'required rollback comparator input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required rollback comparator input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$candidate_bundle_json" "$bundle_normalized" "candidate_bundle_json"
json_input "$rollout_plan_json" "$rollout_normalized" "rollout_plan_json"
json_input "$current_policy_state_json" "$state_normalized" "current_policy_state_json"

bundle_sha="$(sha256sum "$candidate_bundle_json" | awk '{print $1}')"
rollout_sha="$(sha256sum "$rollout_plan_json" | awk '{print $1}')"
state_sha="$(sha256sum "$current_policy_state_json" | awk '{print $1}')"

jq -n \
  --arg source_revision "$source_revision" \
  --arg generated_at "$generated_at" \
  --arg candidate_bundle_json "$candidate_bundle_json" \
  --arg rollout_plan_json "$rollout_plan_json" \
  --arg current_policy_state_json "$current_policy_state_json" \
  --arg bundle_sha "$bundle_sha" \
  --arg rollout_sha "$rollout_sha" \
  --arg state_sha "$state_sha" \
  --arg receipt_path "$receipt_path" \
  --arg ledger_path "$ledger_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile rollout "$rollout_normalized" \
  --slurpfile state "$state_normalized" '
    def bad($kind; $source; $label; $detail): {kind:$kind,source:$source,label:$label,detail:$detail};
    def nonempty($v): (($v // "") | tostring | length) > 0;
    def has_evidence($links; $kind): any($links[]?; (.artifact_kind // "") == $kind and nonempty(.path) and ((.sha256 // "") | test("^[0-9a-f]{64}$")));
    def unsafe_text($v): (($v // "") | tostring | test("automatic|automatically|live retuning|changes active queue"));

    ($bundle[0]) as $bundle_doc
    | ($rollout[0]) as $plan_doc
    | ($state[0]) as $state_doc
    | (($bundle_doc.promoted_candidate.expected_fidelity_delta_millionths // 0) | tonumber) as $candidate_delta
    | (($state_doc.current_policy_metrics.overall_fidelity_millionths // 0) | tonumber) as $current_score
    | (($current_score + $candidate_delta) | if . < 0 then 0 elif . > 1000000 then 1000000 else . end) as $candidate_score
    | ($bundle_doc.evidence_links // []) as $links
    | (
        (if (($bundle_doc.schema_version // "") != "franken-engine.swarm-execution-queue-tuning-policy-bundle.v1") then [bad("bad_schema";"candidate_bundle_json";"schema_version";"unexpected candidate bundle schema")] else [] end)
        + (if (($plan_doc.schema_version // "") != "franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1") then [bad("bad_schema";"rollout_plan_json";"schema_version";"unexpected rollout plan schema")] else [] end)
        + (if (($state_doc.schema_version // "") != "franken-engine.swarm-execution-queue-current-policy-state.v1") then [bad("bad_schema";"current_policy_state_json";"schema_version";"unexpected current policy state schema")] else [] end)
        + (if (($bundle_doc.decision // "") == "fail_closed" or ($plan_doc.decision // "") == "reject") then [bad("upstream_rejected";"rollout_plan_json";"decision";"upstream bundle or rollout plan rejected promotion")] else [] end)
        + (($bundle_doc.fail_closed_reasons // []) | map(bad("upstream_fail_closed_reason";(.source // "candidate_bundle_json");(.label // "unknown");(.detail // .kind // "upstream fail-closed reason"))))
        + (if (($plan_doc.candidate_bundle_id // "") != ($bundle_doc.bundle_id // "")) then [bad("rollout_bundle_mismatch";"rollout_plan_json";"candidate_bundle_id";"rollout plan must reference the candidate bundle")] else [] end)
        + (if (($bundle_doc.rollback_references.prior_policy_bundle_id // "") != ($state_doc.current_policy_bundle_id // "")) then [bad("rollback_reference_mismatch";"candidate_bundle_json";"rollback_references.prior_policy_bundle_id";"bundle rollback reference must match current policy bundle id")] else [] end)
        + (if (($state_doc.evidence_freshness // "") != "fresh") then [bad("stale_evidence";"current_policy_state_json";"evidence_freshness";"current policy evidence must be fresh")] else [] end)
        + (if (($state_doc.rollback_material.prior_frontier_available // false) == true and ($state_doc.rollback_material.rollback_comparator_available // false) == true and ($state_doc.rollback_material.canary_verdict_ledger_available // false) == true) then [] else [bad("missing_rollback_material";"current_policy_state_json";"rollback_material";"current rollback material is incomplete")] end)
        + (if (has_evidence($links; "fidelity_score_receipt_json") and has_evidence($links; "drift_ledger_json") and has_evidence($links; "counterfactual_backtest_report_json") and has_evidence($links; "tuning_plan_json") and has_evidence($links; "frontier_json")) then [] else [bad("missing_supporting_evidence";"candidate_bundle_json";"evidence_links";"bundle lacks required hindsight/fidelity/counterfactual evidence links")] end)
        + (if (($bundle_doc.mutation_policy.changes_active_queue // false) != false or ($bundle_doc.mutation_policy.applies_live_retuning // false) != false or ($plan_doc.mutation_policy.changes_active_queue // false) != false or ($plan_doc.mutation_policy.applies_live_retuning // false) != false) then [bad("unsafe_mutation_policy";"candidate_bundle_json";"mutation_policy";"comparison inputs must be advisory-only")] else [] end)
        + (if unsafe_text($bundle_doc.automation_claim) then [bad("automatic_live_retuning_claim";"candidate_bundle_json";"automation_claim";"candidate bundle claims autonomous retuning")] else [] end)
      ) as $fail_closed_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif $candidate_delta >= 150000 then "better_than_current"
       elif $candidate_delta < 0 then "worse_than_current"
       else "ambiguous_verdict"
       end) as $verdict
    | (if $verdict == "better_than_current" then "continue_canary"
       elif $verdict == "worse_than_current" then "rollback_required"
       elif $verdict == "ambiguous_verdict" then "hold_manual_review"
       else "rollback_required"
       end) as $canary_action
    | {
        rollback_comparator_receipt:{
          schema_version:"franken-engine.swarm-execution-queue-tuning-rollback-comparator-receipt.v1",
          source_revision:$source_revision,
          generated_at:$generated_at,
          verdict:$verdict,
          candidate_bundle_id:($bundle_doc.bundle_id // "unknown"),
          candidate_id:($bundle_doc.promoted_candidate.candidate_id // "none"),
          current_policy_bundle_id:($state_doc.current_policy_bundle_id // "unknown"),
          current_fidelity_millionths:$current_score,
          candidate_expected_fidelity_millionths:$candidate_score,
          candidate_delta_millionths:$candidate_delta,
          cause_effect_explanations:[
            {
              signal:"candidate_delta_millionths",
              value:$candidate_delta,
              interpretation:(if $candidate_delta >= 150000 then "candidate has enough positive delta for bounded canary comparison" elif $candidate_delta < 0 then "candidate is worse than current policy and should roll back" else "candidate delta is too small for automatic confidence" end)
            },
            {
              signal:"rollback_reference_match",
              value:(($bundle_doc.rollback_references.prior_policy_bundle_id // "") == ($state_doc.current_policy_bundle_id // "")),
              interpretation:"candidate rollback references must match the current policy bundle"
            }
          ],
          fail_closed_reasons:$fail_closed_reasons,
          input_hashes:{
            candidate_bundle_json:$bundle_sha,
            rollout_plan_json:$rollout_sha,
            current_policy_state_json:$state_sha
          },
          mutation_policy:{
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false
          },
          artifact_paths:{
            rollback_comparator_receipt_json:$receipt_path,
            canary_verdict_ledger_json:$ledger_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            report_md:$report_path
          }
        },
        canary_verdict_ledger:{
          schema_version:"franken-engine.swarm-execution-queue-canary-verdict-ledger.v1",
          source_revision:$source_revision,
          generated_at:$generated_at,
          candidate_bundle_id:($bundle_doc.bundle_id // "unknown"),
          candidate_id:($bundle_doc.promoted_candidate.candidate_id // "none"),
          verdict:$verdict,
          recommended_action:$canary_action,
          verdict_rows:[
            {
              row_id:"candidate-vs-current-fidelity",
              current_fidelity_millionths:$current_score,
              candidate_expected_fidelity_millionths:$candidate_score,
              delta_millionths:$candidate_delta,
              outcome:(if $candidate_delta >= 150000 then "candidate_better" elif $candidate_delta < 0 then "candidate_worse" else "ambiguous" end)
            }
          ],
          rollback_triggers:[
            "candidate_delta_negative",
            "proof_drift observed",
            "ownership_drift observed",
            "restore_drift observed",
            "evidence freshness becomes stale",
            "rollback references mismatch",
            "reject local fallback proof evidence"
          ],
          fail_closed_reasons:$fail_closed_reasons,
          mutation_policy:{
            planning_artifact_only:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false
          },
          inputs:{
            candidate_bundle_json:$candidate_bundle_json,
            rollout_plan_json:$rollout_plan_json,
            current_policy_state_json:$current_policy_state_json
          }
        }
      }
  ' >"$core_path"

jq '.rollback_comparator_receipt' "$core_path" >"$receipt_path"
jq '.canary_verdict_ledger' "$core_path" >"$ledger_path"

write_event "rollback_comparator.written" "$(jq -r '.verdict + " / action=" + (.recommended_action // "n/a")' "$ledger_path")"

{
  printf '# Swarm Execution Queue Tuning Rollback Comparator\n\n'
  printf -- "- Verdict: \`%s\`\n" "$(jq -r '.verdict' "$receipt_path")"
  printf -- "- Candidate: \`%s\`\n" "$(jq -r '.candidate_id' "$receipt_path")"
  printf -- "- Candidate delta: \`%s\`\n" "$(jq '.candidate_delta_millionths' "$receipt_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n\n" "$(jq '.fail_closed_reasons | length' "$receipt_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$receipt_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$receipt_path"
    printf '\n'
  fi
  printf '## Rollback Triggers\n'
  jq -r '.rollback_triggers[] | "- " + .' "$ledger_path"
} >"$report_path"

printf 'rollback_comparator_receipt_json=%s\n' "$receipt_path"
printf 'canary_verdict_ledger_json=%s\n' "$ledger_path"
printf 'rollback_comparator_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.verdict' "$receipt_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
