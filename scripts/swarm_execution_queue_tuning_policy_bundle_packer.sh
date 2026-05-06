#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-tuning-policy-bundle}"
run_id="${SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_RUN_DIR:-${artifact_root}/${run_id}}"
generated_at="${SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
original_args=("$@")

fidelity_score_receipt_json=""
drift_ledger_json=""
counterfactual_backtest_report_json=""
tuning_plan_json=""
frontier_json=""
operator_status_json=""
prior_policy_bundle_id=""
prior_frontier_json=""
rollback_comparator_report_json=""
canary_verdict_ledger_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh \
  --fidelity-score-receipt-json FILE \
  --drift-ledger-json FILE \
  --counterfactual-backtest-report-json FILE \
  --tuning-plan-json FILE \
  --frontier-json FILE \
  --operator-status-json FILE \
  --prior-policy-bundle-id ID \
  --prior-frontier-json PATH \
  --rollback-comparator-report-json PATH \
  --canary-verdict-ledger-json PATH \
  [OPTIONS]

Packs a deterministic advisory-only execution queue tuning policy bundle and a
frontier export. It never updates beads, changes live queue weights, sends Agent
Mail, mutates workers, rewrites history, or applies retuning automatically.

Artifacts:
  tuning_policy_bundle.json
  policy_frontier_export.json
  evidence_hashes.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  bundle packed; decision may be pass or degraded
  42 fail-closed due to incomplete evidence, contradictions, or live-retuning claims
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
    --counterfactual-backtest-report-json)
      counterfactual_backtest_report_json="${2:-}"
      shift 2
      ;;
    --tuning-plan-json)
      tuning_plan_json="${2:-}"
      shift 2
      ;;
    --frontier-json)
      frontier_json="${2:-}"
      shift 2
      ;;
    --operator-status-json)
      operator_status_json="${2:-}"
      shift 2
      ;;
    --prior-policy-bundle-id)
      prior_policy_bundle_id="${2:-}"
      shift 2
      ;;
    --prior-frontier-json)
      prior_frontier_json="${2:-}"
      shift 2
      ;;
    --rollback-comparator-report-json)
      rollback_comparator_report_json="${2:-}"
      shift 2
      ;;
    --canary-verdict-ledger-json)
      canary_verdict_ledger_json="${2:-}"
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

for required_arg in \
  "$fidelity_score_receipt_json" \
  "$drift_ledger_json" \
  "$counterfactual_backtest_report_json" \
  "$tuning_plan_json" \
  "$frontier_json" \
  "$operator_status_json" \
  "$prior_policy_bundle_id" \
  "$prior_frontier_json" \
  "$rollback_comparator_report_json" \
  "$canary_verdict_ledger_json"; do
  if [[ -z "$required_arg" ]]; then
    printf 'all required tuning policy bundle inputs and rollback references must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for tuning policy bundle packing\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for tuning policy bundle packing\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
bundle_path="${run_dir}/tuning_policy_bundle.json"
frontier_export_path="${run_dir}/policy_frontier_export.json"
evidence_hashes_path="${run_dir}/evidence_hashes.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
core_path="${run_dir}/tuning_policy_bundle.core.json"

receipt_normalized="${run_dir}/fidelity_score_receipt.normalized.json"
ledger_normalized="${run_dir}/drift_ledger.normalized.json"
backtest_normalized="${run_dir}/counterfactual_backtest_report.normalized.json"
tuning_plan_normalized="${run_dir}/tuning_plan.normalized.json"
frontier_normalized="${run_dir}/frontier.normalized.json"
operator_status_normalized="${run_dir}/operator_status.normalized.json"

printf './scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-tuning-policy-bundle.event.v1" \
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
    printf 'required tuning policy bundle input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required tuning policy bundle input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$fidelity_score_receipt_json" "$receipt_normalized" "fidelity_score_receipt_json"
json_input "$drift_ledger_json" "$ledger_normalized" "drift_ledger_json"
json_input "$counterfactual_backtest_report_json" "$backtest_normalized" "counterfactual_backtest_report_json"
json_input "$tuning_plan_json" "$tuning_plan_normalized" "tuning_plan_json"
json_input "$frontier_json" "$frontier_normalized" "frontier_json"
json_input "$operator_status_json" "$operator_status_normalized" "operator_status_json"

receipt_sha="$(sha256sum "$fidelity_score_receipt_json" | awk '{print $1}')"
ledger_sha="$(sha256sum "$drift_ledger_json" | awk '{print $1}')"
backtest_sha="$(sha256sum "$counterfactual_backtest_report_json" | awk '{print $1}')"
tuning_plan_sha="$(sha256sum "$tuning_plan_json" | awk '{print $1}')"
frontier_sha="$(sha256sum "$frontier_json" | awk '{print $1}')"
operator_status_sha="$(sha256sum "$operator_status_json" | awk '{print $1}')"

jq -n \
  --arg source_revision "$source_revision" \
  --arg generated_at "$generated_at" \
  --arg bundle_path "$bundle_path" \
  --arg frontier_export_path "$frontier_export_path" \
  --arg evidence_hashes_path "$evidence_hashes_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg fidelity_score_receipt_json "$fidelity_score_receipt_json" \
  --arg drift_ledger_json "$drift_ledger_json" \
  --arg counterfactual_backtest_report_json "$counterfactual_backtest_report_json" \
  --arg tuning_plan_json "$tuning_plan_json" \
  --arg frontier_json "$frontier_json" \
  --arg operator_status_json "$operator_status_json" \
  --arg receipt_sha "$receipt_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg backtest_sha "$backtest_sha" \
  --arg tuning_plan_sha "$tuning_plan_sha" \
  --arg frontier_sha "$frontier_sha" \
  --arg operator_status_sha "$operator_status_sha" \
  --arg prior_policy_bundle_id "$prior_policy_bundle_id" \
  --arg prior_frontier_json "$prior_frontier_json" \
  --arg rollback_comparator_report_json "$rollback_comparator_report_json" \
  --arg canary_verdict_ledger_json "$canary_verdict_ledger_json" \
  --slurpfile receipt "$receipt_normalized" \
  --slurpfile ledger "$ledger_normalized" \
  --slurpfile backtest "$backtest_normalized" \
  --slurpfile plan "$tuning_plan_normalized" \
  --slurpfile frontier "$frontier_normalized" \
  --slurpfile operator_status "$operator_status_normalized" '
    def required_schema($doc; $schema; $source):
      if (($doc.schema_version // "") != $schema) then
        [{kind:"bad_schema",source:$source,label:"schema_version",detail:"unexpected schema"}]
      else [] end;
    def evidence($kind; $path; $sha): {artifact_kind:$kind,path:$path,sha256:$sha};
    def has_candidate($rows; $id): any($rows[]?; (.candidate_id // "") == $id);
    def by_delta: sort_by((0 - (.expected_fidelity_delta_millionths // -1000000)), (.candidate_id // ""));
    def candidate_state($candidate; $promoted_id):
      if (($candidate.candidate_id // "") == $promoted_id) then
        {frontier_state:"promoted",keep_reason:"promoted candidate from tuning plan"}
      elif (($candidate.expected_fidelity_delta_millionths // 0) >= 0) then
        {frontier_state:"kept_for_review",keep_reason:"non-negative frontier candidate retained for manual comparison"}
      else
        {frontier_state:"discarded",discard_reason:"negative expected fidelity delta"}
      end;

    ($receipt[0]) as $receipt_doc
    | ($ledger[0]) as $ledger_doc
    | ($backtest[0]) as $backtest_doc
    | ($plan[0]) as $plan_doc
    | ($frontier[0]) as $frontier_doc
    | ($operator_status[0]) as $operator_doc
    | (($plan_doc.ranked_candidates // []) | if type == "array" then . else [] end | by_delta) as $ranked
    | (($frontier_doc.frontier // []) | if type == "array" then . else [] end | by_delta) as $frontier_rows
    | ($plan_doc.recommended_candidate // ($ranked[0] // null)) as $recommended
    | (($recommended.candidate_id // "") | tostring) as $promoted_id
    | [
        evidence("fidelity_score_receipt_json"; $fidelity_score_receipt_json; $receipt_sha),
        evidence("drift_ledger_json"; $drift_ledger_json; $ledger_sha),
        evidence("counterfactual_backtest_report_json"; $counterfactual_backtest_report_json; $backtest_sha),
        evidence("tuning_plan_json"; $tuning_plan_json; $tuning_plan_sha),
        evidence("frontier_json"; $frontier_json; $frontier_sha),
        evidence("operator_status_json"; $operator_status_json; $operator_status_sha)
      ] as $evidence_links
    | (
        required_schema($receipt_doc; "franken-engine.swarm-execution-queue-fidelity-score-receipt.v1"; "fidelity_score_receipt_json")
        + required_schema($ledger_doc; "franken-engine.swarm-execution-queue-drift-ledger.v1"; "drift_ledger_json")
        + required_schema($backtest_doc; "franken-engine.swarm-execution-queue-counterfactual-backtest-report.v1"; "counterfactual_backtest_report_json")
        + required_schema($plan_doc; "franken-engine.swarm-execution-queue-tuning-plan.v1"; "tuning_plan_json")
        + required_schema($frontier_doc; "franken-engine.swarm-execution-queue-counterfactual-frontier.v1"; "frontier_json")
        + (if (($operator_doc.schema_version // "") | length) == 0 then [{kind:"bad_schema",source:"operator_status_json",label:"schema_version",detail:"operator status artifact must be versioned"}] else [] end)
        + (if (($receipt_doc.decision // "") == "fail_closed" or ($ledger_doc.decision // "") == "fail_closed" or ($backtest_doc.decision // "") == "fail_closed" or ($plan_doc.decision // "") == "fail_closed") then [{kind:"upstream_fail_closed",source:"tuning_plan_json",label:"decision",detail:"upstream tuning evidence already failed closed"}] else [] end)
        + (($backtest_doc.fail_closed_reasons // []) | map({kind:"upstream_fail_closed_reason",source:(.source // "counterfactual_backtest_report_json"),label:(.label // "unknown"),detail:(.detail // .kind // "upstream fail-closed reason")}))
        + (if ($ranked | length) == 0 then [{kind:"missing_candidates",source:"tuning_plan_json",label:"ranked_candidates",detail:"tuning plan has no ranked candidates"}] else [] end)
        + (if ($promoted_id | length) == 0 then [{kind:"missing_promoted_candidate",source:"tuning_plan_json",label:"recommended_candidate",detail:"tuning plan has no promoted candidate"}] else [] end)
        + (if (($promoted_id | length) > 0) and (has_candidate($ranked; $promoted_id) | not) then [{kind:"promoted_candidate_not_ranked",source:"tuning_plan_json",label:$promoted_id,detail:"promoted candidate is absent from ranked candidates"}] else [] end)
        + (if ($frontier_rows | length) == 0 then [{kind:"missing_frontier",source:"frontier_json",label:"frontier",detail:"frontier export has no candidates"}] else [] end)
        + ([$frontier_rows[]? | select(has_candidate($ranked; .candidate_id // "") | not) | {kind:"frontier_candidate_not_ranked",source:"frontier_json",label:(.candidate_id // "unknown"),detail:"frontier candidate is absent from tuning plan ranking"}])
        + ([$ranked[]? | select((.source_row.auto_apply // false) == true or (.source_row.live_retuning // false) == true or (.auto_apply // false) == true or (.live_retuning // false) == true) | {kind:"automatic_live_retuning_claim",source:"tuning_plan_json",label:(.candidate_id // "unknown"),detail:"candidate claims live retuning can be automatic"}])
        + (if (($plan_doc.mutation_policy.changes_active_queue // false) != false or ($plan_doc.mutation_policy.applies_live_retuning // false) != false or ($plan_doc.mutation_policy.advisory_only // true) != true) then [{kind:"unsafe_mutation_policy",source:"tuning_plan_json",label:"mutation_policy",detail:"tuning plan must remain advisory-only"}] else [] end)
        + (if (($prior_policy_bundle_id | length) == 0 or ($prior_frontier_json | length) == 0 or ($rollback_comparator_report_json | length) == 0 or ($canary_verdict_ledger_json | length) == 0) then [{kind:"missing_rollback_reference",source:"cli",label:"rollback_references",detail:"rollback references are required"}] else [] end)
      ) as $fail_closed_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif (($plan_doc.plan_class // "") == "conflicting_improvements" or ($plan_doc.decision // "") == "degraded") then "degraded"
       else "pass"
       end) as $decision
    | (($recommended // {}) + {
        source_tuning_plan_json:$tuning_plan_json
      }) as $promoted_candidate
    | ($ranked | map(. + candidate_state(.; $promoted_id))) as $candidate_explanations
    | {
        evidence_hashes: {
          schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle-evidence-hashes.v1",
          source_revision:$source_revision,
          evidence_links:$evidence_links
        },
        tuning_policy_bundle: {
          schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
          bundle_id:"pending",
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          plan_class:($plan_doc.plan_class // "unknown"),
          promoted_candidate:$promoted_candidate,
          evidence_links:$evidence_links,
          manual_approval:{
            required:true,
            approver_role:"human_operator",
            approval_artifact_path:"approvals/manual-approval.required.json"
          },
          canary_constraints:{
            enabled:true,
            observation_window_seconds:1800,
            max_queue_depth_delta:1,
            max_candidate_weight_delta_millionths:200000,
            rollback_on_drift_classes:["proof_drift","ownership_drift","restore_drift"],
            stop_on_missing_evidence:true
          },
          rollback_references:{
            prior_policy_bundle_id:$prior_policy_bundle_id,
            prior_frontier_json:$prior_frontier_json,
            rollback_comparator_report_json:$rollback_comparator_report_json,
            canary_verdict_ledger_json:$canary_verdict_ledger_json
          },
          mutation_policy:{
            planning_artifact_only:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false
          },
          automation_claim:"none",
          candidate_explanations:$candidate_explanations,
          fail_closed_reasons:$fail_closed_reasons,
          fail_closed_rules:[
            "missing evidence links fail closed",
            "manual approval missing fail closed",
            "rollback references missing fail closed",
            "automatic retuning claims fail closed",
            "unsafe canary constraints fail closed",
            "reject local fallback proof evidence"
          ],
          artifact_paths:{
            tuning_policy_bundle_json:$bundle_path,
            policy_frontier_export_json:$frontier_export_path,
            evidence_hashes_json:$evidence_hashes_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            report_md:$report_path
          }
        },
        policy_frontier_export: {
          schema_version:"franken-engine.swarm-execution-queue-policy-frontier-export.v1",
          bundle_id:"pending",
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          plan_class:($plan_doc.plan_class // "unknown"),
          promoted_candidate_id:$promoted_id,
          candidates:$candidate_explanations,
          mutation_policy:{
            advisory_only:true,
            changes_active_queue:false,
            applies_live_retuning:false
          },
          fail_closed_reasons:$fail_closed_reasons
        }
      }
  ' >"$core_path"

jq '.evidence_hashes' "$core_path" >"$evidence_hashes_path"
jq '.tuning_policy_bundle' "$core_path" >"$bundle_path"
jq '.policy_frontier_export' "$core_path" >"$frontier_export_path"

bundle_id="swarm-execution-queue-tuning-policy-bundle-$(jq -cS 'del(.bundle_id)' "$bundle_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_bundle="${bundle_path}.tmp"
tmp_frontier="${frontier_export_path}.tmp"
jq --arg bundle_id "$bundle_id" '.bundle_id = $bundle_id' "$bundle_path" >"$tmp_bundle"
mv "$tmp_bundle" "$bundle_path"
jq --arg bundle_id "$bundle_id" '.bundle_id = $bundle_id' "$frontier_export_path" >"$tmp_frontier"
mv "$tmp_frontier" "$frontier_export_path"

write_event "tuning_policy_bundle.written" "$(jq -r '.decision + " / class=" + .plan_class + " / bundle=" + .bundle_id' "$bundle_path")"

{
  printf '# Swarm Execution Queue Tuning Policy Bundle\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$bundle_path")"
  printf -- "- Plan class: \`%s\`\n" "$(jq -r '.plan_class' "$bundle_path")"
  printf -- "- Bundle id: \`%s\`\n" "$(jq -r '.bundle_id' "$bundle_path")"
  printf -- "- Promoted candidate: \`%s\`\n" "$(jq -r '.promoted_candidate.candidate_id // "none"' "$bundle_path")"
  printf -- "- Evidence links: \`%s\`\n\n" "$(jq '.evidence_links | length' "$bundle_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$bundle_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$bundle_path"
    printf '\n'
  fi
  printf '## Candidate Frontier\n'
  jq -r '.candidate_explanations[] | "- `" + .candidate_id + "` `" + .frontier_state + "` delta=`" + (.expected_fidelity_delta_millionths | tostring) + "`: " + (.keep_reason // .discard_reason // "review")' "$bundle_path"
} >"$report_path"

printf 'tuning_policy_bundle_json=%s\n' "$bundle_path"
printf 'policy_frontier_export_json=%s\n' "$frontier_export_path"
printf 'tuning_policy_evidence_hashes_json=%s\n' "$evidence_hashes_path"
printf 'tuning_policy_bundle_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$bundle_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
