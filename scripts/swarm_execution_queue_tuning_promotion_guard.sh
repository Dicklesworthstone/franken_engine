#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-tuning-promotion-guard}"
run_id="${SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD_RUN_DIR:-${artifact_root}/${run_id}}"
generated_at="${SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
original_args=("$@")

candidate_bundle_json=""
current_policy_state_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_tuning_promotion_guard.sh \
  --candidate-bundle-json FILE \
  --current-policy-state-json FILE \
  [OPTIONS]

Evaluates whether an advisory queue tuning policy bundle is eligible for a
manual-approval canary rollout plan. It never updates beads, changes live queue
weights, sends Agent Mail, mutates workers, rewrites history, or applies
retuning automatically.

Artifacts:
  promotion_guard_receipt.json
  manual_approval_rollout_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  guard completed; decision may be safe_noop or eligible_canary
  42 fail-closed rejection
  64 usage or missing tool/file errors
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --candidate-bundle-json)
      candidate_bundle_json="${2:-}"
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

if [[ -z "$candidate_bundle_json" || -z "$current_policy_state_json" ]]; then
  printf 'candidate bundle and current policy state JSON inputs are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for tuning promotion guard validation\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for tuning promotion guard validation\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
receipt_path="${run_dir}/promotion_guard_receipt.json"
rollout_plan_path="${run_dir}/manual_approval_rollout_plan.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
core_path="${run_dir}/promotion_guard.core.json"
bundle_normalized="${run_dir}/candidate_bundle.normalized.json"
policy_state_normalized="${run_dir}/current_policy_state.normalized.json"

printf './scripts/swarm_execution_queue_tuning_promotion_guard.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-tuning-promotion-guard.event.v1" \
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
    printf 'required tuning promotion guard input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required tuning promotion guard input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$candidate_bundle_json" "$bundle_normalized" "candidate_bundle_json"
json_input "$current_policy_state_json" "$policy_state_normalized" "current_policy_state_json"

bundle_sha="$(sha256sum "$candidate_bundle_json" | awk '{print $1}')"
policy_state_sha="$(sha256sum "$current_policy_state_json" | awk '{print $1}')"

jq -n \
  --arg source_revision "$source_revision" \
  --arg generated_at "$generated_at" \
  --arg candidate_bundle_json "$candidate_bundle_json" \
  --arg current_policy_state_json "$current_policy_state_json" \
  --arg bundle_sha "$bundle_sha" \
  --arg policy_state_sha "$policy_state_sha" \
  --arg receipt_path "$receipt_path" \
  --arg rollout_plan_path "$rollout_plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile policy_state "$policy_state_normalized" '
    def nonempty($v): (($v // "") | tostring | length) > 0;
    def bad($kind; $source; $label; $detail): {kind:$kind,source:$source,label:$label,detail:$detail};
    def unsafe_text($v): (($v // "") | tostring | test("automatic|automatically|live retuning|changes active queue"));

    ($bundle[0]) as $bundle_doc
    | ($policy_state[0]) as $state
    | (($bundle_doc.promoted_candidate.expected_fidelity_delta_millionths // 0) | tonumber) as $candidate_delta
    | ($bundle_doc.bundle_id // "unknown") as $bundle_id
    | ($state.current_policy_bundle_id // "") as $current_policy_bundle_id
    | (
        (if (($bundle_doc.schema_version // "") != "franken-engine.swarm-execution-queue-tuning-policy-bundle.v1") then [bad("bad_schema";"candidate_bundle_json";"schema_version";"unexpected candidate bundle schema")] else [] end)
        + (if (($state.schema_version // "") != "franken-engine.swarm-execution-queue-current-policy-state.v1") then [bad("bad_schema";"current_policy_state_json";"schema_version";"unexpected current policy state schema")] else [] end)
        + (if (($bundle_doc.decision // "") == "fail_closed") then [bad("upstream_fail_closed";"candidate_bundle_json";"decision";"candidate bundle already failed closed")] else [] end)
        + (($bundle_doc.fail_closed_reasons // []) | map(bad("upstream_fail_closed_reason";(.source // "candidate_bundle_json");(.label // "unknown");(.detail // .kind // "upstream fail-closed reason"))))
        + (if (($bundle_doc.manual_approval.required // false) != true) then [bad("manual_approval_missing";"candidate_bundle_json";"manual_approval";"manual approval must be required before rollout")] else [] end)
        + (if (($bundle_doc.mutation_policy.changes_active_queue // false) != false or ($bundle_doc.mutation_policy.applies_live_retuning // false) != false or ($bundle_doc.mutation_policy.mutates_br // false) != false or ($bundle_doc.mutation_policy.sends_agent_mail // false) != false or ($bundle_doc.mutation_policy.mutates_remote_workers // false) != false) then [bad("unsafe_mutation_policy";"candidate_bundle_json";"mutation_policy";"candidate bundle implies live mutation authority")] else [] end)
        + (if unsafe_text($bundle_doc.automation_claim) then [bad("automatic_live_retuning_claim";"candidate_bundle_json";"automation_claim";"candidate bundle claims autonomous retuning")] else [] end)
        + (if (($state.evidence_freshness // "") != "fresh") then [bad("stale_evidence";"current_policy_state_json";"evidence_freshness";"current policy evidence must be fresh")] else [] end)
        + (if (($state.provenance_state // "") != "consistent") then [bad("contradictory_provenance";"current_policy_state_json";"provenance_state";"current policy provenance must be consistent")] else [] end)
        + (if (($state.mutation_policy.changes_active_queue // false) != false or ($state.mutation_policy.applies_live_retuning // false) != false) then [bad("unsafe_current_policy_mutation";"current_policy_state_json";"mutation_policy";"current policy state must be observational")] else [] end)
        + (if (($bundle_doc.rollback_references.prior_policy_bundle_id // "") != $current_policy_bundle_id) then [bad("rollback_reference_mismatch";"candidate_bundle_json";"rollback_references.prior_policy_bundle_id";"bundle rollback reference must match current policy bundle id")] else [] end)
        + (if (nonempty($bundle_doc.rollback_references.prior_frontier_json) and nonempty($bundle_doc.rollback_references.rollback_comparator_report_json) and nonempty($bundle_doc.rollback_references.canary_verdict_ledger_json)) then [] else [bad("missing_rollback_material";"candidate_bundle_json";"rollback_references";"candidate bundle lacks rollback references")] end)
        + (if (($state.rollback_material.prior_frontier_available // false) == true and ($state.rollback_material.rollback_comparator_available // false) == true and ($state.rollback_material.canary_verdict_ledger_available // false) == true) then [] else [bad("missing_current_rollback_material";"current_policy_state_json";"rollback_material";"current policy state lacks rollback material")] end)
      ) as $reject_reasons
    | (if ($reject_reasons | length) > 0 then "reject"
       elif (($bundle_doc.plan_class // "") == "no_improvement" or $candidate_delta <= 0) then "safe_noop"
       else "eligible_canary"
       end) as $decision
    | {
        promotion_guard_receipt:{
          schema_version:"franken-engine.swarm-execution-queue-tuning-promotion-guard-receipt.v1",
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          candidate_bundle_id:$bundle_id,
          candidate_id:($bundle_doc.promoted_candidate.candidate_id // "none"),
          expected_fidelity_delta_millionths:$candidate_delta,
          current_policy_bundle_id:$current_policy_bundle_id,
          preconditions:{
            evidence_freshness:($state.evidence_freshness // "unknown"),
            provenance_state:($state.provenance_state // "unknown"),
            rollback_material_complete:(($state.rollback_material.prior_frontier_available // false) == true and ($state.rollback_material.rollback_comparator_available // false) == true and ($state.rollback_material.canary_verdict_ledger_available // false) == true),
            manual_approval_required:($bundle_doc.manual_approval.required // false)
          },
          reject_reasons:$reject_reasons,
          input_hashes:{
            candidate_bundle_json:$bundle_sha,
            current_policy_state_json:$policy_state_sha
          },
          mutation_policy:{
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false
          },
          artifact_paths:{
            promotion_guard_receipt_json:$receipt_path,
            manual_approval_rollout_plan_json:$rollout_plan_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            report_md:$report_path
          }
        },
        manual_approval_rollout_plan:{
          schema_version:"franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1",
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          candidate_bundle_id:$bundle_id,
          candidate_id:($bundle_doc.promoted_candidate.candidate_id // "none"),
          manual_approval:{
            required:true,
            approval_artifact_path:($bundle_doc.manual_approval.approval_artifact_path // "approvals/manual-approval.required.json"),
            approver_role:($bundle_doc.manual_approval.approver_role // "human_operator")
          },
          canary_recommendation:(if $decision == "eligible_canary" then {
            stage_order:["manual_review","shadow_canary","bounded_queue_canary","canary_verdict_review"],
            observation_window_seconds:($bundle_doc.canary_constraints.observation_window_seconds // 1800),
            max_queue_depth_delta:($bundle_doc.canary_constraints.max_queue_depth_delta // 1),
            max_candidate_weight_delta_millionths:($bundle_doc.canary_constraints.max_candidate_weight_delta_millionths // 200000)
          } else null end),
          stop_conditions:[
            "manual approval missing",
            "evidence freshness becomes stale",
            "provenance becomes contradictory",
            "rollback material missing",
            "proof_drift observed",
            "ownership_drift observed",
            "restore_drift observed",
            "reject local fallback proof evidence"
          ],
          rejection_reasons:$reject_reasons,
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
            current_policy_state_json:$current_policy_state_json
          }
        }
      }
  ' >"$core_path"

jq '.promotion_guard_receipt' "$core_path" >"$receipt_path"
jq '.manual_approval_rollout_plan' "$core_path" >"$rollout_plan_path"

write_event "promotion_guard.written" "$(jq -r '.decision + " / candidate=" + .candidate_id' "$receipt_path")"

{
  printf '# Swarm Execution Queue Tuning Promotion Guard\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$receipt_path")"
  printf -- "- Candidate: \`%s\`\n" "$(jq -r '.candidate_id' "$receipt_path")"
  printf -- "- Bundle: \`%s\`\n" "$(jq -r '.candidate_bundle_id' "$receipt_path")"
  printf -- "- Reject reasons: \`%s\`\n\n" "$(jq '.reject_reasons | length' "$receipt_path")"
  if [[ "$(jq '.reject_reasons | length' "$receipt_path")" -ne 0 ]]; then
    printf '## Reject Reasons\n'
    jq -r '.reject_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$receipt_path"
    printf '\n'
  fi
  printf '## Stop Conditions\n'
  jq -r '.stop_conditions[] | "- " + .' "$rollout_plan_path"
} >"$report_path"

printf 'promotion_guard_receipt_json=%s\n' "$receipt_path"
printf 'manual_approval_rollout_plan_json=%s\n' "$rollout_plan_path"
printf 'promotion_guard_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$receipt_path")" == "reject" ]]; then
  exit 42
fi
exit 0
