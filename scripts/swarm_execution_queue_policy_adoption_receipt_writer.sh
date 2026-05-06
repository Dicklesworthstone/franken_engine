#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-policy-adoption-receipt}"
run_id="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_RUN_DIR:-${artifact_root}/${run_id}}"
generated_at="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
original_args=("$@")

candidate_bundle_json=""
promotion_guard_receipt_json=""
rollout_plan_json=""
rollback_comparator_receipt_json=""
canary_verdict_ledger_json=""
operator_decision_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh \
  --candidate-bundle-json FILE \
  --promotion-guard-receipt-json FILE \
  --rollout-plan-json FILE \
  --rollback-comparator-receipt-json FILE \
  --canary-verdict-ledger-json FILE \
  --operator-decision-json FILE \
  [--source-revision REV] \
  [--output-dir DIR]

Writes a deterministic adoption receipt plus snapshot bundle for an operator
approved execution queue policy. It never mutates br, Agent Mail, remote
workers, live queue settings, or historical outcomes.

Exit codes:
  0  receipt written and admitted
  42 fail-closed due to incomplete or contradictory adoption evidence
  64 usage or missing tool/file errors
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --candidate-bundle-json)
      candidate_bundle_json="${2:-}"
      shift 2
      ;;
    --promotion-guard-receipt-json)
      promotion_guard_receipt_json="${2:-}"
      shift 2
      ;;
    --rollout-plan-json)
      rollout_plan_json="${2:-}"
      shift 2
      ;;
    --rollback-comparator-receipt-json)
      rollback_comparator_receipt_json="${2:-}"
      shift 2
      ;;
    --canary-verdict-ledger-json)
      canary_verdict_ledger_json="${2:-}"
      shift 2
      ;;
    --operator-decision-json)
      operator_decision_json="${2:-}"
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

for required_arg in \
  "$candidate_bundle_json" \
  "$promotion_guard_receipt_json" \
  "$rollout_plan_json" \
  "$rollback_comparator_receipt_json" \
  "$canary_verdict_ledger_json" \
  "$operator_decision_json"; do
  if [[ -z "$required_arg" ]]; then
    printf 'all required adoption receipt inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for adoption receipt writing\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for adoption receipt writing\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
receipt_path="${run_dir}/adoption_receipt.json"
snapshot_path="${run_dir}/adoption_snapshot_bundle.json"
evidence_hashes_path="${run_dir}/evidence_hashes.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
core_path="${run_dir}/adoption_receipt.core.json"

bundle_normalized="${run_dir}/candidate_bundle.normalized.json"
guard_normalized="${run_dir}/promotion_guard_receipt.normalized.json"
rollout_normalized="${run_dir}/rollout_plan.normalized.json"
rollback_normalized="${run_dir}/rollback_comparator_receipt.normalized.json"
ledger_normalized="${run_dir}/canary_verdict_ledger.normalized.json"
operator_normalized="${run_dir}/operator_decision.normalized.json"

printf './scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-policy-adoption-receipt.event.v1" \
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
    printf 'required adoption receipt input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required adoption receipt input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$candidate_bundle_json" "$bundle_normalized" "candidate_bundle_json"
json_input "$promotion_guard_receipt_json" "$guard_normalized" "promotion_guard_receipt_json"
json_input "$rollout_plan_json" "$rollout_normalized" "rollout_plan_json"
json_input "$rollback_comparator_receipt_json" "$rollback_normalized" "rollback_comparator_receipt_json"
json_input "$canary_verdict_ledger_json" "$ledger_normalized" "canary_verdict_ledger_json"
json_input "$operator_decision_json" "$operator_normalized" "operator_decision_json"

bundle_sha="$(sha256sum "$candidate_bundle_json" | awk '{print $1}')"
guard_sha="$(sha256sum "$promotion_guard_receipt_json" | awk '{print $1}')"
rollout_sha="$(sha256sum "$rollout_plan_json" | awk '{print $1}')"
rollback_sha="$(sha256sum "$rollback_comparator_receipt_json" | awk '{print $1}')"
ledger_sha="$(sha256sum "$canary_verdict_ledger_json" | awk '{print $1}')"
operator_sha="$(sha256sum "$operator_decision_json" | awk '{print $1}')"

jq -n \
  --arg source_revision "$source_revision" \
  --arg generated_at "$generated_at" \
  --arg receipt_path "$receipt_path" \
  --arg snapshot_path "$snapshot_path" \
  --arg evidence_hashes_path "$evidence_hashes_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg candidate_bundle_json "$candidate_bundle_json" \
  --arg promotion_guard_receipt_json "$promotion_guard_receipt_json" \
  --arg rollout_plan_json "$rollout_plan_json" \
  --arg rollback_comparator_receipt_json "$rollback_comparator_receipt_json" \
  --arg canary_verdict_ledger_json "$canary_verdict_ledger_json" \
  --arg operator_decision_json "$operator_decision_json" \
  --arg bundle_sha "$bundle_sha" \
  --arg guard_sha "$guard_sha" \
  --arg rollout_sha "$rollout_sha" \
  --arg rollback_sha "$rollback_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg operator_sha "$operator_sha" \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile guard "$guard_normalized" \
  --slurpfile rollout "$rollout_normalized" \
  --slurpfile rollback "$rollback_normalized" \
  --slurpfile ledger "$ledger_normalized" \
  --slurpfile operator "$operator_normalized" \
  '
    def nonempty($value): (($value // "") | length) > 0;
    def bad($kind; $source; $label; $detail): {kind:$kind,source:$source,label:$label,detail:$detail};
    def evidence($kind; $path; $sha): {artifact_kind:$kind,path:$path,sha256:$sha};
    def unsafe_mutation($doc):
      (($doc.mutation_policy.changes_active_queue // false) != false)
      or (($doc.mutation_policy.applies_live_retuning // false) != false)
      or (($doc.mutation_policy.mutates_br // false) != false)
      or (($doc.mutation_policy.sends_agent_mail // false) != false)
      or (($doc.mutation_policy.mutates_remote_workers // false) != false);

    ($bundle[0]) as $bundle_doc
    | ($guard[0]) as $guard_doc
    | ($rollout[0]) as $rollout_doc
    | ($rollback[0]) as $rollback_doc
    | ($ledger[0]) as $ledger_doc
    | ($operator[0]) as $operator_doc
    | ($bundle_doc.bundle_id // "") as $bundle_id
    | ($bundle_doc.promoted_candidate.candidate_id // "") as $candidate_id
    | [
        (if (($bundle_doc.schema_version // "") != "franken-engine.swarm-execution-queue-tuning-policy-bundle.v1") then bad("bad_schema";"candidate_bundle_json";"schema_version";"unexpected candidate bundle schema") else empty end),
        (if (($guard_doc.schema_version // "") != "franken-engine.swarm-execution-queue-tuning-promotion-guard-receipt.v1") then bad("bad_schema";"promotion_guard_receipt_json";"schema_version";"unexpected promotion guard schema") else empty end),
        (if (($rollout_doc.schema_version // "") != "franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1") then bad("bad_schema";"rollout_plan_json";"schema_version";"unexpected rollout plan schema") else empty end),
        (if (($rollback_doc.schema_version // "") != "franken-engine.swarm-execution-queue-tuning-rollback-comparator-receipt.v1") then bad("bad_schema";"rollback_comparator_receipt_json";"schema_version";"unexpected rollback comparator schema") else empty end),
        (if (($ledger_doc.schema_version // "") != "franken-engine.swarm-execution-queue-canary-verdict-ledger.v1") then bad("bad_schema";"canary_verdict_ledger_json";"schema_version";"unexpected canary verdict ledger schema") else empty end),
        (if (($operator_doc.schema_version // "") != "franken-engine.swarm-execution-queue-policy-adoption-operator-decision.v1") then bad("bad_schema";"operator_decision_json";"schema_version";"unexpected operator decision schema") else empty end),
        (if (($bundle_doc.decision // "") != "pass") then bad("candidate_bundle_not_pass";"candidate_bundle_json";"decision";"candidate bundle must pass before adoption") else empty end),
        (if (($guard_doc.decision // "") != "eligible_canary") then bad("promotion_guard_not_eligible";"promotion_guard_receipt_json";"decision";"promotion guard must be eligible_canary") else empty end),
        (if (($rollout_doc.decision // "") != "eligible_canary") then bad("rollout_plan_not_eligible";"rollout_plan_json";"decision";"rollout plan must be eligible_canary") else empty end),
        (if (($rollback_doc.verdict // "") != "better_than_current") then bad("rollback_verdict_not_adoptable";"rollback_comparator_receipt_json";"verdict";"rollback comparator must be better_than_current") else empty end),
        (if (($ledger_doc.recommended_action // "") != "continue_canary") then bad("canary_action_not_continuing";"canary_verdict_ledger_json";"recommended_action";"canary verdict must recommend continue_canary") else empty end),
        (if (($operator_doc.decision // "") != "adopt") then bad("operator_decision_not_adopt";"operator_decision_json";"decision";"operator decision must be adopt") else empty end),
        (if (($operator_doc.adopted_policy_bundle_id // $bundle_id) == $bundle_id) then empty else bad("operator_bundle_id_mismatch";"operator_decision_json";"adopted_policy_bundle_id";"operator decision must approve the candidate bundle id") end),
        (if (nonempty($operator_doc.approved_by) and nonempty($operator_doc.approved_at) and nonempty($operator_doc.approval_artifact_path) and nonempty($operator_doc.decision_reason)) then empty else bad("missing_operator_approval";"operator_decision_json";"operator_decision";"manual operator approval metadata is incomplete") end),
        (if (($operator_doc.adoption_state // "") | IN("recorded_pending_activation", "recorded_active_policy")) then empty else bad("bad_adoption_state";"operator_decision_json";"adoption_state";"adoption state is unsupported") end),
        (if (($guard_doc.candidate_bundle_id // "") == $bundle_id and ($rollout_doc.candidate_bundle_id // "") == $bundle_id and ($rollback_doc.candidate_bundle_id // "") == $bundle_id and ($ledger_doc.candidate_bundle_id // "") == $bundle_id) then empty else bad("bundle_id_mismatch";"inputs";$bundle_id;"bundle ids must match across adoption inputs") end),
        (if (($guard_doc.candidate_id // "") == $candidate_id and ($rollout_doc.candidate_id // "") == $candidate_id and ($rollback_doc.candidate_id // "") == $candidate_id and ($ledger_doc.candidate_id // "") == $candidate_id) then empty else bad("candidate_id_mismatch";"inputs";$candidate_id;"candidate ids must match across adoption inputs") end),
        (if (($operator_doc.observation_window.duration_seconds // 0) >= 1800 and ($operator_doc.observation_window.minimum_sample_count // 0) >= 3 and (($operator_doc.observation_window.stop_on_missing_evidence // false) == true)) then empty else bad("missing_observation_window";"operator_decision_json";"observation_window";"operator observation window is incomplete or too small") end),
        (if ($operator_doc.supersession | has("supersedes_adoption_receipt_id") and has("supersedes_policy_bundle_id") and nonempty(.supersession_reason) and nonempty(.previous_policy_retention) and nonempty(.expiry_policy)) then empty else bad("missing_supersession_metadata";"operator_decision_json";"supersession";"supersession metadata is incomplete") end),
        (if unsafe_mutation($bundle_doc) or unsafe_mutation($guard_doc) or unsafe_mutation($rollout_doc) or unsafe_mutation($rollback_doc) or unsafe_mutation($ledger_doc) or unsafe_mutation($operator_doc) then bad("unsafe_mutation_policy";"inputs";"mutation_policy";"adoption inputs must remain receipt/snapshot-only") else empty end),
        (if ((($operator_doc.automation_claim // "none") | test("automatic|automatically|live retuning|changes active queue|proves sustained gain")) or (($operator_doc.sustained_gain_claim // false) == true)) then bad("unsafe_operator_claim";"operator_decision_json";"automation_claim";"operator decision must not claim automatic adoption or sustained gain") else empty end)
      ] as $fail_closed_reasons
    | (if ($fail_closed_reasons | length) == 0 then "admitted" else "fail_closed" end) as $decision
    | [
        evidence("candidate_bundle_json"; $candidate_bundle_json; $bundle_sha),
        evidence("promotion_guard_receipt_json"; $promotion_guard_receipt_json; $guard_sha),
        evidence("rollout_plan_json"; $rollout_plan_json; $rollout_sha),
        evidence("rollback_comparator_receipt_json"; $rollback_comparator_receipt_json; $rollback_sha),
        evidence("canary_verdict_ledger_json"; $canary_verdict_ledger_json; $ledger_sha),
        evidence("operator_decision_json"; $operator_decision_json; $operator_sha)
      ] as $evidence_links
    | {
        evidence_hashes:{
          schema_version:"franken-engine.swarm-execution-queue-policy-adoption-evidence-hashes.v1",
          source_revision:$source_revision,
          evidence_links:$evidence_links
        },
        adoption_receipt:{
          schema_version:"franken-engine.swarm-execution-queue-policy-adoption-receipt.v1",
          adoption_receipt_id:"pending",
          adopted_policy_bundle_id:$bundle_id,
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          operator_decision:{
            decision:($operator_doc.decision // "missing"),
            approved_by:($operator_doc.approved_by // ""),
            approved_at:($operator_doc.approved_at // ""),
            approval_artifact_path:($operator_doc.approval_artifact_path // ""),
            decision_reason:($operator_doc.decision_reason // ""),
            adoption_state:($operator_doc.adoption_state // "missing")
          },
          adopted_candidate:{
            candidate_id:$candidate_id,
            expected_fidelity_delta_millionths:($bundle_doc.promoted_candidate.expected_fidelity_delta_millionths // 0),
            source_policy_bundle_id:$bundle_id,
            source_promotion_guard_receipt_json:$promotion_guard_receipt_json,
            source_canary_verdict_ledger_json:$canary_verdict_ledger_json
          },
          evidence_links:$evidence_links,
          observation_window:{
            starts_at:($operator_doc.observation_window.starts_at // $generated_at),
            duration_seconds:($operator_doc.observation_window.duration_seconds // 0),
            minimum_sample_count:($operator_doc.observation_window.minimum_sample_count // 0),
            monitored_metrics:($operator_doc.observation_window.monitored_metrics // []),
            stop_on_missing_evidence:($operator_doc.observation_window.stop_on_missing_evidence // false)
          },
          supersession:{
            supersedes_adoption_receipt_id:($operator_doc.supersession.supersedes_adoption_receipt_id // null),
            supersedes_policy_bundle_id:($operator_doc.supersession.supersedes_policy_bundle_id // ""),
            supersession_reason:($operator_doc.supersession.supersession_reason // ""),
            previous_policy_retention:($operator_doc.supersession.previous_policy_retention // ""),
            expiry_policy:($operator_doc.supersession.expiry_policy // "")
          },
          mutation_policy:{
            receipt_artifact_only:true,
            records_operator_decision:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false
          },
          non_claim_boundaries:[
            "does not prove sustained gain",
            "does not prove canary success beyond linked evidence",
            "does not authorize automatic live retuning",
            "does not mutate scheduler behavior by itself",
            "does not replace later drift-forensics scoring",
            "does not imply active queue changed without this receipt"
          ],
          automation_claim:($operator_doc.automation_claim // "none"),
          fail_closed_reasons:$fail_closed_reasons,
          fail_closed_rules:[
            "missing operator approval fails closed",
            "missing evidence links fail closed",
            "missing evidence hashes fail closed",
            "missing observation window fails closed",
            "missing supersession metadata fails closed",
            "automatic adoption claims fail closed",
            "live retuning claims fail closed",
            "sustained-gain claims fail closed",
            "reject local fallback proof evidence"
          ]
        },
        adoption_snapshot_bundle:{
          schema_version:"franken-engine.swarm-execution-queue-policy-adoption-snapshot-bundle.v1",
          snapshot_id:"pending",
          adoption_receipt_id:"pending",
          adopted_policy_bundle_id:$bundle_id,
          candidate_id:$candidate_id,
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          fail_closed_reasons:$fail_closed_reasons,
          evidence_hashes_json:$evidence_hashes_path,
          normalized_inputs:{
            candidate_bundle:$bundle_doc,
            promotion_guard_receipt:$guard_doc,
            rollout_plan:$rollout_doc,
            rollback_comparator_receipt:$rollback_doc,
            canary_verdict_ledger:$ledger_doc,
            operator_decision:$operator_doc
          },
          artifact_paths:{
            adoption_receipt_json:$receipt_path,
            adoption_snapshot_bundle_json:$snapshot_path,
            evidence_hashes_json:$evidence_hashes_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            report_md:$report_path
          },
          mutation_policy:{
            receipt_artifact_only:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false
          }
        }
      }
  ' >"$core_path"

jq '.evidence_hashes' "$core_path" >"$evidence_hashes_path"
jq '.adoption_receipt' "$core_path" >"$receipt_path"

receipt_id="queue-policy-adoption-receipt-$(jq -cS 'del(.adoption_receipt_id)' "$receipt_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_receipt="${receipt_path}.tmp"
jq --arg receipt_id "$receipt_id" '.adoption_receipt_id = $receipt_id' "$receipt_path" >"$tmp_receipt"
mv "$tmp_receipt" "$receipt_path"

jq --arg receipt_id "$receipt_id" '.adoption_snapshot_bundle | .adoption_receipt_id = $receipt_id' "$core_path" >"$snapshot_path"
snapshot_id="queue-policy-adoption-snapshot-$(jq -cS 'del(.snapshot_id)' "$snapshot_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_snapshot="${snapshot_path}.tmp"
jq --arg snapshot_id "$snapshot_id" '.snapshot_id = $snapshot_id' "$snapshot_path" >"$tmp_snapshot"
mv "$tmp_snapshot" "$snapshot_path"

write_event "adoption_receipt.written" "$(jq -r '.decision + " / bundle=" + .adopted_policy_bundle_id + " / receipt=" + .adoption_receipt_id' "$receipt_path")"

{
  printf '# Swarm Execution Queue Policy Adoption Receipt\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$receipt_path")"
  printf -- "- Receipt: \`%s\`\n" "$(jq -r '.adoption_receipt_id' "$receipt_path")"
  printf -- "- Bundle: \`%s\`\n" "$(jq -r '.adopted_policy_bundle_id' "$receipt_path")"
  printf -- "- Candidate: \`%s\`\n" "$(jq -r '.adopted_candidate.candidate_id' "$receipt_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n\n" "$(jq '.fail_closed_reasons | length' "$receipt_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$receipt_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$receipt_path"
    printf '\n'
  fi
  printf '## Evidence Links\n'
  jq -r '.evidence_links[] | "- `" + .artifact_kind + "` `" + .sha256 + "` " + .path' "$receipt_path"
} >"$report_path"

printf 'adoption_receipt_json=%s\n' "$receipt_path"
printf 'adoption_snapshot_bundle_json=%s\n' "$snapshot_path"
printf 'adoption_evidence_hashes_json=%s\n' "$evidence_hashes_path"
printf 'adoption_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$receipt_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
