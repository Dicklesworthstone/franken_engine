#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-policy-expiry-supersession}"
run_id="${SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_RUN_DIR:-${artifact_root}/${run_id}}"
generated_at="${SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
original_args=("$@")

adoption_receipt_json=""
sustained_gain_receipt_json=""
post_adoption_drift_ledger_json=""
newer_candidate_bundle_json=""
evidence_ownership_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh \
  --adoption-receipt-json FILE \
  --sustained-gain-receipt-json FILE \
  --post-adoption-drift-ledger-json FILE \
  --newer-candidate-bundle-json FILE \
  --evidence-ownership-json FILE \
  [--source-revision REV] \
  [--output-dir DIR]

Emits an advisory-only expiry and supersession plan for an adopted execution
queue policy. It never mutates br, Agent Mail, remote workers, live queue
settings, retirement state, supersession state, or historical outcomes.

Exit codes:
  0  plan completed; decision may be retain, expire, or supersede
  42 fail-closed due to stale, ambiguous, or contradictory evidence
  64 usage or missing tool/file errors
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --adoption-receipt-json)
      adoption_receipt_json="${2:-}"
      shift 2
      ;;
    --sustained-gain-receipt-json)
      sustained_gain_receipt_json="${2:-}"
      shift 2
      ;;
    --post-adoption-drift-ledger-json)
      post_adoption_drift_ledger_json="${2:-}"
      shift 2
      ;;
    --newer-candidate-bundle-json)
      newer_candidate_bundle_json="${2:-}"
      shift 2
      ;;
    --evidence-ownership-json)
      evidence_ownership_json="${2:-}"
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
  "$adoption_receipt_json" \
  "$sustained_gain_receipt_json" \
  "$post_adoption_drift_ledger_json" \
  "$newer_candidate_bundle_json" \
  "$evidence_ownership_json"; do
  if [[ -z "$required_arg" ]]; then
    printf 'all required expiry/supersession inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for expiry/supersession planning\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for expiry/supersession planning\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/expiry_supersession_plan.json"
ledger_path="${run_dir}/expiry_supersession_ledger.json"
evidence_hashes_path="${run_dir}/evidence_hashes.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
core_path="${run_dir}/expiry_supersession.core.json"

adoption_normalized="${run_dir}/adoption_receipt.normalized.json"
sustained_normalized="${run_dir}/sustained_gain_receipt.normalized.json"
drift_normalized="${run_dir}/post_adoption_drift_ledger.normalized.json"
candidate_normalized="${run_dir}/newer_candidate_bundle.normalized.json"
ownership_normalized="${run_dir}/evidence_ownership.normalized.json"

printf './scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-policy-expiry-supersession.event.v1" \
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
    printf 'required expiry/supersession input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required expiry/supersession input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$adoption_receipt_json" "$adoption_normalized" "adoption_receipt_json"
json_input "$sustained_gain_receipt_json" "$sustained_normalized" "sustained_gain_receipt_json"
json_input "$post_adoption_drift_ledger_json" "$drift_normalized" "post_adoption_drift_ledger_json"
json_input "$newer_candidate_bundle_json" "$candidate_normalized" "newer_candidate_bundle_json"
json_input "$evidence_ownership_json" "$ownership_normalized" "evidence_ownership_json"

adoption_sha="$(sha256sum "$adoption_receipt_json" | awk '{print $1}')"
sustained_sha="$(sha256sum "$sustained_gain_receipt_json" | awk '{print $1}')"
drift_sha="$(sha256sum "$post_adoption_drift_ledger_json" | awk '{print $1}')"
candidate_sha="$(sha256sum "$newer_candidate_bundle_json" | awk '{print $1}')"
ownership_sha="$(sha256sum "$evidence_ownership_json" | awk '{print $1}')"

jq -n \
  --arg source_revision "$source_revision" \
  --arg generated_at "$generated_at" \
  --arg adoption_receipt_json "$adoption_receipt_json" \
  --arg sustained_gain_receipt_json "$sustained_gain_receipt_json" \
  --arg post_adoption_drift_ledger_json "$post_adoption_drift_ledger_json" \
  --arg newer_candidate_bundle_json "$newer_candidate_bundle_json" \
  --arg evidence_ownership_json "$evidence_ownership_json" \
  --arg plan_path "$plan_path" \
  --arg ledger_path "$ledger_path" \
  --arg evidence_hashes_path "$evidence_hashes_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg adoption_sha "$adoption_sha" \
  --arg sustained_sha "$sustained_sha" \
  --arg drift_sha "$drift_sha" \
  --arg candidate_sha "$candidate_sha" \
  --arg ownership_sha "$ownership_sha" \
  --slurpfile adoption "$adoption_normalized" \
  --slurpfile sustained "$sustained_normalized" \
  --slurpfile drift "$drift_normalized" \
  --slurpfile candidate "$candidate_normalized" \
  --slurpfile ownership "$ownership_normalized" \
  '
    def nonempty($value): (($value // "") | length) > 0;
    def bad($kind; $source; $label; $detail): {kind:$kind,source:$source,label:$label,detail:$detail};
    def evidence($kind; $path; $sha): {artifact_kind:$kind,path:$path,sha256:$sha};
    def safe_mutation_policy($doc):
      (($doc.mutation_policy.changes_active_queue // false) == false)
      and (($doc.mutation_policy.applies_live_retuning // false) == false)
      and (($doc.mutation_policy.mutates_br // false) == false)
      and (($doc.mutation_policy.sends_agent_mail // false) == false)
      and (($doc.mutation_policy.mutates_remote_workers // false) == false)
      and (($doc.mutation_policy.rewrites_historical_outcomes // false) == false);
    def unsafe_claim($doc):
      (($doc.automation_claim // "none") | test("automatic|automatically|live retuning|changes active queue|retirement executed|supersession executed"))
      or (($doc.retirement_executed // false) == true)
      or (($doc.supersession_executed // false) == true)
      or (($doc.mutation_policy.retirement_executed // false) == true)
      or (($doc.mutation_policy.supersession_executed // false) == true);
    def rollback_relevant($row):
      (($row.rollback_relevant // false) == true)
      or (($row.drift_class // "") | IN("proof_drift", "ownership_drift", "restore_drift"))
      or (($row.mismatch_class // "") | IN("proof_brownout_miss", "stale_owner_miss", "contradictory_evidence"));

    ($adoption[0]) as $adoption_doc
    | ($sustained[0]) as $sustained_doc
    | ($drift[0]) as $drift_doc
    | ($candidate[0]) as $candidate_doc
    | ($ownership[0]) as $ownership_doc
    | ($adoption_doc.adopted_policy_bundle_id // "") as $adopted_bundle_id
    | ($adoption_doc.adopted_candidate.candidate_id // "") as $adopted_candidate_id
    | ($adoption_doc.adopted_candidate.expected_fidelity_delta_millionths // 0) as $adopted_delta
    | ($candidate_doc.bundle_id // "") as $newer_bundle_id
    | ($candidate_doc.promoted_candidate.candidate_id // "") as $newer_candidate_id
    | ($candidate_doc.promoted_candidate.expected_fidelity_delta_millionths // -1) as $newer_delta
    | ($candidate_doc.rollback_references.prior_policy_bundle_id // "") as $candidate_prior_bundle_id
    | ($drift_doc.drift_rows // []) as $drift_rows
    | ([$drift_rows[]? | select(rollback_relevant(.))]) as $rollback_rows
    | ($ownership_doc.rows // []) as $ownership_rows
    | ["adoption_receipt_json","sustained_gain_receipt_json","post_adoption_drift_ledger_json","newer_candidate_bundle_json"] as $required_owner_kinds
    | (
        (($candidate_doc.decision // "") | IN("pass", "degraded"))
        and nonempty($newer_bundle_id)
        and ($newer_bundle_id != $adopted_bundle_id)
        and nonempty($newer_candidate_id)
        and ($newer_delta > $adopted_delta)
        and safe_mutation_policy($candidate_doc)
        and (nonempty($candidate_prior_bundle_id) | not or $candidate_prior_bundle_id == $adopted_bundle_id)
      ) as $eligible_newer_candidate
    | [
        (if (($adoption_doc.schema_version // "") != "franken-engine.swarm-execution-queue-policy-adoption-receipt.v1") then bad("bad_schema";"adoption_receipt_json";"schema_version";"unexpected adoption receipt schema") else empty end),
        (if (($sustained_doc.schema_version // "") != "franken-engine.swarm-execution-queue-policy-sustained-gain-receipt.v1") then bad("bad_schema";"sustained_gain_receipt_json";"schema_version";"unexpected sustained-gain receipt schema") else empty end),
        (if (($drift_doc.schema_version // "") != "franken-engine.swarm-execution-queue-post-adoption-drift-ledger.v1") then bad("bad_schema";"post_adoption_drift_ledger_json";"schema_version";"unexpected post-adoption drift ledger schema") else empty end),
        (if (($candidate_doc.schema_version // "") != "franken-engine.swarm-execution-queue-tuning-policy-bundle.v1") then bad("bad_schema";"newer_candidate_bundle_json";"schema_version";"unexpected tuning policy bundle schema") else empty end),
        (if (($ownership_doc.schema_version // "") != "franken-engine.swarm-execution-queue-policy-evidence-ownership.v1") then bad("bad_schema";"evidence_ownership_json";"schema_version";"unexpected evidence ownership schema") else empty end),
        (if (($adoption_doc.decision // "") == "admitted") then empty else bad("adoption_not_admitted";"adoption_receipt_json";"decision";"adoption receipt must be admitted before expiry planning") end),
        (if (($sustained_doc.verdict // "") == "fail_closed") then bad("upstream_fail_closed";"sustained_gain_receipt_json";"verdict";"sustained-gain receipt already failed closed") else empty end),
        (if (($sustained_doc.adopted_policy_bundle_id // "") == $adopted_bundle_id and ($sustained_doc.candidate_id // "") == $adopted_candidate_id) then empty else bad("adoption_sustained_identity_mismatch";"sustained_gain_receipt_json";$adopted_bundle_id;"sustained-gain receipt identity does not match adoption receipt") end),
        (if (nonempty($candidate_prior_bundle_id) and $candidate_prior_bundle_id != $adopted_bundle_id) then bad("candidate_prior_policy_conflict";"newer_candidate_bundle_json";$candidate_prior_bundle_id;"candidate bundle prior policy does not match adopted policy") else empty end),
        (if all($required_owner_kinds[]; . as $kind | any($ownership_rows[]?; (.artifact_kind // "") == $kind)) then empty else bad("missing_evidence_ownership";"evidence_ownership_json";"rows";"required artifact ownership rows are missing") end),
        ([ $ownership_rows[]? | select((.ambiguous_owner // false) == true or ((.owners // []) | length) != 1) | bad("ambiguous_evidence_ownership";"evidence_ownership_json";(.artifact_kind // "unknown");"evidence ownership is ambiguous") ][]?),
        ([ $ownership_rows[]? | select((.freshness_state // "fresh") != "fresh" or (.trust_state // "accepted") != "accepted") | bad("stale_or_rejected_evidence_ownership";"evidence_ownership_json";(.artifact_kind // "unknown");"evidence ownership row is stale or rejected") ][]?),
        (if safe_mutation_policy($adoption_doc) and safe_mutation_policy($sustained_doc) and safe_mutation_policy($drift_doc) and safe_mutation_policy($candidate_doc) then empty else bad("unsafe_mutation_policy";"inputs";"mutation_policy";"inputs must not claim live mutation authority") end),
        (if unsafe_claim($adoption_doc) or unsafe_claim($sustained_doc) or unsafe_claim($drift_doc) or unsafe_claim($candidate_doc) or unsafe_claim($ownership_doc) then bad("unsafe_execution_claim";"inputs";"automation_claim";"inputs must not claim automatic retuning or executed retirement") else empty end)
      ] as $fail_closed_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($eligible_newer_candidate == true) then "supersede_adopted_policy"
       elif (($sustained_doc.verdict // "") == "regression_detected") or (($rollback_rows | length) > 0) then "expire_adopted_policy"
       else "retain_adopted_policy"
       end) as $decision
    | [
        (if (($sustained_doc.verdict // "") == "regression_detected") then {kind:"sustained_gain_regression",detail:"sustained-gain receipt reports regression"} else empty end),
        (if (($rollback_rows | length) > 0) then {kind:"rollback_relevant_drift",detail:"post-adoption drift ledger contains rollback-relevant rows"} else empty end),
        (if ($eligible_newer_candidate == true) then {kind:"newer_candidate_available",detail:"newer candidate bundle improves expected fidelity delta"} else empty end),
        (if ($decision == "retain_adopted_policy" and (($sustained_doc.verdict // "") == "sustained_gain")) then {kind:"sustained_gain_retained",detail:"sustained-gain evidence supports retention"} else empty end),
        (if ($decision == "retain_adopted_policy" and (($sustained_doc.verdict // "") == "inconclusive_drift")) then {kind:"inconclusive_retention",detail:"post-adoption evidence is inconclusive and no superior newer candidate is eligible"} else empty end)
      ] as $decision_reasons
    | [
        evidence("adoption_receipt_json"; $adoption_receipt_json; $adoption_sha),
        evidence("sustained_gain_receipt_json"; $sustained_gain_receipt_json; $sustained_sha),
        evidence("post_adoption_drift_ledger_json"; $post_adoption_drift_ledger_json; $drift_sha),
        evidence("newer_candidate_bundle_json"; $newer_candidate_bundle_json; $candidate_sha),
        evidence("evidence_ownership_json"; $evidence_ownership_json; $ownership_sha)
      ] as $evidence_links
    | {
        evidence_hashes:{
          schema_version:"franken-engine.swarm-execution-queue-policy-expiry-supersession-evidence-hashes.v1",
          source_revision:$source_revision,
          evidence_links:$evidence_links
        },
        expiry_supersession_plan:{
          schema_version:"franken-engine.swarm-execution-queue-policy-expiry-supersession-plan.v1",
          plan_id:"pending",
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          adopted_policy_bundle_id:$adopted_bundle_id,
          adoption_receipt_id:($adoption_doc.adoption_receipt_id // ""),
          adopted_candidate_id:$adopted_candidate_id,
          adopted_expected_delta_millionths:$adopted_delta,
          sustained_gain_receipt_id:($sustained_doc.sustained_gain_receipt_id // ""),
          sustained_gain_verdict:($sustained_doc.verdict // "unknown"),
          rollback_relevant_drift_count:($rollback_rows | length),
          newer_candidate_bundle_id:$newer_bundle_id,
          newer_candidate_id:$newer_candidate_id,
          newer_expected_delta_millionths:$newer_delta,
          expiry_required:($decision == "expire_adopted_policy" or $decision == "supersede_adopted_policy"),
          supersession_required:($decision == "supersede_adopted_policy"),
          advisory_status:{
            planning_artifact_only:true,
            execution_state:"advisory_not_executed",
            retirement_executed:false,
            supersession_executed:false,
            execution_evidence:"not supplied"
          },
          decision_reasons:$decision_reasons,
          fail_closed_reasons:$fail_closed_reasons,
          evidence_links:$evidence_links,
          mutation_policy:{
            planning_artifact_only:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false,
            retirement_executed:false,
            supersession_executed:false
          },
          artifact_paths:{
            expiry_supersession_plan_json:$plan_path,
            expiry_supersession_ledger_json:$ledger_path,
            evidence_hashes_json:$evidence_hashes_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            report_md:$report_path
          }
        },
        expiry_supersession_ledger:{
          schema_version:"franken-engine.swarm-execution-queue-policy-expiry-supersession-ledger.v1",
          source_revision:$source_revision,
          generated_at:$generated_at,
          decision:$decision,
          ledger_rows:[
            {
              check:"sustained_gain_verdict",
              observed_value:($sustained_doc.verdict // "unknown"),
              effect:(if (($sustained_doc.verdict // "") == "regression_detected") then "expiry_pressure" elif (($sustained_doc.verdict // "") == "sustained_gain") then "retention_support" else "retention_pending_more_evidence" end)
            },
            {
              check:"newer_candidate_delta",
              observed_value:($newer_delta | tostring),
              adopted_value:($adopted_delta | tostring),
              effect:(if $eligible_newer_candidate then "supersession_pressure" else "no_supersession_pressure" end)
            },
            {
              check:"rollback_relevant_drift_count",
              observed_value:(($rollback_rows | length) | tostring),
              effect:(if (($rollback_rows | length) > 0) then "expiry_pressure" else "no_expiry_pressure" end)
            }
          ],
          ownership_rows:($ownership_rows | map({
            artifact_kind:(.artifact_kind // "unknown"),
            owner:(.owners[0] // .owner // "unknown"),
            trust_state:(.trust_state // "unknown"),
            freshness_state:(.freshness_state // "unknown"),
            ambiguous_owner:(.ambiguous_owner // false)
          }) | sort_by(.artifact_kind)),
          fail_closed_reasons:$fail_closed_reasons,
          evidence_links:$evidence_links,
          mutation_policy:{
            planning_artifact_only:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false,
            retirement_executed:false,
            supersession_executed:false
          }
        }
      }
  ' >"$core_path"

jq '.evidence_hashes' "$core_path" >"$evidence_hashes_path"
jq '.expiry_supersession_plan' "$core_path" >"$plan_path"
jq '.expiry_supersession_ledger' "$core_path" >"$ledger_path"

plan_id="queue-policy-expiry-supersession-$(jq -cS 'del(.plan_id)' "$plan_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_plan="${plan_path}.tmp"
jq --arg plan_id "$plan_id" '.plan_id = $plan_id' "$plan_path" >"$tmp_plan"
mv "$tmp_plan" "$plan_path"

write_event "expiry_supersession.written" "$(jq -r '.decision + " / bundle=" + .adopted_policy_bundle_id + " / plan=" + .plan_id' "$plan_path")"

{
  printf '# Swarm Execution Queue Policy Expiry Supersession\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$plan_path")"
  printf -- "- Plan: \`%s\`\n" "$(jq -r '.plan_id' "$plan_path")"
  printf -- "- Adopted bundle: \`%s\`\n" "$(jq -r '.adopted_policy_bundle_id' "$plan_path")"
  printf -- "- Newer candidate bundle: \`%s\`\n" "$(jq -r '.newer_candidate_bundle_id' "$plan_path")"
  printf -- "- Expiry required: \`%s\`\n" "$(jq '.expiry_required' "$plan_path")"
  printf -- "- Supersession required: \`%s\`\n" "$(jq '.supersession_required' "$plan_path")"
  printf -- "- Execution state: \`%s\`\n" "$(jq -r '.advisory_status.execution_state' "$plan_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n\n" "$(jq '.fail_closed_reasons | length' "$plan_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$plan_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$plan_path"
    printf '\n'
  fi
  printf '## Decision Reasons\n'
  jq -r '.decision_reasons[]? | "- `" + .kind + "`: " + .detail' "$plan_path"
  printf '\n## Ledger Rows\n'
  jq -r '.ledger_rows[]? | "- `" + .check + "` effect=`" + .effect + "` value=`" + .observed_value + "`"' "$ledger_path"
} >"$report_path"

printf 'expiry_supersession_plan_json=%s\n' "$plan_path"
printf 'expiry_supersession_ledger_json=%s\n' "$ledger_path"
printf 'expiry_supersession_evidence_hashes_json=%s\n' "$evidence_hashes_path"
printf 'expiry_supersession_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$plan_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
