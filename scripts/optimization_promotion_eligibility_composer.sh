#!/usr/bin/env bash
set -euo pipefail

artifact_root="${OPTIMIZATION_PROMOTION_ELIGIBILITY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-optimization-promotion-eligibility}"
run_id="${OPTIMIZATION_PROMOTION_ELIGIBILITY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${OPTIMIZATION_PROMOTION_ELIGIBILITY_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${OPTIMIZATION_PROMOTION_ELIGIBILITY_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/optimization_promotion_eligibility_composer.sh --input-json FILE [OPTIONS]

Compose a deterministic source-only optimization promotion plan from saved
evidence snapshots. The command never runs Cargo/RCH and never mutates runtime
policy, br, Agent Mail, reservations, workers, or benchmark claims.

Required:
  --input-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  optimization_promotion_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   plan emitted with pass decision
  42  stale, divergent, unsafe, unready, or contaminated evidence failed closed
  64  invalid input or arguments
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
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

if [[ -z "$input_json" ]]; then
  printf 'missing required --input-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "$input_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for optimization promotion eligibility composer\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for optimization promotion eligibility composer\n' >&2
  exit 2
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_json="${run_dir}/optimization_promotion_plan.json"
plan_json_tmp="${plan_json}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"
plan_hash="$input_hash"

printf './scripts/optimization_promotion_eligibility_composer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.optimization-promotion-eligibility.event.v1" \
    --arg trace_id "trace-optimization-promotion-eligibility-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    '{schema_version:$schema_version,trace_id:$trace_id,component:$component,event:$event,outcome:$outcome,error_code:(if $error_code == "" then null else $error_code end)}' \
    >>"$events_path"
}

write_event "optimization_promotion_eligibility_composer" "input_loaded" "captured" ""

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg plan_hash "$plan_hash" \
  --arg plan_json "$plan_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def src: $input[0];
  def evidence: (src.evidence // {});
  def failure($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def required_evidence_ids: [
    "real_hot_path_evidence",
    "proof_specialization_receipt",
    "semantic_parity",
    "rollback_health",
    "safe_mode_fallback",
    "performance_regression",
    "support_surface_truth"
  ];
  def missing_required:
    [required_evidence_ids[] as $id | select((evidence[$id] // null) == null) | $id];
  def stale_required:
    [required_evidence_ids[] as $id
      | evidence[$id]? as $item
      | select($item != null)
      | select(($item.freshness // "fresh") != "fresh")
      | $id];
  def has_synthetic:
    (src.contamination.synthetic_only // false) == true
    or any(required_evidence_ids[]; (evidence[.].synthetic_only // false) == true)
    or (evidence.real_hot_path_evidence.real_runtime_execution != true);
  (
    []
    + (if (src.contract_report.decision // null) != "pass" then [
        failure("FE-OPT-PROMO-CONTRACT-FAILED"; "optimization_promotion_control_contract";
          "promotion-control contract report is absent or not pass";
          "Run scripts/optimization_promotion_control_contract.sh and provide a passing report.")
      ] else [] end)
    + (missing_required
        | map(failure("FE-OPT-PROMO-MISSING-EVIDENCE"; .;
            "required promotion evidence is missing";
            "Provide this evidence family before composing a promotion plan.")))
    + (stale_required
        | map(failure("FE-OPT-PROMO-STALE-EVIDENCE"; .;
            "required promotion evidence is stale";
            "Refresh this evidence family before composing a promotion plan.")))
    + (if (src.expected_source_revision // src.source_revision // $source_revision) != (src.source_revision // $source_revision) then [
        failure("FE-OPT-PROMO-SOURCE-REVISION-MISMATCH"; "source_revision";
          "evidence source revision does not match expected source revision";
          "Regenerate evidence for the current source revision before promotion.")
      ] else [] end)
    + (if evidence.proof_specialization_receipt.proof_inputs_current != true then [
        failure("FE-OPT-PROMO-STALE-EVIDENCE"; "proof_specialization_receipt";
          "proof specialization receipt inputs are no longer current";
          "Regenerate proof-specialization receipts for the current policy/proof epoch.")
      ] else [] end)
    + (if (evidence.semantic_parity.outcome // "match") != "match" then [
        failure("FE-OPT-PROMO-SEMANTIC-DIVERGENCE"; "semantic_parity";
          "specialized and unspecialized behavior diverged";
          "Keep the candidate observed or demote it until semantic parity is restored.")
      ] else [] end)
    + (if evidence.performance_regression.tail_budget_ok != true then [
        failure("FE-OPT-PROMO-TAIL-REGRESSION"; "performance_regression";
          "candidate violates tail-latency budget";
          "Refresh or repair the candidate before promotion.")
      ] else [] end)
    + (if evidence.rollback_health.ready != true or evidence.safe_mode_fallback.ready != true then [
        failure("FE-OPT-PROMO-ROLLBACK-UNREADY"; "rollback_or_safe_mode";
          "rollback or safe-mode fallback is not ready";
          "Do not promote until rollback token and safe-mode replay evidence are available.")
      ] else [] end)
    + (if evidence.support_surface_truth.aligned != true then [
        failure("FE-OPT-PROMO-SUPPORT-TRUTH-DRIFT"; "support_surface_truth";
          "operator/support surface is not aligned with candidate state";
          "Truth the support surface before promotion.")
      ] else [] end)
    + (if has_synthetic then [
        failure("FE-OPT-PROMO-SYNTHETIC-CONTAMINATION"; "contamination";
          "synthetic-only or non-real-runtime evidence cannot support promotion";
          "Replace synthetic material with real runtime evidence or keep it fixture-scoped.")
      ] else [] end)
  ) as $failures
  | (
      if ($failures | length) > 0 then "fail_closed"
      elif (src.requested_state // "observe") == "pin"
        and (evidence.performance_regression.throughput_delta_millionths // 0) >= 250000
        and (evidence.cross_workload_transfer.confidence // "low") == "high"
      then "pin"
      elif (evidence.performance_regression.throughput_delta_millionths // 0) >= 100000
        and (evidence.cross_workload_transfer.confidence // "medium") != "low"
      then "promote"
      else "observe"
      end
    ) as $recommended_state
  | {
      schema_version: "franken-engine.optimization-promotion-plan.v1",
      bead_id: "bd-4j2ck",
      parent_bead_id: "bd-xg3d6",
      component: "optimization_promotion_eligibility_composer",
      source_revision: (src.source_revision // $source_revision),
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      plan_hash: $plan_hash,
      decision: (if ($failures | length) == 0 then "pass" else "fail_closed" end),
      recommended_state: $recommended_state,
      candidate: {
        candidate_id: (src.candidate.candidate_id // "unknown_candidate"),
        requested_state: (src.requested_state // "observe"),
        workload_regime: (src.candidate.workload_regime // "unknown"),
        source_paths: (src.candidate.source_paths // [])
      },
      side_conditions: {
        contract_report_passed: ((src.contract_report.decision // null) == "pass"),
        source_revision_aligned: ((src.expected_source_revision // src.source_revision // $source_revision) == (src.source_revision // $source_revision)),
        real_hot_path_evidence_fresh: ((evidence.real_hot_path_evidence.freshness // "missing") == "fresh"),
        proof_inputs_current: (evidence.proof_specialization_receipt.proof_inputs_current // false),
        semantic_parity_matched: ((evidence.semantic_parity.outcome // "missing") == "match"),
        tail_budget_ok: (evidence.performance_regression.tail_budget_ok // false),
        rollback_ready: (evidence.rollback_health.ready // false),
        safe_mode_ready: (evidence.safe_mode_fallback.ready // false),
        support_surface_aligned: (evidence.support_surface_truth.aligned // false),
        no_synthetic_contamination: (has_synthetic | not)
      },
      reason_codes: (
        if ($failures | length) > 0 then ($failures | map(.code))
        elif $recommended_state == "pin" then ["OPT_PROMO_PIN_ALL_SIDE_CONDITIONS_MET"]
        elif $recommended_state == "promote" then ["OPT_PROMO_PROMOTE_ALL_SIDE_CONDITIONS_MET"]
        else ["OPT_PROMO_OBSERVE_ONLY_INSUFFICIENT_TRANSFER_OR_DELTA"]
        end
      ),
      fail_closed_reasons: $failures,
      next_validation_commands: [
        {
          purpose: "focused promotion eligibility proof",
          command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_4j2ck CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --lib optimization_promotion -- --nocapture"
        }
      ],
      artifact_paths: {
        plan_json: $plan_json,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      },
      mutation_policy: {
        advisory_only: true,
        proof_only: true,
        fixture_fed_only: true,
        mutates_runtime_policy: false,
        mutates_br: false,
        sends_agent_mail: false,
        releases_reservations: false,
        runs_cargo: false,
        runs_rch: false,
        mutates_remote_workers: false,
        publishes_benchmark_claims: false
      }
    }
  ' >"$plan_json_tmp"
mv "$plan_json_tmp" "$plan_json"

jq -r '
  "# Optimization Promotion Plan\n\n"
  + "- Decision: `" + .decision + "`\n"
  + "- Recommended state: `" + .recommended_state + "`\n"
  + "- Candidate: `" + .candidate.candidate_id + "`\n"
  + "- Plan hash: `" + .plan_hash + "`\n"
  + "- Fail-closed reasons: `" + ((.fail_closed_reasons | length) | tostring) + "`\n\n"
  + "## Reason Codes\n"
  + (.reason_codes | map("- `" + . + "`") | join("\n"))
  + "\n\n## Next Validation Commands\n"
  + (.next_validation_commands | map("- `" + .command + "`") | join("\n"))
  + "\n"
' "$plan_json" >"$report_md"

decision="$(jq -r '.decision' "$plan_json")"
if [[ "$decision" == "pass" ]]; then
  write_event "optimization_promotion_eligibility_composer" "plan_emitted" "pass" ""
  exit 0
fi

first_error="$(jq -r '.fail_closed_reasons[0].code // "FE-OPT-PROMO-FAIL-CLOSED"' "$plan_json")"
write_event "optimization_promotion_eligibility_composer" "plan_emitted" "fail_closed" "$first_error"
exit 42
