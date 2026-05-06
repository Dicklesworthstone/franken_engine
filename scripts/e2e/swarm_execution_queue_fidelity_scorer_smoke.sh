#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scorer="${root_dir}/scripts/swarm_execution_queue_fidelity_scorer.sh"
normalizer="${root_dir}/scripts/swarm_execution_queue_hindsight_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_FIDELITY_SCORER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_fidelity_scorer_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_execution_queue/fidelity_scorer_fixtures.json"
normalizer_fixture_bundle_path="${root_dir}/scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json"
failures=0

normalizer_input_ids=(
  queue_artifact_json
  queue_run_manifest_json
  normalized_queue_input_json
  risk_budget_receipt_json
  bottleneck_report_json
  bead_status_snapshot_json
  bead_timing_snapshot_json
  owner_contact_snapshot_json
  reservation_friction_snapshot_json
  proof_outcome_snapshot_json
  checkpoint_restore_state_json
)

record_pass() {
  printf 'PASS swarm-execution-queue-fidelity-scorer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-fidelity-scorer %s\n' "$1" >&2
  failures=$((failures + 1))
}

rewrite_json() {
  local path="$1"
  local filter="$2"
  local tmp_path="${path}.tmp"
  jq "$filter" "$path" >"$tmp_path"
  mv "$tmp_path" "$path"
}

extract_normalizer_input() {
  local input_id="$1"
  local output_path="$2"

  jq -e \
    --arg input_id "$input_id" \
    '.scenarios[] | select(.scenario_id == "healthy") | .inputs[$input_id]' \
    "$normalizer_fixture_bundle_path" >"$output_path"
}

write_normalizer_inputs() {
  local dir="$1"
  local input_id

  mkdir -p "$dir"
  for input_id in "${normalizer_input_ids[@]}"; do
    extract_normalizer_input "$input_id" "${dir}/${input_id}.json"
  done
}

run_hindsight_normalizer() {
  local input_dir="$1"
  local output_dir="$2"

  mkdir -p "$output_dir"
  bash "$normalizer" \
    --queue-artifact-json "${input_dir}/queue_artifact_json.json" \
    --queue-run-manifest-json "${input_dir}/queue_run_manifest_json.json" \
    --normalized-queue-input-json "${input_dir}/normalized_queue_input_json.json" \
    --risk-budget-receipt-json "${input_dir}/risk_budget_receipt_json.json" \
    --bottleneck-report-json "${input_dir}/bottleneck_report_json.json" \
    --bead-status-snapshot-json "${input_dir}/bead_status_snapshot_json.json" \
    --bead-timing-snapshot-json "${input_dir}/bead_timing_snapshot_json.json" \
    --owner-contact-snapshot-json "${input_dir}/owner_contact_snapshot_json.json" \
    --reservation-friction-snapshot-json "${input_dir}/reservation_friction_snapshot_json.json" \
    --proof-outcome-snapshot-json "${input_dir}/proof_outcome_snapshot_json.json" \
    --checkpoint-restore-state-json "${input_dir}/checkpoint_restore_state_json.json" \
    --source-revision fixture-rev \
    --observation-epoch-seconds 1800000300 \
    --output-dir "$output_dir" >/dev/null
}

prepare_scorer_inputs() {
  local scenario="$1"
  local case_dir="$2"
  local input_dir="${case_dir}/normalizer-inputs"
  local hindsight_dir="${case_dir}/hindsight"

  write_normalizer_inputs "$input_dir"
  run_hindsight_normalizer "$input_dir" "$hindsight_dir"

  case "$scenario" in
    exact_match)
      ;;
    conservative_correct)
      rewrite_json "${hindsight_dir}/hindsight_report.json" '.decision = "degraded" | .rows[0].actual_outcome = "deferred" | .rows[0].fidelity_class = "justified_override" | .rows[0].drift_class = "restore_drift" | .rows[0].checkpoint_restore_outcome = "manual_review_blocked" | .rows[0].confidence_band = "medium" | .degraded_inputs = [{kind:"checkpoint_restore_attention",source:"checkpoint_restore_state_json",label:"bd-ready-a",detail:"manual_review_blocked"}]'
      ;;
    over_conservative)
      rewrite_json "${hindsight_dir}/hindsight_report.json" '.decision = "degraded" | .rows[0].recommended_first_action = "defer broad proof until brownout clears" | .rows[0].actual_outcome = "closed" | .rows[0].fidelity_class = "delayed_match" | .rows[0].drift_class = "timing_drift" | .rows[0].actual_start_delta_seconds = 4200 | .rows[0].confidence_band = "medium" | .degraded_inputs = [{kind:"timing_drift",source:"bead_timing_snapshot_json",label:"bd-ready-a",detail:"conservative advice delayed a successful close"}]'
      ;;
    stale_owner_miss)
      rewrite_json "${hindsight_dir}/hindsight_report.json" '.decision = "degraded" | .rows[0].owner_friction_outcome = "stale_owner_contact" | .rows[0].fidelity_class = "delayed_match" | .rows[0].drift_class = "ownership_drift" | .rows[0].confidence_band = "low" | .degraded_inputs = [{kind:"owner_friction",source:"owner_contact_snapshot_json",label:"bd-ready-a",detail:"stale_owner_contact"}]'
      ;;
    proof_brownout_miss)
      rewrite_json "${hindsight_dir}/hindsight_report.json" '.decision = "degraded" | .rows[0].proof_outcome = "brownout" | .rows[0].fidelity_class = "delayed_match" | .rows[0].drift_class = "proof_drift" | .rows[0].confidence_band = "low" | .degraded_inputs = [{kind:"proof_brownout",source:"proof_outcome_snapshot_json",label:"bd-ready-a",detail:"brownout"}]'
      ;;
    contradictory_evidence)
      rewrite_json "${hindsight_dir}/hindsight_report.json" '.rows[0].owner_identity.inconsistent = true | .rows[0].owner_identity.contact_owner = "AgentB"'
      ;;
    *)
      record_failure "unknown scorer scenario ${scenario}"
      return 1
      ;;
  esac
}

run_scorer_case() {
  local case_dir="$1"
  local output_dir="$2"
  local expected_code="$3"
  local code

  mkdir -p "$output_dir"
  set +e
  bash "$scorer" \
    --hindsight-report-json "${case_dir}/hindsight/hindsight_report.json" \
    --hindsight-input-json "${case_dir}/hindsight/hindsight_input.json" \
    --evidence-ledger-json "${case_dir}/hindsight/evidence_ledger.json" \
    --counterfactual-candidates-json "${case_dir}/hindsight/counterfactual_candidates.json" \
    --source-revision fixture-rev \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "expected scorer exit ${expected_code}, got ${code}"
    return 1
  fi
  if [[ ! -f "${output_dir}/fidelity_score_receipt.json" || ! -f "${output_dir}/drift_ledger.json" ]]; then
    record_failure "scorer did not emit receipt and drift ledger"
    return 1
  fi
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatic reopen is allowed|automatically reopens|runs br update|will run br update|br update .*--status|release_file_reservations|will release reservations|sends Agent Mail automatically|mutates remote workers|changes active queue automatically|automatic queue actuation is allowed' "$path"; then
    record_failure "${path#"$root_dir"/} contains live-mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-fidelity-scorer-contract.v1"
    and .bead_id == "bd-eiqk4"
    and .parent_bead_id == "bd-d5daf"
    and (.depends_on | index("bd-7s7ui") != null)
    and (.depends_on | index("bd-p5j9g") != null)
    and .script == "scripts/swarm_execution_queue_fidelity_scorer.sh"
    and .smoke_script == "scripts/e2e/swarm_execution_queue_fidelity_scorer_smoke.sh"
    and .upstream_normalizer == "scripts/swarm_execution_queue_hindsight_normalizer.sh"
    and .receipt_schema_version == "franken-engine.swarm-execution-queue-fidelity-score-receipt.v1"
    and .drift_ledger_schema_version == "franken-engine.swarm-execution-queue-drift-ledger.v1"
    and (.component_scores | index("proof_health_prediction_millionths") != null)
    and (.mismatch_classes | index("over_conservative") != null)
    and (.mismatch_classes | index("proof_brownout_miss") != null)
    and (.fail_closed_rules | map(test("contradictory owner")) | any)
    and (.degraded_rules | map(test("over-conservative")) | any)
    and (.selftest_scenarios | index("exact_match") != null)
    and (.selftest_scenarios | index("conservative_correct") != null)
    and (.selftest_scenarios | index("over_conservative") != null)
    and (.selftest_scenarios | index("stale_owner_miss") != null)
    and (.selftest_scenarios | index("proof_brownout_miss") != null)
    and (.selftest_scenarios | index("contradictory_evidence") != null)
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reopens_beads == false
    and .mutation_policy.rewrites_historical_outcomes == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_active_queue == false
  ' "$contract_path" >/dev/null
}

fixture_bundle_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-fidelity-scorer-fixtures.v1"
    and .source_fixture_bundle == "scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json"
    and (.scenarios | length) == 6
    and all(.scenarios[]; (.expected_mismatch_class | type) == "string" and (.expected_decision | type) == "string")
  ' "$fixture_bundle_path" >/dev/null
}

run_rch_policy_gate() {
  local scope_file output_dir
  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-execution-queue-fidelity-scope.XXXXXX")"
  output_dir="${SWARM_EXECUTION_QUEUE_FIDELITY_RCH_POLICY_ROOT:-${TMPDIR:-/tmp}/swarm-execution-queue-fidelity-rch-policy}"
  printf '%s\n' \
    "scripts/swarm_execution_queue_fidelity_scorer.sh" \
    "scripts/e2e/swarm_execution_queue_fidelity_scorer_smoke.sh" \
    "docs/SWARM_EXECUTION_QUEUE_FIDELITY_SCORER.md" \
    "docs/swarm_execution_queue_fidelity_scorer_contract_v1.json" \
    "scripts/testdata/swarm_execution_queue/fidelity_scorer_fixtures.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "$output_dir" \
    --scope-file "$scope_file" >/dev/null
}

run_check() {
  bash -n "$scorer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixture_bundle_path" "$normalizer_fixture_bundle_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  if fixture_bundle_shape_ok; then
    record_pass "checked-in fixture bundle shape"
  else
    record_failure "checked-in fixture bundle shape mismatch"
  fi

  while IFS= read -r referenced_path; do
    if [[ ! -e "${root_dir}/${referenced_path}" ]]; then
      record_failure "missing referenced path ${referenced_path}"
    fi
  done < <(jq -r '.script, .smoke_script, .docs, .fixture_bundle, .upstream_normalizer, .upstream_contract' "$contract_path")

  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'drift_ledger.json' "$docs_path" || record_failure "docs must mention drift ledger artifact"
  grep -Fq 'contradictory_evidence' "$docs_path" || record_failure "docs must mention contradictory-evidence fail-closed class"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$contract_path"
  run_rch_policy_gate || record_failure "rch policy scoped gate failed"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

run_selftest() {
  local tmp_parent tmp_root scenario case_dir output_dir expected_decision expected_class expected_code
  tmp_parent="${SWARM_EXECUTION_QUEUE_FIDELITY_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-fidelity.XXXXXX")"

  run_check

  while IFS= read -r scenario; do
    case_dir="${tmp_root}/${scenario}"
    output_dir="${case_dir}/scorer"
    prepare_scorer_inputs "$scenario" "$case_dir"
    expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
    expected_class="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_mismatch_class' "$fixture_bundle_path")"
    expected_code=0
    if [[ "$expected_decision" == "fail_closed" ]]; then
      expected_code=42
    fi

    run_scorer_case "$case_dir" "$output_dir" "$expected_code"
    jq -e \
      --arg expected_decision "$expected_decision" \
      --arg expected_class "$expected_class" '
        .decision == $expected_decision
        and .summary.row_count == 1
        and (.summary.fail_closed_reason_count >= (if $expected_decision == "fail_closed" then 1 else 0 end))
      ' "${output_dir}/fidelity_score_receipt.json" >/dev/null
    jq -e \
      --arg expected_class "$expected_class" '
        .rows[0].mismatch_class == $expected_class
        and (.rows[0].remediation | length) > 0
      ' "${output_dir}/drift_ledger.json" >/dev/null
    record_pass "${scenario} fixture scores as ${expected_class}"
  done < <(jq -r '.scenarios[].scenario_id' "$fixture_bundle_path")

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'swarm_execution_queue_fidelity_scorer_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
