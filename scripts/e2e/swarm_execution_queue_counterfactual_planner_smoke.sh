#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_execution_queue_counterfactual_planner.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_PLANNER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_counterfactual_planner_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_execution_queue/counterfactual_planner_fixtures.json"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-counterfactual-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-counterfactual-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

write_case_inputs() {
  local dir="$1"
  local scenario="$2"
  local rows_json='[]'

  mkdir -p "$dir"
  case "$scenario" in
    no_improvement)
      rows_json='[{"task_id":"bd-ready-a","mismatch_class":"exact_match","row_score_millionths":1000000,"source_row":{"actual_outcome":"closed"}}]'
      ;;
    one_clear_improvement)
      rows_json='[{"task_id":"bd-ready-a","mismatch_class":"over_conservative","row_score_millionths":760000,"source_row":{"actual_outcome":"closed"}}]'
      ;;
    conflicting_improvements)
      rows_json='[{"task_id":"bd-ready-a","mismatch_class":"over_conservative","row_score_millionths":760000,"source_row":{"actual_outcome":"closed"}},{"task_id":"bd-ready-b","mismatch_class":"proof_brownout_miss","row_score_millionths":480000,"source_row":{"actual_outcome":"started"}}]'
      ;;
    insufficient_evidence)
      rows_json='[{"task_id":"bd-ready-a","mismatch_class":"missing_outcome","row_score_millionths":320000,"source_row":{"actual_outcome":"not_observed"}}]'
      ;;
    incomplete_evidence_fail_closed)
      rows_json='[{"task_id":"bd-ready-a","mismatch_class":"exact_match","source_row":{"auto_apply":true}}]'
      ;;
    *)
      record_failure "unknown scenario ${scenario}"
      return 1
      ;;
  esac

  jq -n \
    --arg scenario "$scenario" \
    --argjson rows "$rows_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-drift-ledger.v1",
      source_revision:"fixture-rev",
      decision:"pass",
      rows:$rows,
      fail_closed_reasons:[],
      degraded_inputs:[]
    }' >"${dir}/drift_ledger.json"

  jq -n \
    --arg scenario "$scenario" \
    --argjson rows "$rows_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-fidelity-score-receipt.v1",
      source_revision:"fixture-rev",
      decision:"pass",
      overall_fidelity_millionths: (if $scenario == "no_improvement" then 1000000 elif $scenario == "incomplete_evidence_fail_closed" then 900000 else 600000 end),
      confidence_band: (if $scenario == "no_improvement" then "high" else "medium" end),
      summary:{
        row_count:($rows | length),
        fail_closed_reason_count:0,
        degraded_input_count:(if $scenario == "no_improvement" then 0 else 1 end)
      },
      artifact_paths:{}
    }' >"${dir}/fidelity_score_receipt.json"
}

run_planner_case() {
  local input_dir="$1"
  local output_dir="$2"
  local expected_code="$3"
  local code

  mkdir -p "$output_dir"
  set +e
  bash "$planner" \
    --fidelity-score-receipt-json "${input_dir}/fidelity_score_receipt.json" \
    --drift-ledger-json "${input_dir}/drift_ledger.json" \
    --source-revision fixture-rev \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "expected planner exit ${expected_code}, got ${code}"
    return 1
  fi
  if [[ ! -f "${output_dir}/tuning_plan.json" || ! -f "${output_dir}/frontier.json" ]]; then
    record_failure "planner did not emit tuning plan and frontier"
    return 1
  fi
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatic reopen is allowed|automatically reopens|runs br update|will run br update|br update .*--status|release_file_reservations|will release reservations|sends Agent Mail automatically|mutates remote workers|changes active queue automatically|automatic queue actuation is allowed|apply retuning automatically' "$path"; then
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
    .schema_version == "franken-engine.swarm-execution-queue-counterfactual-planner-contract.v1"
    and .bead_id == "bd-mp7x3"
    and .parent_bead_id == "bd-d5daf"
    and (.depends_on | index("bd-p5j9g") != null)
    and (.depends_on | index("bd-eiqk4") != null)
    and .script == "scripts/swarm_execution_queue_counterfactual_planner.sh"
    and .smoke_script == "scripts/e2e/swarm_execution_queue_counterfactual_planner_smoke.sh"
    and .upstream_scorer == "scripts/swarm_execution_queue_fidelity_scorer.sh"
    and (.plan_classes | index("one_clear_improvement") != null)
    and (.candidate_ids | index("raise_proof_health_penalty") != null)
    and (.fail_closed_rules | map(test("automatic live-retuning")) | any)
    and (.selftest_scenarios | index("no_improvement") != null)
    and (.selftest_scenarios | index("one_clear_improvement") != null)
    and (.selftest_scenarios | index("conflicting_improvements") != null)
    and (.selftest_scenarios | index("insufficient_evidence") != null)
    and (.selftest_scenarios | index("incomplete_evidence_fail_closed") != null)
    and .mutation_policy.mutates_br == false
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.rewrites_historical_outcomes == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null
}

fixture_bundle_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-counterfactual-planner-fixtures.v1"
    and (.scenarios | length) == 5
    and all(.scenarios[]; (.expected_decision | type) == "string" and (.expected_plan_class | type) == "string")
  ' "$fixture_bundle_path" >/dev/null
}

run_rch_policy_gate() {
  local scope_file output_dir
  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-execution-queue-counterfactual-scope.XXXXXX")"
  output_dir="${SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_RCH_POLICY_ROOT:-${TMPDIR:-/tmp}/swarm-execution-queue-counterfactual-rch-policy}"
  printf '%s\n' \
    "scripts/swarm_execution_queue_counterfactual_planner.sh" \
    "scripts/e2e/swarm_execution_queue_counterfactual_planner_smoke.sh" \
    "docs/SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_PLANNER.md" \
    "docs/swarm_execution_queue_counterfactual_planner_contract_v1.json" \
    "scripts/testdata/swarm_execution_queue/counterfactual_planner_fixtures.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "$output_dir" \
    --scope-file "$scope_file" >/dev/null
}

run_check() {
  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixture_bundle_path"

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
  done < <(jq -r '.script, .smoke_script, .docs, .fixture_bundle, .upstream_scorer, .upstream_contract' "$contract_path")

  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'frontier.json' "$docs_path" || record_failure "docs must mention frontier artifact"
  grep -Fq 'apply retuning automatically' "$docs_path" || record_failure "docs must reject automatic retuning"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$contract_path"
  run_rch_policy_gate || record_failure "rch policy scoped gate failed"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

run_selftest() {
  local tmp_parent tmp_root scenario input_dir output_dir expected_decision expected_class expected_code
  tmp_parent="${SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-counterfactual.XXXXXX")"

  run_check

  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/inputs"
    output_dir="${tmp_root}/${scenario}/out"
    write_case_inputs "$input_dir" "$scenario"
    expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
    expected_class="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_plan_class' "$fixture_bundle_path")"
    expected_code=0
    if [[ "$expected_decision" == "fail_closed" ]]; then
      expected_code=42
    fi
    run_planner_case "$input_dir" "$output_dir" "$expected_code"
    jq -e \
      --arg expected_decision "$expected_decision" \
      --arg expected_class "$expected_class" \
      '.decision == $expected_decision and .plan_class == $expected_class and (.ranked_candidates | length) >= 1' \
      "${output_dir}/tuning_plan.json" >/dev/null
    jq -e '.frontier | type == "array" and length >= 1' "${output_dir}/frontier.json" >/dev/null
    record_pass "${scenario} fixture produces ${expected_class}"
  done < <(jq -r '.scenarios[].scenario_id' "$fixture_bundle_path")

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'swarm_execution_queue_counterfactual_planner_smoke_artifacts=%s\n' "$tmp_root"
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
