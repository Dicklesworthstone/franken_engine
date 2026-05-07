#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger="${root_dir}/scripts/swarm_capability_affinity_routing_outcome_ledger.sh"
docs_path="${root_dir}/docs/SWARM_CAPABILITY_AFFINITY_ROUTING_OUTCOME_LEDGER.md"
contract_path="${root_dir}/docs/swarm_capability_affinity_routing_outcome_ledger_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_capability_affinity_routing_outcome_ledger/fixtures.json"
failures=0

record_pass() {
  printf 'PASS swarm-capability-affinity-routing-outcome-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-capability-affinity-routing-outcome-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh [check|selftest]
EOF
}

extract_fixture_input() {
  local scenario="$1"
  local input_id="$2"
  local output_path="$3"
  jq --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[] | select(.scenario_id == $scenario) | .inputs[$input_id]
  ' "$fixture_bundle_path" >"$output_path"
}

materialize_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  mkdir -p "$dir"
  extract_fixture_input "$scenario" "capability_affinity_routing_advisory_json" "${dir}/advisory.json"
  extract_fixture_input "$scenario" "routing_outcome_samples_json" "${dir}/routing_outcomes.json"
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'mutates remote workers|changes live queue policy automatically|updates beads automatically|releases reservations automatically|sends Agent Mail automatically|runs Cargo automatically|runs RCH automatically|reroutes tasks automatically|repairs workers automatically' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
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
    .schema_version == "franken-engine.swarm-capability-affinity-routing-outcome-ledger-contract.v1"
    and .bead_id == "bd-wa7by"
    and .parent_bead_id == "bd-lg2qn"
    and (.depends_on | index("bd-vp44k") != null)
    and .script == "scripts/swarm_capability_affinity_routing_outcome_ledger.sh"
    and .smoke_script == "scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh"
    and .docs == "docs/SWARM_CAPABILITY_AFFINITY_ROUTING_OUTCOME_LEDGER.md"
    and .fixture_bundle == "scripts/testdata/swarm_capability_affinity_routing_outcome_ledger/fixtures.json"
    and .ledger_schema_version == "franken-engine.swarm-capability-affinity-routing-outcome-ledger.v1"
    and .source_schema_version == "franken-engine.swarm-capability-affinity-routing-outcome-sources.v1"
    and (.required_inputs | length == 2)
    and (.ledger_fields | index("task_outcomes") != null)
    and (.truth_states | index("contaminated") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and (.blocked_rules | map(test("toolchain drift"; "i")) | any)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and (.selftest_scenarios | index("blocked_capability_gap_receipt") != null)
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-capability-affinity-routing-outcome-ledger-fixtures.v1"
    and (.scenarios | length) == 5
    and any(.scenarios[]; .scenario_id == "successful_cohort_match" and .expected_exit_code == 0)
    and any(.scenarios[]; .scenario_id == "blocked_toolchain_drift_receipt" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "blocked_capability_gap_receipt" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected_exit_code == 42)
  ' "$fixture_bundle_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local input_dir="$2"
  local output_dir="$3"
  local expected_decision expected_truth_state expected_exit_code
  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$fixture_bundle_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$fixture_bundle_path")"
  mkdir -p "$output_dir"
  local code=0
  set +e
  bash "$ledger" \
    --source-revision fixture-rev \
    --capability-affinity-routing-advisory-json "${input_dir}/advisory.json" \
    --routing-outcome-samples-json "${input_dir}/routing_outcomes.json" \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" --arg truth_state "$expected_truth_state" '
    .decision == $decision and .truth_state == $truth_state
  ' "${output_dir}/swarm_capability_affinity_routing_outcome_ledger.json" >/dev/null || {
    record_failure "${scenario} decision or truth state mismatch"
    return 1
  }
}

run_check() {
  bash -n "$ledger"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixture_bundle_path"
  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  if fixtures_shape_ok; then
    record_pass "fixture bundle shape"
  else
    record_failure "fixture bundle shape mismatch"
  fi
  grep -Fq 'evidence-only and advisory-only' "$docs_path" || record_failure "docs must say evidence-only and advisory-only"
  grep -Fq 'local fallback contamination fails closed' "$docs_path" || record_failure "docs must mention local fallback contamination"
  grep -Fq 'toolchain drift receipts block the outcome ledger' "$docs_path" || record_failure "docs must mention toolchain drift blocking"
  grep -Fq 'rch workers capabilities --refresh --json' "$docs_path" || record_failure "docs must mention worker capability refresh evidence"
  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  local tmp_root scenario input_dir output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-capability-affinity-routing-outcome-ledger-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/in"
    output_dir="${tmp_root}/${scenario}/out"
    materialize_fixture_dir "$scenario" "$input_dir"
    run_case "$scenario" "$input_dir" "$output_dir" || continue
    jq -e \
      --argjson expected_matched "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_matched_task_ids' "$fixture_bundle_path")" \
      --argjson expected_blocked "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_blocked_task_ids' "$fixture_bundle_path")" \
      --argjson expected_reason_codes "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_reason_codes' "$fixture_bundle_path")" \
      '.matched_task_ids == $expected_matched
       and ((.capability_gap_task_ids + .toolchain_drift_task_ids) | unique) == $expected_blocked
       and ($expected_reason_codes - .reason_codes | length) == 0' \
      "${output_dir}/swarm_capability_affinity_routing_outcome_ledger.json" >/dev/null || {
        record_failure "${scenario} matched/blocked task sets or reason codes mismatch"
        continue
      }
    record_pass "selftest ${scenario}"
  done < <(jq -r '.scenarios[].scenario_id' "$fixture_bundle_path")
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
