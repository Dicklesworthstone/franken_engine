#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_topology_aware_queue_fidelity_ledger.sh"
docs_path="${root_dir}/docs/SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER.md"
contract_path="${root_dir}/docs/swarm_topology_aware_queue_fidelity_ledger_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json"
failures=0

record_pass() {
  printf 'PASS swarm-topology-aware-queue-fidelity-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-aware-queue-fidelity-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh [check|selftest]
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
  extract_fixture_input "$scenario" "queue_advisory_bundle_json" "${dir}/queue_advisory_bundle.json"
  extract_fixture_input "$scenario" "placement_evidence_ledger_json" "${dir}/placement_evidence_ledger.json"
  extract_fixture_input "$scenario" "queue_artifact_json" "${dir}/queue_artifact.json"
  extract_fixture_input "$scenario" "bottleneck_report_json" "${dir}/bottleneck_report.json"
  extract_fixture_input "$scenario" "locality_outcome_samples_json" "${dir}/locality_outcome_samples.json"
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'mutates remote workers|pins workers automatically|changes live queue policy automatically|updates beads automatically|releases reservations automatically|sends Agent Mail automatically|runs Cargo automatically|runs RCH automatically' "$path"; then
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
    .schema_version == "franken-engine.swarm-topology-aware-queue-fidelity-ledger-contract.v1"
    and .bead_id == "bd-q1zfn"
    and .parent_bead_id == "bd-2pn2x"
    and (.depends_on | index("bd-utk1x") != null)
    and (.depends_on | index("bd-cocup") != null)
    and .script == "scripts/swarm_topology_aware_queue_fidelity_ledger.sh"
    and .smoke_script == "scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh"
    and .docs == "docs/SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER.md"
    and .fixture_bundle == "scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json"
    and .receipt_schema_version == "franken-engine.swarm-topology-aware-queue-fidelity-receipt.v1"
    and .drift_ledger_schema_version == "franken-engine.swarm-topology-aware-queue-drift-ledger.v1"
    and .source_schema_version == "franken-engine.swarm-topology-aware-queue-fidelity-sources.v1"
    and (.required_inputs | length == 5)
    and (.reason_codes | index("cache_cold_no_reuse_credit") != null)
    and (.reason_codes | index("drained_worker_avoidance_confirmed") != null)
    and (.reason_codes | index("contradictory_receipt") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and (.selftest_scenarios | index("blocked_drained_worker_avoidance_failure") != null)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-aware-queue-fidelity-ledger-fixtures.v1"
    and (.scenarios | length) == 6
    and any(.scenarios[]; .scenario_id == "healthy_locality_match" and .expected_decision == "pass")
    and any(.scenarios[]; .scenario_id == "cache_cold_fallback_no_false_reuse_credit" and .expected_required_reason_code == "cache_cold_no_reuse_credit")
    and any(.scenarios[]; .scenario_id == "blocked_locality_drift" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "degraded_drained_worker_avoidance_success" and (.expected_drained_worker_avoidance_task_ids | index("bd-drain-ok") != null))
    and any(.scenarios[]; .scenario_id == "blocked_drained_worker_avoidance_failure" and (.expected_excluded_worker_violation_task_ids | index("bd-drain-bad") != null))
    and any(.scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected_exit_code == 42)
  ' "$fixture_bundle_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local input_dir="$2"
  local output_dir="$3"
  local expected_decision expected_truth_state expected_exit_code expected_required_reason_code expected_match_task_ids expected_cache_cold_task_ids expected_drift_task_ids expected_drain_success_task_ids expected_excluded_violation_task_ids expected_missing_task_ids

  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$fixture_bundle_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$fixture_bundle_path")"
  expected_required_reason_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_required_reason_code' "$fixture_bundle_path")"
  expected_match_task_ids="$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | (.expected_matched_task_ids // [])' "$fixture_bundle_path")"
  expected_cache_cold_task_ids="$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | (.expected_cache_cold_no_reuse_credit_task_ids // [])' "$fixture_bundle_path")"
  expected_drift_task_ids="$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | (.expected_locality_drift_task_ids // [])' "$fixture_bundle_path")"
  expected_drain_success_task_ids="$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | (.expected_drained_worker_avoidance_task_ids // [])' "$fixture_bundle_path")"
  expected_excluded_violation_task_ids="$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | (.expected_excluded_worker_violation_task_ids // [])' "$fixture_bundle_path")"
  expected_missing_task_ids="$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | (.expected_missing_outcome_task_ids // [])' "$fixture_bundle_path")"

  mkdir -p "$output_dir"
  local code=0
  set +e
  bash "$script_path" \
    --source-revision fixture-rev \
    --queue-advisory-bundle-json "${input_dir}/queue_advisory_bundle.json" \
    --placement-evidence-ledger-json "${input_dir}/placement_evidence_ledger.json" \
    --queue-artifact-json "${input_dir}/queue_artifact.json" \
    --bottleneck-report-json "${input_dir}/bottleneck_report.json" \
    --locality-outcome-samples-json "${input_dir}/locality_outcome_samples.json" \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi

  jq -e \
    --arg decision "$expected_decision" \
    --arg truth_state "$expected_truth_state" \
    --arg required_reason_code "$expected_required_reason_code" \
    --argjson expected_match_task_ids "$expected_match_task_ids" \
    --argjson expected_cache_cold_task_ids "$expected_cache_cold_task_ids" \
    --argjson expected_drift_task_ids "$expected_drift_task_ids" \
    --argjson expected_drain_success_task_ids "$expected_drain_success_task_ids" \
    --argjson expected_excluded_violation_task_ids "$expected_excluded_violation_task_ids" \
    --argjson expected_missing_task_ids "$expected_missing_task_ids" '
    .decision == $decision
    and .truth_state == $truth_state
    and (.reason_codes | index($required_reason_code) != null)
    and .matched_task_ids == $expected_match_task_ids
    and .cache_cold_no_reuse_credit_task_ids == $expected_cache_cold_task_ids
    and .locality_drift_task_ids == $expected_drift_task_ids
    and .drained_worker_avoidance_task_ids == $expected_drain_success_task_ids
    and .excluded_worker_violation_task_ids == $expected_excluded_violation_task_ids
    and .missing_outcome_task_ids == $expected_missing_task_ids
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
  ' "${output_dir}/swarm_topology_aware_queue_fidelity_receipt.json" >/dev/null || {
    record_failure "${scenario} fidelity receipt mismatch"
    return 1
  }
}

run_check() {
  bash -n "$script_path"
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

  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'Local fallback contamination fails closed.' "$docs_path" || record_failure "docs must mention local fallback contamination"
  grep -Fq 'Cache-cold fallback must not receive false cache-reuse credit.' "$docs_path" || record_failure "docs must mention cache-cold fallback truth"
  grep -Fq 'distinguish missing evidence from contradictory evidence' "$docs_path" || record_failure "docs must mention missing-versus-contradictory evidence"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  local tmp_root scenario input_dir output_dir

  tmp_root="${TMPDIR:-/tmp}/swarm-topology-aware-queue-fidelity-ledger/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/in"
    output_dir="${tmp_root}/${scenario}/out"
    materialize_fixture_dir "$scenario" "$input_dir"
    run_case "$scenario" "$input_dir" "$output_dir" || continue
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
