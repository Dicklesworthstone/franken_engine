#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_topology_aware_queue_scorer.sh"
docs_path="${root_dir}/docs/SWARM_TOPOLOGY_AWARE_QUEUE_SCORER.md"
contract_path="${root_dir}/docs/swarm_topology_aware_queue_scorer_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_topology_aware_queue_scorer/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-topology-aware-queue-scorer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-aware-queue-scorer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh [check|selftest]
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
  local optional_input_id=""
  mkdir -p "$dir"
  extract_fixture_input "$scenario" "topology_queue_signal_input_json" "${dir}/topology_queue_signal_input.json"
  extract_fixture_input "$scenario" "proof_cache_locality_plan_json" "${dir}/proof_cache_locality_plan.json"
  extract_fixture_input "$scenario" "queue_artifact_json" "${dir}/queue_artifact.json"
  extract_fixture_input "$scenario" "bottleneck_report_json" "${dir}/bottleneck_report.json"
  extract_fixture_input "$scenario" "locality_outcome_samples_json" "${dir}/locality_outcome_samples.json"
  for optional_input_id in \
    "placement_adoption_history_json" \
    "operator_status_snapshot_json" \
    "resource_envelope_json" \
    "tail_latency_locality_json"
  do
    if jq -e --arg scenario "$scenario" --arg input_id "$optional_input_id" '
      .scenarios[]
      | select(.scenario_id == $scenario)
      | (.inputs[$input_id] != null)
    ' "$fixture_bundle_path" >/dev/null; then
      extract_fixture_input "$scenario" "$optional_input_id" "${dir}/${optional_input_id}.json"
    fi
  done
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
    .schema_version == "franken-engine.swarm-topology-aware-queue-scorer-contract.v1"
    and .bead_id == "bd-utk1x"
    and .parent_bead_id == "bd-2pn2x"
    and (.depends_on | index("bd-t58g5") != null)
    and (.depends_on | index("bd-wuj5w") != null)
    and .parent_contract == "docs/swarm_topology_aware_queue_advisory_contract_v1.json"
    and .script == "scripts/swarm_topology_aware_queue_scorer.sh"
    and .smoke_script == "scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh"
    and .docs == "docs/SWARM_TOPOLOGY_AWARE_QUEUE_SCORER.md"
    and .fixture_bundle == "scripts/testdata/swarm_topology_aware_queue_scorer/cases.json"
    and .advisory_schema_version == "franken-engine.swarm-topology-aware-queue-advisory.v1"
    and .source_schema_version == "franken-engine.swarm-topology-aware-queue-advisory-sources.v1"
    and (.required_inputs | length == 5)
    and (.optional_inputs | length == 4)
    and (.advisory_fields | index("worker_exclusions") != null)
    and (.advisory_fields | index("locality_bias_summary") != null)
    and (.advisory_fields | index("risk_budget_summary") != null)
    and (.advisory_fields | index("feedback_summary") != null)
    and (.reason_codes | index("drained_worker_excluded") != null)
    and (.reason_codes | index("cache_reuse_outcome_confirmed") != null)
    and (.reason_codes | index("cache_reuse_outcome_missed") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and (.selftest_scenarios | index("cache_reuse_feedback") != null)
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-aware-queue-scorer-fixtures.v1"
    and (.scenarios | length) == 6
    and any(.scenarios[]; .scenario_id == "healthy_confirmed" and .expected_decision == "pass" and .expected_rank_bias_mode == "prefer_hot_cache_locality")
    and any(.scenarios[]; .scenario_id == "degraded_missing_locality_support" and .expected_decision == "degraded")
    and any(.scenarios[]; .scenario_id == "blocked_contradictory_locality" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected_exit_code == 42)
    and any(.scenarios[]; .scenario_id == "drained_worker_exclusion" and (.expected_excluded_worker_ids | index("rch-e") != null))
    and any(.scenarios[]; .scenario_id == "cache_reuse_feedback" and .expected_feedback_reason_code == "cache_reuse_outcome_confirmed")
  ' "$fixture_bundle_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local input_dir="$2"
  local output_dir="$3"
  local expected_decision expected_truth_state expected_exit_code expected_rank_bias_mode expected_required_reason_code expected_feedback_reason_code
  local optional_input_id=""
  local optional_path=""
  local -a cmd

  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$fixture_bundle_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$fixture_bundle_path")"
  expected_rank_bias_mode="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_rank_bias_mode' "$fixture_bundle_path")"
  expected_required_reason_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_required_reason_code' "$fixture_bundle_path")"
  expected_feedback_reason_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_feedback_reason_code' "$fixture_bundle_path")"

  mkdir -p "$output_dir"
  cmd=(
    bash "$script_path"
    --source-revision fixture-rev
    --topology-queue-signal-input-json "${input_dir}/topology_queue_signal_input.json"
    --proof-cache-locality-plan-json "${input_dir}/proof_cache_locality_plan.json"
    --queue-artifact-json "${input_dir}/queue_artifact.json"
    --bottleneck-report-json "${input_dir}/bottleneck_report.json"
    --locality-outcome-samples-json "${input_dir}/locality_outcome_samples.json"
    --output-dir "$output_dir"
  )
  for optional_input_id in \
    "placement_adoption_history_json" \
    "operator_status_snapshot_json" \
    "resource_envelope_json" \
    "tail_latency_locality_json"
  do
    optional_path="${input_dir}/${optional_input_id}.json"
    if [[ -f "$optional_path" ]]; then
      case "$optional_input_id" in
        placement_adoption_history_json)
          cmd+=(--placement-adoption-history-json "$optional_path")
          ;;
        operator_status_snapshot_json)
          cmd+=(--operator-status-snapshot-json "$optional_path")
          ;;
        resource_envelope_json)
          cmd+=(--resource-envelope-json "$optional_path")
          ;;
        tail_latency_locality_json)
          cmd+=(--tail-latency-locality-json "$optional_path")
          ;;
      esac
    fi
  done
  local code=0
  set +e
  "${cmd[@]}" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi

  jq -e \
    --arg decision "$expected_decision" \
    --arg truth_state "$expected_truth_state" \
    --arg rank_bias_mode "$expected_rank_bias_mode" \
    --arg required_reason_code "$expected_required_reason_code" \
    --arg feedback_reason_code "$expected_feedback_reason_code" '
    .decision == $decision
    and .truth_state == $truth_state
    and .locality_bias_summary.rank_bias_mode == $rank_bias_mode
    and (.reason_codes | index($required_reason_code) != null)
    and (.reason_codes | index($feedback_reason_code) != null)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
  ' "${output_dir}/queue_advisory_bundle.json" >/dev/null || {
    record_failure "${scenario} advisory bundle mismatch"
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
  grep -Fq 'Drained or probe-required worker exclusions degrade advice' "$docs_path" || record_failure "docs must mention worker exclusion degradation"
  grep -Fq 'cache reuse misses degrade the advisory' "$docs_path" || record_failure "docs must mention cache reuse miss degradation"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  local tmp_root scenario input_dir output_dir expected_excluded

  tmp_root="${TMPDIR:-/tmp}/swarm-topology-aware-queue-scorer/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/in"
    output_dir="${tmp_root}/${scenario}/out"
    materialize_fixture_dir "$scenario" "$input_dir"
    run_case "$scenario" "$input_dir" "$output_dir" || continue

    expected_excluded="$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_excluded_worker_ids' "$fixture_bundle_path")"
    jq -e --argjson expected_excluded "$expected_excluded" '
      .worker_exclusions.excluded_worker_ids == $expected_excluded
    ' "${output_dir}/queue_advisory_bundle.json" >/dev/null || {
      record_failure "${scenario} excluded worker ids mismatch"
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
