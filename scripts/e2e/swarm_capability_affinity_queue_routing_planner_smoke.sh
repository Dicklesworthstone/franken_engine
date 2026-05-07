#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_capability_affinity_queue_routing_planner.sh"
docs_path="${root_dir}/docs/SWARM_CAPABILITY_AFFINITY_QUEUE_ROUTING_PLANNER.md"
contract_path="${root_dir}/docs/swarm_capability_affinity_queue_routing_planner_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_capability_affinity_queue_routing_planner/fixtures.json"
failures=0

record_pass() {
  printf 'PASS swarm-capability-affinity-queue-routing-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-capability-affinity-queue-routing-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh [check|selftest]
EOF
}

extract_fixture_input() {
  local scenario="$1"
  local input_id="$2"
  local output_path="$3"
  local is_null
  is_null="$(jq -r --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[] | select(.scenario_id == $scenario) | (.inputs[$input_id] == null)
  ' "$fixture_bundle_path")"
  if [[ "$is_null" == "true" ]]; then
    return 1
  fi
  jq --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[] | select(.scenario_id == $scenario) | .inputs[$input_id]
  ' "$fixture_bundle_path" >"$output_path"
}

materialize_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  mkdir -p "$dir"
  extract_fixture_input "$scenario" "worker_capability_toolchain_input_json" "${dir}/worker_capability_toolchain_input.json" || return 1
  extract_fixture_input "$scenario" "routing_outcome_samples_json" "${dir}/routing_outcome_samples.json" || true
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
    .schema_version == "franken-engine.swarm-capability-affinity-queue-routing-planner-contract.v1"
    and .bead_id == "bd-vp44k"
    and .parent_bead_id == "bd-lg2qn"
    and (.depends_on | index("bd-wplun") != null)
    and (.depends_on | index("bd-t58g5") != null)
    and (.depends_on | index("bd-7ayfz") != null)
    and (.depends_on | index("bd-ywibz") != null)
    and .script == "scripts/swarm_capability_affinity_queue_routing_planner.sh"
    and .smoke_script == "scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh"
    and .docs == "docs/SWARM_CAPABILITY_AFFINITY_QUEUE_ROUTING_PLANNER.md"
    and .fixture_bundle == "scripts/testdata/swarm_capability_affinity_queue_routing_planner/fixtures.json"
    and .advisory_schema_version == "franken-engine.capability-affinity-queue-routing-advisory.v1"
    and .source_schema_version == "franken-engine.capability-affinity-queue-routing-sources.v1"
    and (.required_inputs | length == 1)
    and (.optional_inputs | length == 1)
    and (.advisory_fields | index("worker_affinity_summary") != null)
    and (.advisory_fields | index("toolchain_parity_summary") != null)
    and (.advisory_fields | index("capability_coverage_summary") != null)
    and (.truth_states | index("contaminated") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and (.blocked_rules | map(test("toolchain fingerprint mismatch"; "i")) | any)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.reroutes_tasks_automatically == false
    and (.selftest_scenarios | index("blocked_missing_required_capability") != null)
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-capability-affinity-queue-routing-planner-fixtures.v1"
    and (.scenarios | length) == 5
    and any(.scenarios[]; .scenario_id == "healthy_confirmed" and .expected_routing_mode == "capability_affinity_confirmed")
    and any(.scenarios[]; .scenario_id == "degraded_missing_optional_support" and .expected_routing_mode == "broader_cohort_fallback")
    and any(.scenarios[]; .scenario_id == "blocked_toolchain_fingerprint_mismatch" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "blocked_missing_required_capability" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected_exit_code == 42)
  ' "$fixture_bundle_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local input_dir="$2"
  local output_dir="$3"
  local expected_decision expected_truth_state expected_exit_code expected_routing_mode
  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$fixture_bundle_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$fixture_bundle_path")"
  expected_routing_mode="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_routing_mode' "$fixture_bundle_path")"
  mkdir -p "$output_dir"
  local args=(
    --source-revision fixture-rev
    --worker-capability-toolchain-input-json "${input_dir}/worker_capability_toolchain_input.json"
    --output-dir "$output_dir"
  )
  [[ -f "${input_dir}/routing_outcome_samples.json" ]] && args+=(--routing-outcome-samples-json "${input_dir}/routing_outcome_samples.json")

  local code=0
  set +e
  bash "$planner" "${args[@]}" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" --arg truth_state "$expected_truth_state" --arg routing_mode "$expected_routing_mode" '
    .decision == $decision and .truth_state == $truth_state and .worker_affinity_summary.routing_mode == $routing_mode
  ' "${output_dir}/capability_affinity_queue_routing_advisory.json" >/dev/null || {
    record_failure "${scenario} decision, truth state, or routing mode mismatch"
    return 1
  }
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
  if fixtures_shape_ok; then
    record_pass "fixture bundle shape"
  else
    record_failure "fixture bundle shape mismatch"
  fi

  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'local fallback contamination fails closed' "$docs_path" || record_failure "docs must mention local fallback contamination"
  grep -Fq 'toolchain fingerprint mismatch blocks routing advice' "$docs_path" || record_failure "docs must mention toolchain mismatch blocking"
  grep -Fq 'broader_cohort_fallback' "$docs_path" || record_failure "docs must mention broader cohort fallback"
  grep -Fq 'rch workers capabilities --refresh --json' "$docs_path" || record_failure "docs must mention worker capability refresh evidence"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  local tmp_root scenario input_dir output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-capability-affinity-queue-routing-planner-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/in"
    output_dir="${tmp_root}/${scenario}/out"
    materialize_fixture_dir "$scenario" "$input_dir" || {
      record_failure "could not materialize fixture ${scenario}"
      continue
    }
    run_case "$scenario" "$input_dir" "$output_dir" || continue

    jq -e \
      --argjson expected_advised "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_advised_worker_ids' "$fixture_bundle_path")" \
      --argjson expected_reason_codes "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_reason_codes' "$fixture_bundle_path")" \
      --argjson expected_blocked "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_blocked_task_ids' "$fixture_bundle_path")" \
      '.worker_affinity_summary.advised_worker_ids == $expected_advised
       and ($expected_reason_codes - .reason_codes | length) == 0
       and ((.capability_coverage_summary.missing_required_capability_task_ids + .toolchain_parity_summary.toolchain_mismatch_task_ids) | unique) == $expected_blocked' \
      "${output_dir}/capability_affinity_queue_routing_advisory.json" >/dev/null || {
        record_failure "${scenario} advised workers, reason codes, or blocked task sets mismatch"
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
