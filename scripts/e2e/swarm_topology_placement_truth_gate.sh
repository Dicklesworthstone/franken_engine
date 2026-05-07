#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${SWARM_TOPOLOGY_PLACEMENT_DRILL_CONTRACT_PATH:-${root_dir}/docs/swarm_topology_placement_no_mock_drill_contract_v1.json}"
drill_path="${root_dir}/scripts/e2e/swarm_topology_placement_no_mock_drill.sh"
failures=0

record_pass() {
  printf 'PASS swarm-topology-placement-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-placement-truth-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_placement_truth_gate.sh [check|selftest]
EOF
}

required_repo_paths=(
  scripts/swarm_topology_placement_normalizer.sh
  scripts/swarm_topology_placement_planner.sh
  scripts/swarm_topology_placement_receipt_ledger.sh
  scripts/swarm_operator_status_report.sh
  scripts/e2e/swarm_topology_placement_no_mock_drill.sh
  scripts/e2e/swarm_topology_placement_truth_gate.sh
  scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json
  docs/swarm_topology_placement_no_mock_drill_contract_v1.json
)

assert_contract_shape() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-placement-no-mock-drill-contract.v1"
    and .bead_id == "bd-2r3eq"
    and .drill_script == "scripts/e2e/swarm_topology_placement_no_mock_drill.sh"
    and .truth_gate_script == "scripts/e2e/swarm_topology_placement_truth_gate.sh"
    and (.composed_scripts | index("scripts/swarm_topology_placement_normalizer.sh") != null)
    and (.composed_scripts | index("scripts/swarm_topology_placement_planner.sh") != null)
    and (.composed_scripts | index("scripts/swarm_topology_placement_receipt_ledger.sh") != null)
    and (.composed_scripts | index("scripts/swarm_operator_status_report.sh") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json") != null)
    and (.required_artifact_references | index("swarm_topology_placement_input.json") != null)
    and (.required_artifact_references | index("swarm_topology_placement_plan.json") != null)
    and (.required_artifact_references | index("swarm_topology_placement_receipt.json") != null)
    and (.required_artifact_references | index("swarm_topology_placement_evidence_ledger.json") != null)
    and (.required_artifact_references | index("status.json") != null)
    and any(.drill_scenarios[]; .scenario_id == "healthy_confirmed" and .expected.operator_topology_readiness == "ready" and .expected.plan_decision == "pass")
    and any(.drill_scenarios[]; .scenario_id == "degraded_missing_cache_residency" and .expected.operator_topology_readiness == "degraded" and .expected.plan_decision == "degraded")
    and any(.drill_scenarios[]; .scenario_id == "blocked_contradictory_locality" and .expected.operator_topology_readiness == "blocked" and .expected.plan_decision == "blocked")
    and any(.drill_scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected.operator_topology_readiness == "contaminated" and .expected.plan_decision == "fail_closed")
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_live_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.rebinds_hosts_automatically == false
    and .mutation_policy.treats_missing_topology_as_healthy == false
    and .mutation_policy.treats_missing_cache_evidence_as_healthy == false
    and (.required_truth_gate_rejections | index("heavy_cargo_or_rch_claim") != null)
    and (.required_truth_gate_rejections | index("live_worker_or_queue_mutation_claim") != null)
    and (.required_truth_gate_rejections | index("automatic_worker_pinning_or_host_rebinding_claim") != null)
    and (.required_truth_gate_rejections | index("missing_topology_or_cache_evidence_is_healthy_claim") != null)
    and (.verification_commands | index("bash scripts/e2e/swarm_topology_placement_no_mock_drill.sh selftest") != null)
    and (.verification_commands | index("bash scripts/e2e/swarm_topology_placement_truth_gate.sh selftest") != null)
  ' "$contract_path" >/dev/null
}

assert_required_paths() {
  local path
  for path in "${required_repo_paths[@]}"; do
    if [[ ! -e "${root_dir}/${path}" ]]; then
      record_failure "missing required path: ${path}"
    fi
  done
}

claim_is_negated() {
  local claim_lc="$1"
  [[ "$claim_lc" == *"does not"* || "$claim_lc" == *"must not"* || "$claim_lc" == *"cannot"* || "$claim_lc" == *"never"* || "$claim_lc" == *"reject"* || "$claim_lc" == *"forbid"* ]]
}

assert_truth_claims() {
  local claim claim_lc
  while IFS= read -r claim; do
    [[ -n "$claim" ]] || continue
    claim_lc="$(printf '%s' "$claim" | tr '[:upper:]' '[:lower:]')"

    if [[ "$claim_lc" == *"runs heavy cargo"* || "$claim_lc" == *"runs cargo"* || "$claim_lc" == *"runs rch"* || "$claim_lc" == *"executes rch"* ]]; then
      if ! claim_is_negated "$claim_lc"; then
        record_failure "heavy Cargo or RCH claim must be rejected: ${claim}"
      fi
    fi
    if [[ "$claim_lc" == *"mutates live workers"* || "$claim_lc" == *"changes live queue policy"* || "$claim_lc" == *"mutates queue policy"* ]]; then
      if ! claim_is_negated "$claim_lc"; then
        record_failure "live worker or queue mutation claim must be rejected: ${claim}"
      fi
    fi
    if [[ "$claim_lc" == *"pins workers automatically"* || "$claim_lc" == *"rebinds hosts automatically"* || "$claim_lc" == *"automatic worker pinning"* || "$claim_lc" == *"automatic host rebinding"* ]]; then
      if ! claim_is_negated "$claim_lc"; then
        record_failure "automatic pinning or rebinding claim must be rejected: ${claim}"
      fi
    fi
    if [[ "$claim_lc" == *"missing topology"* && "$claim_lc" == *"healthy"* ]]; then
      if ! claim_is_negated "$claim_lc"; then
        record_failure "missing topology healthy-by-default claim must be rejected: ${claim}"
      fi
    fi
    if [[ "$claim_lc" == *"missing cache"* && "$claim_lc" == *"healthy"* ]]; then
      if ! claim_is_negated "$claim_lc"; then
        record_failure "missing cache healthy-by-default claim must be rejected: ${claim}"
      fi
    fi
  done < <(jq -r '.operator_truth_claims[]?' "$contract_path")
}

assert_verification_commands_are_lightweight() {
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "truth contract must not advertise heavy Cargo in drill verification: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "truth contract must not advertise RCH in drill verification: ${command}"
    fi
  done < <(jq -r '.verification_commands[]?' "$contract_path")
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  jq empty "$contract_path" >/dev/null

  if assert_contract_shape; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  assert_required_paths
  assert_truth_claims
  assert_verification_commands_are_lightweight

  if [[ "$failures" -eq 0 ]]; then
    record_pass "truth claims and artifact references"
  fi
}

run_selftest() {
  local tmp_root bad_contract

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-placement-truth-gate.XXXXXX")"

  bad_contract="${tmp_root}/bad-heavy-cargo.json"
  jq '.operator_truth_claims += ["The drill runs heavy Cargo and RCH work."]' "$contract_path" >"$bad_contract"
  if SWARM_TOPOLOGY_PLACEMENT_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "heavy Cargo/RCH positive claim should fail"
  else
    record_pass "heavy Cargo/RCH positive claim rejection"
  fi

  bad_contract="${tmp_root}/bad-live-mutation.json"
  jq '.operator_truth_claims += ["The drill mutates live workers and changes live queue policy."]' "$contract_path" >"$bad_contract"
  if SWARM_TOPOLOGY_PLACEMENT_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "live mutation positive claim should fail"
  else
    record_pass "live worker and queue mutation rejection"
  fi

  bad_contract="${tmp_root}/bad-pinning.json"
  jq '.operator_truth_claims += ["The drill pins workers automatically and rebinds hosts automatically."]' "$contract_path" >"$bad_contract"
  if SWARM_TOPOLOGY_PLACEMENT_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "automatic pinning/rebinding positive claim should fail"
  else
    record_pass "automatic pinning and host rebinding rejection"
  fi

  bad_contract="${tmp_root}/bad-missing-cache-healthy.json"
  jq '.operator_truth_claims += ["Missing topology or missing cache evidence is healthy by default."]' "$contract_path" >"$bad_contract"
  if SWARM_TOPOLOGY_PLACEMENT_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing topology/cache healthy claim should fail"
  else
    record_pass "missing topology/cache healthy-by-default rejection"
  fi

  bad_contract="${tmp_root}/bad-policy.json"
  jq '.mutation_policy.runs_rch = true' "$contract_path" >"$bad_contract"
  if SWARM_TOPOLOGY_PLACEMENT_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "mutation policy RCH=true should fail"
  else
    record_pass "mutation policy RCH rejection"
  fi

  printf 'swarm_topology_placement_truth_gate_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
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
