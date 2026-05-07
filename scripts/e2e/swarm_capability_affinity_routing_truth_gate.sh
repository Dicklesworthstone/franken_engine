#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH:-${root_dir}/docs/swarm_capability_affinity_routing_no_mock_drill_contract_v1.json}"
drill_path="${root_dir}/scripts/e2e/swarm_capability_affinity_routing_no_mock_drill.sh"
failures=0

record_pass() {
  printf 'PASS swarm-capability-affinity-routing-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-capability-affinity-routing-truth-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_capability_affinity_routing_truth_gate.sh [check|selftest]
EOF
}

assert_contract_shape() {
  jq -e '
    .schema_version == "franken-engine.swarm-capability-affinity-routing-no-mock-drill-contract.v1"
    and .bead_id == "bd-x0030"
    and .parent_bead_id == "bd-lg2qn"
    and .track_contract_path == "docs/swarm_capability_affinity_routing_contract_v1.json"
    and .drill_script == "scripts/e2e/swarm_capability_affinity_routing_no_mock_drill.sh"
    and .truth_gate_script == "scripts/e2e/swarm_capability_affinity_routing_truth_gate.sh"
    and (.depends_on | index("bd-wplun") != null)
    and (.depends_on | index("bd-vp44k") != null)
    and (.depends_on | index("bd-wa7by") != null)
    and (.depends_on | index("bd-da98k") != null)
    and (.composed_scripts | index("scripts/swarm_worker_capability_toolchain_normalizer.sh") != null)
    and (.composed_scripts | index("scripts/swarm_capability_affinity_queue_routing_planner.sh") != null)
    and (.composed_scripts | index("scripts/swarm_capability_affinity_routing_outcome_ledger.sh") != null)
    and (.composed_scripts | index("scripts/swarm_operator_status_report.sh") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_worker_capability_toolchain/worker_capability_toolchain_fixtures.json") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_capability_affinity_queue_routing_planner/fixtures.json") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_capability_affinity_routing_outcome_ledger/fixtures.json") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_capability_affinity_routing_no_mock_drill/cases.json") != null)
    and (.required_artifact_references | index("swarm_worker_capability_toolchain_input.json") != null)
    and (.required_artifact_references | index("capability_affinity_queue_routing_advisory.json") != null)
    and (.required_artifact_references | index("swarm_capability_affinity_routing_outcome_ledger.json") != null)
    and (.required_artifact_references | index("status.json") != null)
    and (.required_artifact_references | index("swarm_capability_affinity_routing_no_mock_drill_report.json") != null)
    and any(.drill_scenarios[]; .scenario_id == "healthy_confirmed" and .expected.operator_capability_affinity_readiness == "ready" and .expected.planner_decision == "pass")
    and any(.drill_scenarios[]; .scenario_id == "degraded_missing_optional_support" and .expected.operator_capability_affinity_readiness == "degraded" and .expected.planner_decision == "degraded")
    and any(.drill_scenarios[]; .scenario_id == "blocked_capability_gap" and .expected.operator_capability_affinity_readiness == "blocked" and .expected.required_reason_code == "observed_capability_gap")
    and any(.drill_scenarios[]; .scenario_id == "blocked_unsupported_toolchain" and .expected.operator_capability_affinity_readiness == "blocked" and .expected.required_reason_code == "observed_toolchain_drift")
    and any(.drill_scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected.operator_capability_affinity_readiness == "contaminated" and .expected.planner_decision == "fail_closed")
    and (.required_truth_gate_rejections | index("heavy_cargo_or_rch_claim") != null)
    and (.required_truth_gate_rejections | index("live_worker_or_queue_mutation_claim") != null)
    and (.required_truth_gate_rejections | index("automatic_reroute_or_worker_repair_claim") != null)
    and (.required_truth_gate_rejections | index("degraded_optional_evidence_healthy_claim") != null)
    and (.required_truth_gate_rejections | index("capability_gap_or_unsupported_toolchain_healthy_claim") != null)
    and (.required_truth_gate_rejections | index("contamination_non_fail_closed_claim") != null)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_live_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reroutes_tasks_automatically == false
    and .mutation_policy.repairs_workers_automatically == false
    and .mutation_policy.treats_degraded_optional_evidence_as_healthy == false
    and .mutation_policy.treats_capability_gaps_as_healthy == false
    and .mutation_policy.treats_unsupported_toolchain_as_healthy == false
    and .mutation_policy.treats_contamination_as_non_fail_closed == false
  ' "$contract_path" >/dev/null
}

assert_required_paths() {
  local path

  while IFS= read -r path; do
    if [[ ! -e "${root_dir}/${path}" ]]; then
      record_failure "missing required path ${path}"
      return 1
    fi
  done < <(jq -r '.required_repo_paths[]' "$contract_path")
}

assert_truth_claims() {
  local claim

  while IFS= read -r claim; do
    case "$claim" in
      *"runs heavy Cargo and RCH work."*)
        record_failure "heavy Cargo or RCH positive claim present"
        return 1
        ;;
      *"mutates live workers and changes live queue policy."*)
        record_failure "live worker or queue mutation claim present"
        return 1
        ;;
      *"reroutes tasks automatically"*|*"repairs workers automatically"*)
        record_failure "automatic reroute or repair claim present"
        return 1
        ;;
      *"healthy by default."*)
        if [[ "$claim" != *"instead of healthy by default."* ]]; then
          record_failure "healthy-by-default degraded evidence claim present"
          return 1
        fi
        ;;
      *"can still be treated as healthy routing advice."*)
        record_failure "capability gap or unsupported toolchain healthy claim present"
        return 1
        ;;
      *"does not fail closed."*)
        record_failure "contamination non-fail-closed claim present"
        return 1
        ;;
    esac
  done < <(jq -r '.operator_truth_claims[]' "$contract_path")
}

assert_verification_commands_are_lightweight() {
  local command

  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "truth contract must not advertise heavy Cargo in verification: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "truth contract must not advertise RCH in verification: ${command}"
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
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-capability-affinity-routing-truth-gate.XXXXXX")"

  bad_contract="${tmp_root}/bad-heavy-cargo.json"
  jq '.operator_truth_claims += ["The drill runs heavy Cargo and RCH work."]' "$contract_path" >"$bad_contract"
  if SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "heavy Cargo or RCH positive claim should fail"
  else
    record_pass "heavy Cargo or RCH positive claim rejection"
  fi

  bad_contract="${tmp_root}/bad-live-mutation.json"
  jq '.operator_truth_claims += ["The drill mutates live workers and changes live queue policy."]' "$contract_path" >"$bad_contract"
  if SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "live worker or queue mutation positive claim should fail"
  else
    record_pass "live worker or queue mutation rejection"
  fi

  bad_contract="${tmp_root}/bad-reroute-repair.json"
  jq '.operator_truth_claims += ["The drill reroutes tasks automatically and repairs workers automatically."]' "$contract_path" >"$bad_contract"
  if SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "automatic reroute or repair positive claim should fail"
  else
    record_pass "automatic reroute or repair rejection"
  fi

  bad_contract="${tmp_root}/bad-healthy-default.json"
  jq '.operator_truth_claims += ["Degraded optional evidence is healthy by default."]' "$contract_path" >"$bad_contract"
  if SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "degraded optional evidence healthy claim should fail"
  else
    record_pass "degraded optional evidence healthy rejection"
  fi

  bad_contract="${tmp_root}/bad-block-ignored.json"
  jq '.operator_truth_claims += ["Capability gaps or unsupported toolchain can still be treated as healthy routing advice."]' "$contract_path" >"$bad_contract"
  if SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "capability gap or unsupported toolchain healthy claim should fail"
  else
    record_pass "capability gap or unsupported toolchain healthy rejection"
  fi

  bad_contract="${tmp_root}/bad-contamination.json"
  jq '.operator_truth_claims += ["Local fallback contamination is advisory only and does not fail closed."]' "$contract_path" >"$bad_contract"
  if SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "contamination non-fail-closed claim should fail"
  else
    record_pass "contamination non-fail-closed rejection"
  fi

  bad_contract="${tmp_root}/bad-policy.json"
  jq '.mutation_policy.runs_rch = true' "$contract_path" >"$bad_contract"
  if SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "mutation policy RCH=true should fail"
  else
    record_pass "mutation policy RCH rejection"
  fi

  printf 'swarm_capability_affinity_routing_truth_gate_artifacts=%s\n' "$tmp_root"
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
