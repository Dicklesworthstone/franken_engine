#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${SWARM_TOPOLOGY_AWARE_QUEUE_NO_MOCK_DRILL_CONTRACT_PATH:-${root_dir}/docs/swarm_topology_aware_queue_no_mock_drill_contract_v1.json}"
drill_path="${root_dir}/scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh"
failures=0

record_pass() {
  printf 'PASS swarm-topology-aware-queue-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-aware-queue-truth-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_aware_queue_truth_gate.sh [check|selftest]
EOF
}

assert_contract_shape() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-aware-queue-no-mock-drill-contract.v1"
    and .bead_id == "bd-o9pr3"
    and .parent_bead_id == "bd-2pn2x"
    and .track_contract_path == "docs/swarm_topology_aware_queue_advisory_contract_v1.json"
    and .drill_script == "scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh"
    and .truth_gate_script == "scripts/e2e/swarm_topology_aware_queue_truth_gate.sh"
    and .operator_runbook_path == "docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md"
    and (.depends_on | index("bd-utk1x") != null)
    and (.depends_on | index("bd-q1zfn") != null)
    and (.depends_on | index("bd-zvd0e") != null)
    and (.depends_on | index("bd-2r3eq") != null)
    and (.composed_scripts | index("scripts/swarm_topology_queue_signal_normalizer.sh") != null)
    and (.composed_scripts | index("scripts/swarm_topology_aware_queue_scorer.sh") != null)
    and (.composed_scripts | index("scripts/swarm_topology_aware_queue_fidelity_ledger.sh") != null)
    and (.composed_scripts | index("scripts/swarm_operator_status_report.sh") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_topology_aware_queue_scorer/cases.json") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json") != null)
    and (.fixture_bundles | index("scripts/testdata/swarm_topology_aware_queue_no_mock_drill/cases.json") != null)
    and (.required_artifact_references | index("swarm_topology_queue_signal_input.json") != null)
    and (.required_artifact_references | index("queue_advisory_bundle.json") != null)
    and (.required_artifact_references | index("swarm_topology_aware_queue_fidelity_receipt.json") != null)
    and (.required_artifact_references | index("swarm_topology_aware_queue_drift_ledger.json") != null)
    and (.required_artifact_references | index("status.json") != null)
    and (.required_artifact_references | index("run_manifest.json") != null)
    and (.required_artifact_references | index("trace_ids.json") != null)
    and (.required_artifact_references | index("events.jsonl") != null)
    and (.required_artifact_references | index("commands.txt") != null)
    and (.required_artifact_references | index("report.md") != null)
    and any(.operator_truth_claims[]; contains("run_manifest.json") and contains("trace_ids.json") and contains("without implying warm automation"))
    and any(.drill_scenarios[]; .scenario_id == "healthy_hot_cache_reuse" and .expected_readiness == "ready")
    and any(.drill_scenarios[]; .scenario_id == "degraded_missing_locality_adoption" and .expected_readiness == "degraded")
    and any(.drill_scenarios[]; .scenario_id == "blocked_contradictory_locality" and .expected_readiness == "blocked")
    and any(.drill_scenarios[]; .scenario_id == "drain_recommended_worker_exclusion" and .required_advisory_reason_code == "drained_worker_excluded")
    and any(.drill_scenarios[]; .scenario_id == "unstable_worker_downgrade" and .required_fidelity_reason_code == "observed_excluded_worker_used")
    and any(.drill_scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected_readiness == "contaminated")
    and (.required_truth_gate_rejections | index("heavy_cargo_or_rch_claim") != null)
    and (.required_truth_gate_rejections | index("live_worker_or_queue_mutation_claim") != null)
    and (.required_truth_gate_rejections | index("automatic_reroute_or_worker_pin_claim") != null)
    and (.required_truth_gate_rejections | index("degraded_optional_evidence_healthy_claim") != null)
    and (.required_truth_gate_rejections | index("contradictory_locality_healthy_claim") != null)
    and (.required_truth_gate_rejections | index("unstable_worker_not_downgraded_claim") != null)
    and (.required_truth_gate_rejections | index("contamination_non_fail_closed_claim") != null)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_live_workers == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reroutes_tasks_automatically == false
    and .mutation_policy.edits_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.treats_degraded_optional_evidence_as_healthy == false
    and .mutation_policy.treats_contradictory_locality_as_healthy == false
    and .mutation_policy.treats_unstable_worker_evidence_as_healthy == false
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
        record_failure "live worker or queue mutation positive claim present"
        return 1
        ;;
      *"reroutes tasks automatically"*|*"pins workers automatically"*)
        record_failure "automatic reroute or pin positive claim present"
        return 1
        ;;
      *"healthy by default."*)
        if [[ "$claim" != *"instead of healthy by default."* ]]; then
          record_failure "healthy-by-default degraded evidence claim present"
          return 1
        fi
        ;;
      *"Contradictory locality can still be healthy."*)
        record_failure "contradictory locality healthy claim present"
        return 1
        ;;
      *"Unstable worker evidence remains healthy advice."*)
        record_failure "unstable worker healthy claim present"
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

assert_operator_runbook_handoff() {
  local runbook_path
  local required

  runbook_path="${root_dir}/$(jq -r '.operator_runbook_path' "$contract_path")"

  for required in \
    "scripts/swarm_topology_aware_queue_scorer.sh" \
    "franken-engine.swarm-topology-aware-queue-advisory.v1" \
    "queue_advisory_bundle.json" \
    "admission_decision" \
    "admit" \
    "narrow" \
    "defer" \
    "fail_closed" \
    "selected_command_policy.selected_commands" \
    "unsafe_command_broadening" \
    "missing_target_dir_evidence" \
    "memory_headroom_too_low"
  do
    if ! grep -Fq "$required" "$runbook_path"; then
      record_failure "operator runbook missing topology admission reference: ${required}"
    fi
  done

  if grep -Eiq 'topology.*(mutates live|changes live queue policy|pins workers automatically|runs Cargo|runs RCH)' "$runbook_path"; then
    record_failure "operator runbook overclaims topology admission live mutation or execution"
  fi
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
  assert_operator_runbook_handoff

  if [[ "$failures" -eq 0 ]]; then
    record_pass "truth claims and artifact references"
  fi
}

run_negative_case() {
  local bad_contract="$1"
  local label="$2"

  if SWARM_TOPOLOGY_AWARE_QUEUE_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "${label} should fail"
  else
    record_pass "${label} rejection"
  fi
}

run_selftest() {
  local tmp_root bad_contract

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-aware-queue-truth-gate.XXXXXX")"

  bad_contract="${tmp_root}/bad-heavy-cargo.json"
  jq '.operator_truth_claims += ["The drill runs heavy Cargo and RCH work."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "heavy Cargo or RCH positive claim"

  bad_contract="${tmp_root}/bad-live-mutation.json"
  jq '.operator_truth_claims += ["The drill mutates live workers and changes live queue policy."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "live worker or queue mutation"

  bad_contract="${tmp_root}/bad-reroute-pin.json"
  jq '.operator_truth_claims += ["The drill reroutes tasks automatically and pins workers automatically."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "automatic reroute or pin"

  bad_contract="${tmp_root}/bad-healthy-default.json"
  jq '.operator_truth_claims += ["Missing locality evidence is healthy by default."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "degraded optional evidence healthy"

  bad_contract="${tmp_root}/bad-contradiction.json"
  jq '.operator_truth_claims += ["Contradictory locality can still be healthy."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "contradictory locality healthy"

  bad_contract="${tmp_root}/bad-unstable.json"
  jq '.operator_truth_claims += ["Unstable worker evidence remains healthy advice."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "unstable worker healthy"

  bad_contract="${tmp_root}/bad-contamination.json"
  jq '.operator_truth_claims += ["Local fallback contamination is advisory only and does not fail closed."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "contamination non-fail-closed"

  bad_contract="${tmp_root}/bad-policy.json"
  jq '.mutation_policy.runs_rch = true' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "mutation policy RCH=true"

  printf 'swarm_topology_aware_queue_truth_gate_artifacts=%s\n' "$tmp_root"
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
