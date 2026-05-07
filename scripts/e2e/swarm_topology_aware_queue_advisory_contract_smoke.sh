#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${root_dir}/docs/SWARM_TOPOLOGY_AWARE_QUEUE_ADVISORY_CONTRACT.md"
contract_path="${root_dir}/docs/swarm_topology_aware_queue_advisory_contract_v1.json"
failures=0

record_pass() {
  printf 'PASS swarm-topology-aware-queue-advisory-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-aware-queue-advisory-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_aware_queue_advisory_contract_smoke.sh [check|selftest]
EOF
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
    .schema_version == "franken-engine.swarm-topology-aware-queue-advisory-contract.v1"
    and .bead_id == "bd-f3cmp"
    and .parent_bead_id == "bd-2pn2x"
    and .docs == "docs/SWARM_TOPOLOGY_AWARE_QUEUE_ADVISORY_CONTRACT.md"
    and .smoke_script == "scripts/e2e/swarm_topology_aware_queue_advisory_contract_smoke.sh"
    and .rust_module == "crates/franken-engine/src/swarm_control_loop.rs"
    and (.bridged_surfaces | index("scripts/swarm_execution_queue_input_normalizer.sh") != null)
    and (.bridged_surfaces | index("scripts/swarm_topology_placement_normalizer.sh") != null)
    and (.bridged_surfaces | index("scripts/swarm_rch_stall_rehabilitation_ledger.sh") != null)
    and (.bridged_surfaces | index("scripts/swarm_operator_status_report.sh") != null)
    and (.required_preserved_inputs | length == 6)
    and (.optional_preserved_inputs | length == 4)
    and (.minimum_advisory_subject_fields | index("preferred_worker_ids") != null)
    and (.minimum_advisory_subject_fields | index("local_fallback_detected") != null)
    and (.future_artifacts | index("queue_advisory_bundle.json") != null)
    and (.truth_states | index("contaminated") != null)
    and (.decisions | index("fail_closed") != null)
    and (.required_reason_codes | index("drained_worker_excluded") != null)
    and (.required_reason_codes | index("cache_reuse_outcome_confirmed") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and .mutation_policy.contract_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and (.proof_cases | index("blocked_contradictory_locality") != null)
    and (.proof_cases | index("cache_reuse_feedback") != null)
  ' "$contract_path" >/dev/null
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  grep -Fq 'evidence-only and advisory-only' "$docs_path" || record_failure "docs must say evidence-only and advisory-only"
  grep -Fq 'local fallback contamination fails closed' "$docs_path" || record_failure "docs must mention local fallback contamination"
  grep -Fq 'queue_advisory_bundle.json' "$docs_path" || record_failure "docs must mention future advisory artifact"
  grep -Fq 'drained or probe-required worker' "$docs_path" || record_failure "docs must mention worker exclusion truth"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  run_check
  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest contract truths remain coherent"
  fi
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
