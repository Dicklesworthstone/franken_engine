#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${root_dir}/docs/SWARM_CAPABILITY_AFFINITY_ROUTING_CONTRACT.md"
contract_path="${root_dir}/docs/swarm_capability_affinity_routing_contract_v1.json"
failures=0

record_pass() {
  printf 'PASS swarm-capability-affinity-routing-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-capability-affinity-routing-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_capability_affinity_routing_contract_smoke.sh [check|selftest]
EOF
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
    .schema_version == "franken-engine.swarm-capability-affinity-routing-contract.v1"
    and .bead_id == "bd-7h4ek"
    and .parent_bead_id == "bd-lg2qn"
    and .docs == "docs/SWARM_CAPABILITY_AFFINITY_ROUTING_CONTRACT.md"
    and .smoke_script == "scripts/e2e/swarm_capability_affinity_routing_contract_smoke.sh"
    and .rust_module == "crates/franken-engine/src/swarm_control_loop.rs"
    and .toolchain_surface == "crates/franken-engine/src/seqlock_candidate_inventory.rs"
    and (.bridged_surfaces | index("scripts/swarm_execution_queue_input_normalizer.sh") != null)
    and (.bridged_surfaces | index("scripts/swarm_topology_queue_signal_normalizer.sh") != null)
    and (.bridged_surfaces | index("scripts/swarm_rch_stall_rehabilitation_ledger.sh") != null)
    and (.bridged_surfaces | index("scripts/rch_remote_compile_stall_bundle_capture.sh") != null)
    and (.bridged_surfaces | index("scripts/swarm_operator_status_report.sh") != null)
    and (.required_preserved_inputs | length == 6)
    and (.optional_preserved_inputs | length == 3)
    and (.minimum_advisory_subject_fields | index("required_capabilities") != null)
    and (.minimum_advisory_subject_fields | index("observed_toolchain_fingerprint") != null)
    and (.minimum_advisory_subject_fields | index("local_fallback_detected") != null)
    and (.future_artifacts | index("capability_affinity_routing_advisory.json") != null)
    and (.truth_states | index("contaminated") != null)
    and (.decisions | index("fail_closed") != null)
    and (.required_reason_codes | index("toolchain_fingerprint_mismatch") != null)
    and (.required_reason_codes | index("missing_required_capability") != null)
    and (.required_reason_codes | index("remote_stall_contaminated") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and (.blocked_rules | map(test("toolchain fingerprint mismatch"; "i")) | any)
    and .mutation_policy.contract_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reroutes_tasks_automatically == false
    and (.proof_cases | index("blocked_toolchain_fingerprint_mismatch") != null)
    and (.proof_cases | index("rehabilitation_excluded_cohort") != null)
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
  grep -Fq 'toolchain fingerprint mismatch blocks routing advice' "$docs_path" || record_failure "docs must mention toolchain mismatch blocking"
  grep -Fq 'capability_affinity_routing_advisory.json' "$docs_path" || record_failure "docs must mention future advisory artifact"
  grep -Fq 'rch workers capabilities --refresh --json' "$docs_path" || record_failure "docs must mention worker capability refresh evidence"

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
