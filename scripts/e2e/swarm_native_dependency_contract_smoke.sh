#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${root_dir}/docs/SWARM_NATIVE_DEPENDENCY_ROUTING_CONTRACT.md"
contract_path="${root_dir}/docs/swarm_native_dependency_routing_contract_v1.json"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_contract/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_contract_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'apt(-get)? install|dnf install|yum install|mutates remote workers|changes live queue policy automatically|updates beads automatically|releases reservations automatically|sends Agent Mail automatically|reroutes tasks automatically|repairs workers automatically' "$path"; then
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
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-routing-contract.v1"
    and .bead_id == "bd-sqm14.1"
    and .parent_bead_id == "bd-sqm14"
    and .docs == "docs/SWARM_NATIVE_DEPENDENCY_ROUTING_CONTRACT.md"
    and .smoke_script == "scripts/e2e/swarm_native_dependency_contract_smoke.sh"
    and .testdata == "scripts/testdata/swarm_native_dependency_contract/cases.json"
    and (.bridged_surfaces | index("docs/SWARM_CAPABILITY_AFFINITY_ROUTING_CONTRACT.md") != null)
    and (.bridged_surfaces | index("docs/RCH_VALIDATION_PREFLIGHT_CONTRACT_V1.md") != null)
    and (.required_preserved_inputs | index("native_requirement_bundle_json") != null)
    and (.required_preserved_inputs | index("worker_native_probe_snapshot_json") != null)
    and (.required_preserved_inputs | index("rch_failure_log_excerpt_json") != null)
    and (.required_preserved_inputs | index("validation_command_context_json") != null)
    and (.minimum_advisory_subject_fields | index("validation_id") != null)
    and (.minimum_advisory_subject_fields | index("path_dependency_closure") != null)
    and (.minimum_advisory_subject_fields | index("abi_fingerprint") != null)
    and (.minimum_advisory_subject_fields | index("contamination_state") != null)
    and ([.native_dependency_families[].dependency_id] | index("hdf5") != null)
    and ([.native_dependency_families[].dependency_id] | index("unknown_build_script_native_dependency") != null)
    and (.probe_kinds | index("pkg_config_modversion") != null)
    and (.probe_kinds | index("header_presence") != null)
    and (.truth_states | index("contaminated") != null)
    and (.truth_states | index("unknown") != null)
    and (.decisions | index("fail_closed") != null)
    and (.required_reason_codes | index("hdf5_required_present") != null)
    and (.required_reason_codes | index("hdf5_required_missing") != null)
    and (.required_reason_codes | index("optional_native_dependency_absent") != null)
    and (.required_reason_codes | index("stale_worker_probe") != null)
    and (.required_reason_codes | index("contradictory_pkg_config_header_evidence") != null)
    and (.required_reason_codes | index("local_fallback_contaminated") != null)
    and (.required_reason_codes | index("unsupported_worker_mutation_advice") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and (.blocked_rules | map(test("hdf5 required and absent"; "i")) | any)
    and (.future_artifacts | index("native_dependency_routing_advisory.json") != null)
    and (.event_fields | index("trace_id") != null)
    and (.event_fields | index("validation_id") != null)
    and (.event_fields | index("worker_id") != null)
    and (.event_fields | index("dependency_id") != null)
    and (.event_fields | index("error_code") != null)
    and .mutation_policy.contract_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.installs_remote_packages == false
    and .mutation_policy.reroutes_tasks_automatically == false
    and (.proof_cases | index("hdf5_required_present") != null)
    and (.proof_cases | index("hdf5_required_missing") != null)
    and (.proof_cases | index("optional_native_dependency_absent") != null)
    and (.proof_cases | index("stale_worker_probe") != null)
    and (.proof_cases | index("contradictory_pkg_config_header_evidence") != null)
    and (.proof_cases | index("local_fallback_contaminated") != null)
  ' "$contract_path" >/dev/null
}

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-contract-cases.v1"
    and (.scenarios | length == 6)
    and ([.scenarios[].scenario_id] | sort == [
      "contradictory_pkg_config_header_evidence",
      "hdf5_required_missing",
      "hdf5_required_present",
      "local_fallback_contaminated",
      "optional_native_dependency_absent",
      "stale_worker_probe"
    ])
    and all(.scenarios[];
      (.expected_reason_codes | length > 0)
      and (.inputs.validation_command_context_json.validation_id | type == "string")
      and (.inputs.validation_command_context_json.command | type == "string")
      and (.inputs.native_requirement_bundle_json.schema_version == "franken-engine.native-requirement-bundle.v1")
      and (.inputs.worker_native_probe_snapshot_json.schema_version == "franken-engine.worker-native-probe-snapshot.v1")
      and (.inputs.rch_failure_log_excerpt_json.schema_version == "franken-engine.rch-failure-log-excerpt.v1")
    )
    and (.scenarios[] | select(.scenario_id == "hdf5_required_present") | .expected_decision == "pass" and (.expected_reason_codes | index("hdf5_required_present") != null))
    and (.scenarios[] | select(.scenario_id == "hdf5_required_missing") | .expected_decision == "blocked" and (.expected_reason_codes | index("pkg_config_unavailable") != null))
    and (.scenarios[] | select(.scenario_id == "optional_native_dependency_absent") | .expected_truth_state == "degraded")
    and (.scenarios[] | select(.scenario_id == "stale_worker_probe") | .expected_decision == "fail_closed")
    and (.scenarios[] | select(.scenario_id == "contradictory_pkg_config_header_evidence") | .expected_decision == "fail_closed")
    and (.scenarios[] | select(.scenario_id == "local_fallback_contaminated") | .expected_truth_state == "contaminated" and .inputs.worker_native_probe_snapshot_json.contamination_state == "local_fallback")
  ' "$cases_path" >/dev/null
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  jq empty "$cases_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  if cases_shape_ok; then
    record_pass "fixture cases"
  else
    record_failure "fixture cases mismatch"
  fi

  grep -Fq 'evidence-only and advisory-only' "$docs_path" || record_failure "docs must say evidence-only and advisory-only"
  grep -Fq 'HDF5_DIR' "$docs_path" || record_failure "docs must mention HDF5_DIR"
  grep -Fqi 'local fallback contamination fails closed' "$docs_path" || record_failure "docs must mention local fallback fail-closed behavior"
  grep -Fqi 'unsupported worker mutation advice fails closed' "$docs_path" || record_failure "docs must mention unsupported worker mutation advice"
  grep -Fq 'native_dependency_routing_advisory.json' "$docs_path" || record_failure "docs must mention future advisory artifact"
  grep -Fq 'trace_id' "$docs_path" || record_failure "docs must include structured event fields"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_mutation_claims "$cases_path"
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
