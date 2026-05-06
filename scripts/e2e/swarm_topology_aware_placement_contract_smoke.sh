#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_TOPOLOGY_AWARE_PLACEMENT_DOC:-${root_dir}/docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_CONTRACT.md}"
contract_path="${SWARM_TOPOLOGY_AWARE_PLACEMENT_CONTRACT:-${root_dir}/docs/swarm_topology_aware_placement_contract_v1.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-topology-aware-placement-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-aware-placement-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_aware_placement_contract_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'mutates live workers|automatically pins workers|automatically rebinds hosts|releases file reservations automatically|sends Agent Mail automatically|updates beads automatically|reassigns beads automatically|changes live queue policy automatically' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden live-mutation wording"
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
  local path="$1"
  jq -e '
    .schema_version == "franken-engine.swarm-topology-aware-placement-contract.v1"
    and .bead_id == "bd-5p9ln"
    and .parent_bead_id == "bd-6arnx"
    and .track == "SWARM-SCALE-II"
    and .docs.runbook == "docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_CONTRACT.md"
    and .docs.contract == "docs/swarm_topology_aware_placement_contract_v1.json"
    and .operator_status_section == "swarm_topology_placement"
    and (.source_surfaces | map(.source_id) | index("execution_queue_input") != null)
    and (.source_surfaces | map(.source_id) | index("resource_envelope") != null)
    and (.source_surfaces | map(.source_id) | index("operator_status") != null)
    and (.source_surfaces | map(.source_id) | index("metadata_locality_governance") != null)
    and (.planned_surfaces | index("scripts/swarm_topology_placement_normalizer.sh") != null)
    and (.planned_surfaces | index("scripts/swarm_topology_placement_planner.sh") != null)
    and (.planned_surfaces | index("scripts/swarm_topology_placement_receipt_ledger.sh") != null)
    and (.planned_surfaces | index("scripts/e2e/swarm_topology_placement_no_mock_drill.sh") != null)
    and (.planned_surfaces | index("scripts/e2e/swarm_topology_placement_truth_gate.sh") != null)
    and (.required_artifacts | index("swarm_topology_placement_plan.json") != null)
    and (.required_artifacts | index("swarm_topology_placement_receipt.json") != null)
    and (.required_artifacts | index("swarm_topology_placement_no_mock_drill_report.json") != null)
    and (.required_plan_fields | index("recommended_topology_class") != null)
    and (.required_plan_fields | index("warm_cache_residency_state") != null)
    and (.proof_categories | map(.category_id) | index("healthy_topology_aware_planning") != null)
    and (.proof_categories | map(.category_id) | index("degraded_partial_topology") != null)
    and (.proof_categories | map(.category_id) | index("blocked_contradictory_locality") != null)
    and (.proof_categories | map(.category_id) | index("contaminated_local_fallback") != null)
    and (.fail_closed_classes | index("contradictory_locality_evidence") != null)
    and (.fail_closed_classes | index("rch_local_fallback_contaminates_locality") != null)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.queries_live_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.rebinds_hosts_automatically == false
    and (.operator_status_handoff_note | test("only predictive dashboard producer"))
    and (.operator_status_handoff_note | test("advisory-only"))
  ' "$path" >/dev/null
}

docs_shape_ok() {
  local path="$1"
  grep -Fq 'Machine-readable contract:' "$path" \
    && grep -Fq 'Smoke gate:' "$path" \
    && grep -Fq 'The operator status report remains the only predictive dashboard producer in' "$path" \
    && grep -Fq 'healthy_topology_aware_planning' "$path" \
    && grep -Fq 'degraded_partial_topology' "$path" \
    && grep -Fq 'blocked_contradictory_locality' "$path" \
    && grep -Fq 'contaminated_local_fallback' "$path" \
    && grep -Fq 'does not run Cargo or RCH' "$path" \
    && grep -Fq 'does not mutate remote workers' "$path"
}

run_check_with_paths() {
  local docs="$1"
  local contract="$2"

  jq empty "$contract" >/dev/null || record_failure "contract JSON is invalid"

  if contract_shape_ok "$contract"; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  if docs_shape_ok "$docs"; then
    record_pass "docs shape"
  else
    record_failure "docs shape mismatch"
  fi

  check_no_mutation_claims "$docs"
  check_no_mutation_claims "$contract"
  check_no_bare_heavy_cargo "$docs"
  check_no_bare_heavy_cargo "$contract"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  run_check_with_paths "$docs_path" "$contract_path"
}

run_selftest() {
  local tmp_root good_docs good_contract bad_docs bad_contract
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-aware-placement-contract-smoke.XXXXXX")"
  good_docs="${tmp_root}/good.md"
  good_contract="${tmp_root}/good.json"
  bad_docs="${tmp_root}/bad.md"
  bad_contract="${tmp_root}/bad.json"

  cp "$docs_path" "$good_docs"
  cp "$contract_path" "$good_contract"
  run_check_with_paths "$good_docs" "$good_contract"

  cp "$docs_path" "$bad_docs"
  printf '\nThis drill mutates live workers automatically.\n' >>"$bad_docs"
  failures=0
  run_check_with_paths "$bad_docs" "$good_contract"
  if [[ "$failures" -eq 0 ]]; then
    record_failure "selftest expected forbidden wording failure"
  else
    record_pass "selftest forbidden wording is rejected"
  fi

  cp "$contract_path" "$bad_contract"
  jq 'del(.proof_categories[] | select(.category_id == "contaminated_local_fallback"))' "$bad_contract" >"${bad_contract}.tmp"
  mv "${bad_contract}.tmp" "$bad_contract"
  failures=0
  run_check_with_paths "$good_docs" "$bad_contract"
  if [[ "$failures" -eq 0 ]]; then
    record_failure "selftest expected missing proof category failure"
  else
    record_pass "selftest missing proof category is rejected"
  fi

  failures=0
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
