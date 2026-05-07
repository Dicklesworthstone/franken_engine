#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_BENCHMARK_WORKLOAD_CATALOG_DOC:-${root_dir}/docs/SWARM_BENCHMARK_WORKLOAD_CATALOG.md}"
contract_path="${SWARM_BENCHMARK_WORKLOAD_CATALOG_CONTRACT:-${root_dir}/docs/swarm_benchmark_workload_catalog_contract_v1.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-benchmark-workload-catalog-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-benchmark-workload-catalog-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_benchmark_workload_catalog_contract_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'runs cargo automatically|runs rch automatically|automatically executes benchmarks|automatically claims beads|automatically closes beads|automatically releases reservations|automatically sends Agent Mail|changes live queue policy automatically' "$path"; then
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

check_required_sources_exist() {
  local path="$1"
  jq -r '
    .source_inventory[]
    | [
        .benchmark_entrypoint,
        (.replay_entrypoint // empty),
        .measurement_source.path,
        ((.artifact_paths[]? | select(startswith("docs/") or startswith("artifacts/benchmark_denominator/README"))))
      ]
    | .[]
  ' "$path" | while IFS= read -r repo_path; do
    [[ -n "$repo_path" ]] || continue
    if [[ ! -e "${root_dir}/${repo_path}" ]]; then
      record_failure "missing referenced source path ${repo_path}"
    fi
  done
}

contract_shape_ok() {
  local path="$1"
  jq -e '
    .schema_version == "franken-engine.swarm-benchmark-workload-catalog-contract.v1"
    and .bead_id == "bd-ep64o"
    and .parent_bead_id == "bd-kl5f5"
    and .track == "SWARM-BENCH-I"
    and .docs.runbook == "docs/SWARM_BENCHMARK_WORKLOAD_CATALOG.md"
    and .docs.contract == "docs/swarm_benchmark_workload_catalog_contract_v1.json"
    and (.required_workload_fields | index("workload_id") != null)
    and (.required_workload_fields | index("validation_commands") != null)
    and (.source_inventory | length >= 6)
    and (.example_workloads | length >= 5)
    and (.source_inventory | map(.workload_id) | index("benchmark_denominator_suite") != null)
    and (.source_inventory | map(.workload_id) | index("extension_heavy_benchmark_spec") != null)
    and (.source_inventory | map(.workload_id) | index("plas_benchmark_bundle") != null)
    and (.source_inventory | map(.workload_id) | index("parser_phase0_artifact_contract") != null)
    and (.source_inventory | map(.workload_id) | index("sibling_integration_benchmark_gate") != null)
    and (.source_inventory | map(.workload_id) | index("frankenengine_throughput_baseline_status") != null)
    and .global_mutation_policy.advisory_only == true
    and .global_mutation_policy.proof_only == true
    and .global_mutation_policy.fixture_fed_only == true
    and .global_mutation_policy.mutates_br == false
    and .global_mutation_policy.reassigns_beads == false
    and .global_mutation_policy.releases_reservations == false
    and .global_mutation_policy.sends_agent_mail == false
    and .global_mutation_policy.queries_live_agent_mail == false
    and .global_mutation_policy.runs_cargo == false
    and .global_mutation_policy.runs_rch == false
    and .global_mutation_policy.changes_live_queue_policy == false
    and .global_rch_policy.heavy_cargo_examples_must_start_with == "rch exec -- env CARGO_TARGET_DIR="
    and .global_rch_policy.bare_heavy_cargo_is_fail_closed == true
  ' "$path" >/dev/null
}

docs_shape_ok() {
  local path="$1"
  grep -Fq 'Machine-readable contract:' "$path" \
    && grep -Fq 'Smoke gate:' "$path" \
    && grep -Fq 'This surface is advisory only and proof only.' "$path" \
    && grep -Fq "does not query live \`br\`," "$path" \
    && grep -Fq 'Agent Mail, RCH, git, or workers.' "$path" \
    && grep -Fq 'does not execute Cargo or RCH.' "$path" \
    && grep -Fq 'The catalog producer itself does not execute Cargo or RCH.' "$path"
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

  check_required_sources_exist "$contract"
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
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-benchmark-workload-catalog-contract-smoke.XXXXXX")"
  good_docs="${tmp_root}/good.md"
  good_contract="${tmp_root}/good.json"
  bad_docs="${tmp_root}/bad.md"
  bad_contract="${tmp_root}/bad.json"

  cp "$docs_path" "$good_docs"
  cp "$contract_path" "$good_contract"
  run_check_with_paths "$good_docs" "$good_contract"

  cp "$docs_path" "$bad_docs"
  printf '\nThis surface runs Cargo automatically after scoring.\n' >>"$bad_docs"
  failures=0
  run_check_with_paths "$bad_docs" "$good_contract"
  if [[ "$failures" -eq 0 ]]; then
    record_failure "selftest expected forbidden wording failure"
  else
    record_pass "selftest forbidden wording is rejected"
  fi

  cp "$contract_path" "$bad_contract"
  jq '
    .source_inventory[0].validation_commands = ["cargo test -p frankenengine-engine --test benchmark_denominator"]
  ' "$bad_contract" >"${bad_contract}.tmp"
  mv "${bad_contract}.tmp" "$bad_contract"
  failures=0
  run_check_with_paths "$good_docs" "$bad_contract"
  if [[ "$failures" -eq 0 ]]; then
    record_failure "selftest expected bare heavy Cargo failure"
  else
    record_pass "selftest bare heavy Cargo is rejected"
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
