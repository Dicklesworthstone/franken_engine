#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_topology_placement_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_NORMALIZER.md"
contract_path="${root_dir}/docs/swarm_topology_aware_placement_input_contract_v1.json"
parent_contract_path="${root_dir}/docs/swarm_topology_aware_placement_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json"
failures=0

required_input_ids=(
  host_topology_json
  numa_evidence_json
  worker_inventory_json
)

optional_input_ids=(
  cache_residency_json
  resource_envelope_json
  execution_queue_input_json
  tail_latency_evidence_json
)

record_pass() {
  printf 'PASS swarm-topology-placement-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-placement-normalizer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_placement_normalizer_smoke.sh [check|selftest]
EOF
}

extract_fixture_input() {
  local scenario="$1"
  local input_id="$2"
  local output_path="$3"

  local is_null
  is_null="$(jq -r --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | (.inputs[$input_id] == null)
  ' "$fixture_bundle_path")"
  if [[ "$is_null" == "true" ]]; then
    return 1
  fi

  jq --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | .inputs[$input_id]
  ' "$fixture_bundle_path" >"$output_path"
}

materialize_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local input_id
  mkdir -p "$dir"

  for input_id in "${required_input_ids[@]}"; do
    if ! extract_fixture_input "$scenario" "$input_id" "${dir}/${input_id}.json"; then
      record_failure "required fixture input ${input_id} missing for ${scenario}"
      return 1
    fi
  done

  for input_id in "${optional_input_ids[@]}"; do
    extract_fixture_input "$scenario" "$input_id" "${dir}/${input_id}.json" || true
  done
}

run_normalizer_case() {
  local scenario="$1"
  local input_dir="$2"
  local output_dir="$3"
  local expected_code="$4"
  local code=0
  local args=()
  local input_id

  mkdir -p "$output_dir"
  args+=(
    --bead-id bd-3ynhq
    --source-revision fixture-rev
    --reference-time "$(jq -r '.reference_time' "$fixture_bundle_path")"
    --max-snapshot-age-seconds "$(jq -r '.max_snapshot_age_seconds' "$fixture_bundle_path")"
    --host-topology-json "${input_dir}/host_topology_json.json"
    --numa-evidence-json "${input_dir}/numa_evidence_json.json"
    --worker-inventory-json "${input_dir}/worker_inventory_json.json"
  )
  for input_id in "${optional_input_ids[@]}"; do
    if [[ -f "${input_dir}/${input_id}.json" ]]; then
      case "$input_id" in
        cache_residency_json)
          args+=(--cache-residency-json "${input_dir}/${input_id}.json")
          ;;
        resource_envelope_json)
          args+=(--resource-envelope-json "${input_dir}/${input_id}.json")
          ;;
        execution_queue_input_json)
          args+=(--execution-queue-input-json "${input_dir}/${input_id}.json")
          ;;
        tail_latency_evidence_json)
          args+=(--tail-latency-evidence-json "${input_dir}/${input_id}.json")
          ;;
      esac
    fi
  done
  args+=(--output-dir "$output_dir")

  set +e
  bash "$normalizer" "${args[@]}" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${scenario} expected exit ${expected_code}, got ${code}"
    return 1
  fi
  if [[ ! -f "${output_dir}/swarm_topology_placement_input.json" ]]; then
    record_failure "${scenario} did not emit swarm_topology_placement_input.json"
    return 1
  fi
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'mutates remote workers|pins workers automatically|rebinds hosts automatically|sends Agent Mail automatically|updates beads automatically|reassigns beads automatically|changes live queue policy automatically' "$path"; then
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
  jq -e '
    .schema_version == "franken-engine.swarm-topology-placement-input-normalizer-contract.v1"
    and .bead_id == "bd-3ynhq"
    and .parent_bead_id == "bd-6arnx"
    and (.depends_on | index("bd-5p9ln") != null)
    and .script == "scripts/swarm_topology_placement_normalizer.sh"
    and .smoke_script == "scripts/e2e/swarm_topology_placement_normalizer_smoke.sh"
    and .docs == "docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_NORMALIZER.md"
    and .parent_contract == "docs/swarm_topology_aware_placement_contract_v1.json"
    and .fixture_bundle == "scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json"
    and .input_schema_version == "franken-engine.swarm-topology-placement-input.v1"
    and .source_schema_version == "franken-engine.swarm-topology-placement-sources.v1"
    and (.required_inputs | length == 3)
    and (.optional_inputs | length == 4)
    and (.normalized_input_fields | index("placement_hints") != null)
    and (.normalized_input_fields | index("fail_closed_reasons") != null)
    and (.required_source_fields | index("freshness_state") != null)
    and (.truth_states | index("contaminated") != null)
    and (.blocked_rules | map(test("contradictory")) | any)
    and (.degraded_rules | map(test("missing cache residency")) | any)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.rebinds_hosts_automatically == false
    and (.selftest_scenarios | index("healthy_confirmed") != null)
    and (.selftest_scenarios | index("fail_closed_malformed_topology") != null)
  ' "$contract_path" >/dev/null
}

fixture_bundle_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-placement-normalizer-fixtures.v1"
    and (.scenarios | length) >= 5
    and any(.scenarios[]; .scenario_id == "healthy_confirmed" and .expected_decision == "pass" and .expected_truth_state == "confirmed")
    and any(.scenarios[]; .scenario_id == "degraded_missing_cache_residency" and .inputs.cache_residency_json == null)
    and any(.scenarios[]; .scenario_id == "blocked_contradictory_locality" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected_truth_state == "contaminated")
    and any(.scenarios[]; .scenario_id == "fail_closed_malformed_topology" and .expected_exit_code == 42)
    and all(.scenarios[]; .inputs.host_topology_json.host_id | length > 0)
    and all(.scenarios[]; .inputs.numa_evidence_json.node_count >= 1)
    and all(.scenarios[]; (.inputs.worker_inventory_json.workers | length) >= 1)
  ' "$fixture_bundle_path" >/dev/null
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$parent_contract_path" "$fixture_bundle_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  if fixture_bundle_shape_ok; then
    record_pass "checked-in fixture bundle shape"
  else
    record_failure "checked-in fixture bundle shape mismatch"
  fi

  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'swarm_topology_placement_input.json' "$docs_path" || record_failure "docs must mention normalized input artifact"
  grep -Fq 'contaminated_local_fallback' "$docs_path" || record_failure "docs must mention contaminated local fallback proof case"
  grep -Fq 'run Cargo or RCH' "$docs_path" || record_failure "docs must reject Cargo/RCH claims"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  local tmp_root scenario input_dir output_dir expected_decision expected_truth_state expected_exit_code
  tmp_root="${TMPDIR:-/tmp}/swarm-topology-placement-normalizer-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"

  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/in"
    output_dir="${tmp_root}/${scenario}/out"
    materialize_fixture_dir "$scenario" "$input_dir" || continue
    expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
    expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$fixture_bundle_path")"
    expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$fixture_bundle_path")"

    run_normalizer_case "$scenario" "$input_dir" "$output_dir" "$expected_exit_code" || continue

    jq -e --arg decision "$expected_decision" --arg truth_state "$expected_truth_state" '
      .decision == $decision and .truth_state == $truth_state
    ' "${output_dir}/swarm_topology_placement_input.json" >/dev/null || {
      record_failure "${scenario} decision or truth state mismatch"
      continue
    }

    case "$scenario" in
      healthy_confirmed)
        jq -e '
          .placement_hints.recommended_topology_class == "numa_local_hot_cache"
          and .warm_cache_residency.state == "hot"
          and (.placement_hints.preferred_worker_ids | index("rch-a") != null)
          and (.fail_closed_reasons | length) == 0
        ' "${output_dir}/swarm_topology_placement_input.json" >/dev/null \
          || record_failure "healthy fixture must produce hot-cache NUMA-local advice"
        ;;
      degraded_missing_cache_residency)
        jq -e '
          any(.degraded_reasons[]?; .source_id == "cache_residency_json")
          and .warm_cache_residency.state == "missing_optional"
        ' "${output_dir}/swarm_topology_placement_input.json" >/dev/null \
          || record_failure "degraded fixture must expose missing cache residency"
        ;;
      blocked_contradictory_locality)
        jq -e '
          any(.blocked_reasons[]?; .code == "contradictory_locality_evidence")
          and .placement_hints.recommended_topology_class == "contradictory_locality"
        ' "${output_dir}/swarm_topology_placement_input.json" >/dev/null \
          || record_failure "blocked fixture must expose contradictory locality"
        ;;
      contaminated_local_fallback)
        jq -e '
          any(.fail_closed_reasons[]?; .code == "rch_local_fallback_contaminates_locality")
        ' "${output_dir}/swarm_topology_placement_input.json" >/dev/null \
          || record_failure "contaminated fixture must expose local fallback contamination"
        ;;
      fail_closed_malformed_topology)
        jq -e '
          any(.fail_closed_reasons[]?; .code == "malformed_topology_snapshot")
        ' "${output_dir}/swarm_topology_placement_input.json" >/dev/null \
          || record_failure "malformed topology fixture must fail closed"
        ;;
    esac
  done < <(jq -r '.scenarios[].scenario_id' "$fixture_bundle_path")

  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest fixtures"
  fi
  printf 'swarm_topology_placement_normalizer_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
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
    record_failure "unknown mode: ${1:-}"
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
