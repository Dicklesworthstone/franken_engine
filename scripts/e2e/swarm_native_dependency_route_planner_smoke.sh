#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_native_dependency_route_planner.sh"
contract_path="${root_dir}/docs/swarm_native_dependency_route_planner_contract_v1.json"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_route_planner/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-route-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-route-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_route_planner_smoke.sh [check|selftest]
EOF
}

extract_fixture_input() {
  local scenario="$1"
  local input_id="$2"
  local output_path="$3"
  jq --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[] | select(.scenario_id == $scenario) | .inputs[$input_id]
  ' "$cases_path" >"$output_path"
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
    .schema_version == "franken-engine.swarm-native-dependency-route-planner-contract.v1"
    and .bead_id == "bd-sqm14.4"
    and .parent_bead_id == "bd-sqm14"
    and (.depends_on | index("bd-sqm14.1") != null)
    and (.depends_on | index("bd-sqm14.2") != null)
    and (.depends_on | index("bd-sqm14.3") != null)
    and .script == "scripts/swarm_native_dependency_route_planner.sh"
    and .smoke_script == "scripts/e2e/swarm_native_dependency_route_planner_smoke.sh"
    and .fixture_bundle == "scripts/testdata/swarm_native_dependency_route_planner/cases.json"
    and .output_schema_version == "franken-engine.native-dependency-routing-advisory.v1"
    and (.advisory_fields | index("compatible_worker_ids") != null)
    and (.advisory_fields | index("fail_closed_workers") != null)
    and (.required_reason_codes | index("compatible_worker_available") != null)
    and (.required_reason_codes | index("no_compatible_workers") != null)
    and (.required_reason_codes | index("local_fallback_contaminated") != null)
    and .exit_codes.blocked == 75
    and .exit_codes.fail_closed == 42
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and (.proof_cases | index("present_hdf5_compatible_route") != null)
    and (.proof_cases | index("all_incompatible_workers_blocked") != null)
  ' "$contract_path" >/dev/null
}

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-route-planner-cases.v1"
    and (.scenarios | length == 6)
    and ([.scenarios[].scenario_id] | sort == [
      "all_incompatible_workers_blocked",
      "contradictory_probe_fail_closed",
      "local_fallback_contaminated_fail_closed",
      "missing_hdf5_worker_rejected",
      "present_hdf5_compatible_route",
      "stale_worker_evidence_fail_closed"
    ])
    and all(.scenarios[];
      (.expected_reason_codes | length > 0)
      and (.inputs.native_requirement_bundle_json.schema_version == "franken-engine.native-requirement-bundle.v1")
      and (.inputs.worker_probe_snapshots_json.schema_version == "franken-engine.worker-native-probe-snapshot-set.v1")
      and (.inputs.worker_probe_snapshots_json.snapshots | length > 0)
    )
    and (.scenarios[] | select(.scenario_id == "present_hdf5_compatible_route") | .expected_exit_code == 0)
    and (.scenarios[] | select(.scenario_id == "missing_hdf5_worker_rejected") | (.expected_incompatible_worker_ids | index("vmi1227854") != null))
    and (.scenarios[] | select(.scenario_id == "stale_worker_evidence_fail_closed") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "contradictory_probe_fail_closed") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "all_incompatible_workers_blocked") | .expected_exit_code == 75)
    and (.scenarios[] | select(.scenario_id == "local_fallback_contaminated_fail_closed") | .expected_truth_state == "contaminated")
  ' "$cases_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local req_path="$2"
  local snapshots_path="$3"
  local output_dir="$4"
  local expected_decision expected_truth_state expected_exit_code
  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$cases_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$cases_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$cases_path")"
  mkdir -p "$output_dir"

  local code=0
  set +e
  bash "$planner" \
    --source-revision fixture-rev \
    --native-requirement-bundle-json "$req_path" \
    --worker-probe-snapshots-json "$snapshots_path" \
    --contract-json "$contract_path" \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" --arg truth_state "$expected_truth_state" '
    .decision == $decision and .truth_state == $truth_state
  ' "${output_dir}/native_dependency_routing_advisory.json" >/dev/null || {
    record_failure "${scenario} decision or truth state mismatch"
    return 1
  }
  jq -e \
    --argjson expected_compatible "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_compatible_worker_ids' "$cases_path")" \
    --argjson expected_incompatible "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_incompatible_worker_ids' "$cases_path")" \
    --argjson expected_fail_closed "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_fail_closed_worker_ids' "$cases_path")" \
    --argjson expected_reason_codes "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_reason_codes' "$cases_path")" '
      (.compatible_worker_ids | sort) == ($expected_compatible | sort)
      and ([.incompatible_workers[].worker_id] | sort) == ($expected_incompatible | sort)
      and ([.fail_closed_workers[].worker_id] | sort) == ($expected_fail_closed | sort)
      and (($expected_reason_codes - .reason_codes) | length == 0)
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
  ' "${output_dir}/native_dependency_routing_advisory.json" >/dev/null || {
    record_failure "${scenario} route sets, reason codes, or mutation policy mismatch"
    return 1
  }
  jq -e 'length >= 2' "${output_dir}/events.jsonl" >/dev/null || {
    record_failure "${scenario} events.jsonl did not record structured events"
    return 1
  }
}

run_check() {
  bash -n "$planner"
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

  check_no_mutation_claims "$planner"
  check_no_mutation_claims "$contract_path"
  check_no_mutation_claims "$cases_path"
  check_no_bare_heavy_cargo "$planner"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$cases_path"
}

run_selftest() {
  local tmp_root scenario req_path snapshots_path output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-native-dependency-route-planner-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    req_path="${tmp_root}/${scenario}/native_requirement_bundle.json"
    snapshots_path="${tmp_root}/${scenario}/worker_probe_snapshots.json"
    output_dir="${tmp_root}/${scenario}/out"
    mkdir -p "$(dirname "$req_path")"
    extract_fixture_input "$scenario" "native_requirement_bundle_json" "$req_path"
    extract_fixture_input "$scenario" "worker_probe_snapshots_json" "$snapshots_path"
    run_case "$scenario" "$req_path" "$snapshots_path" "$output_dir" || continue
    record_pass "selftest ${scenario}"
  done < <(jq -r '.scenarios[].scenario_id' "$cases_path")
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
