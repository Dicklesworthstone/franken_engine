#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_native_dependency_worker_probe_normalizer.sh"
contract_path="${root_dir}/docs/swarm_native_dependency_worker_probe_contract_v1.json"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_worker_probe/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-worker-probe %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-worker-probe %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_worker_probe_smoke.sh [check|selftest]
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
    .schema_version == "franken-engine.swarm-native-dependency-worker-probe-contract.v1"
    and .bead_id == "bd-sqm14.3"
    and .parent_bead_id == "bd-sqm14"
    and (.depends_on | index("bd-sqm14.1") != null)
    and .contract == "docs/swarm_native_dependency_routing_contract_v1.json"
    and .requirement_map == "docs/swarm_native_dependency_requirement_map_v1.json"
    and .script == "scripts/swarm_native_dependency_worker_probe_normalizer.sh"
    and .smoke_script == "scripts/e2e/swarm_native_dependency_worker_probe_smoke.sh"
    and .fixture_bundle == "scripts/testdata/swarm_native_dependency_worker_probe/cases.json"
    and .output_schema_version == "franken-engine.worker-native-probe-snapshot.v1"
    and (.preserved_fields | index("abi_fingerprint") != null)
    and (.preserved_fields | index("contamination_state") != null)
    and (.classifications | index("present") != null)
    and (.classifications | index("missing") != null)
    and (.classifications | index("stale") != null)
    and (.classifications | index("contradictory") != null)
    and (.classifications | index("unsupported") != null)
    and (.classifications | index("contaminated") != null)
    and (.required_reason_codes | index("hdf5_present") != null)
    and (.required_reason_codes | index("hdf5_missing") != null)
    and (.required_reason_codes | index("stale_worker_probe") != null)
    and (.required_reason_codes | index("contradictory_pkg_config_header_evidence") != null)
    and (.required_reason_codes | index("probe_unavailable") != null)
    and (.required_reason_codes | index("local_fallback_contaminated") != null)
    and .exit_codes.blocked == 75
    and .exit_codes.fail_closed == 42
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and (.proof_cases | index("present_hdf5") != null)
    and (.proof_cases | index("local_fallback_contaminated") != null)
  ' "$contract_path" >/dev/null
}

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-worker-probe-cases.v1"
    and (.scenarios | length == 6)
    and ([.scenarios[].scenario_id] | sort == [
      "contradictory_pkg_config_header",
      "local_fallback_contaminated",
      "missing_hdf5",
      "present_hdf5",
      "probe_unavailable",
      "stale_probe"
    ])
    and all(.scenarios[];
      (.expected_reason_codes | length > 0)
      and (.inputs.raw_worker_probe_json.schema_version == "franken-engine.raw-worker-native-probe.v1")
      and (.inputs.raw_worker_probe_json.worker_id | type == "string")
      and (.inputs.raw_worker_probe_json.probes | length > 0)
    )
    and (.scenarios[] | select(.scenario_id == "present_hdf5") | .expected_exit_code == 0)
    and (.scenarios[] | select(.scenario_id == "missing_hdf5") | .expected_exit_code == 75)
    and (.scenarios[] | select(.scenario_id == "stale_probe") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "contradictory_pkg_config_header") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "probe_unavailable") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "local_fallback_contaminated") | .expected_truth_state == "contaminated")
  ' "$cases_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local input_path="$2"
  local output_dir="$3"
  local expected_decision expected_truth_state expected_exit_code
  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$cases_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$cases_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$cases_path")"
  mkdir -p "$output_dir"

  local code=0
  set +e
  bash "$normalizer" \
    --source-revision fixture-rev \
    --raw-worker-probe-json "$input_path" \
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
  ' "${output_dir}/worker_native_probe_snapshot.json" >/dev/null || {
    record_failure "${scenario} decision or truth state mismatch"
    return 1
  }
  jq -e \
    --argjson expected_classifications "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_classifications' "$cases_path")" \
    --argjson expected_reason_codes "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_reason_codes' "$cases_path")" '
      ([.dependency_classifications[] | {dependency_id, classification}] | sort_by(.dependency_id)) == ($expected_classifications | sort_by(.dependency_id))
      and (($expected_reason_codes - .reason_codes) | length == 0)
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
  ' "${output_dir}/worker_native_probe_snapshot.json" >/dev/null || {
    record_failure "${scenario} classifications, reason codes, or mutation policy mismatch"
    return 1
  }
  jq -e 'length >= 2' "${output_dir}/events.jsonl" >/dev/null || {
    record_failure "${scenario} events.jsonl did not record structured events"
    return 1
  }
}

run_check() {
  bash -n "$normalizer"
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

  check_no_mutation_claims "$normalizer"
  check_no_mutation_claims "$contract_path"
  check_no_mutation_claims "$cases_path"
  check_no_bare_heavy_cargo "$normalizer"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$cases_path"
}

run_selftest() {
  local tmp_root scenario input_path output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-native-dependency-worker-probe-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_path="${tmp_root}/${scenario}/raw_worker_probe.json"
    output_dir="${tmp_root}/${scenario}/out"
    mkdir -p "$(dirname "$input_path")"
    extract_fixture_input "$scenario" "raw_worker_probe_json" "$input_path"
    run_case "$scenario" "$input_path" "$output_dir" || continue
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
