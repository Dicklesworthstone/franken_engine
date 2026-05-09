#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
infer_script="${root_dir}/scripts/swarm_native_dependency_requirement_infer.sh"
map_path="${root_dir}/docs/swarm_native_dependency_requirement_map_v1.json"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_requirement_infer/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-requirement-infer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-requirement-infer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_requirement_infer_smoke.sh [check|selftest]
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

materialize_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  mkdir -p "$dir"
  extract_fixture_input "$scenario" "validation_command_context_json" "${dir}/validation_command_context.json"
  extract_fixture_input "$scenario" "cargo_lock_snapshot_json" "${dir}/cargo_lock_snapshot.json"
  extract_fixture_input "$scenario" "workspace_manifest_snapshot_json" "${dir}/workspace_manifest_snapshot.json"
  extract_fixture_input "$scenario" "path_dependency_manifests_json" "${dir}/path_dependency_manifests.json"
  extract_fixture_input "$scenario" "build_script_diagnostics_json" "${dir}/build_script_diagnostics.json"
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

map_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-requirement-map.v1"
    and .bead_id == "bd-sqm14.2"
    and .parent_bead_id == "bd-sqm14"
    and (.depends_on | index("bd-sqm14.1") != null)
    and .contract == "docs/swarm_native_dependency_routing_contract_v1.json"
    and .script == "scripts/swarm_native_dependency_requirement_infer.sh"
    and .smoke_script == "scripts/e2e/swarm_native_dependency_requirement_infer_smoke.sh"
    and .fixture_bundle == "scripts/testdata/swarm_native_dependency_requirement_infer/cases.json"
    and .output_schema_version == "franken-engine.native-requirement-bundle.v1"
    and .source_schema_version == "franken-engine.native-requirement-infer-sources.v1"
    and (.required_inputs | length == 5)
    and ([.native_dependency_families[].dependency_id] | index("hdf5") != null)
    and ([.native_dependency_families[].dependency_id] | index("sqlite3") != null)
    and ([.native_dependency_families[].dependency_id] | index("openssl") != null)
    and ([.native_dependency_families[].dependency_id] | index("zstd") != null)
    and (.required_reason_codes | index("hdf5_required_present") != null)
    and (.required_reason_codes | index("optional_native_dependency_gated_out") != null)
    and (.required_reason_codes | index("ambiguous_build_script_diagnostic") != null)
    and (.required_reason_codes | index("stale_cargo_lock_manifest_mismatch") != null)
    and (.fail_closed_rules | map(test("build-script native dependency"; "i")) | any)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and (.proof_cases | index("hdf5_path_dependency_closure") != null)
    and (.proof_cases | index("stale_cargo_lock_manifest_mismatch") != null)
  ' "$map_path" >/dev/null
}

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-requirement-infer-cases.v1"
    and (.scenarios | length == 5)
    and ([.scenarios[].scenario_id] | sort == [
      "hdf5_path_dependency_closure",
      "optional_native_dependency_gated_out",
      "rust_only_no_native_dependencies",
      "stale_cargo_lock_manifest_mismatch",
      "unknown_build_script_native_dependency"
    ])
    and all(.scenarios[];
      (.expected_reason_codes | length > 0)
      and (.inputs.validation_command_context_json.schema_version == "franken-engine.validation-command-context.v1")
      and (.inputs.cargo_lock_snapshot_json.schema_version == "franken-engine.cargo-lock-snapshot.v1")
      and (.inputs.workspace_manifest_snapshot_json.schema_version == "franken-engine.workspace-manifest-snapshot.v1")
      and (.inputs.path_dependency_manifests_json.schema_version == "franken-engine.path-dependency-manifests.v1")
      and (.inputs.build_script_diagnostics_json.schema_version == "franken-engine.build-script-diagnostics.v1")
    )
    and (.scenarios[] | select(.scenario_id == "hdf5_path_dependency_closure") | (.expected_dependency_ids | index("hdf5") != null))
    and (.scenarios[] | select(.scenario_id == "rust_only_no_native_dependencies") | .expected_dependency_ids == [])
    and (.scenarios[] | select(.scenario_id == "unknown_build_script_native_dependency") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "optional_native_dependency_gated_out") | (.expected_reason_codes | index("optional_native_dependency_gated_out") != null))
    and (.scenarios[] | select(.scenario_id == "stale_cargo_lock_manifest_mismatch") | .expected_exit_code == 42)
  ' "$cases_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local input_dir="$2"
  local output_dir="$3"
  local expected_decision expected_truth_state expected_exit_code
  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$cases_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$cases_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$cases_path")"
  mkdir -p "$output_dir"

  local code=0
  set +e
  bash "$infer_script" \
    --source-revision fixture-rev \
    --validation-command-context-json "${input_dir}/validation_command_context.json" \
    --cargo-lock-snapshot-json "${input_dir}/cargo_lock_snapshot.json" \
    --workspace-manifest-snapshot-json "${input_dir}/workspace_manifest_snapshot.json" \
    --path-dependency-manifests-json "${input_dir}/path_dependency_manifests.json" \
    --build-script-diagnostics-json "${input_dir}/build_script_diagnostics.json" \
    --requirement-map-json "$map_path" \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" --arg truth_state "$expected_truth_state" '
    .decision == $decision and .truth_state == $truth_state
  ' "${output_dir}/native_dependency_requirement_bundle.json" >/dev/null || {
    record_failure "${scenario} decision or truth state mismatch"
    return 1
  }
  jq -e \
    --argjson expected_dependency_ids "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_dependency_ids' "$cases_path")" \
    --argjson expected_reason_codes "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_reason_codes' "$cases_path")" '
      ([.dependency_requirements[].dependency_id] | unique | sort) == ($expected_dependency_ids | unique | sort)
      and (($expected_reason_codes - .reason_codes) | length == 0)
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
  ' "${output_dir}/native_dependency_requirement_bundle.json" >/dev/null || {
    record_failure "${scenario} dependency ids, reason codes, or mutation policy mismatch"
    return 1
  }
  jq -e 'length >= 2' "${output_dir}/events.jsonl" >/dev/null || {
    record_failure "${scenario} events.jsonl did not record structured events"
    return 1
  }
}

run_check() {
  bash -n "$infer_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$map_path"
  jq empty "$cases_path"

  if map_shape_ok; then
    record_pass "map shape"
  else
    record_failure "map shape mismatch"
  fi
  if cases_shape_ok; then
    record_pass "fixture cases"
  else
    record_failure "fixture cases mismatch"
  fi

  check_no_mutation_claims "$infer_script"
  check_no_mutation_claims "$map_path"
  check_no_mutation_claims "$cases_path"
  check_no_bare_heavy_cargo "$infer_script"
  check_no_bare_heavy_cargo "$map_path"
  check_no_bare_heavy_cargo "$cases_path"
}

run_selftest() {
  local tmp_root scenario input_dir output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-native-dependency-requirement-infer-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/in"
    output_dir="${tmp_root}/${scenario}/out"
    materialize_fixture_dir "$scenario" "$input_dir"
    run_case "$scenario" "$input_dir" "$output_dir" || continue
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
