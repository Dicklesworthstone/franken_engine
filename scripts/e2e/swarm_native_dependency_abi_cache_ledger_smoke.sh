#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger="${root_dir}/scripts/swarm_native_dependency_abi_cache_ledger.sh"
contract_path="${root_dir}/docs/swarm_native_dependency_abi_cache_ledger_contract_v1.json"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_abi_cache_ledger/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-abi-cache-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-abi-cache-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_abi_cache_ledger_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'apt(-get)? install|dnf install|yum install|rm -rf|git clean|deletes target directories automatically|mutates remote workers|changes live queue policy automatically|updates beads automatically|sends Agent Mail automatically|reroutes tasks automatically|repairs workers automatically' "$path"; then
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
    .schema_version == "franken-engine.swarm-native-dependency-abi-cache-ledger-contract.v1"
    and .bead_id == "bd-sqm14.5"
    and .parent_bead_id == "bd-sqm14"
    and (.depends_on | index("bd-sqm14.2") != null)
    and (.depends_on | index("bd-sqm14.3") != null)
    and .script == "scripts/swarm_native_dependency_abi_cache_ledger.sh"
    and .smoke_script == "scripts/e2e/swarm_native_dependency_abi_cache_ledger_smoke.sh"
    and .fixture_bundle == "scripts/testdata/swarm_native_dependency_abi_cache_ledger/cases.json"
    and .output_schema_version == "franken-engine.native-dependency-abi-cache-ledger.v1"
    and (.fingerprint_fields | index("rch_worker_id") != null)
    and (.fingerprint_fields | index("pkg_config_version") != null)
    and (.fingerprint_fields | index("header_paths") != null)
    and (.required_reason_codes | index("abi_fingerprint_match") != null)
    and (.required_reason_codes | index("missing_required_header_path") != null)
    and (.required_reason_codes | index("worker_identity_changed") != null)
    and .exit_codes.reuse_quarantined == 75
    and .exit_codes.fail_closed == 42
    and .mutation_policy.deletes_target_dirs == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and (.proof_cases | index("hdf5_1_14_5_reuse_match") != null)
    and (.proof_cases | index("changed_worker_identity_quarantine") != null)
  ' "$contract_path" >/dev/null
}

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-abi-cache-ledger-cases.v1"
    and (.scenarios | length == 5)
    and ([.scenarios[].scenario_id] | sort == [
      "changed_hdf5_version_quarantine",
      "changed_worker_identity_quarantine",
      "hdf5_1_14_5_reuse_match",
      "missing_hdf5_header_fail_closed",
      "missing_hdf5_quarantine"
    ])
    and all(.scenarios[];
      (.expected_reason_codes | length > 0)
      and (.inputs.abi_cache_input_json.schema_version == "franken-engine.native-dependency-abi-cache-input.v1")
      and (.inputs.abi_cache_input_json.native_dependencies | length > 0)
    )
    and (.scenarios[] | select(.scenario_id == "hdf5_1_14_5_reuse_match") | .expected_exit_code == 0)
    and (.scenarios[] | select(.scenario_id == "missing_hdf5_quarantine") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "changed_hdf5_version_quarantine") | .expected_exit_code == 75)
    and (.scenarios[] | select(.scenario_id == "missing_hdf5_header_fail_closed") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "changed_worker_identity_quarantine") | .expected_exit_code == 75)
  ' "$cases_path" >/dev/null
}

canonical_fingerprint_for_case() {
  local input_path="$1"
  jq -cS '{
    rust_toolchain,
    rch_worker_id,
    target_dir_id,
    requirement_bundle_version,
    native_dependencies: ((.native_dependencies // []) | sort_by(.dependency_id) | map({
      dependency_id,
      pkg_config_version,
      include_roots,
      environment_roots,
      header_paths,
      abi_fingerprint
    }))
  }' "$input_path" | sha256sum | awk '{print $1}'
}

materialize_case_input() {
  local scenario="$1"
  local output_path="$2"
  jq --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .inputs.abi_cache_input_json' "$cases_path" >"$output_path"
  if jq -e '.cached_proof.abi_fingerprint == "__SELF__"' "$output_path" >/dev/null; then
    local fingerprint
    fingerprint="$(canonical_fingerprint_for_case "$output_path")"
    local tmp="${output_path}.tmp"
    jq --arg fingerprint "$fingerprint" '.cached_proof.abi_fingerprint = $fingerprint' "$output_path" >"$tmp"
    mv "$tmp" "$output_path"
  fi
}

run_case() {
  local scenario="$1"
  local input_path="$2"
  local output_dir="$3"
  local expected_decision expected_exit_code expected_reuse_allowed
  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$cases_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$cases_path")"
  expected_reuse_allowed="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_reuse_allowed' "$cases_path")"
  mkdir -p "$output_dir"

  local code=0
  set +e
  bash "$ledger" \
    --source-revision fixture-rev \
    --abi-cache-input-json "$input_path" \
    --contract-json "$contract_path" \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" --argjson reuse_allowed "$expected_reuse_allowed" '
    .decision == $decision and .reuse_allowed == $reuse_allowed
  ' "${output_dir}/native_dependency_abi_cache_ledger.json" >/dev/null || {
    record_failure "${scenario} decision or reuse flag mismatch"
    return 1
  }
  jq -e \
    --argjson expected_reason_codes "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_reason_codes' "$cases_path")" '
      (($expected_reason_codes - .reason_codes) | length == 0)
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
      and .mutation_policy.deletes_target_dirs == false
  ' "${output_dir}/native_dependency_abi_cache_ledger.json" >/dev/null || {
    record_failure "${scenario} reason codes or mutation policy mismatch"
    return 1
  }
  jq -e 'length >= 2' "${output_dir}/events.jsonl" >/dev/null || {
    record_failure "${scenario} events.jsonl did not record structured events"
    return 1
  }
}

run_check() {
  bash -n "$ledger"
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

  check_no_mutation_claims "$ledger"
  check_no_mutation_claims "$contract_path"
  check_no_mutation_claims "$cases_path"
  check_no_bare_heavy_cargo "$ledger"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$cases_path"
}

run_selftest() {
  local tmp_root scenario input_path output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-native-dependency-abi-cache-ledger-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_path="${tmp_root}/${scenario}/abi_cache_input.json"
    output_dir="${tmp_root}/${scenario}/out"
    mkdir -p "$(dirname "$input_path")"
    materialize_case_input "$scenario" "$input_path"
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
