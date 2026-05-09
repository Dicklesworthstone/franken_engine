#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
status_script="${root_dir}/scripts/swarm_native_dependency_operator_status.sh"
docs_path="${root_dir}/docs/SWARM_NATIVE_DEPENDENCY_OPERATOR_STATUS.md"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_operator_status/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-operator-status %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-operator-status %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_operator_status_smoke.sh [check|selftest]
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

check_no_forbidden_text() {
  local path="$1"
  if grep -Eiq '(^|[^a-z])master([^a-z]|$)|apt(-get)? install|dnf install|yum install|rm -rf|mutates remote workers|reroutes tasks automatically|repairs workers automatically' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden operator wording"
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

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-operator-status-cases.v1"
    and (.scenarios | length == 4)
    and ([.scenarios[].scenario_id] | sort == [
      "all_blocked_missing_hdf5",
      "compatible_reusable",
      "incompatible_worker_rejected",
      "stale_fail_closed"
    ])
    and all(.scenarios[];
      (.expected_strings | length > 0)
      and (.inputs.route_advisory_json.schema_version == "franken-engine.native-dependency-routing-advisory.v1")
      and (.inputs.abi_cache_ledger_json.schema_version == "franken-engine.native-dependency-abi-cache-ledger.v1")
    )
    and (.scenarios[] | select(.scenario_id == "compatible_reusable") | .expected_exit_code == 0)
    and (.scenarios[] | select(.scenario_id == "stale_fail_closed") | .expected_exit_code == 42)
    and (.scenarios[] | select(.scenario_id == "all_blocked_missing_hdf5") | .expected_exit_code == 75)
  ' "$cases_path" >/dev/null
}

run_case() {
  local scenario="$1"
  local route_path="$2"
  local abi_path="$3"
  local output_dir="$4"
  local expected_status expected_exit_code
  expected_status="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_status' "$cases_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$cases_path")"
  mkdir -p "$output_dir"

  local code=0
  set +e
  bash "$status_script" \
    --source-revision fixture-rev \
    --route-advisory-json "$route_path" \
    --abi-cache-ledger-json "$abi_path" \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi
  jq -e --arg status "$expected_status" '.status == $status and .source_failure_claimed == false and .advisory_only == true' "${output_dir}/native_dependency_operator_status.json" >/dev/null || {
    record_failure "${scenario} status JSON mismatch"
    return 1
  }
  while IFS= read -r expected; do
    grep -Fq "$expected" "${output_dir}/native_dependency_operator_status.md" "${output_dir}/agent_mail_handoff.md" "${output_dir}/br_closeout_snippet.md" || {
      record_failure "${scenario} missing expected text: ${expected}"
      return 1
    }
  done < <(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_strings[]' "$cases_path")
  check_no_forbidden_text "${output_dir}/native_dependency_operator_status.md"
  check_no_forbidden_text "${output_dir}/agent_mail_handoff.md"
  check_no_forbidden_text "${output_dir}/br_closeout_snippet.md"
}

run_check() {
  bash -n "$status_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$cases_path"
  cases_shape_ok && record_pass "fixture cases" || record_failure "fixture cases mismatch"

  grep -Fq 'advisory-only and evidence-only' "$docs_path" || record_failure "docs must say advisory-only and evidence-only"
  grep -Fq 'not evidence that the source patch failed' "$docs_path" || record_failure "docs must preserve no-source-failure wording"
  check_no_forbidden_text "$docs_path"
  check_no_forbidden_text "$status_script"
  check_no_forbidden_text "$cases_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$status_script"
  check_no_bare_heavy_cargo "$cases_path"
}

run_selftest() {
  local tmp_root scenario route_path abi_path output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-native-dependency-operator-status-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    route_path="${tmp_root}/${scenario}/route.json"
    abi_path="${tmp_root}/${scenario}/abi.json"
    output_dir="${tmp_root}/${scenario}/out"
    mkdir -p "$(dirname "$route_path")"
    extract_fixture_input "$scenario" "route_advisory_json" "$route_path"
    extract_fixture_input "$scenario" "abi_cache_ledger_json" "$abi_path"
    run_case "$scenario" "$route_path" "$abi_path" "$output_dir" || continue
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
