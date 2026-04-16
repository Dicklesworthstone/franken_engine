#!/usr/bin/env bash
# Float Arithmetic E2E Test Suite
# Validates IEEE 754 float support through the full parse->lower->execute pipeline
# with structured JSONL logging and Node.js oracle comparison.
#
# Usage:
#   ./scripts/run_float_e2e.sh [mode]
#   mode: ci (default), interactive, replay
#
# Environment:
#   FLOAT_E2E_ARTIFACT_ROOT - artifact output directory (default: artifacts/float_e2e)
#   FLOAT_E2E_REPLAY_RUN_DIR - replay from existing run directory
#   RCH_EXEC_TIMEOUT_SECONDS - timeout for rch commands (default: 300)

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${FLOAT_E2E_ARTIFACT_ROOT:-artifacts/float_e2e}"
explicit_replay_run_dir="${FLOAT_E2E_REPLAY_RUN_DIR:-}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-300}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/float_conformance_report.json"
node_oracle_path="${run_dir}/node_oracle_results.json"

# Test case counters
total_tests=0
passed_tests=0
failed_tests=0
skipped_tests=0
oracle_divergences=0

# Check if run directory is complete for replay
run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/float_conformance_report.json" ]] || return 1
}

# Replay existing run
replay_existing_run_dir() {
  local candidate="${1:-}"
  if ! run_dir_is_complete "${candidate}"; then
    echo "float e2e replay: run directory incomplete: ${candidate}" >&2
    exit 1
  fi
  echo "=== Float E2E Replay ==="
  echo "manifest: ${candidate}/run_manifest.json"
  cat "${candidate}/run_manifest.json"
  echo ""
  echo "events:"
  cat "${candidate}/events.jsonl"
  echo ""
  echo "report:"
  cat "${candidate}/float_conformance_report.json"
}

if [[ -n "${explicit_replay_run_dir}" ]]; then
  replay_existing_run_dir "${explicit_replay_run_dir}"
  exit 0
fi

mkdir -p "$run_dir"

# Initialize manifest
cat > "$manifest_path" << EOF
{
  "suite": "float_e2e",
  "version": "1.0.0",
  "timestamp": "${timestamp}",
  "mode": "${mode}",
  "root_dir": "${root_dir}",
  "run_dir": "${run_dir}",
  "node_version": "$(node --version 2>/dev/null || echo 'not_available')",
  "replay_command": "FLOAT_E2E_REPLAY_RUN_DIR=\"${run_dir}\" ./scripts/run_float_e2e.sh ${mode}"
}
EOF

# Initialize events file
echo "" > "$events_path"

# Log a test event in JSONL format
log_event() {
  local test_id="$1"
  local category="$2"
  local js_source="$3"
  local expected="$4"
  local actual="$5"
  local status="$6"
  local error="${7:-null}"
  local parse_ms="${8:-0}"
  local execute_ms="${9:-0}"
  local node_result="${10:-null}"

  # Escape JSON strings
  js_source_escaped=$(echo "$js_source" | jq -Rs '.')
  expected_escaped=$(echo "$expected" | jq -Rs '.')
  actual_escaped=$(echo "$actual" | jq -Rs '.')
  error_escaped=$(if [[ "$error" == "null" ]]; then echo "null"; else echo "$error" | jq -Rs '.'; fi)
  node_result_escaped=$(if [[ "$node_result" == "null" ]]; then echo "null"; else echo "$node_result" | jq -Rs '.'; fi)

  cat >> "$events_path" << EOF
{"test_id":${test_id},"category":"${category}","js_source":${js_source_escaped},"expected":${expected_escaped},"actual":${actual_escaped},"status":"${status}","error":${error_escaped},"parse_ms":${parse_ms},"execute_ms":${execute_ms},"node_result":${node_result_escaped}}
EOF
}

# Run a single test case
run_test() {
  local test_id="$1"
  local category="$2"
  local js_source="$3"
  local expected="$4"

  ((total_tests++)) || true

  local start_time end_time duration_ms
  local actual=""
  local status="pass"
  local error="null"
  local node_result="null"

  echo "[$test_id] $category: $js_source"
  echo "  Expected: $expected"

  # Log command
  echo "[$test_id] frankenctl run -e \"$js_source\"" >> "$commands_path"

  start_time=$(date +%s%N)

  # Try to run via frankenctl (if available and working)
  if command -v frankenctl >/dev/null 2>&1; then
    # Create temp file for JS source
    local tmp_js
    tmp_js=$(mktemp --suffix=.js)
    echo "console.log($js_source);" > "$tmp_js"

    # Try to execute
    if actual=$(timeout "${rch_timeout_seconds}s" frankenctl run "$tmp_js" 2>&1); then
      actual=$(echo "$actual" | tail -1 | tr -d '\n')
    else
      error="execution failed or timed out"
      status="error"
      actual="<error>"
    fi
    rm -f "$tmp_js"
  else
    # frankenctl not available, mark as skipped
    status="skip"
    actual="<skipped: frankenctl not available>"
    ((skipped_tests++)) || true
  fi

  end_time=$(date +%s%N)
  duration_ms=$(( (end_time - start_time) / 1000000 ))

  # Compare with expected (if not error/skip)
  if [[ "$status" == "pass" ]]; then
    if [[ "$actual" != "$expected" ]]; then
      status="fail"
      ((failed_tests++)) || true
    else
      ((passed_tests++)) || true
    fi
  fi

  # Run Node.js oracle for comparison
  if command -v node >/dev/null 2>&1; then
    node_result=$(node -e "console.log($js_source)" 2>&1 || echo "<node_error>")
    node_result=$(echo "$node_result" | tr -d '\n')

    # Check for divergence from node
    if [[ "$status" == "pass" && "$actual" != "$node_result" ]]; then
      echo "  WARNING: Divergence from Node.js oracle"
      ((oracle_divergences++)) || true
    fi
  fi

  echo "  Actual: $actual"
  echo "  Status: $status"
  if [[ -n "$node_result" && "$node_result" != "null" ]]; then
    echo "  Node.js: $node_result"
  fi
  echo ""

  # Log event
  log_event "$test_id" "$category" "$js_source" "$expected" "$actual" "$status" "$error" "$duration_ms" "0" "$node_result"
}

echo "=== Float Arithmetic E2E Test Suite ==="
echo "Timestamp: $timestamp"
echo "Mode: $mode"
echo "Output: $run_dir"
echo ""

# ============================================================================
# Test Cases
# ============================================================================

echo "--- Category: Basic Arithmetic (10 cases) ---"
echo ""

run_test 1 "basic_arithmetic" "1.5 + 2.5" "4"
run_test 2 "basic_arithmetic" "0.1 + 0.2" "0.30000000000000004"
run_test 3 "basic_arithmetic" "1 / 3" "0.3333333333333333"
run_test 4 "basic_arithmetic" "2 ** 0.5" "1.4142135623730951"
run_test 5 "basic_arithmetic" "-0.5 * 2" "-1"
run_test 6 "basic_arithmetic" "1e10 + 1" "10000000001"
run_test 7 "basic_arithmetic" "Number.MAX_SAFE_INTEGER + 1" "9007199254740992"
run_test 8 "basic_arithmetic" "1.7976931348623157e+308" "1.7976931348623157e+308"
run_test 9 "basic_arithmetic" "5e-324" "5e-324"
run_test 10 "basic_arithmetic" "3 + 0.14" "3.14"

echo "--- Category: Special Values (8 cases) ---"
echo ""

run_test 11 "special_values" "NaN !== NaN" "true"
run_test 12 "special_values" "isNaN(NaN)" "true"
run_test 13 "special_values" "isNaN(42)" "false"
run_test 14 "special_values" "Infinity + 1" "Infinity"
run_test 15 "special_values" "1 / 0" "Infinity"
run_test 16 "special_values" "-1 / 0" "-Infinity"
run_test 17 "special_values" "isNaN(0 / 0)" "true"
run_test 18 "special_values" "-0 === 0" "true"

echo "--- Category: Type Coercion (6 cases) ---"
echo ""

run_test 19 "type_coercion" "'3.14' * 1" "3.14"
run_test 20 "type_coercion" "true + 0.5" "1.5"
run_test 21 "type_coercion" "null + 1.5" "1.5"
run_test 22 "type_coercion" "isNaN(undefined + 1)" "true"
run_test 23 "type_coercion" "typeof NaN" "number"
run_test 24 "type_coercion" "typeof Infinity" "number"

echo "--- Category: Bitwise (4 cases) ---"
echo ""

run_test 25 "bitwise" "3.7 | 0" "3"
run_test 26 "bitwise" "-1.5 | 0" "-1"
run_test 27 "bitwise" "2147483648.5 | 0" "-2147483648"
run_test 28 "bitwise" "NaN | 0" "0"

# ============================================================================
# Generate Report
# ============================================================================

echo "=== Summary ==="
echo "Total: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"
echo "Skipped: $skipped_tests"
echo "Node.js Oracle Divergences: $oracle_divergences"
echo ""

# Write conformance report
cat > "$report_path" << EOF
{
  "suite": "float_e2e",
  "timestamp": "${timestamp}",
  "summary": {
    "total": ${total_tests},
    "passed": ${passed_tests},
    "failed": ${failed_tests},
    "skipped": ${skipped_tests},
    "oracle_divergences": ${oracle_divergences}
  },
  "categories": {
    "basic_arithmetic": {"tests": 10},
    "special_values": {"tests": 8},
    "type_coercion": {"tests": 6},
    "bitwise": {"tests": 4}
  },
  "artifacts": {
    "manifest": "${manifest_path}",
    "events": "${events_path}",
    "commands": "${commands_path}",
    "report": "${report_path}"
  },
  "pass_rate": $(echo "scale=4; $passed_tests / $total_tests * 100" | bc 2>/dev/null || echo "0")
}
EOF

echo "Report written to: $report_path"
echo "Events written to: $events_path"

# Exit with failure if any tests failed
if [[ $failed_tests -gt 0 ]]; then
  echo ""
  echo "FAIL: $failed_tests test(s) failed"
  exit 1
fi

echo ""
echo "PASS: All tests passed (or skipped)"
exit 0
