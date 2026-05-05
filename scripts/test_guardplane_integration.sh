#!/usr/bin/env bash
set -euo pipefail

# Test script for RC-4.2 Guardplane Adapter integration
# This script tests the GuardplaneAdapter implementation with the baseline interpreter

LOG="artifacts/test_guardplane_integration_$(date +%s).jsonl"
ARTIFACTS="artifacts/guardplane_integration/$(date +%Y%m%d_%H%M%S)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_guardplane_integration}"
RCH_LOG_DIR="${ARTIFACTS}/rch_logs"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$RCH_LOG_DIR"

if ! command -v rch >/dev/null 2>&1; then
    echo "rch is required for guardplane Cargo validation" >&2
    exit 2
fi

last_rch_exit=0

rch_reject_local_fallback() {
    local log_path="$1"
    if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(' "$log_path"; then
        echo "rch reported local fallback; refusing local Cargo execution" >&2
        return 1
    fi
}

run_rch_cargo_step() {
    local step_name="$1"
    local log_path="${RCH_LOG_DIR}/${step_name}.log"
    local exit_code
    shift

    echo "==> rch exec -- env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} $*"
    set +e
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
        rch exec -- env "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" "$@" 2>&1 | tee "$log_path"
    exit_code="${PIPESTATUS[0]}"
    set -e

    if ! rch_reject_local_fallback "$log_path"; then
        exit_code=1
    fi
    last_rch_exit="$exit_code"
}

echo "Starting Guardplane Integration Test Suite..."
echo "{\"suite\":\"guardplane_integration\",\"started\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 1: Unit tests for GuardplaneAdapter
echo "Running GuardplaneAdapter unit tests..."
run_rch_cargo_step guardplane_adapter_unit cargo test -p frankenengine-engine guardplane_adapter::tests --nocapture
test_exit="$last_rch_exit"
echo "{\"test\":\"unit_tests\",\"exit\":$test_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

if [[ "$test_exit" -ne 0 ]]; then
    echo "Unit tests failed with exit code $test_exit"
    exit "$test_exit"
fi

# Test 2: Integration tests with interpreter hooks
echo "Running guardplane calibration integration tests..."
run_rch_cargo_step guardplane_calibration_integration cargo test -p frankenengine-engine guardplane_calibration_integration --nocapture
integration_exit="$last_rch_exit"
echo "{\"test\":\"integration_tests\",\"exit\":$integration_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 3: Enrichment integration tests
echo "Running guardplane calibration enrichment tests..."
run_rch_cargo_step guardplane_calibration_enrichment cargo test -p frankenengine-engine guardplane_calibration_enrichment_integration --nocapture
enrichment_exit="$last_rch_exit"
echo "{\"test\":\"enrichment_tests\",\"exit\":$enrichment_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 4: Compilation check to ensure adapter compiles cleanly
echo "Checking compilation of guardplane adapter..."
run_rch_cargo_step guardplane_compile cargo check -p frankenengine-engine
compile_exit="$last_rch_exit"
echo "{\"test\":\"compilation_check\",\"exit\":$compile_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 5: Clippy check for code quality
echo "Running clippy checks on guardplane adapter..."
run_rch_cargo_step guardplane_clippy cargo clippy -p frankenengine-engine --lib -- -D warnings
clippy_exit="$last_rch_exit"
echo "{\"test\":\"clippy_check\",\"exit\":$clippy_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Summary
total_tests=5
failed_tests=0

if [[ "$test_exit" -ne 0 ]]; then ((failed_tests += 1)); fi
if [[ "$integration_exit" -ne 0 ]]; then ((failed_tests += 1)); fi
if [[ "$enrichment_exit" -ne 0 ]]; then ((failed_tests += 1)); fi
if [[ "$compile_exit" -ne 0 ]]; then ((failed_tests += 1)); fi
if [[ "$clippy_exit" -ne 0 ]]; then ((failed_tests += 1)); fi

passed_tests=$((total_tests - failed_tests))

echo ""
echo "=== Guardplane Integration Test Results ==="
echo "Total tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"
echo "Log file: $LOG"

echo "{\"suite\":\"guardplane_integration\",\"completed\":\"$(date -Iseconds)\",\"total\":$total_tests,\"passed\":$passed_tests,\"failed\":$failed_tests}" >> "$LOG"

if [[ "$failed_tests" -eq 0 ]]; then
    echo "✅ All guardplane integration tests passed!"
    exit 0
else
    echo "❌ $failed_tests test(s) failed!"
    exit 1
fi
