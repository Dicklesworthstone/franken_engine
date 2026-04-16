#!/usr/bin/env bash
set -euo pipefail

# Test script for RC-4.2 Guardplane Adapter integration
# This script tests the GuardplaneAdapter implementation with the baseline interpreter

LOG="artifacts/test_guardplane_integration_$(date +%s).jsonl"
mkdir -p "$(dirname "$LOG")"

echo "Starting Guardplane Integration Test Suite..."
echo "{\"suite\":\"guardplane_integration\",\"started\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 1: Unit tests for GuardplaneAdapter
echo "Running GuardplaneAdapter unit tests..."
cargo test -p frankenengine-engine guardplane_adapter::tests --nocapture 2>&1
test_exit=$?
echo "{\"test\":\"unit_tests\",\"exit\":$test_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

if [ $test_exit -ne 0 ]; then
    echo "Unit tests failed with exit code $test_exit"
    exit $test_exit
fi

# Test 2: Integration tests with interpreter hooks
echo "Running guardplane calibration integration tests..."
cargo test -p frankenengine-engine guardplane_calibration_integration --nocapture 2>&1
integration_exit=$?
echo "{\"test\":\"integration_tests\",\"exit\":$integration_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 3: Enrichment integration tests
echo "Running guardplane calibration enrichment tests..."
cargo test -p frankenengine-engine guardplane_calibration_enrichment_integration --nocapture 2>&1
enrichment_exit=$?
echo "{\"test\":\"enrichment_tests\",\"exit\":$enrichment_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 4: Compilation check to ensure adapter compiles cleanly
echo "Checking compilation of guardplane adapter..."
cargo check -p frankenengine-engine 2>&1
compile_exit=$?
echo "{\"test\":\"compilation_check\",\"exit\":$compile_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 5: Clippy check for code quality
echo "Running clippy checks on guardplane adapter..."
cargo clippy -p frankenengine-engine --lib -- -D warnings 2>&1
clippy_exit=$?
echo "{\"test\":\"clippy_check\",\"exit\":$clippy_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Summary
total_tests=5
failed_tests=0

if [ $test_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $integration_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $enrichment_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $compile_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $clippy_exit -ne 0 ]; then ((failed_tests++)); fi

passed_tests=$((total_tests - failed_tests))

echo ""
echo "=== Guardplane Integration Test Results ==="
echo "Total tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"
echo "Log file: $LOG"

echo "{\"suite\":\"guardplane_integration\",\"completed\":\"$(date -Iseconds)\",\"total\":$total_tests,\"passed\":$passed_tests,\"failed\":$failed_tests}" >> "$LOG"

if [ $failed_tests -eq 0 ]; then
    echo "✅ All guardplane integration tests passed!"
    exit 0
else
    echo "❌ $failed_tests test(s) failed!"
    exit 1
fi