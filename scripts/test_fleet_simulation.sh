#!/usr/bin/env bash
set -euo pipefail

# Fleet simulation E2E test script - RC-5.1
# Tests N in-process engine instances with deterministic message bus

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_TIMESTAMP="$(date +%s)"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${FLEET_SIMULATION_E2E_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_fleet_simulation_${RUN_TIMESTAMP}_$$}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
LOG="artifacts/test_fleet_simulation_$(date +%s).jsonl"
ARTIFACTS="artifacts/fleet_simulation_evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required rch binary not found: $RCH_BIN" >&2
    exit 2
fi

echo "=== Fleet Simulation Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"
echo "RCH target dir: $CARGO_TARGET_DIR"

printf '{"suite":"fleet_simulation","started":"%s"}\n' "$(date -Iseconds)" >> "$LOG"

run_rch_cargo_test() {
    local step_name="$1"
    shift

    local output_file="${ARTIFACTS}/${step_name}.rch.log"

    "$RCH_BIN" exec -- env \
        "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
        "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
        "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
        cargo test "$@" 2>&1 | tee "$output_file"
    local status=${PIPESTATUS[0]}

    if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$output_file"; then
        echo "rch reported local fallback for $step_name; refusing local execution" >&2
        return 125
    fi

    return "$status"
}

run_fleet_test() {
    local test_name=$1
    local test_exit
    echo "Running fleet simulation test: $test_name"

    # Run cargo test for the specific fleet simulator tests through rch.
    if run_rch_cargo_test "fleet_${test_name}" --lib -p frankenengine-engine "fleet_simulator::tests::${test_name}" -- --nocapture; then
        test_exit=0
    else
        test_exit=$?
    fi

    echo "{\"test\":\"$test_name\",\"exit\":$test_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
    return $test_exit
}

capture_fleet_test() {
    local result_var=$1
    local test_name=$2
    local rc

    if run_fleet_test "$test_name"; then
        rc=0
    else
        rc=$?
    fi

    printf -v "$result_var" '%s' "$rc"
}

test1_exit=0
test2_exit=0
test3_exit=0
test4_exit=0
test5_exit=0
test6_exit=0
test7_exit=0
test8_exit=0
test9_exit=0
test10_exit=0

# Test 1: Create fleet with N=10 instances
echo "Test 1: Fleet creation"
capture_fleet_test test1_exit "test_create_fleet"

# Test 2: Message delivery between instances
echo "Test 2: Message delivery"
capture_fleet_test test2_exit "test_message_delivery"

# Test 3: Broadcast messaging
echo "Test 3: Broadcast messaging"
capture_fleet_test test3_exit "test_broadcast_message"

# Test 4: Partition mode affecting delivery
echo "Test 4: Partition mode simulation"
capture_fleet_test test4_exit "test_partition_mode_affects_delivery"

# Test 5: Instance state transitions
echo "Test 5: Instance state transitions"
capture_fleet_test test5_exit "test_instance_state_transitions"

# Test 6: Simulation statistics
echo "Test 6: Simulation statistics"
capture_fleet_test test6_exit "test_simulation_stats"

# Test 7: Event logging
echo "Test 7: Event logging"
capture_fleet_test test7_exit "test_event_logging"

# Test 8: Error handling
echo "Test 8: Error handling"
capture_fleet_test test8_exit "test_invalid_instance_count"

# Test 9: Instance not found error
echo "Test 9: Instance lookup error handling"
capture_fleet_test test9_exit "test_instance_not_found_error"

# Additional integration test: Full fleet simulation scenario
echo "Test 10: Full simulation scenario"
if run_rch_cargo_test "full_simulation" --lib -p frankenengine-engine fleet_simulator -- --nocapture; then
    test10_exit=0
else
    test10_exit=$?
fi
echo "{\"test\":\"full_simulation\",\"exit\":$test10_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Calculate results
total_tests=10
failed_tests=0

if [ "$test1_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test2_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test3_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test4_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test5_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test6_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test7_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test8_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test9_exit" -ne 0 ]; then ((failed_tests++)); fi
if [ "$test10_exit" -ne 0 ]; then ((failed_tests++)); fi

passed_tests=$((total_tests - failed_tests))
all_tests_passed=false
if [ "$failed_tests" -eq 0 ]; then
    all_tests_passed=true
fi

echo ""
echo "=== Fleet Simulation Test Results ==="
echo "Total test cases: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

# Create summary artifact
cat > "$ARTIFACTS/test_summary.json" << EOF
{
  "test_suite": "fleet_simulation",
  "timestamp": "$(date -Iseconds)",
  "total_test_cases": $total_tests,
  "passed_test_cases": $passed_tests,
  "failed_test_cases": $failed_tests,
  "test_results": {
    "fleet_creation": {"exit_code": $test1_exit},
    "message_delivery": {"exit_code": $test2_exit},
    "broadcast_messaging": {"exit_code": $test3_exit},
    "partition_simulation": {"exit_code": $test4_exit},
    "state_transitions": {"exit_code": $test5_exit},
    "simulation_stats": {"exit_code": $test6_exit},
    "event_logging": {"exit_code": $test7_exit},
    "error_handling": {"exit_code": $test8_exit},
    "instance_lookup_errors": {"exit_code": $test9_exit},
    "full_simulation": {"exit_code": $test10_exit}
  },
  "artifacts_location": "$ARTIFACTS",
  "log_file": "$LOG",
  "description": "Fleet simulator tests N=10 instances with deterministic message bus, partition mode simulation, and JSONL event logging"
}
EOF

cat > "$ARTIFACTS/run_manifest.json" << EOF
{
  "schema_version": "franken-engine.fleet-simulation-e2e.v1",
  "generated_at": "$(date -Iseconds)",
  "test_suite": "fleet_simulation",
  "all_tests_passed": $all_tests_passed,
  "total_test_cases": $total_tests,
  "passed_test_cases": $passed_tests,
  "failed_test_cases": $failed_tests,
  "test_summary": "test_summary.json",
  "jsonl_log": "$LOG",
  "rch_logs": {
    "fleet_creation": "fleet_test_create_fleet.rch.log",
    "message_delivery": "fleet_test_message_delivery.rch.log",
    "broadcast_messaging": "fleet_test_broadcast_message.rch.log",
    "partition_simulation": "fleet_test_partition_mode_affects_delivery.rch.log",
    "state_transitions": "fleet_test_instance_state_transitions.rch.log",
    "simulation_stats": "fleet_test_simulation_stats.rch.log",
    "event_logging": "fleet_test_event_logging.rch.log",
    "error_handling": "fleet_test_invalid_instance_count.rch.log",
    "instance_lookup_errors": "fleet_test_instance_not_found_error.rch.log",
    "full_simulation": "full_simulation.rch.log"
  },
  "failure_policy": "Any failed cargo test, RCH failure, or local-fallback rejection fails this script; no failure is pre-classified as expected."
}
EOF

echo "{\"manifest\":\"fleet_simulation_run_manifest\",\"path\":\"$ARTIFACTS/run_manifest.json\",\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

printf '{"suite":"fleet_simulation","completed":"%s","total":%s,"passed":%s,"failed":%s}\n' \
    "$(date -Iseconds)" "$total_tests" "$passed_tests" "$failed_tests" >> "$LOG"

if [ "$failed_tests" -eq 0 ]; then
    echo "✅ All fleet simulation tests passed!"
    echo "📊 Fleet infrastructure ready for quarantine propagation and SLO measurement"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test case(s) failed!"
    echo "Failures are not expected placeholders; inspect the RCH logs and test summary."
    echo "Check logs at: $LOG"
    exit 1
fi
