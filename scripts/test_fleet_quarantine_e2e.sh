#!/usr/bin/env bash
set -euo pipefail

# Fleet Quarantine Propagation E2E Test Script - RC-5.5
# Tests end-to-end fleet quarantine with SLO proof and TEE attestation

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="artifacts/test_fleet_quarantine_${TIMESTAMP}.jsonl"
ARTIFACTS="artifacts/fleet_evidence/${TIMESTAMP}"
TEST_OUTPUT_DIR="$ARTIFACTS/test_output"
CONVERGENCE_SOURCE="$ARTIFACTS/convergence_metrics_sources.jsonl"
TEE_SOURCE="$ARTIFACTS/tee_verification_sources.jsonl"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${FLEET_QUARANTINE_E2E_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_fleet_quarantine_${TIMESTAMP}}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"
mkdir -p "$TEST_OUTPUT_DIR"
: > "$CONVERGENCE_SOURCE"
: > "$TEE_SOURCE"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required rch binary not found: $RCH_BIN" >&2
    exit 127
fi

echo "=== Fleet Quarantine Propagation E2E Test ==="
echo "Timestamp: $TIMESTAMP"
echo "Artifacts: $ARTIFACTS"
echo "Log: $LOG"
echo "RCH target dir: $CARGO_TARGET_DIR"

# Initialize test log
cat > "$LOG" << EOF
{"suite":"fleet_quarantine_e2e","started":"$(date -Iseconds)","instances":10,"timestamp":"$TIMESTAMP"}
EOF

echo "Starting fleet quarantine integration tests..."

extract_test_markers() {
    local output_file=$1

    grep '^FLEET_CONVERGENCE_METRICS_JSON=' "$output_file" \
        | sed 's/^FLEET_CONVERGENCE_METRICS_JSON=//' >> "$CONVERGENCE_SOURCE" || true
    grep '^FLEET_TEE_VERIFICATION_JSON=' "$output_file" \
        | sed 's/^FLEET_TEE_VERIFICATION_JSON=//' >> "$TEE_SOURCE" || true
}

run_rch_cargo_test() {
    "$RCH_BIN" exec -- env \
        "CARGO_INCREMENTAL=$CARGO_INCREMENTAL" \
        "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
        "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
        cargo test "$@"
}

# Test execution helper
run_fleet_quarantine_test() {
    local test_name=$1
    local output_file="$TEST_OUTPUT_DIR/${test_name}.log"
    echo "Running fleet quarantine test: $test_name"

    local start_time
    start_time=$(date +%s%3N)
    local test_exit=0

    # Run cargo test for specific fleet quarantine test through rch.
    if run_rch_cargo_test --test fleet_quarantine_integration "$test_name" -- --nocapture 2>&1 | tee "$output_file"; then
        test_exit=0
    else
        test_exit=1
    fi
    extract_test_markers "$output_file"

    local end_time
    end_time=$(date +%s%3N)
    local duration=$((end_time - start_time))

    cat >> "$LOG" << EOF
{"test":"$test_name","status":"$([ $test_exit -eq 0 ] && echo "pass" || echo "fail")","duration_ms":$duration,"timestamp":"$(date -Iseconds)"}
EOF

    return $test_exit
}

# ==========================================================================
# Core Integration Tests
# ==========================================================================

echo "=== Core Integration Tests ==="

# Test 1: Fleet starts with all instances healthy
run_fleet_quarantine_test "test_fleet_start_all_healthy"
test1_exit=$?

# Test 2: Quarantine decision broadcasts to all instances
run_fleet_quarantine_test "test_quarantine_broadcast"
test2_exit=$?

# Test 3: Convergence time measurement
run_fleet_quarantine_test "test_convergence_measured"
test3_exit=$?

# Test 4: TEE attestation integration
run_fleet_quarantine_test "test_tee_attestation_required"
test4_exit=$?

# Test 5: Duplicate quarantine decisions ignored
run_fleet_quarantine_test "test_duplicate_quarantine_ignored"
test5_exit=$?

# Test 6: Partition mode resilience
run_fleet_quarantine_test "test_minority_partition_tightens"
test6_exit=$?

# Test 7: SLO compliance verification
run_fleet_quarantine_test "test_convergence_slo_met"
test7_exit=$?

# Test 8: Evidence bundle completeness
run_fleet_quarantine_test "test_evidence_bundle_complete"
test8_exit=$?

# Test 9: Statistical analysis with 100 events
echo "Running statistical analysis test (100 quarantine events)..."
run_fleet_quarantine_test "test_100_quarantine_events"
test9_exit=$?

# ==========================================================================
# Full Fleet Simulation Test
# ==========================================================================

echo "=== Full Fleet Simulation ==="

# Test 10: Complete fleet quarantine simulation
echo "Running complete fleet quarantine simulation..."
full_output_file="$TEST_OUTPUT_DIR/full_fleet_simulation.log"
if run_rch_cargo_test --test fleet_quarantine_integration -- --nocapture 2>&1 | tee "$full_output_file"; then
    test10_exit=0
else
    test10_exit=1
fi
extract_test_markers "$full_output_file"

cat >> "$LOG" << EOF
{"test":"full_fleet_simulation","status":"$([ $test10_exit -eq 0 ] && echo "pass" || echo "fail")","timestamp":"$(date -Iseconds)"}
EOF

# ==========================================================================
# Generate Summary Report
# ==========================================================================

# Calculate results
total_tests=10
failed_tests=0

if [ $test1_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test2_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test3_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test4_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test5_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test6_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test7_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test8_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test9_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test10_exit -ne 0 ]; then ((failed_tests++)); fi

passed_tests=$((total_tests - failed_tests))
success_rate=$(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l)

echo ""
echo "=== Fleet Quarantine E2E Test Results ==="
echo "Total test cases: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"
echo "Success rate: ${success_rate}%"

# Create detailed summary artifact
cat > "$ARTIFACTS/fleet_quarantine_summary.json" << EOF
{
  "test_suite": "fleet_quarantine_e2e",
  "timestamp": "$(date -Iseconds)",
  "execution_summary": {
    "total_tests": $total_tests,
    "passed_tests": $passed_tests,
    "failed_tests": $failed_tests,
    "success_rate_percent": $success_rate
  },
  "test_results": {
    "fleet_start_healthy": {"exit_code": $test1_exit},
    "quarantine_broadcast": {"exit_code": $test2_exit},
    "convergence_measured": {"exit_code": $test3_exit},
    "tee_attestation": {"exit_code": $test4_exit},
    "duplicate_ignored": {"exit_code": $test5_exit},
    "partition_resilience": {"exit_code": $test6_exit},
    "slo_compliance": {"exit_code": $test7_exit},
    "evidence_bundle": {"exit_code": $test8_exit},
    "statistical_analysis": {"exit_code": $test9_exit},
    "full_simulation": {"exit_code": $test10_exit}
  },
  "fleet_configuration": {
    "instance_count": 10,
    "max_convergence_slo_ms": 500,
    "tee_platform": "intel_sgx",
    "partition_modes_tested": ["normal", "degraded", "healing"]
  },
  "slo_verification": {
    "convergence_target_ms": 500,
    "statistical_sample_size": 100,
    "slo_compliance_required": ">=95%"
  },
  "artifacts_location": "$ARTIFACTS",
  "log_file": "$LOG",
  "convergence_source_file": "$CONVERGENCE_SOURCE",
  "tee_source_file": "$TEE_SOURCE",
  "description": "End-to-end fleet quarantine propagation with SLO proof and TEE attestation"
}
EOF

# Generate convergence metrics artifact from measured test output.
if [ ! -s "$CONVERGENCE_SOURCE" ]; then
    echo "No measured convergence metric markers found in cargo test output" >&2
    exit 1
fi

jq -s \
    --arg ts "$(date -Iseconds)" \
    --arg source_file "$CONVERGENCE_SOURCE" \
    --arg log_file "$LOG" '
def percentile($values; $p):
  if ($values | length) == 0 then 0
  else $values[((($values | length) * $p / 100) | floor)]
  end;

[ .[]
  | select(.measurement_source == "fleet_quarantine_integration_output")
  | select(.simulated == false)
] as $sources
| ($sources[0].slo_threshold_ms // 500) as $threshold
| [ $sources[] | .durations_ms[]? ] as $durations
| if ($durations | length) == 0 then
    error("no measured convergence durations")
  else
    ($durations | sort) as $sorted
    | ($sorted | map(select(. > $threshold)) | length) as $violations
    | {
        p50_ms: percentile($sorted; 50),
        p95_ms: percentile($sorted; 95),
        p99_ms: percentile($sorted; 99),
        max_ms: ($sorted[-1]),
        mean_ms: (($sorted | add) / ($sorted | length)),
        slo_met: ($violations == 0),
        total_events: ($sorted | length),
        violations: $violations,
        slo_threshold_ms: $threshold,
        compliance_percentage: (((($sorted | length) - $violations) * 100) / ($sorted | length)),
        measurement_timestamp: $ts,
        measurement_source: "fleet_quarantine_integration_output",
        source_artifact: $source_file,
        log_file: $log_file,
        simulated: false,
        raw_measurement_count: ($sorted | length)
      }
  end
' "$CONVERGENCE_SOURCE" > "$ARTIFACTS/convergence_metrics.json"

jq -e '
  .simulated == false
  and .measurement_source == "fleet_quarantine_integration_output"
  and (.raw_measurement_count > 0)
  and (.source_artifact | length > 0)
' "$ARTIFACTS/convergence_metrics.json" > /dev/null

# Generate TEE attestation verification artifact. Mock-provider output is
# explicitly non-authoritative and fails closed for evidence gates.
if [ -s "$TEE_SOURCE" ]; then
    jq -s \
        --arg ts "$(date -Iseconds)" \
        --arg source_file "$TEE_SOURCE" '
.[0] + {
  authoritative: false,
  fail_closed_for_evidence_gates: true,
  evidence_gate_status: "fail_closed_non_authoritative_mock",
  verification_timestamp: $ts,
  source_artifact: $source_file
}
' "$TEE_SOURCE" > "$ARTIFACTS/tee_verification.json"
else
    cat > "$ARTIFACTS/tee_verification.json" << EOF
{
  "provider_kind": "none",
  "authoritative": false,
  "fail_closed_for_evidence_gates": true,
  "evidence_gate_status": "fail_closed_no_test_output",
  "source_available": false,
  "verification_timestamp": "$(date -Iseconds)",
  "source_artifact": "$TEE_SOURCE"
}
EOF
fi

jq -e '
  .authoritative == false
  and .fail_closed_for_evidence_gates == true
  and (.evidence_gate_status | startswith("fail_closed_"))
' "$ARTIFACTS/tee_verification.json" > /dev/null

# Final log entry
cat >> "$LOG" << EOF
{"suite":"fleet_quarantine_e2e","completed":"$(date -Iseconds)","total":$total_tests,"passed":$passed_tests,"failed":$failed_tests,"success_rate":$success_rate}
EOF

echo ""
echo "Artifacts generated:"
echo "- Summary: $ARTIFACTS/fleet_quarantine_summary.json"
echo "- Convergence metrics: $ARTIFACTS/convergence_metrics.json"
echo "- TEE verification: $ARTIFACTS/tee_verification.json"
echo "- Full log: $LOG"
echo ""

if [ $failed_tests -eq 0 ]; then
    echo "✅ All fleet quarantine tests passed!"
    echo "🔒 Fleet quarantine propagation with SLO proof verified"
    echo "📊 Convergence SLO: metrics derived from measured fleet test output"
    echo "🛡️  TEE attestation: mock-provider artifact marked non-authoritative/fail-closed"
    echo "📁 Evidence bundles published to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test case(s) failed!"
    echo "📋 Review test results and artifacts for details"
    echo "📁 Artifacts location: $ARTIFACTS"
    exit 1
fi
