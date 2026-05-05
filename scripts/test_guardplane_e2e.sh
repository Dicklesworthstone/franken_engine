#!/usr/bin/env bash
set -euo pipefail

# End-to-end test for Guardplane Integration - RC-4.5
# Tests that untrusted extensions trigger guardplane escalation while trusted extensions run clean

LOG="artifacts/test_guardplane_$(date +%s).jsonl"
ARTIFACTS="artifacts/guardplane_evidence/$(date +%Y%m%d_%H%M%S)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_guardplane_e2e}"
RCH_LOG_DIR="${ARTIFACTS}/rch_logs"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"
mkdir -p "$RCH_LOG_DIR"

if ! command -v rch >/dev/null 2>&1; then
    echo "rch is required for guardplane E2E Cargo validation" >&2
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

echo "=== Guardplane End-to-End Integration Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"

printf '{"suite":"guardplane_integration","started":"%s"}\n' "$(date -Iseconds)" >> "$LOG"

# Create test JavaScript that will trigger property access hooks
cat > /tmp/fe_gp_test.js << 'EOF'
const obj = {a:1, b:2, c:3, d:4, e:5};
let sum = 0;
// This loop will trigger many property access hooks
for (let i = 0; i < 100; i++) {
  sum += obj.a + obj.b + obj.c + obj.d + obj.e;
}
sum; // Should be 1500
EOF

echo "Test JavaScript created: /tmp/fe_gp_test.js"

# Test 1: Run integration test for trusted vs untrusted behavior
echo "Running guardplane integration test..."
run_rch_cargo_step guardplane_integration_e2e cargo test -p frankenengine-engine guardplane_integration_e2e -- --nocapture
test1_exit="$last_rch_exit"
echo "{\"test\":\"guardplane_integration_e2e\",\"exit\":$test1_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 2: Run decision receipt validation tests
echo "Running decision receipt validation tests..."
run_rch_cargo_step decision_receipt cargo test -p frankenengine-engine decision_receipt -- --nocapture
test2_exit="$last_rch_exit"
echo "{\"test\":\"decision_receipt_validation\",\"exit\":$test2_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 3: Run guardplane adapter tests
echo "Running guardplane adapter tests..."
run_rch_cargo_step guardplane_adapter cargo test -p frankenengine-engine guardplane_adapter -- --nocapture
test3_exit="$last_rch_exit"
echo "{\"test\":\"guardplane_adapter\",\"exit\":$test3_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 4: Run containment action tests
echo "Running containment action enforcement tests..."
run_rch_cargo_step containment_tests cargo test -p frankenengine-engine containment_tests -- --nocapture
test4_exit="$last_rch_exit"
echo "{\"test\":\"containment_enforcement\",\"exit\":$test4_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Calculate results
total_tests=4
failed_tests=0

if [[ "$test1_exit" -ne 0 ]]; then ((failed_tests += 1)); fi
if [[ "$test2_exit" -ne 0 ]]; then ((failed_tests += 1)); fi
if [[ "$test3_exit" -ne 0 ]]; then ((failed_tests += 1)); fi
if [[ "$test4_exit" -ne 0 ]]; then ((failed_tests += 1)); fi

passed_tests=$((total_tests - failed_tests))

echo ""
echo "=== Guardplane Integration Test Results ==="
echo "Total test suites: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

# Create summary artifact
cat > "$ARTIFACTS/test_summary.json" << EOF
{
  "test_suite": "guardplane_integration_e2e",
  "timestamp": "$(date -Iseconds)",
  "total_test_suites": $total_tests,
  "passed_test_suites": $passed_tests,
  "failed_test_suites": $failed_tests,
  "test_results": {
    "guardplane_integration_e2e": {"exit_code": $test1_exit},
    "decision_receipt_validation": {"exit_code": $test2_exit},
    "guardplane_adapter": {"exit_code": $test3_exit},
    "containment_enforcement": {"exit_code": $test4_exit}
  },
  "artifacts_location": "$ARTIFACTS",
  "log_file": "$LOG"
}
EOF

printf '{"suite":"guardplane_integration","completed":"%s","total":%s,"passed":%s,"failed":%s}\n' \
    "$(date -Iseconds)" \
    "$total_tests" \
    "$passed_tests" \
    "$failed_tests" >> "$LOG"

if [[ "$failed_tests" -eq 0 ]]; then
    echo "✅ All guardplane integration tests passed!"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test suite(s) failed!"
    echo "Check logs at: $LOG"
    exit 1
fi
