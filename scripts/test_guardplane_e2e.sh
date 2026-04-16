#!/usr/bin/env bash
set -euo pipefail

# End-to-end test for Guardplane Integration - RC-4.5
# Tests that untrusted extensions trigger guardplane escalation while trusted extensions run clean

LOG="artifacts/test_guardplane_$(date +%s).jsonl"
ARTIFACTS="artifacts/guardplane_evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"

echo "=== Guardplane End-to-End Integration Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"

echo '{"suite":"guardplane_integration","started":"'$(date -Iseconds)'"}' >> "$LOG"

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
cargo test -p frankenengine-engine guardplane_integration_e2e -- --nocapture 2>&1
test1_exit=$?
echo "{\"test\":\"guardplane_integration_e2e\",\"exit\":$test1_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 2: Run decision receipt validation tests
echo "Running decision receipt validation tests..."
cargo test -p frankenengine-engine decision_receipt -- --nocapture 2>&1
test2_exit=$?
echo "{\"test\":\"decision_receipt_validation\",\"exit\":$test2_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 3: Run guardplane adapter tests
echo "Running guardplane adapter tests..."
cargo test -p frankenengine-engine guardplane_adapter -- --nocapture 2>&1
test3_exit=$?
echo "{\"test\":\"guardplane_adapter\",\"exit\":$test3_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Test 4: Run containment action tests
echo "Running containment action enforcement tests..."
cargo test -p frankenengine-engine containment_tests -- --nocapture 2>&1
test4_exit=$?
echo "{\"test\":\"containment_enforcement\",\"exit\":$test4_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Calculate results
total_tests=4
failed_tests=0

if [ $test1_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test2_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test3_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test4_exit -ne 0 ]; then ((failed_tests++)); fi

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

echo '{"suite":"guardplane_integration","completed":"'$(date -Iseconds)'","total":'$total_tests',"passed":'$passed_tests',"failed":'$failed_tests'}' >> "$LOG"

if [ $failed_tests -eq 0 ]; then
    echo "✅ All guardplane integration tests passed!"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test suite(s) failed!"
    echo "Check logs at: $LOG"
    exit 1
fi