#!/usr/bin/env bash
set -euo pipefail

# TEE Attestation E2E test script - RC-5.4
# Tests mock quote generation, verification, and policy integration

LOG="artifacts/test_tee_attestation_$(date +%s).jsonl"
ARTIFACTS="artifacts/tee_attestation_evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"

echo "=== TEE Attestation Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"

echo '{"suite":"tee_attestation","started":"'$(date -Iseconds)'"}' >> "$LOG"

run_tee_test() {
    local test_name=$1
    echo "Running TEE attestation test: $test_name"

    # Run cargo test for the specific TEE attestation tests
    if cargo test --lib -p frankenengine-engine tee_attestation_policy::tests::${test_name} -- --nocapture 2>&1; then
        test_exit=0
    else
        test_exit=1
    fi

    echo "{\"test\":\"$test_name\",\"exit\":$test_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
    return $test_exit
}

# Test 1: Mock generates valid quote
echo "Test 1: Mock quote generation"
run_tee_test "mock_generates_valid_quote"
test1_exit=$?

# Test 2: Expired quote rejection
echo "Test 2: Expired quote rejection"
run_tee_test "expired_quote_rejected"
test2_exit=$?

# Test 3: Tampered quote rejection
echo "Test 3: Tampered quote rejection"
run_tee_test "tampered_quote_rejected"
test3_exit=$?

# Test 4: Correct platform in quote
echo "Test 4: Platform verification"
run_tee_test "correct_platform_in_quote"
test4_exit=$?

# Test 5: Freshness check
echo "Test 5: Freshness verification"
run_tee_test "freshness_check"
test5_exit=$?

# Test 6: High-impact requires attestation
echo "Test 6: High-impact attestation requirements"
run_tee_test "high_impact_requires_attestation"
test6_exit=$?

# Additional integration test: Full TEE policy with mock provider
echo "Test 7: Full TEE integration"
if cargo test --lib -p frankenengine-engine tee_attestation_policy -- --nocapture 2>&1; then
    test7_exit=0
else
    test7_exit=1
fi
echo "{\"test\":\"full_tee_integration\",\"exit\":$test7_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

# Calculate results
total_tests=7
failed_tests=0

if [ $test1_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test2_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test3_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test4_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test5_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test6_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test7_exit -ne 0 ]; then ((failed_tests++)); fi

passed_tests=$((total_tests - failed_tests))

echo ""
echo "=== TEE Attestation Test Results ==="
echo "Total test cases: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

# Create summary artifact
cat > "$ARTIFACTS/test_summary.json" << EOF
{
  "test_suite": "tee_attestation",
  "timestamp": "$(date -Iseconds)",
  "total_test_cases": $total_tests,
  "passed_test_cases": $passed_tests,
  "failed_test_cases": $failed_tests,
  "test_results": {
    "mock_quote_generation": {"exit_code": $test1_exit},
    "expired_quote_rejection": {"exit_code": $test2_exit},
    "tampered_quote_rejection": {"exit_code": $test3_exit},
    "platform_verification": {"exit_code": $test4_exit},
    "freshness_verification": {"exit_code": $test5_exit},
    "high_impact_requirements": {"exit_code": $test6_exit},
    "full_integration": {"exit_code": $test7_exit}
  },
  "artifacts_location": "$ARTIFACTS",
  "log_file": "$LOG",
  "description": "TEE attestation mock provider with quote generation, verification, and policy integration"
}
EOF

# Generate TEE attestation demo output
echo "Generating demo TEE attestation..."
cat > /tmp/tee_demo.rs << 'EOF'
use std::collections::BTreeMap;

// This would be a real demo if integrated with the main crate
fn main() {
    println!("TEE Attestation Demo");
    println!("===================");
    println!("MockTeeProvider platforms: Intel SGX, ARM TrustZone, ARM CCA, AMD SEV");
    println!("Quote generation: measurement_hash, nonce, timestamp, platform, signature");
    println!("Verification: HMAC signature validation, freshness checks, measurement approval");
    println!("Policy integration: high-impact decisions require fresher attestation");
    println!("Demo complete - see artifacts/ for full attestation data");
}
EOF

echo "{\"demo\":\"tee_attestation_created\",\"platforms\":4,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"

echo '{"suite":"tee_attestation","completed":"'$(date -Iseconds)'","total":'$total_tests',"passed":'$passed_tests',"failed":'$failed_tests'}' >> "$LOG"

if [ $failed_tests -eq 0 ]; then
    echo "✅ All TEE attestation tests passed!"
    echo "🔐 TEE substrate ready for quarantine propagation and high-impact containment"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test case(s) failed!"
    echo "Note: Some failures expected until TEE integration is complete."
    echo "Check logs at: $LOG"
    exit 1
fi