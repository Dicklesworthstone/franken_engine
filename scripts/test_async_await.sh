#!/usr/bin/env bash
set -euo pipefail

# End-to-end test for async/await implementation - RC-2.4
# Tests basic async function execution, await expressions, and Promise integration

LOG="artifacts/test_async_await_$(date +%s).jsonl"
ARTIFACTS="artifacts/async_await_evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"

echo "=== Async/Await Integration Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"

echo '{"suite":"async_await_integration","started":"'$(date -Iseconds)'"}' >> "$LOG"

run_test() {
  local name=$1 js_content=$2
  echo "Running test: $name"
  echo "$js_content" > "/tmp/fe_async_${name}.js"

  # Try to run with frankenctl (will fail until fully implemented)
  if command -v frankenctl >/dev/null 2>&1; then
    frankenctl run --input "/tmp/fe_async_${name}.js" --out "/tmp/fe_async_${name}.json" 2>&1
    test_exit=$?
  else
    echo "frankenctl not available, marking as pending implementation"
    test_exit=127 # Command not found
  fi

  echo "{\"test\":\"$name\",\"exit\":$test_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
  return $test_exit
}

# Test 1: Basic async function that returns a value
echo "Test 1: Basic async function return"
run_test "basic_async_return" "
async function getValue() {
  return 42;
}
getValue().then(result => {
  console.log('Result:', result); // Should be 42
});
"
test1_exit=$?

# Test 2: Async function with await
echo "Test 2: Async function with await"
run_test "async_with_await" "
async function addAsync(a, b) {
  const result = await Promise.resolve(a + b);
  return result;
}
addAsync(40, 2).then(result => {
  console.log('Sum:', result); // Should be 42
});
"
test2_exit=$?

# Test 3: Sequential awaits
echo "Test 3: Sequential awaits"
run_test "sequential_awaits" "
async function sequence() {
  const a = await Promise.resolve(10);
  const b = await Promise.resolve(20);
  const c = await Promise.resolve(30);
  return a + b + c;
}
sequence().then(result => {
  console.log('Sequence result:', result); // Should be 60
});
"
test3_exit=$?

# Test 4: Async function calling async function
echo "Test 4: Async calling async"
run_test "async_calls_async" "
async function helper(x) {
  return await Promise.resolve(x * 2);
}
async function main() {
  const result = await helper(21);
  return result;
}
main().then(result => {
  console.log('Nested async result:', result); // Should be 42
});
"
test4_exit=$?

# Test 5: Error propagation in async functions
echo "Test 5: Async error propagation"
run_test "async_error_propagation" "
async function throwError() {
  throw new Error('async error');
}
async function catchError() {
  try {
    await throwError();
    return 'should not reach here';
  } catch (err) {
    return 'caught: ' + err.message;
  }
}
catchError().then(result => {
  console.log('Error handling result:', result); // Should be 'caught: async error'
});
"
test5_exit=$?

# Test 6: Await non-promise value
echo "Test 6: Await non-promise"
run_test "await_non_promise" "
async function awaitValue() {
  const result = await 42; // await non-promise should resolve immediately
  return result;
}
awaitValue().then(result => {
  console.log('Non-promise await result:', result); // Should be 42
});
"
test6_exit=$?

# Calculate results
total_tests=6
failed_tests=0

if [ $test1_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test2_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test3_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test4_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test5_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test6_exit -ne 0 ]; then ((failed_tests++)); fi

passed_tests=$((total_tests - failed_tests))

echo ""
echo "=== Async/Await Integration Test Results ==="
echo "Total test cases: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

# Create summary artifact
cat > "$ARTIFACTS/test_summary.json" << EOF
{
  "test_suite": "async_await_integration",
  "timestamp": "$(date -Iseconds)",
  "total_test_cases": $total_tests,
  "passed_test_cases": $passed_tests,
  "failed_test_cases": $failed_tests,
  "test_results": {
    "basic_async_return": {"exit_code": $test1_exit},
    "async_with_await": {"exit_code": $test2_exit},
    "sequential_awaits": {"exit_code": $test3_exit},
    "async_calls_async": {"exit_code": $test4_exit},
    "async_error_propagation": {"exit_code": $test5_exit},
    "await_non_promise": {"exit_code": $test6_exit}
  },
  "artifacts_location": "$ARTIFACTS",
  "log_file": "$LOG"
}
EOF

echo '{"suite":"async_await_integration","completed":"'$(date -Iseconds)'","total":'$total_tests',"passed":'$passed_tests',"failed":'$failed_tests'}' >> "$LOG"

if [ $failed_tests -eq 0 ]; then
    echo "✅ All async/await integration tests passed!"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test case(s) failed!"
    echo "Note: Tests may fail until async/await implementation is complete."
    echo "Check logs at: $LOG"
    exit 1
fi