#!/usr/bin/env bash
set -euo pipefail

# End-to-end test for async generators & for-await-of implementation - RC-2.6
# Tests async function* syntax, yield with promise wrapping, and for-await-of iteration

LOG="artifacts/test_async_generators_$(date +%s).jsonl"
ARTIFACTS="artifacts/async_generators_evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"

echo "=== Async Generators & for-await-of Integration Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"

echo '{"suite":"async_generators_integration","started":"'$(date -Iseconds)'"}' >> "$LOG"

run_test() {
    local name=$1 js_content=$2
    echo "Running test: $name"
    echo "$js_content" > "/tmp/fe_ag_${name}.js"

    # Try to run with frankenctl (will fail until fully implemented)
    if command -v frankenctl >/dev/null 2>&1; then
        frankenctl run --input "/tmp/fe_ag_${name}.js" --out "/tmp/fe_ag_${name}.json" 2>&1
        test_exit=$?
    else
        echo "frankenctl not available, marking as pending implementation"
        test_exit=127 # Command not found
    fi

    echo "{\"test\":\"$name\",\"exit\":$test_exit,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
    return $test_exit
}

# Test 1: Basic async generator function
echo "Test 1: Basic async generator"
run_test "basic_async_gen" "
async function* count(n) {
  for (let i = 0; i < n; i++) {
    yield await Promise.resolve(i);
  }
}
(async () => {
  const values = [];
  for await (const v of count(3)) {
    values.push(v);
  }
  console.log('Values:', values); // Should be [0, 1, 2]
  return values;
})();
"
test1_exit=$?

# Test 2: Async generator with await inside generator body
echo "Test 2: Async generator with await"
run_test "async_gen_with_await" "
async function* fetchItems(ids) {
  for (const id of ids) {
    yield await Promise.resolve({ id, data: 'item_' + id });
  }
}
(async () => {
  for await (const item of fetchItems([1, 2, 3])) {
    console.log('Item:', item);
  }
})();
"
test2_exit=$?

# Test 3: for-await-of with early break
echo "Test 3: for-await-of early break"
run_test "for_await_early_break" "
async function* infinite() {
  let i = 0;
  while (true) {
    yield await Promise.resolve(i++);
  }
}
(async () => {
  for await (const v of infinite()) {
    console.log('Value:', v);
    if (v >= 2) break;
  }
  console.log('Broke out of infinite loop');
})();
"
test3_exit=$?

# Test 4: Async generator error handling
echo "Test 4: Async generator error handling"
run_test "async_gen_error_handling" "
async function* errorGenerator() {
  yield await Promise.resolve(1);
  yield await Promise.resolve(2);
  throw new Error('Generator error');
}
(async () => {
  try {
    for await (const v of errorGenerator()) {
      console.log('Value:', v);
    }
  } catch (err) {
    console.log('Caught error:', err.message);
  }
})();
"
test4_exit=$?

# Test 5: Async generator return value
echo "Test 5: Async generator return"
run_test "async_gen_return" "
async function* returningGenerator() {
  yield await Promise.resolve('first');
  yield await Promise.resolve('second');
  return 'final';
}
(async () => {
  const gen = returningGenerator();
  console.log(await gen.next()); // {value: 'first', done: false}
  console.log(await gen.next()); // {value: 'second', done: false}
  console.log(await gen.next()); // {value: 'final', done: true}
})();
"
test5_exit=$?

# Calculate results
total_tests=5
failed_tests=0

if [ $test1_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test2_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test3_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test4_exit -ne 0 ]; then ((failed_tests++)); fi
if [ $test5_exit -ne 0 ]; then ((failed_tests++)); fi

passed_tests=$((total_tests - failed_tests))

echo ""
echo "=== Async Generators & for-await-of Test Results ==="
echo "Total test cases: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

# Create summary artifact
cat > "$ARTIFACTS/test_summary.json" << EOF
{
  "test_suite": "async_generators_integration",
  "timestamp": "$(date -Iseconds)",
  "total_test_cases": $total_tests,
  "passed_test_cases": $passed_tests,
  "failed_test_cases": $failed_tests,
  "test_results": {
    "basic_async_gen": {"exit_code": $test1_exit},
    "async_gen_with_await": {"exit_code": $test2_exit},
    "for_await_early_break": {"exit_code": $test3_exit},
    "async_gen_error_handling": {"exit_code": $test4_exit},
    "async_gen_return": {"exit_code": $test5_exit}
  },
  "artifacts_location": "$ARTIFACTS",
  "log_file": "$LOG"
}
EOF

echo '{"suite":"async_generators_integration","completed":"'$(date -Iseconds)'","total":'$total_tests',"passed":'$passed_tests',"failed":'$failed_tests'}' >> "$LOG"

if [ $failed_tests -eq 0 ]; then
    echo "✅ All async generators integration tests passed!"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test case(s) failed!"
    echo "Note: Tests may fail until async generators implementation is complete."
    echo "Check logs at: $LOG"
    exit 1
fi