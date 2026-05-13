#!/usr/bin/env bash
set -euo pipefail

# End-to-end acceptance probe for async generators & for-await-of - RC-2.6.
# This is a regression probe for bd-mw20e.3: async generator .next() body
# execution must not regress to the old fail-closed placeholder behavior.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_async_generators_${timestamp}_$$}"
LOG="artifacts/test_async_generators_${timestamp}.jsonl"
ARTIFACTS="artifacts/async_generators_evidence/${timestamp}"
cargo_stdout="${ARTIFACTS}/cargo_build_stdout.log"
cargo_stderr="${ARTIFACTS}/cargo_build_stderr.log"
commands_path="${ARTIFACTS}/commands.txt"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"

cd "${repo_root}"

echo "=== Async Generators & for-await-of Integration Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"

printf '{"suite":"async_generators_integration","started":"%s"}\n' "$(date -Iseconds)" >> "$LOG"

if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
    echo "Required rch binary not found: ${RCH_BIN}" >&2
    exit 2
fi

run_rch_cargo_build() {
    printf 'rch exec -- env RUSTUP_TOOLCHAIN=%q CARGO_BUILD_JOBS=%q CARGO_TARGET_DIR=%q cargo build -p frankenengine-engine --bin frankenctl\n' \
        "${RUSTUP_TOOLCHAIN}" "${CARGO_BUILD_JOBS}" "${CARGO_TARGET_DIR}" > "$commands_path"

    set +e
    "${RCH_BIN}" exec -- env \
        "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN}" \
        "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
        "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
        cargo build -p frankenengine-engine --bin frankenctl > "$cargo_stdout" 2> "$cargo_stderr"
    local status=$?
    set -e

    if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$cargo_stdout" "$cargo_stderr"; then
        cat "$cargo_stdout" >&2
        cat "$cargo_stderr" >&2
        echo "rch reported local fallback; refusing local execution" >&2
        return 125
    fi

    if [[ "$status" -ne 0 ]]; then
        cat "$cargo_stdout" >&2
        cat "$cargo_stderr" >&2
        return "$status"
    fi
}

echo "Building frankenctl with rch..."
run_rch_cargo_build
frankenctl_bin="${CARGO_TARGET_DIR}/debug/frankenctl"
if [[ ! -x "$frankenctl_bin" ]]; then
    echo "expected frankenctl binary at ${frankenctl_bin}" >&2
    exit 1
fi

run_test() {
    local name=$1 js_content=$2
    local js_path="${ARTIFACTS}/${name}.js"
    local out_path="${ARTIFACTS}/${name}.json"
    local stdout_path="${ARTIFACTS}/${name}.stdout.log"
    local stderr_path="${ARTIFACTS}/${name}.stderr.log"

    echo "Running test: $name"
    printf '%s\n' "$js_content" > "$js_path"

    set +e
    "$frankenctl_bin" run --input "$js_path" --out "$out_path" > "$stdout_path" 2> "$stderr_path"
    local test_exit=$?
    set -e

    jq -nc \
        --arg test "$name" \
        --arg time "$(date -Iseconds)" \
        --arg js_path "$js_path" \
        --arg out_path "$out_path" \
        --arg stdout_path "$stdout_path" \
        --arg stderr_path "$stderr_path" \
        --argjson exit "$test_exit" \
        '{test:$test, exit:$exit, time:$time, js_path:$js_path, out_path:$out_path, stdout_path:$stdout_path, stderr_path:$stderr_path}' \
        >> "$LOG"
    return $test_exit
}

# Test 1: Basic async generator function
echo "Test 1: Basic async generator"
test1_exit=0
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
" || test1_exit=$?

# Test 2: Async generator with await inside generator body
echo "Test 2: Async generator with await"
test2_exit=0
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
" || test2_exit=$?

# Test 3: for-await-of with early break
echo "Test 3: for-await-of early break"
test3_exit=0
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
" || test3_exit=$?

# Test 4: Async generator error handling
echo "Test 4: Async generator error handling"
test4_exit=0
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
" || test4_exit=$?

# Test 5: Async generator return value
echo "Test 5: Async generator return"
test5_exit=0
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
" || test5_exit=$?

# Calculate results
total_tests=5
failed_tests=0

if [[ "$test1_exit" -ne 0 ]]; then ((failed_tests++)); fi
if [[ "$test2_exit" -ne 0 ]]; then ((failed_tests++)); fi
if [[ "$test3_exit" -ne 0 ]]; then ((failed_tests++)); fi
if [[ "$test4_exit" -ne 0 ]]; then ((failed_tests++)); fi
if [[ "$test5_exit" -ne 0 ]]; then ((failed_tests++)); fi

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
  "regression_contract": "bd-mw20e.3 closed the fail-closed async generator .next() placeholder; any failing case here is a regression or a newly discovered unsupported for-await-of surface that needs a bead.",
  "frankenctl_bin": "$frankenctl_bin",
  "cargo_target_dir": "$CARGO_TARGET_DIR",
  "cargo_stdout": "$cargo_stdout",
  "cargo_stderr": "$cargo_stderr",
  "commands_path": "$commands_path",
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

printf '{"suite":"async_generators_integration","completed":"%s","total":%s,"passed":%s,"failed":%s}\n' \
    "$(date -Iseconds)" "$total_tests" "$passed_tests" "$failed_tests" >> "$LOG"

if [[ "$failed_tests" -eq 0 ]]; then
    echo "✅ All async generators integration tests passed!"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "❌ $failed_tests test case(s) failed!"
    echo "Async generator support regressed or still lacks a required for-await-of surface."
    echo "Check logs at: $LOG"
    exit 1
fi
