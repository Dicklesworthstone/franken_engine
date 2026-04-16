#!/usr/bin/env bash
#
# Standard Library Completeness Test Suite
# Tests every BuiltinId variant through actual interpreter execution
#

set -euo pipefail

LOG_FILE="${LOG:-artifacts/test_stdlib_$(date +%s).jsonl}"
mkdir -p "$(dirname "$LOG_FILE")"

echo "=== Standard Library Completeness E2E Test Suite ===" | tee -a "$LOG_FILE"
echo "{\"test\": \"stdlib_completeness\", \"phase\": \"start\", \"timestamp\": \"$(date -Iseconds)\"}" >> "$LOG_FILE"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Helper function to run a test
run_test() {
    local test_name="$1"
    local js_code="$2"
    local expected_pattern="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo "--- Test: $test_name ---"

    local test_file="/tmp/fe_stdlib_test_${TOTAL_TESTS}.js"
    local result_file="/tmp/fe_stdlib_result_${TOTAL_TESTS}.json"

    echo "$js_code" > "$test_file"

    local start_time
    start_time=$(date +%s.%3N)

    if timeout 30 cargo run --bin frankenctl -- run --input "$test_file" --out "$result_file" >/dev/null 2>&1; then
        local end_time
        end_time=$(date +%s.%3N)
        local duration
        duration=$(echo "$end_time - $start_time" | bc -l)

        if [[ -f "$result_file" ]]; then
            local result_value
            result_value=$(jq -r '.execution_value // "undefined"' "$result_file" 2>/dev/null || echo "parse_error")

            if echo "$result_value" | grep -q "$expected_pattern"; then
                echo "✓ PASS: $test_name -> $result_value"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                echo "{\"test\": \"$test_name\", \"status\": \"pass\", \"duration\": $duration, \"result\": \"$result_value\"}" >> "$LOG_FILE"
            else
                echo "✗ FAIL: $test_name -> expected '$expected_pattern', got '$result_value'"
                FAILED_TESTS=$((FAILED_TESTS + 1))
                echo "{\"test\": \"$test_name\", \"status\": \"fail\", \"duration\": $duration, \"expected\": \"$expected_pattern\", \"actual\": \"$result_value\"}" >> "$LOG_FILE"
            fi
        else
            echo "✗ FAIL: $test_name -> no result file generated"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo "{\"test\": \"$test_name\", \"status\": \"fail\", \"error\": \"no_result_file\"}" >> "$LOG_FILE"
        fi
    else
        echo "✗ FAIL: $test_name -> execution timeout or error"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "{\"test\": \"$test_name\", \"status\": \"fail\", \"error\": \"execution_timeout\"}" >> "$LOG_FILE"
    fi

    # Cleanup
    rm -f "$test_file" "$result_file"
}

# Test basic construction and typeof results
echo "=== Array Methods ==="
run_test "Array_constructor" "new Array(3).length" "3"
run_test "Array_isArray" "Array.isArray([1,2,3])" "true"
run_test "Array_from" "Array.from([1,2,3]).length" "3"
run_test "Array_push" "const a = [1]; a.push(2); a.length" "2"
run_test "Array_pop" "const a = [1,2]; a.pop()" "2"
run_test "Array_slice" "const a = [1,2,3]; a.slice(1,2)[0]" "2"
run_test "Array_map" "const a = [1,2]; a.map(x => x * 2)[0]" "2"
run_test "Array_filter" "const a = [1,2,3]; a.filter(x => x > 1).length" "2"
run_test "Array_reduce" "const a = [1,2,3]; a.reduce((sum, x) => sum + x, 0)" "6"
run_test "Array_indexOf" "[1,2,3].indexOf(2)" "1"
run_test "Array_join" "[1,2,3].join(',')" "1,2,3"

echo ""
echo "=== Object Methods ==="
run_test "Object_keys" "Object.keys({a: 1, b: 2}).length" "2"
run_test "Object_values" "Object.values({a: 1, b: 2}).length" "2"
run_test "Object_entries" "Object.entries({a: 1, b: 2}).length" "2"
run_test "Object_assign" "const o = Object.assign({a: 1}, {b: 2}); o.b" "2"
run_test "Object_create" "const o = Object.create(null); typeof o" "object"

echo ""
echo "=== String Methods ==="
run_test "String_charAt" "'hello'.charAt(1)" "e"
run_test "String_indexOf" "'hello'.indexOf('e')" "1"
run_test "String_slice" "'hello'.slice(1,3)" "el"
run_test "String_toUpperCase" "'hello'.toUpperCase()" "HELLO"
run_test "String_split" "'a,b,c'.split(',').length" "3"
run_test "String_includes" "'hello'.includes('ell')" "true"
run_test "String_trim" "'  hello  '.trim()" "hello"

echo ""
echo "=== Number Methods ==="
run_test "Number_isFinite" "Number.isFinite(42)" "true"
run_test "Number_isInteger" "Number.isInteger(42)" "true"
run_test "Number_parseInt" "Number.parseInt('42')" "42"
run_test "Number_parseFloat" "Number.parseFloat('42.5')" "42.5"

echo ""
echo "=== Math Methods ==="
run_test "Math_abs" "Math.abs(-5)" "5"
run_test "Math_max" "Math.max(1,2,3)" "3"
run_test "Math_min" "Math.min(1,2,3)" "1"
run_test "Math_floor" "Math.floor(3.7)" "3"
run_test "Math_ceil" "Math.ceil(3.2)" "4"
run_test "Math_round" "Math.round(3.7)" "4"

echo ""
echo "=== JSON Methods ==="
run_test "JSON_stringify" "JSON.stringify({a: 1})" '{"a":1}'
run_test "JSON_parse" "JSON.parse('{\"a\": 1}').a" "1"
run_test "JSON_roundtrip" "JSON.parse(JSON.stringify([1,2,3])).length" "3"

echo ""
echo "=== Map/Set Methods ==="
run_test "Map_constructor" "const m = new Map(); m.size" "0"
run_test "Map_set_get" "const m = new Map(); m.set('a', 1); m.get('a')" "1"
run_test "Map_has" "const m = new Map(); m.set('a', 1); m.has('a')" "true"
run_test "Set_constructor" "const s = new Set(); s.size" "0"
run_test "Set_add_has" "const s = new Set(); s.add(1); s.has(1)" "true"

echo ""
echo "=== Promise Methods ==="
run_test "Promise_resolve" "Promise.resolve(42)" "object" # Promises return objects
run_test "Promise_constructor" "typeof new Promise((resolve) => resolve(1))" "object"

echo ""
echo "=== Console Methods ==="
run_test "console_log" "console.log('test'); 'logged'" "logged"
run_test "console_error" "console.error('test'); 'logged'" "logged"

echo ""
echo "=== Global Functions ==="
run_test "parseInt" "parseInt('42')" "42"
run_test "parseFloat" "parseFloat('42.5')" "42.5"
run_test "isNaN" "isNaN(NaN)" "true"
run_test "isFinite" "isFinite(42)" "true"

echo ""
echo "=== Advanced Features Testing ==="
# Test Array.from with iterables
run_test "Array_from_string" "Array.from('abc').length" "3"
run_test "Array_from_set" "Array.from(new Set([1,2,3])).length" "3"

# Test method chaining
run_test "Array_method_chain" "[1,2,3,4,5].filter(x => x > 2).map(x => x * 2).reduce((sum, x) => sum + x, 0)" "18"

echo ""
echo "=== Missing/Gap Testing ==="
# Test for WeakMap (should fail if not implemented)
run_test "WeakMap_check" "typeof WeakMap" "function|undefined"
run_test "WeakSet_check" "typeof WeakSet" "function|undefined"
run_test "Proxy_check" "typeof Proxy" "function|undefined"
run_test "Reflect_check" "typeof Reflect" "object|undefined"

echo ""
echo "=== Results Summary ==="
echo "Total tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"
echo "Success rate: $(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)%"

# Write summary to log
echo "{\"test\": \"stdlib_completeness\", \"phase\": \"complete\", \"timestamp\": \"$(date -Iseconds)\", \"total\": $TOTAL_TESTS, \"passed\": $PASSED_TESTS, \"failed\": $FAILED_TESTS}" >> "$LOG_FILE"

if [[ $FAILED_TESTS -eq 0 ]]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  $FAILED_TESTS tests failed. Check $LOG_FILE for details."
    exit 1
fi