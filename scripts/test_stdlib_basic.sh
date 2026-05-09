#!/usr/bin/env bash
#
# Basic Standard Library Test - Core Methods Only
#

set -euo pipefail

echo "=== Basic Standard Library Test ==="

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

if ! command -v rch >/dev/null 2>&1; then
    echo "rch is required for basic stdlib Cargo execution" >&2
    exit 2
fi

export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target/stdlib_basic}"

run_frankenctl() {
    timeout 30 rch exec -- env "RUSTC_WRAPPER=${RUSTC_WRAPPER}" "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" cargo run --bin frankenctl -- "$@"
}

# Test basic array operations
cat > /tmp/test_array.js << 'EOF'
const arr = [1, 2, 3];
arr.push(4);
arr.length;
EOF

echo "Testing Array.push..."
if run_frankenctl run --input /tmp/test_array.js --out /tmp/result.json >/dev/null 2>&1; then
    if [[ -f /tmp/result.json ]]; then
        result=$(jq -r '.execution_value // "error"' /tmp/result.json 2>/dev/null || echo "parse_error")
        if [[ "$result" == "4" ]]; then
            echo "✓ Array.push works: $result"
        else
            echo "✗ Array.push failed: $result"
        fi
    else
        echo "✗ Array.push: no result file"
    fi
else
    echo "✗ Array.push: execution failed"
fi

# Test basic object operations
cat > /tmp/test_object.js << 'EOF'
const obj = {a: 1, b: 2};
Object.keys(obj).length;
EOF

echo "Testing Object.keys..."
if run_frankenctl run --input /tmp/test_object.js --out /tmp/result2.json >/dev/null 2>&1; then
    if [[ -f /tmp/result2.json ]]; then
        result=$(jq -r '.execution_value // "error"' /tmp/result2.json 2>/dev/null || echo "parse_error")
        if [[ "$result" == "2" ]]; then
            echo "✓ Object.keys works: $result"
        else
            echo "✗ Object.keys failed: $result"
        fi
    else
        echo "✗ Object.keys: no result file"
    fi
else
    echo "✗ Object.keys: execution failed"
fi

# Test JSON
cat > /tmp/test_json.js << 'EOF'
const obj = {hello: "world"};
JSON.stringify(obj);
EOF

echo "Testing JSON.stringify..."
if run_frankenctl run --input /tmp/test_json.js --out /tmp/result3.json >/dev/null 2>&1; then
    if [[ -f /tmp/result3.json ]]; then
        result=$(jq -r '.execution_value // "error"' /tmp/result3.json 2>/dev/null || echo "parse_error")
        if echo "$result" | grep -q "hello"; then
            echo "✓ JSON.stringify works: $result"
        else
            echo "✗ JSON.stringify failed: $result"
        fi
    else
        echo "✗ JSON.stringify: no result file"
    fi
else
    echo "✗ JSON.stringify: execution failed"
fi

# Cleanup
rm -f /tmp/test_*.js /tmp/result*.json

echo "Basic stdlib test complete."
