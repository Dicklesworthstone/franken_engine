#!/bin/bash
set -euo pipefail

# RC-6 Cross-Repo Dependency Isolation Build Verification Script
# Tests both standalone mode and full-integration mode

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${VERIFY_BUILD_MODES_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_verify_build_modes_$(date -u +%Y%m%dT%H%M%SZ)}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

echo "=== RC-6 Dependency Isolation Build Verification ==="
echo "Timestamp: $TIMESTAMP"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
ARTIFACT_DIR="${VERIFY_BUILD_MODES_ARTIFACT_DIR:-${PROJECT_ROOT}/artifacts/verify_build_modes/${TIMESTAMP}}"
mkdir -p "$ARTIFACT_DIR"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required rch binary not found: $RCH_BIN" >&2
    exit 127
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success_count=0
total_tests=4

test_result() {
    local test_name="$1"
    local exit_code="$2"

    if [ "$exit_code" -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $test_name"
        ((success_count++))
    else
        echo -e "${RED}✗${NC} $test_name"
    fi
}

run_rch_cargo_check() {
    local log_name="$1"
    local log_path status
    shift

    log_path="${ARTIFACT_DIR}/${log_name}.log"
    if "$RCH_BIN" exec -- env \
        "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
        "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
        "CARGO_INCREMENTAL=$CARGO_INCREMENTAL" \
        cargo check "$@" > "$log_path" 2>&1; then
        status=0
    else
        status=$?
    fi

    if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$log_path"; then
        echo "rch reported local fallback; refusing local build verification" >&2
        return 1
    fi

    if [ "$status" -ne 0 ]; then
        echo "RCH log: $log_path"
    fi
    return "$status"
}

echo "Artifact logs: $ARTIFACT_DIR"
echo "RCH target dir: $CARGO_TARGET_DIR"

echo
echo "--- Test 1: Standalone build (no external dependencies) ---"
cd crates/franken-engine
if run_rch_cargo_check "standalone_check_no_default_features" --no-default-features; then
    test_result "Standalone build compiles" 0
else
    echo -e "${YELLOW}Note: Standalone build had issues; inspect artifact log above.${NC}"
    test_result "Standalone build compiles" 1
fi

echo
echo "--- Test 2: Full integration build (with external dependencies) ---"
if run_rch_cargo_check "full_integration_check_all_features" --all-features; then
    test_result "Full integration build compiles" 0
else
    test_result "Full integration build compiles" 1
fi

cd "$PROJECT_ROOT"

echo
echo "--- Test 3: Feature gate configuration ---"
if grep -q "asupersync-integration" crates/franken-engine/Cargo.toml; then
    test_result "Feature gates configured in Cargo.toml" 0
else
    test_result "Feature gates configured in Cargo.toml" 1
fi

echo
echo "--- Test 4: External dependencies are optional ---"
optional_deps="$(grep -A 20 "^\[dependencies\]" crates/franken-engine/Cargo.toml | grep -c "optional = true" || true)"
if [ "$optional_deps" -ge 3 ]; then
    test_result "External dependencies marked as optional" 0
else
    test_result "External dependencies marked as optional" 1
fi

echo
echo "=== Summary ==="
echo "Tests passed: $success_count/$total_tests"

if [ "$success_count" -eq "$total_tests" ]; then
    echo -e "${GREEN}✓ All build mode verifications passed${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Some verifications failed (expected during development)${NC}"
    exit 1
fi
