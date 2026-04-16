#!/bin/bash
set -euo pipefail

# RC-6 Cross-Repo Dependency Isolation Build Verification Script
# Tests both standalone mode and full-integration mode

echo "=== RC-6 Dependency Isolation Build Verification ==="
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

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

echo
echo "--- Test 1: Standalone build (no external dependencies) ---"
cd crates/franken-engine
if cargo check --no-default-features >/dev/null 2>&1; then
    test_result "Standalone build compiles" 0
else
    echo -e "${YELLOW}Note: Standalone build had issues, checking with verbose output...${NC}"
    # Allow this to fail for now since we're still working on it
    test_result "Standalone build compiles" 1
fi

echo
echo "--- Test 2: Full integration build (with external dependencies) ---"
if cargo check --all-features >/dev/null 2>&1; then
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
optional_deps=$(grep -A 20 "^\[dependencies\]" crates/franken-engine/Cargo.toml | grep "optional = true" | wc -l)
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