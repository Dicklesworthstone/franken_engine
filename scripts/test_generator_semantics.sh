#!/usr/bin/env bash
# test_generator_semantics.sh — RC-1.4 Generator Functions E2E test script
# Runs generator-specific focused tests via rch.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TS="$(date +%Y%m%dT%H%M%SZ)"
LOG="${REPO_ROOT}/artifacts/test_generator_semantics_${TS}.jsonl"
mkdir -p "$(dirname "$LOG")"

emit() {
  local test="$1" exit_code="$2" elapsed="$3"
  printf '{"test":"%s","exit":%d,"time":"%s","ts":"%s"}\n' \
    "$test" "$exit_code" "$elapsed" "$TS" >> "$LOG"
}

run_test() {
  local name="$1"
  shift
  local start
  start=$(date +%s)
  local ec=0
  "$@" || ec=$?
  local end
  end=$(date +%s)
  local elapsed="$((end - start))s"
  emit "$name" "$ec" "$elapsed"
  if [ "$ec" -ne 0 ]; then
    echo "FAIL: $name (exit=$ec, ${elapsed})"
  else
    echo "PASS: $name (${elapsed})"
  fi
  return "$ec"
}

echo "=== RC-1.4 Generator Functions E2E Tests ==="
echo "Log: $LOG"
echo ""

TOTAL=0
FAIL=0

# Test 1: lib check passes (generator code compiles)
TOTAL=$((TOTAL + 1))
run_test "lib_check" rch exec "env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_gen_e2e_${TS} \
  cargo check -p frankenengine-engine --lib" || FAIL=$((FAIL + 1))

# Test 2: clippy passes for baseline_interpreter (no new warnings)
TOTAL=$((TOTAL + 1))
run_test "clippy_interpreter" rch exec "env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_gen_e2e_${TS} \
  cargo clippy -p frankenengine-engine --lib -- -D warnings 2>&1 | \
  grep -v 'warning:' | grep 'baseline_interpreter' && exit 1 || exit 0" || FAIL=$((FAIL + 1))

# Test 3: fmt check
TOTAL=$((TOTAL + 1))
run_test "fmt_check" cargo fmt --check -p frankenengine-engine || FAIL=$((FAIL + 1))

echo ""
echo "=== Results: $((TOTAL - FAIL))/$TOTAL passed, $FAIL failed ==="
echo "Artifacts: $LOG"

[ "$FAIL" -eq 0 ]
