#!/bin/bash
set -euo pipefail

# Crypto Migration End-to-End Test Script
# Tests the complete crypto migration from homebrew crypto to standard Ed25519 primitives

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts/crypto_migration_e2e/$TIMESTAMP"
EVENTS_FILE="$ARTIFACTS_DIR/events.jsonl"
MANIFEST_FILE="$ARTIFACTS_DIR/run_manifest.json"
COMMANDS_FILE="$ARTIFACTS_DIR/commands.txt"
GOLDEN_VECTORS_FILE="$ARTIFACTS_DIR/golden_vectors.json"

# Generate unique trace_id for this run
TRACE_ID="crypto-e2e-$(date +%s)-$$"
DECISION_ID="crypto-migration-verification"

# Test colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Global test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=10

RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-600}"
RCH_PRIORITY="${RCH_PRIORITY:-low}"
RCH_CARGO_ENV=(CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1)

# Setup artifacts directory
setup_artifacts() {
    mkdir -p "$ARTIFACTS_DIR"
    {
        echo "# Crypto Migration E2E Test Commands"
        echo "# Started: $TIMESTAMP"
        echo "# Trace ID: $TRACE_ID"
        echo ""
    } > "$COMMANDS_FILE"

    # Create run manifest
    cat > "$MANIFEST_FILE" << EOF
{
  "trace_id": "$TRACE_ID",
  "decision_id": "$DECISION_ID",
  "timestamp": "$TIMESTAMP",
  "environment": {
    "hostname": "$(hostname)",
    "user": "$(whoami)",
    "pwd": "$PROJECT_ROOT",
    "cargo_version": "$(cargo --version)",
    "rustc_version": "$(rustc --version)"
  },
  "test_matrix": {
    "total_tests": $TESTS_TOTAL,
    "scenarios": [
      "ContentHash round-trip",
      "AuthenticityHash keyed",
      "Ed25519 sign/verify",
      "Ed25519 non-repudiation",
      "ContentHash vs AuthenticityHash tier separation",
      "Evidence entry",
      "Capability token",
      "Token audience binding",
      "Replay determinism",
      "Cross-module consistency"
    ]
  }
}
EOF
}

# Log structured test result to JSONL
log_test_result() {
    local test_name="$1"
    local status="$2"
    local duration_ms="$3"
    local input_hash="$4"
    local output_hash="$5"
    local error="${6:-null}"

    python3 - "$EVENTS_FILE" "$test_name" "$status" "$duration_ms" "$input_hash" "$output_hash" "$error" << 'PY'
import datetime
import json
import sys

path, test_name, status, duration_ms, input_hash, output_hash, error = sys.argv[1:]
record = {
    "test_name": test_name,
    "status": status,
    "duration_ms": int(duration_ms),
    "input_hash": input_hash,
    "output_hash": output_hash,
    "error": None if error == "null" else error,
    "timestamp": datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
}
with open(path, "a", encoding="utf-8") as fh:
    json.dump(record, fh, sort_keys=True)
    fh.write("\n")
PY
}

# Log command execution
log_command() {
    local cmd="$1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ"): $cmd" >> "$COMMANDS_FILE"
}

run_rch_test() {
    local test_filter="$1"
    local command=(
        "$RCH_BIN" exec -- env
        "${RCH_CARGO_ENV[@]}"
        cargo test -p frankenengine-engine --lib "$test_filter" -- --nocapture
    )

    log_command "RCH_VISIBILITY=$RCH_VISIBILITY RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=$RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS RCH_PRIORITY=$RCH_PRIORITY ${command[*]}"
    RCH_VISIBILITY="$RCH_VISIBILITY" \
        RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="$RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS" \
        RCH_PRIORITY="$RCH_PRIORITY" \
        "${command[@]}"
}

# Run a test with timing and error handling
run_test() {
    local test_name="$1"
    local test_func="$2"
    local input_data="${3:-test-input}"

    echo -n "Running $test_name... "

    local start_time
    start_time=$(date +%s%3N)
    local input_hash
    input_hash=$(echo -n "$input_data" | sha256sum | cut -d' ' -f1)
    local output_hash=""
    local status="pass"
    local error="null"

    if ! output=$("$test_func" 2>&1); then
        status="fail"
        error="$output"
        output_hash="error"
        echo -e "${RED}FAIL${NC}"
        ((TESTS_FAILED++))
    else
        output_hash=$(echo -n "$output" | sha256sum | cut -d' ' -f1)
        echo -e "${GREEN}PASS${NC}"
        ((TESTS_PASSED++))
    fi

    local end_time
    end_time=$(date +%s%3N)
    local duration=$((end_time - start_time))

    log_test_result "$test_name" "$status" "$duration" "$input_hash" "$output_hash" "$error"
}

# Test 1: ContentHash round-trip
test_content_hash_roundtrip() {
    run_rch_test "hash_tiers::tests::content_hash_serialization_round_trip"
}

# Test 2: AuthenticityHash keyed HMAC
test_authenticity_hash_keyed() {
    run_rch_test "hash_tiers::tests::authenticity_hash_known_hmac_sha256_vector"
}

# Test 3: Ed25519 sign/verify
test_ed25519_sign_verify() {
    run_rch_test "signature_preimage::tests::sign_verify_round_trip"
}

# Test 4: Ed25519 non-repudiation
test_ed25519_nonrepudiation() {
    run_rch_test "signature_preimage::tests::ed25519_non_repudiation"
}

# Test 5: ContentHash vs AuthenticityHash tier separation
test_tier_separation() {
    run_rch_test "hash_tiers::tests::authenticity_hash_keyed_differs_from_content_hash"
}

# Test 6: Evidence entry
test_evidence_entry() {
    run_rch_test "evidence_ledger::tests::evidence_entry_serialization_round_trip"
}

# Test 7: Capability token
test_capability_token() {
    run_rch_test "capability_token::tests::verify_token_correct_presenter_passes"
}

# Test 8: Token audience binding
test_token_audience_binding() {
    run_rch_test "capability_token::tests::verify_token_wrong_presenter_fails_with_audience_mismatch"
}

# Test 9: Replay determinism
test_replay_determinism() {
    run_rch_test "signature_preimage::tests::sign_is_deterministic"
}

# Test 10: Cross-module consistency
test_cross_module_consistency() {
    run_rch_test "signature_preimage::tests::preimage_hash_is_deterministic"
}

# Create golden vectors file
create_golden_vectors() {
    python3 - "$GOLDEN_VECTORS_FILE" << 'PY'
import hashlib
import hmac
import json
import sys

path = sys.argv[1]
content_input = b"test-content-for-hash"
auth_input = b"test-data-for-hmac"
auth_key = b"test-hmac-key-32-bytes-long-abc123"
tier_input = b"same-input-data"
tier_key = b"test-key-32-bytes-long-padding!!"

content_sha256 = hashlib.sha256(content_input).hexdigest()
auth_hmac = hmac.new(auth_key, auth_input, hashlib.sha256).hexdigest()
tier_content = hashlib.sha256(tier_input).hexdigest()
tier_auth = hmac.new(tier_key, tier_input, hashlib.sha256).hexdigest()

vectors = {
    "schema_version": "franken-engine.crypto-migration-e2e.golden-vectors.v1",
    "content_hash": {
        "input": content_input.decode("ascii"),
        "expected_sha256": content_sha256,
    },
    "authenticity_hash": {
        "input": auth_input.decode("ascii"),
        "key": auth_key.decode("ascii"),
        "expected_hmac_sha256": auth_hmac,
    },
    "ed25519": {
        "message": "test-message-for-signing",
        "expected_signature_length": 64,
        "proof_filter": "signature_preimage::tests::sign_verify_round_trip",
    },
    "tier_separation": {
        "input": tier_input.decode("ascii"),
        "content_sha256": tier_content,
        "authenticity_hmac_sha256": tier_auth,
        "content_hash_differs_from_auth_hash": tier_content != tier_auth,
    },
}

with open(path, "w", encoding="utf-8") as fh:
    json.dump(vectors, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

# Main execution
main() {
    echo "===================================="
    echo "Crypto Migration E2E Test Suite"
    echo "Trace ID: $TRACE_ID"
    echo "Artifacts: $ARTIFACTS_DIR"
    echo "===================================="
    echo

    setup_artifacts
    create_golden_vectors

    # Run all test scenarios
    run_test "ContentHash round-trip" "test_content_hash_roundtrip" "test-content-for-hash"
    run_test "AuthenticityHash keyed" "test_authenticity_hash_keyed" "test-data-for-hmac"
    run_test "Ed25519 sign/verify" "test_ed25519_sign_verify" "test-message-for-signing"
    run_test "Ed25519 non-repudiation" "test_ed25519_nonrepudiation" "test-message-for-nonrepudiation"
    run_test "ContentHash vs AuthenticityHash tier separation" "test_tier_separation" "same-input-data"
    run_test "Evidence entry" "test_evidence_entry" "evidence-test-data"
    run_test "Capability token" "test_capability_token" "capability-token-data"
    run_test "Token audience binding" "test_token_audience_binding" "audience-binding-data"
    run_test "Replay determinism" "test_replay_determinism" "determinism-test-input"
    run_test "Cross-module consistency" "test_cross_module_consistency" "cross-module-test-data"

    echo
    echo "===================================="
    echo "Test Results Summary"
    echo "===================================="
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC} / $TESTS_TOTAL"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC} / $TESTS_TOTAL"
    echo

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ All crypto migration tests passed!${NC}"
        echo
        echo "Artifacts generated:"
        echo "  - Events: $EVENTS_FILE"
        echo "  - Manifest: $MANIFEST_FILE"
        echo "  - Commands: $COMMANDS_FILE"
        echo "  - Golden Vectors: $GOLDEN_VECTORS_FILE"
        exit 0
    else
        echo -e "${RED}✗ Some tests failed. Check $EVENTS_FILE for details.${NC}"
        exit 1
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
