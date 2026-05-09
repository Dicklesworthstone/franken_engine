#!/usr/bin/env bash
set -euo pipefail

# TEE Attestation E2E evidence wrapper - RC-5.4
# Runs selected TEE policy tests through rch and emits proof-honest mock-provider
# evidence. Mock provider output is never promoted as authoritative TEE proof.

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="artifacts/test_tee_attestation_${TIMESTAMP}.jsonl"
ARTIFACTS="artifacts/tee_attestation_evidence/${TIMESTAMP}"
TEST_OUTPUT_DIR="$ARTIFACTS/test_output"
RESULTS_JSONL="$ARTIFACTS/test_results.jsonl"
COMMANDS_LOG="$ARTIFACTS/commands.txt"
REMOTE_BATCH_SCRIPT="$ARTIFACTS/remote_tee_attestation_batch.sh"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${TEE_ATTESTATION_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_tee_attestation_${TIMESTAMP}}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
RCH_TIMEOUT_SECONDS="${RCH_TIMEOUT_SECONDS:-3600}"

mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"
mkdir -p "$TEST_OUTPUT_DIR"
: > "$RESULTS_JSONL"
: > "$COMMANDS_LOG"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required rch binary not found: $RCH_BIN" >&2
    exit 127
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Required jq binary not found" >&2
    exit 127
fi

echo "=== TEE Attestation Test ==="
echo "Timestamp: $TIMESTAMP"
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"
echo "RCH target dir: $CARGO_TARGET_DIR"

jq -n \
    --arg suite "tee_attestation" \
    --arg started "$(date -Iseconds)" \
    --arg timestamp "$TIMESTAMP" \
    --arg rch_bin "$RCH_BIN" \
    --arg cargo_target_dir "$CARGO_TARGET_DIR" \
    '{
      suite: $suite,
      started: $started,
      timestamp: $timestamp,
      rch_bin: $rch_bin,
      cargo_target_dir: $cargo_target_dir
    }' >> "$LOG"

cat > "$REMOTE_BATCH_SCRIPT" <<'REMOTE_BATCH_EOF'
set -euo pipefail

cargo test --lib -p frankenengine-engine tee_attestation_policy::tests::mock_generates_valid_quote -- --nocapture
cargo test --lib -p frankenengine-engine tee_attestation_policy::tests::tampered_quote_rejected -- --nocapture
cargo test --lib -p frankenengine-engine tee_attestation_policy::tests::correct_platform_in_quote -- --nocapture
cargo test --lib -p frankenengine-engine tee_attestation_policy::tests::freshness_check -- --nocapture
cargo test -p frankenengine-engine --test tee_attestation_policy stale_quote_is_rejected_for_standard_impact -- --nocapture
cargo test -p frankenengine-engine --test tee_attestation_policy high_impact_has_stricter_freshness_than_standard -- --nocapture
cargo test -p frankenengine-engine --test tee_attestation_policy_integration evaluate_quote_rejects_fail_closed_source_unavailable -- --nocapture
REMOTE_BATCH_EOF

{
    printf '[%s] remote batch via rch exec -- bash -lc %q\n' \
        "$(date -Iseconds)" "$(<"$REMOTE_BATCH_SCRIPT")"
} >> "$COMMANDS_LOG"

echo "=== RCH batched TEE attestation regressions ==="
output_file="$TEST_OUTPUT_DIR/tee_attestation_batch.log"
batch_exit=0
fallback_detected=false
start_time=$(date +%s%3N)
if timeout "$RCH_TIMEOUT_SECONDS" "$RCH_BIN" exec -- env \
    "CARGO_INCREMENTAL=$CARGO_INCREMENTAL" \
    "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
    "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
    bash -lc "$(<"$REMOTE_BATCH_SCRIPT")" 2>&1 | tee "$output_file"; then
    batch_exit=0
else
    batch_exit=$?
fi
end_time=$(date +%s%3N)
duration_ms=$((end_time - start_time))

if grep -Eiq 'falling back to local|local execution|executing locally' "$output_file"; then
    fallback_detected=true
    batch_exit=1
fi

jq -n \
    --arg test "tee_attestation_batch" \
    --arg description "Batched rch proof for selected mock-provider and policy fail-closed TEE regressions." \
    --arg target "bash -lc $REMOTE_BATCH_SCRIPT" \
    --arg output_file "$output_file" \
    --arg remote_batch_script "$REMOTE_BATCH_SCRIPT" \
    --arg timestamp "$(date -Iseconds)" \
    --argjson exit_code "$batch_exit" \
    --argjson duration_ms "$duration_ms" \
    --argjson fallback_detected "$fallback_detected" \
    '{
      test: $test,
      description: $description,
      target: $target,
      output_file: $output_file,
      remote_batch_script: $remote_batch_script,
      exit_code: $exit_code,
      duration_ms: $duration_ms,
      fallback_detected: $fallback_detected,
      selected_regressions: [
        "tee_attestation_policy::tests::mock_generates_valid_quote",
        "tee_attestation_policy::tests::tampered_quote_rejected",
        "tee_attestation_policy::tests::correct_platform_in_quote",
        "tee_attestation_policy::tests::freshness_check",
        "tee_attestation_policy::stale_quote_is_rejected_for_standard_impact",
        "tee_attestation_policy::high_impact_has_stricter_freshness_than_standard",
        "tee_attestation_policy_integration::evaluate_quote_rejects_fail_closed_source_unavailable"
      ],
      timestamp: $timestamp
    }' >> "$RESULTS_JSONL"

jq -n \
    --arg test "tee_attestation_batch" \
    --arg status "$([ "$batch_exit" -eq 0 ] && echo pass || echo fail)" \
    --arg timestamp "$(date -Iseconds)" \
    --argjson exit_code "$batch_exit" \
    --argjson duration_ms "$duration_ms" \
    --argjson fallback_detected "$fallback_detected" \
    '{
      test: $test,
      status: $status,
      exit_code: $exit_code,
      duration_ms: $duration_ms,
      fallback_detected: $fallback_detected,
      timestamp: $timestamp
    }' >> "$LOG"

total_tests=$(jq -s 'length' "$RESULTS_JSONL")
failed_tests=$(jq -s '[.[] | select(.exit_code != 0)] | length' "$RESULTS_JSONL")
passed_tests=$((total_tests - failed_tests))
success_rate=$(jq -n \
    --argjson passed "$passed_tests" \
    --argjson total "$total_tests" \
    'if $total == 0 then 0 else (($passed * 10000 / $total) | round / 100) end')

echo ""
echo "=== TEE Attestation Test Results ==="
echo "Total test groups: $total_tests"
echo "Passed groups: $passed_tests"
echo "Failed groups: $failed_tests"
echo "Success rate: ${success_rate}%"

jq -s \
    --arg timestamp "$(date -Iseconds)" \
    --arg artifacts_location "$ARTIFACTS" \
    --arg log_file "$LOG" \
    --arg commands_log "$COMMANDS_LOG" \
    --arg cargo_target_dir "$CARGO_TARGET_DIR" \
    --argjson total_tests "$total_tests" \
    --argjson passed_tests "$passed_tests" \
    --argjson failed_tests "$failed_tests" \
    --argjson success_rate_percent "$success_rate" \
    '{
      schema_version: "franken-engine.tee-attestation-e2e-summary.v2",
      test_suite: "tee_attestation",
      timestamp: $timestamp,
      execution_summary: {
        total_tests: $total_tests,
        passed_tests: $passed_tests,
        failed_tests: $failed_tests,
        success_rate_percent: $success_rate_percent
      },
      test_results: .,
      artifacts_location: $artifacts_location,
      log_file: $log_file,
      commands_log: $commands_log,
      cargo_target_dir: $cargo_target_dir,
      evidence_limits: {
        provider_kind: "mock",
        authoritative_tee_proof: false,
        fail_closed_for_evidence_gates: true,
        limitation: "MockTeeProvider validates deterministic policy wiring only; it is not hardware TEE attestation."
      }
    }' "$RESULTS_JSONL" > "$ARTIFACTS/test_summary.json"

jq -n \
    --arg timestamp "$(date -Iseconds)" \
    --arg summary "$ARTIFACTS/test_summary.json" \
    --arg results "$RESULTS_JSONL" \
    '{
      schema_version: "franken-engine.tee-attestation-verification.v1",
      provider_kind: "mock",
      authoritative: false,
      fail_closed_for_evidence_gates: true,
      evidence_gate_status: "fail_closed_non_authoritative_mock_provider",
      verification_timestamp: $timestamp,
      summary_artifact: $summary,
      results_artifact: $results,
      limitation: "This artifact proves selected TEE policy regressions ran; it does not prove hardware-backed TEE attestation."
    }' > "$ARTIFACTS/tee_verification.json"

jq -n \
    --arg suite "tee_attestation" \
    --arg completed "$(date -Iseconds)" \
    --argjson total "$total_tests" \
    --argjson passed "$passed_tests" \
    --argjson failed "$failed_tests" \
    --argjson success_rate "$success_rate" \
    '{
      suite: $suite,
      completed: $completed,
      total: $total,
      passed: $passed,
      failed: $failed,
      success_rate: $success_rate
    }' >> "$LOG"

echo ""
echo "Artifacts generated:"
echo "- Summary: $ARTIFACTS/test_summary.json"
echo "- TEE verification: $ARTIFACTS/tee_verification.json"
echo "- Results JSONL: $RESULTS_JSONL"
echo "- Commands: $COMMANDS_LOG"
echo "- Full log: $LOG"
echo ""

if [ "$failed_tests" -eq 0 ]; then
    echo "All TEE attestation tests passed."
    echo "Mock-provider evidence marked non-authoritative and fail-closed for evidence gates."
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "$failed_tests test case(s) failed."
    echo "Check logs at: $LOG"
    exit 1
fi
