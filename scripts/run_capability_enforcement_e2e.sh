#!/usr/bin/env bash
set -euo pipefail

# Capability Enforcement E2E Test Script
# Executes the real capability enforcement test surfaces through rch and records
# replayable command evidence. This script intentionally does not synthesize
# pass/fail capability outcomes.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DEFAULT_MODE="test"
DEFAULT_TIMESTAMP="$(date +%Y%m%dT%H%M%SZ)"
DEFAULT_OUT_DIR="$PROJECT_ROOT/artifacts/capability_enforcement_e2e/$DEFAULT_TIMESTAMP"

MODE="${1:-$DEFAULT_MODE}"
TIMESTAMP="${CAPABILITY_E2E_TIMESTAMP:-$DEFAULT_TIMESTAMP}"
OUT_DIR="${CAPABILITY_E2E_OUT_DIR:-$DEFAULT_OUT_DIR}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${CAPABILITY_E2E_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_capability_e2e_${TIMESTAMP}}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
RCH_TIMEOUT_SECONDS="${RCH_EXEC_TIMEOUT_SECONDS:-1800}"

mkdir -p "$OUT_DIR/command_logs"

EVENTS_LOG="$OUT_DIR/events.jsonl"
COMMANDS_LOG="$OUT_DIR/commands.txt"
RUN_MANIFEST="$OUT_DIR/run_manifest.json"
CAPABILITY_MATRIX="$OUT_DIR/capability_matrix_report.json"
: > "$EVENTS_LOG"
: > "$COMMANDS_LOG"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required rch binary not found: $RCH_BIN" >&2
    exit 127
fi

echo "=== Capability Enforcement E2E Test Suite ===" | tee -a "$COMMANDS_LOG"
echo "Mode: $MODE" | tee -a "$COMMANDS_LOG"
echo "Output: $OUT_DIR" | tee -a "$COMMANDS_LOG"
echo "RCH target dir: $CARGO_TARGET_DIR" | tee -a "$COMMANDS_LOG"
echo "Started: $(date -Iseconds)" | tee -a "$COMMANDS_LOG"

TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

write_event() {
    local test_id="$1"
    local test_name="$2"
    local category="$3"
    local status="$4"
    local exit_code="$5"
    local duration_ms="$6"
    local log_path="$7"
    local command_text="$8"

    jq -nc \
        --argjson test_id "$test_id" \
        --arg test_name "$test_name" \
        --arg category "$category" \
        --arg status "$status" \
        --argjson exit_code "$exit_code" \
        --argjson duration_ms "$duration_ms" \
        --arg log_path "$log_path" \
        --arg command "$command_text" \
        --arg timestamp "$(date -Iseconds)" \
        '{
          test_id: $test_id,
          test_name: $test_name,
          category: $category,
          status: $status,
          exit_code: $exit_code,
          duration_ms: $duration_ms,
          log_path: $log_path,
          command: $command,
          timestamp: $timestamp
        }' >> "$EVENTS_LOG"
}

run_rch_cargo() {
    local test_name="$1"
    local category="$2"
    local log_file start_time end_time duration_ms status exit_code command_text
    shift 2

    TEST_COUNT=$((TEST_COUNT + 1))
    log_file="$OUT_DIR/command_logs/$(printf '%02d' "$TEST_COUNT")_${test_name}.log"
    command_text="rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS CARGO_INCREMENTAL=$CARGO_INCREMENTAL cargo $*"

    echo "Running $test_name: $command_text" | tee -a "$COMMANDS_LOG"
    start_time=$(date +%s%3N)
    if timeout "$RCH_TIMEOUT_SECONDS" "$RCH_BIN" exec -- env \
        "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
        "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
        "CARGO_INCREMENTAL=$CARGO_INCREMENTAL" \
        cargo "$@" > "$log_file" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi
    end_time=$(date +%s%3N)
    duration_ms=$((end_time - start_time))

    if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$log_file"; then
        echo "rch reported local fallback for $test_name" | tee -a "$COMMANDS_LOG"
        exit_code=1
    fi

    if [ "$exit_code" -eq 0 ]; then
        status="pass"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        status="fail"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    write_event "$TEST_COUNT" "$test_name" "$category" "$status" "$exit_code" "$duration_ms" "$log_file" "$command_text"
    return "$exit_code"
}

run_check() {
    run_rch_cargo "capability_lib_check" "compile" check -p frankenengine-engine --lib || true
}

run_real_capability_tests() {
    run_rch_cargo "capability_profile_contracts" "profile_enforcement" test -p frankenengine-engine --test capability_integration -- --nocapture || true
    run_rch_cargo "capability_token_contracts" "token_validation" test -p frankenengine-engine --test capability_token_integration -- --nocapture || true
    run_rch_cargo "hostcall_capability_enforcement" "hostcall_enforcement" test -p frankenengine-engine --test hostcall_capability_enforcement_integration -- --nocapture || true
    run_rch_cargo "orchestrator_capability_integration" "orchestrator_integration" test -p frankenengine-engine --test execution_orchestrator_integration -- --nocapture || true
}

write_reports() {
    local outcome
    if [ "$FAIL_COUNT" -eq 0 ]; then
        outcome="pass"
    else
        outcome="fail"
    fi

    jq -n \
        --arg generated_at "$(date -Iseconds)" \
        --argjson total "$TEST_COUNT" \
        --argjson passed "$PASS_COUNT" \
        --argjson failed "$FAIL_COUNT" \
        --arg outcome "$outcome" \
        '{
          schema_version: "franken-engine.capability-enforcement-e2e.v2",
          generated_at: $generated_at,
          source: "rch-backed real cargo tests",
          outcome: $outcome,
          total_commands: $total,
          passed_commands: $passed,
          failed_commands: $failed,
          test_targets: [
            "capability_integration",
            "capability_token_integration",
            "hostcall_capability_enforcement_integration",
            "execution_orchestrator_integration"
          ],
          evidence_policy: "No simulated capability allow/deny results are emitted by this wrapper."
        }' > "$CAPABILITY_MATRIX"

    jq -n \
        --arg generated_at "$(date -Iseconds)" \
        --arg mode "$MODE" \
        --arg outcome "$outcome" \
        --arg out_dir "$OUT_DIR" \
        --arg events "events.jsonl" \
        --arg matrix "capability_matrix_report.json" \
        --arg commands "commands.txt" \
        --arg manifest "run_manifest.json" \
        --arg target_dir "$CARGO_TARGET_DIR" \
        --argjson total "$TEST_COUNT" \
        --argjson passed "$PASS_COUNT" \
        --argjson failed "$FAIL_COUNT" \
        '{
          schema_version: "franken-engine.capability-enforcement-e2e.run-manifest.v2",
          component: "capability_enforcement_e2e",
          mode: $mode,
          generated_at: $generated_at,
          outcome: $outcome,
          total_commands: $total,
          passed_commands: $passed,
          failed_commands: $failed,
          cargo_target_dir: $target_dir,
          artifact_root: $out_dir,
          artifact_paths: {
            events_jsonl: $events,
            capability_matrix_report: $matrix,
            commands: $commands,
            run_manifest: $manifest,
            command_logs: "command_logs/"
          },
          operator_verification: [
            "cat run_manifest.json",
            "cat events.jsonl | jq .",
            "cat capability_matrix_report.json | jq .",
            "cat commands.txt",
            "find command_logs -type f -maxdepth 1 -print"
          ]
        }' > "$RUN_MANIFEST"
}

case "$MODE" in
    check)
        run_check
        ;;
    test)
        run_real_capability_tests
        ;;
    ci)
        run_check
        run_real_capability_tests
        ;;
    replay)
        if [ -f "$OUT_DIR/run_manifest.json" ]; then
            jq . "$OUT_DIR/run_manifest.json"
            exit 0
        fi
        echo "No manifest found at: $OUT_DIR/run_manifest.json" >&2
        exit 1
        ;;
    *)
        echo "Usage: $0 [check|test|ci|replay]" >&2
        echo "Environment variables:" >&2
        echo "  CAPABILITY_E2E_TIMESTAMP - Custom timestamp for output directory" >&2
        echo "  CAPABILITY_E2E_OUT_DIR - Custom output directory" >&2
        echo "  CAPABILITY_E2E_CARGO_TARGET_DIR - Custom rch cargo target directory" >&2
        exit 2
        ;;
esac

write_reports
echo "Completed: $(date -Iseconds)" | tee -a "$COMMANDS_LOG"
echo "Results: $PASS_COUNT/$TEST_COUNT commands passed" | tee -a "$COMMANDS_LOG"
echo "Artifacts: $OUT_DIR" | tee -a "$COMMANDS_LOG"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "All capability enforcement commands passed." | tee -a "$COMMANDS_LOG"
    exit 0
fi

echo "$FAIL_COUNT capability enforcement command(s) failed." | tee -a "$COMMANDS_LOG"
exit 1
