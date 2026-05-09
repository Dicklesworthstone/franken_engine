#!/usr/bin/env bash
set -euo pipefail

# Memory Budget Enforcement E2E Test Script
# Validates memory budget enforcement with adversarial inputs and structured logging.
# Bead: bd-1yst7.7

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$PROJECT_ROOT/artifacts/memory_budget_e2e/$TIMESTAMP}"
EVENTS_LOG="$ARTIFACTS_DIR/events.jsonl"
MANIFEST="$ARTIFACTS_DIR/run_manifest.json"
COMMANDS_LOG="$ARTIFACTS_DIR/commands.txt"
REPORT="$ARTIFACTS_DIR/memory_budget_report.json"
OUTPUT_LOG="$ARTIFACTS_DIR/memory_budget_adversarial_output.txt"

RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-600}"
RCH_PRIORITY="${RCH_PRIORITY:-low}"
RCH_CARGO_ENV=(CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1)

TEST_TARGET="memory_budget_adversarial"
TEST_CASES=(
    "1|heap_object_limits|test_object_allocation_exhaustion|MemoryBudgetExceeded"
    "2|heap_byte_limits|test_memory_byte_exhaustion|MemoryBudgetExceeded"
    "3|scope_chain_depth|test_scope_depth_exhaustion|ScopeDepthExceeded"
    "4|closure_allocation|test_closure_memory_amplification|success_or_MemoryBudgetExceeded"
    "5|generator_allocation|test_generator_memory_exhaustion|success_or_MemoryBudgetExceeded"
    "6|iterator_allocation|test_iterator_allocation_loop|success_or_MemoryBudgetExceeded"
    "7|combined_pressure|test_combined_memory_exhaustion|success_or_MemoryBudgetExceeded"
    "8|boundary_conditions|test_memory_budget_boundary_conditions|boundary_success_then_MemoryBudgetExceeded"
    "9|regression|test_memory_recovery_after_budget_error|recovery_after_MemoryBudgetExceeded"
)

mkdir -p "$ARTIFACTS_DIR"
: > "$EVENTS_LOG"
: > "$COMMANDS_LOG"

RUN_COMMAND=(
    "$RCH_BIN" exec -- env
    "${RCH_CARGO_ENV[@]}"
    cargo test -p frankenengine-engine --test "$TEST_TARGET" -- --nocapture
)

echo "=== Memory Budget E2E Test Suite ==="
echo "Timestamp: $TIMESTAMP"
echo "Artifacts: $ARTIFACTS_DIR"
echo "Events log: $EVENTS_LOG"
echo

{
    echo "# Memory Budget E2E Commands"
    echo "# Started: $TIMESTAMP"
    echo "RCH_VISIBILITY=$RCH_VISIBILITY RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=$RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS RCH_PRIORITY=$RCH_PRIORITY ${RUN_COMMAND[*]}"
} >> "$COMMANDS_LOG"

python3 - "$MANIFEST" "$ARTIFACTS_DIR" "$OUTPUT_LOG" "$COMMANDS_LOG" "$TEST_TARGET" "${RUN_COMMAND[@]}" __CASES__ "${TEST_CASES[@]}" << 'PY'
import datetime
import json
import sys

separator = sys.argv.index("__CASES__")
manifest_path, artifacts_dir, output_log, commands_log, test_target = sys.argv[1:6]
run_command = sys.argv[6:separator]
cases = []
for spec in sys.argv[separator + 1:]:
    test_id, category, test_name, expected = spec.split("|", 3)
    cases.append(
        {
            "test_id": int(test_id),
            "category": category,
            "test_name": test_name,
            "expected_outcome": expected,
        }
    )

manifest = {
    "suite": "memory_budget_e2e",
    "schema_version": "franken-engine.memory-budget-e2e.v2",
    "timestamp": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "artifacts_dir": artifacts_dir,
    "events_log": "events.jsonl",
    "commands_log": "commands.txt",
    "output_log": "memory_budget_adversarial_output.txt",
    "test_target": test_target,
    "total_test_cases": len(cases),
    "run_command": run_command,
    "test_cases": cases,
    "description": "rch-backed memory budget adversarial integration test evidence",
}
with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

echo "Running rch-backed Rust target: $TEST_TARGET"
start_time="$(date +%s%3N)"
set +e
RCH_VISIBILITY="$RCH_VISIBILITY" \
    RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="$RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS" \
    RCH_PRIORITY="$RCH_PRIORITY" \
    "${RUN_COMMAND[@]}" > "$OUTPUT_LOG" 2>&1
command_exit=$?
set -e
end_time="$(date +%s%3N)"
duration_ms=$((end_time - start_time))

python3 - "$EVENTS_LOG" "$REPORT" "$OUTPUT_LOG" "$command_exit" "$duration_ms" "${TEST_CASES[@]}" << 'PY'
import datetime
import json
import re
import sys

events_path, report_path, output_path = sys.argv[1:4]
command_exit = int(sys.argv[4])
duration_ms = int(sys.argv[5])
case_specs = sys.argv[6:]

with open(output_path, "r", encoding="utf-8", errors="replace") as fh:
    output = fh.read()

timestamp = datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
cases = []
passed = 0

with open(events_path, "a", encoding="utf-8") as events:
    for spec in case_specs:
        test_id, category, test_name, expected = spec.split("|", 3)
        observed = re.search(rf"test\s+{re.escape(test_name)}\s+\.\.\.\s+ok\b", output) is not None
        status = "pass" if command_exit == 0 and observed else "fail"
        if status == "pass":
            passed += 1
        event = {
            "test_id": int(test_id),
            "test_name": test_name,
            "category": category,
            "status": status,
            "expected_outcome": expected,
            "observed_in_rust_output": observed,
            "command_exit_code": command_exit,
            "duration_ms": duration_ms,
            "evidence_source": "cargo_test_memory_budget_adversarial_via_rch",
            "output_log": output_path,
            "timestamp": timestamp,
        }
        json.dump(event, events, sort_keys=True)
        events.write("\n")
        cases.append(event)

    summary = {
        "suite_complete": True,
        "total_tests": len(cases),
        "passed_tests": passed,
        "failed_tests": len(cases) - passed,
        "success_rate_percent": round((passed * 100.0) / len(cases), 2) if cases else 0.0,
        "command_exit_code": command_exit,
        "duration_ms": duration_ms,
        "timestamp": timestamp,
    }
    json.dump(summary, events, sort_keys=True)
    events.write("\n")

report = {
    "suite": "memory_budget_e2e",
    "schema_version": "franken-engine.memory-budget-e2e.report.v2",
    "execution_summary": {
        "total_tests": len(cases),
        "passed_tests": passed,
        "failed_tests": len(cases) - passed,
        "success_rate_percent": round((passed * 100.0) / len(cases), 2) if cases else 0.0,
        "command_exit_code": command_exit,
        "duration_ms": duration_ms,
    },
    "cases": cases,
    "artifacts": {
        "events_log": events_path,
        "summary_report": report_path,
        "rust_output": output_path,
    },
    "compliance": {
        "structured_logging": True,
        "deterministic_execution": True,
        "artifact_publication": True,
        "adversarial_inputs": True,
        "rch_backed_rust_execution": True,
        "simulated_replay": False,
    },
}
with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

passed_tests="$(python3 - "$REPORT" << 'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    report = json.load(fh)
print(report["execution_summary"]["passed_tests"])
PY
)"
failed_tests="$(python3 - "$REPORT" << 'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    report = json.load(fh)
print(report["execution_summary"]["failed_tests"])
PY
)"
success_rate="$(python3 - "$REPORT" << 'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    report = json.load(fh)
print(report["execution_summary"]["success_rate_percent"])
PY
)"

echo
echo "=== Memory Budget E2E Test Results ==="
echo "Total test cases: ${#TEST_CASES[@]}"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"
echo "Success rate: ${success_rate}%"
echo
echo "Artifacts published to: $ARTIFACTS_DIR"
echo "- Events log: $EVENTS_LOG"
echo "- Run manifest: $MANIFEST"
echo "- Commands log: $COMMANDS_LOG"
echo "- Rust output: $OUTPUT_LOG"
echo "- Summary report: $REPORT"

if [[ "$failed_tests" == "0" ]]; then
    echo "All memory budget tests completed successfully."
    exit 0
fi

echo "Memory budget E2E failed; inspect $OUTPUT_LOG and $EVENTS_LOG."
exit 1
