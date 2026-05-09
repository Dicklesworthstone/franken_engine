#!/usr/bin/env bash
set -euo pipefail

# Memory Budget E2E Replay Script
# Replays memory budget enforcement tests by rerunning the rch-backed Rust target.
# Bead: bd-1yst7.7

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <artifacts_dir>"
    echo "Example: $0 artifacts/memory_budget_e2e/20260416T141900Z"
    exit 1
fi

ARTIFACTS_DIR="$1"
EVENTS_LOG="$ARTIFACTS_DIR/events.jsonl"
MANIFEST="$ARTIFACTS_DIR/run_manifest.json"
REPLAY_LOG="$ARTIFACTS_DIR/replay_$(date -u +%Y%m%dT%H%M%SZ).jsonl"
REPLAY_OUTPUT="$ARTIFACTS_DIR/replay_memory_budget_adversarial_output.txt"

RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-600}"
RCH_PRIORITY="${RCH_PRIORITY:-low}"
RCH_CARGO_ENV=(CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1)
TEST_TARGET="memory_budget_adversarial"

if [[ ! -d "$ARTIFACTS_DIR" ]]; then
    echo "Error: artifacts directory not found: $ARTIFACTS_DIR"
    exit 1
fi

if [[ ! -f "$EVENTS_LOG" ]]; then
    echo "Error: events log not found: $EVENTS_LOG"
    exit 1
fi

if [[ ! -f "$MANIFEST" ]]; then
    echo "Error: run manifest not found: $MANIFEST"
    exit 1
fi

echo "=== Memory Budget E2E Replay ==="
echo "Replaying from: $ARTIFACTS_DIR"
echo "Original events: $EVENTS_LOG"
echo "Replay log: $REPLAY_LOG"
echo

jq -e '.schema_version == "franken-engine.memory-budget-e2e.v2"' "$MANIFEST" >/dev/null
jq -e --arg target "$TEST_TARGET" '.test_target == $target' "$MANIFEST" >/dev/null

RUN_COMMAND=(
    "$RCH_BIN" exec -- env
    "${RCH_CARGO_ENV[@]}"
    cargo test -p frankenengine-engine --test "$TEST_TARGET" -- --nocapture
)

python3 - "$REPLAY_LOG" "$ARTIFACTS_DIR" << 'PY'
import datetime
import json
import sys

path, artifacts_dir = sys.argv[1:3]
record = {
    "replay_started": True,
    "original_artifacts": artifacts_dir,
    "timestamp": datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(record, fh, sort_keys=True)
    fh.write("\n")
PY

echo "Running rch-backed replay target: $TEST_TARGET"
set +e
RCH_VISIBILITY="$RCH_VISIBILITY" \
    RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="$RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS" \
    RCH_PRIORITY="$RCH_PRIORITY" \
    "${RUN_COMMAND[@]}" > "$REPLAY_OUTPUT" 2>&1
command_exit=$?
set -e

python3 - "$EVENTS_LOG" "$REPLAY_LOG" "$REPLAY_OUTPUT" "$command_exit" << 'PY'
import datetime
import json
import re
import sys

events_path, replay_log, replay_output_path = sys.argv[1:4]
command_exit = int(sys.argv[4])

with open(replay_output_path, "r", encoding="utf-8", errors="replace") as fh:
    output = fh.read()

expected = []
with open(events_path, "r", encoding="utf-8") as fh:
    for line in fh:
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("test_name") and event.get("status") == "pass":
            expected.append(event["test_name"])

timestamp = datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
validated = 0
invalid = 0
with open(replay_log, "a", encoding="utf-8") as out:
    for test_name in expected:
        observed = re.search(rf"test\s+{re.escape(test_name)}\s+\.\.\.\s+ok\b", output) is not None
        status = "validated" if command_exit == 0 and observed else "invalid"
        if status == "validated":
            validated += 1
        else:
            invalid += 1
        record = {
            "test_name": test_name,
            "replay_status": status,
            "observed_in_rust_output": observed,
            "command_exit_code": command_exit,
            "deterministic_validation": command_exit == 0 and observed,
            "timestamp": timestamp,
        }
        json.dump(record, out, sort_keys=True)
        out.write("\n")

    summary = {
        "replay_complete": True,
        "replayed_tests": len(expected),
        "validated": validated,
        "invalid": invalid,
        "success_rate_percent": round((validated * 100.0) / len(expected), 2) if expected else 0.0,
        "command_exit_code": command_exit,
        "replay_output": replay_output_path,
        "timestamp": timestamp,
    }
    json.dump(summary, out, sort_keys=True)
    out.write("\n")

if invalid or command_exit != 0 or not expected:
    sys.exit(1)
PY

echo
echo "Replay artifacts:"
echo "- Replay log: $REPLAY_LOG"
echo "- Replay Rust output: $REPLAY_OUTPUT"
echo "All memory budget tests validated in replay."
