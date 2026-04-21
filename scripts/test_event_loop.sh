#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

artifact_root="${EVENT_LOOP_E2E_ARTIFACT_ROOT:-artifacts/event_loop_e2e}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
input_path="${run_dir}/event_loop_ordering.js"
report_path="${run_dir}/frankenctl_run_report.json"
stdout_path="${run_dir}/frankenctl_stdout.log"
stderr_path="${run_dir}/frankenctl_stderr.log"
events_path="${run_dir}/events.jsonl"
extension_id="event-loop-ordering-e2e"

mkdir -p "$run_dir"

cat > "$input_path" << 'EOF'
setTimeout(() => console.log('timer'), 0);
Promise.resolve().then(() => console.log('micro'));
console.log('sync');
// Expected output order: sync, micro, timer
EOF

echo "Running event loop E2E test..."
if command -v frankenctl >/dev/null 2>&1; then
  run_cmd=(frankenctl run)
else
  run_cmd=(cargo run -p frankenengine-engine --bin frankenctl -- run)
fi

set +e
"${run_cmd[@]}" \
  --input "$input_path" \
  --extension-id "$extension_id" \
  --out "$report_path" \
  >"$stdout_path" \
  2>"$stderr_path"
status=$?
set -e

python3 - "$status" "$events_path" "$report_path" "$stdout_path" "$stderr_path" "$input_path" << 'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

status = int(sys.argv[1])
events_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
stdout_path = pathlib.Path(sys.argv[4])
stderr_path = pathlib.Path(sys.argv[5])
input_path = pathlib.Path(sys.argv[6])
expected = ["sync", "micro", "timer"]

event = {
    "schema_version": "franken-engine.event-loop-e2e.v1",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "test": "microtask_before_timer",
    "input_path": str(input_path),
    "report_path": str(report_path),
    "stdout_path": str(stdout_path),
    "stderr_path": str(stderr_path),
    "expected_order": expected,
    "frankenctl_exit": status,
}

actual = []
if status == 0:
    try:
        report = json.loads(report_path.read_text())
        actual = [
            entry.get("message")
            for entry in report.get("console_output", [])
            if entry.get("level") == "Log"
        ]
        event["actual_order"] = actual
        if actual == expected:
            event["outcome"] = "pass"
        else:
            event["outcome"] = "fail"
            event["error_code"] = "event_loop_ordering_drift"
            event["detail"] = "console_output order did not match sync,micro,timer"
    except Exception as error:
        event["actual_order"] = actual
        event["outcome"] = "fail"
        event["error_code"] = "event_loop_report_parse_failed"
        event["detail"] = str(error)
else:
    event["actual_order"] = actual
    event["outcome"] = "fail"
    event["error_code"] = "frankenctl_run_failed"
    event["detail"] = stderr_path.read_text(errors="replace")[-4000:]

events_path.write_text(json.dumps(event, sort_keys=True) + "\n")
print(f"event loop E2E evidence: {events_path}")
print(f"expected order: {expected}")
print(f"actual order:   {event.get('actual_order', [])}")

if event["outcome"] != "pass":
    sys.exit(1)
PY

echo "Event loop E2E test completed successfully"
