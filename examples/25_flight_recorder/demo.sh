#!/usr/bin/env bash
# Evidence Flight Recorder + Time-Travel Debugger demo (E3.DOC, bd-fqlfw.3.7).
#
# Walks the E3 operator surface end-to-end with the real `frankenctl` binary:
#
#   1. `run --explain`        one execution emits its report + the linked
#                             explain index (content-addressed, no (N+1)th schema)
#   2. byte-identity          the same frozen input re-run lands byte-identical
#                             report + index (the FE-CLAIM-013 posture)
#   3. `explain`              human summary, then the full derived view bundle
#                             (explain.md / evidence_graph.json / replay.json /
#                             counterfactuals.json / commands.txt / repro.lock)
#   4a. `replay debug`        the fail-closed honesty guarantee: --input state
#                             inspection re-executes the REAL interpreter and
#                             REFUSES to serve state when the source does not
#                             correspond to the trace (bd-fqlfw.3.5.5)
#   4b. `replay debug`        navigation (state/step/back/goto) + why<tick> +
#                             events_at over a recorded sample trace
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
cd "$repo_root"

# Locate the binary (prefer $FRANKENCTL_BIN, then release, then debug).
bin=""
if [[ -n "${FRANKENCTL_BIN:-}" && -x "${FRANKENCTL_BIN}" ]]; then
  bin="${FRANKENCTL_BIN}"
elif [[ -x target/release/frankenctl ]]; then
  bin="target/release/frankenctl"
elif [[ -x target/debug/frankenctl ]]; then
  bin="target/debug/frankenctl"
else
  echo "frankenctl not found. Build it first:" >&2
  echo "  cargo build --release -p frankenengine-engine --bin frankenctl" >&2
  exit 2
fi

out="$script_dir/out"
rm -rf "$out"
mkdir -p "$out"

step() { printf '\n=== %s ===\n' "$*"; }

# The frozen demo program: heap objects + nesting + register traffic.
cat > "$out/demo.js" <<'JS'
const point = { x: 1, y: 2 };
const wrap = { inner: point, tag: 3 };
const sum = point.x + point.y + wrap.tag;
JS

step "1) frankenctl run --explain: report + linked explain index"
"$bin" run --input "$out/demo.js" --extension-id flight-demo \
  --out "$out/run.json" --explain --explain-out "$out/explain.json" >/dev/null
ls -l "$out/run.json" "$out/explain.json"

step "2) byte-identity: identical frozen input -> identical report + index"
cp "$out/run.json" "$out/run_first.json"
cp "$out/explain.json" "$out/explain_first.json"
"$bin" run --input "$out/demo.js" --extension-id flight-demo \
  --out "$out/run.json" --explain --explain-out "$out/explain.json" >/dev/null
diff "$out/run_first.json" "$out/run.json" && echo "run report: byte-identical"
diff "$out/explain_first.json" "$out/explain.json" && echo "explain index: byte-identical"

step "3) frankenctl explain: summary, then the full derived view bundle"
"$bin" explain "$out/explain.json"
"$bin" explain "$out/explain.json" --emit-bundle "$out/explain-bundle" >/dev/null
ls "$out/explain-bundle"

step "4a) time-travel debugger: fail-closed state inspection (honesty demo)"
# The debugger only serves interpreter state from a source that PROVABLY
# corresponds to the trace under debug: per inspect it re-executes the real
# interpreter and compares the produced nondeterminism trace event-for-event.
# Handing it a deliberately wrong (empty) trace demonstrates the refusal —
# the response is a fail-closed protocol error naming the divergence, never
# invented state.
cat > "$out/wrong_trace.json" <<'JSON'
{
  "session_id": "flight-demo",
  "events": [],
  "next_sequence": 0,
  "capture_started_vts": 0,
  "capture_ended_vts": 0
}
JSON
cat > "$out/inspect_commands.jsonl" <<'JSONL'
{"cmd":"inspect","tick":0}
JSONL
"$bin" replay debug --trace "$out/wrong_trace.json" --input "$out/demo.js" \
  --script "$out/inspect_commands.jsonl" --out "$out/inspect_transcript.jsonl" \
  | grep -q '"ok":false' && echo "fail-closed refusal confirmed (see inspect_transcript.jsonl)"

step "4b) time-travel debugger: navigation + why over a recorded trace"
cat > "$out/nav_commands.jsonl" <<'JSONL'
# Where am I, walk the trace, come back, ask why.
{"cmd":"state"}
{"cmd":"step"}
{"cmd":"back"}
{"cmd":"goto","tick":1}
{"cmd":"why","tick":1}
{"cmd":"events_at","tick":1}
JSONL
"$bin" replay debug --trace examples/05_replay_demo/sample_trace.json \
  --script "$out/nav_commands.jsonl" --out "$out/nav_transcript.jsonl"
echo
echo "transcripts preserved under: $out/"

step "4c) time-travel debugger: WORKING live state inspection (bd-9mr8o)"
# `run --emit-trace` hands us the run's real recorded nondeterminism trace;
# handing THAT trace + the same source to the debugger lets inspect serve
# registers, heap values, and IFC labels reconstructed by re-executing the
# real interpreter.
"$bin" run --input "$out/demo.js" --extension-id flight-demo \
  --emit-trace "$out/real_trace.json" >/dev/null
cat > "$out/live_commands.jsonl" <<'JSONL'
{"cmd":"state"}
{"cmd":"inspect","tick":0}
JSONL
"$bin" replay debug --trace "$out/real_trace.json" --input "$out/demo.js" \
  --script "$out/live_commands.jsonl" --out "$out/live_transcript.jsonl" \
  | tail -1 | head -c 400
echo
grep -q '"kind":"inspection"' "$out/live_transcript.jsonl" \
  && echo "live inspection confirmed: registers + heap + IFC labels served from real re-execution"

step "done"
echo "Runbook: runbooks/dw_flight_recorder.md"
echo "Capstone gate: ./scripts/run_dw_flight_recorder.sh ci"
