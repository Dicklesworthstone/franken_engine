#!/usr/bin/env bash
set -euo pipefail

# PERF-INFRA.8 (bd-o4cbn.8.8) — frankenctl cold-start microbench.
#
# Measures process *startup* latency (which the in-process Criterion
# hot_paths suite cannot see) for `frankenctl version` and `frankenctl
# --help` via hyperfine, then emits PERF JSONL span_summary events and an
# optional startup_baseline.json.
#
# Env:
#   HOT   path to the frankenctl binary  (default target/release/frankenctl)
#   OUT   output dir (default tests/artifacts/perf/startup/<ts>/)
#   RUNS  hyperfine runs (default 30)
#   FREEZE_BASELINE=1  also write startup_baseline.json into OUT
#
# Exit codes:
#   0  measured successfully
#   1  hyperfine reported a failure
#   2  usage/env error (missing binary, no hyperfine/python3)

HOT="${HOT:-target/release/frankenctl}"
OUT="${OUT:-tests/artifacts/perf/startup/$(date -u +%Y%m%dT%H%M%SZ)}"
RUNS="${RUNS:-30}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v hyperfine >/dev/null 2>&1; then
    echo "Error: hyperfine is required but not found on PATH" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required but not found on PATH" >&2
    exit 2
fi
if [ ! -x "$HOT" ]; then
    echo "Error: frankenctl binary not found or not executable: $HOT" >&2
    echo "Build it first: cargo build --release --bin frankenctl -p frankenengine-engine" >&2
    echo "Or point HOT=<path> at an existing binary." >&2
    exit 2
fi

mkdir -p "$OUT"

# Cold-start protocol: drop the page cache before each invocation. Requires
# passwordless sudo to write /proc/sys/vm/drop_caches; when unavailable the
# `|| true` degrades to warm-start measurement (documented limitation).
PREPARE='sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1 || true'

echo "Cold-start microbench: HOT=$HOT runs=$RUNS out=$OUT"

set +e
hyperfine \
    --warmup 0 \
    --runs "$RUNS" \
    --prepare "$PREPARE" \
    --command-name version \
    --command-name help \
    --export-json "$OUT/hyperfine.json" \
    --export-markdown "$OUT/summary.md" \
    "\"$HOT\" version" \
    "\"$HOT\" --help"
hf_status=$?
set -e

if [ "$hf_status" -ne 0 ] || [ ! -f "$OUT/hyperfine.json" ]; then
    echo "Error: hyperfine run failed (status $hf_status)" >&2
    exit 1
fi

# Emit PERF JSONL span_summary events (PERF-INFRA.3 schema).
BASELINE_ARG=()
if [ "${FREEZE_BASELINE:-0}" = "1" ]; then
    BASELINE_ARG=(--baseline-out "$OUT/startup_baseline.json")
fi

python3 "$SCRIPT_DIR/hyperfine_to_perf_jsonl.py" \
    --input "$OUT/hyperfine.json" \
    --bead PERF-INFRA.8 \
    --scenario startup_microbench \
    --out "$OUT/events.jsonl" \
    --p95-json "$OUT/startup_p95.json" \
    "${BASELINE_ARG[@]}"

echo "Wrote $OUT/{hyperfine.json,summary.md,events.jsonl,startup_p95.json}"
if [ "${FREEZE_BASELINE:-0}" = "1" ]; then
    echo "Wrote $OUT/startup_baseline.json (copy into tests/artifacts/perf/baselines/<sha>/ to freeze)"
fi
exit 0
