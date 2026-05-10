#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${REPLAY_DEMO_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_replay_demo_$(date +%s)_$$}"
sample_trace="${script_dir}/sample_trace.json"
output1="${script_dir}/output1.json"
output2="${script_dir}/output2.json"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required rch binary not found: $RCH_BIN" >&2
    exit 2
fi

run_frankenctl() {
    local step_name="$1"
    shift
    local log_path
    log_path="$(mktemp "${TMPDIR:-/tmp}/franken-replay-demo-${step_name}.XXXXXX.log")"

    if ! (
        cd "$repo_root"
        "$RCH_BIN" exec -- env \
            "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
            "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
            "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
            cargo run --bin frankenctl -- "$@"
    ) >"$log_path" 2>&1; then
        cat "$log_path" >&2
        rm -f "$log_path"
        return 1
    fi

    if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
        cat "$log_path" >&2
        echo "rch reported local fallback for $step_name; refusing local execution" >&2
        rm -f "$log_path"
        return 125
    fi

    rm -f "$log_path"
}

echo "FrankenEngine Deterministic Replay Verification"
echo "=============================================="

# Clean up any existing output files
rm -f "$output1" "$output2"

echo "Running replay #1..."
run_frankenctl replay1 replay run --trace "$sample_trace" --mode strict --out "$output1"

echo "Running replay #2..."
run_frankenctl replay2 replay run --trace "$sample_trace" --mode strict --out "$output2"

echo "Comparing outputs..."
if diff "$output1" "$output2" > /dev/null 2>&1; then
    echo "✅ SUCCESS: Replay outputs are byte-identical!"
    echo ""
    echo "Sample output:"
    head -15 "$output1"
    echo "..."
    echo ""
    echo "Key metrics:"
    grep -E "(session_id|event_count|replayed_events|divergence_count|complete)" "$output1"
else
    echo "❌ FAILURE: Replay outputs differ!"
    echo "Showing differences:"
    diff "$output1" "$output2"
    exit 1
fi

echo ""
echo "Verification complete. Deterministic replay is working correctly."
