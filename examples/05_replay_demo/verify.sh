#!/bin/bash
set -e

echo "FrankenEngine Deterministic Replay Verification"
echo "=============================================="

# Clean up any existing output files
rm -f output1.json output2.json

echo "Running replay #1..."
cargo run --bin frankenctl -- replay run --trace sample_trace.json --mode strict --out output1.json > /dev/null 2>&1

echo "Running replay #2..."
cargo run --bin frankenctl -- replay run --trace sample_trace.json --mode strict --out output2.json > /dev/null 2>&1

echo "Comparing outputs..."
if diff output1.json output2.json > /dev/null 2>&1; then
    echo "✅ SUCCESS: Replay outputs are byte-identical!"
    echo ""
    echo "Sample output:"
    head -15 output1.json
    echo "..."
    echo ""
    echo "Key metrics:"
    grep -E "(session_id|event_count|replayed_events|divergence_count|complete)" output1.json
else
    echo "❌ FAILURE: Replay outputs differ!"
    echo "Showing differences:"
    diff output1.json output2.json
    exit 1
fi

echo ""
echo "Verification complete. Deterministic replay is working correctly."