#!/bin/bash

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$0")"

echo "Checking Red/Blue Coevolution Signature Fields..."

# Extract all signature_hex values from coevolution_log.json
signatures=$(jq -r '.rounds[].signature_hex' "$SCRIPT_DIR/coevolution_log.json")

# Count total signatures
total_signatures=$(echo "$signatures" | wc -l)
expected_rounds=5

echo "Found $total_signatures signature(s), expected $expected_rounds"

if [ "$total_signatures" -ne "$expected_rounds" ]; then
    echo "❌ FAIL: Expected exactly $expected_rounds rounds, found $total_signatures"
    exit 1
fi

# Verify each signature field matches the required pattern: 64-character hex string
valid_count=0
round=1

while IFS= read -r signature; do
    if [[ $signature =~ ^[0-9a-f]{64}$ ]]; then
        echo "✅ Round $round signature field format valid: $signature"
        valid_count=$((valid_count + 1))
    else
        echo "❌ Round $round signature field format invalid: $signature (expected 64-char hex)"
        exit 1
    fi
    round=$((round + 1))
done <<< "$signatures"

echo ""
echo "🎉 SUCCESS: All $valid_count coevolution rounds have valid signature field format"
echo "   Pattern: /^[0-9a-f]{64}$/"
echo "   Fixture shape checks completed"
