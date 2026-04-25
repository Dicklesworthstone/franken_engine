#!/bin/bash

set -euo pipefail

echo "Verifying Red/Blue Coevolution Signatures..."

# Extract all signature_hex values from coevolution_log.json
signatures=$(jq -r '.rounds[].signature_hex' coevolution_log.json)

# Count total signatures
total_signatures=$(echo "$signatures" | wc -l)
expected_rounds=5

echo "Found $total_signatures signature(s), expected $expected_rounds"

if [ "$total_signatures" -ne "$expected_rounds" ]; then
    echo "❌ FAIL: Expected exactly $expected_rounds rounds, found $total_signatures"
    exit 1
fi

# Verify each signature matches the required pattern: 64-character hex string
valid_count=0
round=1

while IFS= read -r signature; do
    if [[ $signature =~ ^[0-9a-f]{64}$ ]]; then
        echo "✅ Round $round signature valid: $signature"
        valid_count=$((valid_count + 1))
    else
        echo "❌ Round $round signature INVALID: $signature (expected 64-char hex)"
        exit 1
    fi
    round=$((round + 1))
done <<< "$signatures"

echo ""
echo "🎉 SUCCESS: All $valid_count coevolution rounds have valid cryptographic signatures"
echo "   Pattern: /^[0-9a-f]{64}$/"
echo "   Red/Blue coevolution authenticity verified"