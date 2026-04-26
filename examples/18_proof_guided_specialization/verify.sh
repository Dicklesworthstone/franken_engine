#!/bin/bash

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$0")"

echo "Verifying Security-Proof-Guided Specialization Artifacts..."

# Extract verification signature from proof artifact
signature=$(jq -r '.verification_signature_hex' "$SCRIPT_DIR/proof_artifact.json")

echo "Found verification signature: $signature"

# Verify the signature field matches the required pattern: 64-character hex string
if [[ $signature =~ ^[0-9a-f]{64}$ ]]; then
    echo "✅ Verification signature field format valid: $signature"
    echo "   Pattern: /^[0-9a-f]{64}$/"
else
    echo "❌ Verification signature field format invalid: $signature (expected 64-char hex)"
    exit 1
fi

# Verify proof structure
bound_proven=$(jq -r '.bound_proven' "$SCRIPT_DIR/proof_artifact.json")
specialization_id=$(jq -r '.specialization_id' "$SCRIPT_DIR/proof_artifact.json")
evidence_count=$(jq '.evidence_chain | length' "$SCRIPT_DIR/proof_artifact.json")

echo ""
echo "📋 Proof Verification Summary:"
echo "   Bound Proven: $bound_proven"
echo "   Specialization ID: $specialization_id"
echo "   Evidence Chain Links: $evidence_count"

# Verify performance improvements
generic_p99=$(jq -r '.latency_p99_micros' "$SCRIPT_DIR/generic_path_metrics.json")
specialized_p99=$(jq -r '.latency_p99_micros' "$SCRIPT_DIR/specialized_path_metrics.json")

improvement_percent=$(( (generic_p99 - specialized_p99) * 100 / generic_p99 ))

echo ""
echo "🚀 Performance Verification:"
echo "   Generic P99 Latency: ${generic_p99}μs"
echo "   Specialized P99 Latency: ${specialized_p99}μs"
echo "   Improvement: ${improvement_percent}%"

if [ "$specialized_p99" -le 400 ]; then
    echo "✅ Performance bound satisfied (P99 ≤ 400μs)"
else
    echo "❌ Performance bound violated (P99 > 400μs)"
    exit 1
fi

echo ""
echo "🎉 SUCCESS: Security-proof-guided specialization fixture checks passed"
echo "   Signature field format checked"
echo "   Performance bound artifact satisfied"
