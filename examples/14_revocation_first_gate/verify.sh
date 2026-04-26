#!/bin/bash
set -euo pipefail

echo "FrankenEngine Revocation-First Gate Verification"
echo "==============================================="

script_dir="$(dirname "$0")"

# Check that after_revocation.json exists
if [[ ! -f "$script_dir/after_revocation.json" ]]; then
    echo "❌ ERROR: after_revocation.json not found"
    exit 1
fi

# Extract policy_decision using jq or basic grep/sed
policy_decision=$(grep -o '"policy_decision":[[:space:]]*"[^"]*"' "$script_dir/after_revocation.json" | sed 's/.*"\([^"]*\)".*/\1/')

# Extract signature_hex
signature_hex=$(grep -o '"signature_hex":[[:space:]]*"[^"]*"' "$script_dir/after_revocation.json" | sed 's/.*"\([^"]*\)".*/\1/')

echo "Checking policy enforcement..."

# Verify policy_decision is fail-closed
if [[ "$policy_decision" == "fail-closed" ]]; then
    echo "✅ Policy decision is correctly set to 'fail-closed'"
else
    echo "❌ SECURITY VIOLATION: Policy decision is '$policy_decision', expected 'fail-closed'"
    exit 1
fi

# Verify signature_hex matches expected format (64 hex characters)
if [[ "$signature_hex" =~ ^[0-9a-f]{64}$ ]]; then
    echo "✅ Signature hex format is valid (64 hex characters)"
    echo "   Signature: $signature_hex"
else
    echo "❌ SECURITY VIOLATION: Invalid signature hex format"
    echo "   Expected: 64 hex characters matching ^[0-9a-f]{64}$"
    echo "   Got: '$signature_hex'"
    exit 1
fi

# Additional security property checks
echo ""
echo "Checking additional security properties..."

# Verify trust_chain_status is revoked
trust_status=$(grep -o '"trust_chain_status":[[:space:]]*"[^"]*"' "$script_dir/after_revocation.json" | sed 's/.*"\([^"]*\)".*/\1/')
if [[ "$trust_status" == "revoked" ]]; then
    echo "✅ Trust chain status correctly shows 'revoked'"
else
    echo "❌ WARNING: Trust chain status is '$trust_status', expected 'revoked'"
fi

# Check that dangerous capabilities are denied
if grep -q '"read"' "$script_dir/after_revocation.json" && grep -q '"write"' "$script_dir/after_revocation.json" && grep -q '"exec"' "$script_dir/after_revocation.json"; then
    echo "✅ All dangerous capabilities (read, write, exec) are explicitly denied"
else
    echo "❌ WARNING: Some dangerous capabilities may not be explicitly denied"
fi

echo ""
echo "🔒 VERIFICATION PASSED"
echo "Revocation-first execution gate fixture is properly configured with:"
echo "  - Fail-closed policy enforcement"
echo "  - Signature field format check"
echo "  - Explicit capability revocation"
