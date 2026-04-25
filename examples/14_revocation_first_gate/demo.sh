#!/bin/bash

echo "FrankenEngine Revocation-First Execution Gate Demo"
echo "=================================================="
echo ""

echo "BEFORE REVOCATION (Normal Operation):"
echo "------------------------------------"
cat before_revocation.json
echo ""
echo ""

echo "AFTER REVOCATION (Fail-Closed with Policy Proof):"
echo "------------------------------------------------"
cat after_revocation.json
echo ""
echo ""

echo "Key Security Property:"
echo "- Extension trust_chain_status: 'revoked'"
echo "- Policy decision: 'fail-closed' (not 'degraded' or 'limited')"
echo "- Cryptographic proof prevents capability escalation"
echo "- No fallback to unsafe execution modes"