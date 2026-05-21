#!/bin/bash
# scripts/run_rgc_fleet_convergence_slo_gate.sh
# Test script for convergence SLO gate negative testing
# Part of bd-cixqu.2.6 - convergence gate REFUSES claims when partition profile is non-stable

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROFILES_PATH="$PROJECT_ROOT/docs/fleet_partition_fault_profiles_v1.json"

echo "=== Fleet Convergence SLO Gate Test ==="
echo "Testing convergence gate refusal for non-stable partition profiles"
echo ""

# Verify profiles file exists
if [[ ! -f "$PROFILES_PATH" ]]; then
    echo "ERROR: Fleet partition fault profiles not found at $PROFILES_PATH"
    exit 1
fi

echo "Loading partition profiles from: $PROFILES_PATH"

# Test convergence-impossible profiles
IMPOSSIBLE_PROFILES=("permanent_split" "split_brain")

for profile in "${IMPOSSIBLE_PROFILES[@]}"; do
    echo ""
    echo "--- Testing profile: $profile ---"

    # Run convergence gate test
    cargo run --bin convergence_slo_gate_test -- \
        --profile "$profile" \
        --profiles-path "$PROFILES_PATH" \
        --expect-refusal \
        --check-manifest-failure

    if [[ $? -eq 0 ]]; then
        echo "✓ Profile '$profile' correctly refused convergence claim"
    else
        echo "✗ Profile '$profile' FAILED to refuse convergence claim"
        exit 1
    fi
done

echo ""
echo "--- Testing stable profiles for contrast ---"

# Test stable profiles to ensure they pass
STABLE_PROFILES=("normal" "degraded" "healing")

for profile in "${STABLE_PROFILES[@]}"; do
    echo ""
    echo "--- Testing stable profile: $profile ---"

    cargo run --bin convergence_slo_gate_test -- \
        --profile "$profile" \
        --profiles-path "$PROFILES_PATH" \
        --expect-success

    if [[ $? -eq 0 ]]; then
        echo "✓ Profile '$profile' correctly allowed convergence claim"
    else
        echo "✗ Profile '$profile' FAILED to allow convergence claim"
        exit 1
    fi
done

echo ""
echo "=== All convergence gate tests PASSED ==="
echo "Gate correctly refuses claims for permanent partition conditions"
echo "Gate correctly allows claims for stable/recoverable conditions"
echo "SLO publication blocking verified for impossible scenarios"