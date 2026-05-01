#!/bin/bash
set -euo pipefail

# Red Team Attack Execution Harness
# Executes red team scenarios against different JavaScript runtimes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SCENARIO_DIR="$PROJECT_ROOT/crates/franken-engine/tests/red_team_scenarios"

# Available runtimes
NODE_CMD="/usr/bin/node"
BUN_CMD="/home/ubuntu/.bun/bin/bun"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_banner() {
    echo "=================================================="
    echo "  FrankenEngine Red Team Attack Harness"
    echo "=================================================="
    echo ""
}

check_runtime() {
    local runtime="$1"
    local cmd="$2"

    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ $runtime available${NC} ($cmd)"
        return 0
    else
        echo -e "${RED}✗ $runtime not available${NC} ($cmd)"
        return 1
    fi
}

execute_scenario() {
    local scenario_name="$1"
    local runtime="$2"
    local cmd="$3"

    local script_path="$SCENARIO_DIR/$scenario_name.js"
    local manifest_path="$SCENARIO_DIR/$scenario_name.manifest.json"

    if [[ ! -f "$script_path" ]]; then
        echo -e "${RED}✗ Script not found: $script_path${NC}"
        return 1
    fi

    if [[ ! -f "$manifest_path" ]]; then
        echo -e "${RED}✗ Manifest not found: $manifest_path${NC}"
        return 1
    fi

    echo "  Runtime: $runtime"
    echo "  Script: $script_path"

    # Set up environment
    export FRANKENENGINE_REDTEAM_CANARY="canary-token-for-local-test-only"

    # Execute the scenario
    local output
    local exit_code=0

    if [[ "$runtime" == "bun" ]]; then
        output=$("$cmd" run "$script_path" 2>&1) || exit_code=$?
    else
        output=$("$cmd" "$script_path" 2>&1) || exit_code=$?
    fi

    echo "  Exit code: $exit_code"
    echo "  Output:"
    echo "$output" | sed 's/^/    /'

    # Parse attack result from JSON output
    local attack_succeeded=false
    if echo "$output" | grep -q '"attack_succeeded".*true'; then
        attack_succeeded=true
    fi

    # Read expected outcome from manifest
    local expected_outcome
    expected_outcome=$(jq -r ".expected_outcome.$runtime.outcome" "$manifest_path" 2>/dev/null || echo "unknown")

    local expected_success=false
    if [[ "$expected_outcome" == "succeeds" ]]; then
        expected_success=true
    fi

    # Check if result matches expectation
    local matches_expectation=false
    if [[ "$attack_succeeded" == "$expected_success" ]]; then
        matches_expectation=true
    fi

    echo "  Attack succeeded: $attack_succeeded"
    echo "  Expected: $expected_outcome"
    echo -n "  Result: "
    if [[ "$matches_expectation" == "true" ]]; then
        echo -e "${GREEN}✓ MATCHES EXPECTATION${NC}"
    else
        echo -e "${RED}✗ DOES NOT MATCH EXPECTATION${NC}"
    fi

    echo ""
    return 0
}

main() {
    print_banner

    echo "Checking runtime availability..."
    local node_available=false
    local bun_available=false

    if check_runtime "Node.js" "$NODE_CMD"; then
        node_available=true
    fi

    if check_runtime "Bun" "$BUN_CMD"; then
        bun_available=true
    fi

    echo ""

    # List available scenarios
    local scenarios=()
    if [[ -d "$SCENARIO_DIR" ]]; then
        while IFS= read -r -d '' file; do
            local name
            name=$(basename "$file" .js)
            scenarios+=("$name")
        done < <(find "$SCENARIO_DIR" -name "*.js" -print0)
    fi

    if [[ ${#scenarios[@]} -eq 0 ]]; then
        echo -e "${RED}No scenarios found in $SCENARIO_DIR${NC}"
        exit 1
    fi

    echo "Found ${#scenarios[@]} scenario(s):"
    for scenario in "${scenarios[@]}"; do
        echo "  - $scenario"
    done
    echo ""

    # Execute scenarios
    local total_executions=0
    local successful_attacks=0
    local matching_expectations=0

    for scenario in "${scenarios[@]}"; do
        echo "=================================================="
        echo "Scenario: $scenario"
        echo "=================================================="

        if [[ "$node_available" == "true" ]]; then
            echo ""
            echo "--- Executing with Node.js ---"
            if execute_scenario "$scenario" "node" "$NODE_CMD"; then
                total_executions=$((total_executions + 1))
                if execute_scenario "$scenario" "node" "$NODE_CMD" | grep -q "Attack succeeded: true"; then
                    successful_attacks=$((successful_attacks + 1))
                fi
                if execute_scenario "$scenario" "node" "$NODE_CMD" | grep -q "✓ MATCHES EXPECTATION"; then
                    matching_expectations=$((matching_expectations + 1))
                fi
            fi
        fi

        if [[ "$bun_available" == "true" ]]; then
            echo ""
            echo "--- Executing with Bun ---"
            if execute_scenario "$scenario" "bun" "$BUN_CMD"; then
                total_executions=$((total_executions + 1))
                if execute_scenario "$scenario" "bun" "$BUN_CMD" | grep -q "Attack succeeded: true"; then
                    successful_attacks=$((successful_attacks + 1))
                fi
                if execute_scenario "$scenario" "bun" "$BUN_CMD" | grep -q "✓ MATCHES EXPECTATION"; then
                    matching_expectations=$((matching_expectations + 1))
                fi
            fi
        fi

        echo ""
        echo "--- FrankenEngine (Stub) ---"
        echo "  FrankenEngine execution not yet implemented"
        echo "  Expected: fail_closed (all attacks should fail)"
        echo ""
    done

    # Summary
    echo "=================================================="
    echo "SUMMARY"
    echo "=================================================="
    echo "Total executions: $total_executions"
    echo "Successful attacks: $successful_attacks"
    echo "Matching expectations: $matching_expectations"

    if [[ $total_executions -gt 0 ]]; then
        local match_rate
        match_rate=$(echo "scale=1; $matching_expectations * 100 / $total_executions" | bc -l 2>/dev/null || echo "N/A")
        echo "Expectation match rate: ${match_rate}%"
    fi

    echo ""
    echo "Red team harness execution complete."
}

# Check dependencies
if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}Error: jq is required but not installed${NC}" >&2
    exit 1
fi

main "$@"