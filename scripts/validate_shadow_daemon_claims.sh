#!/usr/bin/env bash
#
# Validate Shadow Daemon Documentation Claims
#
# This script validates that documentation claims about the shadow daemon
# remain truthful and comply with adoption gate restrictions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Function to log with color
log() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to run a check
run_check() {
    local description=$1
    local command=$2

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo ""
    log "$BLUE" "🔍 Check $TOTAL_CHECKS: $description"

    if eval "$command"; then
        log "$GREEN" "  ✅ PASS"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log "$RED" "  ❌ FAIL"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Function to check for forbidden patterns in documentation
check_forbidden_patterns() {
    local file_path=$1
    local description=$2

    if [[ ! -f "$file_path" ]]; then
        log "$YELLOW" "  ⚠️  File not found: $file_path"
        return 1
    fi

    local content
    content=$(cat "$file_path")
    local content_lower
    content_lower=$(echo "$content" | tr '[:upper:]' '[:lower:]')

    # Check for autonomous mutation claims
    if echo "$content_lower" | grep -q "autonomous.*mutation\|autonomous.*execute\|autonomous.*modify"; then
        log "$RED" "  ❌ Found autonomous mutation claim in $description"
        echo "$content_lower" | grep -n "autonomous.*mutation\|autonomous.*execute\|autonomous.*modify" | head -3
        return 1
    fi

    # Check for production daemon claims
    if echo "$content_lower" | grep -q "production.*daemon\|production-ready.*daemon\|deploy.*daemon.*production"; then
        log "$RED" "  ❌ Found production daemon claim in $description"
        echo "$content_lower" | grep -n "production.*daemon\|production-ready.*daemon\|deploy.*daemon.*production" | head -3
        return 1
    fi

    # Check for operator replacement claims
    if echo "$content_lower" | grep -q "replace.*operator\|replaces.*operator\|operator.*replacement"; then
        log "$RED" "  ❌ Found operator replacement claim in $description"
        echo "$content_lower" | grep -n "replace.*operator\|replaces.*operator\|operator.*replacement" | head -3
        return 1
    fi

    log "$GREEN" "  ✅ No forbidden patterns found in $description"
    return 0
}

# Function to check that advisory language is present
check_advisory_language() {
    local file_path=$1
    local description=$2

    if [[ ! -f "$file_path" ]]; then
        log "$YELLOW" "  ⚠️  File not found: $file_path"
        return 1
    fi

    # Should contain advisory language
    if ! grep -Eiq "advisory|recommendation|preview|manual" "$file_path"; then
        log "$RED" "  ❌ Missing advisory language in $description"
        return 1
    fi

    log "$GREEN" "  ✅ Advisory language found in $description"
    return 0
}

# Function to validate command examples
check_command_examples() {
    local file_path=$1
    local description=$2

    if [[ ! -f "$file_path" ]]; then
        log "$YELLOW" "  ⚠️  File not found: $file_path"
        return 1
    fi

    # Extract code blocks and check for forbidden commands
    local forbidden_commands=("br " "git " "rch " "agent-mail " "worker " "queue ")
    local has_violations=0

    # Simple extraction of command-like patterns
    while IFS= read -r line; do
        # Skip comments and explanations
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ "$line" =~ ^[[:space:]]*// ]]; then
            continue
        fi

        # Check for forbidden command patterns in potential commands
        if [[ "$line" =~ ^[[:space:]]*[a-zA-Z] ]]; then
            for cmd in "${forbidden_commands[@]}"; do
                if [[ "$line" =~ $cmd ]]; then
                    # Allow if it's clearly a comment or example description
                    if [[ "$line" == *echo*"$cmd"* ]] || [[ "$line" == *"# "*"$cmd"* ]] || [[ "$line" == *"Remember to"*"$cmd"* ]]; then
                        continue
                    fi
                    log "$RED" "  ❌ Found potentially dangerous command in $description: $line"
                    has_violations=1
                fi
            done
        fi
    done < "$file_path"

    if [[ $has_violations -eq 0 ]]; then
        log "$GREEN" "  ✅ No dangerous command examples found in $description"
        return 0
    else
        return 1
    fi
}

check_script_command_examples() {
    local script_path
    local has_violations=0

    while IFS= read -r script_path; do
        if ! check_command_examples "$script_path" "script $script_path"; then
            has_violations=1
        fi
    done < <(find scripts/ -name '*.sh' ! -path '*/e2e/shadow_daemon_lifecycle_drill.sh' | sort)

    return "$has_violations"
}

check_shadow_no_mock_gate_truth() {
    local proof_doc="${SHADOW_PROOF_DOC:-docs/SHADOW_DAEMON_PROOF_STATE.md}"
    local lifecycle_drill="${SHADOW_LIFECYCLE_DRILL:-scripts/e2e/shadow_daemon_lifecycle_drill.sh}"

    if [[ ! -f "$proof_doc" || ! -f "$lifecycle_drill" ]]; then
        log "$RED" "  ❌ Missing shadow proof-state inputs"
        return 1
    fi

    if grep -A3 'no_mock_drill' "$proof_doc" | grep -Eq 'GREEN|🟢'; then
        log "$RED" "  ❌ no_mock_drill is still documented as green"
        return 1
    fi

    if ! grep -A4 'no_mock_drill' "$proof_doc" | grep -Eq 'BLOCKED|🔴'; then
        log "$RED" "  ❌ no_mock_drill is not documented as blocked"
        return 1
    fi

    if ! grep -q 'synthetic evidence exercise' "$proof_doc"; then
        log "$RED" "  ❌ Proof-state doc does not name the lifecycle drill as synthetic"
        return 1
    fi

    if ! grep -q 'EXIT_SYNTHETIC_EVIDENCE' "$lifecycle_drill"; then
        log "$RED" "  ❌ Lifecycle drill no longer has a synthetic-evidence exit guard"
        return 1
    fi

    if grep -q 'cargo run --bin shadow_' "$lifecycle_drill"; then
        log "$RED" "  ❌ Synthetic lifecycle drill still invokes shadow helper binaries via bare cargo"
        return 1
    fi

    log "$GREEN" "  ✅ no_mock_drill remains blocked and synthetic drill evidence fails closed"
    return 0
}

# Main validation function
main() {
    log "$BLUE" "🚦 Shadow Daemon Documentation Claims Validation"
    log "$BLUE" "=============================================="

    cd "$PROJECT_ROOT"

    # Check main README
    run_check "README.md forbidden patterns" \
        "check_forbidden_patterns 'README.md' 'main README'"

    run_check "README.md advisory language" \
        "check_advisory_language 'README.md' 'main README'"

    # Check shadow daemon contract
    run_check "Shadow daemon contract forbidden patterns" \
        "check_forbidden_patterns 'docs/SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT.md' 'shadow daemon contract'"

    run_check "Shadow daemon contract advisory language" \
        "check_advisory_language 'docs/SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT.md' 'shadow daemon contract'"

    # Check handoff contracts
    run_check "Handoff contracts forbidden patterns" \
        "check_forbidden_patterns 'docs/handoff_contracts.md' 'handoff contracts'"

    run_check "Handoff contracts advisory language" \
        "check_advisory_language 'docs/handoff_contracts.md' 'handoff contracts'"

    # Check proof state documentation
    run_check "Proof state documentation exists" \
        "test -f 'docs/SHADOW_DAEMON_PROOF_STATE.md'"

    run_check "Proof state contains gate status" \
        "grep -q 'Gate Status\|gate status' 'docs/SHADOW_DAEMON_PROOF_STATE.md' || grep -q 'BLOCKED CAPABILITIES' 'docs/SHADOW_DAEMON_PROOF_STATE.md'"

    run_check "No-mock lifecycle gate truth" \
        "check_shadow_no_mock_gate_truth"

    # Rust compile/test gates are enforced by the standard rch workflow, not this
    # documentation scanner.

    # Do not scan implementation scripts for br/git/rch command execution here:
    # those commands are normal implementation details in this repo. The
    # shadow-lifecycle adoption risk is covered by the targeted no-mock gate
    # truth check above.

    # Summary
    echo ""
    log "$BLUE" "=========================================="
    log "$BLUE" "📊 VALIDATION SUMMARY"
    log "$BLUE" "=========================================="

    log "$BLUE" "Total checks: $TOTAL_CHECKS"
    log "$GREEN" "Passed: $PASSED_CHECKS"

    if [[ $FAILED_CHECKS -gt 0 ]]; then
        log "$RED" "Failed: $FAILED_CHECKS"
        echo ""
        log "$RED" "❌ VALIDATION FAILED"
        log "$RED" "Documentation contains claims that violate adoption gate restrictions."
        log "$RED" "Please review and update documentation to reflect advisory-only status."
        exit 1
    else
        echo ""
        log "$GREEN" "✅ VALIDATION PASSED"
        log "$GREEN" "All documentation claims comply with adoption gate restrictions."
        log "$GREEN" "Shadow daemon documentation correctly reflects advisory-only status."
    fi
}

# Handle command line arguments
case "${1:-validate}" in
    "validate")
        main
        ;;
    "help")
        echo "Usage: $0 [validate|help]"
        echo ""
        echo "Commands:"
        echo "  validate  Run all documentation validation checks (default)"
        echo "  help      Show this help message"
        echo ""
        echo "This script validates that shadow daemon documentation claims"
        echo "comply with adoption gate restrictions and maintain advisory-only semantics."
        echo ""
        echo "Environment overrides for fixture checks:"
        echo "  SHADOW_PROOF_DOC        Proof-state document path"
        echo "  SHADOW_LIFECYCLE_DRILL  Lifecycle drill script path"
        ;;
    *)
        log "$RED" "Unknown command: $1"
        echo "Use '$0 help' for usage information."
        exit 1
        ;;
esac
