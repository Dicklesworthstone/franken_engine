#!/bin/bash
set -euo pipefail

# Gate Script Linter for Logging Discipline
#
# Scans gate scripts to ensure they follow logging discipline standards,
# particularly the requirement for 'set -euo pipefail' at the top.
#
# Part of bd-cixqu.45 logging discipline implementation.
#
# Usage:
#   ./lint_gate_scripts.sh
#   ./lint_gate_scripts.sh <script_dir>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SEARCH_DIR="${1:-$SCRIPT_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Linting gate scripts for logging discipline compliance..."
echo "Search directory: $SEARCH_DIR"
echo

# Find all gate scripts
gate_scripts=($(find "$SEARCH_DIR" -name "run_*.sh" -type f 2>/dev/null || true))

if [[ ${#gate_scripts[@]} -eq 0 ]]; then
    echo -e "${YELLOW}No gate scripts found in $SEARCH_DIR${NC}"
    exit 0
fi

echo "Found ${#gate_scripts[@]} gate scripts to check"
echo

passed=0
failed=0
issues=()

for script in "${gate_scripts[@]}"; do
    script_name=$(basename "$script")

    # Check if script has set -euo pipefail in first 10 lines
    if head -n 10 "$script" | grep -q "^set -euo pipefail" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $script_name"
        ((passed++))
    else
        echo -e "${RED}✗${NC} $script_name (missing 'set -euo pipefail')"
        issues+=("$script_name: missing 'set -euo pipefail'")
        ((failed++))
    fi
done

echo
echo "Lint results: $passed passed, $failed failed"

if [[ $failed -gt 0 ]]; then
    echo
    echo "Issues found:"
    for issue in "${issues[@]}"; do
        echo "  - $issue"
    done
    echo
    echo "Fix: Add 'set -euo pipefail' after the shebang line in each failing script"
    exit 1
else
    echo -e "${GREEN}All gate scripts pass logging discipline lint checks!${NC}"
    exit 0
fi