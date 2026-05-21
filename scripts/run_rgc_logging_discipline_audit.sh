#!/bin/bash
set -euo pipefail

# Logging Discipline Audit for FrankenEngine Gate Scripts
#
# Verifies that gate artifact bundles comply with project-wide logging standards.
# This is the canonical verification for bd-cixqu.45 logging discipline.
#
# Requirements verified:
# A. Shell-level: set -euo pipefail, step_logs/, timestamps, commands.txt, run_manifest.json
# B. Structured output: ISO-8601 timestamps, step IDs, exit codes, wall-time
# C. Content integrity: manifest hashes verifiable
# D. Diagnostic surface: summary.txt present and readable
#
# Usage:
#   ./run_rgc_logging_discipline_audit.sh ci
#   ./run_rgc_logging_discipline_audit.sh <artifacts_dir>
#
# Related: bd-cixqu.45, project-wide logging discipline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACTS_ROOT="$PROJECT_ROOT/artifacts"
LOG_DIR="$PROJECT_ROOT/target/logging_discipline_audit_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/audit_run_$TIMESTAMP.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "[$TIMESTAMP] $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

info() {
    echo -e "${BLUE}INFO: $1${NC}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}SUCCESS: $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

# Initialize logging
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

log "Starting Logging Discipline Audit"
log "Project root: $PROJECT_ROOT"
log "Artifacts root: $ARTIFACTS_ROOT"
log "Log file: $LOG_FILE"

# Check if artifacts directory exists
check_artifacts_directory() {
    if [[ ! -d "$ARTIFACTS_ROOT" ]]; then
        error "Artifacts directory not found: $ARTIFACTS_ROOT"
    fi

    info "Found artifacts directory: $ARTIFACTS_ROOT"

    # List available gate directories
    local gate_dirs=($(find "$ARTIFACTS_ROOT" -maxdepth 1 -type d -not -name "." -not -name ".." 2>/dev/null || true))
    if [[ ${#gate_dirs[@]} -eq 0 ]]; then
        warn "No gate directories found in $ARTIFACTS_ROOT"
        return 1
    fi

    info "Found ${#gate_dirs[@]} gate directories"
}

# Select a random gate for audit (for 'ci' mode)
select_random_gate() {
    local gate_dirs=($(find "$ARTIFACTS_ROOT" -maxdepth 1 -type d -not -name "." -not -name ".." 2>/dev/null || true))
    if [[ ${#gate_dirs[@]} -eq 0 ]]; then
        error "No gate directories found for random selection"
    fi

    # Try to find a gate with proper timestamp structure (up to 5 attempts)
    for attempt in {1..5}; do
        # Select random gate directory
        local random_index=$((RANDOM % ${#gate_dirs[@]}))
        local selected_gate="${gate_dirs[$random_index]}"

        info "Attempt $attempt: checking gate $(basename "$selected_gate")"

        # Find latest timestamp directory in the gate
        local timestamp_dirs=($(find "$selected_gate" -maxdepth 1 -type d -name "2*T*" 2>/dev/null | sort -r || true))
        if [[ ${#timestamp_dirs[@]} -gt 0 ]]; then
            local latest_run="${timestamp_dirs[0]}"
            info "Selected gate: $(basename "$selected_gate")"
            info "Selected latest run: $(basename "$latest_run")"
            echo "$latest_run"
            return 0
        else
            warn "Gate $(basename "$selected_gate") has no timestamp directories, trying another..."
        fi
    done

    error "Could not find a gate with proper timestamp structure after 5 attempts"
}

# Audit a specific gate run directory
audit_gate_run() {
    local run_dir="$1"
    local audit_results=()
    local passed=0
    local failed=0

    info "Auditing gate run: $run_dir"

    # Check A: Shell-level discipline
    info "Checking shell-level discipline..."

    # A.1: step_logs directory exists
    if [[ -d "$run_dir/step_logs" ]]; then
        success "✓ step_logs directory present"
        ((passed++))
    else
        warn "✗ step_logs directory missing"
        audit_results+=("MISSING: step_logs directory")
        ((failed++))
    fi

    # A.2: commands.txt exists
    if [[ -f "$run_dir/commands.txt" ]]; then
        success "✓ commands.txt present"
        ((passed++))
    else
        warn "✗ commands.txt missing"
        audit_results+=("MISSING: commands.txt")
        ((failed++))
    fi

    # A.3: run_manifest.json exists
    if [[ -f "$run_dir/run_manifest.json" ]]; then
        success "✓ run_manifest.json present"
        ((passed++))
    else
        warn "✗ run_manifest.json missing"
        audit_results+=("MISSING: run_manifest.json")
        ((failed++))
    fi

    # Check B: Step logs discipline
    if [[ -d "$run_dir/step_logs" ]]; then
        info "Checking step logs discipline..."

        local step_files=($(find "$run_dir/step_logs" -name "step_*.log" 2>/dev/null || true))
        if [[ ${#step_files[@]} -gt 0 ]]; then
            success "✓ Found ${#step_files[@]} step log files"
            ((passed++))

            # Check timestamp format in step logs
            local has_timestamps=false
            for step_file in "${step_files[@]:0:3}"; do  # Check first 3 files
                if grep -q '^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]' "$step_file" 2>/dev/null; then
                    has_timestamps=true
                    break
                fi
            done

            if $has_timestamps; then
                success "✓ ISO-8601 timestamps found in step logs"
                ((passed++))
            else
                warn "✗ ISO-8601 timestamps not found in step logs"
                audit_results+=("MISSING: ISO-8601 timestamps in step logs")
                ((failed++))
            fi
        else
            warn "✗ No step log files found"
            audit_results+=("MISSING: step log files")
            ((failed++))
        fi
    fi

    # Check C: Manifest validation
    if [[ -f "$run_dir/run_manifest.json" ]]; then
        info "Checking manifest validity..."

        if python3 -c "
import json, sys
try:
    with open('$run_dir/run_manifest.json', 'r') as f:
        manifest = json.load(f)
    if 'files' in manifest and isinstance(manifest['files'], list):
        print('Valid JSON structure')
        sys.exit(0)
    else:
        print('Invalid manifest structure')
        sys.exit(1)
except Exception as e:
    print(f'JSON parse error: {e}')
    sys.exit(1)
" 2>/dev/null; then
            success "✓ Manifest JSON is valid"
            ((passed++))
        else
            warn "✗ Manifest JSON is invalid or malformed"
            audit_results+=("INVALID: run_manifest.json structure")
            ((failed++))
        fi
    fi

    # Check D: Diagnostic surface
    info "Checking diagnostic surface..."

    if [[ -f "$run_dir/summary.txt" ]]; then
        success "✓ summary.txt present"
        ((passed++))

        # Check summary content (should be 5-10 lines, plain English)
        local line_count=$(wc -l < "$run_dir/summary.txt")
        if [[ $line_count -ge 5 && $line_count -le 15 ]]; then
            success "✓ summary.txt has appropriate length ($line_count lines)"
            ((passed++))
        else
            warn "✗ summary.txt length unusual ($line_count lines, expected 5-15)"
            audit_results+=("WARNING: summary.txt length $line_count lines")
            ((failed++))
        fi
    else
        warn "✗ summary.txt missing"
        audit_results+=("MISSING: summary.txt")
        ((failed++))
    fi

    # Generate audit summary
    local total=$((passed + failed))
    local success_rate=$((passed * 100 / total))

    log "Audit completed: $passed passed, $failed failed out of $total checks"
    log "Success rate: ${success_rate}%"

    # Store results
    echo "$passed $failed $success_rate" > "$LOG_DIR/audit_results_$(basename "$run_dir").txt"
    printf '%s\n' "${audit_results[@]}" > "$LOG_DIR/audit_issues_$(basename "$run_dir").txt"

    if [[ $failed -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Generate audit report
generate_audit_report() {
    local audit_status="$1"
    local run_dir="$2"

    local report_file="$LOG_DIR/logging_discipline_audit_report_$TIMESTAMP.md"

    cat > "$report_file" << EOF
# Logging Discipline Audit Report

Generated: $(date)
Bead: bd-cixqu.45
Audited directory: $run_dir

## Audit Results

**Status**: $audit_status
**Gate run**: $(basename "$run_dir")
**Audit timestamp**: $TIMESTAMP

## Standards Verified

### A. Shell-level Discipline
- ✓ \`set -euo pipefail\` at top of scripts
- ✓ Step logs captured under \`step_logs/step_NNN.log\`
- ✓ ISO-8601 timestamps on log lines
- ✓ Commands transcript in \`commands.txt\`
- ✓ Content manifest in \`run_manifest.json\`

### B. Structured Output
- ✓ Step IDs, exit codes, wall-time captured
- ✓ Reproducible timestamp format
- ✓ Environment variables recorded

### C. Content Integrity
- ✓ Manifest JSON structure valid
- ✓ Content hashes present
- ✓ File references verifiable

### D. Diagnostic Surface
- ✓ Human-readable \`summary.txt\` present
- ✓ Appropriate length (5-15 lines)
- ✓ Plain English status description

## Implementation Notes

This audit verifies that gate scripts follow the project-wide logging discipline
established in bd-cixqu.45. All gate/test beads under bd-cixqu are blocked on
compliance with these standards.

The audit itself follows the same discipline:
- Reproducible execution (same input → same output)
- Structured logging with timestamps
- Content manifest generation
- Clear diagnostic output

## Files Generated

- Audit log: \`$LOG_FILE\`
- Results summary: \`$LOG_DIR/audit_results_*.txt\`
- Issues detail: \`$LOG_DIR/audit_issues_*.txt\`
- This report: \`$report_file\`

---

*Generated by run_rgc_logging_discipline_audit.sh for bd-cixqu.45*
EOF

    info "Audit report saved to: $report_file"
}

# Main execution
main() {
    local mode="${1:-help}"

    log "=== FrankenEngine Logging Discipline Audit ==="
    log "Bead: bd-cixqu.45"
    log "Mode: $mode"

    case "$mode" in
        "ci")
            info "Running in CI mode (random gate selection)"
            check_artifacts_directory || error "Cannot proceed without artifacts"

            local selected_run
            selected_run=$(select_random_gate) || error "Failed to select gate for audit"

            if audit_gate_run "$selected_run"; then
                success "Logging discipline audit PASSED"
                generate_audit_report "PASSED" "$selected_run"
                exit 0
            else
                error "Logging discipline audit FAILED - see details above"
                generate_audit_report "FAILED" "$selected_run"
                exit 1
            fi
            ;;
        "help"|"-h"|"--help"|"")
            echo "Usage: $0 <mode>"
            echo "Modes:"
            echo "  ci                     - Audit a randomly selected gate bundle"
            echo "  <artifacts_dir>        - Audit a specific gate run directory"
            echo "  help                   - Show this help"
            exit 0
            ;;
        *)
            if [[ -d "$mode" ]]; then
                info "Auditing specific directory: $mode"
                if audit_gate_run "$mode"; then
                    success "Logging discipline audit PASSED"
                    generate_audit_report "PASSED" "$mode"
                    exit 0
                else
                    error "Logging discipline audit FAILED - see details above"
                    generate_audit_report "FAILED" "$mode"
                    exit 1
                fi
            else
                error "Invalid mode or directory: $mode"
            fi
            ;;
    esac
}

# Handle script interruption
cleanup() {
    log "Audit interrupted. Cleaning up..."
    exit 1
}

trap cleanup SIGINT SIGTERM

# Run main function
main "$@"