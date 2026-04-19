#!/bin/bash
# Production Hardening Exit Gate Replay Script
#
# Replays production hardening gate execution from archived artifacts
# for deterministic validation and incident investigation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Configuration
REPLAY_GATE_ID="${1:-}"
REPLAY_DIR="${PRODUCTION_HARDENING_GATE_REPLAY_RUN_DIR:-${PROJECT_ROOT}/artifacts/production_hardening_exit_gate/${REPLAY_GATE_ID}}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[REPLAY-INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_success() {
    echo -e "${GREEN}[REPLAY-SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_warning() {
    echo -e "${YELLOW}[REPLAY-WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[REPLAY-ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# Usage information
usage() {
    cat << EOF
Usage: $0 <gate_id>

Replay production hardening gate execution from archived artifacts.

Arguments:
  gate_id     The gate ID to replay (e.g., prod-gate-20260419014200)

Environment Variables:
  PRODUCTION_HARDENING_GATE_REPLAY_RUN_DIR  Custom replay directory path

Examples:
  $0 prod-gate-20260419014200
  PRODUCTION_HARDENING_GATE_REPLAY_RUN_DIR=/custom/path $0 prod-gate-20260419014200

The script expects the following directory structure:
  \${REPLAY_DIR}/
    ├── production_hardening_summary.json
    ├── production_hardening_gate.log
    ├── evidence/
    ├── command_logs/
    └── artifacts/
EOF
}

# Validate replay environment
validate_replay_environment() {
    log_info "Validating replay environment"

    if [[ -z "${REPLAY_GATE_ID}" ]]; then
        log_error "Missing gate_id argument"
        usage
        exit 1
    fi

    if [[ ! -d "${REPLAY_DIR}" ]]; then
        log_error "Replay directory not found: ${REPLAY_DIR}"
        log_error "Ensure the gate artifacts are available at the expected location"
        exit 1
    fi

    # Check required files
    local required_files=(
        "production_hardening_summary.json"
        "production_hardening_gate.log"
    )

    for file in "${required_files[@]}"; do
        if [[ ! -f "${REPLAY_DIR}/${file}" ]]; then
            log_error "Required file not found: ${REPLAY_DIR}/${file}"
            exit 1
        fi
    done

    # Check required directories
    local required_dirs=(
        "evidence"
        "command_logs"
        "artifacts"
    )

    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "${REPLAY_DIR}/${dir}" ]]; then
            log_error "Required directory not found: ${REPLAY_DIR}/${dir}"
            exit 1
        fi
    done

    log_success "Replay environment validation passed"
}

# Display gate summary
display_gate_summary() {
    log_info "=== Production Hardening Gate Summary ==="

    if command -v jq >/dev/null 2>&1; then
        local summary_file="${REPLAY_DIR}/production_hardening_summary.json"

        local gate_id=$(jq -r '.gate_id' "${summary_file}")
        local start_time=$(jq -r '.start_time' "${summary_file}")
        local end_time=$(jq -r '.end_time' "${summary_file}")
        local duration=$(jq -r '.duration_seconds' "${summary_file}")
        local status=$(jq -r '.status' "${summary_file}")
        local production_readiness=$(jq -r '.production_readiness' "${summary_file}")

        echo "Gate ID: ${gate_id}"
        echo "Start Time: ${start_time}"
        echo "End Time: ${end_time}"
        echo "Duration: ${duration} seconds"
        echo "Status: ${status}"
        echo "Production Readiness: ${production_readiness}"
        echo ""

        log_info "=== Phase Completion Status ==="
        jq -r '.phases_completed[]' "${summary_file}" | while read -r phase; do
            echo "✅ ${phase}"
        done
        echo ""

        log_info "=== Gate Requirements Met ==="
        jq -r '.gate_requirements_met | to_entries[] | "\(.key): \(.value)"' "${summary_file}" | while read -r requirement; do
            echo "✅ ${requirement}"
        done
        echo ""

        log_info "=== Testing Requirements Met ==="
        jq -r '.testing_requirements_met | to_entries[] | "\(.key): \(.value)"' "${summary_file}" | while read -r requirement; do
            echo "✅ ${requirement}"
        done

    else
        log_warning "jq not available - showing raw summary file"
        cat "${REPLAY_DIR}/production_hardening_summary.json"
    fi
}

# Display evidence artifacts
display_evidence_artifacts() {
    log_info "=== Evidence Artifacts ==="

    local evidence_dir="${REPLAY_DIR}/evidence"

    if [[ -d "${evidence_dir}" ]]; then
        local artifact_count=$(find "${evidence_dir}" -name "*.json" | wc -l)
        echo "Evidence artifacts found: ${artifact_count}"

        if [[ ${artifact_count} -gt 0 ]]; then
            echo ""
            find "${evidence_dir}" -name "*.json" | sort | while read -r artifact; do
                local relative_path=${artifact#${REPLAY_DIR}/}
                local size=$(stat -c%s "${artifact}" 2>/dev/null || stat -f%z "${artifact}" 2>/dev/null || echo "unknown")
                echo "📁 ${relative_path} (${size} bytes)"
            done
        fi
    else
        log_warning "Evidence directory not found"
    fi
}

# Display command execution logs
display_command_logs() {
    log_info "=== Command Execution Logs ==="

    local logs_dir="${REPLAY_DIR}/command_logs"

    if [[ -d "${logs_dir}" ]]; then
        local log_count=$(find "${logs_dir}" -name "*.log" | wc -l)
        echo "Command logs found: ${log_count}"

        if [[ ${log_count} -gt 0 ]]; then
            echo ""
            find "${logs_dir}" -name "*.log" | sort | while read -r logfile; do
                local relative_path=${logfile#${REPLAY_DIR}/}
                local size=$(stat -c%s "${logfile}" 2>/dev/null || stat -f%z "${logfile}" 2>/dev/null || echo "unknown")
                echo "📄 ${relative_path} (${size} bytes)"
            done
        fi
    else
        log_warning "Command logs directory not found"
    fi
}

# Validate security matrix results
validate_security_matrix_replay() {
    log_info "=== Security Matrix Validation Replay ==="

    # Check for security matrix evidence
    local security_evidence=$(find "${REPLAY_DIR}/evidence" -name "*security*" -name "*.json" | head -5)

    if [[ -n "${security_evidence}" ]]; then
        echo "Security matrix evidence artifacts:"
        echo "${security_evidence}" | while read -r artifact; do
            local relative_path=${artifact#${REPLAY_DIR}/}
            echo "  ✅ ${relative_path}"
        done
    else
        log_warning "No security matrix evidence found"
    fi
}

# Validate fuzz campaign results
validate_fuzz_campaign_replay() {
    log_info "=== Fuzz Campaign Validation Replay ==="

    # Check for fuzz campaign evidence
    local fuzz_evidence=$(find "${REPLAY_DIR}/evidence" -name "*fuzz*" -name "*.json" | head -10)

    if [[ -n "${fuzz_evidence}" ]]; then
        echo "Fuzz campaign evidence artifacts:"
        echo "${fuzz_evidence}" | while read -r artifact; do
            local relative_path=${artifact#${REPLAY_DIR}/}
            echo "  ✅ ${relative_path}"
        done
    else
        log_warning "No fuzz campaign evidence found"
    fi
}

# Validate quarantine drill results
validate_quarantine_drill_replay() {
    log_info "=== Quarantine Drill Validation Replay ==="

    # Check for quarantine drill evidence
    local quarantine_evidence=$(find "${REPLAY_DIR}/evidence" -name "*quarantine*" -name "*.json" | head -5)

    if [[ -n "${quarantine_evidence}" ]]; then
        echo "Quarantine drill evidence artifacts:"
        echo "${quarantine_evidence}" | while read -r artifact; do
            local relative_path=${artifact#${REPLAY_DIR}/}
            echo "  ✅ ${relative_path}"
        done
    else
        log_warning "No quarantine drill evidence found"
    fi
}

# Validate replay audit results
validate_replay_audit_replay() {
    log_info "=== Replay Audit Validation Replay ==="

    # Check for replay audit evidence
    local replay_evidence=$(find "${REPLAY_DIR}/evidence" -name "*replay*" -name "*.json" | head -5)

    if [[ -n "${replay_evidence}" ]]; then
        echo "Replay audit evidence artifacts:"
        echo "${replay_evidence}" | while read -r artifact; do
            local relative_path=${artifact#${REPLAY_DIR}/}
            echo "  ✅ ${relative_path}"
        done
    else
        log_warning "No replay audit evidence found"
    fi
}

# Display execution timeline
display_execution_timeline() {
    log_info "=== Execution Timeline ==="

    local main_log="${REPLAY_DIR}/production_hardening_gate.log"

    if [[ -f "${main_log}" ]]; then
        echo "Key execution milestones:"

        # Extract phase start/completion times
        grep -E "\[INFO\].*===.*===" "${main_log}" | head -20 | while read -r line; do
            echo "  ${line}"
        done

        echo ""
        echo "Final status:"
        grep -E "\[SUCCESS\]" "${main_log}" | tail -5 | while read -r line; do
            echo "  ${line}"
        done
    else
        log_warning "Main log file not found"
    fi
}

# Verify deterministic replay capability
verify_deterministic_replay() {
    log_info "=== Deterministic Replay Verification ==="

    # Check if structured logging captured required events
    local main_log="${REPLAY_DIR}/production_hardening_gate.log"

    if [[ -f "${main_log}" ]]; then
        local event_count=$(grep -c "PRODUCTION_HARDENING_LOG:" "${main_log}" || echo "0")
        echo "Structured log events captured: ${event_count}"

        if [[ ${event_count} -gt 0 ]]; then
            echo ""
            echo "Structured log events (sample):"
            grep "PRODUCTION_HARDENING_LOG:" "${main_log}" | head -5 | while read -r event; do
                echo "  📝 ${event}"
            done
        fi
    fi

    # Verify evidence completeness
    local evidence_count=$(find "${REPLAY_DIR}/evidence" -name "*.json" | wc -l)
    local expected_evidence_categories=8  # security, fuzz, properties, faults, quarantine, replay, etc.

    if [[ ${evidence_count} -ge ${expected_evidence_categories} ]]; then
        log_success "Evidence collection appears complete (${evidence_count} artifacts)"
    else
        log_warning "Evidence collection may be incomplete (${evidence_count} artifacts < ${expected_evidence_categories} expected)"
    fi
}

# Main replay execution
main() {
    echo "🔄 Production Hardening Exit Gate - Replay Mode"
    echo "Gate ID: ${REPLAY_GATE_ID}"
    echo "Replay Directory: ${REPLAY_DIR}"
    echo ""

    validate_replay_environment
    display_gate_summary
    display_evidence_artifacts
    display_command_logs
    validate_security_matrix_replay
    validate_fuzz_campaign_replay
    validate_quarantine_drill_replay
    validate_replay_audit_replay
    display_execution_timeline
    verify_deterministic_replay

    echo ""
    log_success "🎉 Production Hardening Gate Replay Completed"
    log_success "📁 Artifacts: ${REPLAY_DIR}"

    # Final validation
    local summary_file="${REPLAY_DIR}/production_hardening_summary.json"
    if [[ -f "${summary_file}" ]] && command -v jq >/dev/null 2>&1; then
        local production_readiness=$(jq -r '.production_readiness' "${summary_file}")
        if [[ "${production_readiness}" == "GO" ]]; then
            log_success "🚀 Production Readiness Status: GO"
        else
            log_warning "⚠️  Production Readiness Status: ${production_readiness}"
        fi
    fi
}

# Error handling
trap 'log_error "Production hardening gate replay failed"; exit 1' ERR

# Execute main function
main "$@"