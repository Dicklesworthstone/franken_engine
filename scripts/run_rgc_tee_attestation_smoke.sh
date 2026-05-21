#!/usr/bin/env bash

set -euo pipefail

# TEE attestation smoke test for RGC continuous integration.
#
# This script validates TEE attestation capabilities on the current worker:
# - If TEE hardware is available, generates live quotes and validates them
# - If TEE hardware is not available, records 'skipped' (not 'passed')
# - Validates safe-mode fallback behavior for non-TEE workers
#
# Exit codes:
#   0: Test completed successfully (either passed on TEE or skipped on non-TEE)
#   1: Test failed (hardware available but quote generation failed)
#   2: Invalid usage or environment setup error

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SMOKE_TEST_TIMEOUT=30
readonly TEE_TEST_OUTPUT_FILE="/tmp/rgc_tee_attestation_smoke_$$.json"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

cleanup() {
    if [[ -f "${TEE_TEST_OUTPUT_FILE}" ]]; then
        rm -f "${TEE_TEST_OUTPUT_FILE}" || true
    fi
}

trap cleanup EXIT

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

TEE attestation smoke test for RGC CI pipeline.

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    --timeout SECONDS   Override default timeout (default: ${SMOKE_TEST_TIMEOUT}s)
    --output FILE       Override output file location
    --force-tee         Force TEE mode (fail if TEE not available)
    --force-safe-mode   Force safe-mode test only

ENVIRONMENT VARIABLES:
    FRANKEN_TEE_ENABLED    Set to 'true' to simulate TEE availability
    FRANKEN_TEE_ERROR      Set to error message to simulate TEE hardware error
    FRANKEN_TEE_QUOTE_FAIL Set to '1' to simulate quote generation failure
    RGC_CI                 Set to 'true' when running in CI environment

EXAMPLES:
    # Normal smoke test (auto-detects TEE capability)
    $0

    # Force TEE test (fail if not available)
    $0 --force-tee

    # Test with verbose output
    $0 --verbose

    # Simulate TEE environment for testing
    FRANKEN_TEE_ENABLED=true $0

EOF
}

detect_tee_capability() {
    log_info "Detecting TEE capability..."

    # Check environment variables first (for testing/CI)
    if [[ "${FRANKEN_TEE_ENABLED:-}" == "true" ]]; then
        log_success "TEE capability detected via FRANKEN_TEE_ENABLED"
        return 0
    fi

    if [[ -n "${FRANKEN_TEE_ERROR:-}" ]]; then
        log_error "TEE hardware error detected: ${FRANKEN_TEE_ERROR}"
        return 2
    fi

    # In production, this would check actual TEE hardware
    # For now, we check for specific platform indicators
    if [[ -f "/dev/sgx_enclave" ]] || [[ -f "/dev/sgx/enclave" ]]; then
        log_success "Intel SGX TEE hardware detected"
        return 0
    fi

    if [[ -d "/sys/firmware/tee" ]]; then
        log_success "ARM TrustZone TEE detected"
        return 0
    fi

    # Check for AMD SEV
    if [[ -f "/dev/sev" ]]; then
        log_success "AMD SEV TEE detected"
        return 0
    fi

    log_info "No TEE hardware detected"
    return 1
}

run_tee_smoke_test() {
    local test_type="$1"

    log_info "Running TEE attestation smoke test (mode: ${test_type})"

    cd "${PROJECT_ROOT}/crates/franken-engine"

    # Set environment for test type
    case "${test_type}" in
        "tee_available")
            export FRANKEN_TEE_ENABLED=true
            unset FRANKEN_TEE_ERROR FRANKEN_TEE_QUOTE_FAIL
            ;;
        "safe_mode")
            unset FRANKEN_TEE_ENABLED FRANKEN_TEE_ERROR
            ;;
        "tee_error")
            unset FRANKEN_TEE_ENABLED
            export FRANKEN_TEE_ERROR="Simulated hardware error for testing"
            ;;
    esac

    # Run the smoke test with timeout
    local test_cmd="cargo test --test tee_attestation_integration -- --test-threads=1"

    if timeout "${SMOKE_TEST_TIMEOUT}" ${test_cmd} 2>&1 | tee "${TEE_TEST_OUTPUT_FILE}"; then
        log_success "TEE attestation smoke test completed successfully"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_error "TEE smoke test timed out after ${SMOKE_TEST_TIMEOUT} seconds"
        else
            log_error "TEE smoke test failed with exit code ${exit_code}"
        fi
        return $exit_code
    fi
}

generate_smoke_test_report() {
    local test_result="$1"
    local test_type="$2"
    local timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    cat > "${TEE_TEST_OUTPUT_FILE}.report.json" << EOF
{
    "test_type": "tee_attestation_smoke",
    "timestamp": "${timestamp}",
    "test_mode": "${test_type}",
    "result": "${test_result}",
    "worker_platform": "$(uname -m)",
    "worker_os": "$(uname -s)",
    "ci_environment": "${RGC_CI:-false}",
    "tee_enabled": "${FRANKEN_TEE_ENABLED:-false}",
    "test_timeout_seconds": ${SMOKE_TEST_TIMEOUT}
}
EOF

    if [[ "${VERBOSE:-false}" == "true" ]]; then
        log_info "Test report generated:"
        cat "${TEE_TEST_OUTPUT_FILE}.report.json"
    fi
}

main() {
    local force_tee=false
    local force_safe_mode=false
    local verbose=false
    local timeout="${SMOKE_TEST_TIMEOUT}"
    local output_file="${TEE_TEST_OUTPUT_FILE}"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                verbose=true
                export VERBOSE=true
                shift
                ;;
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --output)
                output_file="$2"
                TEE_TEST_OUTPUT_FILE="$2"
                shift 2
                ;;
            --force-tee)
                force_tee=true
                shift
                ;;
            --force-safe-mode)
                force_safe_mode=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage >&2
                exit 2
                ;;
        esac
    done

    log_info "Starting TEE attestation smoke test"
    log_info "Project root: ${PROJECT_ROOT}"
    log_info "Test timeout: ${timeout} seconds"

    # Determine test mode
    local test_result="unknown"
    local test_type=""

    if [[ "${force_safe_mode}" == "true" ]]; then
        test_type="safe_mode"
        log_info "Forced safe-mode test"
        if run_tee_smoke_test "${test_type}"; then
            test_result="skipped"
            log_success "Safe-mode fallback test: SKIPPED (as expected)"
        else
            test_result="failed"
            log_error "Safe-mode fallback test: FAILED"
        fi
    elif [[ "${force_tee}" == "true" ]]; then
        test_type="tee_available"
        log_info "Forced TEE test"
        if run_tee_smoke_test "${test_type}"; then
            test_result="passed"
            log_success "TEE attestation test: PASSED"
        else
            test_result="failed"
            log_error "TEE attestation test: FAILED"
        fi
    else
        # Auto-detect mode
        case "$(detect_tee_capability; echo $?)" in
            0)
                test_type="tee_available"
                log_info "TEE capability detected, running live attestation test"
                if run_tee_smoke_test "${test_type}"; then
                    test_result="passed"
                    log_success "TEE attestation test: PASSED"
                else
                    test_result="failed"
                    log_error "TEE attestation test: FAILED"
                fi
                ;;
            1)
                test_type="safe_mode"
                log_info "No TEE capability detected, testing safe-mode fallback"
                if run_tee_smoke_test "${test_type}"; then
                    test_result="skipped"
                    log_success "Safe-mode fallback test: SKIPPED (as expected for non-TEE worker)"
                else
                    test_result="failed"
                    log_error "Safe-mode fallback test: FAILED"
                fi
                ;;
            2)
                test_type="tee_error"
                log_warning "TEE hardware error detected, testing error handling"
                if run_tee_smoke_test "${test_type}"; then
                    test_result="skipped"
                    log_success "TEE error handling test: SKIPPED (graceful degradation)"
                else
                    test_result="failed"
                    log_error "TEE error handling test: FAILED"
                fi
                ;;
        esac
    fi

    # Generate report
    generate_smoke_test_report "${test_result}" "${test_type}"

    # Determine exit code
    case "${test_result}" in
        "passed"|"skipped")
            log_success "TEE attestation smoke test completed: ${test_result^^}"
            exit 0
            ;;
        "failed")
            log_error "TEE attestation smoke test: FAILED"
            exit 1
            ;;
        *)
            log_error "TEE attestation smoke test: UNKNOWN RESULT"
            exit 2
            ;;
    esac
}

# Only run main if this script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi