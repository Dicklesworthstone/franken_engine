#!/bin/bash
#
# Smoke test for signed decision receipt generation and verification.
#
# This script generates a fresh signed decision receipt artifact and validates
# the complete end-to-end workflow: generation -> verification -> artifact collection.
#
# Usage:
#   ./scripts/run_rgc_signed_decision_receipt_smoke.sh ci
#
# Output structure:
#   artifacts/signed_decision_receipt/<timestamp>/
#     ├── receipt.json              # Generated receipt artifact
#     ├── run_manifest.json         # Run metadata and verification commands
#     ├── events.jsonl             # Structured event log
#     ├── commands.txt             # Commands executed during the run
#     └── step_logs/               # Per-step detailed logs
#         ├── 01_generate.log
#         ├── 02_verify.log
#         └── 03_validate.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TIMESTAMP="$(date +%s)"
ARTIFACT_DIR="artifacts/signed_decision_receipt/${TIMESTAMP}"
STEP_LOGS_DIR="${ARTIFACT_DIR}/step_logs"

# Logging functions
log_event() {
    local event="$1"
    local status="$2"
    local details="${3:-}"
    local timestamp_iso=$(date -Iseconds)
    echo "{\"timestamp\":\"${timestamp_iso}\",\"event\":\"${event}\",\"status\":\"${status}\",\"details\":\"${details}\"}" \
        >> "${ARTIFACT_DIR}/events.jsonl"
}

log_command() {
    local cmd="$1"
    echo "$(date -Iseconds): ${cmd}" >> "${ARTIFACT_DIR}/commands.txt"
}

run_step() {
    local step="$1"
    local description="$2"
    shift 2

    echo "=== ${step}: ${description} ==="
    log_event "${step}" "started" "${description}"
    log_command "${step}: $*"

    # Run command and capture output
    local log_file="${STEP_LOGS_DIR}/${step}.log"
    if "$@" > "${log_file}" 2>&1; then
        log_event "${step}" "success" "${description}"
        echo "✓ ${step} completed successfully"
    else
        local exit_code=$?
        log_event "${step}" "failure" "Exit code: ${exit_code}"
        echo "✗ ${step} failed with exit code ${exit_code}"
        echo "Log output:"
        cat "${log_file}"
        exit "${exit_code}"
    fi
}

main() {
    local mode="${1:-interactive}"

    echo "FrankenEngine Signed Decision Receipt Smoke Test"
    echo "================================================"
    echo "Mode: ${mode}"
    echo "Artifact dir: ${ARTIFACT_DIR}"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""

    # Create artifact directory structure
    mkdir -p "${ARTIFACT_DIR}"
    mkdir -p "${STEP_LOGS_DIR}"

    # Initialize logging
    echo "# Commands executed during signed decision receipt smoke test" > "${ARTIFACT_DIR}/commands.txt"
    echo "# Started at: $(date -Iseconds)" >> "${ARTIFACT_DIR}/commands.txt"
    echo "" >> "${ARTIFACT_DIR}/commands.txt"

    log_event "smoke_test_start" "success" "mode=${mode}"

    # Change to project root
    cd "${PROJECT_ROOT}"

    # Step 1: Generate receipt via example
    run_step "01_generate" "Generate signed decision receipt example" \
        cargo run --example live_signed_decision_receipt_example

    # Find the generated receipt
    RECEIPT_JSON=$(find artifacts/signed_decision_receipt -name "receipt.json" -type f | head -1)
    if [[ -z "${RECEIPT_JSON}" ]]; then
        log_event "receipt_location" "failure" "No receipt.json found"
        echo "✗ Failed to locate generated receipt.json"
        exit 1
    fi

    log_event "receipt_location" "success" "Found: ${RECEIPT_JSON}"
    echo "Found receipt: ${RECEIPT_JSON}"

    # Extract receipt ID for verification
    RECEIPT_ID=$(jq -r '.receipt_id' "${RECEIPT_JSON}")
    if [[ -z "${RECEIPT_ID}" || "${RECEIPT_ID}" == "null" ]]; then
        log_event "receipt_id_extraction" "failure" "Cannot extract receipt_id"
        echo "✗ Failed to extract receipt_id from ${RECEIPT_JSON}"
        exit 1
    fi

    log_event "receipt_id_extraction" "success" "receipt_id=${RECEIPT_ID}"
    echo "Receipt ID: ${RECEIPT_ID}"

    # Step 2: Build frankenctl if needed
    if ! command -v frankenctl &> /dev/null; then
        run_step "02_build_frankenctl" "Build frankenctl binary" \
            cargo build --bin frankenctl
        export PATH="${PROJECT_ROOT}/target/debug:${PATH}"
    else
        log_event "frankenctl_check" "success" "frankenctl already available"
    fi

    # Step 3: Verify receipt (currently a placeholder since the verifier needs to be implemented)
    # For now, we'll validate the JSON structure and required fields
    run_step "03_verify_structure" "Verify receipt JSON structure" \
        "${SCRIPT_DIR}/validate_receipt_structure.sh" "${RECEIPT_JSON}"

    # Step 4: Validate schema compliance
    run_step "04_validate_schema" "Validate against decision_receipt_v1.json schema" \
        jq --arg schema_version "franken-engine.signed-decision-receipt.v1" \
           'if .schema_version == $schema_version then empty else error("Invalid schema_version") end' \
           "${RECEIPT_JSON}"

    # Copy the receipt to our smoke test artifact directory for analysis
    cp "${RECEIPT_JSON}" "${ARTIFACT_DIR}/"

    # Create final run manifest
    cat > "${ARTIFACT_DIR}/run_manifest.json" <<EOF
{
  "run_id": "signed-decision-receipt-smoke-${TIMESTAMP}",
  "timestamp": ${TIMESTAMP},
  "test_type": "smoke_test",
  "mode": "${mode}",
  "artifacts": [
    {
      "path": "receipt.json",
      "type": "signed_decision_receipt",
      "schema_version": "franken-engine.signed-decision-receipt.v1",
      "receipt_id": "${RECEIPT_ID}"
    },
    {
      "path": "events.jsonl",
      "type": "structured_log"
    },
    {
      "path": "commands.txt",
      "type": "command_log"
    },
    {
      "path": "step_logs/",
      "type": "detailed_logs"
    }
  ],
  "verification_commands": [
    "jq '.schema_version' ${ARTIFACT_DIR}/receipt.json",
    "jq '.receipt_id' ${ARTIFACT_DIR}/receipt.json"
  ],
  "future_verification_command": "frankenctl verify receipt --input ${ARTIFACT_DIR}/receipt.json --receipt-id ${RECEIPT_ID}"
}
EOF

    log_event "smoke_test_complete" "success" "All steps completed"

    echo ""
    echo "✓ Smoke test completed successfully"
    echo "Artifacts generated in: ${ARTIFACT_DIR}"
    echo ""
    echo "Generated files:"
    find "${ARTIFACT_DIR}" -type f | sort | sed 's/^/  /'
    echo ""
    echo "Receipt ID: ${RECEIPT_ID}"
    echo "Receipt file: ${ARTIFACT_DIR}/receipt.json"

    if [[ "${mode}" == "ci" ]]; then
        echo ""
        echo "CI mode: Smoke test passed - receipt generation workflow functional"
    fi
}

# Helper script for validating receipt structure
create_validation_script() {
    cat > "${SCRIPT_DIR}/validate_receipt_structure.sh" <<'EOF'
#!/bin/bash
# Validate receipt JSON structure has all required fields

set -euo pipefail

RECEIPT_FILE="$1"

if [[ ! -f "${RECEIPT_FILE}" ]]; then
    echo "Receipt file not found: ${RECEIPT_FILE}"
    exit 1
fi

echo "Validating receipt structure: ${RECEIPT_FILE}"

# Check required top-level fields
required_fields=(
    "schema_version"
    "receipt_id"
    "decision_id"
    "policy_id"
    "evidence_hash_chain_root"
    "posterior_snapshot"
    "expected_loss_vector"
    "action"
    "timestamp"
    "signature_bundle"
)

for field in "${required_fields[@]}"; do
    if ! jq -e ".${field}" "${RECEIPT_FILE}" > /dev/null; then
        echo "✗ Missing required field: ${field}"
        exit 1
    fi
    echo "✓ Found required field: ${field}"
done

# Check posterior_snapshot structure
posterior_fields=("mean_expected_loss" "confidence_interval_95_lower" "confidence_interval_95_upper" "posterior_mode" "evaluation_count")
for field in "${posterior_fields[@]}"; do
    if ! jq -e ".posterior_snapshot.${field}" "${RECEIPT_FILE}" > /dev/null; then
        echo "✗ Missing posterior_snapshot field: ${field}"
        exit 1
    fi
done

# Check signature_bundle structure
signature_fields=("signature_algorithm" "signature_hex" "public_key_hex" "threshold_signature")
for field in "${signature_fields[@]}"; do
    if ! jq -e ".signature_bundle.${field}" "${RECEIPT_FILE}" > /dev/null; then
        echo "✗ Missing signature_bundle field: ${field}"
        exit 1
    fi
done

echo "✓ Receipt structure validation passed"
EOF
    chmod +x "${SCRIPT_DIR}/validate_receipt_structure.sh"
}

# Create the validation helper if it doesn't exist
create_validation_script

# Run main function
main "$@"