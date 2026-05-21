#!/usr/bin/env bash
set -euo pipefail

# Production Feature Catalog Bundle F.2 Validator
# Validates the signed IFC declassification receipts bundle structure
# and ensures compliance with F.1 specification

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUNDLE_ROOT="$PROJECT_ROOT/artifacts/production_feature_catalog/signed_ifc_declassification"
LATEST_BUNDLE=""

log() {
    echo "[F.2-bundle-validator] $1" >&2
}

error() {
    echo "[F.2-bundle-validator] ERROR: $1" >&2
    exit 1
}

validate_bundle_structure() {
    local bundle_dir="$1"

    log "Validating bundle structure: $bundle_dir"

    # Check required files exist
    [[ -f "$bundle_dir/feature_catalog_manifest.json" ]] || error "Missing feature_catalog_manifest.json"
    [[ -f "$bundle_dir/ifc_verification_input.json" ]] || error "Missing ifc_verification_input.json"
    [[ -f "$bundle_dir/bundle_summary.md" ]] || error "Missing bundle_summary.md"

    log "✓ Bundle structure validation passed"
}

validate_manifest_schema() {
    local bundle_dir="$1"
    local manifest="$bundle_dir/feature_catalog_manifest.json"

    log "Validating manifest schema"

    # Check required JSON fields exist (basic validation)
    python3 -c "
import json
import sys
try:
    with open('$manifest', 'r') as f:
        data = json.load(f)

    required_fields = [
        'schema_version', 'feature_id', 'source_claim', 'bundle_bead_id',
        'evidence_bundle_references', 'operator_description', 'verification_commands'
    ]

    for field in required_fields:
        if field not in data:
            print(f'Missing required field: {field}')
            sys.exit(1)

    # Check feature_id matches expected
    if data['feature_id'] != 'signed_ifc_declassification_receipts':
        print(f'Invalid feature_id: {data[\"feature_id\"]}')
        sys.exit(1)

    # Check source_claim matches FE-CLAIM-015
    if data['source_claim'] != 'FE-CLAIM-015':
        print(f'Invalid source_claim: {data[\"source_claim\"]}')
        sys.exit(1)

    print('Manifest validation passed')
except Exception as e:
    print(f'Manifest validation failed: {e}')
    sys.exit(1)
"

    log "✓ Manifest schema validation passed"
}

validate_source_evidence() {
    local fe_claim_path="$PROJECT_ROOT/artifacts/reproducibility_bundles/FE-CLAIM-015"

    log "Validating source evidence exists"

    [[ -d "$fe_claim_path" ]] || error "Source FE-CLAIM-015 evidence missing: $fe_claim_path"
    [[ -f "$fe_claim_path/manifest.json" ]] || error "Source manifest missing: $fe_claim_path/manifest.json"
    [[ -f "$fe_claim_path/env.json" ]] || error "Source env missing: $fe_claim_path/env.json"
    [[ -f "$fe_claim_path/repro.lock" ]] || error "Source repro.lock missing: $fe_claim_path/repro.lock"

    log "✓ Source evidence validation passed"
}

validate_verification_commands() {
    local smoke_test="$PROJECT_ROOT/scripts/e2e/live_ifc_declassification_smoke.sh"

    log "Validating verification assets"

    [[ -x "$smoke_test" ]] || error "Smoke test not executable: $smoke_test"

    log "✓ Verification commands validation passed"
}

find_latest_bundle() {
    if [[ ! -d "$BUNDLE_ROOT" ]]; then
        error "Bundle root directory not found: $BUNDLE_ROOT"
    fi

    # Find the latest timestamped bundle directory
    LATEST_BUNDLE=$(find "$BUNDLE_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)

    if [[ -z "$LATEST_BUNDLE" ]]; then
        error "No bundle directories found in $BUNDLE_ROOT"
    fi

    log "Found latest bundle: $LATEST_BUNDLE"
}

main() {
    log "Starting F.2 bundle validation"
    log "Bundle root: $BUNDLE_ROOT"

    find_latest_bundle
    validate_bundle_structure "$LATEST_BUNDLE"
    validate_manifest_schema "$LATEST_BUNDLE"
    validate_source_evidence
    validate_verification_commands

    log "✅ F.2 bundle validation PASSED"
    log "Bundle ready for production feature catalog inclusion"

    echo "F.2 bundle validated successfully: $LATEST_BUNDLE"
}

main "$@"