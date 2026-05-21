#!/usr/bin/env bash
set -euo pipefail

# Production Feature Catalog Bundle F.3 Validator
# Validates the deterministic replay coverage bundle structure
# and ensures compliance with F.1 specification

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUNDLE_ROOT="$PROJECT_ROOT/artifacts/production_feature_catalog/deterministic_replay"
LATEST_BUNDLE=""

log() {
    echo "[F.3-bundle-validator] $1" >&2
}

error() {
    echo "[F.3-bundle-validator] ERROR: $1" >&2
    exit 1
}

validate_bundle_structure() {
    local bundle_dir="$1"

    log "Validating bundle structure: $bundle_dir"

    # Check required files exist
    [[ -f "$bundle_dir/feature_catalog_manifest.json" ]] || error "Missing feature_catalog_manifest.json"
    [[ -f "$bundle_dir/deterministic_replay_verification_input.json" ]] || error "Missing deterministic_replay_verification_input.json"
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
        'evidence_bundle_references', 'operator_description', 'verification_commands',
        'security_critical_coverage'
    ]

    for field in required_fields:
        if field not in data:
            print(f'Missing required field: {field}')
            sys.exit(1)

    # Check feature_id matches expected
    if data['feature_id'] != 'deterministic_replay_coverage':
        print(f'Invalid feature_id: {data[\"feature_id\"]}')
        sys.exit(1)

    # Check source_claim matches FE-CLAIM-013
    if data['source_claim'] != 'FE-CLAIM-013':
        print(f'Invalid source_claim: {data[\"source_claim\"]}')
        sys.exit(1)

    # Check security coverage requirements
    coverage = data.get('security_critical_coverage', {})
    if coverage.get('coverage_percentage') != 100:
        print(f'Invalid coverage percentage: {coverage.get(\"coverage_percentage\")}')
        sys.exit(1)

    print('Manifest validation passed')
except Exception as e:
    print(f'Manifest validation failed: {e}')
    sys.exit(1)
"

    log "✓ Manifest schema validation passed"
}

validate_source_evidence() {
    local fe_claim_path="$PROJECT_ROOT/artifacts/reproducibility_bundles/FE-CLAIM-013"

    log "Validating source evidence exists"

    [[ -d "$fe_claim_path" ]] || error "Source FE-CLAIM-013 evidence missing: $fe_claim_path"
    [[ -f "$fe_claim_path/manifest.json" ]] || error "Source manifest missing: $fe_claim_path/manifest.json"
    [[ -f "$fe_claim_path/env.json" ]] || error "Source env missing: $fe_claim_path/env.json"
    [[ -f "$fe_claim_path/repro.lock" ]] || error "Source repro.lock missing: $fe_claim_path/repro.lock"

    log "✓ Source evidence validation passed"
}

validate_verification_commands() {
    local metric_gate="$PROJECT_ROOT/scripts/run_replay_coverage_metric_gate.sh"
    local integration_test="$PROJECT_ROOT/crates/franken-engine/tests/deterministic_replay_integration.rs"

    log "Validating verification assets"

    [[ -x "$metric_gate" ]] || error "Metric gate not executable: $metric_gate"
    [[ -f "$integration_test" ]] || error "Integration test missing: $integration_test"

    log "✓ Verification commands validation passed"
}

validate_security_coverage() {
    local bundle_dir="$1"
    local manifest="$bundle_dir/feature_catalog_manifest.json"

    log "Validating security coverage requirements"

    python3 -c "
import json
import sys
try:
    with open('$manifest', 'r') as f:
        data = json.load(f)

    coverage = data.get('security_critical_coverage', {})

    # Check required decision types
    decision_types = coverage.get('decision_types', [])
    required_types = ['allow', 'deny', 'escalation']
    for req_type in required_types:
        if req_type not in decision_types:
            print(f'Missing decision type: {req_type}')
            sys.exit(1)

    # Check coverage percentage is 100
    if coverage.get('coverage_percentage') != 100:
        print(f'Coverage must be 100%, got: {coverage.get(\"coverage_percentage\")}')
        sys.exit(1)

    # Check byte identical replay
    if not coverage.get('byte_identical_replay'):
        print('Byte identical replay must be true')
        sys.exit(1)

    # Check deterministic validation
    if not coverage.get('deterministic_validation'):
        print('Deterministic validation must be true')
        sys.exit(1)

    print('Security coverage validation passed')
except Exception as e:
    print(f'Security coverage validation failed: {e}')
    sys.exit(1)
"

    log "✓ Security coverage validation passed"
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
    log "Starting F.3 bundle validation"
    log "Bundle root: $BUNDLE_ROOT"

    find_latest_bundle
    validate_bundle_structure "$LATEST_BUNDLE"
    validate_manifest_schema "$LATEST_BUNDLE"
    validate_source_evidence
    validate_verification_commands
    validate_security_coverage "$LATEST_BUNDLE"

    log "✅ F.3 bundle validation PASSED"
    log "Deterministic replay coverage bundle ready for production feature catalog inclusion"

    echo "F.3 bundle validated successfully: $LATEST_BUNDLE"
}

main "$@"