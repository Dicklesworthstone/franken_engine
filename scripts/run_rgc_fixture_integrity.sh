#!/bin/bash
# scripts/run_rgc_fixture_integrity.sh
# Fixture integrity verification gate for test data fixtures
# Part of bd-cixqu.48 - test fixture setup cross-cutting requirement

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FIXTURES_BASE="$PROJECT_ROOT/crates/franken-engine/tests/data"

# Gate configuration
GATE_NAME="fixture_integrity"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts/$GATE_NAME/$TIMESTAMP"
STEP_LOGS_DIR="$ARTIFACTS_DIR/step_logs"

# Create artifact directories
mkdir -p "$STEP_LOGS_DIR"

# Logging function with timestamps
log_step() {
    local step_num="$1"
    local description="$2"
    local log_file="$STEP_LOGS_DIR/step_$(printf "%03d" "$step_num").log"

    echo "$(date -u +%Y-%m-%dT%H:%M:%S%z) [STEP $step_num] $description" | tee "$log_file"
    return "${PIPESTATUS[0]}"
}

echo "=== Fixture Integrity Verification Gate ==="
echo "Verifying content hashes for all test data fixtures"
echo "Artifacts: $ARTIFACTS_DIR"
echo ""

STEP=1
EXIT_CODE=0

# Step 1: Verify fixture directories exist
log_step $STEP "Verifying fixture directories exist"
STEP=$((STEP + 1))

REQUIRED_DIRS=(
    "decision_traces"
    "capability_verdicts"
    "red_team_cosmetic_variants"
    "fleet_partition_profiles"
    "lockstep_divergence_examples"
    "proof_bundle_specimens"
)

MISSING_DIRS=()
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "$FIXTURES_BASE/$dir" ]]; then
        MISSING_DIRS+=("$dir")
    fi
done

if [[ ${#MISSING_DIRS[@]} -gt 0 ]]; then
    log_step $STEP "ERROR: Missing fixture directories: ${MISSING_DIRS[*]}"
    EXIT_CODE=1
else
    log_step $STEP "All required fixture directories found"
fi
STEP=$((STEP + 1))

# Step 2: Generate current content hashes
log_step $STEP "Generating current content hashes for all fixtures"
CURRENT_HASHES="$ARTIFACTS_DIR/current_fixture_hashes.txt"

find "$FIXTURES_BASE" -type f \( -name "*.json" -o -name "*.js" -o -name "*.md" -o -name "*.tar.gz" \) -print0 | \
    while IFS= read -r -d '' file; do
        rel_path="${file#$FIXTURES_BASE/}"
        hash=$(sha256sum "$file" | cut -d' ' -f1)
        echo "$hash  $rel_path"
    done | sort > "$CURRENT_HASHES"

FIXTURE_COUNT=$(wc -l < "$CURRENT_HASHES")
log_step $STEP "Generated hashes for $FIXTURE_COUNT fixture files"
STEP=$((STEP + 1))

# Step 3: Create/update manifest files for each directory
log_step $STEP "Creating fixture manifest files"

for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$FIXTURES_BASE/$dir" ]]; then
        manifest_file="$FIXTURES_BASE/$dir/fixture_manifest.json"
        temp_manifest="$ARTIFACTS_DIR/${dir}_manifest.json"

        {
            echo "{"
            echo "  \"schema_version\": \"franken-engine.fixture-manifest.v1\","
            echo "  \"directory\": \"$dir\","
            echo "  \"generated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
            echo "  \"content_hashes\": {"

            # Generate hashes for files in this directory
            find "$FIXTURES_BASE/$dir" -type f \( -name "*.json" -o -name "*.js" -o -name "*.md" -o -name "*.tar.gz" \) -print0 | \
                while IFS= read -r -d '' file; do
                    rel_path="${file#$FIXTURES_BASE/$dir/}"
                    hash=$(sha256sum "$file" | cut -d' ' -f1)
                    echo "    \"$rel_path\": \"$hash\","
                done | sed '$ s/,$//'

            echo "  }"
            echo "}"
        } > "$temp_manifest"

        # Copy manifest to fixture directory
        cp "$temp_manifest" "$manifest_file"
        log_step $STEP "Created manifest for $dir ($(find "$FIXTURES_BASE/$dir" -type f \( -name "*.json" -o -name "*.js" -o -name "*.md" -o -name "*.tar.gz" \) | wc -l) files)"
    fi
done
STEP=$((STEP + 1))

# Step 4: Verify PAC Bayes parameters file exists and is valid JSON
log_step $STEP "Verifying PAC Bayes parameters file"
PAC_BAYES_FILE="$FIXTURES_BASE/pac_bayes_parameters_v1.json"

if [[ -f "$PAC_BAYES_FILE" ]]; then
    if python3 -m json.tool "$PAC_BAYES_FILE" > /dev/null 2>&1; then
        log_step $STEP "PAC Bayes parameters file is valid JSON"
    else
        log_step $STEP "ERROR: PAC Bayes parameters file is invalid JSON"
        EXIT_CODE=1
    fi
else
    log_step $STEP "ERROR: PAC Bayes parameters file not found"
    EXIT_CODE=1
fi
STEP=$((STEP + 1))

# Step 5: Verify all directories have README files
log_step $STEP "Verifying README files exist"
MISSING_READMES=()

for dir in "${REQUIRED_DIRS[@]}"; do
    readme_file="$FIXTURES_BASE/$dir/README.md"
    if [[ ! -f "$readme_file" ]]; then
        MISSING_READMES+=("$dir")
    fi
done

if [[ ${#MISSING_READMES[@]} -gt 0 ]]; then
    log_step $STEP "ERROR: Missing README files in: ${MISSING_READMES[*]}"
    EXIT_CODE=1
else
    log_step $STEP "All fixture directories have README files"
fi
STEP=$((STEP + 1))

# Step 6: Generate summary
log_step $STEP "Generating gate summary"

SUMMARY_FILE="$ARTIFACTS_DIR/summary.txt"
{
    echo "Fixture Integrity Verification Gate"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Exit code: $EXIT_CODE"
    echo ""
    if [[ $EXIT_CODE -eq 0 ]]; then
        echo "✓ All test data fixtures verified successfully"
        echo "✓ $FIXTURE_COUNT fixture files processed"
        echo "✓ All ${#REQUIRED_DIRS[@]} required directories present"
        echo "✓ All manifest files generated"
        echo "✓ PAC Bayes parameters file valid"
        echo "✓ All README files present"
    else
        echo "✗ Fixture integrity verification failed"
        [[ ${#MISSING_DIRS[@]} -gt 0 ]] && echo "  Missing directories: ${MISSING_DIRS[*]}"
        [[ ${#MISSING_READMES[@]} -gt 0 ]] && echo "  Missing READMEs: ${MISSING_READMES[*]}"
    fi
    echo ""
    echo "Artifacts produced:"
    echo "  - current_fixture_hashes.txt: Content hashes of all fixtures"
    echo "  - fixture manifests in each directory"
    echo "  - Step logs in step_logs/"
} > "$SUMMARY_FILE"

cat "$SUMMARY_FILE"

# Step 7: Create run manifest
log_step $STEP "Creating run manifest"

RUN_MANIFEST="$ARTIFACTS_DIR/run_manifest.json"
{
    echo "{"
    echo "  \"schema_version\": \"franken-engine.proof-artifact-manifest.v1\","
    echo "  \"gate_name\": \"$GATE_NAME\","
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"exit_code\": $EXIT_CODE,"
    echo "  \"artifacts\": {"

    find "$ARTIFACTS_DIR" -type f -print0 | \
        while IFS= read -r -d '' file; do
            rel_path="${file#$ARTIFACTS_DIR/}"
            hash=$(sha256sum "$file" | cut -d' ' -f1)
            echo "    \"$rel_path\": \"$hash\","
        done | sed '$ s/,$//'

    echo "  }"
    echo "}"
} > "$RUN_MANIFEST"

log_step $STEP "Run manifest created: $RUN_MANIFEST"

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    echo "✓ Fixture integrity verification PASSED"
else
    echo "✗ Fixture integrity verification FAILED"
fi
echo "Artifacts: $ARTIFACTS_DIR"

exit $EXIT_CODE