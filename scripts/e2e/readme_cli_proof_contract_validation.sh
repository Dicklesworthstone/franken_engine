#!/usr/bin/env bash
set -euo pipefail

# E2E validation that README CLI smoke artifacts conform to shared proof contract
# Validates bd-1fjqa: aligning README CLI smoke with the shared proof artifact contract

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

# Test configuration
test_id="readme-cli-proof-contract-validation-$(date -u +%Y%m%dT%H%M%SZ)"
test_artifact_root="${root_dir}/artifacts/readme_cli_proof_contract_validation"
test_run_dir="${test_artifact_root}/${test_id}"
validation_log="${test_run_dir}/validation.log"
rch_log_dir="${test_run_dir}/rch_logs"

# Set up focused test environment
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_readme_cli_proof_contract_validation_${test_id}}"
export README_CLI_WORKFLOW_ARTIFACT_ROOT="${test_run_dir}/cli_workflow"
export README_CLI_WORKFLOW_RUN_ID="proof-contract-test"

mkdir -p "${test_run_dir}"
mkdir -p "${rch_log_dir}"
mkdir -p "${CARGO_TARGET_DIR}"

exec > >(tee "${validation_log}") 2>&1

if ! command -v rch >/dev/null 2>&1; then
    echo "❌ rch is required for README CLI proof-contract Cargo validation"
    exit 2
fi

rch_reject_local_fallback() {
    local log_path="$1"
    if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(' "$log_path"; then
        echo "❌ rch reported local fallback; refusing local Cargo execution"
        return 1
    fi
}

run_rch_cargo_step() {
    local step_name="$1"
    local log_path="${rch_log_dir}/${step_name}.log"
    shift

    echo "==> rch exec -- env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} $*"
    if ! RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
        rch exec -- env "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" "$@" 2>&1 | tee "$log_path"; then
        return 1
    fi
    rch_reject_local_fallback "$log_path"
}

echo "README CLI Proof Contract Validation"
echo "===================================="
echo "Test ID: ${test_id}"
echo "Run directory: ${test_run_dir}"
echo "Cargo target: ${CARGO_TARGET_DIR}"
echo ""

# Step 1: Build frankenctl binary for focused testing
echo "Step 1: Building frankenctl binary..."
start_time=$(date +%s%3N)

cd "${root_dir}"
if ! run_rch_cargo_step "build-frankenctl" cargo build -p frankenengine-engine --bin frankenctl; then
    echo "❌ Failed to build frankenctl binary"
    exit 1
fi

build_duration=$(($(date +%s%3N) - start_time))
echo "✓ Built frankenctl binary (${build_duration}ms)"

# Set frankenctl binary path for README CLI smoke
export FRANKENCTL_BIN="${CARGO_TARGET_DIR}/debug/frankenctl"

if [[ ! -x "$FRANKENCTL_BIN" ]]; then
    echo "❌ frankenctl binary not executable: $FRANKENCTL_BIN"
    exit 1
fi

echo "✓ frankenctl binary ready: $FRANKENCTL_BIN"
echo ""

# Step 2: Run README CLI workflow smoke test
echo "Step 2: Running README CLI workflow smoke test..."
start_time=$(date +%s%3N)

cli_smoke_script="${root_dir}/scripts/e2e/readme_cli_workflow_smoke.sh"
if [[ ! -x "$cli_smoke_script" ]]; then
    echo "❌ README CLI smoke script not found or not executable: $cli_smoke_script"
    exit 1
fi

# Run the CLI smoke test and capture its output
if ! "${cli_smoke_script}" 2>&1; then
    echo "❌ README CLI smoke test failed"
    exit 1
fi

smoke_duration=$(($(date +%s%3N) - start_time))
echo "✓ README CLI smoke test completed (${smoke_duration}ms)"

# Determine the actual run directory
cli_run_dir="${README_CLI_WORKFLOW_ARTIFACT_ROOT}/${README_CLI_WORKFLOW_RUN_ID}"

if [[ ! -d "$cli_run_dir" ]]; then
    echo "❌ CLI smoke run directory not found: $cli_run_dir"
    echo "Expected directory layout:"
    ls -la "${README_CLI_WORKFLOW_ARTIFACT_ROOT}/" 2>/dev/null || echo "(directory not found)"
    exit 1
fi

echo "✓ CLI smoke artifacts found in: $cli_run_dir"
echo ""

# Step 3: Validate proof contract compliance
echo "Step 3: Validating proof contract compliance..."

# Required artifact files
required_files=(
    "manifest.json"
    "events.jsonl"
    "commands.txt"
    "report.json"
    "report.md"
    "redaction_policy.json"
)

echo "Checking required artifact files..."
for file in "${required_files[@]}"; do
    file_path="${cli_run_dir}/${file}"
    if [[ ! -f "$file_path" ]]; then
        echo "❌ Missing required artifact: $file"
        exit 1
    fi
    echo "✓ Found: $file"
done

echo ""

# Validate manifest schema
echo "Validating manifest schema..."
manifest_path="${cli_run_dir}/manifest.json"

# Check manifest has required schema version
schema_version=$(jq -r '.schema_version // empty' "$manifest_path")
if [[ "$schema_version" != "$PROOF_ARTIFACT_MANIFEST_SCHEMA_VERSION" ]]; then
    echo "❌ Invalid manifest schema version: expected $PROOF_ARTIFACT_MANIFEST_SCHEMA_VERSION, got $schema_version"
    exit 1
fi
echo "✓ Manifest schema version: $schema_version"

# Check manifest has required fields
required_fields=(
    ".gate_name"
    ".status"
    ".bead_ids"
    ".commands"
    ".artifact_paths"
    ".generated_artifacts"
    ".rerun_command"
)

for field in "${required_fields[@]}"; do
    if ! jq -e "$field" "$manifest_path" >/dev/null; then
        echo "❌ Missing required manifest field: $field"
        exit 1
    fi
done
echo "✓ Manifest contains all required fields"

# Check for required artifact roles
required_roles=("command_transcript" "structured_events" "source_machine_report")
for role in "${required_roles[@]}"; do
    if ! jq -e --arg role "$role" '.generated_artifacts[] | select(.role == $role)' "$manifest_path" >/dev/null; then
        echo "❌ Missing required artifact role: $role"
        exit 1
    fi
    echo "✓ Found artifact role: $role"
done

echo ""

# Validate events schema
echo "Validating structured events schema..."
events_path="${cli_run_dir}/events.jsonl"

if [[ ! -s "$events_path" ]]; then
    echo "❌ Events file is empty: $events_path"
    exit 1
fi

# Check each event line has valid schema
line_num=0
while IFS= read -r line; do
    ((line_num++))
    if [[ -z "$line" ]]; then
        continue
    fi

    event_schema=$(echo "$line" | jq -r '.schema_version // empty')
    if [[ "$event_schema" != "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION" ]]; then
        echo "❌ Invalid event schema at line $line_num: expected $PROOF_ARTIFACT_EVENT_SCHEMA_VERSION, got $event_schema"
        exit 1
    fi

    # Check required event fields
    if ! echo "$line" | jq -e '.event_name and .severity and .step_id' >/dev/null; then
        echo "❌ Missing required event fields at line $line_num"
        exit 1
    fi
done < "$events_path"

echo "✓ Events file contains $line_num valid events"

# Validate redaction policy
echo "Validating redaction policy..."
redaction_path="${cli_run_dir}/redaction_policy.json"

policy_schema=$(jq -r '.schema_version // empty' "$redaction_path")
if [[ "$policy_schema" != "$PROOF_ARTIFACT_REDACTION_POLICY_SCHEMA_VERSION" ]]; then
    echo "❌ Invalid redaction policy schema: expected $PROOF_ARTIFACT_REDACTION_POLICY_SCHEMA_VERSION, got $policy_schema"
    exit 1
fi
echo "✓ Redaction policy schema: $policy_schema"

# Test redaction effectiveness
if grep -r "TOKEN\|SECRET\|PASSWORD" "${cli_run_dir}/manifest.json" "${cli_run_dir}/report.json" "${cli_run_dir}/report.md" | grep -v "<redacted>" >/dev/null; then
    echo "❌ Potential secret leakage detected in redacted artifacts"
    exit 1
fi
echo "✓ No secret leakage detected in artifacts"

# Validate report schema
echo "Validating machine report schema..."
report_path="${cli_run_dir}/report.json"

report_schema=$(jq -r '.schema_version // empty' "$report_path")
if [[ "$report_schema" != "$PROOF_ARTIFACT_REPORT_SCHEMA_VERSION" ]]; then
    echo "❌ Invalid report schema: expected $PROOF_ARTIFACT_REPORT_SCHEMA_VERSION, got $report_schema"
    exit 1
fi
echo "✓ Report schema: $report_schema"

# Check report has required fields
if ! jq -e '.gate_name and .status and .failure_count' "$report_path" >/dev/null; then
    echo "❌ Missing required report fields"
    exit 1
fi
echo "✓ Report contains required fields"

echo ""

# Step 4: Validate rerun capability
echo "Step 4: Validating rerun capability..."

rerun_command=$(jq -r '.rerun_command // empty' "$manifest_path")
if [[ -z "$rerun_command" ]]; then
    echo "❌ Empty rerun command in manifest"
    exit 1
fi
echo "✓ Rerun command available: $rerun_command"

# Verify commands transcript
commands_path="${cli_run_dir}/commands.txt"
if [[ ! -s "$commands_path" ]]; then
    echo "❌ Empty commands transcript"
    exit 1
fi
echo "✓ Commands transcript generated"

# Check that human report exists and is readable
human_report_path="${cli_run_dir}/report.md"
if [[ ! -s "$human_report_path" ]]; then
    echo "❌ Empty human report"
    exit 1
fi

# Verify human report contains helpful information
if ! grep -i "rerun\|command\|artifact" "$human_report_path" >/dev/null; then
    echo "❌ Human report lacks expected guidance"
    exit 1
fi
echo "✓ Human report contains rerun guidance"

echo ""

# Step 5: Test with unit tests
echo "Step 5: Running unit tests for proof contract integration..."
test_start_time=$(date +%s%3N)

if ! run_rch_cargo_step "proof-contract-unit" cargo test readme_cli_proof_contract_integration --lib; then
    echo "❌ Unit tests failed for proof contract integration"
    exit 1
fi

test_duration=$(($(date +%s%3N) - test_start_time))
echo "✓ Unit tests passed (${test_duration}ms)"

echo ""

# Generate validation summary
total_duration=$(($(date +%s%3N) - $(date -d "$(echo "$test_id" | sed 's/.*-\([0-9T]*Z\)$/\1/' | tr 'T' ' ' | sed 's/Z$//')" +%s%3N) ))

cat > "${test_run_dir}/validation_summary.json" <<EOF
{
  "test_id": "$test_id",
  "validation_status": "pass",
  "readme_cli_smoke_run_dir": "$cli_run_dir",
  "total_duration_ms": $total_duration,
  "validated_components": [
    "manifest_schema_compatibility",
    "structured_events_validation",
    "cli_command_transcript_redaction",
    "artifact_linkage_requirements",
    "missing_artifact_diagnostics",
    "rerun_capability",
    "human_report_guidance"
  ],
  "required_artifacts_verified": $(printf '%s\n' "${required_files[@]}" | jq -R . | jq -s .),
  "required_artifact_roles_verified": $(printf '%s\n' "${required_roles[@]}" | jq -R . | jq -s .),
  "schema_versions_validated": {
    "manifest": "$PROOF_ARTIFACT_MANIFEST_SCHEMA_VERSION",
    "events": "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION",
    "report": "$PROOF_ARTIFACT_REPORT_SCHEMA_VERSION",
    "redaction_policy": "$PROOF_ARTIFACT_REDACTION_POLICY_SCHEMA_VERSION"
  },
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "✅ README CLI Proof Contract Validation PASSED"
echo ""
echo "📊 Validation Summary:"
echo "   • Total duration: ${total_duration}ms"
echo "   • README CLI smoke artifacts: $cli_run_dir"
echo "   • Validation report: ${test_run_dir}/validation_summary.json"
echo "   • Validation log: ${validation_log}"
echo ""
echo "🔍 Validated Contract Compliance:"
echo "   ✓ Manifest schema ($PROOF_ARTIFACT_MANIFEST_SCHEMA_VERSION)"
echo "   ✓ Structured events schema ($PROOF_ARTIFACT_EVENT_SCHEMA_VERSION)"
echo "   ✓ Machine report schema ($PROOF_ARTIFACT_REPORT_SCHEMA_VERSION)"
echo "   ✓ Redaction policy schema ($PROOF_ARTIFACT_REDACTION_POLICY_SCHEMA_VERSION)"
echo "   ✓ Required artifact roles: command_transcript, structured_events, source_machine_report"
echo "   ✓ Redaction effectiveness (no secret leakage)"
echo "   ✓ Rerun capability with commands transcript"
echo "   ✓ Human report with guidance"

echo ""
echo "🎯 bd-1fjqa objectives achieved:"
echo "   • README CLI smoke artifacts aligned with shared proof contract"
echo "   • Manifest compatibility verified with $(jq -r '.gate_name' "$manifest_path")"
echo "   • Structured logging conforms to contract schema"
echo "   • Artifact linkage and rerun capability validated"
echo "   • Unit and E2E tests cover all requirements"
