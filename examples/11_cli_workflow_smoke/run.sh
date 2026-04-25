#!/bin/bash
set -euo pipefail

echo "FrankenEngine CLI Workflow Smoke Test"
echo "====================================="

# Ensure we're in the project root
cd "$(dirname "$0")/../.."

echo "Starting full CLI workflow..."
if [[ ! -f scripts/e2e/frankenctl_cli_workflow.sh ]]; then
    echo "❌ ERROR: scripts/e2e/frankenctl_cli_workflow.sh not found"
    echo "This script requires the E2E workflow script to be present."
    exit 1
fi

# Run the full workflow in CI mode
echo "Executing: bash scripts/e2e/frankenctl_cli_workflow.sh ci"
bash scripts/e2e/frankenctl_cli_workflow.sh ci

# Find the most recent artifact directory
artifact_base="artifacts/frankenctl_cli_workflow"
if [[ ! -d "$artifact_base" ]]; then
    echo "❌ ERROR: No artifacts directory found at $artifact_base"
    exit 1
fi

latest_dir=$(ls -1t "$artifact_base" | head -1)
if [[ -z "$latest_dir" ]]; then
    echo "❌ ERROR: No artifact runs found in $artifact_base"
    exit 1
fi

artifact_path="$artifact_base/$latest_dir"
echo "✅ Workflow completed successfully"
echo "📁 Artifacts saved to: $artifact_path"

# Save the artifact path for verification
echo "$artifact_path" > examples/11_cli_workflow_smoke/last_run_artifact_path.txt

echo ""
echo "Run './verify.sh' to validate the generated artifacts."