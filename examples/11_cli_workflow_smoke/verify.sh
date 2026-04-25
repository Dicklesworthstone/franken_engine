#!/bin/bash
set -euo pipefail

echo "FrankenEngine CLI Workflow Artifact Verification"
echo "==============================================="

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
echo "🔍 Verifying artifacts in: $artifact_path"
echo ""

# Required files checklist
required_files=(
    "run_manifest.json"
    "events.jsonl"
    "trace_ids.json"
    "commands.txt"
    "support_bundle/index.json"
    "support_bundle/preflight_report.json"
    "support_bundle/onboarding_scorecard.json"
    "support_bundle/rollout_decision_artifact.json"
    "support_bundle/frankenctl_doctor_report.json"
    "step_logs/step_000.log"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [[ -f "$artifact_path/$file" ]]; then
        echo "✅ $file"
    else
        echo "❌ $file (MISSING)"
        missing_files+=("$file")
    fi
done

echo ""
echo "📊 Artifact Summary:"
echo "  Total files checked: ${#required_files[@]}"
echo "  Files present: $((${#required_files[@]} - ${#missing_files[@]}))"
echo "  Missing files: ${#missing_files[@]}"

if [[ ${#missing_files[@]} -gt 0 ]]; then
    echo ""
    echo "❌ VERIFICATION FAILED"
    echo "Missing required files:"
    for file in "${missing_files[@]}"; do
        echo "  - $file"
    done
    exit 1
fi

echo ""
echo "📋 Directory listing:"
find "$artifact_path" -type f | sort

echo ""
echo "✅ VERIFICATION PASSED"
echo "All required artifact files are present."

# Show some sample content
echo ""
echo "📄 Sample run_manifest.json (first 10 lines):"
head -10 "$artifact_path/run_manifest.json" || true

echo ""
echo "📄 Sample trace_ids.json:"
cat "$artifact_path/trace_ids.json" 2>/dev/null || echo "(not readable)"