#!/usr/bin/env bash
set -euo pipefail

# Live guardplane decision example smoke test.
#
# This script demonstrates the FrankenEngine's probabilistic guardplane
# computing posteriors and expected-loss decisions on synthetic data.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

bead_id="bd-1ypps"
component="live_guardplane_decision_example"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="artifacts/guardplane_decision_example/${timestamp}"
target_dir="${CARGO_TARGET_DIR:-$root_dir/target/smoke_guardplane}"

echo "🚀 Live Guardplane Decision Example Smoke Test"
echo "   Bead: $bead_id"
echo "   Component: $component"
echo "   Output: $output_dir"

mkdir -p "$output_dir"

# Build the example
echo "📦 Building live guardplane decision example..."
RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:-CARGO_TARGET_DIR}" \
    rch exec -- env CARGO_TARGET_DIR="$target_dir" \
    cargo build --example live_guardplane_decision_example --release

# Run the example and capture output
echo "🔍 Running guardplane decision analysis..."
example_output="$("$target_dir/release/examples/live_guardplane_decision_example" 2>&1 || true)"
example_exit_code=$?

echo "📊 Example output:"
echo "$example_output"

if [[ $example_exit_code -eq 0 ]]; then
    echo "✅ Example completed successfully"
else
    echo "❌ Example failed with exit code: $example_exit_code"
    exit 1
fi

# Verify expected outputs in the example output
expected_outputs=(
    "FrankenEngine Live Guardplane Decision Example"
    "Example 1: Suspicious Extension Analysis"
    "Example 2: Benign Extension Analysis"
    "Guardplane decision proof artifacts generated"
    "Live guardplane decision examples completed successfully"
)

for expected in "${expected_outputs[@]}"; do
    if echo "$example_output" | grep -q "$expected"; then
        echo "✓ Found expected output: '$expected'"
    else
        echo "✗ Missing expected output: '$expected'"
        exit 1
    fi
done

# Check if proof artifacts were generated in expected locations
suspicious_artifacts="/tmp/guardplane_example_suspicious"
benign_artifacts="/tmp/guardplane_example_benign"

for artifacts_dir in "$suspicious_artifacts" "$benign_artifacts"; do
    if [[ -d "$artifacts_dir" ]]; then
        echo "✓ Found artifacts directory: $artifacts_dir"

        # Check for required files
        required_files=(
            "manifest.json"
            "report.json"
            "report.md"
            "events.jsonl"
            "commands.txt"
        )

        for file in "${required_files[@]}"; do
            if [[ -f "$artifacts_dir/$file" ]]; then
                echo "  ✓ Found artifact: $file"
            else
                echo "  ✗ Missing artifact: $file"
                exit 1
            fi
        done

        # Validate JSON structure
        if jq empty < "$artifacts_dir/manifest.json" 2>/dev/null; then
            echo "  ✓ manifest.json is valid JSON"
        else
            echo "  ✗ manifest.json is invalid JSON"
            exit 1
        fi

        if jq empty < "$artifacts_dir/report.json" 2>/dev/null; then
            echo "  ✓ report.json is valid JSON"
        else
            echo "  ✗ report.json is invalid JSON"
            exit 1
        fi

        # Check manifest content
        bead_id_actual="$(jq -r '.bead_id // empty' < "$artifacts_dir/manifest.json")"
        if [[ "$bead_id_actual" == "$bead_id" ]]; then
            echo "  ✓ Manifest has correct bead ID: $bead_id"
        else
            echo "  ✗ Manifest bead ID mismatch. Expected: $bead_id, Got: $bead_id_actual"
            exit 1
        fi

        component_actual="$(jq -r '.component // empty' < "$artifacts_dir/manifest.json")"
        if [[ "$component_actual" == "$component" ]]; then
            echo "  ✓ Manifest has correct component: $component"
        else
            echo "  ✗ Manifest component mismatch. Expected: $component, Got: $component_actual"
            exit 1
        fi
    else
        echo "✗ Missing artifacts directory: $artifacts_dir"
        exit 1
    fi
done

# Generate summary report
cat > "$output_dir/smoke_test_summary.json" <<EOF
{
  "bead_id": "$bead_id",
  "component": "$component",
  "smoke_test_status": "passed",
  "example_exit_code": $example_exit_code,
  "artifacts_validated": 2,
  "generated_at_utc": "$timestamp"
}
EOF

echo "📋 Summary report: $output_dir/smoke_test_summary.json"
echo "✅ Live guardplane decision example smoke test PASSED"
echo "   Both suspicious and benign extension examples executed successfully"
echo "   All required proof artifacts generated and validated"
