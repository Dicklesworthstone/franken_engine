#!/bin/bash
# CI Performance Regression Gate for FrankenEngine
# Ensures performance doesn't regress by more than 5% in CI/CD pipeline

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts/performance_regression_gate/$(date +%Y%m%d_%H%M%S)"

echo "🚦 FrankenEngine CI Performance Regression Gate"
echo "============================================="
echo "Project Root: $PROJECT_ROOT"
echo "Artifacts Dir: $ARTIFACTS_DIR"
echo ""

# Create artifacts directory
mkdir -p "$ARTIFACTS_DIR"

echo "🔌 Checking benchmark suite index wiring..."
"$PROJECT_ROOT/scripts/e2e/benchmark_suite_index_wiring_smoke.sh" check \
    2>&1 | tee "$ARTIFACTS_DIR/benchmark_suite_index_wiring_smoke.log"
echo ""

# Check if baseline performance data exists
BASELINE_DIR="$PROJECT_ROOT/artifacts/performance_baselines"
if [[ ! -d "$BASELINE_DIR" ]] || [[ -z "$(ls -A "$BASELINE_DIR" 2>/dev/null || true)" ]]; then
    echo "⚠️ No baseline performance data found."
    echo "This appears to be the first run or baseline data is missing."
    echo ""
    echo "Generating initial baseline instead of checking for regressions..."

    # Run baseline benchmark collection
    echo "📊 Collecting performance baseline..."
    if node "$SCRIPT_DIR/run_baseline_benchmarks.js" 2>&1 | tee "$ARTIFACTS_DIR/baseline_generation.log"; then
        echo ""
        echo "✅ Performance baseline generated successfully!"
        echo "📁 Artifacts saved to: $(find "$BASELINE_DIR" -type d -name "2026-*" | tail -1)"
        echo ""
        echo "ℹ️ Future CI runs will check for regressions against this baseline."
        echo "To update the baseline, delete the contents of $BASELINE_DIR and re-run this gate."
        exit 0
    else
        echo ""
        echo "❌ Failed to generate performance baseline!"
        echo "Check the logs for details: $ARTIFACTS_DIR/baseline_generation.log"
        exit 1
    fi
fi

# Run regression check
echo "🔍 Running performance regression check..."
echo ""

node "$SCRIPT_DIR/performance_regression_gate.js" --output "$ARTIFACTS_DIR" 2>&1 | tee "$ARTIFACTS_DIR/regression_check.log"
GATE_EXIT_CODE=$?

# Copy gate results for CI artifact preservation
if [[ -f "$ARTIFACTS_DIR/regression_report.json" ]]; then
    echo ""
    echo "📄 Regression report generated:"
    echo "  Report: $ARTIFACTS_DIR/regression_report.json"
    echo "  Log: $ARTIFACTS_DIR/regression_check.log"

    # Extract key metrics for CI summary
    if command -v jq >/dev/null 2>&1; then
        echo ""
        echo "📊 Performance Summary:"
        jq -r '"  Gate Status: " + (if .gate_passed then "✅ PASSED" else "❌ FAILED" end)' "$ARTIFACTS_DIR/regression_report.json"
        jq -r '"  Benchmarks Checked: " + (.summary.totalChecked | tostring)' "$ARTIFACTS_DIR/regression_report.json"
        jq -r '"  Regressions Found: " + (.summary.regressionCount | tostring)' "$ARTIFACTS_DIR/regression_report.json"
        jq -r '"  Max Regression: " + ((.summary.maxRegression * 100) | tostring | .[0:5]) + "%"' "$ARTIFACTS_DIR/regression_report.json"
    fi
else
    echo "⚠️ No regression report generated - check logs for errors"
fi

echo ""
if [[ $GATE_EXIT_CODE -eq 0 ]]; then
    echo "✅ Performance regression gate PASSED!"
    echo "No significant performance regressions detected."
else
    echo "❌ Performance regression gate FAILED!"
    echo "Significant performance regressions were detected."
    echo ""
    echo "📋 Next Steps:"
    echo "1. Review the regression report: $ARTIFACTS_DIR/regression_report.json"
    echo "2. Investigate performance changes in your code"
    echo "3. Fix regressions or document intentional performance changes"
    echo "4. If changes are intentional, update the baseline with:"
    echo "   rm -rf $BASELINE_DIR/* && node scripts/run_baseline_benchmarks.js"
fi

echo ""
echo "🎯 Performance gate completed"
echo "Artifacts preserved at: $ARTIFACTS_DIR"

exit $GATE_EXIT_CODE
