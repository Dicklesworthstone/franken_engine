#!/bin/bash
set -euo pipefail

# PERF-INFRA.1: Freeze current Criterion estimates as a performance baseline
# Usage: scripts/perf/freeze_baseline.sh <git-sha>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <git-sha>"
    echo "Freezes current Criterion estimates as a baseline for the specified git SHA"
    exit 1
fi

GIT_SHA="$1"
BASELINE_DIR="tests/artifacts/perf/baselines/${GIT_SHA}"
CRITERION_DIR="target/criterion"

# Validate git SHA format (basic check)
if ! [[ "$GIT_SHA" =~ ^[a-f0-9]{7,40}$ ]]; then
    echo "Error: Invalid git SHA format: $GIT_SHA"
    exit 1
fi

# Check if baseline already exists
if [ -d "$BASELINE_DIR" ]; then
    echo "Error: Baseline for $GIT_SHA already exists at $BASELINE_DIR"
    exit 1
fi

# Check if Criterion output exists
if [ ! -d "$CRITERION_DIR" ]; then
    echo "Error: Criterion output directory not found: $CRITERION_DIR"
    echo "Run 'cargo bench --bench hot_paths' first to generate benchmark results"
    exit 1
fi

echo "Creating baseline for git SHA: $GIT_SHA"
mkdir -p "$BASELINE_DIR"

# Copy Criterion estimates for each benchmark function
# Based on hot_paths.rs benchmark functions
BENCH_FUNCTIONS=(
    "parser_arena_materialization"
    "lowering_pipeline_ir3"
    "baseline_interpreter_eval"
    "baseline_value_string_clone"
    "iterator_protocol_trace"
    "scheduler_queue_commit"
    "evidence_ledger_bundle"
    "transport_certificate_serialization"
)

echo "Copying Criterion estimates..."
for fn in "${BENCH_FUNCTIONS[@]}"; do
    criterion_path="$CRITERION_DIR/real_runtime_hot_paths/$fn"

    if [ -d "$criterion_path" ]; then
        # Copy the estimates.json if it exists
        if [ -f "$criterion_path/base/estimates.json" ]; then
            cp "$criterion_path/base/estimates.json" "$BASELINE_DIR/criterion_${fn}_estimates.json"
            echo "  ✓ Copied estimates for $fn"
        else
            echo "  ⚠ Warning: No estimates.json found for $fn"
        fi
    else
        echo "  ⚠ Warning: No criterion output found for $fn"
    fi
done

# Create baseline summary
cat > "$BASELINE_DIR/baseline_summary.json" << EOF
{
  "git_sha": "$GIT_SHA",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "criterion_functions": $(printf '%s\n' "${BENCH_FUNCTIONS[@]}" | jq -R . | jq -s .),
  "baseline_type": "criterion_estimates",
  "created_by": "scripts/perf/freeze_baseline.sh"
}
EOF

# Create build/environment fingerprint
cat > "$BASELINE_DIR/fingerprint.json" << EOF
{
  "git_sha": "$GIT_SHA",
  "git_branch": "$(git branch --show-current 2>/dev/null || echo 'unknown')",
  "git_dirty": $([ -z "$(git status --porcelain)" ] && echo "false" || echo "true"),
  "rust_version": "$(rustc --version)",
  "target_triple": "$(rustc -vV | grep host | cut -d' ' -f2)",
  "features": [],
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$(hostname)",
  "cargo_profile": "release"
}
EOF

# Create README for this baseline
cat > "$BASELINE_DIR/README.md" << EOF
# Performance Baseline: $GIT_SHA

Generated: $(date -u +%Y-%m-%d\ %H:%M:%S\ UTC)

## Conditions

- Git SHA: $GIT_SHA
- Git branch: $(git branch --show-current 2>/dev/null || echo 'unknown')
- Working directory: $([ -z "$(git status --porcelain)" ] && echo "clean" || echo "dirty")
- Rust version: $(rustc --version)
- Target: $(rustc -vV | grep host | cut -d' ' -f2)
- Hostname: $(hostname)

## Benchmark Results

This baseline captures Criterion estimates for ${#BENCH_FUNCTIONS[@]} benchmark functions from the \`hot_paths\` benchmark suite:

$(printf -- '- %s\n' "${BENCH_FUNCTIONS[@]}")

## Files

- \`criterion_*_estimates.json\`: Individual function estimates from Criterion
- \`baseline_summary.json\`: Metadata about this baseline
- \`fingerprint.json\`: Build and environment fingerprint
- \`README.md\`: This documentation

## Usage

Performance regression gates can compare current benchmark results against this baseline to detect significant performance changes.
EOF

echo "✓ Baseline created successfully at $BASELINE_DIR"
echo "✓ Captured estimates for ${#BENCH_FUNCTIONS[@]} benchmark functions"
echo "✓ Created summary and fingerprint files"