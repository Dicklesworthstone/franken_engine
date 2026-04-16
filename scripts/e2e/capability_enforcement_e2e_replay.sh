#!/usr/bin/env bash
set -euo pipefail

# Capability Enforcement E2E Replay Script
# Replays capability enforcement tests from existing artifacts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default configuration
DEFAULT_ARTIFACT_DIR="$PROJECT_ROOT/artifacts/capability_enforcement_e2e"

# Parse arguments
MODE="${1:-latest}"
ARTIFACT_DIR="${2:-$DEFAULT_ARTIFACT_DIR}"

usage() {
    echo "Usage: $0 [latest|<timestamp>|list] [artifact_dir]"
    echo ""
    echo "Modes:"
    echo "  latest     - Replay the most recent artifact bundle"
    echo "  <timestamp> - Replay specific timestamp (e.g., 20260416T140000Z)"
    echo "  list       - List available artifact bundles"
    echo ""
    echo "Examples:"
    echo "  $0 latest"
    echo "  $0 20260416T140000Z"
    echo "  $0 list"
}

list_artifacts() {
    if [ ! -d "$ARTIFACT_DIR" ]; then
        echo "No artifact directory found: $ARTIFACT_DIR"
        return 1
    fi

    echo "Available capability enforcement e2e artifact bundles:"
    find "$ARTIFACT_DIR" -maxdepth 1 -type d -name "20*" | sort -r | head -10 | while read -r dir; do
        local timestamp=$(basename "$dir")
        local manifest="$dir/run_manifest.json"
        if [ -f "$manifest" ]; then
            local outcome=$(jq -r '.outcome // "unknown"' "$manifest" 2>/dev/null)
            local total_tests=$(jq -r '.total_tests // "unknown"' "$manifest" 2>/dev/null)
            local passed_tests=$(jq -r '.passed_tests // "unknown"' "$manifest" 2>/dev/null)
            echo "  $timestamp - $outcome ($passed_tests/$total_tests passed)"
        else
            echo "  $timestamp - incomplete (no manifest)"
        fi
    done
}

find_latest() {
    if [ ! -d "$ARTIFACT_DIR" ]; then
        echo "No artifact directory found: $ARTIFACT_DIR" >&2
        return 1
    fi

    local latest_dir
    latest_dir=$(find "$ARTIFACT_DIR" -maxdepth 1 -type d -name "20*" | sort -r | head -1)

    if [ -z "$latest_dir" ]; then
        echo "No artifact bundles found in: $ARTIFACT_DIR" >&2
        return 1
    fi

    echo "$latest_dir"
}

replay_artifact() {
    local bundle_dir="$1"
    local manifest="$bundle_dir/run_manifest.json"
    local events="$bundle_dir/events.jsonl"
    local matrix_report="$bundle_dir/capability_matrix_report.json"
    local commands="$bundle_dir/commands.txt"

    if [ ! -f "$manifest" ]; then
        echo "Error: No run_manifest.json found in $bundle_dir"
        return 1
    fi

    echo "=== Capability Enforcement E2E Replay ==="
    echo "Bundle: $(basename "$bundle_dir")"
    echo "Replaying from: $bundle_dir"
    echo ""

    echo "=== Run Manifest ==="
    jq . "$manifest" || cat "$manifest"
    echo ""

    if [ -f "$matrix_report" ]; then
        echo "=== Capability Matrix Report ==="
        jq . "$matrix_report" || cat "$matrix_report"
        echo ""
    fi

    if [ -f "$events" ]; then
        echo "=== Test Results Summary ==="
        echo "Total events: $(wc -l < "$events")"
        echo ""

        echo "Passed tests:"
        jq -r 'select(.status == "pass") | "\(.test_id): \(.test_name) - \(.profile):\(.operation) -> \(.actual_result)"' "$events" 2>/dev/null || echo "No passed tests found"
        echo ""

        echo "Failed tests:"
        jq -r 'select(.status == "fail") | "\(.test_id): \(.test_name) - \(.profile):\(.operation) -> \(.actual_result) (expected: \(.expected_result))"' "$events" 2>/dev/null || echo "No failed tests found"
        echo ""

        echo "Performance summary:"
        echo "Average duration: $(jq -r '[.duration_ms] | add / length | round' "$events" 2>/dev/null || echo "unknown")ms"
        echo ""
    fi

    if [ -f "$commands" ]; then
        echo "=== Commands Log (last 10 lines) ==="
        tail -10 "$commands"
        echo ""
    fi

    # Verify artifact completeness
    local outcome=$(jq -r '.outcome // "unknown"' "$manifest" 2>/dev/null)
    local total_tests=$(jq -r '.total_tests // 0' "$manifest" 2>/dev/null)
    local passed_tests=$(jq -r '.passed_tests // 0' "$manifest" 2>/dev/null)

    echo "=== Replay Summary ==="
    echo "Outcome: $outcome"
    echo "Tests: $passed_tests/$total_tests passed"

    # Artifact verification
    local required_files=("run_manifest.json" "events.jsonl" "capability_matrix_report.json" "commands.txt")
    local missing_files=()

    for file in "${required_files[@]}"; do
        if [ ! -f "$bundle_dir/$file" ]; then
            missing_files+=("$file")
        fi
    done

    if [ ${#missing_files[@]} -eq 0 ]; then
        echo "Artifact bundle: COMPLETE"
        return 0
    else
        echo "Artifact bundle: INCOMPLETE (missing: ${missing_files[*]})"
        return 1
    fi
}

case "$MODE" in
    "list")
        list_artifacts
        ;;
    "latest")
        latest_dir=$(find_latest)
        if [ $? -eq 0 ]; then
            replay_artifact "$latest_dir"
        else
            exit 1
        fi
        ;;
    "help"|"-h"|"--help")
        usage
        ;;
    *)
        # Assume it's a timestamp
        bundle_dir="$ARTIFACT_DIR/$MODE"
        if [ -d "$bundle_dir" ]; then
            replay_artifact "$bundle_dir"
        else
            echo "Error: Artifact bundle not found: $bundle_dir"
            echo ""
            echo "Available bundles:"
            list_artifacts
            exit 1
        fi
        ;;
esac