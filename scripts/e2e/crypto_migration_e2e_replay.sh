#!/bin/bash
set -euo pipefail

# Crypto Migration E2E Test Replay Wrapper
# Resolves latest complete artifact bundle and provides replay functionality

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACTS_BASE="$PROJECT_ROOT/artifacts/crypto_migration_e2e"
E2E_SCRIPT="$PROJECT_ROOT/scripts/run_crypto_migration_e2e.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [COMMAND]

Crypto Migration E2E Test Replay Wrapper

COMMANDS:
    run                 Run a new e2e test (default)
    latest              Show latest complete test run
    list                List all available test runs
    replay <timestamp>  Replay specific test run by timestamp
    analyze <timestamp> Analyze test results from specific run
    compare <ts1> <ts2> Compare results between two test runs
    cleanup             Remove old test artifacts (keeps last 10)

OPTIONS:
    -v, --verbose       Verbose output
    -q, --quiet         Quiet mode (errors only)
    -h, --help          Show this help message

EXAMPLES:
    $0                  # Run new e2e test
    $0 latest           # Show latest complete test run
    $0 replay 20260416T082000Z  # Replay specific test
    $0 analyze 20260416T082000Z # Analyze specific test results
    $0 cleanup          # Clean up old artifacts

EOF
}

# Find latest complete test run
find_latest_complete() {
    if [[ ! -d "$ARTIFACTS_BASE" ]]; then
        echo "No test artifacts found at $ARTIFACTS_BASE" >&2
        return 1
    fi

    local latest=""
    for dir in "$ARTIFACTS_BASE"/*; do
        if [[ -d "$dir" ]]; then
            local timestamp=$(basename "$dir")
            local events_file="$dir/events.jsonl"
            local manifest_file="$dir/run_manifest.json"

            # Check if run is complete (has events and manifest)
            if [[ -f "$events_file" && -f "$manifest_file" ]]; then
                # Count total tests in events file
                local test_count=$(wc -l < "$events_file" 2>/dev/null || echo "0")
                if [[ "$test_count" -gt 0 ]]; then
                    if [[ -z "$latest" || "$timestamp" > "$latest" ]]; then
                        latest="$timestamp"
                    fi
                fi
            fi
        fi
    done

    if [[ -z "$latest" ]]; then
        echo "No complete test runs found" >&2
        return 1
    fi

    echo "$latest"
}

# List all available test runs
list_test_runs() {
    if [[ ! -d "$ARTIFACTS_BASE" ]]; then
        echo "No test artifacts found at $ARTIFACTS_BASE"
        return 0
    fi

    echo "Available crypto migration e2e test runs:"
    echo "=========================================="
    echo

    local found_any=false
    for dir in "$ARTIFACTS_BASE"/*; do
        if [[ -d "$dir" ]]; then
            local timestamp=$(basename "$dir")
            local events_file="$dir/events.jsonl"
            local manifest_file="$dir/run_manifest.json"

            if [[ -f "$manifest_file" ]]; then
                found_any=true
                local trace_id=""
                local test_count=0
                local passed_count=0
                local failed_count=0
                local status="INCOMPLETE"

                # Extract info from manifest
                if [[ -f "$manifest_file" ]]; then
                    trace_id=$(jq -r '.trace_id // "unknown"' "$manifest_file" 2>/dev/null || echo "unknown")
                fi

                # Count test results from events
                if [[ -f "$events_file" ]]; then
                    test_count=$(wc -l < "$events_file")
                    passed_count=$(grep -c '"status":"pass"' "$events_file" 2>/dev/null || echo "0")
                    failed_count=$(grep -c '"status":"fail"' "$events_file" 2>/dev/null || echo "0")

                    if [[ $test_count -eq 10 ]]; then
                        if [[ $failed_count -eq 0 ]]; then
                            status="${GREEN}COMPLETE (ALL PASS)${NC}"
                        else
                            status="${RED}COMPLETE (${failed_count} FAILED)${NC}"
                        fi
                    else
                        status="${YELLOW}INCOMPLETE ($test_count/10)${NC}"
                    fi
                fi

                echo -e "  $timestamp - $trace_id - $status"
                echo "    Tests: $passed_count passed, $failed_count failed ($test_count total)"
                echo "    Artifacts: $dir"
                echo
            fi
        fi
    done

    if [[ "$found_any" == false ]]; then
        echo "No test runs found."
    fi
}

# Show latest complete test run
show_latest() {
    local latest
    if ! latest=$(find_latest_complete); then
        echo -e "${RED}No complete test runs found${NC}" >&2
        return 1
    fi

    echo -e "${GREEN}Latest complete test run: $latest${NC}"
    echo

    local dir="$ARTIFACTS_BASE/$latest"
    local events_file="$dir/events.jsonl"
    local manifest_file="$dir/run_manifest.json"

    # Show run info
    if [[ -f "$manifest_file" ]]; then
        echo "Run Information:"
        echo "  Trace ID: $(jq -r '.trace_id' "$manifest_file" 2>/dev/null)"
        echo "  Decision ID: $(jq -r '.decision_id' "$manifest_file" 2>/dev/null)"
        echo "  Timestamp: $(jq -r '.timestamp' "$manifest_file" 2>/dev/null)"
        echo "  Environment: $(jq -r '.environment.hostname' "$manifest_file" 2>/dev/null)"
        echo
    fi

    # Show test results
    if [[ -f "$events_file" ]]; then
        echo "Test Results:"
        local passed=0
        local failed=0

        while IFS= read -r line; do
            local test_name=$(echo "$line" | jq -r '.test_name')
            local status=$(echo "$line" | jq -r '.status')
            local duration=$(echo "$line" | jq -r '.duration_ms')

            if [[ "$status" == "pass" ]]; then
                echo -e "  ${GREEN}✓${NC} $test_name (${duration}ms)"
                ((passed++))
            else
                local error=$(echo "$line" | jq -r '.error // "unknown error"')
                echo -e "  ${RED}✗${NC} $test_name (${duration}ms) - $error"
                ((failed++))
            fi
        done < "$events_file"

        echo
        echo -e "Summary: ${GREEN}$passed passed${NC}, ${RED}$failed failed${NC}"
    fi
}

# Replay specific test run
replay_test() {
    local timestamp="$1"
    local dir="$ARTIFACTS_BASE/$timestamp"

    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Test run not found: $timestamp${NC}" >&2
        echo "Available runs:"
        list_test_runs
        return 1
    fi

    echo -e "${BLUE}Replaying test run: $timestamp${NC}"
    echo "Source directory: $dir"
    echo

    # Show original run info
    local manifest_file="$dir/run_manifest.json"
    if [[ -f "$manifest_file" ]]; then
        echo "Original Run:"
        echo "  Trace ID: $(jq -r '.trace_id' "$manifest_file" 2>/dev/null)"
        echo "  Timestamp: $(jq -r '.timestamp' "$manifest_file" 2>/dev/null)"
        echo
    fi

    # Execute new run with replay context
    echo "Executing new test run..."
    export CRYPTO_E2E_REPLAY_SOURCE="$dir"
    exec "$E2E_SCRIPT"
}

# Analyze test results from specific run
analyze_test() {
    local timestamp="$1"
    local dir="$ARTIFACTS_BASE/$timestamp"

    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Test run not found: $timestamp${NC}" >&2
        return 1
    fi

    local events_file="$dir/events.jsonl"
    local manifest_file="$dir/run_manifest.json"

    echo -e "${BLUE}Analyzing test run: $timestamp${NC}"
    echo "Directory: $dir"
    echo

    # Basic statistics
    if [[ -f "$events_file" ]]; then
        local total_tests=$(wc -l < "$events_file")
        local passed_tests=$(grep -c '"status":"pass"' "$events_file" 2>/dev/null || echo "0")
        local failed_tests=$(grep -c '"status":"fail"' "$events_file" 2>/dev/null || echo "0")

        echo "Test Statistics:"
        echo "  Total Tests: $total_tests"
        echo "  Passed: $passed_tests"
        echo "  Failed: $failed_tests"
        echo "  Success Rate: $(( passed_tests * 100 / (total_tests > 0 ? total_tests : 1) ))%"
        echo

        # Performance analysis
        echo "Performance Analysis:"
        local total_duration=0
        local max_duration=0
        local min_duration=999999
        local slowest_test=""
        local fastest_test=""

        while IFS= read -r line; do
            local test_name=$(echo "$line" | jq -r '.test_name')
            local duration=$(echo "$line" | jq -r '.duration_ms')

            if [[ "$duration" =~ ^[0-9]+$ ]]; then
                total_duration=$((total_duration + duration))

                if [[ $duration -gt $max_duration ]]; then
                    max_duration=$duration
                    slowest_test="$test_name"
                fi

                if [[ $duration -lt $min_duration ]]; then
                    min_duration=$duration
                    fastest_test="$test_name"
                fi
            fi
        done < "$events_file"

        if [[ $total_tests -gt 0 ]]; then
            local avg_duration=$((total_duration / total_tests))
            echo "  Total Duration: ${total_duration}ms"
            echo "  Average Duration: ${avg_duration}ms"
            echo "  Slowest Test: $slowest_test (${max_duration}ms)"
            echo "  Fastest Test: $fastest_test (${min_duration}ms)"
        fi
        echo

        # Failed test analysis
        if [[ $failed_tests -gt 0 ]]; then
            echo "Failed Tests Details:"
            while IFS= read -r line; do
                local status=$(echo "$line" | jq -r '.status')
                if [[ "$status" == "fail" ]]; then
                    local test_name=$(echo "$line" | jq -r '.test_name')
                    local error=$(echo "$line" | jq -r '.error')
                    echo "  - $test_name: $error"
                fi
            done < "$events_file"
            echo
        fi
    fi

    # File sizes
    echo "Artifact Files:"
    if [[ -f "$events_file" ]]; then
        echo "  events.jsonl: $(stat -c%s "$events_file" 2>/dev/null || echo "unknown") bytes"
    fi
    if [[ -f "$manifest_file" ]]; then
        echo "  run_manifest.json: $(stat -c%s "$manifest_file" 2>/dev/null || echo "unknown") bytes"
    fi
    local commands_file="$dir/commands.txt"
    if [[ -f "$commands_file" ]]; then
        echo "  commands.txt: $(stat -c%s "$commands_file" 2>/dev/null || echo "unknown") bytes"
    fi
    local golden_file="$dir/golden_vectors.json"
    if [[ -f "$golden_file" ]]; then
        echo "  golden_vectors.json: $(stat -c%s "$golden_file" 2>/dev/null || echo "unknown") bytes"
    fi
}

# Compare two test runs
compare_tests() {
    local ts1="$1"
    local ts2="$2"
    local dir1="$ARTIFACTS_BASE/$ts1"
    local dir2="$ARTIFACTS_BASE/$ts2"

    if [[ ! -d "$dir1" ]]; then
        echo -e "${RED}Test run not found: $ts1${NC}" >&2
        return 1
    fi

    if [[ ! -d "$dir2" ]]; then
        echo -e "${RED}Test run not found: $ts2${NC}" >&2
        return 1
    fi

    echo -e "${BLUE}Comparing test runs: $ts1 vs $ts2${NC}"
    echo

    local events1="$dir1/events.jsonl"
    local events2="$dir2/events.jsonl"

    if [[ -f "$events1" && -f "$events2" ]]; then
        # Compare test results
        echo "Test Results Comparison:"
        echo "  Run 1 ($ts1): $(grep -c '"status":"pass"' "$events1" 2>/dev/null || echo "0") passed, $(grep -c '"status":"fail"' "$events1" 2>/dev/null || echo "0") failed"
        echo "  Run 2 ($ts2): $(grep -c '"status":"pass"' "$events2" 2>/dev/null || echo "0") passed, $(grep -c '"status":"fail"' "$events2" 2>/dev/null || echo "0") failed"
        echo

        # Performance comparison
        local total1=0
        local count1=0
        while IFS= read -r line; do
            local duration=$(echo "$line" | jq -r '.duration_ms')
            if [[ "$duration" =~ ^[0-9]+$ ]]; then
                total1=$((total1 + duration))
                count1=$((count1 + 1))
            fi
        done < "$events1"

        local total2=0
        local count2=0
        while IFS= read -r line; do
            local duration=$(echo "$line" | jq -r '.duration_ms')
            if [[ "$duration" =~ ^[0-9]+$ ]]; then
                total2=$((total2 + duration))
                count2=$((count2 + 1))
            fi
        done < "$events2"

        if [[ $count1 -gt 0 && $count2 -gt 0 ]]; then
            local avg1=$((total1 / count1))
            local avg2=$((total2 / count2))
            echo "Performance Comparison:"
            echo "  Run 1 Average: ${avg1}ms"
            echo "  Run 2 Average: ${avg2}ms"

            if [[ $avg2 -lt $avg1 ]]; then
                local improvement=$(( (avg1 - avg2) * 100 / avg1 ))
                echo -e "  ${GREEN}Performance improvement: ${improvement}%${NC}"
            elif [[ $avg2 -gt $avg1 ]]; then
                local regression=$(( (avg2 - avg1) * 100 / avg1 ))
                echo -e "  ${YELLOW}Performance regression: ${regression}%${NC}"
            else
                echo "  No significant performance change"
            fi
        fi
    fi
}

# Cleanup old test artifacts
cleanup_artifacts() {
    if [[ ! -d "$ARTIFACTS_BASE" ]]; then
        echo "No artifacts directory found at $ARTIFACTS_BASE"
        return 0
    fi

    echo "Cleaning up old crypto migration e2e test artifacts..."

    # Count current artifacts
    local count=$(find "$ARTIFACTS_BASE" -maxdepth 1 -type d ! -path "$ARTIFACTS_BASE" | wc -l)

    if [[ $count -le 10 ]]; then
        echo "Only $count test runs found, no cleanup needed (keeping all, limit is 10)"
        return 0
    fi

    # Keep the 10 most recent
    local to_remove=$((count - 10))
    echo "Found $count test runs, removing oldest $to_remove (keeping newest 10)"

    # Sort by timestamp and remove oldest
    find "$ARTIFACTS_BASE" -maxdepth 1 -type d ! -path "$ARTIFACTS_BASE" -printf '%f\n' | \
    sort | head -n "$to_remove" | while read -r timestamp; do
        local dir="$ARTIFACTS_BASE/$timestamp"
        echo "  Removing: $timestamp"
        rm -rf "$dir"
    done

    echo "Cleanup complete!"
}

# Main function
main() {
    local verbose=false
    local quiet=false
    local command="run"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                verbose=true
                shift
                ;;
            -q|--quiet)
                quiet=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            run|latest|list|cleanup)
                command="$1"
                shift
                ;;
            replay|analyze)
                command="$1"
                shift
                if [[ $# -eq 0 ]]; then
                    echo -e "${RED}Error: $command requires a timestamp argument${NC}" >&2
                    echo "Use 'list' to see available test runs" >&2
                    exit 1
                fi
                timestamp="$1"
                shift
                ;;
            compare)
                command="$1"
                shift
                if [[ $# -lt 2 ]]; then
                    echo -e "${RED}Error: compare requires two timestamp arguments${NC}" >&2
                    echo "Use 'list' to see available test runs" >&2
                    exit 1
                fi
                ts1="$1"
                ts2="$2"
                shift 2
                ;;
            *)
                echo -e "${RED}Unknown argument: $1${NC}" >&2
                print_usage >&2
                exit 1
                ;;
        esac
    done

    # Execute command
    case "$command" in
        run)
            exec "$E2E_SCRIPT"
            ;;
        latest)
            show_latest
            ;;
        list)
            list_test_runs
            ;;
        replay)
            replay_test "$timestamp"
            ;;
        analyze)
            analyze_test "$timestamp"
            ;;
        compare)
            compare_tests "$ts1" "$ts2"
            ;;
        cleanup)
            cleanup_artifacts
            ;;
        *)
            echo -e "${RED}Unknown command: $command${NC}" >&2
            print_usage >&2
            exit 1
            ;;
    esac
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi