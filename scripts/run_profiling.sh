#!/usr/bin/env bash
set -euo pipefail

# Profiling Infrastructure Runner - RC-3.5
# Runs benchmarks with profiling enabled and generates optimization target reports

FRANKENCTL_BIN="${FRANKENCTL_BIN:-frankenctl}"
LOG="${FRANKEN_PROFILE_LOG:-artifacts/profiling_$(date +%s).jsonl}"
ARTIFACTS="${FRANKEN_PROFILE_ARTIFACTS_DIR:-artifacts/profiling_evidence/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$(dirname "$LOG")"
mkdir -p "$ARTIFACTS"

echo "=== Profiling Infrastructure Test ==="
echo "Artifacts directory: $ARTIFACTS"
echo "Log file: $LOG"

echo '{"suite":"profiling_infrastructure","started":"'$(date -Iseconds)'"}' >> "$LOG"

captured_profiles=()

if ! command -v "$FRANKENCTL_BIN" >/dev/null 2>&1; then
    cat > "$ARTIFACTS/degraded_non_authoritative.json" << EOF
{
    "suite": "profiling_infrastructure",
    "status": "degraded",
    "authoritative": false,
    "reason": "frankenctl_missing",
    "frankenctl_bin": "$FRANKENCTL_BIN",
    "optimization_report_emitted": false,
    "time": "$(date -Iseconds)"
}
EOF
    echo "{\"suite\":\"profiling_infrastructure\",\"status\":\"degraded\",\"authoritative\":false,\"reason\":\"frankenctl_missing\",\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
    echo "❌ frankenctl not available; refusing to emit authoritative profiling evidence"
    echo "Non-authoritative degraded marker: $ARTIFACTS/degraded_non_authoritative.json"
    exit 127
fi

# Function to run a benchmark with profiling
run_profiled_benchmark() {
    local name=$1
    local js_file=$2
    local profile_out="$ARTIFACTS/${name}_profile.json"
    local frankenctl_log="$ARTIFACTS/${name}_frankenctl.log"

    echo "Profiling benchmark: $name"
    echo "JavaScript file: $js_file"

    if [[ ! -f "$js_file" ]]; then
        echo "⚠️ Benchmark file not found: $js_file"
        echo "{\"benchmark\":\"$name\",\"status\":\"skipped\",\"reason\":\"file_not_found\",\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
        return 1
    fi

    PROFILING_CONFIG='{
        "enable_instruction_profiling": true,
        "enable_hotspot_profiling": true,
        "enable_memory_profiling": true,
        "enable_call_stack_profiling": false,
        "hotspot_sampling_interval": 1000
    }'

    if "$FRANKENCTL_BIN" run --input "$js_file" --profile --profile-config "$PROFILING_CONFIG" --out "$profile_out" > "$frankenctl_log" 2>&1; then
        benchmark_exit=$?
    else
        benchmark_exit=$?
    fi

    if [[ $benchmark_exit -eq 0 && ! -s "$profile_out" ]]; then
        echo "❌ frankenctl completed without writing profile artifact: $profile_out"
        benchmark_exit=1
    fi

    if [[ $benchmark_exit -eq 0 ]]; then
        captured_profiles+=("$profile_out")
        echo "{\"benchmark\":\"$name\",\"exit\":$benchmark_exit,\"authoritative\":true,\"profile_artifact\":\"$profile_out\",\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
    else
        echo "{\"benchmark\":\"$name\",\"exit\":$benchmark_exit,\"authoritative\":false,\"profile_artifact\":\"\",\"frankenctl_log\":\"$frankenctl_log\",\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
    fi

    return $benchmark_exit
}

# Profile micro-benchmarks
echo "=== Profiling Micro-Benchmarks ==="
micro_benchmarks=(
    "arithmetic_loop:benchmarks/micro/arithmetic_loop.js"
    "float_arithmetic:benchmarks/micro/float_arithmetic.js"
    "property_access:benchmarks/micro/property_access.js"
    "function_calls:benchmarks/micro/function_calls.js"
    "object_creation:benchmarks/micro/object_creation.js"
    "array_operations:benchmarks/micro/array_operations.js"
    "string_operations:benchmarks/micro/string_operations.js"
    "json_operations:benchmarks/micro/json_operations.js"
)

micro_failed=0
for benchmark_spec in "${micro_benchmarks[@]}"; do
    IFS=':' read -r name file <<< "$benchmark_spec"
    if ! run_profiled_benchmark "$name" "$file"; then
        ((micro_failed += 1))
    fi
done

# Profile macro-benchmarks
echo "=== Profiling Macro-Benchmarks ==="
macro_benchmarks=(
    "json_transformation:benchmarks/macro/json_transformation.js"
    "tree_traversal:benchmarks/macro/tree_traversal.js"
    "recursive_algorithms:benchmarks/macro/recursive_algorithms.js"
    "text_processing:benchmarks/macro/text_processing.js"
    "event_emitter_simulation:benchmarks/macro/event_emitter_simulation.js"
)

macro_failed=0
for benchmark_spec in "${macro_benchmarks[@]}"; do
    IFS=':' read -r name file <<< "$benchmark_spec"
    if ! run_profiled_benchmark "$name" "$file"; then
        ((macro_failed += 1))
    fi
done

# Generate consolidated optimization report
echo "=== Generating Optimization Target Report ==="
total_benchmarks=$((${#micro_benchmarks[@]} + ${#macro_benchmarks[@]}))
total_failed=$((micro_failed + macro_failed))
total_passed=$((total_benchmarks - total_failed))

if [[ $total_passed -gt 0 ]]; then
    {
        cat << EOF
{
    "report_metadata": {
        "generated_at": "$(date -Iseconds)",
        "profiling_session": "$ARTIFACTS",
        "authoritative": true,
        "source": "frankenctl profile captures",
        "total_benchmarks_profiled": $total_benchmarks,
        "successful_profiles": $total_passed,
        "failed_profiles": $total_failed
    },
    "profile_artifacts": [
EOF
        for i in "${!captured_profiles[@]}"; do
            comma=","
            if [[ $i -eq $((${#captured_profiles[@]} - 1)) ]]; then
                comma=""
            fi
            printf '        "%s"%s\n' "${captured_profiles[$i]}" "$comma"
        done
        cat << EOF
    ],
    "top_optimization_opportunities": [],
    "analysis_status": "raw_profiles_captured_no_synthetic_recommendations"
}
EOF
    } > "$ARTIFACTS/optimization_targets.json"
else
    cat > "$ARTIFACTS/degraded_non_authoritative.json" << EOF
{
    "suite": "profiling_infrastructure",
    "status": "failed",
    "authoritative": false,
    "reason": "no_real_profile_captures",
    "optimization_report_emitted": false,
    "time": "$(date -Iseconds)"
}
EOF
fi

echo ""
echo "=== Profiling Infrastructure Results ==="
echo "Total benchmarks: $total_benchmarks"
echo "Successfully profiled: $total_passed"
echo "Failed to profile: $total_failed"
if [[ $total_passed -gt 0 ]]; then
    echo "Optimization report: $ARTIFACTS/optimization_targets.json"
else
    echo "Optimization report: not emitted; no real profile captures"
fi

echo '{"suite":"profiling_infrastructure","completed":"'$(date -Iseconds)'","total":'$total_benchmarks',"passed":'$total_passed',"failed":'$total_failed'}' >> "$LOG"

if [ $total_failed -eq 0 ]; then
    echo "✅ All profiling infrastructure tests passed!"
    echo "📊 Authoritative optimization target report generated"
    echo "Artifacts written to: $ARTIFACTS"
    exit 0
else
    echo "⚠️ $total_failed benchmark(s) failed profiling!"
    echo "Check logs at: $LOG"
    exit 1
fi
