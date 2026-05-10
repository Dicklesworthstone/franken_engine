#!/usr/bin/env bash
set -euo pipefail

# Test262 Regression Gate - CI Integration Script
# Part of bd-6a61n.1.8 (RC-1.8) implementation
# Prevents Test262 pass rate from regressing below high-water mark

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
HIGH_WATER_MARK_FILE="${TEST262_GATE_HIGH_WATER_MARK_FILE:-$PROJECT_ROOT/crates/franken-engine/tests/fixtures/test262_high_water_mark.toml}"
GATE_MODE="${1:-validate}"  # validate|update|report
ARTIFACTS_DIR="${TEST262_GATE_ARTIFACTS_DIR:-$PROJECT_ROOT/artifacts/test262/gate_$(date +%Y%m%d_%H%M%S)}"
PINS_FILE="${TEST262_GATE_PINS_FILE:-$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_pins.toml}"
PROFILE_FILE="${TEST262_GATE_PROFILE_FILE:-$PROJECT_ROOT/crates/franken-engine/tests/test262_es2020_profile.toml}"
WAIVERS_FILE="${TEST262_GATE_WAIVERS_FILE:-$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_waivers.toml}"
CASE_VECTORS_FILE="${TEST262_GATE_CASE_VECTORS_FILE:-$PROJECT_ROOT/crates/franken-engine/tests/test262_case_vectors.jsonl}"
OBSERVED_RESULTS_FILE="${TEST262_GATE_OBSERVED_RESULTS_FILE:-}"
RUN_DATE="${TEST262_GATE_RUN_DATE:-$(date -u +%Y-%m-%d)}"
WORKER_COUNT="${TEST262_GATE_WORKER_COUNT:-8}"
ACKNOWLEDGE_PASS_REGRESSION="${TEST262_GATE_ACKNOWLEDGE_PASS_REGRESSION:-false}"
RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${TEST262_GATE_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_test262_gate_$(date +%s)_$$}"

echo "🚦 Test262 Regression Gate"
echo "Mode: $GATE_MODE"
echo "Artifacts: $ARTIFACTS_DIR"

mkdir -p "$ARTIFACTS_DIR"
cd "$PROJECT_ROOT"

fail() {
    echo "❌ $*" >&2
    exit 1
}

require_command() {
    local command_name="$1"
    command -v "$command_name" >/dev/null 2>&1 || fail "Required command not found: $command_name"
}

run_rch_runner() {
    local log_file="$1"
    shift

    "$RCH_BIN" exec -- env \
        "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
        "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
        "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
        "$@" > >(tee "$log_file") 2>&1
    local status=$?

    if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$log_file"; then
        fail "rch reported local fallback while running franken_test262_runner"
    fi

    return "$status"
}

# Function to parse TOML value (simple implementation)
parse_toml_value() {
    local file="$1"
    local key="$2"
    if [[ -f "$file" ]]; then
        grep "^$key" "$file" | cut -d'=' -f2 | tr -d ' "' || echo "0"
    else
        echo "0"
    fi
}

calculate_rate() {
    local passed="$1"
    local total="$2"
    awk -v passed="$passed" -v total="$total" 'BEGIN {
        if (total <= 0) {
            printf "0.000000";
        } else {
            printf "%.6f", passed / total;
        }
    }'
}

decimal_less_than() {
    local lhs="$1"
    local rhs="$2"
    awk -v lhs="$lhs" -v rhs="$rhs" 'BEGIN { exit !(lhs < rhs) }'
}

truthy() {
    case "${1,,}" in
        1|true|yes|y|on) return 0 ;;
        *) return 1 ;;
    esac
}

json_field() {
    local file="$1"
    local expression="$2"
    jq -er "$expression" "$file"
}

# Check if high-water mark exists
if [[ ! -f "$HIGH_WATER_MARK_FILE" && "$GATE_MODE" != "update" ]]; then
    echo "⚠️  No high-water mark found at $HIGH_WATER_MARK_FILE"
    echo "Creating initial high-water mark with REAL baseline measurements..."

    # Run actual Test262 runner to get baseline measurements instead of fake values
    echo "🧪 Running Test262 baseline measurement..."
    require_command "$RCH_BIN"
    require_command jq

    BASELINE_OUTPUT_ROOT="$ARTIFACTS_DIR/baseline_test262_runner"
    BASELINE_LOG="$ARTIFACTS_DIR/baseline_runner.log"
    BASELINE_HWM_JSON="$ARTIFACTS_DIR/baseline_high_water_mark.json"

    BASELINE_RUNNER_ARGS=(
        cargo run -p frankenengine-engine --bin franken_test262_runner --
        --pins "$PINS_FILE"
        --profile "$PROFILE_FILE"
        --waivers "$WAIVERS_FILE"
        --case-vectors "$CASE_VECTORS_FILE"
        --output-root "$BASELINE_OUTPUT_ROOT"
        --high-water-mark "$BASELINE_HWM_JSON"
        --run-date "$RUN_DATE"
        --worker-count "$WORKER_COUNT"
    )

    if ! run_rch_runner "$BASELINE_LOG" "${BASELINE_RUNNER_ARGS[@]}"; then
        fail "Baseline franken_test262_runner failed; cannot create initial high-water mark with real data"
    fi

    BASELINE_MANIFEST_PATH="$(grep -Eo 'test262 run_manifest=.*' "$BASELINE_LOG" | tail -n 1 | sed 's/.*test262 run_manifest=//')"
    BASELINE_CANONICAL_HWM_PATH="$(grep -Eo 'test262 canonical_high_water_mark=.*' "$BASELINE_LOG" | tail -n 1 | sed 's/.*test262 canonical_high_water_mark=//')"

    [[ -n "$BASELINE_MANIFEST_PATH" ]] || fail "Baseline runner did not report a run_manifest path"
    [[ -n "$BASELINE_CANONICAL_HWM_PATH" ]] || fail "Baseline runner did not report a canonical_high_water_mark path"
    [[ -f "$BASELINE_MANIFEST_PATH" ]] || fail "Baseline runner manifest missing: $BASELINE_MANIFEST_PATH"
    [[ -f "$BASELINE_CANONICAL_HWM_PATH" ]] || fail "Baseline canonical high-water mark missing: $BASELINE_CANONICAL_HWM_PATH"

    BASELINE_TOTAL_TESTS="$(json_field "$BASELINE_MANIFEST_PATH" '.total_profile_tests')"
    BASELINE_PASSED_TESTS="$(json_field "$BASELINE_MANIFEST_PATH" '.passed')"
    BASELINE_FAILED_TESTS="$(json_field "$BASELINE_MANIFEST_PATH" '.failed')"
    BASELINE_WAIVED_TESTS="$(json_field "$BASELINE_MANIFEST_PATH" '.waived')"
    BASELINE_HWM_PASS_COUNT="$(json_field "$BASELINE_CANONICAL_HWM_PATH" '.pass_count')"
    BASELINE_HWM_RECORDED_AT="$(json_field "$BASELINE_CANONICAL_HWM_PATH" '.recorded_at_utc')"
    BASELINE_PASS_RATE="$(calculate_rate "$BASELINE_PASSED_TESTS" "$BASELINE_TOTAL_TESTS")"

    [[ "$BASELINE_TOTAL_TESTS" =~ ^[0-9]+$ && "$BASELINE_TOTAL_TESTS" -gt 0 ]] \
        || fail "Baseline runner reported no profile tests"
    [[ "$BASELINE_PASSED_TESTS" =~ ^[0-9]+$ ]] || fail "Baseline passed count is invalid"
    [[ "$BASELINE_FAILED_TESTS" =~ ^[0-9]+$ ]] || fail "Baseline failed count is invalid"
    [[ "$BASELINE_WAIVED_TESTS" =~ ^[0-9]+$ ]] || fail "Baseline waived count is invalid"
    [[ "$BASELINE_HWM_PASS_COUNT" =~ ^[0-9]+$ ]] || fail "Baseline high-water pass_count is invalid"

    # Create high-water mark with REAL measurements
    cat > "$HIGH_WATER_MARK_FILE" << EOF
schema_version = "franken-engine.test262-high-water-mark.v1"
measurement_date = "$BASELINE_HWM_RECORDED_AT"
es_profile = "ES2020"
created_by = "test262_regression_gate.sh baseline"
baseline_manifest = "$BASELINE_MANIFEST_PATH"
baseline_canonical_high_water_mark = "$BASELINE_CANONICAL_HWM_PATH"

[pass_counts]
total_tests = $BASELINE_TOTAL_TESTS
passed_tests = $BASELINE_HWM_PASS_COUNT
failed_tests = $BASELINE_FAILED_TESTS
skipped_tests = 0
waived_tests = $BASELINE_WAIVED_TESTS

[chapter_breakdown]
# Real chapter breakdown would require runner enhancement
chapter_8_types_pass_rate = 0.0
chapter_12_expressions_pass_rate = 0.0
chapter_13_statements_pass_rate = 0.0
chapter_14_functions_pass_rate = 0.0

[regression_policy]
allow_pass_rate_decrease = false
min_pass_rate_threshold = 0.60
regression_acknowledgment_required = true
EOF

    echo "✅ Created initial high-water mark with REAL baseline: $HIGH_WATER_MARK_FILE"
    echo "📊 Real baseline: $BASELINE_HWM_PASS_COUNT/$BASELINE_TOTAL_TESTS tests passed ($(awk -v rate="$BASELINE_PASS_RATE" 'BEGIN { printf "%.1f%%", rate * 100 }'))"
fi

if [[ ! -f "$HIGH_WATER_MARK_FILE" ]]; then
    fail "No high-water mark found at $HIGH_WATER_MARK_FILE"
fi

# Read current high-water mark
HWM_TOTAL_TESTS=$(parse_toml_value "$HIGH_WATER_MARK_FILE" "total_tests")
HWM_PASSED_TESTS=$(parse_toml_value "$HIGH_WATER_MARK_FILE" "passed_tests")
HWM_PASS_RATE=$(calculate_rate "$HWM_PASSED_TESTS" "$HWM_TOTAL_TESTS")
MIN_THRESHOLD=$(parse_toml_value "$HIGH_WATER_MARK_FILE" "min_pass_rate_threshold")

echo "📊 Current High-Water Mark:"
echo "  Total tests: $HWM_TOTAL_TESTS"
echo "  Passed tests: $HWM_PASSED_TESTS"
echo "  Pass rate: $HWM_PASS_RATE"
echo "  Min threshold: $MIN_THRESHOLD"

# Gate logic based on mode
case "$GATE_MODE" in
    "validate")
        echo "🔍 Validating Test262 configuration..."

        # Check that all required files exist
        REQUIRED_FILES=(
            "$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_pins.toml"
            "$PROJECT_ROOT/crates/franken-engine/tests/test262_es2020_profile.toml"
            "$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_waivers.toml"
        )

        VALIDATION_PASSED=true
        for file in "${REQUIRED_FILES[@]}"; do
            if [[ -f "$file" ]]; then
                echo "✅ Found: $file"
            else
                echo "❌ Missing: $file"
                VALIDATION_PASSED=false
            fi
        done

        # Validate high-water mark format
        if grep -q "schema_version.*test262-high-water-mark" "$HIGH_WATER_MARK_FILE"; then
            echo "✅ High-water mark schema valid"
        else
            echo "❌ High-water mark schema invalid"
            VALIDATION_PASSED=false
        fi

        # Generate validation report
        cat > "$ARTIFACTS_DIR/validation_report.json" << EOF
{
  "schema_version": "franken-engine.test262-gate-validation.v1",
  "timestamp": "$(date -Iseconds)",
  "gate_mode": "validate",
  "validation_passed": $VALIDATION_PASSED,
  "high_water_mark": {
    "file_path": "$HIGH_WATER_MARK_FILE",
    "total_tests": $HWM_TOTAL_TESTS,
    "passed_tests": $HWM_PASSED_TESTS,
    "pass_rate": $HWM_PASS_RATE,
    "min_threshold": $MIN_THRESHOLD
  },
  "required_files_check": {
$(for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo "    \"$file\": \"present\","
    else
        echo "    \"$file\": \"missing\","
    fi
done | sed '$ s/,$//')
  }
}
EOF

        if $VALIDATION_PASSED; then
            echo "✅ Test262 regression gate validation passed"
            exit 0
        else
            echo "❌ Test262 regression gate validation failed"
            exit 1
        fi
        ;;

    "report")
        echo "📋 Generating Test262 conformance report..."

        cat > "$ARTIFACTS_DIR/conformance_report.json" << EOF
{
  "schema_version": "franken-engine.test262-conformance-report.v1",
  "timestamp": "$(date -Iseconds)",
  "report_type": "current_status",
  "engine_profile": "FrankenEngine baseline interpreter",
  "test_suite": {
    "name": "Test262",
    "profile": "ES2020",
    "version_pin": "$(parse_toml_value "$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_pins.toml" "test262_commit")"
  },
  "baseline_measurements": {
    "total_tests": $HWM_TOTAL_TESTS,
    "passed_tests": $HWM_PASSED_TESTS,
    "failed_tests": $(( HWM_TOTAL_TESTS - HWM_PASSED_TESTS )),
    "overall_pass_rate": $HWM_PASS_RATE,
    "chapter_breakdown": {
      "chapter_8_types": $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_8_types_pass_rate"),
      "chapter_12_expressions": $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_12_expressions_pass_rate"),
      "chapter_13_statements": $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_13_statements_pass_rate"),
      "chapter_14_functions": $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_14_functions_pass_rate")
    }
  },
  "waivers": {
    "count": $(grep -c "\\[\\[waiver\\]\\]" "$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_waivers.toml" || echo "0"),
    "policy": "documented_known_failures_only"
  },
  "next_steps": [
    "Run actual Test262 suite against current engine",
    "Update high-water mark with real measurements",
    "Implement CI regression prevention",
    "Add chapter-level granular reporting"
  ]
}
EOF

        echo "✅ Generated conformance report: $ARTIFACTS_DIR/conformance_report.json"
        ;;

    "update")
        echo "🔄 Updating Test262 high-water mark from runner results..."
        require_command "$RCH_BIN"
        require_command jq
        require_command awk

        RUNNER_OUTPUT_ROOT="$ARTIFACTS_DIR/test262_runner"
        RUNNER_LOG="$ARTIFACTS_DIR/franken_test262_runner.log"
        CANDIDATE_HWM_JSON="$ARTIFACTS_DIR/candidate_high_water_mark.json"

        RUNNER_ARGS=(
            cargo run -p frankenengine-engine --bin franken_test262_runner --
            --pins "$PINS_FILE"
            --profile "$PROFILE_FILE"
            --waivers "$WAIVERS_FILE"
            --case-vectors "$CASE_VECTORS_FILE"
            --output-root "$RUNNER_OUTPUT_ROOT"
            --high-water-mark "$CANDIDATE_HWM_JSON"
            --run-date "$RUN_DATE"
            --worker-count "$WORKER_COUNT"
        )

        if [[ -n "$OBSERVED_RESULTS_FILE" ]]; then
            RUNNER_ARGS+=(--observed-results "$OBSERVED_RESULTS_FILE" --allow-precomputed-observed)
        fi

        if truthy "$ACKNOWLEDGE_PASS_REGRESSION"; then
            RUNNER_ARGS+=(--acknowledge-pass-regression)
        fi

        printf '%q ' "${RUNNER_ARGS[@]}" > "$ARTIFACTS_DIR/update_command.txt"
        echo "" >> "$ARTIFACTS_DIR/update_command.txt"

        if ! run_rch_runner "$RUNNER_LOG" "${RUNNER_ARGS[@]}"; then
            fail "franken_test262_runner failed; leaving $HIGH_WATER_MARK_FILE unchanged"
        fi

        RUNNER_MANIFEST_PATH="$(grep -Eo 'test262 run_manifest=.*' "$RUNNER_LOG" | tail -n 1 | sed 's/.*test262 run_manifest=//')"
        RUNNER_HWM_PATH="$(grep -Eo 'test262 high_water_mark=.*' "$RUNNER_LOG" | tail -n 1 | sed 's/.*test262 high_water_mark=//')"
        RUNNER_CANONICAL_HWM_PATH="$(grep -Eo 'test262 canonical_high_water_mark=.*' "$RUNNER_LOG" | tail -n 1 | sed 's/.*test262 canonical_high_water_mark=//')"

        [[ -n "$RUNNER_MANIFEST_PATH" ]] || fail "Runner did not report a run_manifest path"
        [[ -n "$RUNNER_HWM_PATH" ]] || fail "Runner did not report a high_water_mark artifact path"
        [[ -n "$RUNNER_CANONICAL_HWM_PATH" ]] || fail "Runner did not report a canonical high_water_mark path"
        [[ -f "$RUNNER_MANIFEST_PATH" ]] || fail "Runner manifest missing: $RUNNER_MANIFEST_PATH"
        [[ -f "$RUNNER_HWM_PATH" ]] || fail "Runner high-water artifact missing: $RUNNER_HWM_PATH"
        [[ -f "$RUNNER_CANONICAL_HWM_PATH" ]] || fail "Runner canonical high-water mark missing: $RUNNER_CANONICAL_HWM_PATH"

        RUNNER_SCHEMA="$(json_field "$RUNNER_CANONICAL_HWM_PATH" '.schema_version')"
        [[ "$RUNNER_SCHEMA" == "franken-engine.test262-high-water-mark.v1" ]] \
            || fail "Runner high-water schema invalid: $RUNNER_SCHEMA"

        RUN_TOTAL_TESTS="$(json_field "$RUNNER_MANIFEST_PATH" '.total_profile_tests')"
        RUN_PASSED_TESTS="$(json_field "$RUNNER_MANIFEST_PATH" '.passed')"
        RUN_FAILED_TESTS="$(json_field "$RUNNER_MANIFEST_PATH" '.failed')"
        RUN_WAIVED_TESTS="$(json_field "$RUNNER_MANIFEST_PATH" '.waived')"
        RUN_BLOCKED_FAILURES="$(json_field "$RUNNER_MANIFEST_PATH" '.blocked_failures')"
        RUN_PROFILE_HASH="$(json_field "$RUNNER_MANIFEST_PATH" '.profile_hash')"
        RUN_HWM_PASS_COUNT="$(json_field "$RUNNER_CANONICAL_HWM_PATH" '.pass_count')"
        RUN_HWM_RECORDED_AT="$(json_field "$RUNNER_CANONICAL_HWM_PATH" '.recorded_at_utc')"
        RUN_PASS_RATE="$(calculate_rate "$RUN_PASSED_TESTS" "$RUN_TOTAL_TESTS")"

        [[ "$RUN_TOTAL_TESTS" =~ ^[0-9]+$ && "$RUN_TOTAL_TESTS" -gt 0 ]] \
            || fail "Runner reported no profile tests"
        [[ "$RUN_PASSED_TESTS" =~ ^[0-9]+$ ]] || fail "Runner passed count is invalid"
        [[ "$RUN_FAILED_TESTS" =~ ^[0-9]+$ ]] || fail "Runner failed count is invalid"
        [[ "$RUN_WAIVED_TESTS" =~ ^[0-9]+$ ]] || fail "Runner waived count is invalid"
        [[ "$RUN_BLOCKED_FAILURES" =~ ^[0-9]+$ ]] || fail "Runner blocked_failures count is invalid"
        [[ "$RUN_HWM_PASS_COUNT" =~ ^[0-9]+$ ]] || fail "Runner high-water pass_count is invalid"

        if [[ "$RUN_BLOCKED_FAILURES" -ne 0 ]]; then
            fail "Runner reported $RUN_BLOCKED_FAILURES blocked failure(s); leaving $HIGH_WATER_MARK_FILE unchanged"
        fi

        if decimal_less_than "$RUN_PASS_RATE" "$MIN_THRESHOLD"; then
            fail "Runner pass rate $RUN_PASS_RATE is below minimum threshold $MIN_THRESHOLD"
        fi

        if decimal_less_than "$RUN_PASS_RATE" "$HWM_PASS_RATE" && ! truthy "$ACKNOWLEDGE_PASS_REGRESSION"; then
            fail "Runner pass rate $RUN_PASS_RATE regressed below high-water rate $HWM_PASS_RATE; set TEST262_GATE_ACKNOWLEDGE_PASS_REGRESSION=1 to acknowledge"
        fi

        HWM_TMP="$ARTIFACTS_DIR/updated_high_water_mark.toml"
        cat > "$HWM_TMP" << EOF
schema_version = "franken-engine.test262-high-water-mark.v1"
measurement_date = "$RUN_HWM_RECORDED_AT"
es_profile = "ES2020"
created_by = "test262_regression_gate.sh update"
profile_hash = "$RUN_PROFILE_HASH"
runner_manifest = "$RUNNER_MANIFEST_PATH"
runner_high_water_mark = "$RUNNER_HWM_PATH"
runner_canonical_high_water_mark = "$RUNNER_CANONICAL_HWM_PATH"

[pass_counts]
total_tests = $RUN_TOTAL_TESTS
passed_tests = $RUN_HWM_PASS_COUNT
failed_tests = $RUN_FAILED_TESTS
skipped_tests = 0
waived_tests = $RUN_WAIVED_TESTS

[chapter_breakdown]
chapter_8_types_pass_rate = $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_8_types_pass_rate")
chapter_12_expressions_pass_rate = $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_12_expressions_pass_rate")
chapter_13_statements_pass_rate = $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_13_statements_pass_rate")
chapter_14_functions_pass_rate = $(parse_toml_value "$HIGH_WATER_MARK_FILE" "chapter_14_functions_pass_rate")

[regression_policy]
allow_pass_rate_decrease = false
min_pass_rate_threshold = $MIN_THRESHOLD
regression_acknowledgment_required = true
EOF

        mv "$HWM_TMP" "$HIGH_WATER_MARK_FILE"

        cat > "$ARTIFACTS_DIR/update_report.json" << EOF
{
  "schema_version": "franken-engine.test262-high-water-update.v1",
  "timestamp": "$(date -Iseconds)",
  "gate_mode": "update",
  "high_water_mark_file": "$HIGH_WATER_MARK_FILE",
  "previous_pass_rate": $HWM_PASS_RATE,
  "runner_pass_rate": $RUN_PASS_RATE,
  "runner_total_tests": $RUN_TOTAL_TESTS,
  "runner_passed_tests": $RUN_PASSED_TESTS,
  "persisted_pass_count": $RUN_HWM_PASS_COUNT,
  "runner_manifest": "$RUNNER_MANIFEST_PATH",
  "runner_high_water_mark": "$RUNNER_HWM_PATH",
  "runner_canonical_high_water_mark": "$RUNNER_CANONICAL_HWM_PATH",
  "regression_acknowledged": $(if truthy "$ACKNOWLEDGE_PASS_REGRESSION"; then echo true; else echo false; fi)
}
EOF

        echo "✅ Updated high-water mark: $HIGH_WATER_MARK_FILE"
        echo "📄 Update report: $ARTIFACTS_DIR/update_report.json"
        ;;

    *)
        echo "❌ Unknown gate mode: $GATE_MODE"
        echo "Usage: $0 [validate|update|report]"
        exit 1
        ;;
esac

echo ""
echo "🎯 Test262 regression gate completed"
echo "Mode: $GATE_MODE"
echo "Artifacts: $ARTIFACTS_DIR"
