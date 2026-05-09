#!/usr/bin/env bash
set -euo pipefail

# Test262 Baseline Pass Rate Measurement Script
# Part of bd-6a61n.1.8 (RC-1.8) implementation. This wrapper publishes only
# measured checked-in vector evidence; it does not emit estimated pass rates.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts/test262/$TIMESTAMP"
LOGS_DIR="$ARTIFACTS_DIR/logs"
RUNNER_OUTPUT_ROOT="$ARTIFACTS_DIR/runner"
RUN_DATE="${TEST262_BASELINE_RUN_DATE:-$(date -u +%Y-%m-%d)}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${TEST262_BASELINE_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_test262_baseline_${TIMESTAMP}}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
RCH_TIMEOUT_SECONDS="${RCH_EXEC_TIMEOUT_SECONDS:-900}"

echo "🧪 Test262 Baseline Pass Rate Measurement"
echo "Timestamp: $TIMESTAMP"
echo "Artifacts: $ARTIFACTS_DIR"
echo "RCH target dir: $CARGO_TARGET_DIR"

mkdir -p "$ARTIFACTS_DIR" "$LOGS_DIR" "$RUNNER_OUTPUT_ROOT"

# Configuration paths
PINS="$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_pins.toml"
PROFILE="$PROJECT_ROOT/crates/franken-engine/tests/test262_es2020_profile.toml"
WAIVERS="$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_waivers.toml"
CASE_VECTORS="$PROJECT_ROOT/crates/franken-engine/tests/test262_case_vectors.jsonl"
CANONICAL_HWM="$ARTIFACTS_DIR/canonical_high_water_mark.json"
COMMANDS_LOG="$ARTIFACTS_DIR/commands.txt"
EVENTS_LOG="$ARTIFACTS_DIR/events.jsonl"
RUN_MANIFEST="$ARTIFACTS_DIR/run_manifest.json"
BASELINE_REPORT="$ARTIFACTS_DIR/baseline_report.json"
: > "$COMMANDS_LOG"
: > "$EVENTS_LOG"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "❌ Required rch binary not found: $RCH_BIN" >&2
    exit 127
fi

# Check if Test262 suite is available. This baseline intentionally does not
# claim a full official suite run when only checked-in derived vectors exist.
TEST262_DIR="$PROJECT_ROOT/test262"
FULL_SUITE_AVAILABLE=false
if [[ ! -d "$TEST262_DIR" ]]; then
    echo "⚠️  Test262 suite not found at $TEST262_DIR"
    echo "Using checked-in Test262-derived case vectors only; full-suite claim remains disabled."
else
    FULL_SUITE_AVAILABLE=true
fi

# Log configuration
echo "📋 Configuration:"
echo "  Pins: $PINS"
echo "  Profile: $PROFILE"
echo "  Waivers: $WAIVERS"
echo "  Case Vectors: $CASE_VECTORS"

write_event() {
    local step="$1"
    local status="$2"
    local exit_code="$3"
    local log_path="$4"
    jq -nc \
        --arg step "$step" \
        --arg status "$status" \
        --argjson exit_code "$exit_code" \
        --arg log_path "$log_path" \
        --arg timestamp "$(date -Iseconds)" \
        '{step:$step,status:$status,exit_code:$exit_code,log_path:$log_path,timestamp:$timestamp}' >> "$EVENTS_LOG"
}

run_rch_step() {
    local step="$1"
    local log_path="$LOGS_DIR/${step}.log"
    local exit_code
    shift

    {
        printf 'rch exec -- env CARGO_TARGET_DIR=%q CARGO_BUILD_JOBS=%q CARGO_INCREMENTAL=%q cargo' \
            "$CARGO_TARGET_DIR" "$CARGO_BUILD_JOBS" "$CARGO_INCREMENTAL"
        printf ' %q' "$@"
        printf '\n'
    } >> "$COMMANDS_LOG"

    if timeout "$RCH_TIMEOUT_SECONDS" "$RCH_BIN" exec -- env \
        "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
        "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
        "CARGO_INCREMENTAL=$CARGO_INCREMENTAL" \
        cargo "$@" > "$log_path" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi

    if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$log_path"; then
        echo "❌ rch local fallback detected for $step" >&2
        exit_code=1
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        write_event "$step" "pass" "$exit_code" "$log_path"
        return 0
    fi

    write_event "$step" "fail" "$exit_code" "$log_path"
    echo "❌ Step failed: $step (see $log_path)" >&2
    return "$exit_code"
}

# Validate configuration files
echo "📝 Validating Test262 configuration..."

# Check pins file
if [[ -f "$PINS" ]]; then
    echo "✅ Found pins configuration: $PINS"
    grep -E "^(schema_version|source_repo|es_profile|test262_commit)" "$PINS" | head -4
else
    echo "❌ Missing pins configuration: $PINS"
    exit 1
fi

# Check profile file
if [[ -f "$PROFILE" ]]; then
    echo "✅ Found profile configuration: $PROFILE"
    echo "Profile includes $(grep -c "\\[\\[include\\]\\]" "$PROFILE") include patterns"
    echo "Profile excludes $(grep -c "\\[\\[exclude\\]\\]" "$PROFILE") exclude patterns"
else
    echo "❌ Missing profile configuration: $PROFILE"
    exit 1
fi

# Check waivers file
if [[ -f "$WAIVERS" ]]; then
    echo "✅ Found waivers configuration: $WAIVERS"
    echo "Current waivers: $(grep -c "\\[\\[waiver\\]\\]" "$WAIVERS") tests"
else
    echo "❌ Missing waivers configuration: $WAIVERS"
    exit 1
fi

if [[ -f "$CASE_VECTORS" ]]; then
    echo "✅ Found checked-in case vectors: $CASE_VECTORS"
    echo "Case vectors: $(wc -l < "$CASE_VECTORS")"
    jq -c . "$CASE_VECTORS" >/dev/null
else
    echo "❌ Missing case vectors: $CASE_VECTORS"
    exit 1
fi

cd "$PROJECT_ROOT"

echo "🔨 Checking Test262 runner..."
run_rch_step check_runner check -p frankenengine-engine --bin franken_test262_runner

echo "🚀 Running checked-in Test262-derived vector baseline..."
run_rch_step run_checked_in_vectors run -p frankenengine-engine --bin franken_test262_runner -- \
    --pins "$PINS" \
    --profile "$PROFILE" \
    --waivers "$WAIVERS" \
    --case-vectors "$CASE_VECTORS" \
    --output-root "$RUNNER_OUTPUT_ROOT" \
    --high-water-mark "$CANONICAL_HWM" \
    --run-date "$RUN_DATE"

RUNNER_LOG="$LOGS_DIR/run_checked_in_vectors.log"
RUNNER_MANIFEST="$(grep -Eo 'test262 run_manifest=.*' "$RUNNER_LOG" | tail -n 1 | sed 's/.*test262 run_manifest=//' || true)"
RUNNER_EVIDENCE="$(grep -Eo 'test262 evidence=.*' "$RUNNER_LOG" | tail -n 1 | sed 's/.*test262 evidence=//' || true)"
RUNNER_HWM="$(grep -Eo 'test262 high_water_mark=.*' "$RUNNER_LOG" | tail -n 1 | sed 's/.*test262 high_water_mark=//' || true)"
RUNNER_CANONICAL_HWM="$(grep -Eo 'test262 canonical_high_water_mark=.*' "$RUNNER_LOG" | tail -n 1 | sed 's/.*test262 canonical_high_water_mark=//' || true)"

[[ -n "$RUNNER_MANIFEST" && -f "$RUNNER_MANIFEST" ]] || { echo "❌ Runner manifest not found in $RUNNER_LOG" >&2; exit 1; }
[[ -n "$RUNNER_EVIDENCE" && -f "$RUNNER_EVIDENCE" ]] || { echo "❌ Runner evidence not found in $RUNNER_LOG" >&2; exit 1; }
[[ -n "$RUNNER_HWM" && -f "$RUNNER_HWM" ]] || { echo "❌ Runner high-water mark not found in $RUNNER_LOG" >&2; exit 1; }
[[ -n "$RUNNER_CANONICAL_HWM" && -f "$RUNNER_CANONICAL_HWM" ]] || { echo "❌ Runner canonical high-water mark not found in $RUNNER_LOG" >&2; exit 1; }

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg run_date "$RUN_DATE" \
    --arg pins "$PINS" \
    --arg profile "$PROFILE" \
    --arg waivers "$WAIVERS" \
    --arg case_vectors "$CASE_VECTORS" \
    --arg runner_manifest "$RUNNER_MANIFEST" \
    --arg runner_evidence "$RUNNER_EVIDENCE" \
    --arg runner_high_water_mark "$RUNNER_HWM" \
    --arg runner_canonical_high_water_mark "$RUNNER_CANONICAL_HWM" \
    --argjson full_suite_available "$FULL_SUITE_AVAILABLE" \
    '{
      schema_version: "franken-engine.test262-baseline-report.v2",
      timestamp: $timestamp,
      run_date: $run_date,
      proof_state: "checked_in_vectors_provisional",
      claim_scope: "checked_in_test262_derived_vectors",
      full_suite_claim_allowed: false,
      full_suite_available: $full_suite_available,
      configuration: {
        pins_path: $pins,
        profile_path: $profile,
        waivers_path: $waivers,
        case_vectors_path: $case_vectors
      },
      runner_artifacts: {
        run_manifest: $runner_manifest,
        evidence: $runner_evidence,
        high_water_mark: $runner_high_water_mark,
        canonical_high_water_mark: $runner_canonical_high_water_mark
      },
      limitations: [
        "checked-in vector profile, not a full official Test262 suite run",
        "full official Test262 pass-rate claims require an official checkout run",
        "this script does not emit estimated pass rates or template high-water marks"
      ]
    }' > "$BASELINE_REPORT"

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg component "test262_baseline_measurement" \
    --arg outcome "pass" \
    --arg commands "$COMMANDS_LOG" \
    --arg events "$EVENTS_LOG" \
    --arg baseline_report "$BASELINE_REPORT" \
    --arg runner_manifest "$RUNNER_MANIFEST" \
    --arg cargo_target_dir "$CARGO_TARGET_DIR" \
    '{
      schema_version: "franken-engine.test262-baseline-run.v2",
      timestamp: $timestamp,
      component: $component,
      outcome: $outcome,
      cargo_target_dir: $cargo_target_dir,
      purpose: "checked_in_vector_baseline_measurement",
      artifact_paths: {
        commands: $commands,
        events: $events,
        baseline_report: $baseline_report,
        runner_manifest: $runner_manifest
      }
    }' > "$RUN_MANIFEST"

# Summary
echo "🎯 Test262 baseline measurement setup completed"
echo ""
echo "📁 Artifacts generated in: $ARTIFACTS_DIR"
echo "  - run_manifest.json: Run configuration and metadata"
echo "  - baseline_report.json: measured checked-in vector baseline with limitations"
echo "  - events.jsonl: rch-backed command events"
echo "  - commands.txt: command transcript"
echo "  - logs/: rch command logs"
echo ""
echo "🚀 Next steps:"
echo "  1. Ensure a pinned official tc39/test262 checkout is available for full-suite claims"
echo "  2. Refresh checked-in vectors with franken_test262_generator when the pin changes"
echo "  3. Use scripts/run_test262_es2020_gate.sh for release gating"
echo ""
echo "✅ Baseline measurement infrastructure ready"
