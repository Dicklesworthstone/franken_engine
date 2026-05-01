#!/usr/bin/env bash
set -euo pipefail

# Aggregate proof-suite runner for bd-mtpwv.
#
# Runs all proof gates in deterministic order and produces combined reports.
# This is the final user-facing proof entry point that aggregates individual
# gate results without masking or downgrading failures.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
suite_root="${PROOF_SUITE_ARTIFACT_ROOT:-artifacts/proof_suite}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${suite_root}/${timestamp}"
events_path="${run_dir}/events.jsonl"
report_path="${run_dir}/proof_suite_report.json"
commands_path="${run_dir}/commands.txt"
markdown_path="${run_dir}/report.md"

mkdir -p "$run_dir"
printf './scripts/run_proof_suite.sh %s\n' "$mode" >"$commands_path"

# Use focused CARGO_TARGET_DIR as required
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_PearlTower_focused}"
mkdir -p "$CARGO_TARGET_DIR"

echo "🚀 FrankenEngine Proof Suite Runner"
echo "   Mode: $mode"
echo "   Run directory: $run_dir"
echo "   Cargo target: $CARGO_TARGET_DIR"
echo ""

# Define proof gates in deterministic order
# Based on the beads mentioned: bd-y6v8s, bd-1vwza, bd-2488a, bd-38mby, bd-1qr4f, bd-1bao8, bd-1py8v, bd-3mp80, bd-dpfvh, bd-1ypps
declare -a PROOF_GATES=(
    # Core claim matrix (foundation)
    "claim_to_proof_matrix:./scripts/run_claim_to_proof_matrix_gate.sh:bd-1qkrc"

    # Live security examples (bd-1ypps, bd-1py8v, bd-dpfvh)
    "live_guardplane_decision:./scripts/e2e/live_guardplane_decision_smoke.sh:bd-1ypps"
    "live_ifc_declassification:./scripts/e2e/live_ifc_declassification_smoke.sh:bd-dpfvh"
    "live_quarantine_propagation:CARGO_TARGET_DIR=${CARGO_TARGET_DIR} cargo run --example live_quarantine_propagation_example --no-default-features:bd-1py8v"

    # Disruptive-floor metric gates (bd-y6v8s, bd-1vwza, bd-38mby, bd-2488a)
    "throughput_disruptive_floor:./scripts/run_throughput_disruptive_floor_metric_gate.sh:bd-y6v8s"
    "compromise_rate_disruptive_floor:./scripts/run_compromise_rate_disruptive_floor_metric_gate.sh:bd-1vwza"
    "containment_latency_metric:./scripts/run_containment_latency_metric_gate.sh:bd-38mby"
    "replay_coverage_metric:./scripts/run_replay_coverage_metric_gate.sh:bd-2488a"

    # Additional gates (bd-1bao8, bd-3mp80, bd-1qr4f)
    "production_feature_catalog:./scripts/run_production_feature_catalog_gate.sh:bd-3mp80"
    "readme_cli_proof_contract:./scripts/e2e/readme_cli_proof_contract_validation.sh:bd-1qr4f"
)

# Track results
total_gates=${#PROOF_GATES[@]}
passed_gates=0
failed_gates=0
skipped_gates=0
gate_results=()

json_string() {
  jq -Rn --arg value "$1" '$value'
}

emit_suite_event() {
  local gate_name="$1"
  local gate_command="$2"
  local gate_bead="$3"
  local gate_status="$4"
  local gate_exit_code="$5"
  local gate_duration_ms="$6"
  local gate_error="${7:-}"

  jq -nc \
    --arg gate_name "$gate_name" \
    --arg gate_command "$gate_command" \
    --arg gate_bead "$gate_bead" \
    --arg gate_status "$gate_status" \
    --arg gate_exit_code "$gate_exit_code" \
    --arg gate_duration_ms "$gate_duration_ms" \
    --arg gate_error "$gate_error" \
    '{
      schema_version: "'"$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION"'",
      event_name: "proof_suite.gate_executed",
      severity: (if $gate_status == "pass" then "info" else "error" end),
      step_id: $gate_name,
      command_id: "proof-suite-runner",
      gate_name: $gate_name,
      gate_command: $gate_command,
      gate_bead: $gate_bead,
      gate_status: $gate_status,
      gate_exit_code: ($gate_exit_code | tonumber),
      gate_duration_ms: ($gate_duration_ms | tonumber),
      gate_error: (if $gate_error == "" then null else $gate_error end)
    }' >>"$events_path"
}

echo "Executing ${total_gates} proof gates..."
echo ""

# Execute each gate
for gate_spec in "${PROOF_GATES[@]}"; do
    IFS=':' read -r gate_name gate_command gate_bead <<< "$gate_spec"

    echo "🔍 Running ${gate_name} (${gate_bead})"
    echo "   Command: ${gate_command}"

    gate_start_time=$(date +%s%3N)
    gate_exit_code=0
    gate_output=""
    gate_status="pass"
    gate_error=""

    # Capture both stdout and stderr, preserve exit code
    if gate_output=$(eval "$gate_command" 2>&1); then
        gate_exit_code=0
        gate_status="pass"
        passed_gates=$((passed_gates + 1))
        echo "   ✅ PASSED"
    else
        gate_exit_code=$?
        gate_status="fail"
        gate_error="Gate failed with exit code $gate_exit_code"
        failed_gates=$((failed_gates + 1))
        echo "   ❌ FAILED (exit code: $gate_exit_code)"

        # Show first few lines of error output
        if [[ -n "$gate_output" ]]; then
            echo "   Error preview:"
            echo "$gate_output" | head -3 | sed 's/^/      /'
        fi
    fi

    gate_end_time=$(date +%s%3N)
    gate_duration=$((gate_end_time - gate_start_time))

    # Store result for summary
    gate_results+=("$gate_name:$gate_status:$gate_exit_code:$gate_duration:$gate_bead")

    # Emit event
    emit_suite_event \
        "$gate_name" \
        "$gate_command" \
        "$gate_bead" \
        "$gate_status" \
        "$gate_exit_code" \
        "$gate_duration" \
        "$gate_error"

    echo ""
done

# Determine overall verdict
if [[ $failed_gates -eq 0 ]]; then
    overall_verdict="pass"
    overall_status="✅ ALL GATES PASSED"
else
    overall_verdict="fail"
    overall_status="❌ ${failed_gates}/${total_gates} GATES FAILED"
fi

# Generate JSON report
jq -n \
  --arg schema_version "franken-engine.proof-suite-report.v1" \
  --arg suite_mode "$mode" \
  --arg suite_verdict "$overall_verdict" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --argjson total_gates "$total_gates" \
  --argjson passed_gates "$passed_gates" \
  --argjson failed_gates "$failed_gates" \
  --argjson skipped_gates "$skipped_gates" \
  --slurpfile events "$events_path" \
  '{
    schema_version: $schema_version,
    suite_mode: $suite_mode,
    suite_verdict: $suite_verdict,
    events_path: $events_path,
    commands_path: $commands_path,
    summary: {
      total_gates: $total_gates,
      passed_gates: $passed_gates,
      failed_gates: $failed_gates,
      skipped_gates: $skipped_gates
    },
    gate_results: $events,
    generated_at_utc: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
  }' >"$report_path"

# Generate markdown report
cat > "$markdown_path" <<EOF
# FrankenEngine Proof Suite Report

**Generated**: $(date -u +%Y-%m-%d\ %H:%M:%S\ UTC)
**Mode**: $mode
**Verdict**: $overall_verdict

## Summary

- **Total gates**: $total_gates
- **Passed**: $passed_gates
- **Failed**: $failed_gates
- **Skipped**: $skipped_gates

## Gate Results

EOF

# Add gate results table
echo "| Gate | Status | Duration | Bead | Command |" >> "$markdown_path"
echo "|------|--------|----------|------|---------|" >> "$markdown_path"

for result in "${gate_results[@]}"; do
    IFS=':' read -r gate_name gate_status gate_exit_code gate_duration gate_bead <<< "$result"

    if [[ "$gate_status" == "pass" ]]; then
        status_emoji="✅"
    else
        status_emoji="❌"
    fi

    echo "| \`$gate_name\` | $status_emoji $gate_status | ${gate_duration}ms | \`$gate_bead\` | See events.jsonl |" >> "$markdown_path"
done

if [[ $failed_gates -gt 0 ]]; then
    echo "" >> "$markdown_path"
    echo "## Failed Gates" >> "$markdown_path"
    echo "" >> "$markdown_path"

    for result in "${gate_results[@]}"; do
        IFS=':' read -r gate_name gate_status gate_exit_code gate_duration gate_bead <<< "$result"

        if [[ "$gate_status" != "pass" ]]; then
            echo "### $gate_name (exit code: $gate_exit_code)" >> "$markdown_path"
            echo "" >> "$markdown_path"
            echo "**Bead**: $gate_bead" >> "$markdown_path"
            echo "**Duration**: ${gate_duration}ms" >> "$markdown_path"
            echo "" >> "$markdown_path"
            echo "Check the events.jsonl file for detailed error information." >> "$markdown_path"
            echo "" >> "$markdown_path"
        fi
    done
fi

cat >> "$markdown_path" <<EOF

## Artifacts Generated

- \`events.jsonl\`: Detailed gate execution events
- \`commands.txt\`: Command transcript
- \`report.json\`: Machine-readable report
- \`manifest.json\`: Proof artifact manifest

## Rerun Instructions

To rerun the entire suite:
\`\`\`bash
./scripts/run_proof_suite.sh ci
\`\`\`

To rerun a specific failed gate, check the command in the gate results table above.

---
*Generated by FrankenEngine Proof Suite Runner (bd-mtpwv)*
EOF

# Generate proof artifact bundle
proof_contract_write_standard_bundle \
  "$run_dir" \
  "proof_suite" \
  "$overall_verdict" \
  "./scripts/run_proof_suite.sh ${mode}" \
  "$report_path" \
  "$events_path" \
  "$commands_path" \
  "bd-mtpwv" \
  "" \
  "$failed_gates"

echo "📊 Proof Suite Results:"
echo "   $overall_status"
echo ""
echo "📁 Artifacts:"
echo "   Report: $report_path"
echo "   Events: $events_path"
echo "   Manifest: ${run_dir}/manifest.json"
echo "   Markdown: $markdown_path"

if [[ "$overall_verdict" == "fail" ]]; then
    echo ""
    echo "❌ Failed gates:"
    jq -r '.gate_results[] | select(.gate_status != "pass") | "   \(.gate_name): \(.gate_error // "unknown error")"' "$report_path"
    exit 1
fi

exit 0