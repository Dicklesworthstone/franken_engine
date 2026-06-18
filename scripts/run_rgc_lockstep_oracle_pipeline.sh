#!/bin/bash
# RGC lockstep oracle pipeline gate (bd-cixqu.9.3)
#
# Executes the full Node+Bun lockstep oracle pipeline comparing FrankenEngine
# against reference runtimes. Emits divergence/convergence verdicts with typed
# evidence atoms per the I.2 divergence classification taxonomy.
#
# Usage:
#   scripts/run_rgc_lockstep_oracle_pipeline.sh ci
#   scripts/run_rgc_lockstep_oracle_pipeline.sh dev [workload_filter]
#
# Environment:
#   RGC_LOCKSTEP_ORACLE_ARTIFACTS_DIR - Override artifacts directory
#   RGC_LOCKSTEP_ORACLE_WORKLOAD_FILTER - Filter to specific workloads
#   CARGO_INCREMENTAL - Passed through to cargo commands
#   RUSTFLAGS - Passed through to cargo commands
#
# Artifacts:
#   artifacts/lockstep_oracle/${timestamp}/
#   ├── run_manifest.json          # Artifact manifest with content hashes
#   ├── events.jsonl               # Structured event log
#   ├── commands.txt               # Shell command transcript
#   ├── summary.txt                # Operator-readable summary
#   ├── step_logs/                 # Timestamped step logs
#   │   ├── step_001_setup.log
#   │   ├── step_002_build.log
#   │   ├── step_003_workload_generation.log
#   │   ├── step_004_node_comparison.log
#   │   ├── step_005_bun_comparison.log
#   │   └── step_006_analysis.log
#   ├── workload_traces/           # Generated trace files
#   │   ├── node_traces/
#   │   ├── bun_traces/
#   │   └── franken_traces/
#   └── divergence_reports/        # Classification results
#       ├── node_vs_franken.json
#       ├── bun_vs_franken.json
#       └── evidence_atoms.jsonl

set -euo pipefail

# Logging discipline per bd-cixqu.45
if ! command -v ts >/dev/null 2>&1; then
    echo "ERROR: ts command required for timestamp logging (apt-get install moreutils)" >&2
    exit 1
fi

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly PROJECT_DIR
readonly GATE_NAME="lockstep_oracle"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly TIMESTAMP
readonly ARTIFACTS_BASE="${RGC_LOCKSTEP_ORACLE_ARTIFACTS_DIR:-${PROJECT_DIR}/artifacts}"
readonly ARTIFACTS_DIR="${ARTIFACTS_BASE}/${GATE_NAME}/${TIMESTAMP}"
readonly STEP_LOGS_DIR="${ARTIFACTS_DIR}/step_logs"
readonly WORKLOAD_TRACES_DIR="${ARTIFACTS_DIR}/workload_traces"
readonly DIVERGENCE_REPORTS_DIR="${ARTIFACTS_DIR}/divergence_reports"

# Workload configuration
readonly WORKLOAD_FILTER="${RGC_LOCKSTEP_ORACLE_WORKLOAD_FILTER:-}"

# Global state
declare -i STEP_COUNTER=1
declare -i TOTAL_WORKLOADS=0
declare -i TOTAL_COMPARISONS=0
declare -i CONVERGENT_CASES=0
declare -i DIVERGENT_CASES=0

# Utility functions
emit_event() {
    local event_type="$1"
    local event_data="$2"
    local timestamp
    timestamp=$(date -u --iso-8601=seconds)

    echo "{\"timestamp\":\"${timestamp}\",\"event\":\"${event_type}\",\"data\":${event_data}}" >> "${ARTIFACTS_DIR}/events.jsonl"
}

emit_command() {
    {
        echo "# Step ${STEP_COUNTER}: $(date -u --iso-8601=seconds)"
        echo "# Working directory: $(pwd)"
        echo "# Environment: CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-} RUSTFLAGS=${RUSTFLAGS:-}"
        echo "$*"
        echo ""
    } >> "${ARTIFACTS_DIR}/commands.txt"
}

run_step() {
    local step_name="$1"
    shift
    local step_index
    local step_log
    local start_time
    step_index=$(printf '%03d' "${STEP_COUNTER}")
    step_log="${STEP_LOGS_DIR}/step_${step_index}_${step_name}.log"
    start_time=$(date -u --iso-8601=seconds)

    {
        echo "=== Step ${STEP_COUNTER}: ${step_name} ==="
        echo "Start time: ${start_time}"
        echo "Command: $*"
        echo ""
    } | ts '%Y-%m-%dT%H:%M:%S%z ' >> "${step_log}"

    emit_command "$*"
    emit_event "step_start" "{\"step\":${STEP_COUNTER},\"name\":\"${step_name}\",\"command\":\"$*\"}"

    local wall_start
    local exit_code=0
    wall_start=$(date +%s)

    if "$@" 2>&1 | ts '%Y-%m-%dT%H:%M:%S%z ' >> "${step_log}"; then
        exit_code=0
    else
        exit_code=$?
    fi

    local wall_end
    local wall_time
    local end_time
    wall_end=$(date +%s)
    wall_time=$((wall_end - wall_start))
    end_time=$(date -u --iso-8601=seconds)

    {
        echo ""
        echo "End time: ${end_time}"
        echo "Exit code: ${exit_code}"
        echo "Wall time: ${wall_time}s"
    } | ts '%Y-%m-%dT%H:%M:%S%z ' >> "${step_log}"

    emit_event "step_complete" "{\"step\":${STEP_COUNTER},\"name\":\"${step_name}\",\"exit_code\":${exit_code},\"wall_time_s\":${wall_time}}"

    if [ ${exit_code} -ne 0 ]; then
        echo "ERROR: Step ${STEP_COUNTER} (${step_name}) failed with exit code ${exit_code}" >&2
        exit ${exit_code}
    fi

    ((STEP_COUNTER++))
}

setup_artifacts() {
    # Create initial directories before calling run_step
    mkdir -p "${ARTIFACTS_DIR}" "${STEP_LOGS_DIR}" "${WORKLOAD_TRACES_DIR}" "${DIVERGENCE_REPORTS_DIR}"

    run_step "setup" echo "Artifact directories created successfully"

    # Create trace subdirectories
    mkdir -p "${WORKLOAD_TRACES_DIR}/node_traces"
    mkdir -p "${WORKLOAD_TRACES_DIR}/bun_traces"
    mkdir -p "${WORKLOAD_TRACES_DIR}/franken_traces"

    # Initialize files
    echo "# RGC Lockstep Oracle Pipeline Command Log" > "${ARTIFACTS_DIR}/commands.txt"
    echo "# Generated: $(date -u --iso-8601=seconds)" >> "${ARTIFACTS_DIR}/commands.txt"
    echo "" >> "${ARTIFACTS_DIR}/commands.txt"

    touch "${ARTIFACTS_DIR}/events.jsonl"

    emit_event "pipeline_start" "{\"artifacts_dir\":\"${ARTIFACTS_DIR}\",\"workload_filter\":\"${WORKLOAD_FILTER}\"}"
}

build_lockstep_oracle() {
    run_step "build" cargo build --package frankenengine-engine --bin runtime-lockstep-orchestrator --bin frankenctl --release
}

generate_workload_traces() {
    local event_data
    event_data=$(jq -cn --arg workload_filter "${WORKLOAD_FILTER}" '{workload_filter:$workload_filter}')
    emit_event "workload_generation_start" "${event_data}"

    local workload_args=()
    if [[ -n "${WORKLOAD_FILTER}" ]]; then
        workload_args=(--workload "${WORKLOAD_FILTER}")
    fi

    run_step "workload_generation" "${PROJECT_DIR}/target/release/runtime-lockstep-orchestrator" \
        all \
        --traces-dir "${WORKLOAD_TRACES_DIR}" \
        "${workload_args[@]}" \
        --traces-only \
        --keep-traces

    local node_count
    local bun_count
    local franken_count
    node_count=$(find "${WORKLOAD_TRACES_DIR}/node_traces" -type f -name '*.trace.json' | wc -l | tr -d ' ')
    bun_count=$(find "${WORKLOAD_TRACES_DIR}/bun_traces" -type f -name '*.trace.json' | wc -l | tr -d ' ')
    franken_count=$(find "${WORKLOAD_TRACES_DIR}/franken_traces" -type f -name '*.trace.json' | wc -l | tr -d ' ')

    if [[ "${node_count}" -eq 0 || "${bun_count}" -eq 0 || "${franken_count}" -eq 0 ]]; then
        echo "ERROR: observed lockstep traces were not generated for every runtime (node=${node_count}, bun=${bun_count}, franken=${franken_count})" >&2
        exit 1
    fi

    if [[ "${node_count}" -ne "${franken_count}" || "${bun_count}" -ne "${franken_count}" ]]; then
        echo "ERROR: observed trace counts disagree (node=${node_count}, bun=${bun_count}, franken=${franken_count})" >&2
        exit 1
    fi

    TOTAL_WORKLOADS=${franken_count}

    emit_event "workload_generation_complete" "{\"node_traces\":${node_count},\"bun_traces\":${bun_count},\"franken_traces\":${franken_count}}"
    echo "Generated observed traces for ${TOTAL_WORKLOADS} workloads" | ts '%Y-%m-%dT%H:%M:%S%z '
}

canonicalize_generated_report() {
    local generated_prefix="$1"
    local canonical_path="$2"
    local generated_path

    generated_path=$(find "${DIVERGENCE_REPORTS_DIR}" -type f -name "${generated_prefix}*.json" | sort | tail -n 1)
    if [[ -z "${generated_path}" ]]; then
        echo "ERROR: generated report with prefix ${generated_prefix} not found" >&2
        exit 1
    fi

    cp "${generated_path}" "${canonical_path}"
}

record_report_counts() {
    local runtime_label="$1"
    local report_path="$2"

    if [[ ! -f "${report_path}" ]]; then
        echo "ERROR: ${runtime_label} comparison report not generated: ${report_path}" >&2
        exit 1
    fi

    local cases_count
    local passed_count
    local failed_count
    cases_count=$(jq -r '.summary.total_cases' "${report_path}")
    passed_count=$(jq -r '.summary.pass_cases' "${report_path}")
    failed_count=$(jq -r '.summary.failed_cases' "${report_path}")

    TOTAL_COMPARISONS=$((TOTAL_COMPARISONS + cases_count))
    CONVERGENT_CASES=$((CONVERGENT_CASES + passed_count))
    DIVERGENT_CASES=$((DIVERGENT_CASES + failed_count))

    emit_event "${runtime_label}_comparison_complete" "{\"total_cases\":${cases_count},\"passed\":${passed_count},\"failed\":${failed_count}}"
}

run_lockstep_analysis() {
    emit_event "lockstep_analysis_start" "{}"

    run_step "lockstep_analysis" "${PROJECT_DIR}/target/release/runtime-lockstep-orchestrator" \
        analyze \
        --traces-dir "${WORKLOAD_TRACES_DIR}" \
        --output-dir "${DIVERGENCE_REPORTS_DIR}" \
        --runtime all

    local node_report_path="${DIVERGENCE_REPORTS_DIR}/node_vs_franken.json"
    local bun_report_path="${DIVERGENCE_REPORTS_DIR}/bun_vs_franken.json"

    canonicalize_generated_report "node_vs_franken_report_" "${node_report_path}"
    canonicalize_generated_report "bun_vs_franken_report_" "${bun_report_path}"

    record_report_counts "node" "${node_report_path}"
    record_report_counts "bun" "${bun_report_path}"

    emit_event "lockstep_analysis_complete" "{\"total_comparisons\":${TOTAL_COMPARISONS},\"convergent_cases\":${CONVERGENT_CASES},\"divergent_cases\":${DIVERGENT_CASES}}"
}

append_divergence_evidence_atoms() {
    local runtime_pair="$1"
    local report_path="$2"
    local generated_at="$3"
    local evidence_atoms_file="$4"

    jq -c \
        --arg runtime_pair "${runtime_pair}" \
        --arg generated_at "${generated_at}" \
        '.case_results[] | select(.pass == false) | {
          schema_version: "franken-engine.divergence-evidence.v1",
          evidence_id: ($runtime_pair + ":" + .fixture_ref + ":" + .react_trace_id + ":" + .franken_trace_id),
          generated_at_utc: $generated_at,
          lockstep_case_id: .fixture_ref,
          runtime_pair: $runtime_pair,
          classification: (.divergence // {}),
          original_divergence: (.divergence // {}),
          classification_confidence: "Automated",
          evidence_sources: [{
            source_type: "ReferenceImplementation",
            identifier: $runtime_pair,
            description: "Observed lockstep oracle divergence report"
          }],
          signature: null
        }' "${report_path}" >> "${evidence_atoms_file}"
}

analyze_divergences() {
    emit_event "analysis_start" "{\"total_divergences\":${DIVERGENT_CASES}}"

    local evidence_atoms_file="${DIVERGENCE_REPORTS_DIR}/evidence_atoms.jsonl"
    local generated_at
    generated_at=$(date -u --iso-8601=seconds)

    echo "Generating evidence atoms for ${DIVERGENT_CASES} observed divergences..." | ts '%Y-%m-%dT%H:%M:%S%z '

    : > "${evidence_atoms_file}"
    append_divergence_evidence_atoms "node_vs_franken" "${DIVERGENCE_REPORTS_DIR}/node_vs_franken.json" "${generated_at}" "${evidence_atoms_file}"
    append_divergence_evidence_atoms "bun_vs_franken" "${DIVERGENCE_REPORTS_DIR}/bun_vs_franken.json" "${generated_at}" "${evidence_atoms_file}"

    local evidence_count
    evidence_count=$(jq -s 'length' "${evidence_atoms_file}")
    if [[ ${DIVERGENT_CASES} -gt 0 && "${evidence_count}" -eq 0 ]]; then
        echo "ERROR: divergence reports contain failures, but no evidence atoms were emitted" >&2
        exit 1
    else
        echo "Generated ${evidence_count} divergence evidence atoms" | ts '%Y-%m-%dT%H:%M:%S%z '
    fi

    emit_event "analysis_complete" "{\"evidence_atoms_generated\":${evidence_count}}"
}

generate_manifest() {
    local manifest_file="${ARTIFACTS_DIR}/run_manifest.json"
    local timestamp
    timestamp=$(date -u --iso-8601=seconds)

    echo "Generating artifact manifest..." | ts '%Y-%m-%dT%H:%M:%S%z '

    # Calculate content hashes for all generated files
    cat > "${manifest_file}" <<EOF
{
  "schema_version": "franken-engine.proof-artifact-manifest.v1",
  "generated_at_utc": "${timestamp}",
  "gate_name": "rgc_lockstep_oracle_pipeline",
  "run_id": "${TIMESTAMP}",
  "artifacts_base_dir": "${ARTIFACTS_DIR}",
  "summary": {
    "total_workloads": ${TOTAL_WORKLOADS},
    "total_comparisons": ${TOTAL_COMPARISONS},
    "convergent_cases": ${CONVERGENT_CASES},
    "divergent_cases": ${DIVERGENT_CASES}
  },
  "file_manifest": {
EOF

    local first=true
    while IFS= read -r file; do
        local rel_path
        local content_hash
        rel_path="${file#"${ARTIFACTS_DIR}"/}"
        content_hash=$(sha256sum "${file}" | cut -d' ' -f1)

        if [[ "${first}" == "true" ]]; then
            first=false
        else
            echo "," >> "${manifest_file}"
        fi

        echo "    \"${rel_path}\": \"sha256:${content_hash}\"" >> "${manifest_file}"
    done < <(find "${ARTIFACTS_DIR}" -type f -not -name "run_manifest.json" | sort)

    cat >> "${manifest_file}" <<EOF
  }
}
EOF

    emit_event "manifest_generated" "{\"manifest_path\":\"${manifest_file}\"}"
}

generate_summary() {
    local summary_file="${ARTIFACTS_DIR}/summary.txt"
    local end_time
    local node_trace_count
    local bun_trace_count
    local franken_trace_count
    end_time=$(date -u --iso-8601=seconds)
    node_trace_count=$(find "${WORKLOAD_TRACES_DIR}/node_traces" -type f -name '*.trace.json' | wc -l | tr -d ' ')
    bun_trace_count=$(find "${WORKLOAD_TRACES_DIR}/bun_traces" -type f -name '*.trace.json' | wc -l | tr -d ' ')
    franken_trace_count=$(find "${WORKLOAD_TRACES_DIR}/franken_traces" -type f -name '*.trace.json' | wc -l | tr -d ' ')

    cat > "${summary_file}" <<EOF
RGC Lockstep Oracle Pipeline Gate Summary
========================================

Execution completed: ${end_time}
Exit code: 0

Workloads tested: ${TOTAL_WORKLOADS}
Total runtime comparisons: ${TOTAL_COMPARISONS}
Convergent cases: ${CONVERGENT_CASES}
Divergent cases: ${DIVERGENT_CASES}

Runtime coverage:
  - Node.js vs FrankenEngine: ${node_trace_count} traces
  - Bun vs FrankenEngine: ${bun_trace_count} traces
  - FrankenEngine reference: ${franken_trace_count} traces

Artifacts generated:
  - Trace files: ${WORKLOAD_TRACES_DIR}/
  - Comparison reports: ${DIVERGENCE_REPORTS_DIR}/
  - Evidence atoms: ${DIVERGENCE_REPORTS_DIR}/evidence_atoms.jsonl
  - Step logs: ${STEP_LOGS_DIR}/
  - Event log: events.jsonl
  - Command transcript: commands.txt

All lockstep oracle pipeline components executed successfully.
Divergence classification taxonomy (I.2) applied to all cases.
Ready for operator review and triage.
EOF

    echo "Generated summary: ${summary_file}" | ts '%Y-%m-%dT%H:%M:%S%z '
}

main() {
    local mode="${1:-}"

    if [[ "${mode}" != "ci" && "${mode}" != "dev" ]]; then
        echo "Usage: $0 {ci|dev} [workload_filter]" >&2
        echo "" >&2
        echo "Modes:" >&2
        echo "  ci  - Full CI mode with all workloads" >&2
        echo "  dev - Development mode with optional workload filter" >&2
        exit 1
    fi

    if [[ "${mode}" == "dev" && -n "${2:-}" ]]; then
        export RGC_LOCKSTEP_ORACLE_WORKLOAD_FILTER="$2"
    fi

    echo "Starting RGC lockstep oracle pipeline in ${mode} mode..." | ts '%Y-%m-%dT%H:%M:%S%z '

    # Verify required tools
    for tool in jq node bun cargo; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "ERROR: Required tool '${tool}' not found in PATH" >&2
            exit 1
        fi
    done

    setup_artifacts
    build_lockstep_oracle
    generate_workload_traces
    run_lockstep_analysis
    analyze_divergences
    generate_manifest
    generate_summary

    emit_event "pipeline_complete" "{\"mode\":\"${mode}\",\"artifacts_dir\":\"${ARTIFACTS_DIR}\",\"exit_code\":0}"

    echo "RGC lockstep oracle pipeline completed successfully!" | ts '%Y-%m-%dT%H:%M:%S%z '
    echo "Artifacts: ${ARTIFACTS_DIR}" | ts '%Y-%m-%dT%H:%M:%S%z '
    echo "Summary: ${ARTIFACTS_DIR}/summary.txt" | ts '%Y-%m-%dT%H:%M:%S%z '

    return 0
}

main "$@"
