#!/bin/bash
# RGC lockstep oracle pipeline replay wrapper (bd-cixqu.9.3)
#
# Replays a previously captured lockstep oracle pipeline run for verification,
# regression testing, and divergence analysis comparison.
#
# Usage:
#   scripts/e2e/rgc_lockstep_oracle_pipeline_replay.sh
#   RGC_LOCKSTEP_ORACLE_PIPELINE_REPLAY_RUN_DIR=path/to/run scripts/e2e/rgc_lockstep_oracle_pipeline_replay.sh
#
# Environment:
#   RGC_LOCKSTEP_ORACLE_PIPELINE_REPLAY_RUN_DIR - Pin to specific preserved bundle
#   RGC_LOCKSTEP_ORACLE_ARTIFACTS_DIR - Override artifacts base directory
#
# Exit codes:
#   0 - Replay completed successfully
#   1 - No complete bundle found
#   2 - Bundle validation failed
#   3 - Replay diverged from recorded run

set -euo pipefail

# Logging discipline per bd-cixqu.45
if ! command -v ts >/dev/null 2>&1; then
    echo "ERROR: ts command required for timestamp logging (apt-get install moreutils)" >&2
    exit 1
fi

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly GATE_SCRIPT="${PROJECT_DIR}/scripts/run_rgc_lockstep_oracle_pipeline.sh"
readonly ARTIFACTS_BASE="${RGC_LOCKSTEP_ORACLE_ARTIFACTS_DIR:-${PROJECT_DIR}/artifacts}"
readonly LOCKSTEP_ORACLE_ARTIFACTS_DIR="${ARTIFACTS_BASE}/lockstep_oracle"

# Replay configuration
readonly REPLAY_RUN_DIR="${RGC_LOCKSTEP_ORACLE_PIPELINE_REPLAY_RUN_DIR:-}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_ARTIFACTS_DIR="${ARTIFACTS_BASE}/lockstep_oracle_replay/${TIMESTAMP}"

find_latest_complete_bundle() {
    echo "Searching for complete lockstep oracle bundles..." | ts '%Y-%m-%dT%H:%M:%S%z '

    if [[ ! -d "${LOCKSTEP_ORACLE_ARTIFACTS_DIR}" ]]; then
        echo "ERROR: No lockstep oracle artifacts directory found: ${LOCKSTEP_ORACLE_ARTIFACTS_DIR}" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    local latest_complete=""
    local latest_timestamp=""

    # Find all potential run directories
    for run_dir in "${LOCKSTEP_ORACLE_ARTIFACTS_DIR}"/*/; do
        if [[ ! -d "${run_dir}" ]]; then
            continue
        fi

        local run_timestamp=$(basename "${run_dir}")

        # Validate bundle completeness
        if validate_bundle_completeness "${run_dir}"; then
            if [[ -z "${latest_timestamp}" ]] || [[ "${run_timestamp}" > "${latest_timestamp}" ]]; then
                latest_complete="${run_dir}"
                latest_timestamp="${run_timestamp}"
            fi
        else
            echo "WARNING: Incomplete bundle found, skipping: ${run_dir}" | ts '%Y-%m-%dT%H:%M:%S%z '
        fi
    done

    if [[ -z "${latest_complete}" ]]; then
        echo "ERROR: No complete lockstep oracle bundles found in ${LOCKSTEP_ORACLE_ARTIFACTS_DIR}" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    echo "Found latest complete bundle: ${latest_complete}" | ts '%Y-%m-%dT%H:%M:%S%z '
    echo "${latest_complete}"
}

validate_bundle_completeness() {
    local bundle_dir="$1"

    # Check required files
    local required_files=(
        "run_manifest.json"
        "events.jsonl"
        "commands.txt"
        "summary.txt"
    )

    local required_dirs=(
        "step_logs"
        "workload_traces"
        "divergence_reports"
    )

    for file in "${required_files[@]}"; do
        if [[ ! -f "${bundle_dir}/${file}" ]]; then
            echo "Missing required file: ${bundle_dir}/${file}" | ts '%Y-%m-%dT%H:%M:%S%z '
            return 1
        fi
    done

    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "${bundle_dir}/${dir}" ]]; then
            echo "Missing required directory: ${bundle_dir}/${dir}" | ts '%Y-%m-%dT%H:%M:%S%z '
            return 1
        fi
    done

    # Validate manifest integrity
    if ! jq -e '.schema_version' "${bundle_dir}/run_manifest.json" >/dev/null 2>&1; then
        echo "Invalid manifest file: ${bundle_dir}/run_manifest.json" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    # Check for step logs
    if [[ ! -f "${bundle_dir}/step_logs/step_001_setup.log" ]]; then
        echo "Missing step logs in: ${bundle_dir}/step_logs/" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    # Validate traces exist
    if [[ ! -d "${bundle_dir}/workload_traces/node_traces" ]] || \
       [[ ! -d "${bundle_dir}/workload_traces/bun_traces" ]] || \
       [[ ! -d "${bundle_dir}/workload_traces/franken_traces" ]]; then
        echo "Missing trace directories in: ${bundle_dir}/workload_traces/" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    echo "Bundle completeness validated: ${bundle_dir}" | ts '%Y-%m-%dT%H:%M:%S%z '
    return 0
}

verify_bundle_integrity() {
    local bundle_dir="$1"
    local manifest_file="${bundle_dir}/run_manifest.json"

    echo "Verifying bundle integrity using manifest..." | ts '%Y-%m-%dT%H:%M:%S%z '

    # Verify all files listed in manifest exist and have correct hashes
    local verification_failed=false

    jq -r '.file_manifest | to_entries[] | "\(.key) \(.value)"' "${manifest_file}" | while read -r file_path expected_hash; do
        local full_path="${bundle_dir}/${file_path}"

        if [[ ! -f "${full_path}" ]]; then
            echo "ERROR: Manifest file missing: ${full_path}" | ts '%Y-%m-%dT%H:%M:%S%z '
            verification_failed=true
            continue
        fi

        local actual_hash="sha256:$(sha256sum "${full_path}" | cut -d' ' -f1)"
        if [[ "${actual_hash}" != "${expected_hash}" ]]; then
            echo "ERROR: Hash mismatch for ${file_path}: expected ${expected_hash}, got ${actual_hash}" | ts '%Y-%m-%dT%H:%M:%S%z '
            verification_failed=true
        fi
    done

    if [[ "${verification_failed}" == "true" ]]; then
        echo "ERROR: Bundle integrity verification failed" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    echo "Bundle integrity verified successfully" | ts '%Y-%m-%dT%H:%M:%S%z '
    return 0
}

setup_replay_environment() {
    local original_bundle="$1"

    echo "Setting up replay environment..." | ts '%Y-%m-%dT%H:%M:%S%z '

    mkdir -p "${REPLAY_ARTIFACTS_DIR}"

    # Copy original bundle for reference
    cp -r "${original_bundle}" "${REPLAY_ARTIFACTS_DIR}/original_bundle"

    # Initialize replay artifacts
    mkdir -p "${REPLAY_ARTIFACTS_DIR}/replay_run"
    mkdir -p "${REPLAY_ARTIFACTS_DIR}/comparison"

    echo "Replay environment ready: ${REPLAY_ARTIFACTS_DIR}" | ts '%Y-%m-%dT%H:%M:%S%z '
}

run_replay() {
    local original_bundle="$1"
    local replay_run_dir="${REPLAY_ARTIFACTS_DIR}/replay_run"

    echo "Executing lockstep oracle pipeline replay..." | ts '%Y-%m-%dT%H:%M:%S%z '

    # Extract workload configuration from original run
    local original_manifest="${original_bundle}/run_manifest.json"
    local original_workloads_count=$(jq -r '.summary.total_workloads' "${original_manifest}")

    echo "Original run had ${original_workloads_count} workloads" | ts '%Y-%m-%dT%H:%M:%S%z '

    # Execute gate script in dev mode
    export RGC_LOCKSTEP_ORACLE_ARTIFACTS_DIR="${REPLAY_ARTIFACTS_DIR}"

    if ! "${GATE_SCRIPT}" dev 2>&1 | ts '%Y-%m-%dT%H:%M:%S%z '; then
        echo "ERROR: Replay execution failed" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    # Find the generated replay run directory
    local actual_replay_dir
    actual_replay_dir=$(find "${REPLAY_ARTIFACTS_DIR}/lockstep_oracle" -maxdepth 1 -type d -name "*T*Z" | head -1)

    if [[ -z "${actual_replay_dir}" ]] || [[ ! -d "${actual_replay_dir}" ]]; then
        echo "ERROR: Replay run directory not found" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 1
    fi

    echo "Replay execution completed: ${actual_replay_dir}" | ts '%Y-%m-%dT%H:%M:%S%z '
    echo "${actual_replay_dir}"
}

compare_runs() {
    local original_bundle="$1"
    local replay_bundle="$2"
    local comparison_dir="${REPLAY_ARTIFACTS_DIR}/comparison"

    echo "Comparing original and replay runs..." | ts '%Y-%m-%dT%H:%M:%S%z '

    # Compare manifests
    local comparison_report="${comparison_dir}/comparison_report.json"
    local original_manifest="${original_bundle}/run_manifest.json"
    local replay_manifest="${replay_bundle}/run_manifest.json"

    local original_summary=$(jq '.summary' "${original_manifest}")
    local replay_summary=$(jq '.summary' "${replay_manifest}")

    cat > "${comparison_report}" <<EOF
{
  "comparison_timestamp": "$(date -u --iso-8601=seconds)",
  "original_bundle": "${original_bundle}",
  "replay_bundle": "${replay_bundle}",
  "summary_comparison": {
    "original": ${original_summary},
    "replay": ${replay_summary}
  },
  "differences": []
}
EOF

    # Compare key metrics
    local differences=false

    local orig_workloads=$(jq -r '.summary.total_workloads' "${original_manifest}")
    local replay_workloads=$(jq -r '.summary.total_workloads' "${replay_manifest}")

    if [[ "${orig_workloads}" != "${replay_workloads}" ]]; then
        echo "DIFFERENCE: Workload count mismatch - original: ${orig_workloads}, replay: ${replay_workloads}" | ts '%Y-%m-%dT%H:%M:%S%z '
        differences=true
    fi

    local orig_comparisons=$(jq -r '.summary.total_comparisons' "${original_manifest}")
    local replay_comparisons=$(jq -r '.summary.total_comparisons' "${replay_manifest}")

    if [[ "${orig_comparisons}" != "${replay_comparisons}" ]]; then
        echo "DIFFERENCE: Comparison count mismatch - original: ${orig_comparisons}, replay: ${replay_comparisons}" | ts '%Y-%m-%dT%H:%M:%S%z '
        differences=true
    fi

    # Generate side-by-side diff for manifests
    diff -u "${original_manifest}" "${replay_manifest}" > "${comparison_dir}/manifest_diff.txt" || true

    # Generate side-by-side diff for summaries
    diff -u "${original_bundle}/summary.txt" "${replay_bundle}/summary.txt" > "${comparison_dir}/summary_diff.txt" || true

    if [[ "${differences}" == "true" ]]; then
        echo "WARNING: Differences detected between original and replay runs" | ts '%Y-%m-%dT%H:%M:%S%z '
        echo "See comparison report: ${comparison_report}" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 3
    else
        echo "No significant differences detected between runs" | ts '%Y-%m-%dT%H:%M:%S%z '
        return 0
    fi
}

generate_replay_summary() {
    local original_bundle="$1"
    local replay_bundle="$2"
    local comparison_result="$3"
    local summary_file="${REPLAY_ARTIFACTS_DIR}/replay_summary.txt"

    local end_time=$(date -u --iso-8601=seconds)

    cat > "${summary_file}" <<EOF
RGC Lockstep Oracle Pipeline Replay Summary
===========================================

Replay completed: ${end_time}
Exit code: ${comparison_result}

Original bundle: ${original_bundle}
Replay bundle: ${replay_bundle}

Bundle verification: $(if validate_bundle_completeness "${original_bundle}"; then echo "PASSED"; else echo "FAILED"; fi)
Bundle integrity: $(if verify_bundle_integrity "${original_bundle}"; then echo "PASSED"; else echo "FAILED"; fi)
Replay execution: $(if [[ -n "${replay_bundle}" ]]; then echo "COMPLETED"; else echo "FAILED"; fi)
Run comparison: $(if [[ ${comparison_result} -eq 0 ]]; then echo "NO DIFFERENCES"; elif [[ ${comparison_result} -eq 3 ]]; then echo "DIFFERENCES DETECTED"; else echo "FAILED"; fi)

Artifacts:
  - Original bundle: ${REPLAY_ARTIFACTS_DIR}/original_bundle/
  - Replay run: ${replay_bundle}
  - Comparison report: ${REPLAY_ARTIFACTS_DIR}/comparison/
  - Replay summary: ${summary_file}

$(if [[ ${comparison_result} -eq 0 ]]; then
    echo "Replay verification completed successfully - no regressions detected."
elif [[ ${comparison_result} -eq 3 ]]; then
    echo "Replay detected differences - manual review required."
    echo "Check comparison/ directory for detailed diffs."
else
    echo "Replay failed - see logs for details."
fi)
EOF

    echo "Generated replay summary: ${summary_file}" | ts '%Y-%m-%dT%H:%M:%S%z '
}

main() {
    echo "Starting RGC lockstep oracle pipeline replay..." | ts '%Y-%m-%dT%H:%M:%S%z '

    # Verify required tools
    for tool in jq diff; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "ERROR: Required tool '${tool}' not found in PATH" >&2
            exit 1
        fi
    done

    # Determine source bundle
    local source_bundle
    if [[ -n "${REPLAY_RUN_DIR}" ]]; then
        if [[ ! -d "${REPLAY_RUN_DIR}" ]]; then
            echo "ERROR: Specified replay run directory does not exist: ${REPLAY_RUN_DIR}" | ts '%Y-%m-%dT%H:%M:%S%z '
            exit 1
        fi
        source_bundle="${REPLAY_RUN_DIR}"
        echo "Using pinned bundle: ${source_bundle}" | ts '%Y-%m-%dT%H:%M:%S%z '
    else
        if ! source_bundle=$(find_latest_complete_bundle); then
            echo "ERROR: No complete bundle found for replay" | ts '%Y-%m-%dT%H:%M:%S%z '
            exit 1
        fi
    fi

    # Validate source bundle
    if ! validate_bundle_completeness "${source_bundle}"; then
        echo "ERROR: Source bundle validation failed: ${source_bundle}" | ts '%Y-%m-%dT%H:%M:%S%z '
        exit 2
    fi

    if ! verify_bundle_integrity "${source_bundle}"; then
        echo "ERROR: Source bundle integrity check failed: ${source_bundle}" | ts '%Y-%m-%dT%H:%M:%S%z '
        exit 2
    fi

    # Setup and execute replay
    setup_replay_environment "${source_bundle}"

    local replay_bundle
    if ! replay_bundle=$(run_replay "${source_bundle}"); then
        echo "ERROR: Replay execution failed" | ts '%Y-%m-%dT%H:%M:%S%z '
        exit 1
    fi

    # Compare results
    local comparison_result=0
    if ! compare_runs "${source_bundle}" "${replay_bundle}"; then
        comparison_result=$?
    fi

    generate_replay_summary "${source_bundle}" "${replay_bundle}" "${comparison_result}"

    echo "RGC lockstep oracle pipeline replay completed!" | ts '%Y-%m-%dT%H:%M:%S%z '
    echo "Results: ${REPLAY_ARTIFACTS_DIR}" | ts '%Y-%m-%dT%H:%M:%S%z '
    echo "Summary: ${REPLAY_ARTIFACTS_DIR}/replay_summary.txt" | ts '%Y-%m-%dT%H:%M:%S%z '

    exit ${comparison_result}
}

main "$@"