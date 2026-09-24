#!/usr/bin/env bash
set -euo pipefail

# Live IFC/declassification runner (bd-dpfvh): runs the IFC integration tests
# and the live example verifier, records each step's real exit status, and
# fails if any step failed.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="${repo_root}/artifacts/live_ifc_declassification_runner/${timestamp}"

mkdir -p "${artifact_dir}"
cd "${repo_root}"

run_step() {
    local name="$1" log="$2"
    shift 2
    echo "Running ${name}..."
    local status=0
    "$@" > "${artifact_dir}/${log}" 2>&1 || status=$?
    if [[ ${status} -eq 0 ]]; then
        echo "✅ ${name} passed"
    else
        echo "❌ ${name} failed (exit ${status}) - see ${artifact_dir}/${log}"
    fi
    return "${status}"
}

integration_status=0
run_step "IFC declassification integration tests" integration_tests.log \
    rch exec -- cargo test -p frankenengine-engine \
    --test live_ifc_declassification_integration \
    --test live_ifc_declassification_runtime_integration || integration_status=$?

lib_status=0
run_step "IFC library unit tests" ifc_lib_tests.log \
    rch exec -- cargo test -p frankenengine-engine --lib ifc || lib_status=$?

example_status=0
run_step "live example verification" example_output.log \
    "${repo_root}/examples/22_live_ifc_declassification/verify.sh" || example_status=$?

jq -n \
    --arg timestamp "${timestamp}" \
    --argjson integration_status "${integration_status}" \
    --argjson lib_status "${lib_status}" \
    --argjson example_status "${example_status}" \
    '{
      schema_version: "franken-engine.ifc-declassification-runner.v2",
      bead_id: "bd-dpfvh",
      execution_timestamp: $timestamp,
      steps: {
        integration_tests: {log: "integration_tests.log", exit_status: $integration_status},
        ifc_lib_tests: {log: "ifc_lib_tests.log", exit_status: $lib_status},
        example_verification: {log: "example_output.log", exit_status: $example_status}
      },
      passed: ($integration_status == 0 and $lib_status == 0 and $example_status == 0)
    }' > "${artifact_dir}/summary_report.json"

echo "📁 Artifact directory: ${artifact_dir}"
if [[ ${integration_status} -ne 0 || ${lib_status} -ne 0 || ${example_status} -ne 0 ]]; then
    exit 1
fi
echo "✅ Live IFC/declassification runner passed"
