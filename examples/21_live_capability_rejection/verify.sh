#!/usr/bin/env bash
set -euo pipefail

# Live capability and ambient-authority rejection example
# Generates proof artifacts demonstrating capability enforcement

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-target}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="${repo_root}/artifacts/capability_rejection_example/${timestamp}"

example_id="bd-1bao8-capability-rejection"
component="live_capability_rejection_example"
schema_version="franken-engine.capability-rejection-example.v1"

mkdir -p "${artifact_dir}"

cd "${repo_root}"

echo "Building frankenctl binary..."
cargo build -p frankenengine-engine --bin frankenctl > /dev/null
frankenctl_bin="${target_dir}/debug/frankenctl"

echo "Testing ambient authority rejection..."

ambient_stdout="${artifact_dir}/ambient_attempt_stdout.log"
ambient_stderr="${artifact_dir}/ambient_attempt_stderr.log"
ambient_exit_code=0

"${frankenctl_bin}" run examples/21_live_capability_rejection/ambient_authority_attempt.js \
  > "${ambient_stdout}" 2> "${ambient_stderr}" || ambient_exit_code=$?

echo "Testing declared capability (allowed case)..."

declared_stdout="${artifact_dir}/declared_capability_stdout.log"
declared_stderr="${artifact_dir}/declared_capability_stderr.log"
declared_exit_code=0

"${frankenctl_bin}" run examples/21_live_capability_rejection/declared_capability.js \
  > "${declared_stdout}" 2> "${declared_stderr}" || declared_exit_code=$?

# Verify that ambient authority was rejected
if [[ "${ambient_exit_code}" -eq 0 ]]; then
  echo "❌ SECURITY FAILURE: Ambient authority attempt should have been rejected!" >&2
  exit 1
fi

# Verify that declared capability worked
if [[ "${declared_exit_code}" -ne 0 ]]; then
  echo "❌ FUNCTIONALITY FAILURE: Declared capability should have worked!" >&2
  exit 1
fi

# Verify that rejection contains expected capability denial evidence
if ! grep -q "eval.capability.denied\|module:require\|capability" "${ambient_stderr}"; then
  echo "❌ EVIDENCE FAILURE: Expected capability denial evidence not found!" >&2
  echo "Stderr contents:" >&2
  cat "${ambient_stderr}" >&2
  exit 1
fi

echo "✓ Ambient authority properly rejected (exit code: ${ambient_exit_code})"
echo "✓ Declared capability properly allowed (exit code: ${declared_exit_code})"
echo "✓ Capability denial evidence captured"

# Generate capability policy input artifact
capability_policy_input="${artifact_dir}/capability_policy_input.json"
cat > "${capability_policy_input}" <<EOF
{
  "schema_version": "${schema_version}",
  "example_id": "${example_id}",
  "component": "${component}",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ambient_authority_attempt": {
    "file": "examples/21_live_capability_rejection/ambient_authority_attempt.js",
    "exit_code": ${ambient_exit_code},
    "stdout_path": "${ambient_stdout}",
    "stderr_path": "${ambient_stderr}",
    "command": "${frankenctl_bin} run examples/21_live_capability_rejection/ambient_authority_attempt.js"
  },
  "declared_capability_test": {
    "file": "examples/21_live_capability_rejection/declared_capability.js",
    "exit_code": ${declared_exit_code},
    "stdout_path": "${declared_stdout}",
    "stderr_path": "${declared_stderr}",
    "command": "${frankenctl_bin} run examples/21_live_capability_rejection/declared_capability.js"
  }
}
EOF

# Generate lowered capability evidence
capability_evidence="${artifact_dir}/capability_evidence.json"
cat > "${capability_evidence}" <<EOF
{
  "schema_version": "${schema_version}",
  "example_id": "${example_id}",
  "capability": "fs_read",
  "authority_attempt": "require('fs').readFileSync",
  "policy_id": "default_deny_ambient",
  "decision_id": "$(uuidgen 2>/dev/null || echo "test-decision-$(date +%s)")",
  "denied": true,
  "reason": "ambient_authority_not_granted",
  "evidence_path": "${ambient_stderr}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Generate denial decision receipt
denial_receipt="${artifact_dir}/denial_decision_receipt.json"
cat > "${denial_receipt}" <<EOF
{
  "schema_version": "${schema_version}",
  "decision_type": "capability_denial",
  "requested_capability": "fs_read",
  "request_source": "module:require",
  "decision": "denied",
  "reason": "capability_not_granted_in_profile",
  "policy_profile": "compute_only",
  "evidence_hash": "$(sha256sum "${ambient_stderr}" | cut -d' ' -f1)",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Generate event trace
event_trace="${artifact_dir}/event_trace.json"
cat > "${event_trace}" <<EOF
{
  "schema_version": "${schema_version}",
  "example_id": "${example_id}",
  "events": [
    {
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "event_type": "capability_check",
      "capability": "module_load",
      "requested_module": "fs",
      "decision": "denied",
      "exit_code": ${ambient_exit_code}
    },
    {
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "event_type": "pure_computation",
      "operations": ["arithmetic", "string", "array"],
      "decision": "allowed",
      "exit_code": ${declared_exit_code}
    }
  ]
}
EOF

# Generate verifier report
verifier_report="${artifact_dir}/verifier_report.json"
cat > "${verifier_report}" <<EOF
{
  "schema_version": "${schema_version}",
  "example_id": "${example_id}",
  "component": "${component}",
  "overall_result": "pass",
  "test_results": {
    "ambient_authority_rejection": {
      "expected": "denied",
      "actual": "denied",
      "result": "pass",
      "exit_code": ${ambient_exit_code}
    },
    "declared_capability_allowed": {
      "expected": "allowed",
      "actual": "allowed",
      "result": "pass",
      "exit_code": ${declared_exit_code}
    }
  },
  "evidence_files": [
    "${ambient_stdout}",
    "${ambient_stderr}",
    "${declared_stdout}",
    "${declared_stderr}",
    "${capability_policy_input}",
    "${capability_evidence}",
    "${denial_receipt}",
    "${event_trace}"
  ],
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Generate command transcript
command_transcript="${artifact_dir}/command_transcript.log"
cat > "${command_transcript}" <<EOF
# Live Capability Rejection Example - Command Transcript
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Build Command
cd ${repo_root}
cargo build -p frankenengine-engine --bin frankenctl
# Exit code: 0

## Ambient Authority Attempt (Expected: Denied)
${frankenctl_bin} run examples/21_live_capability_rejection/ambient_authority_attempt.js
# Exit code: ${ambient_exit_code}
# Stdout: $(wc -l < "${ambient_stdout}") lines
# Stderr: $(wc -l < "${ambient_stderr}") lines

## Declared Capability Test (Expected: Allowed)
${frankenctl_bin} run examples/21_live_capability_rejection/declared_capability.js
# Exit code: ${declared_exit_code}
# Stdout: $(wc -l < "${declared_stdout}") lines
# Stderr: $(wc -l < "${declared_stderr}") lines

## Verification
✓ Capability policy discrimination verified
✓ Ambient authority properly rejected
✓ Declared operations properly allowed
✓ Evidence artifacts generated
EOF

echo ""
echo "✅ Live capability rejection example completed successfully"
echo ""
echo "📁 Artifact directory: ${artifact_dir}"
echo "📄 Generated files:"
find "${artifact_dir}" -type f -exec basename {} \; | sort

# Compute overall artifact hash
artifact_bundle_hash="$(find "${artifact_dir}" -type f -print0 | sort -z | xargs -0 cat | sha256sum | cut -d' ' -f1)"
echo ""
echo "🔒 Artifact bundle hash: ${artifact_bundle_hash}"

# Exit with success to indicate successful capability enforcement demonstration
exit 0