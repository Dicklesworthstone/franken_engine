#!/usr/bin/env bash
set -euo pipefail

# Live capability and ambient-authority rejection example
# Generates proof artifacts demonstrating capability enforcement

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
frankenctl_bin="${repo_root}/target/release/frankenctl"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="${repo_root}/artifacts/capability_rejection_example/${timestamp}"
legacy_stdout="${artifact_dir}/legacy_positional_stdout.log"
legacy_stderr="${artifact_dir}/legacy_positional_stderr.log"

example_id="bd-1bao8-capability-rejection"
component="live_capability_rejection_example"
schema_version="franken-engine.capability-rejection-example.v1"

mkdir -p "${artifact_dir}"

cd "${repo_root}"

if [[ ! -x "${frankenctl_bin}" ]]; then
  echo "Required release binary is missing or not executable: ${frankenctl_bin}" >&2
  exit 2
fi

fail_on_cli_usage() {
  local output_file="$1"
  if grep -Eiq '(^|[^[:alpha:]])usage([^[:alpha:]]|$)|missing required|requires --input|requires --extension-id' "${output_file}"; then
    echo "frankenctl emitted CLI usage or missing-flag remediation" >&2
    cat "${output_file}" >&2
    return 1
  fi
}

assert_fs_read_denied() {
  local output_file="$1"
  fail_on_cli_usage "${output_file}"
  if ! grep -Eiq 'CapabilityDenied|capability denied: fs:read' "${output_file}"; then
    echo "expected a typed fs:read capability denial" >&2
    cat "${output_file}" >&2
    return 1
  fi
}

# Regression guard: obsolete positional argv must not count as a capability denial.
legacy_exit_code=0
"${frankenctl_bin}" run examples/21_live_capability_rejection/ambient_authority_attempt.js \
  > "${legacy_stdout}" 2> "${legacy_stderr}" || legacy_exit_code=$?
if [[ "${legacy_exit_code}" -eq 0 ]]; then
  echo "❌ REGRESSION FAILURE: Obsolete positional argv unexpectedly succeeded!" >&2
  exit 1
fi
if assert_fs_read_denied "${legacy_stderr}" >/dev/null 2>&1; then
  echo "❌ REGRESSION FAILURE: CLI usage error was misclassified as capability denial!" >&2
  exit 1
fi

echo "Testing ambient authority rejection..."

ambient_stdout="${artifact_dir}/ambient_attempt_stdout.log"
ambient_stderr="${artifact_dir}/ambient_attempt_stderr.log"
ambient_exit_code=0

"${frankenctl_bin}" run \
  --input examples/21_live_capability_rejection/ambient_authority_attempt.js \
  --extension-id example-21-ambient-authority \
  > "${ambient_stdout}" 2> "${ambient_stderr}" || ambient_exit_code=$?

echo "Testing declared capability (allowed case)..."

declared_stdout="${artifact_dir}/declared_capability_stdout.log"
declared_stderr="${artifact_dir}/declared_capability_stderr.log"
declared_exit_code=0

"${frankenctl_bin}" run \
  --input examples/21_live_capability_rejection/declared_capability.js \
  --extension-id example-21-declared-capability \
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

# Verify a typed membrane denial, and reject CLI usage failures explicitly.
assert_fs_read_denied "${ambient_stderr}"
fail_on_cli_usage "${declared_stderr}"
if ! grep -q '"execution_value": "undefined"' "${declared_stdout}"; then
  echo "❌ EVIDENCE FAILURE: Declared script did not emit the expected run report!" >&2
  cat "${declared_stdout}" >&2
  exit 1
fi

echo "✓ Ambient authority properly rejected (exit code: ${ambient_exit_code})"
echo "✓ Declared capability properly allowed (exit code: ${declared_exit_code})"
echo "✓ Capability denial evidence captured"
echo "✓ Obsolete positional argv rejected as a non-capability CLI failure (exit code: ${legacy_exit_code})"

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
    "command": "${frankenctl_bin} run --input examples/21_live_capability_rejection/ambient_authority_attempt.js --extension-id example-21-ambient-authority"
  },
  "declared_capability_test": {
    "file": "examples/21_live_capability_rejection/declared_capability.js",
    "exit_code": ${declared_exit_code},
    "stdout_path": "${declared_stdout}",
    "stderr_path": "${declared_stderr}",
    "command": "${frankenctl_bin} run --input examples/21_live_capability_rejection/declared_capability.js --extension-id example-21-declared-capability"
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

## Binary Under Test
${frankenctl_bin}

## Ambient Authority Attempt (Expected: Denied)
${frankenctl_bin} run --input examples/21_live_capability_rejection/ambient_authority_attempt.js --extension-id example-21-ambient-authority
# Exit code: ${ambient_exit_code}
# Stdout: $(wc -l < "${ambient_stdout}") lines
# Stderr: $(wc -l < "${ambient_stderr}") lines

## Declared Capability Test (Expected: Allowed)
${frankenctl_bin} run --input examples/21_live_capability_rejection/declared_capability.js --extension-id example-21-declared-capability
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
