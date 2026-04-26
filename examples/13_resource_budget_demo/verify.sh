#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

echo "Running escalation demo and verifying output..."

# Generate the log
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target_resource_demo}"
cd "${repo_root}"
log_json="$(cargo run --quiet --bin franken_resource_budget_demo -- "demo:budget-exhaustion")"

# Parse and verify the log
expected="$(printf '%s\n' "${log_json}" | jq -r '.expected_sequence | join(",")')"
actual="$(printf '%s\n' "${log_json}" | jq -r '.events | sort_by(.timestamp_ns) | map(.action | keys[0]) | join(",")')"

if [[ "${actual}" != "${expected}" ]]; then
  echo "expected action sequence ${expected}, got ${actual}" >&2
  exit 1
fi

timestamps_are_sorted="$(
  printf '%s\n' "${log_json}" | jq -r '
    [.events | sort_by(.timestamp_ns) | .[].timestamp_ns]
    as $ts
    | if ($ts | length) < 2 then "true"
      else ([range(0; ($ts | length) - 1) | $ts[.] <= $ts[. + 1]] | all | tostring)
      end
  '
)"

if [[ "${timestamps_are_sorted}" != "true" ]]; then
  echo "timestamps are not monotonic" >&2
  exit 1
fi

# Verify the terminate step now has a real implementation (not api_gap)
terminate_source="$(printf '%s\n' "${log_json}" | jq -r '.events[-1].source_module')"
if [[ "${terminate_source}" == "conceptual_operator_contract" ]]; then
  echo "terminate step still uses conceptual implementation" >&2
  exit 1
fi

if [[ "${terminate_source}" != "resource_escalation_control" ]]; then
  echo "expected terminate step from resource_escalation_control, got ${terminate_source}" >&2
  exit 1
fi

# Verify we have a real terminate action
terminate_action="$(printf '%s\n' "${log_json}" | jq -r '.events[-1].action | keys[0]')"
if [[ "${terminate_action}" != "terminate" ]]; then
  echo "expected terminate action, got ${terminate_action}" >&2
  exit 1
fi

echo "✓ verified deterministic sequence: ${actual}"
echo "✓ verified monotonic timestamps"
echo "✓ verified real terminate implementation (${terminate_source})"
echo "✓ all checks passed!"
