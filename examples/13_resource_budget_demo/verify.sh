#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${RESOURCE_BUDGET_DEMO_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_resource_budget_demo_$(date +%s)_$$}"

echo "Running escalation demo and verifying output..."

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "Required rch binary not found: $RCH_BIN" >&2
  exit 2
fi

run_resource_budget_demo() {
  local stdout_path stderr_path
  stdout_path="$(mktemp "${TMPDIR:-/tmp}/resource-budget-demo.XXXXXX.stdout")"
  stderr_path="$(mktemp "${TMPDIR:-/tmp}/resource-budget-demo.XXXXXX.stderr")"

  set +e
  (
    cd "${repo_root}"
    "$RCH_BIN" exec -- env \
      "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
      "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
      "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
      cargo run --quiet --bin franken_resource_budget_demo -- "demo:budget-exhaustion"
  ) >"${stdout_path}" 2>"${stderr_path}"
  local status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    cat "${stderr_path}" >&2
    rm -f "${stdout_path}" "${stderr_path}"
    return "${status}"
  fi

  if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "${stdout_path}" "${stderr_path}"; then
    cat "${stderr_path}" >&2
    echo "rch reported local fallback; refusing local execution" >&2
    rm -f "${stdout_path}" "${stderr_path}"
    return 125
  fi

  cat "${stdout_path}"
  rm -f "${stdout_path}" "${stderr_path}"
}

# Generate the log
log_json="$(run_resource_budget_demo)"

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
