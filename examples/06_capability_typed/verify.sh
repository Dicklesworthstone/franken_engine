#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
frankenctl_bin="${repo_root}/target/release/frankenctl"
pure_stdout="$(mktemp)"
pure_stderr="$(mktemp)"
cap_stdout="$(mktemp)"
cap_stderr="$(mktemp)"
legacy_stdout="$(mktemp)"
legacy_stderr="$(mktemp)"
trap 'rm -f "${pure_stdout}" "${pure_stderr}" "${cap_stdout}" "${cap_stderr}" "${legacy_stdout}" "${legacy_stderr}"' EXIT

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

cd "${repo_root}"

legacy_status=0
"${frankenctl_bin}" run examples/06_capability_typed/requires_capability.js \
  > "${legacy_stdout}" 2> "${legacy_stderr}" || legacy_status=$?
if [[ "${legacy_status}" -eq 0 ]]; then
  echo "obsolete positional frankenctl argv unexpectedly succeeded" >&2
  exit 1
fi
if assert_fs_read_denied "${legacy_stderr}" >/dev/null 2>&1; then
  echo "CLI usage error was misclassified as capability denial" >&2
  exit 1
fi

"${frankenctl_bin}" run \
  --input examples/06_capability_typed/pure_compute.js \
  --extension-id example-06-pure-compute \
  > "${pure_stdout}" 2> "${pure_stderr}"

fail_on_cli_usage "${pure_stderr}"
grep -q '"execution_value": "42"' "${pure_stdout}"

if "${frankenctl_bin}" run \
    --input examples/06_capability_typed/requires_capability.js \
    --extension-id example-06-requires-capability \
    > "${cap_stdout}" 2> "${cap_stderr}"; then
    echo "expected requires_capability.js to fail closed" >&2
    exit 1
fi

assert_fs_read_denied "${cap_stderr}"

printf 'pure_compute.js => 42\n'
printf 'requires_capability.js => capability denied: fs:read\n'
printf 'legacy positional argv => rejected as non-capability CLI failure (exit %s)\n' "${legacy_status}"
