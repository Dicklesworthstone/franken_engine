#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-target}"
pure_stdout="$(mktemp)"
pure_stderr="$(mktemp)"
cap_stdout="$(mktemp)"
cap_stderr="$(mktemp)"
trap 'rm -f "${pure_stdout}" "${pure_stderr}" "${cap_stdout}" "${cap_stderr}"' EXIT

cd "${repo_root}"

cargo build -p frankenengine-engine --bin frankenctl > /dev/null
frankenctl_bin="${target_dir}/debug/frankenctl"

"${frankenctl_bin}" run examples/06_capability_typed/pure_compute.js \
  > "${pure_stdout}" 2> "${pure_stderr}"

test "$(tr -d '\r\n' < "${pure_stdout}")" = "42"

if "${frankenctl_bin}" run examples/06_capability_typed/requires_capability.js \
    > "${cap_stdout}" 2> "${cap_stderr}"; then
    echo "expected requires_capability.js to fail closed" >&2
    exit 1
fi

grep -q "eval.capability.denied" "${cap_stderr}"
grep -q "module:require" "${cap_stderr}"

printf 'pure_compute.js => %s\n' "$(tr -d '\r\n' < "${pure_stdout}")"
printf 'requires_capability.js => fail-closed capability boundary verified\n'
