#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
target_dir="${CARGO_TARGET_DIR:-${CAPABILITY_TYPED_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_capability_typed_$(date +%s)_$$}}"
pure_stdout="$(mktemp)"
pure_stderr="$(mktemp)"
cap_stdout="$(mktemp)"
cap_stderr="$(mktemp)"
cargo_stderr="$(mktemp)"
trap 'rm -f "${pure_stdout}" "${pure_stderr}" "${cap_stdout}" "${cap_stderr}" "${cargo_stderr}"' EXIT

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "Required rch binary not found: $RCH_BIN" >&2
  exit 2
fi

run_rch_cargo_build() {
  set +e
  "$RCH_BIN" exec -- env \
    "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
    "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
    "CARGO_TARGET_DIR=$target_dir" \
    cargo build -p frankenengine-engine --bin frankenctl > /dev/null 2>"${cargo_stderr}"
  local status=$?
  set -e

  if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "${cargo_stderr}"; then
    cat "${cargo_stderr}" >&2
    echo "rch reported local fallback; refusing local execution" >&2
    return 125
  fi

  if [[ "${status}" -ne 0 ]]; then
    cat "${cargo_stderr}" >&2
    return "${status}"
  fi
}

cd "${repo_root}"

run_rch_cargo_build
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
