#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
input_path="examples/12_frankenctl_react_demo/sample.tsx"
work_dir="$(mktemp -d)"
report_path="${work_dir}/react_compile_report.json"
cargo_stderr="${work_dir}/cargo_build.stderr"
trap 'rm -rf "${work_dir}"' EXIT

RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target_react_demo}"

cd "${repo_root}"

if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
  echo "Required rch binary not found: ${RCH_BIN}" >&2
  exit 2
fi

run_rch_cargo_build() {
  set +e
  "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN}" \
    "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
    cargo build -p frankenengine-engine --bin frankenctl > /dev/null 2> "${cargo_stderr}"
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

run_rch_cargo_build
frankenctl_bin="${CARGO_TARGET_DIR}/debug/frankenctl"

set +e
"${frankenctl_bin}" react compile \
  --input "${input_path}" \
  --source-form tsx \
  --runtime automatic \
  --trace-id "trace-react-demo" \
  --decision-id "decision-react-demo" \
  --policy-id "policy-react-demo" \
  --out "${report_path}" \
  >/dev/null
status=$?
set -e

if [[ "${status}" -ne 25 ]]; then
  echo "expected frankenctl react compile to fail closed with exit code 25, got ${status}" >&2
  exit 1
fi

echo "frankenctl react compile exited with expected fail-closed status 25"
echo "captured report: ${report_path}"
cat "${report_path}"
