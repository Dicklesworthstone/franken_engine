#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${RESOURCE_BUDGET_DEMO_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_resource_budget_demo_$(date +%s)_$$}"
EVIDENCE_DIR="${RESOURCE_BUDGET_DEMO_EVIDENCE_DIR:-${repo_root}/artifacts/resource_budget_demo/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
mkdir -p "${EVIDENCE_DIR}"
stdout_path="${EVIDENCE_DIR}/demo.stdout"
stderr_path="${EVIDENCE_DIR}/demo.stderr"

echo "Running deterministic resource budget escalation demo..."
echo

if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
  echo "Required rch binary not found: ${RCH_BIN}" >&2
  exit 2
fi

set +e
(
  cd "${repo_root}"
  "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN}" \
    "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
    cargo run --bin franken_resource_budget_demo -- "demo:budget-exhaustion"
) >"${stdout_path}" 2>"${stderr_path}"
status=$?
set -e

if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "${stdout_path}" "${stderr_path}"; then
  cat "${stderr_path}" >&2
  echo "rch reported local fallback; refusing local execution" >&2
  echo "evidence logs preserved in ${EVIDENCE_DIR}" >&2
  exit 125
fi

cat "${stdout_path}"

if [[ "${status}" -ne 0 ]]; then
  cat "${stderr_path}" >&2
  echo "evidence logs preserved in ${EVIDENCE_DIR}" >&2
  exit "${status}"
fi
