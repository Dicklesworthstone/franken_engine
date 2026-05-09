#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${1:-${repo_root}/artifacts/lowering_gap_truth_consumer_parity/${stamp}}"
step_logs_dir="${run_dir}/step_logs"
commands_path="${run_dir}/commands.txt"

mkdir -p "${step_logs_dir}"
: >"${commands_path}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_azurefalcon_lowering}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"

cd "${repo_root}"

run_rch_logged() {
  local log_path="$1"
  shift
  local -a command=(
    rch exec -- env
    "RUSTC_WRAPPER=${RUSTC_WRAPPER}"
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}"
    "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}"
    "$@"
  )
  printf '%s\n' "${command[*]}" >>"${commands_path}"
  "${command[@]}" >"${log_path}" 2>&1
}

run_rch_logged "${step_logs_dir}/step_001_cli.log" cargo run -p frankenengine-engine --bin franken_lowering_gap_inventory -- --out-dir "${run_dir}"

run_rch_logged "${step_logs_dir}/step_002_cargo_test_lowering.log" cargo test -p frankenengine-engine lowering

printf 'lowering truth consumer parity artifacts: %s\n' "${run_dir}"
