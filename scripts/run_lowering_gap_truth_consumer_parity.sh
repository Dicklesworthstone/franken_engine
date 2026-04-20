#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${1:-${repo_root}/artifacts/lowering_gap_truth_consumer_parity/${stamp}}"
step_logs_dir="${run_dir}/step_logs"

mkdir -p "${step_logs_dir}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_azurefalcon_lowering}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

cd "${repo_root}"

cargo run -p frankenengine-engine --bin franken_lowering_gap_inventory -- --out-dir "${run_dir}" \
  >"${step_logs_dir}/step_001_cli.log" 2>&1

printf '%s\n' \
  "CARGO_TARGET_DIR=${CARGO_TARGET_DIR} CARGO_INCREMENTAL=${CARGO_INCREMENTAL} cargo test -p frankenengine-engine lowering" \
  >>"${run_dir}/commands.txt"

cargo test -p frankenengine-engine lowering \
  >"${step_logs_dir}/step_002_cargo_test_lowering.log" 2>&1

printf 'lowering truth consumer parity artifacts: %s\n' "${run_dir}"
