#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-ci}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_franken_shipped_path_parity}"
artifact_root="${FRANKEN_SHIPPED_PATH_PARITY_ARTIFACT_ROOT:-artifacts/franken_shipped_path_parity}"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"

run_rch() {
  rch exec -- env CARGO_TARGET_DIR="${target_dir}" "$@"
}

run_binary() {
  local out_dir="${artifact_root}/${run_stamp}"
  mkdir -p "${out_dir}"
  "${target_dir}/debug/franken_shipped_path_parity" \
    --frankenctl-bin "${target_dir}/debug/frankenctl" \
    --out-dir "${out_dir}" \
    --fail-on-mismatch
}

case "${mode}" in
  check)
    run_rch cargo check -p frankenengine-engine --bin franken_shipped_path_parity --test shipped_path_parity_cli
    ;;
  test)
    run_rch cargo test -p frankenengine-engine --test shipped_path_parity_cli
    ;;
  clippy)
    run_rch cargo clippy -p frankenengine-engine --bin franken_shipped_path_parity --test shipped_path_parity_cli -- -D warnings
    ;;
  run)
    run_rch cargo build -p frankenengine-engine --bin frankenctl --bin franken_shipped_path_parity
    run_binary
    ;;
  ci)
    run_rch cargo check -p frankenengine-engine --bin franken_shipped_path_parity --test shipped_path_parity_cli
    run_rch cargo test -p frankenengine-engine --test shipped_path_parity_cli
    run_rch cargo clippy -p frankenengine-engine --bin franken_shipped_path_parity --test shipped_path_parity_cli -- -D warnings
    run_rch cargo build -p frankenengine-engine --bin frankenctl --bin franken_shipped_path_parity
    run_binary
    ;;
  *)
    echo "usage: ./scripts/run_franken_shipped_path_parity.sh [check|test|clippy|run|ci]" >&2
    exit 2
    ;;
esac
