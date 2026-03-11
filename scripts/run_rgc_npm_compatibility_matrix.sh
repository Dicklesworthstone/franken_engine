#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-ci}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_npm_compatibility_matrix}"
artifact_root="${RGC_NPM_COMPATIBILITY_MATRIX_ARTIFACT_ROOT:-artifacts/rgc_npm_compatibility_matrix}"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"

run_rch() {
  rch exec -- env CARGO_TARGET_DIR="${target_dir}" "$@"
}

run_binary() {
  local out_dir="${artifact_root}/${run_stamp}"
  mkdir -p "${out_dir}"
  "${target_dir}/debug/franken_npm_compatibility_matrix" \
    --out-dir "${out_dir}"
}

case "${mode}" in
  check)
    run_rch cargo check -p frankenengine-engine --bin franken_npm_compatibility_matrix --test npm_compatibility_matrix_cli
    ;;
  test)
    run_rch cargo test -p frankenengine-engine --test npm_compatibility_matrix_cli
    ;;
  clippy)
    run_rch cargo clippy -p frankenengine-engine --bin franken_npm_compatibility_matrix --test npm_compatibility_matrix_cli -- -D warnings
    ;;
  run)
    run_rch cargo build -p frankenengine-engine --bin franken_npm_compatibility_matrix
    run_binary
    ;;
  ci)
    run_rch cargo check -p frankenengine-engine --bin franken_npm_compatibility_matrix --test npm_compatibility_matrix_cli
    run_rch cargo test -p frankenengine-engine --test npm_compatibility_matrix_cli
    run_rch cargo clippy -p frankenengine-engine --bin franken_npm_compatibility_matrix --test npm_compatibility_matrix_cli -- -D warnings
    run_rch cargo build -p frankenengine-engine --bin franken_npm_compatibility_matrix
    run_binary
    ;;
  *)
    echo "usage: ./scripts/run_rgc_npm_compatibility_matrix.sh [check|test|clippy|run|ci]" >&2
    exit 2
    ;;
esac
