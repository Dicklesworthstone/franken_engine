#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-ci}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_shape_transition_lattice}"
artifact_root="${RGC_SHAPE_TRANSITION_LATTICE_ARTIFACT_ROOT:-artifacts/rgc_shape_transition_lattice}"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"

run_rch() {
  rch exec -- env CARGO_TARGET_DIR="${target_dir}" "$@"
}

run_remote_binary() {
  local out_dir="${artifact_root}/${run_stamp}"
  run_rch cargo run -p frankenengine-engine --bin franken_shape_lattice_bundle -- --out-dir "${out_dir}"
}

case "${mode}" in
  check)
    run_rch cargo check -p frankenengine-engine --bin franken_shape_lattice_bundle --test shape_transition_lattice_cli
    ;;
  test)
    run_rch cargo test -p frankenengine-engine --test shape_transition_lattice_cli
    ;;
  clippy)
    run_rch cargo clippy -p frankenengine-engine --bin franken_shape_lattice_bundle --test shape_transition_lattice_cli -- -D warnings
    ;;
  run)
    run_remote_binary
    ;;
  ci)
    run_rch cargo check -p frankenengine-engine --bin franken_shape_lattice_bundle --test shape_transition_lattice_cli
    run_rch cargo test -p frankenengine-engine --test shape_transition_lattice_cli
    run_rch cargo clippy -p frankenengine-engine --bin franken_shape_lattice_bundle --test shape_transition_lattice_cli -- -D warnings
    run_remote_binary
    ;;
  *)
    echo "usage: ./scripts/run_rgc_shape_transition_lattice.sh [check|test|clippy|run|ci]" >&2
    exit 2
    ;;
esac
