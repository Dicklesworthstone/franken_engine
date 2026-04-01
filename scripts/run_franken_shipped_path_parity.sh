#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-ci}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
uid="$(id -u)"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/.rch_target/franken_shipped_path_parity_uid${uid}_${mode}_${timestamp}_$$}"
artifact_root="${FRANKEN_SHIPPED_PATH_PARITY_ARTIFACT_ROOT:-artifacts/franken_shipped_path_parity}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for shipped-path parity heavy commands" >&2
  exit 2
fi

run_rch() {
  rch exec -- env CARGO_TARGET_DIR="${target_dir}" "$@"
}

run_binary() {
  local out_dir_rel="${artifact_root}/${timestamp}_uid${uid}_${mode}_$$"
  local out_dir="${root_dir}/${out_dir_rel}"
  run_rch bash -lc '
    set -euo pipefail
    cargo build -p frankenengine-engine --bin frankenctl --bin franken_shipped_path_parity
    mkdir -p "$1"
    "$CARGO_TARGET_DIR"/debug/franken_shipped_path_parity \
      --frankenctl-bin "$CARGO_TARGET_DIR"/debug/frankenctl \
      --out-dir "$1" \
      --fail-on-mismatch
  ' bash "${out_dir}"
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
    run_binary
    ;;
  ci)
    run_rch cargo check -p frankenengine-engine --bin franken_shipped_path_parity --test shipped_path_parity_cli
    run_rch cargo test -p frankenengine-engine --test shipped_path_parity_cli
    run_rch cargo clippy -p frankenengine-engine --bin franken_shipped_path_parity --test shipped_path_parity_cli -- -D warnings
    run_binary
    ;;
  *)
    echo "usage: ./scripts/run_franken_shipped_path_parity.sh [check|test|clippy|run|ci]" >&2
    exit 2
    ;;
esac
