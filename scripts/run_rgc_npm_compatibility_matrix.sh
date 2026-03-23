#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

mode="${1:-ci}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_npm_compatibility_matrix}"
artifact_root="${RGC_NPM_COMPATIBILITY_MATRIX_ARTIFACT_ROOT:-artifacts/rgc_npm_compatibility_matrix}"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${run_stamp}"
replay_command="RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR=${run_dir} ./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for npm compatibility matrix heavy commands" >&2
  exit 2
fi

run_rch() {
  rch exec -- env CARGO_TARGET_DIR="${target_dir}" "$@"
}

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/npm_compat_matrix_report.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
}

print_bundle_paths() {
  echo "rgc npm compatibility matrix report: ${run_dir}/npm_compat_matrix_report.json"
  echo "rgc npm compatibility matrix trace ids: ${run_dir}/trace_ids.json"
  echo "rgc npm compatibility matrix manifest: ${run_dir}/run_manifest.json"
  echo "rgc npm compatibility matrix events: ${run_dir}/events.jsonl"
  echo "rgc npm compatibility matrix commands: ${run_dir}/commands.txt"
  echo "rgc npm compatibility matrix replay: ${replay_command}"
}

run_remote_binary() {
  run_rch cargo run -p frankenengine-engine --bin franken_npm_compatibility_matrix -- --out-dir "${run_dir}"
  if ! run_dir_is_complete "${run_dir}"; then
    echo "rgc npm compatibility matrix run produced an incomplete bundle: ${run_dir}" >&2
    exit 1
  fi
  print_bundle_paths
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
    run_remote_binary
    ;;
  ci)
    run_rch cargo check -p frankenengine-engine --bin franken_npm_compatibility_matrix --test npm_compatibility_matrix_cli
    run_rch cargo test -p frankenengine-engine --test npm_compatibility_matrix_cli
    run_rch cargo clippy -p frankenengine-engine --bin franken_npm_compatibility_matrix --test npm_compatibility_matrix_cli -- -D warnings
    run_remote_binary
    ;;
  *)
    echo "usage: ./scripts/run_rgc_npm_compatibility_matrix.sh [check|test|clippy|run|ci]" >&2
    exit 2
    ;;
esac
