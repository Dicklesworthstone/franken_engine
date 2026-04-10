#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

manifest_path="${1:-}"
out_dir="${2:-}"

if [[ -z "$manifest_path" ]]; then
  echo "usage: scripts/run_engine_comparison_benchmarks.sh <comparison-manifest.json> [out-dir]" >&2
  exit 64
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for engine comparison benchmarks" >&2
  exit 1
fi

toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="${BENCHMARK_COMPARE_RUN_ID:-benchmark-compare-${timestamp}}"
default_target_dir="/data/projects/franken_engine/target_rch_benchmark_compare_${$}"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
out_dir="${out_dir:-${BENCHMARK_COMPARE_OUT_DIR:-artifacts/benchmark_compare/${timestamp}}}"
log_path="$(mktemp "${TMPDIR:-/tmp}/benchmark_compare_rch.XXXXXX.log")"
trap 'rm -f "$log_path"' EXIT

command=(
  cargo run -p frankenengine-engine --bin frankenctl --
  benchmark compare
  --manifest "$manifest_path"
  --out-dir "$out_dir"
  --run-id "$run_id"
)

echo "==> ${command[*]}"

set +e
rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "${command[@]}" \
  2>&1 | tee "$log_path"
rc=${PIPESTATUS[0]}
set -e

if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
  echo "error: rch reported local fallback; refusing local execution for comparison benchmarks" >&2
  exit 125
fi

if ! grep -Eq 'Remote command finished: exit=0' "$log_path"; then
  echo "error: missing successful remote completion marker in rch output" >&2
  exit "${rc:-1}"
fi

exit "$rc"
