#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${RGC_ZERO_PLACEHOLDER_SCAN_ARTIFACT_ROOT:-artifacts/rgc_zero_placeholder_scan}"
out_dir="${RGC_ZERO_PLACEHOLDER_SCAN_OUT_DIR:-${artifact_root}/${timestamp}}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_rgc_zero_placeholder_scan_${target_namespace}}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for zero-placeholder scan execution" >&2
  exit 2
fi

mkdir -p "$out_dir"

rch_output="$(mktemp)"
cleanup() {
  rm -f "$rch_output"
}
trap cleanup EXIT

if ! timeout "${rch_timeout_seconds}" \
  rch exec --color never -- env \
  "RUSTUP_TOOLCHAIN=${toolchain}" \
  "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
  "CARGO_TARGET_DIR=${target_dir}" \
  cargo run -p frankenengine-engine --bin franken_zero_placeholder_scan -- \
  --out-dir "$out_dir" 2>&1 | tee "$rch_output"; then
  exit 1
fi

worker="$(
  sed -n 's/.*Selected worker: \([^ ]*\) at .*/\1/p' "$rch_output" | tail -n 1
)"
if [[ -z "$worker" ]]; then
  echo "failed to determine rch worker for artifact sync" >&2
  exit 1
fi

scp -q -r "${worker}:${out_dir}/." "$out_dir/"

test -f "$out_dir/zero_placeholder_inventory.json"
test -f "$out_dir/trace_ids.json"
test -f "$out_dir/run_manifest.json"
test -f "$out_dir/events.jsonl"
test -f "$out_dir/commands.txt"

printf 'zero-placeholder scan artifacts: %s\n' "$out_dir"
