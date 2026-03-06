#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="${LOWERING_GAP_INVENTORY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
out_dir="${LOWERING_GAP_INVENTORY_OUT_DIR:-$repo_root/artifacts/lowering_gap_inventory/$timestamp}"

mkdir -p "$out_dir"

rch_output="$(mktemp)"
cleanup() {
  rm -f "$rch_output"
}
trap cleanup EXIT

if ! rch exec --color never -- env \
  CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_lowering_gap_inventory \
  cargo run -p frankenengine-engine --bin franken_lowering_gap_inventory -- \
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

test -f "$out_dir/lowering_gap_inventory.json"
test -f "$out_dir/run_manifest.json"
test -f "$out_dir/events.jsonl"
test -f "$out_dir/commands.txt"

printf 'lowering gap inventory artifacts: %s\n' "$out_dir"
