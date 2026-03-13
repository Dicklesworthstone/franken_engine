#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <out-dir> [asupersync-root]" >&2
  exit 1
fi

out_dir="$1"
asupersync_root="${2:-/dp/asupersync}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_asupersync_contract_matrix}"

rch exec -- env CARGO_TARGET_DIR="$target_dir" cargo run -p frankenengine-engine --bin franken_asupersync_contract_matrix -- --out-dir "$out_dir" --asupersync-root "$asupersync_root"
