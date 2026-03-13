#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <out-dir>" >&2
  exit 1
fi

out_dir="$1"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_rgc_planning_track}"

rch exec -- env CARGO_TARGET_DIR="$target_dir" cargo run -p frankenengine-engine --bin franken_rgc_planning_track -- --out-dir "$out_dir"
