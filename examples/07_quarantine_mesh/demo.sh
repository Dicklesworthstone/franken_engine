#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${QUARANTINE_MESH_DEMO_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_quarantine_mesh_demo_$(date +%s)_$$}"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "Required rch binary not found: $RCH_BIN" >&2
  exit 2
fi

log_path="$(mktemp "${TMPDIR:-/tmp}/quarantine-mesh-demo.XXXXXX.log")"
trap 'rm -f "$log_path"' EXIT

set +e
"$RCH_BIN" exec -- env \
  "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
  "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
  "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
  cargo run --quiet -p frankenengine-engine --bin franken-quarantine-mesh-demo 2>&1 | tee "$log_path"
status=${PIPESTATUS[0]}
set -e

if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
  echo "rch reported local fallback; refusing local execution" >&2
  exit 125
fi

exit "$status"
