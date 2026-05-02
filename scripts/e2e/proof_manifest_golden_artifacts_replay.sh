#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

log() {
  printf '[proof-manifest-golden][%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

if [[ -n "${PROOF_MANIFEST_GOLDEN_TARGET_DIR:-}" ]]; then
  export CARGO_TARGET_DIR="${PROOF_MANIFEST_GOLDEN_TARGET_DIR}"
elif [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  export CARGO_TARGET_DIR
fi

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RCH_CARGO_WRAPPER_BYPASS="${RCH_CARGO_WRAPPER_BYPASS:-1}"

log "repo=${root_dir}"
log "cargo=${CARGO:-cargo}"
log "target_dir=${CARGO_TARGET_DIR:-<cargo-default>}"
log "incremental=${CARGO_INCREMENTAL}"
log "rch_cargo_wrapper_bypass=${RCH_CARGO_WRAPPER_BYPASS}"
log "test_target=proof_manifest_golden_artifacts"

cmd=(
  "${CARGO:-cargo}"
  test
  -p
  frankenengine-engine
  --test
  proof_manifest_golden_artifacts
  --
  --nocapture
)

log "running=${cmd[*]}"
"${cmd[@]}"
log "completed=proof_manifest_golden_artifacts"
