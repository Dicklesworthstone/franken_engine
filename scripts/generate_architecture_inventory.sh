#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for architecture inventory Cargo execution" >&2
  exit 2
fi

export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target_cod_9}"

command=(rch exec -- env "RUSTC_WRAPPER=${RUSTC_WRAPPER}" "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" cargo run -p frankenengine-engine --bin franken-architecture-inventory -- "$@")
"${command[@]}"
