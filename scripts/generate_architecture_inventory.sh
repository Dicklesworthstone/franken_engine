#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

run_inventory() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- env "RUSTC_WRAPPER=${RUSTC_WRAPPER}" "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" \
      cargo build -p frankenengine-engine --bin franken-architecture-inventory >&2
    "${repo_root}/target/debug/franken-architecture-inventory" "$@"
  elif [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    cargo run -q -p frankenengine-engine --bin franken-architecture-inventory -- "$@"
  else
    echo "rch is required for architecture inventory Cargo execution" >&2
    exit 2
  fi
}

if [[ $# -eq 0 ]]; then
  rendered="$(run_inventory --stdout)"
  printf '%s\n' "$rendered" >"${repo_root}/docs/ARCHITECTURE_INVENTORY.md"
  echo "wrote ${repo_root}/docs/ARCHITECTURE_INVENTORY.md"
else
  run_inventory "$@"
fi
