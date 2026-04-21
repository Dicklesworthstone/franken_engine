#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/data/projects/franken_engine/target_cod_9 cargo run -p frankenengine-engine --bin franken-architecture-inventory -- "$@"
