#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/franken-architecture-bins.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

mkdir -p \
  "$work_dir/crates/franken-engine/src/bin" \
  "$work_dir/docs"

cat >"$work_dir/crates/franken-engine/Cargo.toml" <<'TOML'
[package]
name = "synthetic-inventory"
version = "0.1.0"

[[bin]]
name = "manifest-tool"
path = "src/bin/manifest_tool.rs"
TOML

printf '%s\n' 'fn main() {}' >"$work_dir/crates/franken-engine/src/bin/manifest_tool.rs"
printf '%s\n' 'fn main() {}' >"$work_dir/crates/franken-engine/src/bin/auto_tool.rs"

cat >"$work_dir/docs/ARCHITECTURE_INVENTORY.md" <<'MD'
# FrankenEngine Architecture Inventory

## Summary

| Metric | Count |
| --- | ---: |
| Release binary targets | 1 |

## Release Binary Targets

- `stale` — `crates/franken-engine/src/bin/stale.rs` (auto)

## Missing Exported Source Files

None.
MD

if python3 "$root_dir/scripts/reconcile_architecture_binary_inventory.py" \
  --repo-root "$work_dir" --check >/dev/null 2>&1; then
  echo 'stale architecture binary inventory unexpectedly passed' >&2
  exit 1
fi

python3 "$root_dir/scripts/reconcile_architecture_binary_inventory.py" \
  --repo-root "$work_dir" --fix
python3 "$root_dir/scripts/reconcile_architecture_binary_inventory.py" \
  --repo-root "$work_dir" --check

grep -F '| Release binary targets | 2 |' \
  "$work_dir/docs/ARCHITECTURE_INVENTORY.md" >/dev/null
grep -F -- '- `auto_tool` — `crates/franken-engine/src/bin/auto_tool.rs` (auto)' \
  "$work_dir/docs/ARCHITECTURE_INVENTORY.md" >/dev/null
grep -F -- '- `manifest-tool` — `crates/franken-engine/src/bin/manifest_tool.rs` (manifest)' \
  "$work_dir/docs/ARCHITECTURE_INVENTORY.md" >/dev/null

printf '%s\n' 'fn main() {}' >"$work_dir/crates/franken-engine/src/bin/new_tool.rs"
if python3 "$root_dir/scripts/reconcile_architecture_binary_inventory.py" \
  --repo-root "$work_dir" --check >/dev/null 2>&1; then
  echo 'new auto binary unexpectedly escaped inventory drift detection' >&2
  exit 1
fi

python3 "$root_dir/scripts/reconcile_architecture_binary_inventory.py" \
  --repo-root "$work_dir" --fix
grep -F '| Release binary targets | 3 |' \
  "$work_dir/docs/ARCHITECTURE_INVENTORY.md" >/dev/null
grep -F -- '- `new_tool` — `crates/franken-engine/src/bin/new_tool.rs` (auto)' \
  "$work_dir/docs/ARCHITECTURE_INVENTORY.md" >/dev/null

python3 - "$work_dir/docs/ARCHITECTURE_INVENTORY.md" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
path.write_text(text.replace("## Release Binary Targets", "## Renamed Binary Targets"), encoding="utf-8")
PY
set +e
python3 "$root_dir/scripts/reconcile_architecture_binary_inventory.py" \
  --repo-root "$work_dir" --check >/dev/null 2>&1
malformed_exit=$?
set -e
if [[ "$malformed_exit" -ne 2 ]]; then
  echo "malformed inventory format returned $malformed_exit instead of 2" >&2
  exit 1
fi

printf '%s\n' 'architecture binary inventory reconciler smoke: PASS'
