#!/usr/bin/env bash
# No-mock negative drill for the inventory-doc half of
# scripts/check_readme_inventory.py (BRIDGE-00.8 item 3).
#
# docs/ARCHITECTURE_INVENTORY.md calls itself "an exact golden artifact" in its own
# header, and until 2026-07-26 nothing enforced that. It reported 495 source modules
# from April onward while the tree carried 621 -- three months of silent rot in a
# repository whose entire discipline is that drift fails closed.
#
# In a healthy tree the guard reports 23/23 ok and exits 0, which proves nothing
# about its ability to detect anything. This drill builds a synthetic tree, injects
# each drift shape the real rot took, and asserts the guard rejects every one.
#
# The four shapes, each a thing that actually happens:
#   1. a module exists in the tree but is absent from the doc  (a module was added)
#   2. a module is listed in the doc but absent from the tree  (a module was deleted)
#   3. the Summary count disagrees with the list beneath it    (hand-patched to pass)
#   4. a `pub mod` line moved in lib.rs without regeneration   (exports reordered)
#
# Shape 3 is the one worth having. The cheap way to "fix" a failing count is to edit
# the number, and that edit is invisible to any check that only reads the number.
#
# Hermetic: no cargo, no /dp siblings, nothing outside the temp dir is touched.
#
# Usage: ./scripts/e2e/architecture_inventory_gate_drift.sh
# Exit:  0 the guard rejected every injected drift; 1 the drill failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARD="${REPO_ROOT}/scripts/check_readme_inventory.py"
WORK="$(mktemp -d -t arch_inventory_drift.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

SRC="${WORK}/crates/franken-engine/src"
mkdir -p "${SRC}/nested" "${WORK}/docs"

cat >"${SRC}/lib.rs" <<'EOF'
pub mod alpha;
pub mod beta_gate;
pub mod nested;
EOF
: >"${SRC}/alpha.rs"
: >"${SRC}/beta_gate.rs"
: >"${SRC}/nested/mod.rs"

# The doc as a correct generator run would render it. Keep this byte-shape in sync
# with architecture_inventory.rs::render_markdown -- the em-dashes are U+2014.
write_doc() {
  cat >"${WORK}/docs/ARCHITECTURE_INVENTORY.md" <<EOF
# FrankenEngine Architecture Inventory

## Summary

| Metric | Count |
| --- | ---: |
| Source module files | ${1} |
| lib.rs public module exports | 3 |
| Disabled lib.rs exports | 0 |
| Gate module files | 1 |
| Release binary targets | 0 |
| Missing exported source files | 0 |
| Unexported root module files | 0 |

## Source Module Files

${2}

## lib.rs Public Module Exports

- \`alpha\` — line 1
- \`beta_gate\` — line 2
- \`nested\` — line ${3}

## Disabled lib.rs Exports

None.

## Gate Module Files

- \`beta_gate\` — \`crates/franken-engine/src/beta_gate.rs\`

## Release Binary Targets

None.

## Missing Exported Source Files

None.

## Unexported Root Module Files

None.
EOF
}

ALL_MODULES="- \`alpha\` — \`crates/franken-engine/src/alpha.rs\`
- \`beta_gate\` — \`crates/franken-engine/src/beta_gate.rs\`
- \`nested\` — \`crates/franken-engine/src/nested/mod.rs\`"

run_guard() {
  set +e
  python3 "$GUARD" --repo-root "$WORK" --section inventory-doc \
    --json "${WORK}/report.json" >"${WORK}/stdout.txt" 2>"${WORK}/stderr.txt"
  guard_exit=$?
  set -e
}

fail() {
  echo "DRILL FAILED: $1" >&2
  echo "--- guard stdout ---" >&2; cat "${WORK}/stdout.txt" >&2 || true
  echo "--- guard stderr ---" >&2; cat "${WORK}/stderr.txt" >&2 || true
  exit 1
}

# Baseline: a correct doc must pass, or every rejection below proves nothing.
write_doc 3 "$ALL_MODULES" 3
run_guard
[[ "$guard_exit" -eq 0 ]] || fail "healthy synthetic tree rejected (exit ${guard_exit})"
echo "  baseline: correct doc accepted"

assert_drift() {
  local label="$1" surface="$2"
  run_guard
  [[ "$guard_exit" -eq 1 ]] || fail "${label}: expected exit 1, got ${guard_exit}"
  python3 - "${WORK}/report.json" "$surface" <<'PY' || fail "${label}: report did not name the drifted surface"
import json, sys
report = json.load(open(sys.argv[1]))
surface = sys.argv[2]
rows = {r["surface"]: r for r in report["rows"]}
row = rows.get(surface)
assert row is not None, f"no row for {surface}; got {sorted(rows)}"
assert row["status"] == "drift", f"{surface} status={row['status']!r}"
assert report["summary"]["inventory_doc_drift"] >= 1, report["summary"]
PY
  echo "  rejected: ${label}"
}

# 1. A module present in the tree, missing from the doc.
write_doc 2 "- \`alpha\` — \`crates/franken-engine/src/alpha.rs\`
- \`beta_gate\` — \`crates/franken-engine/src/beta_gate.rs\`" 3
assert_drift "module added to tree but absent from doc" inventory_doc.source_modules

# 2. A module listed in the doc that no longer exists.
write_doc 4 "${ALL_MODULES}
- \`deleted_module\` — \`crates/franken-engine/src/deleted_module.rs\`" 3
assert_drift "module deleted from tree but still listed" inventory_doc.source_modules

# 3. Summary hand-patched away from the list beneath it. The list is correct here,
#    so only the Summary row may fail -- that is the point of checking both.
write_doc 999 "$ALL_MODULES" 3
assert_drift "Summary count hand-patched" inventory_doc.summary.source_module_files
python3 - "${WORK}/report.json" <<'PY' || fail "Summary drill also flagged the list, so it did not isolate the Summary"
import json, sys
rows = {r["surface"]: r for r in json.load(open(sys.argv[1]))["rows"]}
assert rows["inventory_doc.source_modules"]["status"] == "ok", rows["inventory_doc.source_modules"]
PY

# 4. An export whose recorded line number no longer matches lib.rs.
write_doc 3 "$ALL_MODULES" 99
assert_drift "pub mod line number moved" inventory_doc.lib_exports

echo "architecture_inventory_gate_drift=passed shapes_rejected=4 baseline_accepted=1"
