#!/usr/bin/env bash
# check_conformance_frontier_docs.sh — doc-drift guard for the E7 Conformance
# Frontier docs (DW.DOCS deliverable #6, bd-fqlfw.7.7).
#
# Fails closed if the conformance-frontier documentation drifts from the shipped
# surface. The sources of truth are:
#   - the binary surface:   crates/franken-engine/src/bin/franken_coverage_frontier.rs
#                           (the USAGE/--help text + the real ExitCode returns)
#   - the coverage views:   crates/franken-engine/src/coverage_summary.rs (CoverageView)
#   - the claim state:      docs/claim_to_proof_matrix_v1.json (FE-CLAIM-026)
#   - the shipped gate/replay/example paths on disk
# The documents checked against them are README.md, runbooks/dw_conformance_frontier.md,
# and examples/24_conformance_frontier/README.md.
#
# Pure bash + grep + python3 (json); no cargo build required, deterministic.
set -uo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.." || { echo "cannot cd to repo root" >&2; exit 2; }

BIN_SRC="crates/franken-engine/src/bin/franken_coverage_frontier.rs"
SUMMARY_SRC="crates/franken-engine/src/coverage_summary.rs"
MATRIX="docs/claim_to_proof_matrix_v1.json"
README="README.md"
RUNBOOK="runbooks/dw_conformance_frontier.md"
EXAMPLE_README="examples/24_conformance_frontier/README.md"

fail=0
pass=0
note() { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
err()  { printf '  FAIL %s\n' "$1" >&2; fail=$((fail + 1)); }

# A required input file is missing -> hard fail (cannot verify).
for f in "$BIN_SRC" "$SUMMARY_SRC" "$MATRIX" "$README" "$RUNBOOK" "$EXAMPLE_README"; do
  [[ -f "$f" ]] || { echo "missing source-of-truth file: $f" >&2; exit 2; }
done

echo "== A. modes & flags: documented in the runbook AND present in the binary surface =="
# Each frontier flag must exist in the binary USAGE text and be documented in the runbook.
FLAGS=(--report --run-suite --engine-core-oracle --rank --file-beads --execute \
       --ledger --top-n --parent --usage-signal --cross-reference --coverage-summary --out)
for flag in "${FLAGS[@]}"; do
  if ! grep -q -- "$flag" "$BIN_SRC"; then err "flag $flag absent from binary surface ($BIN_SRC)"; continue; fi
  if ! grep -q -- "$flag" "$RUNBOOK"; then err "flag $flag not documented in runbook"; continue; fi
  note "flag $flag present in binary + runbook"
done

echo "== B. mutual exclusivity: doc claim is enforced in code =="
if grep -q "mutually exclusive" "$BIN_SRC" && grep -qi "mutually exclusive" "$RUNBOOK"; then
  note "the four report modes are documented AND enforced as mutually exclusive"
else
  err "mutual-exclusivity claim drifted between runbook and binary"
fi

echo "== C. exit codes: documented set matches the binary's real returns =="
# The frontier binary returns exactly {0, 2, 3}. It must NOT be documented as having
# an exit 4 (that belongs to the differential oracle — a common copy-paste drift).
if grep -q "ExitCode::from(2)" "$BIN_SRC" && grep -q "ExitCode::from(3)" "$BIN_SRC"; then
  note "binary returns exit 2 and exit 3"
else
  err "binary no longer returns the documented exit 2/3 set"
fi
if grep -q "ExitCode::from(4)" "$BIN_SRC"; then
  err "binary now returns exit 4 but docs do not document it"
else
  note "binary has no exit 4 (matches docs)"
fi
for code in '| 0 |' '| 2 |' '| 3 |'; do
  if grep -qF "$code" "$RUNBOOK"; then note "runbook documents exit code row '$code'"; else err "runbook missing exit code row '$code'"; fi
done

echo "== D. claim state: FE-CLAIM-026 is TARGETED in the matrix and in the docs =="
state="$(python3 -c "
import json,sys
m=json.load(open('$MATRIX'))
claims=m.get('claims',m) if isinstance(m,dict) else m
for c in (claims if isinstance(claims,list) else claims.values()):
    if c.get('claim_id')=='FE-CLAIM-026':
        print(c.get('actual_wording_state','')); sys.exit(0)
sys.exit(3)
" 2>/dev/null)"
if [[ "$state" == "target" ]]; then
  note "matrix: FE-CLAIM-026 actual_wording_state = target"
else
  err "matrix: FE-CLAIM-026 state is '$state' (expected 'target'); docs may be stale"
fi
for doc in "$README" "$RUNBOOK" "$EXAMPLE_README"; do
  if ! grep -q "FE-CLAIM-026" "$doc"; then err "$doc does not mention FE-CLAIM-026"; continue; fi
  if ! grep -qi "TARGETED" "$doc"; then err "$doc mentions FE-CLAIM-026 but not its TARGETED state"; continue; fi
  # Never describe FE-CLAIM-026 as OBSERVED (state-upgrade drift).
  if grep -n "FE-CLAIM-026" "$doc" | grep -qi "OBSERVED"; then err "$doc describes FE-CLAIM-026 as OBSERVED (forbidden upgrade)"; continue; fi
  note "$doc: FE-CLAIM-026 documented as TARGETED"
done

echo "== E. coverage views: the six documented views match the CoverageView enum =="
mapfile -t VIEWS < <(grep -oE 'CoverageView::[A-Za-z]+ => "[a-z-]+"' "$SUMMARY_SRC" | sed -E 's/.*=> "//; s/"$//')
if [[ ${#VIEWS[@]} -ne 6 ]]; then
  err "expected 6 CoverageView variants, found ${#VIEWS[@]} in $SUMMARY_SRC"
else
  note "CoverageView exposes 6 views: ${VIEWS[*]}"
fi
for view in "${VIEWS[@]}"; do
  for doc in "$README" "$RUNBOOK"; do
    if grep -qF "$view" "$doc"; then note "view '$view' documented in $(basename "$doc")"; else err "view '$view' missing from $(basename "$doc")"; fi
  done
done

echo "== F. referenced artifacts exist on disk =="
ARTIFACTS=(
  scripts/run_dw_conformance_frontier.sh
  scripts/e2e/dw_conformance_frontier_replay.sh
  scripts/run_coverage_summary_bundle_gate.sh
  examples/24_conformance_frontier/demo.sh
  runbooks/dw_conformance_frontier.md
)
for a in "${ARTIFACTS[@]}"; do
  if [[ -e "$a" ]]; then note "exists: $a"; else err "referenced artifact missing: $a"; fi
done

echo
if [[ "$fail" -eq 0 ]]; then
  echo "PASS: conformance-frontier docs are consistent with the shipped surface ($pass checks)."
  exit 0
else
  echo "FAIL: $fail drift(s) detected ($pass ok). Reconcile the docs with the source of truth above." >&2
  exit 1
fi
