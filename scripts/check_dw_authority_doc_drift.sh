#!/usr/bin/env bash
# check_dw_authority_doc_drift.sh — DW.DOCS doc-drift guard for the E5
# authority/intake analyzer (bd-fqlfw.5.6).
#
# Fails closed if the operator-facing docs (the runbook, the README Command
# Reference section, the franken-lsp setup doc, and the analyzed-subset doc) quote a
# CLI surface, an exit code, a finding/claim ID, a gate/replay script, or a bounded
# wording that no longer matches the shipped source of truth.
#
# Usage: scripts/check_dw_authority_doc_drift.sh   (exit 0 = no drift, 1 = drift)
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

RUNBOOK="runbooks/dw_authority_check.md"
SUBSET_DOC="docs/AUTHORITY_FOOTPRINT_ANALYZED_SUBSET_V1.md"
LSP_DOC="docs/dueling_wizards/FRANKEN_LSP_EDITOR_SETUP.md"
README="README.md"
CLI_SRC="crates/franken-engine/src/bin/frankenctl.rs"
ANALYZER_SRC="crates/franken-engine/src/authority_footprint.rs"
LSP_SRC="crates/franken-engine/src/bin/franken_lsp.rs"
GATE="scripts/run_dw_authority_check.sh"
REPLAY="scripts/e2e/dw_authority_check_replay.sh"
MATRIX="docs/claim_to_proof_matrix_v1.json"

fail=0
note() { printf '  drift: %s\n' "$1" >&2; fail=1; }
have() { grep -qF -- "$2" "$1" 2>/dev/null; }

echo "[doc-drift] E5 authority/intake analyzer docs vs source of truth"

# 1. Required files exist.
for f in "$RUNBOOK" "$SUBSET_DOC" "$LSP_DOC" "$README" "$CLI_SRC" "$ANALYZER_SRC" \
         "$LSP_SRC" "$GATE" "$REPLAY" "$MATRIX"; do
  [ -f "$f" ] || note "missing required file: $f"
done

# 2. The subcommands the docs document must exist in the shipped CLI usage().
for sub in "frankenctl check" "frankenctl onboard"; do
  have "$CLI_SRC" "$sub" || note "CLI usage() no longer advertises: $sub"
  have "$RUNBOOK" "$sub" || note "runbook no longer documents: $sub"
  have "$README" "$sub" || note "README Command Reference no longer lists: $sub"
done

# 2b. README links to the runbook + LSP setup doc must resolve to real files.
have "$README" "runbooks/dw_authority_check.md" || note "README lost the runbook link"
have "$README" "FRANKEN_LSP_EDITOR_SETUP.md" || note "README lost the LSP setup link"

# 2c. The LSP setup doc must name the franken-lsp binary that ships.
have "$LSP_DOC" "franken-lsp" || note "LSP setup doc no longer names the franken-lsp binary"

# 3. Exit codes: the analyzed-subset doc is the canonical table (backtick-wrapped
#    codes). All three must be listed.
for code in '`0`' '`1`' '`2`'; do
  have "$SUBSET_DOC" "$code" || note "analyzed-subset doc dropped exit code row '$code'"
done

# 4. Finding codes the docs name must still be emitted by the analyzer.
for fe in "FE-CAP-0001" "FE-CAP-0002" "FE-CAP-0003"; do
  have "$ANALYZER_SRC" "$fe" || note "analyzer no longer emits $fe (doc references it)"
done

# 5. The gate + replay wrapper the runbook points at must be runnable.
[ -x "$GATE" ] || note "$GATE is not executable"
[ -x "$REPLAY" ] || note "$REPLAY is not executable"
have "$RUNBOOK" "run_dw_authority_check.sh" || note "runbook lost the gate-script reference"

# 6. The local-fallback the runbook documents must exist in the gate.
have "$GATE" "DW_RUN_LOCAL" || note "gate lost DW_RUN_LOCAL fallback (runbook documents it)"
have "$RUNBOOK" "DW_RUN_LOCAL" || note "runbook lost the DW_RUN_LOCAL note"

# 7. The cited claim ID must exist in the claim-to-proof matrix.
have "$MATRIX" "FE-CLAIM-006" || note "claim matrix no longer carries FE-CLAIM-006 (docs cite it)"

# 8. Bounded-wording invariant: docs must keep the supported-syntax framing and
#    must keep the explicit "not a noninterference proof" bound (never drop it).
have "$SUBSET_DOC" "not a proof of noninterference" \
  || note "analyzed-subset doc dropped the 'not a proof of noninterference' bound"
have "$RUNBOOK" "never a noninterference proof" \
  || note "runbook dropped the 'never a noninterference proof' bound"

if [ "$fail" -ne 0 ]; then
  echo "[doc-drift] FAIL — docs drifted from the shipped surface" >&2
  exit 1
fi
echo "[doc-drift] OK — docs match the shipped CLI / exit codes / claim state"
