#!/usr/bin/env bash
# run_dw_span_provenance.sh — E1.TEST span-provenance gate (bd-fqlfw.1.4).
#
# Drives the span-provenance verification stack per DW.STD (bd-fqlfw.11) and
# emits the mandated audit bundle under artifacts/dw_span_provenance/<ts>/:
#
#   1. span_provenance_goldens          — exact line/column goldens for the
#      security-relevant accessors (process.env, globalThis.process, nested
#      member chains, require call sites), multi-line placement, AST
#      Member/Call statement-span equality, bare-accessor contract, and the
#      stale-doctrine regression pin (one column of drift fails).
#   2. ambient_authority_lowering_rejection_integration — the denial paths
#      the spans decorate, end to end.
#   3. A fail-closed source check that the pre-bd-fqlfw.1.2 "Currently
#      always `None`" span doctrine stays removed.
#   4. A span-coverage tally derived from the golden run's own output,
#      logged to events.jsonl by node kind; fails closed if any
#      spanned-kind golden did not pass, and records the bare-identifier
#      gap explicitly (documented, tracked — never a silent pass).
#
# Ir2Op.span coverage extends this gate when bd-fqlfw.1.5 (E1.T2b) lands.
#
# Usage: ./scripts/run_dw_span_provenance.sh ci
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_span_provenance" "$mode"

# Run a cargo test command and judge pass/fail on the TEST RESULTS, not the
# rch hook's exit code: the hook exits non-zero after an SSH-timeout retry
# even when the delivered run is fully green (observed fleet-wide
# 2026-06-11; see the bead filed from this gate's first run). Fail-closed
# semantics are preserved — any FAILED result line, compile error, panic,
# or missing 'test result: ok' line still fails the step; a wrapper-exit
# anomaly over green results passes WITH a logged anomaly line in the step
# log (never silent).
dw_cargo_results() {
  local out rc ok bad
  out=$(mktemp)
  if "$@" > "$out" 2>&1; then rc=0; else rc=$?; fi
  cat "$out"
  ok=$(grep -c '^test result: ok\.' "$out" || true)
  bad=$(grep -cE '^test result: FAILED|^error(\[|:)|panicked at' "$out" || true)
  rm -f "$out"
  if [[ "$bad" -eq 0 && "$ok" -ge 1 ]]; then
    if [[ "$rc" -ne 0 ]]; then
      echo "[dw-anomaly] wrapper exit=$rc with fully green test results — rch hook timeout-exit bug; passing on results"
    fi
    return 0
  fi
  return $(( rc == 0 ? 1 : rc ))
}

dw_run_step "cargo test -p frankenengine-engine --test span_provenance_goldens" \
  dw_cargo_results cargo test -p frankenengine-engine --test span_provenance_goldens

dw_run_step "cargo test -p frankenengine-engine --test ambient_authority_lowering_rejection_integration" \
  dw_cargo_results cargo test -p frankenengine-engine --test ambient_authority_lowering_rejection_integration

dw_run_step "stale span doctrine stays removed from lowering_pipeline.rs" \
  bash -c '! grep -q "Currently always \`None\`" crates/franken-engine/src/lowering_pipeline.rs'

# Span-coverage tally by node kind, derived from the golden run's own log
# (steps/01_*.log) rather than hardcoded numbers.
tally_coverage() {
  local log
  log="$(ls "$DW_STEPS_DIR"/01_*.log)"
  local spanned_ok spanned_expected bare_ok bare_expected
  # Spanned-kind goldens assert Some(span) with exact values.
  spanned_expected=$(grep -c '^fn golden_' crates/franken-engine/tests/span_provenance_goldens.rs || true)
  bare_expected=$(grep -c '^fn golden_bare_' crates/franken-engine/tests/span_provenance_goldens.rs || true)
  # Non-span structural tests (doc pin, strictness) are excluded from the
  # spanned tally below.
  local meta_expected
  meta_expected=$(grep -cE '^fn golden_(stale|span_convention)' crates/franken-engine/tests/span_provenance_goldens.rs || true)
  spanned_expected=$((spanned_expected - bare_expected - meta_expected))
  spanned_ok=$(grep -cE '^test golden_.* \.\.\. ok$' "$log" || true)
  bare_ok=$(grep -cE '^test golden_bare_.* \.\.\. ok$' "$log" || true)
  local meta_ok
  meta_ok=$(grep -cE '^test golden_(stale|span_convention).* \.\.\. ok$' "$log" || true)
  spanned_ok=$((spanned_ok - bare_ok - meta_ok))

  local pct=0
  [[ "$spanned_expected" -gt 0 ]] && pct=$((100 * spanned_ok / spanned_expected))
  dw_log_event "span_coverage_tally" "info" "$(printf \
    '{"spanned_kind_goldens":{"ok":%d,"expected":%d,"coverage_pct":%d},"bare_identifier_goldens":{"ok":%d,"expected":%d,"contract":"span None — documented gap, tracked by identifier-span follow-up + bd-fqlfw.1.5"},"granularity":"statement (sub-expression precision is a tracked follow-up)"}' \
    "$spanned_ok" "$spanned_expected" "$pct" "$bare_ok" "$bare_expected")"
  if [[ "$pct" -ne 100 || "$bare_ok" -ne "$bare_expected" ]]; then
    echo "span coverage below contract: spanned ${spanned_ok}/${spanned_expected}, bare ${bare_ok}/${bare_expected}" >&2
    return 1
  fi
}

dw_run_step "span-coverage tally by node kind (fail-closed at 100% of spanned kinds)" \
  tally_coverage

dw_finish
