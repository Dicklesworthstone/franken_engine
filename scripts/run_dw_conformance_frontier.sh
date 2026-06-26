#!/usr/bin/env bash
# run_dw_conformance_frontier.sh - E7.TEST conformance-frontier test+verify capstone
# gate (bd-fqlfw.7.6).
#
# Drives the whole E7 conformance-frontier stack through the DW.STD (bd-fqlfw.11)
# e2e bundle harness:
#   - the capstone integration test (deterministic clustering, ranking
#     reproducibility, truth-gate drift detection, weighted-coverage views + gated
#     number, idempotent auto-bead filing with E4 scaffolds, and the operator-binary
#     E2E over the real engine<->core oracle),
#   - the per-module unit tests for each rung: coverage_frontier (T1),
#     coverage_frontier_rank (T2), coverage_frontier_xref (T3), coverage_summary
#     (T4), coverage_frontier_filing (T5).
#
# In ci/test mode it ALSO runs the real `franken_coverage_frontier` binary over the
# in-process engine<->core differential oracle in its rank / coverage-summary /
# file-beads modes, persisting each report into the run dir, and PROVES determinism
# by emitting the file-beads plan twice and asserting the two plan digests are
# identical. The live corpus is best-effort: if no binary is available it is
# recorded as skipped (the capstone test already proves the CLI path via
# CARGO_BIN_EXE), never silently passed.
#
# Heavy Cargo work routes through rch by default (the franken_engine session policy
# for shared Rust builds). Set DW_RUN_LOCAL=1 to fall back to a local cargo build
# (e.g. when rch workers are unavailable); the gate still emits the same
# content-addressed bundle.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_conformance_frontier" "$mode"

dw_cargo() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' "$@"
  else
    rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' "$@"
  fi
}

dw_cargo_label() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    printf 'DW_RUN_LOCAL env RCH_CARGO_WRAPPER_BYPASS=1 %s' "$*"
  else
    printf "rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' %s" "$*"
  fi
}

rch_test() {
  local test_name="$1"
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --test "$test_name" -- --nocapture)" \
    dw_cargo_results dw_cargo \
      cargo test -p frankenengine-engine --test "$test_name" -- --nocapture
}

# The per-rung in-module unit tests across the whole E7 chain (T1..T5).
rch_lib_test() {
  local filter="$1"
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --lib "$filter" -- --nocapture)" \
    dw_cargo_results dw_cargo \
      cargo test -p frankenengine-engine --lib "$filter" -- --nocapture
}

run_tests() {
  rch_test dw_conformance_frontier_capstone
  rch_lib_test coverage_frontier::tests::
  rch_lib_test coverage_frontier_rank::tests::
  rch_lib_test coverage_frontier_xref::tests::
  rch_lib_test coverage_summary::tests::
  rch_lib_test coverage_frontier_filing::tests::
}

# Run the real binary over the in-process engine<->core oracle in each report mode,
# persisting outputs and proving the file-beads plan is deterministic across runs.
#
# Binary acquisition: unless the operator pins one via DW_FRONTIER_BIN, we BUILD a
# fresh dev binary here rather than trust a possibly-stale `target/release` build —
# a prior release build can predate newer modes (e.g. --file-beads) and would
# reject them. In ci/test mode the capstone test step already built target/debug,
# so this build is a cheap cache hit.
run_live_corpus() {
  local bin
  if [[ -n "${DW_FRONTIER_BIN:-}" && -x "${DW_FRONTIER_BIN}" ]]; then
    bin="${DW_FRONTIER_BIN}"
  else
    dw_run_step "$(dw_cargo_label cargo build -p frankenengine-engine --bin franken_coverage_frontier)" \
      dw_cargo cargo build -p frankenengine-engine --bin franken_coverage_frontier
    bin="target/debug/franken_coverage_frontier"
  fi
  if [[ ! -x "$bin" ]]; then
    dw_log_event "live_corpus" "skip" \
      '{"reason":"franken_coverage_frontier binary unavailable after build attempt; the capstone test already proves the CLI path via CARGO_BIN_EXE"}'
    return 0
  fi
  dw_log_event "live_corpus" "info" "$(printf '{"frontier":"%s"}' "$(dw__json_escape "$bin")")"

  local corpus="$DW_RUN_DIR/frontier_corpus"
  mkdir -p "$corpus"

  dw_run_step "franken_coverage_frontier --engine-core-oracle --rank -> frontier_corpus/rank.json" \
    "$bin" --engine-core-oracle --rank --out "$corpus/rank.json"
  dw_run_step "franken_coverage_frontier --engine-core-oracle --coverage-summary -> frontier_corpus/summary.json" \
    "$bin" --engine-core-oracle --coverage-summary --out "$corpus/summary.json"
  dw_run_step "franken_coverage_frontier --engine-core-oracle --file-beads (plan A)" \
    "$bin" --engine-core-oracle --file-beads --out "$corpus/plan_a.json"
  dw_run_step "franken_coverage_frontier --engine-core-oracle --file-beads (plan B)" \
    "$bin" --engine-core-oracle --file-beads --out "$corpus/plan_b.json"

  # Determinism: the two independently-emitted file-beads plans are byte-identical.
  dw_run_step "assert file-beads plan is deterministic (plan_a == plan_b)" \
    bash -c 'diff -q "$1/plan_a.json" "$1/plan_b.json" >/dev/null || { echo "file-beads plan is non-deterministic" >&2; exit 1; }' _ "$corpus"

  # Structural: each report mode produced its content-addressed report file.
  dw_run_step "assert frontier report files present (rank/summary/plan)" \
    bash -c 'for f in rank.json summary.json plan_a.json plan_b.json; do [ -f "$1/$f" ] || { echo "missing $f" >&2; exit 1; }; done' _ "$corpus"

  dw_log_event "live_corpus" "pass" \
    '{"modes":["rank","coverage-summary","file-beads x2"],"corpus_root":"frontier_corpus/","determinism":"plan_a==plan_b"}'
}

case "$mode" in
  check)
    dw_run_step "$(dw_cargo_label cargo check -p frankenengine-engine --bin franken_coverage_frontier --test dw_conformance_frontier_capstone)" \
      dw_cargo \
        cargo check -p frankenengine-engine --bin franken_coverage_frontier --test dw_conformance_frontier_capstone
    ;;
  test|ci)
    run_tests
    run_live_corpus
    ;;
  corpus)
    run_live_corpus
    ;;
  *) echo "usage: $0 [check|test|ci|corpus]" >&2; exit 2 ;;
esac

dw_finish
