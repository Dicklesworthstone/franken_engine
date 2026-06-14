#!/usr/bin/env bash
# run_dw_authority_check.sh - E5.TEST authority/intake analyzer gate (bd-fqlfw.5.5).
#
# Drives the E5 capstone stack through the DW.STD bundle harness:
#   - file-level frankenctl check integration,
#   - package-level frankenctl onboard integration,
#   - authority/intake capstone assertions,
#   - franken-lsp diagnostics/hover/code-lens protocol assertions.
#
# Heavy Cargo work is routed through rch, matching the franken_engine session
# policy for shared Rust builds.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_authority_check" "$mode"

rch_test() {
  local test_name="$1"
  dw_run_step "rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' cargo test -p frankenengine-engine --test ${test_name} -- --nocapture" \
    dw_cargo_results rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
      cargo test -p frankenengine-engine --test "$test_name" -- --nocapture
}

run_tests() {
  rch_test frankenctl_check_authority_footprint
  rch_test package_intake_integration
  rch_test authority_footprint_capstone
  rch_test franken_lsp_authority_footprint
}

case "$mode" in
  check)
    dw_run_step "rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' cargo check -p frankenengine-engine --bin frankenctl --bin franken-lsp --test authority_footprint_capstone" \
      rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
        cargo check -p frankenengine-engine --bin frankenctl --bin franken-lsp --test authority_footprint_capstone
    ;;
  test|ci)
    run_tests
    ;;
  *) echo "usage: $0 [check|test|ci]" >&2; exit 2 ;;
esac

dw_finish
