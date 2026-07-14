#!/usr/bin/env bash
# run_dw_authority_check.sh - E5.TEST authority/intake analyzer gate (bd-fqlfw.5.5).
#
# Drives the E5 capstone stack through the DW.STD bundle harness:
#   - file-level frankenctl check integration,
#   - package-level frankenctl onboard integration,
#   - authority/intake capstone assertions,
#   - franken-lsp diagnostics/hover/code-lens protocol assertions.
#
# Heavy Cargo work is routed through rch by default, matching the franken_engine
# session policy for shared Rust builds. Set DW_RUN_LOCAL=1 to fall back to a local
# cargo build (e.g. when rch workers are unavailable); the gate still emits the same
# content-addressed bundle.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_authority_check" "$mode"

dw_rustflags="$(dw_compose_linker_policy_rustflags "${RUSTFLAGS:--C linker=cc}")"
printf -v dw_rustflags_shell '%q' "$dw_rustflags"

# Heavy Cargo work routes through rch by default (the franken_engine session
# policy for shared Rust builds). When rch is unavailable (e.g. a worker-side
# sibling-crate drift), set DW_RUN_LOCAL=1 to fall back to a local cargo build so
# the gate still emits a real content-addressed bundle instead of hanging on rch.
dw_cargo() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    env -u CARGO_ENCODED_RUSTFLAGS \
      RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 RUSTFLAGS="$dw_rustflags" "$@"
  else
    env -u CARGO_ENCODED_RUSTFLAGS \
      rch exec -- env -u CARGO_ENCODED_RUSTFLAGS \
      CARGO_INCREMENTAL=0 RUSTFLAGS="$dw_rustflags" "$@"
  fi
}

dw_cargo_label() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    printf 'DW_RUN_LOCAL=1 env -u CARGO_ENCODED_RUSTFLAGS RCH_CARGO_WRAPPER_BYPASS=1 RUSTFLAGS=%s %s' "$dw_rustflags_shell" "$*"
  else
    printf 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL=0 RUSTFLAGS=%s %s' "$dw_rustflags_shell" "$*"
  fi
}

rch_test() {
  local test_name="$1"
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --test "$test_name" -- --nocapture)" \
    dw_cargo_results dw_cargo \
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
    dw_run_step "$(dw_cargo_label cargo check -p frankenengine-engine --bin frankenctl --bin franken-lsp --test authority_footprint_capstone)" \
      dw_cargo \
        cargo check -p frankenengine-engine --bin frankenctl --bin franken-lsp --test authority_footprint_capstone
    ;;
  test|ci)
    run_tests
    ;;
  *) echo "usage: $0 [check|test|ci]" >&2; exit 2 ;;
esac

dw_finish
