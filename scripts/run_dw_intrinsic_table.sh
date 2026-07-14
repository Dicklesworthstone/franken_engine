#!/usr/bin/env bash
# run_dw_intrinsic_table.sh - E4.TEST intrinsic-table gate (bd-fqlfw.4.6).
#
# Drives the declarative intrinsic-table verification stack per DW.STD
# (bd-fqlfw.11) and emits the mandated audit bundle under
# artifacts/dw_intrinsic_table/<ts>/.
#
# Usage: ./scripts/run_dw_intrinsic_table.sh ci
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_intrinsic_table" "$mode"

dw_rustflags="$(dw_compose_linker_policy_rustflags "${RUSTFLAGS:--C linker=cc -C debuginfo=0}")"

rch_cargo() {
  local target_dir
  target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_dw_intrinsic_table_${USER:-agent}}"
  env -u CARGO_ENCODED_RUSTFLAGS \
    RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" \
    CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
    CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}" \
    RUSTFLAGS="$dw_rustflags" \
    CARGO_TARGET_DIR="$target_dir" \
    rch exec --no-self-healing -- env -u CARGO_ENCODED_RUSTFLAGS "$@"
}

run_source_guards() {
  dw_run_step "intrinsic-table codegen remains glue-only" \
    bash -c '! grep -nE "fn string_|match .*Value|=> .*Value" crates/franken-engine/src/intrinsics_codegen.rs'

  dw_run_step "Secret receiver IFC regression remains wired" \
    grep -q "table_dispatch_propagates_secret_receiver_label_to_dst" crates/franken-engine/src/baseline_interpreter.rs

  dw_run_step "intrinsic-table replay wrapper is executable" \
    test -x scripts/e2e/dw_intrinsic_table_replay.sh
}

run_tests() {
  dw_run_step "cargo test -p frankenengine-engine intrinsics_codegen --lib -- --nocapture" \
    dw_cargo_results rch_cargo cargo test -p frankenengine-engine intrinsics_codegen --lib -- --nocapture

  dw_run_step "cargo test -p frankenengine-engine string_intrinsic_table_parity_tests --lib -- --nocapture" \
    dw_cargo_results rch_cargo cargo test -p frankenengine-engine string_intrinsic_table_parity_tests --lib -- --nocapture

  dw_run_step "cargo test -p frankenengine-engine --test intrinsic_table_string_family_migration -- --nocapture" \
    dw_cargo_results rch_cargo cargo test -p frankenengine-engine --test intrinsic_table_string_family_migration -- --nocapture
}

case "$mode" in
  check)
    dw_run_step "cargo check -p frankenengine-engine --test intrinsic_table_string_family_migration" \
      rch_cargo cargo check -p frankenengine-engine --test intrinsic_table_string_family_migration
    ;;
  test)
    run_source_guards
    run_tests
    ;;
  ci)
    dw_run_step "cargo check -p frankenengine-engine --test intrinsic_table_string_family_migration" \
      rch_cargo cargo check -p frankenengine-engine --test intrinsic_table_string_family_migration
    run_source_guards
    run_tests
    ;;
  *) echo "usage: $0 [check|test|ci]" >&2; exit 2 ;;
esac

dw_finish
