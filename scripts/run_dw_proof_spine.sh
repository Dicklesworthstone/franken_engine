#!/usr/bin/env bash
# run_dw_proof_spine.sh - E6.TEST Proof-Producing Claim Spine v1 test+verify
# capstone gate (bd-fqlfw.6.6).
#
# Drives the E6 proof-spine stack through the DW.STD (bd-fqlfw.11) e2e bundle
# harness:
#   - the strict proof.json producer contract (E6.T1, proof_schema.rs),
#   - the Lean proof producer (E6.T2): green build => Passed artifact accepted
#     for FE-CLAIM-016; broken/absent toolchain => Unavailable, never Proven,
#   - the translation-validator witnesses (E6.T3): proof OR counterexample
#     artifact per validator class, bridged into the strict contract,
#   - the claim-gate classification matrix (E6.T5): Unavailable / FixtureOnly /
#     Unknown / Counterexample / Proven each map to the correct
#     promote/demote/block decision; fixture-only artifacts are REJECTED for
#     OBSERVED; stale/hash-mismatch demotes; the v2-deferred claims
#     (FE-CLAIM-018..021) stay HYPOTHESIS via Unavailable, never fabricated
#     Proven.
#
# In ci/test mode it ALSO drives the real `franken_lean_proof_producer` binary
# over the repo Lean corpus (proofs/lean4/) when the lake/lean toolchain and
# the mathlib package cache are present: the emitted proof.json must read
# verdict=passed, bind exactly FE-CLAIM-016, and be byte-identical across two
# fixed-input passes. When the toolchain is absent the live leg is recorded as
# skipped (the test steps already prove the library path), never silently
# passed.
#
# Heavy Cargo work routes through rch by default (the franken_engine session
# policy for shared Rust builds). Set DW_RUN_LOCAL=1 to fall back to a local
# cargo build (optionally with DW_CARGO_TARGET_DIR to isolate the target dir);
# the gate still emits the same content-addressed bundle.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_proof_spine" "$mode"

dw_cargo() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 \
      ${DW_CARGO_TARGET_DIR:+CARGO_TARGET_DIR="$DW_CARGO_TARGET_DIR"} \
      RUSTFLAGS='-C linker=cc' "$@"
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

rch_lib_test() {
  local filter="$1"
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --lib "$filter")" \
    dw_cargo_results dw_cargo \
      cargo test -p frankenengine-engine --lib "$filter"
}

rch_test() {
  local test_name="$1"
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --test "$test_name" -- --nocapture)" \
    dw_cargo_results dw_cargo \
      cargo test -p frankenengine-engine --test "$test_name" -- --nocapture
}

run_tests() {
  # E6.T1 strict contract + E6.T5 classification matrix.
  rch_lib_test proof_schema
  rch_lib_test proof_spine_claim_gate
  # E6.T2 Lean producer (unit) + E6.T3 witnesses (unit).
  rch_lib_test lean_proof_producer
  rch_lib_test translation_validation_proof_carrier
  # Integration lanes: gate decisions from real producer runs; witness
  # emission round-trips; the real-toolchain Lean lane (self-skipping when
  # lake/lean are absent — an explicit evidence state, not a silent pass).
  rch_test proof_spine_claim_gate_integration
  rch_test translation_validation_proof_carrier_integration
  rch_test translation_validation_receipt_integration
  rch_test lean_proof_producer_integration
}

# Locate the franken_lean_proof_producer binary for the live E2E leg.
#   $DW_LEAN_PRODUCER_BIN -> <target>/release -> <target>/debug.
dw_locate_lean_producer() {
  local candidate target_root="${DW_CARGO_TARGET_DIR:-target}"
  if [[ -n "${DW_LEAN_PRODUCER_BIN:-}" && -x "${DW_LEAN_PRODUCER_BIN}" ]]; then
    printf '%s' "${DW_LEAN_PRODUCER_BIN}"; return 0
  fi
  for candidate in "$target_root/release/franken_lean_proof_producer" \
                   "$target_root/debug/franken_lean_proof_producer"; do
    if [[ -x "$candidate" ]]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}

# Live leg: real lake/lean over proofs/lean4/ via the operator binary.
run_live_e2e() {
  if ! command -v lake >/dev/null 2>&1 || ! command -v lean >/dev/null 2>&1; then
    dw_log_event "live_e2e" "skip" \
      '{"reason":"lake/lean toolchain not on PATH (scripts/install_lean_toolchain.sh); test steps already prove the library path"}'
    return 0
  fi
  if [[ ! -d proofs/lean4/.lake/packages/mathlib ]]; then
    dw_log_event "live_e2e" "skip" \
      '{"reason":"mathlib package cache absent under proofs/lean4/.lake — cold fetch is a network dependency this gate refuses; run lake build there once"}'
    return 0
  fi

  local bin
  if ! bin="$(dw_locate_lean_producer)"; then
    dw_run_step "$(dw_cargo_label cargo build -p frankenengine-engine --bin franken_lean_proof_producer)" \
      dw_cargo \
        cargo build -p frankenengine-engine --bin franken_lean_proof_producer
    if ! bin="$(dw_locate_lean_producer)"; then
      dw_log_event "live_e2e" "skip" \
        '{"reason":"franken_lean_proof_producer binary not found after build; set DW_LEAN_PRODUCER_BIN"}'
      return 0
    fi
  fi
  dw_log_event "live_e2e" "info" "$(printf '{"lean_producer":"%s"}' "$(dw__json_escape "$bin")")"

  local e2e_root="$DW_RUN_DIR/proof_spine_e2e"
  mkdir -p "$e2e_root"

  # Two fixed-input passes must be byte-identical (repro.lock discipline).
  local pass
  for pass in a b; do
    dw_run_step "franken_lean_proof_producer over proofs/lean4 (pass ${pass})" \
      "$bin" \
        --proof-dir proofs/lean4 \
        --out "$e2e_root/FE-CLAIM-016.proof.json" \
        --invocation-id dw-proof-spine-capstone \
        --ticks 0 --epoch 1
    if [[ "$pass" == "a" ]]; then
      cp "$e2e_root/FE-CLAIM-016.proof.json" "$e2e_root/FE-CLAIM-016.proof_pass_a.json"
    fi
  done
  dw_run_step "proof.json byte-identity across passes (fixed input)" \
    diff "$e2e_root/FE-CLAIM-016.proof_pass_a.json" "$e2e_root/FE-CLAIM-016.proof.json"

  dw_run_step "proof.json binds exactly FE-CLAIM-016 with a Passed verdict" \
    bash -c '
      set -euo pipefail
      artifact="$1/FE-CLAIM-016.proof.json"
      claims=$(jq -c ".claim_ids" "$artifact")
      [[ "$claims" == "[\"FE-CLAIM-016\"]" ]] || { echo "unexpected claim_ids: $claims" >&2; exit 1; }
      jq -e ".checker_result == \"Passed\" or .checker_result.Passed != null" "$artifact" >/dev/null \
        || { echo "checker_result is not Passed" >&2; jq ".checker_result" "$artifact" >&2; exit 1; }
      for deferred in FE-CLAIM-018 FE-CLAIM-019 FE-CLAIM-020 FE-CLAIM-021; do
        if jq -e --arg c "$deferred" ".claim_ids | index(\$c)" "$artifact" >/dev/null 2>&1; then
          echo "v2-deferred claim $deferred fabricated into the artifact" >&2; exit 1
        fi
      done
    ' _ "$e2e_root"

  dw_log_event "live_e2e" "pass" '{"bundle_root":"proof_spine_e2e/"}'
}

case "$mode" in
  check)
    dw_run_step "$(dw_cargo_label cargo check -p frankenengine-engine --bin franken_lean_proof_producer --test proof_spine_claim_gate_integration --test lean_proof_producer_integration)" \
      dw_cargo \
        cargo check -p frankenengine-engine --bin franken_lean_proof_producer --test proof_spine_claim_gate_integration --test lean_proof_producer_integration
    ;;
  test|ci)
    run_tests
    run_live_e2e
    ;;
  e2e)
    run_live_e2e
    ;;
  *) echo "usage: $0 [check|test|ci|e2e]" >&2; exit 2 ;;
esac

dw_finish
