#!/usr/bin/env bash
# run_dw_specialization_shadow.sh - E9.TEST Specialization Lane test+verify
# capstone gate (bd-fqlfw.9.6, SAFETY-CRITICAL).
#
# Drives the E9 security-proof-guided specialization stack (shadow-first)
# through the DW.STD (bd-fqlfw.11) e2e bundle harness:
#   - SHADOW INVARIANT (E9.T1/T2): with the lane in shadow mode, discovery
#     and equivalence validation provably change NOTHING about runtime
#     semantics — execution values, tick counts, and nondeterminism traces
#     are byte-identical with and without the lane (the whole safety
#     premise). Candidates land inactive with run-independent ids.
#   - EQUIVALENCE RECEIPTS FAIL-CLOSED (E9.T2): verdicts derive from real
#     differential run facts; nothing defaults to proven; inconclusive and
#     disproven candidates are QUARANTINED, never activated; the
#     proof -> specialization receipt -> benchmark chain persists and joins.
#   - REPLAY IDENTITY (E9.T3): the replay-identity hash binds full trace
#     content to the execution lane and its specialization receipt hashes;
#     strict replay either reproduces the same specialization or forces
#     baseline with output-equivalence verification - never silently a
#     different path.
#   - SAFE MODE (E9.T3): the kill switch provably disables ALL
#     specializations; unknown/missing/stale proof, epoch change, and
#     receipt mismatch all fall back to baseline with typed reasons.
#   - ACTIVATION v1 (E9.T4): the first activated path (capability-pruned
#     hostcall dispatch metadata) is low-blast-radius, measured faster at
#     the dispatch-decision level, byte-equivalent at the execution level,
#     and falls back safely on any of the seven gate-binding failures.
#   - NO-ELISION INVARIANT: dedicated named tests assert NO IFC/containment
#     check elision exists anywhere in v1 - no discovery family proposes
#     IfcCheckElision, and the activation gate refuses it by construction.
#
# The integration lanes ARE the live end-to-end evidence: they parse, lower,
# and execute real programs through the real orchestrator/interpreter and
# assert acceptance on the resulting artifacts (no fixtures, no mocks).
#
# Heavy Cargo work routes through rch by default (the franken_engine session
# policy for shared Rust builds). Set DW_RUN_LOCAL=1 to fall back to a local
# cargo build (optionally with DW_CARGO_TARGET_DIR to isolate the target
# dir); the gate still emits the same content-addressed bundle.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_specialization_shadow" "$mode"

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
  # E9.T1 shadow discovery: unproven lanes never proposed, candidate ids
  # run-independent, activation pinned off, inactive empty-proof receipts.
  rch_lib_test e9_shadow_candidate_discovery
  # E9.T2 equivalence lane: fail-closed verdicts, quarantine of disproven
  # AND inconclusive, chain persistence + idempotency, invalidation reasons.
  rch_lib_test e9_equivalence_receipts
  # E9.T3 replay identity + kill switch: lane-bound identity hashes, strict
  # lane rule (same-lane-or-forced-baseline), fail-closed lane resolution.
  rch_lib_test deterministic_replay
  # E9.T4 activation gate: seven bindings, typed refusals, byte-equivalent
  # activated execution, table-miss fall-through, measured benchmark.
  rch_lib_test e9_first_activation

  # Integration lanes: real parse -> lower -> execute -> evidence flows.
  rch_test e9_shadow_candidate_discovery_integration
  rch_test e9_equivalence_receipts_integration
  rch_test e9_replay_identity_integration
  rch_test e9_first_activation_integration
}

# SAFETY-CRITICAL invariant lane: the named tests that pin the E9 v1
# contract are run individually so the bundle records each one explicitly.
run_invariants() {
  # NO IFC/containment-check elision exists in v1: no discovery family can
  # propose it, and the activation gate refuses it by construction.
  rch_lib_test e9_shadow_candidate_discovery::tests::no_family_ever_proposes_ifc_check_elision
  rch_lib_test e9_first_activation::tests::ifc_check_elision_is_forbidden_by_construction
  # Safe mode disables ALL specializations, even fully verified ones.
  rch_lib_test deterministic_replay::tests::safe_mode_disables_all_specializations_even_fully_verified
  rch_lib_test e9_first_activation::tests::kill_switch_refuses_activation
  # Strict replay never silently swaps lanes.
  rch_lib_test deterministic_replay::tests::strict_lane_rule_never_silently_swaps_lanes
  # Quarantined candidates are never activation-eligible.
  rch_lib_test e9_equivalence_receipts::tests::inconclusive_quarantine_can_be_disabled_but_never_activates
  rch_lib_test e9_first_activation::tests::quarantined_candidate_refuses
  dw_log_event "invariants" "pass" \
    '{"no_ifc_elision":"pinned by two named tests","safe_mode":"disables all specializations","strict_replay":"never silently a different path","quarantine":"never activated"}'
}

case "$mode" in
  check)
    dw_run_step "$(dw_cargo_label cargo check -p frankenengine-engine --test e9_shadow_candidate_discovery_integration --test e9_equivalence_receipts_integration --test e9_replay_identity_integration --test e9_first_activation_integration)" \
      dw_cargo \
        cargo check -p frankenengine-engine --test e9_shadow_candidate_discovery_integration --test e9_equivalence_receipts_integration --test e9_replay_identity_integration --test e9_first_activation_integration
    ;;
  test|ci)
    run_tests
    run_invariants
    ;;
  invariants)
    run_invariants
    ;;
  *) echo "usage: $0 [check|test|ci|invariants]" >&2; exit 2 ;;
esac

dw_finish
