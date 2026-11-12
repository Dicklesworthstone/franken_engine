#!/usr/bin/env bash
# run_dw_non_use_certificate.sh - E8.TEST Non-Use Certificate test+verify
# soundness-critical capstone gate (bd-fqlfw.8.7).
#
# Drives the E8 Non-Use / Non-Exfiltration Certificate stack through the
# DW.STD (bd-fqlfw.11) content-addressed bundle harness:
#   - non_use_certificate.rs unit invariants (v2 envelope, external trust-root
#     verification, explicit certifier authority, scope + refusal derivation),
#   - third_party_verifier.rs non-use claim verification (external trust anchor,
#     repro.lock SHA-256 + byte-length completeness, recorded-trace digest parity,
#     declassification receipt verification, capability_trace consistency,
#     explicit_flow_ifc_v1 boundary check),
#   - e8_analyzed_subset.rs + data_contract.rs unit invariants,
#   - non_use_certificate_integration (positive labeled run with verified
#     DeclassificationReceipt + capability_trace, unanalyzed-construct soundness
#     matrix with span provenance, byte-identical two-pass CLI replay under
#     explicit RuntimeEvidenceAuthority, non-self-fed frankenctl replay run,
#     and negative tests for claimant-key substitution, trace tampering, and
#     wrong trust anchor),
#   - e8_trusted_surface_red_team (certifier/contract-parser/MCP-shim red-team),
#   - agent_sandbox_integration (agent-sandbox + MCP tool-runner shim +
#     guardplane containment),
#   - data_contract_integration (preflight refusal ledger + input hash binding).
#
# Heavy Cargo work routes through rch by default. Set DW_RUN_LOCAL=1 to fall
# back to a local cargo build when rch workers are unavailable.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_non_use_certificate" "$mode"

dw_jobs="${DW_CARGO_JOBS:-2}"
dw_rustflags="$(dw_compose_linker_policy_rustflags "${RUSTFLAGS:--C linker=cc}")"
printf -v dw_rustflags_shell '%q' "$dw_rustflags"

dw_cargo() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    env -u CARGO_ENCODED_RUSTFLAGS \
      RCH_CARGO_WRAPPER_BYPASS=1 \
      CARGO_BUILD_JOBS="$dw_jobs" \
      CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_TEST_INCREMENTAL=false \
      CARGO_PROFILE_DEV_DEBUG=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      ${DW_CARGO_TARGET_DIR:+CARGO_TARGET_DIR="$DW_CARGO_TARGET_DIR"} \
      RUSTFLAGS="$dw_rustflags" "$@"
  else
    local -a worker_args=()
    if [[ -n "${RCH_WORKER:-}" ]]; then
      rch workers probe "$RCH_WORKER" >/dev/null 2>&1 || true
      worker_args=(--worker "$RCH_WORKER")
    fi
    env -u CARGO_ENCODED_RUSTFLAGS \
      rch exec "${worker_args[@]}" -- env -u CARGO_ENCODED_RUSTFLAGS \
      CARGO_BUILD_JOBS="$dw_jobs" \
      CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_TEST_INCREMENTAL=false \
      CARGO_PROFILE_DEV_DEBUG=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS="$dw_rustflags" "$@"
  fi
}

dw_cargo_label() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    printf 'DW_RUN_LOCAL=1 env -u CARGO_ENCODED_RUSTFLAGS RCH_CARGO_WRAPPER_BYPASS=1 CARGO_BUILD_JOBS=%s CARGO_INCREMENTAL=0 RUSTFLAGS=%s %s' \
      "$dw_jobs" "$dw_rustflags_shell" "$*"
  else
    printf 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_JOBS=%s CARGO_INCREMENTAL=0 RUSTFLAGS=%s %s' \
      "$dw_jobs" "$dw_rustflags_shell" "$*"
  fi
}

rch_lib_test() {
  local filter="$1"
  dw_run_step "$(dw_cargo_label cargo test -j "$dw_jobs" -p frankenengine-engine --lib "$filter" -- --test-threads=2)" \
    dw_cargo_results dw_cargo \
      cargo test -j "$dw_jobs" -p frankenengine-engine --lib "$filter" -- --test-threads=2
}

rch_test() {
  local test_name="$1"
  dw_run_step "$(dw_cargo_label cargo test -j "$dw_jobs" -p frankenengine-engine --test "$test_name" -- --test-threads=2 --nocapture)" \
    dw_cargo_results dw_cargo \
      cargo test -j "$dw_jobs" -p frankenengine-engine --test "$test_name" -- --test-threads=2 --nocapture
}

dw_locate_frankenctl() {
  local candidate target_root="${DW_CARGO_TARGET_DIR:-target}"
  if [[ -n "${DW_FRANKENCTL_BIN:-}" && -x "${DW_FRANKENCTL_BIN}" ]]; then
    printf '%s' "${DW_FRANKENCTL_BIN}"; return 0
  fi
  if [[ -n "${FRANKENCTL_BIN:-}" && -x "${FRANKENCTL_BIN}" ]]; then
    printf '%s' "${FRANKENCTL_BIN}"; return 0
  fi
  for candidate in "$target_root/release/frankenctl" "$target_root/debug/frankenctl"; do
    if [[ -x "$candidate" ]]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}

run_tests() {
  rch_lib_test non_use_certificate
  rch_lib_test third_party_verifier::tests::non_use_certificate
  rch_lib_test e8_analyzed_subset
  rch_lib_test data_contract

  rch_test non_use_certificate_integration
  rch_test e8_trusted_surface_red_team
  rch_test agent_sandbox_integration
  rch_test data_contract_integration
}

run_live_e2e() {
  local bin=""
  if ! bin="$(dw_locate_frankenctl)"; then
    if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
      dw_run_step "$(dw_cargo_label cargo build -j "$dw_jobs" -p frankenengine-engine --bin frankenctl)" \
        dw_cargo cargo build -j "$dw_jobs" -p frankenengine-engine --bin frankenctl
      bin="$(dw_locate_frankenctl || true)"
    fi
  fi

  if [[ -z "$bin" ]]; then
    dw_log_event "live_demo" "skip" \
      '{"reason":"host-local frankenctl binary not present under target/ (rch builds execute CARGO_BIN_EXE_frankenctl remotely inside non_use_certificate_integration and agent_sandbox_integration); set DW_FRANKENCTL_BIN or DW_RUN_LOCAL=1 to also run examples/26_non_exfiltration_certificate/demo.sh locally"}'
    return 0
  fi

  dw_run_step "examples/26_non_exfiltration_certificate/demo.sh (live four-act demo)" \
    env FRANKENCTL_BIN="$bin" ./examples/26_non_exfiltration_certificate/demo.sh
  if [[ -d examples/26_non_exfiltration_certificate/out/certified_bundle ]]; then
    mkdir -p "$DW_RUN_DIR/non_use_certificate_e2e"
    cp -R examples/26_non_exfiltration_certificate/out/certified_bundle \
      "$DW_RUN_DIR/non_use_certificate_e2e/certified_bundle"
    dw_log_event "live_demo" "pass" '{"bundle_root":"non_use_certificate_e2e/certified_bundle"}'
  fi
}

run_doc_drift() {
  if [[ -x scripts/check_dw_non_use_certificate_doc_drift.sh ]]; then
    dw_run_step "scripts/check_dw_non_use_certificate_doc_drift.sh" \
      ./scripts/check_dw_non_use_certificate_doc_drift.sh
  fi
}

case "$mode" in
  check)
    dw_run_step "$(dw_cargo_label cargo check -j "$dw_jobs" -p frankenengine-engine --bin frankenctl --test non_use_certificate_integration --test e8_trusted_surface_red_team --test agent_sandbox_integration)" \
      dw_cargo \
        cargo check -j "$dw_jobs" -p frankenengine-engine --bin frankenctl --test non_use_certificate_integration --test e8_trusted_surface_red_team --test agent_sandbox_integration
    run_doc_drift
    ;;
  test|ci)
    run_tests
    run_live_e2e
    run_doc_drift
    ;;
  e2e)
    run_live_e2e
    ;;
  *) echo "usage: $0 [check|test|ci|e2e]" >&2; exit 2 ;;
esac

dw_finish
