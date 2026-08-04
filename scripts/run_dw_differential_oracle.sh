#!/usr/bin/env bash
# run_dw_differential_oracle.sh - E2.TEST differential-oracle test+verify capstone
# gate (bd-fqlfw.2.8).
#
# Drives the E2 differential-oracle stack through the DW.STD (bd-fqlfw.11) e2e
# bundle harness:
#   - the capstone integration test (content-addressed bundle emit + byte-identical
#     re-verify, canonicalization, 7-class taxonomy, engine<->core free oracle with
#     minimized+preserved defects, degraded fail-closed receipt, FE-CLAIM-010 posture),
#   - the operator-facing `frankenctl oracle run|report` CLI integration,
#   - the differential-oracle integration + the E2.T5 divergence-preserving minimizer,
#   - the in-module unit tests (canonicalization, divergence taxonomy, minimizer,
#     engine<->core internal twin).
#
# In ci/test mode it ALSO runs a small fixed corpus through the actual `frankenctl
# oracle run` CLI across the two hermetic in-process lanes (franken-engine +
# franken-core), persisting a real content-addressed oracle bundle (manifest.json +
# report.json + repro.lock) into the run dir and re-verifying it byte-identically
# with `frankenctl oracle report`. The live corpus is best-effort: if no frankenctl
# binary is available it is recorded as skipped (the test steps already prove the
# CLI path), never silently passed.
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
dw_begin "dw_differential_oracle" "$mode"

dw_rustflags="$(dw_compose_linker_policy_rustflags "${RUSTFLAGS:--C linker=cc}")"
printf -v dw_rustflags_shell '%q' "$dw_rustflags"

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

# The in-module unit tests (canonicalization correctness, divergence-taxonomy
# classification, divergence-preserving minimizer, engine<->core internal twin).
rch_lib_test() {
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --lib differential_oracle::tests:: -- --nocapture)" \
    dw_cargo_results dw_cargo \
      cargo test -p frankenengine-engine --lib differential_oracle::tests:: -- --nocapture
}

run_tests() {
  rch_test dw_differential_oracle_capstone
  rch_test oracle_cli_integration
  rch_test differential_oracle_integration
  rch_test differential_oracle_minimization_bd_fqlfw_2_5
  rch_lib_test
}

# Locate a frankenctl binary for the live corpus step. Preference order:
#   $DW_FRANKENCTL_BIN -> target/release/frankenctl -> target/debug/frankenctl.
# Echoes the path on success; empty string (and rc=1) when none is available.
dw_locate_frankenctl() {
  local candidate
  if [[ -n "${DW_FRANKENCTL_BIN:-}" && -x "${DW_FRANKENCTL_BIN}" ]]; then
    printf '%s' "${DW_FRANKENCTL_BIN}"; return 0
  fi
  for candidate in target/release/frankenctl target/debug/frankenctl; do
    if [[ -x "$candidate" ]]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}

# Run a fixed, hermetic franken+core corpus through the real CLI, persisting a real
# content-addressed oracle bundle per case and re-verifying it byte-identically.
run_live_corpus() {
  local bin
  if ! bin="$(dw_locate_frankenctl)"; then
    dw_log_event "live_corpus" "skip" \
      '{"reason":"no frankenctl binary found (build with cargo build --release -p frankenengine-engine --bin frankenctl, or set DW_FRANKENCTL_BIN); test steps already prove the CLI path"}'
    return 0
  fi
  dw_log_event "live_corpus" "info" "$(printf '{"frankenctl":"%s"}' "$(dw__json_escape "$bin")")"

  local corpus_root="$DW_RUN_DIR/oracle_corpus"
  mkdir -p "$corpus_root/inputs"

  # The fixed corpus: bare value-producing expressions on which the two in-process
  # lanes agree. Bare expressions (not console.log) keep the comparison hermetic —
  # the core lane has no console builtin.
  local -a names=(arith_sum arith_parens string_concat ternary)
  local -a srcs=('40 + 2;' '(1 + 2) * 3;' '"a" + "b" + "c";' 'true ? 10 : 20;')
  local i case_id src input bundle
  for i in "${!names[@]}"; do
    case_id="${names[$i]}"; src="${srcs[$i]}"
    input="$corpus_root/inputs/${case_id}.js"
    bundle="$corpus_root/${case_id}"
    printf '%s\n' "$src" > "$input"
    dw_run_step "frankenctl oracle run ${case_id} --engines franken,core --bundle <run>/oracle_corpus/${case_id}" \
      "$bin" oracle run "$input" --engines franken,core --bundle "$bundle" --json
    dw_run_step "frankenctl oracle report <run>/oracle_corpus/${case_id} (byte-identical re-verify)" \
      "$bin" oracle report "$bundle" --json
    # Structural assertion: the canonical three-file content-addressed bundle exists.
    # Routed through dw_run_step so the harness owns the pass/fail bookkeeping.
    dw_run_step "assert content-addressed bundle files present: ${case_id}" \
      bash -c 'for f in manifest.json report.json repro.lock; do [ -f "$1/$f" ] || { echo "missing $f in $1" >&2; exit 1; }; done' _ "$bundle"
  done
  dw_log_event "live_corpus" "pass" \
    "$(printf '{"cases":%d,"bundle_root":"oracle_corpus/"}' "${#names[@]}")"
}

case "$mode" in
  check)
    dw_run_step "$(dw_cargo_label cargo check -p frankenengine-engine --bin frankenctl --test dw_differential_oracle_capstone --test oracle_cli_integration)" \
      dw_cargo \
        cargo check -p frankenengine-engine --bin frankenctl --test dw_differential_oracle_capstone --test oracle_cli_integration
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
