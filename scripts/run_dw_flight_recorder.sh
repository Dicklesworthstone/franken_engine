#!/usr/bin/env bash
# run_dw_flight_recorder.sh - E3.TEST Flight Recorder + time-travel debugger
# test+verify capstone gate (bd-fqlfw.3.6).
#
# Drives the E3 stack through the DW.STD (bd-fqlfw.11) e2e bundle harness:
#   - the flight-recorder index contract (links resolve, missing/stale flagged
#     not invented, no payload duplication against existing bundlers),
#   - the operator explain views,
#   - the reverse-via-re-run navigation cursor + sparse checkpointing,
#   - the debugger protocol (event breakpoints, why<tick>, --robot round-trip),
#   - the capstone cross-layer assertions (reconstructed == originally-observed
#     interpreter state at sampled ticks; live-reconstruction robot determinism).
#
# In ci/test mode it ALSO drives the real `frankenctl` binary on a frozen input:
# `frankenctl run --explain` twice with fixed inputs, asserting the run report
# and the linked explain bundle are byte-identical across runs, then re-verifies
# the bundle's link graph with `frankenctl explain`. The live leg is best-effort:
# when no frankenctl binary is available it is recorded as skipped (the test
# steps already prove the library path), never silently passed.
#
# Heavy Cargo work routes through rch by default (the franken_engine session
# policy for shared Rust builds). Set DW_RUN_LOCAL=1 to fall back to a local
# cargo build; the gate still emits the same content-addressed bundle.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "dw_flight_recorder" "$mode"

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

run_tests() {
  rch_test runtime_explain_bundle_integration
  rch_test runtime_explain_views_integration
  rch_test replay_time_travel_integration
  rch_test time_travel_debugger_integration
  rch_test flight_recorder_capstone
}

# Locate a frankenctl binary for the live E2E leg. Preference order:
#   $DW_FRANKENCTL_BIN -> target/release/frankenctl -> target/debug/frankenctl.
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

# Frozen-input `frankenctl run --explain` byte-identity + link re-verification.
run_live_e2e() {
  local bin
  if ! bin="$(dw_locate_frankenctl)"; then
    dw_log_event "live_e2e" "skip" \
      '{"reason":"no frankenctl binary found (build with cargo build --release -p frankenengine-engine --bin frankenctl, or set DW_FRANKENCTL_BIN); test steps already prove the library path"}'
    return 0
  fi
  dw_log_event "live_e2e" "info" "$(printf '{"frankenctl":"%s"}' "$(dw__json_escape "$bin")")"

  local e2e_root="$DW_RUN_DIR/flight_recorder_e2e"
  mkdir -p "$e2e_root"
  local frozen="$e2e_root/frozen_input.js"
  printf 'const point = { x: 1, y: 2 };\nconst wrap = { inner: point, tag: 3 };\nconst sum = point.x + point.y + wrap.tag;\n' > "$frozen"

  # Both passes write the SAME output paths (the run report embeds its own
  # --out/--explain-out paths, so distinct filenames would trivially differ);
  # pass A is snapshotted before pass B overwrites.
  local pass
  for pass in a b; do
    dw_run_step "frankenctl run --explain (frozen input, pass ${pass})" \
      "$bin" run \
        --input "$frozen" \
        --extension-id dw-flight-recorder \
        --out "$e2e_root/run.json" \
        --explain \
        --explain-out "$e2e_root/explain.json"
    if [[ "$pass" == "a" ]]; then
      cp "$e2e_root/run.json" "$e2e_root/run_pass_a.json"
      cp "$e2e_root/explain.json" "$e2e_root/explain_pass_a.json"
    fi
  done

  dw_run_step "run report byte-identity across passes (fixed input)" \
    diff "$e2e_root/run_pass_a.json" "$e2e_root/run.json"
  dw_run_step "explain bundle byte-identity across passes (fixed input)" \
    diff "$e2e_root/explain_pass_a.json" "$e2e_root/explain.json"

  dw_run_step "frankenctl explain re-verifies the bundle's link graph" \
    "$bin" explain --input "$e2e_root/explain.json" --format json \
      --out "$e2e_root/explain_report.json"
  dw_run_step "assert explain artifacts present" \
    bash -c 'for f in run.json explain.json explain_report.json; do [ -s "$1/$f" ] || { echo "missing or empty $f in $1" >&2; exit 1; }; done' _ "$e2e_root"

  # bd-9mr8o: the end-to-end CLI inspection loop. `run --emit-trace` captures
  # the run's recorded nondeterminism trace; the debugger re-executes the same
  # source against it and serves reconstructed interpreter state. The trace
  # itself must also be byte-identical across fixed-input runs.
  dw_run_step "frankenctl run --emit-trace (frozen input, pass a)" \
    "$bin" run --input "$frozen" --extension-id dw-flight-recorder \
      --emit-trace "$e2e_root/trace.json"
  cp "$e2e_root/trace.json" "$e2e_root/trace_pass_a.json"
  dw_run_step "frankenctl run --emit-trace (frozen input, pass b)" \
    "$bin" run --input "$frozen" --extension-id dw-flight-recorder \
      --emit-trace "$e2e_root/trace.json"
  dw_run_step "emitted trace byte-identity across passes (fixed input)" \
    diff "$e2e_root/trace_pass_a.json" "$e2e_root/trace.json"
  printf '%s\n' '{"cmd":"inspect","tick":0}' > "$e2e_root/inspect.jsonl"
  dw_run_step "replay debug --input live inspection round-trip (registers/heap/IFC labels)" \
    bash -c '"$1" replay debug --trace "$2/trace.json" --input "$3" --script "$2/inspect.jsonl" --out "$2/inspect_transcript.jsonl" && grep -q "\"kind\":\"inspection\"" "$2/inspect_transcript.jsonl"' \
      _ "$bin" "$e2e_root" "$frozen"

  dw_log_event "live_e2e" "pass" '{"bundle_root":"flight_recorder_e2e/"}'
}

case "$mode" in
  check)
    dw_run_step "$(dw_cargo_label cargo check -p frankenengine-engine --bin frankenctl --test flight_recorder_capstone --test time_travel_debugger_integration)" \
      dw_cargo \
        cargo check -p frankenengine-engine --bin frankenctl --test flight_recorder_capstone --test time_travel_debugger_integration
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
