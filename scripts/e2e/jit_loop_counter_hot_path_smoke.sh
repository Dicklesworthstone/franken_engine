#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${JIT_LOOP_COUNTER_HOT_PATH_ARTIFACT_ROOT:-${root_dir}/artifacts/jit_loop_counter_hot_path_smoke}"
run_id="$(date -u +"%Y%m%dT%H%M%SZ")"
out_dir="${artifact_root}/${run_id}"
mkdir -p "$out_dir"

events_log="${out_dir}/events.tsv"
commands_log="${out_dir}/commands.txt"
stdout_log="${out_dir}/stdout.log"
stderr_log="${out_dir}/stderr.log"
report_md="${out_dir}/report.md"

exec > >(tee "$stdout_log") 2> >(tee "$stderr_log" >&2)

log_event() {
  local event="$1"
  local detail="${2:-}"
  printf '%s\t%s\t%s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$event" "$detail" >> "$events_log"
}

run_step() {
  local name="$1"
  shift
  log_event "start" "$name"
  printf '%s\n' "$*" >> "$commands_log"
  "$@"
  log_event "pass" "$name"
}

export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${root_dir}/target_cod_bd_3vwbg}"
export RUSTFLAGS="${RUSTFLAGS:--C linker=cc}"

run_cargo_step() {
  local name="$1"
  shift
  run_step "$name" rch exec -- env \
    RUSTC_WRAPPER="$RUSTC_WRAPPER" \
    CARGO_INCREMENTAL="$CARGO_INCREMENTAL" \
    CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS" \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    RUSTFLAGS="$RUSTFLAGS" \
    cargo "$@"
}

log_event "artifact_dir" "$out_dir"
log_event "cargo_target_dir" "$CARGO_TARGET_DIR"

run_cargo_step "unit-loop-counter-storage" \
  test -p frankenengine-engine --lib loop_iteration_counter_tests -- --nocapture

run_cargo_step "integration-many-distinct-loop-backedges" \
  test -p frankenengine-engine --test jit_hot_path_detection \
    jit_loop_iteration_counters_track_many_distinct_backedges -- --nocapture

run_cargo_step "integration-loop-counter-eviction" \
  test -p frankenengine-engine --test jit_hot_path_detection \
    jit_eviction_removes_cold_loop_counts_after_many_loop_sites -- --nocapture

{
  printf '# JIT Loop Counter Hot Path Smoke\n\n'
  printf '%s\n' "- bead: bd-3vwbg"
  printf "%s \`%s\`\n" "- artifact_dir:" "$out_dir"
  printf "%s \`%s\`\n" "- cargo_target_dir:" "$CARGO_TARGET_DIR"
  printf '%s\n' "- result: pass"
  printf '%s\n' "- logs: \`events.tsv\`, \`commands.txt\`, \`stdout.log\`, \`stderr.log\`"
} > "$report_md"

log_event "report" "$report_md"
