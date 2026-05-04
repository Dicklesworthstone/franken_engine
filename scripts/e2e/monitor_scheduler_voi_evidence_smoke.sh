#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${MONITOR_SCHEDULER_VOI_EVIDENCE_ARTIFACT_ROOT:-${root_dir}/artifacts/monitor_scheduler_voi_evidence_smoke}"
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

export RCH_CARGO_WRAPPER_BYPASS="${RCH_CARGO_WRAPPER_BYPASS:-1}"
export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target_cod_bd_bdrwq4}"
export RUSTFLAGS="${RUSTFLAGS:--C linker=cc}"

log_event "artifact_dir" "$out_dir"
log_event "cargo_target_dir" "$CARGO_TARGET_DIR"

run_step "unit-evidence-report-contract" \
  cargo test -p frankenengine-engine --lib monitor_schedule_evidence_report -- --nocapture

run_step "unit-history-evidence-contract" \
  cargo test -p frankenengine-engine --lib monitor_scheduler_history_evidence_reports -- --nocapture

run_step "integration-public-report-api" \
  cargo test -p frankenengine-engine --test monitor_scheduler_integration \
    schedule_evidence_report_public_api_contains_budget_fields -- --nocapture

{
  printf '# Monitor Scheduler VOI Evidence Smoke\n\n'
  printf '%s\n' '- bead: bd-bdrwq.4'
  printf '%s `%s`\n' '- artifact_dir:' "$out_dir"
  printf '%s `%s`\n' '- cargo_target_dir:' "$CARGO_TARGET_DIR"
  printf '%s\n' '- result: pass'
  printf '%s\n' '- logs: `events.tsv`, `commands.txt`, `stdout.log`, `stderr.log`'
} > "$report_md"

log_event "report" "$report_md"
