#!/usr/bin/env bash
# run_rgc_incident_narration.sh - Track X.3 incident-narration gate
# (bd-cixqu.24.3): byte-identical narration replay check.
#
# The load-bearing contract: replaying a decision regenerates the narration
# receipt (franken-engine.narration-receipt.v1, bd-cixqu.24.2) with
# byte-identical narrative_text_canonical. Any divergence between original
# and replayed narration fails the gate with a diff (first divergence byte +
# both narration hashes). The canonicalizer is shared with the receipt
# schema (generate_constrained_narrative) so "identical" is defined once.
#
# Standard 5-mode gate: check | test | clippy | replay | ci. Fail-closed
# throughout: a missing verdict marker, a non-identical replay, or an
# undetected perturbation all fail the run, and the dw harness emits a
# content-addressed bundle (run_manifest.json, events.jsonl, commands.txt,
# steps/) whose summary verdict lands in incident_narration_report.json.
#
# Heavy Cargo work routes through rch by default. Set DW_RUN_LOCAL=1 to run
# cargo locally (optionally DW_CARGO_TARGET_DIR to isolate the target dir);
# the gate emits the same bundle either way.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

# shellcheck source=scripts/dw/lib/dw_e2e_lib.sh
source "$script_dir/dw/lib/dw_e2e_lib.sh"

mode="${1:-ci}"
dw_begin "rgc_incident_narration" "$mode"

dw_rustflags="$(dw_compose_linker_policy_rustflags "${RUSTFLAGS:--C linker=cc -Clinker-features=-lld}")"
printf -v dw_rustflags_shell '%q' "$dw_rustflags"

# Local mode preserves caller flags while composing the linker policy. It
# still leaves CARGO_INCREMENTAL untouched to keep warm target dirs stable.
dw_cargo() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    env -u CARGO_ENCODED_RUSTFLAGS RCH_CARGO_WRAPPER_BYPASS=1 \
      ${DW_CARGO_TARGET_DIR:+CARGO_TARGET_DIR="$DW_CARGO_TARGET_DIR"} \
      RUSTFLAGS="$dw_rustflags" \
      "$@"
  else
    env -u CARGO_ENCODED_RUSTFLAGS \
      rch exec -- env -u CARGO_ENCODED_RUSTFLAGS \
      CARGO_INCREMENTAL=0 RUSTFLAGS="$dw_rustflags" "$@"
  fi
}

dw_cargo_label() {
  if [[ "${DW_RUN_LOCAL:-0}" == "1" ]]; then
    printf 'DW_RUN_LOCAL env -u CARGO_ENCODED_RUSTFLAGS RCH_CARGO_WRAPPER_BYPASS=1 RUSTFLAGS=%s %s' "$dw_rustflags_shell" "$*"
  else
    printf 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL=0 RUSTFLAGS=%s %s' "$dw_rustflags_shell" "$*"
  fi
}

run_check() {
  dw_run_step "$(dw_cargo_label cargo check -p frankenengine-engine --test rgc_incident_narration)" \
    dw_cargo \
      cargo check -p frankenengine-engine --test rgc_incident_narration
}

run_clippy() {
  dw_run_step "$(dw_cargo_label cargo clippy -p frankenengine-engine --test rgc_incident_narration -- -D warnings)" \
    dw_cargo \
      cargo clippy -p frankenengine-engine --test rgc_incident_narration -- -D warnings
}

# Extract the single-line JSON verdict marker printed by the gate lane into
# incident_narration_report.json, and refuse the run if it is missing or if
# either replay pin failed. This is the bd-cixqu.45 summary-verdict surface:
# original vs replayed narration hashes + the gate verdict.
extract_verdict_report() {
  local report="$DW_RUN_DIR/incident_narration_report.json"
  local marker_line
  marker_line=$(grep -h 'RGC_INCIDENT_NARRATION_VERDICT: ' "$DW_STEPS_DIR"/*.log 2>/dev/null | tail -n1 || true)
  if [[ -z "$marker_line" ]]; then
    dw_log_event "verdict" "fail" '{"error":"missing RGC_INCIDENT_NARRATION_VERDICT marker - gate lane did not run"}'
    DW_FAILED_STEP="extract_verdict_report"
    return 1
  fi
  printf '%s\n' "${marker_line#*RGC_INCIDENT_NARRATION_VERDICT: }" > "$report"
  if ! jq -e '.identical_replay == true and .perturbation_detected == true and .gate_verdict == "pass"' \
    "$report" >/dev/null 2>&1; then
    dw_log_event "verdict" "fail" \
      "$(printf '{"error":"narration replay verdict is not certifying","report":%s}' "$(cat "$report")")"
    DW_FAILED_STEP="extract_verdict_report"
    return 1
  fi
  dw_log_event "verdict" "pass" "$(cat "$report")"
}

run_tests() {
  # Receipt schema + replay-check unit lanes (bd-cixqu.24.2 + this bead).
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --lib galaxy_brain_explainability::tests::narration_)" \
    dw_cargo_results dw_cargo \
      cargo test -p frankenengine-engine --lib galaxy_brain_explainability::tests::narration_
  # Integration lanes: byte-identical replay, perturbation divergence with a
  # diff, and the verdict-marker emission the report is built from.
  dw_run_step "$(dw_cargo_label cargo test -p frankenengine-engine --test rgc_incident_narration -- --nocapture)" \
    dw_cargo_results dw_cargo \
      cargo test -p frankenengine-engine --test rgc_incident_narration -- --nocapture
  extract_verdict_report
}

case "$mode" in
  check)
    run_check
    ;;
  test|replay)
    run_tests
    ;;
  clippy)
    run_clippy
    ;;
  ci)
    run_check
    run_tests
    run_clippy
    ;;
  *) echo "usage: $0 [check|test|clippy|replay|ci]" >&2; exit 2 ;;
esac

dw_finish
