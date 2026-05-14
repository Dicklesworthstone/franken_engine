#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill="${root_dir}/scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.sh"
golden_path="${root_dir}/scripts/testdata/goldens/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.golden"
mode="${1:-check}"

record_pass() {
  printf 'PASS zero-ready-validation-truth-no-mock-drill-smoke %s\n' "$1"
}

record_failure() {
  printf 'FAIL zero-ready-validation-truth-no-mock-drill-smoke %s\n' "$1" >&2
  exit 1
}

canonicalize_report() {
  local report_path="$1"
  jq 'del(.artifact_paths)' "$report_path"
}

compare_golden() {
  local actual_path="$1"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden"
    return
  fi

  [[ -f "$golden_path" ]] || record_failure "missing golden ${golden_path}"
  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift; set UPDATE_GOLDENS=1 only after reviewing the diff"
  fi
  record_pass "golden matches"
}

run_check() {
  local tmp_parent tmp_root output_dir actual_path
  tmp_parent="${ZERO_READY_VALIDATION_TRUTH_DRILL_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/zero-ready-validation-truth.XXXXXX")"
  output_dir="${tmp_root}/bundle"
  actual_path="${tmp_root}/actual.golden"

  bash -n "$drill" "${BASH_SOURCE[0]}"

  ZERO_READY_VALIDATION_TRUTH_DRILL_RUN_ID="20260514T000000Z" \
  ZERO_READY_VALIDATION_TRUTH_DRILL_SOURCE_REVISION="smoke-zero-ready-validation-truth" \
  ZERO_READY_VALIDATION_TRUTH_DRILL_GENERATED_AT_UTC="2026-05-14T00:00:00Z" \
    "$drill" fixture --output-dir "$output_dir" >"${tmp_root}/stdout.log" 2>"${tmp_root}/stderr.log" \
    || {
      cat "${tmp_root}/stderr.log" >&2
      record_failure "fixture run failed"
    }

  "$drill" replay --replay-run-dir "$output_dir" >"${tmp_root}/replay.stdout.log" 2>"${tmp_root}/replay.stderr.log" \
    || {
      cat "${tmp_root}/replay.stderr.log" >&2
      record_failure "replay failed"
    }

  canonicalize_report "${output_dir}/zero_ready_validation_truth_no_mock_drill_report.json" >"$actual_path"
  compare_golden "$actual_path"
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    record_pass "selftest"
    ;;
  -h|--help|help)
    printf 'Usage: %s [check|selftest]\n' "${BASH_SOURCE[0]}"
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
