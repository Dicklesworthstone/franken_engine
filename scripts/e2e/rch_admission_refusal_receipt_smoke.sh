#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/rch_admission_refusal_receipt.sh"
cases_path="${root_dir}/scripts/testdata/rch_admission_refusal_receipt/cases.json"
mode="${1:-check}"
output_root="${2:-${RCH_ADMISSION_REFUSAL_RECEIPT_SMOKE_DIR:-${TMPDIR:-/tmp}/rch-admission-refusal-receipt-smoke-$$}}"
failures=0

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_admission_refusal_receipt_smoke.sh [check|selftest] [output_root]

Runs shell/JQ-only checks for rch_admission_refusal_receipt.sh.
This smoke harness does not run cargo or live rch commands.
EOF
}

record_pass() {
  printf 'PASS rch-admission-refusal-receipt %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-admission-refusal-receipt %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_tools() {
  if ! command -v jq >/dev/null 2>&1; then
    printf 'jq is required for rch admission refusal receipt smoke\n' >&2
    exit 2
  fi
}

static_check() {
  require_tools
  jq empty "$cases_path" >/dev/null
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  jq -e '
    .schema_version == "franken-engine.rch-admission-refusal-receipt-fixtures.v1"
    and (.cases | length) >= 1
    and any(.cases[]; .case_id == "mixed_no_admissible_workers_live_shape")
  ' "$cases_path" >/dev/null
}

run_case_once() {
  local case_json="$1"
  local run_dir="$2"
  local diagnose_path="${run_dir}/diagnose.json"
  local out_dir="${run_dir}/out"
  local stdout_path="${run_dir}/stdout.txt"
  local stderr_path="${run_dir}/stderr.txt"
  local actual_exit expected_exit

  mkdir -p "$run_dir"
  jq '.diagnose' <<<"$case_json" >"$diagnose_path"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"

  set +e
  bash "$script_path" \
    --diagnose-json "$diagnose_path" \
    --output-dir "$out_dir" \
    --case-id "$(jq -r '.case_id' <<<"$case_json")" \
    --bead-id "$(jq -r '.bead_id' <<<"$case_json")" \
    --parent-bead-id "$(jq -r '.parent_bead_id' <<<"$case_json")" \
    --thread-id "$(jq -r '.thread_id' <<<"$case_json")" \
    --generated-at "2026-06-18T09:45:00Z" \
    >"$stdout_path" 2>"$stderr_path"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    printf 'case %s expected exit %s got %s\n' "$(jq -r '.case_id' <<<"$case_json")" "$expected_exit" "$actual_exit" >&2
    cat "$stderr_path" >&2
    return 1
  fi

  if ! jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
    .schema_version == "franken-engine.rch-admission-refusal-receipt.v1"
    and .final_verdict == $expected.final_verdict
    and .reason_code == $expected.reason_code
    and .operator_category == $expected.operator_category
    and .source_evidence == false
    and .cargo_executed == false
    and .decisions.would_intercept == true
    and .decisions.would_offload == false
    and (.commands.safe_validation_command | startswith("rch exec -- "))
    and (.commands.diagnose_command | startswith("rch diagnose --dry-run --json -- "))
    and .refusal.reason_counts.active_project_exclusion == $expected.reason_counts.active_project_exclusion
    and .refusal.reason_counts.critical_pressure == $expected.reason_counts.critical_pressure
    and .refusal.reason_counts.health_below_fallback == $expected.reason_counts.health_below_fallback
    and .refusal.reason_counts.hard_preflight == $expected.reason_counts.hard_preflight
    and (if (($expected.active_project_worker // "") == "") then true else ((.refusal.active_project_exclusion.workers | index($expected.active_project_worker)) != null) end)
    and (if (($expected.denied_reason_code // "") == "") then true else (.refusal.denied_reason_counts[$expected.denied_reason_code] == $expected.denied_reason_count) end)
    and (if (($expected.final_reason_contains // "") == "") then true else any(.refusal.worker_denials[]?; ((.final_reason // "") | contains($expected.final_reason_contains))) end)
  ' "${out_dir}/rch_admission_refusal_receipt.json" >/dev/null; then
    printf 'case %s receipt mismatch\n' "$(jq -r '.case_id' <<<"$case_json")" >&2
    jq '.' "${out_dir}/rch_admission_refusal_receipt.json" >&2
    return 1
  fi

  test -s "${out_dir}/events.jsonl"
  test -s "${out_dir}/commands.txt"
  test -s "${out_dir}/report.md"
}

run_case() {
  local case_json="$1"
  local case_id tmp_a tmp_b receipt_a receipt_b

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  tmp_a="${output_root}/${case_id}.a"
  tmp_b="${output_root}/${case_id}.b"
  run_case_once "$case_json" "$tmp_a" || {
    record_failure "${case_id} first run"
    return
  }
  run_case_once "$case_json" "$tmp_b" || {
    record_failure "${case_id} second run"
    return
  }

  receipt_a="$(jq -cS . "${tmp_a}/out/rch_admission_refusal_receipt.json")"
  receipt_b="$(jq -cS . "${tmp_b}/out/rch_admission_refusal_receipt.json")"
  if [[ "$receipt_a" != "$receipt_b" ]]; then
    record_failure "${case_id} receipt is not deterministic"
    return
  fi
  record_pass "$case_id"
}

run_check() {
  static_check || record_failure "static check"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi
  while IFS= read -r case_json; do
    run_case "$case_json"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
