#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
truth_gate="${root_dir}/scripts/e2e/rch_remote_compile_stall_truth_gate.sh"
suite_json="${root_dir}/scripts/testdata/rch_remote_compile_stall_truth_gate/cases.json"
fixture_root="${root_dir}/scripts/testdata/rch_remote_compile_stall_truth_gate"
contract_json="${root_dir}/docs/rch_remote_compile_stall_bundle_contract_v1.json"

record_pass() {
  printf 'PASS rch-remote-compile-stall-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-remote-compile-stall-truth-gate %s\n' "$1" >&2
}

run_check() {
  bash -n "$truth_gate" "${BASH_SOURCE[0]}"
  shellcheck -x "$truth_gate" "${BASH_SOURCE[0]}"
  jq empty "$contract_json" "$suite_json" >/dev/null

  find "$fixture_root" -type f -name '*.json' -print0 | xargs -0 -n1 jq empty >/dev/null
  jq -e '
    .schema_version == "franken-engine.rch-remote-compile-stall-truth-gate-suite.v1"
    and (.cases | length) == 4
    and any(.cases[]; .category == "healthy_remote_completion")
    and any(.cases[]; .category == "explicit_timeout")
    and any(.cases[]; .category == "fresh_heartbeat_frozen_progress_stall")
    and any(.cases[]; .category == "local_fallback_contamination")
  ' "$suite_json" >/dev/null

  record_pass "shell syntax, shellcheck, and fixture JSON"
}

assert_report() {
  local report_path="$1"

  jq -e '
    .schema_version == "franken-engine.rch-remote-compile-stall-truth-gate-report.v1"
    and .decision == "pass"
    and .case_count == 4
    and .passed_count == 4
    and .failed_count == 0
    and .required_coverage.healthy_remote_completion == true
    and .required_coverage.explicit_timeout == true
    and .required_coverage.fresh_heartbeat_frozen_progress_stall == true
    and .required_coverage.local_fallback_contamination == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and any(.cases[]; .case_id == "healthy_remote_completion" and .actual.final_verdict == "source_pass" and .actual.truth_state == "confirmed")
    and any(.cases[]; .case_id == "transport_timeout_check_lib" and .actual.final_verdict == "transport_timeout" and .actual.truth_state == "degraded")
    and any(.cases[]; .case_id == "fresh_heartbeat_frozen_progress_test" and .actual.final_verdict == "fresh_heartbeat_frozen_progress_stall" and .actual.truth_state == "degraded")
    and any(.cases[]; .case_id == "contaminated_local_fallback_check_lib" and .actual.final_verdict == "contaminated_local_fallback" and .actual.truth_state == "contaminated")
  ' "$report_path" >/dev/null
}

run_selftest() {
  local tmp_root report_path bad_suite bad_dir actual_exit

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/rch-remote-compile-stall-truth-gate.XXXXXX")"
  "$truth_gate" --output-dir "${tmp_root}/pass" --suite-json "$suite_json" >/dev/null
  report_path="${tmp_root}/pass/truth_gate_report.json"
  assert_report "$report_path"
  test -s "${tmp_root}/pass/events.jsonl"
  test -s "${tmp_root}/pass/commands.txt"
  test -s "${tmp_root}/pass/summary.md"
  record_pass "selftest pass suite"

  bad_suite="${tmp_root}/bad_cases.json"
  jq '(.cases[] | select(.case_id == "transport_timeout_check_lib") | .expected_final_verdict) = "source_pass"' "$suite_json" >"$bad_suite"
  bad_dir="${tmp_root}/bad"
  set +e
  "$truth_gate" --output-dir "$bad_dir" --suite-json "$bad_suite" >/dev/null 2>&1
  actual_exit=$?
  set -e
  if [[ "$actual_exit" -ne 42 ]]; then
    record_failure "mutated suite exit ${actual_exit}, expected 42"
    return 1
  fi
  jq -e '.decision == "fail_closed" and any(.cases[]; .case_id == "transport_timeout_check_lib" and (.failures | index("unexpected_final_verdict")))' "${bad_dir}/truth_gate_report.json" >/dev/null
  record_pass "selftest fails closed on contradictory expected verdict"

  printf 'rch_remote_compile_stall_truth_gate_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
