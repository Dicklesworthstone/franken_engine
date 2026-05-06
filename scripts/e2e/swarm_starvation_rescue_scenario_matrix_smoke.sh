#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix_script="${root_dir}/scripts/swarm_starvation_rescue_scenario_matrix.sh"
matrix_fixture="${root_dir}/scripts/testdata/swarm_starvation_rescue/scenario_matrix.json"
golden_path="${root_dir}/scripts/testdata/goldens/swarm_starvation_rescue_scenario_matrix.golden"
contract_path="${root_dir}/docs/swarm_starvation_rescue_scenario_matrix_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_STARVATION_RESCUE_SCENARIO_MATRIX.md"

record_pass() {
  printf 'PASS swarm-starvation-rescue-scenario-matrix %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-starvation-rescue-scenario-matrix %s\n' "$1" >&2
}

compare_golden() {
  local actual_path="$1"
  local checked_in_golden="$2"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$checked_in_golden"
    record_pass "updated golden"
    return 0
  fi

  if [[ ! -f "$checked_in_golden" ]]; then
    record_failure "missing golden ${checked_in_golden}"
    return 1
  fi

  if ! diff -u "$checked_in_golden" "$actual_path"; then
    record_failure "golden drift; use UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches"
}

run_check() {
  bash -n "$matrix_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$matrix_fixture"
  jq empty "$contract_path"
  jq -e '
    .report_schema_version == "franken-engine.swarm-starvation-rescue-scenario-matrix-report.v1"
    and .matrix_schema_version == "franken-engine.swarm-starvation-rescue-scenario-matrix.v1"
    and (.required_scenario_classes | length) == 6
  ' "$contract_path" >/dev/null
  grep -q 'UPDATE_GOLDENS=1 bash scripts/e2e/swarm_starvation_rescue_scenario_matrix_smoke.sh selftest' "$docs_path"
  record_pass "syntax docs and contract inventory"
}

run_selftest() {
  local tmp_parent tmp_root output_dir actual_path

  run_check
  tmp_parent="${SWARM_STARVATION_RESCUE_SCENARIO_MATRIX_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-starvation-rescue-scenario-matrix.XXXXXX")"
  output_dir="${tmp_root}/output"
  actual_path="${tmp_root}/swarm_starvation_rescue_scenario_matrix.actual.golden"

  "$matrix_script" --matrix-json "$matrix_fixture" --output-dir "$output_dir" >/dev/null
  jq -e '
    .schema_version == "franken-engine.swarm-starvation-rescue-scenario-matrix-report.v1"
    and .matrix_schema_version == "franken-engine.swarm-starvation-rescue-scenario-matrix.v1"
    and .scenario_count == 6
    and .failure_count == 0
    and .summary.fail_closed_case_count == 3
    and (.summary.mismatch_case_ids | length) == 0
    and ([.cases[].case_id] | index("healthy_advisory_ready") != null)
    and ([.cases[].case_id] | index("brownout_low_priority_starvation") != null)
    and ([.cases[].case_id] | index("contradictory_ownership_fail_closed") != null)
    and any(.cases[]; .case_id == "stale_telemetry_fail_closed" and .actual.decision == "fail_closed")
    and any(.cases[]; .case_id == "local_fallback_rejected" and .actual.local_rch_fallback_detected == "true")
    and any(.cases[]; .case_id == "salvage_pinned_manual_review" and .actual.readiness == "degraded")
  ' "${output_dir}/swarm_starvation_rescue_scenario_matrix_report.json" >/dev/null
  record_pass "scenario matrix report validates"

  cp "${output_dir}/swarm_starvation_rescue_scenario_matrix_report.json" "$actual_path"
  compare_golden "$actual_path" "$golden_path"
  printf 'swarm_starvation_rescue_scenario_matrix_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
