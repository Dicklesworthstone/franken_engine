#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_ops_admission_planner.sh"
fixtures_path="${SWARM_OPS_ADMISSION_FIXTURES:-${root_dir}/scripts/testdata/swarm_ops_admission_planner/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_OPS_ADMISSION_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-ops-admission-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ops-admission-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_ops_admission_planner_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-ops-admission-planner-fixtures.v1"
    and (.cases | length == 6)
    and (.cases | map(.case_id) | index("high_core_healthy") != null)
    and (.cases | map(.case_id) | index("low_memory") != null)
    and (.cases | map(.case_id) | index("disk_pressure") != null)
    and (.cases | map(.case_id) | index("rch_brownout") != null)
    and (.cases | map(.case_id) | index("stale_jsonl") != null)
    and (.cases | map(.case_id) | index("reservation_conflict") != null)
    and all(.cases[]; has("snapshot") and has("expected"))
  ' "$fixtures_path" >/dev/null
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir snapshot expected plan events

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  mkdir -p "$case_dir"
  snapshot="${case_dir}/state_snapshot.json"
  expected="${case_dir}/expected.json"
  jq '.snapshot' <<<"$case_json" >"$snapshot"
  jq '.expected' <<<"$case_json" >"$expected"

  "$planner" --state-snapshot-json "$snapshot" --source-revision fixture-revision --output-dir "${case_dir}/out" >/dev/null
  plan="${case_dir}/out/plan.json"
  events="${case_dir}/out/events.jsonl"

  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-ops-admission-plan.v1"
    and .decision == $expected[0].decision
    and .fail_closed_reasons == $expected[0].fail_closed_reasons
    and .blocked_reasons == $expected[0].blocked_reasons
    and .degraded_reasons == $expected[0].degraded_reasons
    and .summary.admitted_count == $expected[0].admitted_count
    and .summary.deferred_count == $expected[0].deferred_count
    and .summary.blocked_count == $expected[0].blocked_count
    and (.summary.admitted_heavy_count <= .capacity_envelope.max_parallel_heavy_lanes)
    and all(.operator_commands[]; startswith("# advisory-only "))
  ' "$plan" >/dev/null || {
    record_failure "${case_id} plan mismatch"
    return
  }

  jq -s '
    length >= 2
    and all(.[]; has("trace_id") and has("component") and has("event") and has("outcome") and has("error_code") and has("evidence_path"))
    and any(.[]; .component == "swarm_ops_admission_planner" and .event == "plan_emitted")
  ' "$events" >/dev/null || {
    record_failure "${case_id} events missing stable keys"
    return
  }

  jq empty "${case_dir}/out/trace_ids.json" >/dev/null
  test -s "${case_dir}/out/report.md"
  test -s "${case_dir}/out/commands.txt"
  record_pass "${case_id} plan"
}

run_check() {
  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" >/dev/null
  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  grep -Fq 'advisory-only' "$planner"
  if grep -En '(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)' "$planner" >/dev/null; then
    record_failure "planner contains a bare heavy Cargo command"
  fi
  if grep -En '(^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$)' "$planner" >/dev/null; then
    record_failure "planner executes RCH instead of emitting advisory text"
  fi
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
}

run_selftest() {
  local tmp_root stale_plan
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-admission-selftest.XXXXXX")"
  run_all_cases "$tmp_root"
  stale_plan="${tmp_root}/stale_jsonl/out/plan.json"
  if jq -e '.decision == "fail_closed" and (.fail_closed_reasons | index("stale_br_bv_state") != null)' "$stale_plan" >/dev/null; then
    record_pass "selftest stale jsonl fails closed"
  else
    record_failure "selftest stale jsonl was not fail closed"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-admission-run.XXXXXX")"
      fi
      run_all_cases "$output_dir"
    fi
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
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
