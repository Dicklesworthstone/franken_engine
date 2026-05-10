#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_validation_admission_recommender.sh"
docs_path="${root_dir}/docs/SWARM_VALIDATION_ADMISSION_RECOMMENDER.md"
cases_path="${root_dir}/scripts/testdata/swarm_validation_admission_recommender/cases.json"
matrix_path="${root_dir}/docs/swarm_proof_command_preflight_contract_v1.json"
mode="${1:-check}"
output_root="${2:-${SWARM_VALIDATION_ADMISSION_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-validation-admission-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-validation-admission %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-validation-admission %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_validation_admission_recommender_smoke.sh [check|selftest] [output_root]
EOF
}

static_check() {
  jq empty "$cases_path" "$matrix_path" >/dev/null
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  grep -Fq 'does not run `cargo`, `rch`, `br`' "$docs_path"
  jq -e '
    .schema_version == "franken-engine.swarm-validation-admission-recommender-fixtures.v1"
    and (.cases | length) == 4
    and ([.cases[].expected.recommendation] | unique | sort) == ["run_focused_rch_now", "validation_blocked", "wait_existing_all_targets"]
  ' "$cases_path" >/dev/null
}

write_case_files() {
  local case_json="$1"
  local case_dir="$2"
  local ps_path="${case_dir}/ps.txt"
  local br_path="${case_dir}/br.json"
  local dirty_path="${case_dir}/dirty.json"

  if [[ "$(jq -r '.omit_ps_snapshot // false' <<<"$case_json")" != "true" ]]; then
    jq -r '.ps_snapshot // ""' <<<"$case_json" >"$ps_path"
  fi
  jq '.br_snapshot' <<<"$case_json" >"$br_path"
  jq '.dirty_files' <<<"$case_json" >"$dirty_path"

  printf '%s\n' "$ps_path" "$br_path" "$dirty_path"
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id case_dir paths ps_path br_path dirty_path expected_exit actual_exit

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  mkdir -p "$case_dir"
  mapfile -t paths < <(write_case_files "$case_json" "$case_dir")
  ps_path="${paths[0]}"
  br_path="${paths[1]}"
  dirty_path="${paths[2]}"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  set +e
  "$script_path" \
    --bead-id "$(jq -r '.bead_id' <<<"$case_json")" \
    --agent-id "$(jq -r '.agent_id' <<<"$case_json")" \
    --command-class "$(jq -r '.command_class' <<<"$case_json")" \
    --ps-snapshot "$ps_path" \
    --br-snapshot-json "$br_path" \
    --dirty-files-json "$dirty_path" \
    --matrix-json "$matrix_path" \
    --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    return
  fi

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" '
      .schema_version == "franken-engine.swarm-validation-admission-recommender.v1"
      and .recommendation == $expected.recommendation
      and .reason_code == $expected.reason_code
      and (.recommended_target_dir == ($expected.recommended_target_dir // .recommended_target_dir))
      and (if ($expected.finding_reason // "") == "" then true else any(.findings[]; .reason_code == $expected.finding_reason) end)
    ' "${case_dir}/out/recommendation.json" >/dev/null || record_failure "${case_id} recommendation mismatch"
  test -s "${case_dir}/out/events.jsonl"
  test -s "${case_dir}/out/commands.txt"
  test -s "${case_dir}/out/report.md"
  record_pass "$case_id"
}

run_check() {
  static_check || record_failure "static check"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"
  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi
  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
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
