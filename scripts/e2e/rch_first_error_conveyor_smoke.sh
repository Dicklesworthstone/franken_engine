#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
conveyor_script="${root_dir}/scripts/rch_first_error_conveyor.sh"
contract_json="${root_dir}/docs/rch_first_error_conveyor_contract_v1.json"
operator_doc="${root_dir}/docs/RCH_FIRST_ERROR_CONVEYOR.md"
fixture_root="${RCH_FIRST_ERROR_CONVEYOR_FIXTURES:-${root_dir}/scripts/testdata/rch_first_error_conveyor}"
cases_json="${fixture_root}/cases.json"
failures=0

record_pass() {
  printf 'PASS rch-first-error-conveyor %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-first-error-conveyor %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_first_error_conveyor_smoke.sh [check|selftest|run] [output_dir]
EOF
}

write_case_inputs() {
  local case_json="$1"
  local case_dir="$2"

  mkdir -p "$case_dir"
  jq '.clusters' <<<"$case_json" >"${case_dir}/clusters.json"
  jq '.profile' <<<"$case_json" >"${case_dir}/profile.json"
}

run_check() {
  bash -n "$conveyor_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$conveyor_script" "${BASH_SOURCE[0]}"
  fi

  jq empty "$contract_json" >/dev/null
  jq empty "$cases_json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.rch-first-error-conveyor-contract.v1"
    and .advisory_only == true
    and .non_mutation_policy.runs_cargo == false
    and .non_mutation_policy.runs_rch == false
    and .non_mutation_policy.creates_beads == false
    and (.fixture_cases | index("target_relevant_first_error") != null)
    and (.fixture_cases | index("unrelated_sibling_errors") != null)
    and (.fixture_cases | index("truncated_output") != null)
    and (.fixture_cases | index("local_fallback_contamination") != null)
  ' "$contract_json" >/dev/null || record_failure "contract shape"

  jq -e '
    .schema_version == "franken-engine.rch-first-error-conveyor-fixtures.v1"
    and (.cases | length) == 4
    and all(.cases[]; has("clusters") and has("profile") and has("expected"))
  ' "$cases_json" >/dev/null || record_failure "fixture shape"

  grep -Fq 'advisory-only' "$operator_doc"
  grep -Fq 'creates_beads: false' "$conveyor_script"
  grep -Fq 'runs_cargo: false' "$conveyor_script"
  record_pass "shell syntax and contract shape"
}

assert_artifacts_exist() {
  local output_dir="$1"

  jq empty "${output_dir}/first_error_conveyor_plan.json" >/dev/null
  jq empty "${output_dir}/run_manifest.json" >/dev/null
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/report.md"
  test -s "${output_dir}/proposed_commands.txt"
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id case_dir output_dir expected_exit actual_exit
  local -a cmd

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}/input"
  output_dir="${tmp_root}/${case_id}/out"
  write_case_inputs "$case_json" "$case_dir"
  mkdir -p "$output_dir"

  cmd=(
    "$conveyor_script"
    --clusters-json "${case_dir}/clusters.json"
    --profile-json "${case_dir}/profile.json"
    --source-revision fixture-revision
    --case-id "$case_id"
    --output-dir "$output_dir"
  )

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  set +e
  "${cmd[@]}" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    return
  fi

  if ! assert_artifacts_exist "$output_dir"; then
    record_failure "${case_id} missing artifact"
    return
  fi

  if ! jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
      .schema_version == "franken-engine.rch-first-error-conveyor-plan.v1"
      and .decision == $expected.decision
      and .summary.recommendation_count == $expected.recommendation_count
      and .summary.block_current_bead_count == $expected.block_current_bead_count
      and .summary.new_bead_candidate_count == $expected.new_bead_candidate_count
      and .summary.insufficient_evidence_count == $expected.insufficient_evidence_count
      and any(.recommendations[]; .disposition == $expected.primary_disposition)
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.creates_beads == false
    ' "${output_dir}/first_error_conveyor_plan.json" >/dev/null; then
    record_failure "${case_id} plan mismatch"
    return
  fi

  if ! jq -s 'length >= 2 and any(.[]; .event == "plan.emitted")' "${output_dir}/events.jsonl" >/dev/null; then
    record_failure "${case_id} event log mismatch"
    return
  fi

  record_pass "$case_id"
}

run_all_cases() {
  local tmp_root="$1"

  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_json")
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_all_cases "$(mktemp -d "${TMPDIR:-/tmp}/rch-first-error-conveyor.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/rch-first-error-conveyor-run.XXXXXX")}"
      run_all_cases "$output_dir"
      printf 'rch_first_error_conveyor_smoke_artifacts=%s\n' "$output_dir"
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
