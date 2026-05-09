#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
profile_script="${root_dir}/scripts/rch_compile_proof_isolation_profile.sh"
contract_json="${root_dir}/docs/rch_compile_proof_isolation_profile_contract_v1.json"
operator_doc="${root_dir}/docs/RCH_COMPILE_PROOF_ISOLATION_PROFILE.md"
fixture_root="${RCH_COMPILE_PROOF_ISOLATION_PROFILE_FIXTURES:-${root_dir}/scripts/testdata/rch_compile_proof_isolation_profile}"
cases_json="${fixture_root}/cases.json"
failures=0

record_pass() {
  printf 'PASS rch-compile-proof-isolation-profile %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-compile-proof-isolation-profile %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_compile_proof_isolation_profile_smoke.sh [check|selftest|run] [output_dir]
EOF
}

write_case_inputs() {
  local case_json="$1"
  local case_dir="$2"

  mkdir -p "$case_dir"
  jq '.metadata' <<<"$case_json" >"${case_dir}/metadata.json"
  jq '.changed_paths' <<<"$case_json" >"${case_dir}/changed_paths.json"
}

run_check() {
  bash -n "$profile_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$profile_script" "${BASH_SOURCE[0]}"
  fi

  jq empty "$contract_json" >/dev/null
  jq empty "$cases_json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.rch-compile-proof-isolation-profile-contract.v1"
    and .advisory_only == true
    and .non_mutation_policy.runs_cargo == false
    and .non_mutation_policy.runs_rch == false
    and .non_mutation_policy.creates_beads == false
    and (.fixture_cases | index("narrow_integration_test") != null)
    and (.fixture_cases | index("broad_lib_test_drift") != null)
    and (.fixture_cases | index("shell_only_proof") != null)
    and (.fixture_cases | index("local_fallback_contaminated") != null)
  ' "$contract_json" >/dev/null || record_failure "contract shape"

  jq -e '
    .schema_version == "franken-engine.rch-compile-proof-isolation-profile-fixtures.v1"
    and (.cases | length) == 4
    and all(.cases[]; has("metadata") and has("changed_paths") and has("expected"))
  ' "$cases_json" >/dev/null || record_failure "fixture shape"

  grep -Fq 'advisory-only' "$operator_doc"
  grep -Fq 'runs_cargo: false' "$profile_script"
  grep -Fq 'runs_rch: false' "$profile_script"
  record_pass "shell syntax and contract shape"
}

assert_artifacts_exist() {
  local output_dir="$1"

  jq empty "${output_dir}/compile_proof_isolation_profile.json" >/dev/null
  jq empty "${output_dir}/run_manifest.json" >/dev/null
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/report.md"
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
    "$profile_script"
    --metadata-json "${case_dir}/metadata.json"
    --changed-paths-json "${case_dir}/changed_paths.json"
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
      .schema_version == "franken-engine.rch-compile-proof-isolation-profile.v1"
      and .decision == $expected.decision
      and .command.class == $expected.command_class
      and .classification.compile_surface == $expected.compile_surface
      and .classification.target_relevance == $expected.target_relevance
      and .classification.proof_strength == $expected.proof_strength
      and .classification.allowed_fallback == $expected.allowed_fallback
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.creates_beads == false
    ' "${output_dir}/compile_proof_isolation_profile.json" >/dev/null; then
    record_failure "${case_id} profile mismatch"
    return
  fi

  if ! jq -s 'length >= 2 and any(.[]; .event == "profile.emitted")' "${output_dir}/events.jsonl" >/dev/null; then
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
      run_all_cases "$(mktemp -d "${TMPDIR:-/tmp}/rch-compile-proof-isolation-profile.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/rch-compile-proof-isolation-profile-run.XXXXXX")}"
      run_all_cases "$output_dir"
      printf 'rch_compile_proof_isolation_profile_smoke_artifacts=%s\n' "$output_dir"
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
