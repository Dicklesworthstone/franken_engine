#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
capsule_script="${root_dir}/scripts/rch_proof_failure_capsule.sh"
fixture_root="${RCH_PROOF_FAILURE_CAPSULE_FIXTURES:-${root_dir}/scripts/testdata/rch_proof_failure_capsule}"
cases_json="${fixture_root}/cases.json"
failures=0

record_pass() {
  printf 'PASS rch-proof-failure-capsule %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-proof-failure-capsule %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_proof_failure_capsule_smoke.sh [check|selftest|run] [output_dir]
EOF
}

run_check() {
  bash -n "$capsule_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$capsule_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$cases_json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.rch-proof-failure-capsule-fixtures.v1"
    and (.cases | length) >= 7
    and ([.cases[].case_id] | index("remote_success") != null)
    and ([.cases[].case_id] | index("remote_compile_failure") != null)
    and ([.cases[].case_id] | index("local_fallback") != null)
    and ([.cases[].case_id] | index("queue_timeout") != null)
    and ([.cases[].case_id] | index("worker_toolchain_missing") != null)
    and ([.cases[].case_id] | index("interrupted_build") != null)
    and ([.cases[].case_id] | index("target_dir_fingerprint_corruption") != null)
    and all(.cases[]; has("expected"))
  ' "$cases_json" >/dev/null || record_failure "fixture shape"

  # rch-policy-waive: local_fallback_not_rejected reason=smoke asserts the capsule rejects local fallback markers
  grep -Fq 'local fallback' "$capsule_script"
  grep -Fq 'never_claim_success_from_failed_output' "$capsule_script"
  grep -Fq 'runs_cargo: false' "$capsule_script"
  grep -Fq 'runs_rch: false' "$capsule_script"
  record_pass "shell syntax and fixture shape"
}

assert_artifacts_exist() {
  local output_dir="$1"
  jq empty "${output_dir}/proof_failure_capsule.json" >/dev/null
  jq empty "${output_dir}/next_command_advice.json" >/dev/null
  jq empty "${output_dir}/run_manifest.json" >/dev/null
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/report.md"
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id case_dir output_dir expected_exit actual_exit blocker_contains first_error_contains recommended_action
  local -a cmd

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${fixture_root}/${case_id}"
  output_dir="${tmp_root}/${case_id}/out"
  mkdir -p "$output_dir"

  cmd=(
    "$capsule_script"
    --transcript "${case_dir}/transcript.txt"
    --metadata-json "${case_dir}/metadata.json"
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
      .schema_version == "franken-engine.rch-proof-failure-capsule.v1"
      and .case_id == $expected.case_id
      and .classification == $expected.classification
      and .decision == $expected.decision
      and .reason_code == $expected.reason_code
      and .source_evidence == $expected.source_evidence
      and .proof_usable == $expected.proof_usable
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_beads == false
    ' "${output_dir}/proof_failure_capsule.json" >/dev/null; then
    record_failure "${case_id} capsule mismatch"
    return
  fi

  recommended_action="$(jq -r '.expected.recommended_action' <<<"$case_json")"
  if ! jq -e --arg recommended_action "$recommended_action" '
      .recommended_action == $recommended_action
      and .conservative_guards.never_claim_success_from_failed_output == true
      and .conservative_guards.refuses_local_fallback_as_proof == true
      and .conservative_guards.runs_cargo == false
      and .conservative_guards.runs_rch == false
    ' "${output_dir}/next_command_advice.json" >/dev/null; then
    record_failure "${case_id} advice mismatch"
    return
  fi

  blocker_contains="$(jq -r '.expected.blocker_contains // ""' <<<"$case_json")"
  if [[ -n "$blocker_contains" ]] &&
    ! jq -e --arg needle "$blocker_contains" '(.blocker_text // "") | contains($needle)' "${output_dir}/proof_failure_capsule.json" >/dev/null; then
    record_failure "${case_id} blocker text missing expected snippet"
    return
  fi

  first_error_contains="$(jq -r '.expected.first_error_contains // ""' <<<"$case_json")"
  if [[ -n "$first_error_contains" ]] &&
    ! jq -e --arg needle "$first_error_contains" '(.first_relevant_errors | join("\n")) | contains($needle)' "${output_dir}/proof_failure_capsule.json" >/dev/null; then
    record_failure "${case_id} first compiler error missing"
    return
  fi

  if [[ "$case_id" == "local_fallback" ]]; then
    if ! jq -e '.classification != "remote_success" and .proof_usable == false and .observed_markers.local_fallback == true' "${output_dir}/proof_failure_capsule.json" >/dev/null; then
      record_failure "local_fallback classified as usable proof"
      return
    fi
  fi

  if [[ "$case_id" == "target_dir_fingerprint_corruption" ]]; then
    if ! jq -e '.classification != "remote_compile_failure" and .proof_usable == false and .source_evidence == false and .observed_markers.target_dir_fingerprint == true' "${output_dir}/proof_failure_capsule.json" >/dev/null; then
      record_failure "target_dir_fingerprint_corruption classified as source proof"
      return
    fi
  fi

  if ! jq -s 'length >= 4 and any(.[]; .event == "capsule.classified") and any(.[]; .event == "advice.written")' "${output_dir}/events.jsonl" >/dev/null; then
    record_failure "${case_id} event log mismatch"
    return
  fi
  grep -Fq './scripts/rch_proof_failure_capsule.sh' "${output_dir}/commands.txt"

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
      run_all_cases "$(mktemp -d "${TMPDIR:-/tmp}/rch-proof-failure-capsule.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/rch-proof-failure-capsule-run.XXXXXX")}"
      run_all_cases "$output_dir"
      printf 'rch_proof_failure_capsule_smoke_artifacts=%s\n' "$output_dir"
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
