#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
doctor_script="${root_dir}/scripts/swarm_artifact_doctor.sh"
fixture_root="${SWARM_ARTIFACT_DOCTOR_FIXTURES:-${root_dir}/scripts/testdata/swarm_artifact_doctor}"
cases_json="${fixture_root}/cases.json"
contract_json="${fixture_root}/contract.json"
failures=0

record_pass() {
  printf 'PASS swarm-artifact-doctor %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-artifact-doctor %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_artifact_doctor_smoke.sh [check|selftest|run] [output_dir]
EOF
}

run_check() {
  bash -n "$doctor_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$doctor_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$cases_json" "$contract_json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.swarm-artifact-doctor-fixtures.v1"
    and (.cases | length) >= 7
    and ([.cases[].case_id] | index("complete_bundle") != null)
    and ([.cases[].case_id] | index("missing_manifest") != null)
    and ([.cases[].case_id] | index("missing_commands") != null)
    and ([.cases[].case_id] | index("incomplete_replay_directory") != null)
    and ([.cases[].case_id] | index("local_fallback_marker") != null)
    and ([.cases[].case_id] | index("stale_hash") != null)
    and ([.cases[].case_id] | index("unknown_contract") != null)
  ' "$cases_json" >/dev/null || record_failure "fixture shape"

  grep -Fq 'artifact_doctor_report.json' "$doctor_script"
  grep -Fq 'repairs_bundles: false' "$doctor_script"
  grep -Fq 'creates_beads: false' "$doctor_script"
  record_pass "shell syntax and fixture shape"
}

assert_artifacts_exist() {
  local output_dir="$1"
  jq empty "${output_dir}/artifact_doctor_report.json" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id output_dir expected_exit actual_exit use_contract
  local -a cmd

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  output_dir="${tmp_root}/${case_id}/out"
  mkdir -p "$output_dir"

  cmd=(
    "$doctor_script"
    --artifact-dir "${fixture_root}/${case_id}/bundle"
    --source-revision fixture-revision
    --output-dir "$output_dir"
  )
  use_contract="$(jq -r 'if has("contract") then .contract else true end' <<<"$case_json")"
  if [[ "$use_contract" == "true" ]]; then
    cmd+=(--contract-json "$contract_json")
  fi

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
      .schema_version == "franken-engine.swarm-artifact-doctor-report.v1"
      and .status == $expected.status
      and .diagnostic_counts.errors == $expected.errors
      and .diagnostic_counts.warnings == $expected.warnings
      and .non_mutation_attestation.reads_only == true
      and .non_mutation_attestation.repairs_bundles == false
      and .non_mutation_attestation.rewrites_bundles == false
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and (. as $report | all($expected.required_codes[]; . as $code | any($report.diagnostics[]; .code == $code)))
    ' "${output_dir}/artifact_doctor_report.json" >/dev/null; then
    record_failure "${case_id} report mismatch"
    return
  fi

  if ! jq -s 'length >= 3 and any(.[]; .event == "doctor.completed")' "${output_dir}/events.jsonl" >/dev/null; then
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
      run_all_cases "$(mktemp -d "${TMPDIR:-/tmp}/swarm-artifact-doctor.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/swarm-artifact-doctor-run.XXXXXX")}"
      run_all_cases "$output_dir"
      printf 'swarm_artifact_doctor_smoke_artifacts=%s\n' "$output_dir"
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
