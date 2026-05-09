#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cluster_script="${root_dir}/scripts/rch_compile_blocker_cluster.sh"
fixture_root="${RCH_COMPILE_BLOCKER_CLUSTER_FIXTURES:-${root_dir}/scripts/testdata/rch_compile_blocker_cluster}"
cases_json="${fixture_root}/cases.json"
failures=0

record_pass() {
  printf 'PASS rch-compile-blocker-cluster %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-compile-blocker-cluster %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_compile_blocker_cluster_smoke.sh [check|selftest|run] [output_dir]
EOF
}

run_check() {
  bash -n "$cluster_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$cluster_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$cases_json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.rch-compile-blocker-cluster-fixtures.v1"
    and (.cases | length) >= 5
    and ([.cases[].case_id] | index("target_relevant_first_error") != null)
    and ([.cases[].case_id] | index("unrelated_sibling_errors") != null)
    and ([.cases[].case_id] | index("stale_test_api") != null)
    and ([.cases[].case_id] | index("local_fallback_contamination") != null)
    and ([.cases[].case_id] | index("truncated_output") != null)
    and all(.cases[]; has("expected"))
  ' "$cases_json" >/dev/null || record_failure "fixture shape"

  grep -Fq 'proposed_beads.md' "$cluster_script"
  grep -Fq 'creates_beads: false' "$cluster_script"
  grep -Fq 'tests_reached_intended_target' "$cluster_script"
  record_pass "shell syntax and fixture shape"
}

assert_artifacts_exist() {
  local output_dir="$1"
  jq empty "${output_dir}/compile_blocker_clusters.json" >/dev/null
  jq empty "${output_dir}/run_manifest.json" >/dev/null
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/report.md"
  test -s "${output_dir}/proposed_beads.md"
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id case_dir output_dir expected_exit actual_exit required_snippet
  local -a cmd

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${fixture_root}/${case_id}"
  output_dir="${tmp_root}/${case_id}/out"
  mkdir -p "$output_dir"

  cmd=(
    "$cluster_script"
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
      .schema_version == "franken-engine.rch-compile-blocker-clusters.v1"
      and .case_id == $expected.case_id
      and .decision == $expected.decision
      and .cluster_counts.total == $expected.cluster_count
      and .cluster_counts.block_current_bead == $expected.block_current_bead
      and .cluster_counts.file_follow_up == $expected.file_follow_up
      and .cluster_counts.infra_toolchain_blocker == $expected.infra_toolchain_blocker
      and .evidence_health.tests_reached_intended_target == $expected.tests_reached_intended_target
      and .evidence_health.local_fallback_observed == $expected.local_fallback_observed
      and .evidence_health.truncated_output_observed == $expected.truncated_output_observed
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.creates_beads == false
      and any(.clusters[]; .disposition == $expected.primary_disposition and .error_family == $expected.primary_error_family)
    ' "${output_dir}/compile_blocker_clusters.json" >/dev/null; then
    record_failure "${case_id} cluster mismatch"
    return
  fi

  required_snippet="$(jq -r '.expected.proposal_contains // ""' <<<"$case_json")"
  if [[ -n "$required_snippet" ]] && ! grep -Fq "$required_snippet" "${output_dir}/proposed_beads.md"; then
    record_failure "${case_id} proposed bead missing expected snippet"
    return
  fi

  if ! jq -s 'length >= 4 and any(.[]; .event == "clusters.written") and any(.[]; .event == "proposals.written")' "${output_dir}/events.jsonl" >/dev/null; then
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
      run_all_cases "$(mktemp -d "${TMPDIR:-/tmp}/rch-compile-blocker-cluster.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/rch-compile-blocker-cluster-run.XXXXXX")}"
      run_all_cases "$output_dir"
      printf 'rch_compile_blocker_cluster_smoke_artifacts=%s\n' "$output_dir"
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
