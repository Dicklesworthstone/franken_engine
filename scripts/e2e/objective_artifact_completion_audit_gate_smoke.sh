#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_script="${root_dir}/scripts/objective_artifact_completion_audit_gate.sh"
docs_path="${root_dir}/docs/OBJECTIVE_ARTIFACT_COMPLETION_AUDIT_GATE.md"
contract_path="${root_dir}/docs/objective_artifact_completion_audit_gate_contract_v1.json"
fixtures_path="${OBJECTIVE_COMPLETION_AUDIT_FIXTURES:-${root_dir}/scripts/testdata/objective_artifact_completion_audit_gate/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS objective-artifact-completion-audit-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL objective-artifact-completion-audit-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.objective-artifact-completion-audit-gate-contract.v1"
    and .bead_id == "bd-w8jfe"
    and (.required_sections | sort) == ["deferred","missing","satisfied","weakly_verified"]
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "maps each deliverable to concrete artifacts" "$docs_path" \
    && grep -Fq "memory-only notes" "$docs_path" \
    && grep -Fq "satisfied" "$docs_path" \
    && grep -Fq "weakly_verified" "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.objective-artifact-completion-audit-gate-fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "manifest_present_not_covering_objective",
      "objective_fully_covered",
      "stale_memory_only_evidence",
      "test_passing_requirement_missing"
    ] | sort)
  ' "$fixtures_path" >/dev/null
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir status expected_exit expected_decision expected_satisfied expected_missing expected_weak expected_code
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"
  jq '.objective_json' <<<"$case_json" >"${tmpdir}/objective.json"
  jq '.evidence_json' <<<"$case_json" >"${tmpdir}/evidence.json"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_satisfied="$(jq -r '.expected.satisfied_count' <<<"$case_json")"
  expected_missing="$(jq -r '.expected.missing_count' <<<"$case_json")"
  expected_weak="$(jq -r '.expected.weakly_verified_count' <<<"$case_json")"
  expected_code="$(jq -r '.expected.required_weak_code // ""' <<<"$case_json")"
  if [[ "$expected_decision" == "complete" ]]; then
    expected_exit=0
  else
    expected_exit=42
  fi

  set +e
  "$gate_script" \
    --objective-json "${tmpdir}/objective.json" \
    --evidence-json "${tmpdir}/evidence.json" \
    --case-id "$case_id" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" \
    >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    printf 'expected exit %s for %s, got %s\n' "$expected_exit" "$case_id" "$status" >&2
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit ${case_id}"
    return
  fi

  local report="${output_dir}/completion_audit_report.json"
  [[ -f "$report" ]] || { record_failure "missing report ${case_id}"; return; }
  [[ -f "${output_dir}/missing_evidence.jsonl" ]] || { record_failure "missing evidence jsonl ${case_id}"; return; }
  [[ -f "${output_dir}/events.jsonl" ]] || { record_failure "missing events ${case_id}"; return; }
  [[ -f "${output_dir}/commands.txt" ]] || { record_failure "missing commands ${case_id}"; return; }
  [[ -f "${output_dir}/report.md" ]] || { record_failure "missing markdown ${case_id}"; return; }

  jq -e \
    --arg decision "$expected_decision" \
    --argjson satisfied "$expected_satisfied" \
    --argjson missing "$expected_missing" \
    --argjson weak "$expected_weak" '
      .schema_version == "franken-engine.objective-completion-audit-report.v1"
      and .decision == $decision
      and .summary.satisfied_count == $satisfied
      and .summary.missing_count == $missing
      and .summary.weakly_verified_count == $weak
      and (.satisfied | type) == "array"
      and (.missing | type) == "array"
      and (.weakly_verified | type) == "array"
      and (.deferred | type) == "array"
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
      and .mutation_policy.mutates_br == false
      and .mutation_policy.sends_agent_mail == false
    ' "$report" >/dev/null || record_failure "report mismatch ${case_id}"
  if [[ -n "$expected_code" ]]; then
    jq -e --arg code "$expected_code" 'any((.missing + .weakly_verified)[]?; any(.weak_evidence[]?; .code == $code))' "$report" >/dev/null \
      || record_failure "missing weak code ${expected_code} ${case_id}"
  fi
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$gate_script" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate_script" "${BASH_SOURCE[0]}"
  fi
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/objective_artifact_completion_audit_gate_smoke.sh [check|selftest]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
