#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_script="${root_dir}/scripts/idea_wizard_plan_quality_gate.sh"
fixture_root="${IDEA_WIZARD_PLAN_QUALITY_FIXTURES:-${root_dir}/scripts/testdata/idea_wizard_plan_quality_gate}"
pass_beads="${fixture_root}/pass_beads.json"
bad_beads="${fixture_root}/bad_beads.json"
bv_plan="${fixture_root}/bv_plan.json"
failures=0

record_pass() {
  printf 'PASS idea-wizard-plan-quality %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-plan-quality %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/idea_wizard_plan_quality_gate_smoke.sh [check|selftest|run] [output_dir]
EOF
}

run_check() {
  bash -n "$gate_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$pass_beads" "$bad_beads" "$bv_plan" >/dev/null
  grep -Fq 'plan_quality_gate_report.json' "$gate_script"
  grep -Fq 'replaces_br_or_bv: false' "$gate_script"
  grep -Fq 'missing_e2e_logging' "$gate_script"
  record_pass "shell syntax and fixture shape"
}

run_pass_case() {
  local output_dir="$1"
  "$gate_script" \
    --beads-json "$pass_beads" \
    --bv-plan-json "$bv_plan" \
    --source-revision fixture-revision \
    --output-dir "$output_dir" >/dev/null

  jq -e '
    .schema_version == "franken-engine.idea-wizard-plan-quality-report.v1"
    and .decision == "pass"
    and .role_counts.contract_profile >= 1
    and .role_counts.implementation >= 1
    and .role_counts.test_e2e >= 1
    and .role_counts.docs_claim >= 1
    and .diagnostic_counts.total == 0
    and .non_mutation_attestation.replaces_br_or_bv == false
    and .non_mutation_attestation.creates_beads == false
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
  ' "${output_dir}/plan_quality_gate_report.json" >/dev/null || {
    record_failure "pass case report mismatch"
    return
  }
  grep -Fq "| \`bd-ep8y0.1\` | \`contract_profile\` |" "${output_dir}/plan_quality_checklist.md"
  record_pass "pass case"
}

run_bad_case() {
  local output_dir="$1"
  local actual_exit

  set +e
  "$gate_script" \
    --beads-json "$bad_beads" \
    --source-revision fixture-revision \
    --output-dir "$output_dir" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne 42 ]]; then
    record_failure "bad case exit ${actual_exit}, expected 42"
    return
  fi
  jq -e '
    .decision == "fail"
    and .diagnostic_counts.errors >= 4
    and any(.diagnostics[]; .code == "duplicate_upstream_authority_claim")
    and any(.diagnostics[]; .code == "dependency_cycle")
    and any(.diagnostics[]; .code == "missing_e2e_logging")
    and any(.diagnostics[]; .code == "missing_claim_language_safeguard")
    and any(.diagnostics[]; .code == "first_actionable_not_parented")
  ' "${output_dir}/plan_quality_gate_report.json" >/dev/null || {
    record_failure "bad case report mismatch"
    return
  }
  grep -Fq 'duplicate_upstream_authority_claim' "${output_dir}/plan_quality_checklist.md"
  record_pass "bad case diagnostics"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/idea-wizard-plan-quality.XXXXXX")"
      run_pass_case "${tmp_root}/pass"
      run_bad_case "${tmp_root}/bad"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/idea-wizard-plan-quality-run.XXXXXX")}"
      mkdir -p "${output_dir}/pass" "${output_dir}/bad"
      run_pass_case "${output_dir}/pass"
      run_bad_case "${output_dir}/bad"
      printf 'idea_wizard_plan_quality_smoke_artifacts=%s\n' "$output_dir"
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
