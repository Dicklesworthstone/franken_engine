#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_script="${root_dir}/scripts/idea_wizard_plan_quality_gate.sh"
fixture_root="${IDEA_WIZARD_PLAN_QUALITY_FIXTURES:-${root_dir}/scripts/testdata/idea_wizard_plan_quality_gate}"
pass_beads="${fixture_root}/pass_beads.json"
bad_beads="${fixture_root}/bad_beads.json"
bv_plan="${fixture_root}/bv_plan.json"
golden_dir="${IDEA_WIZARD_PLAN_QUALITY_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
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
  goldens_shape_ok
  record_pass "shell syntax and fixture shape"
}

golden_case_names() {
  printf '%s\n' pass bad
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" --arg root_dir "$root_dir" '
    def scrub:
      if type == "string" then
        gsub($root_dir; "[REPO_ROOT]")
        | gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
        | gsub("/data/tmp/[A-Za-z0-9._-]+"; "[DATA_TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$report_path"
}

assert_case_golden() {
  local case_name="$1"
  local report_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/idea_wizard_plan_quality_gate_${case_name}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_report "$report_path" "$tmp_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_name} missing golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_report "$report_path" "$tmp_root"); then
    record_failure "${case_name} golden drift"
    return 1
  fi
}

goldens_shape_ok() {
  local case_name golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_name; do
    golden_path="${golden_dir}/idea_wizard_plan_quality_gate_${case_name}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${case_name} missing checked-in golden"
      continue
    fi
    jq empty "$golden_path" >/dev/null || record_failure "${case_name} invalid golden json"
  done < <(golden_case_names)
}

run_pass_case() {
  local output_dir="$1"
  local tmp_root="$2"
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
  assert_case_golden "pass" "${output_dir}/plan_quality_gate_report.json" "$tmp_root" || return
  record_pass "pass case"
}

run_bad_case() {
  local output_dir="$1"
  local tmp_root="$2"
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
  assert_case_golden "bad" "${output_dir}/plan_quality_gate_report.json" "$tmp_root" || return
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
      run_pass_case "${tmp_root}/pass" "$tmp_root"
      run_bad_case "${tmp_root}/bad" "$tmp_root"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/idea-wizard-plan-quality-run.XXXXXX")}"
      mkdir -p "${output_dir}/pass" "${output_dir}/bad"
      run_pass_case "${output_dir}/pass" "$output_dir"
      run_bad_case "${output_dir}/bad" "$output_dir"
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
