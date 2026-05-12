#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
suite="${root_dir}/scripts/franken_core_graduation_acceptance_suite.sh"
contract_json="${root_dir}/docs/franken_core_graduation_acceptance_suite_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS franken-core-graduation-acceptance-suite %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-graduation-acceptance-suite %s\n' "$1" >&2
  exit 1
}

write_bad_status_claim() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<'EOF'
crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable.

crates/franken-core is workspace-ready and included in the workspace.
EOF
}

assert_report_shape() {
  local report_path="$1"
  jq -e '
    .schema_version == "franken-engine.franken-core-graduation-acceptance-report.v1"
    and (.decision == "ready_for_explicit_workspace_membership_bead" or .decision == "remain_excluded")
    and .workspace_membership_complete == false
    and (.final_proof_commands | length) == 3
    and all(.final_proof_commands[]; startswith("rch exec -- env CARGO_TARGET_DIR="))
    and .coordination_handling.agent_mail_required == false
    and .non_mutation_attestation.mutates_root_cargo_toml == false
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
  ' "$report_path" >/dev/null || record_failure "report shape ${report_path}"
}

run_acceptance_case() {
  local case_name="$1"
  local expected_decision="$2"
  local required_reason="$3"
  shift 3
  local tmpdir output_dir status expected_exit report_path
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  if [[ "$expected_decision" == "remain_excluded" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  "$suite" --source-revision "smoke-${case_name}" --output-dir "$output_dir" "$@" >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e
  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "${case_name} exit ${status}, expected ${expected_exit}"
  fi

  report_path="${output_dir}/acceptance_report.json"
  [[ -f "$report_path" ]] || record_failure "missing report ${case_name}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events ${case_name}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands ${case_name}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing markdown ${case_name}"
  assert_report_shape "$report_path"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$report_path" >/dev/null \
    || record_failure "decision mismatch ${case_name}"
  if [[ -n "$required_reason" ]]; then
    jq -e --arg reason "$required_reason" '.reason_codes | index($reason)' "$report_path" >/dev/null \
      || record_failure "missing reason ${required_reason} ${case_name}"
  fi
  record_pass "$case_name"
}

run_check() {
  jq empty "$contract_json"
  bash -n "$suite" "${BASH_SOURCE[0]}"
  run_acceptance_case "live-ready" "ready_for_explicit_workspace_membership_bead" ""
  git -C "$root_dir" diff --check -- \
    docs/FRANKEN_CORE_GRADUATION_ACCEPTANCE_SUITE_V1.md \
    docs/franken_core_graduation_acceptance_suite_v1.json \
    scripts/franken_core_graduation_acceptance_suite.sh \
    scripts/e2e/franken_core_graduation_acceptance_suite_smoke.sh
  record_pass "check"
}

run_negative() {
  local tmpdir
  tmpdir="$(mktemp -d)"

  run_acceptance_case \
    "missing-child-artifact" \
    "remain_excluded" \
    "missing_child_artifact" \
    --golden-json "${tmpdir}/missing-golden.json" \
    --skip-child-smokes

  jq '.summary.unclassified_row_count = 1 | .rows[0].status = "unclassified"' \
    "${root_dir}/docs/franken_core_api_parity_ledger_v1.json" >"${tmpdir}/bad-parity.json"
  run_acceptance_case \
    "unclassified-api-row" \
    "remain_excluded" \
    "unclassified_api_rows" \
    --parity-json "${tmpdir}/bad-parity.json" \
    --skip-child-smokes

  jq '.required_change_classes += ["mystery_surface"]' \
    "${root_dir}/docs/franken_core_validation_impact_planner_v1.json" >"${tmpdir}/bad-validation.json"
  run_acceptance_case \
    "unknown-validation-class" \
    "remain_excluded" \
    "unknown_validation_class" \
    --validation-contract-json "${tmpdir}/bad-validation.json" \
    --skip-child-smokes

  jq 'del(.reports[] | select(.family == "status_truth_gate"))' \
    "${root_dir}/scripts/testdata/franken_core_graduation_golden_reports/reports.json" >"${tmpdir}/bad-goldens.json"
  run_acceptance_case \
    "missing-golden-coverage" \
    "remain_excluded" \
    "missing_golden_coverage" \
    --golden-json "${tmpdir}/bad-goldens.json" \
    --skip-child-smokes

  write_bad_status_claim "${tmpdir}/bad-status.md"
  run_acceptance_case \
    "stale-docs" \
    "remain_excluded" \
    "stale_docs_or_manifest_claim" \
    --status-claim-file "${tmpdir}/bad-status.md" \
    --skip-child-smokes

  record_pass "negative"
}

case "$mode" in
  check)
    run_check
    ;;
  negative)
    run_negative
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/franken_core_graduation_acceptance_suite_smoke.sh [check|negative]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
