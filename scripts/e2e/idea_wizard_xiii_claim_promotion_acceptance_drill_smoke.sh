#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill="${root_dir}/scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh"
contract_json="${root_dir}/docs/idea_wizard_xiii_claim_promotion_acceptance_drill_v1.json"
docs_path="${root_dir}/docs/IDEA_WIZARD_XIII_CLAIM_PROMOTION_ACCEPTANCE_DRILL.md"
gate_fixtures_json="${root_dir}/scripts/testdata/idea_wizard_xiii_claim_promotion_gate/cases.json"
fixtures_json="${root_dir}/scripts/testdata/idea_wizard_xiii_claim_promotion_acceptance_drill/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-xiii-claim-promotion-acceptance-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-xiii-claim-promotion-acceptance-drill %s\n' "$1" >&2
  exit 1
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"

  mkdir -p "$case_dir"
  jq -e --arg id "$case_id" '.cases[] | select(.case_id == $id)' "$gate_fixtures_json" >/dev/null \
    || record_failure "missing gate fixture case ${case_id}"
  jq --arg id "$case_id" '.cases[] | select(.case_id == $id) | .reports.transparency' "$gate_fixtures_json" >"${case_dir}/transparency_report.json"
  jq --arg id "$case_id" '.cases[] | select(.case_id == $id) | .reports.quarantine' "$gate_fixtures_json" >"${case_dir}/quarantine_report.json"
  jq --arg id "$case_id" '.cases[] | select(.case_id == $id) | .reports.capability' "$gate_fixtures_json" >"${case_dir}/capability_report.json"
  jq -r --arg id "$case_id" '.cases[] | select(.case_id == $id) | .readme_text' "$gate_fixtures_json" >"${case_dir}/README.md"
}

run_drill_expect() {
  local expected_exit="$1"
  local case_dir="$2"
  local output_dir="$3"
  local capability_mode="${4:-present}"
  local capability_path="${case_dir}/capability_report.json"
  local status

  if [[ "$capability_mode" == "missing" ]]; then
    capability_path="${case_dir}/missing_capability_report.json"
  fi

  set +e
  "$drill" \
    --contract-json "$contract_json" \
    --transparency-report "${case_dir}/transparency_report.json" \
    --quarantine-report "${case_dir}/quarantine_report.json" \
    --capability-report "$capability_path" \
    --readme "${case_dir}/README.md" \
    --mode fixture \
    --source-revision "smoke-claim-promotion-acceptance" \
    --output-dir "$output_dir" >/dev/null 2>"${output_dir}.stderr"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${output_dir}.stderr" >&2
    record_failure "drill exit ${status}, expected ${expected_exit}"
  fi
}

golden_core() {
  local report_path="$1"
  jq '{
    decision,
    gate_decision,
    summary,
    claim_assertions: [.claim_assertions[] | {claim_id,status,operator_status,proven_subset_status}],
    mutation_policy
  }' "$report_path"
}

expected_core() {
  local case_id="$1"
  jq --arg id "$case_id" '.cases[] | select(.case_id == $id) | .expected_core' "$fixtures_json"
}

run_check() {
  local tmpdir case_dir output_dir actual expected
  tmpdir="$(mktemp -d)"
  case_dir="${tmpdir}/live_case"
  output_dir="${tmpdir}/live_output"

  bash -n "$drill" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$drill" "${BASH_SOURCE[0]}"
  fi
  jq empty "$contract_json" "$fixtures_json" "$gate_fixtures_json"
  grep -Fq "FE-CLAIM-004" "$docs_path"
  grep -Fq "FE-CLAIM-005" "$docs_path"
  grep -Fq "FE-CLAIM-006" "$docs_path"

  materialize_case "live_proof" "$case_dir"
  run_drill_expect 0 "$case_dir" "$output_dir"
  actual="$(golden_core "${output_dir}/aggregate_report.json")"
  expected="$(expected_core "live_proof")"
  if ! jq -e --argjson actual "$actual" --argjson expected "$expected" -n '$actual == $expected' >/dev/null; then
    printf 'actual:\n%s\nexpected:\n%s\n' "$actual" "$expected" >&2
    record_failure "live golden mismatch"
  fi
  jq -e '
    .decision == "pass"
    and .source_inputs.reports.transparency.snapshot != null
    and .artifact_paths.gate_report_json != null
  ' "${output_dir}/aggregate_report.json" >/dev/null \
    || record_failure "source preservation or nested gate path missing"
  git -C "$root_dir" diff --check -- \
    "$docs_path" \
    "$contract_json" \
    "$drill" \
    "${BASH_SOURCE[0]}" \
    "$fixtures_json"
  record_pass "check"
}

run_negative_case() {
  local case_id="$1"
  local tmpdir case_dir output_dir expected_reason
  tmpdir="$(mktemp -d)"
  case_dir="${tmpdir}/${case_id}"
  output_dir="${tmpdir}/${case_id}_output"
  expected_reason="$(jq -r --arg id "$case_id" '.cases[] | select(.case_id == $id) | .expected_failure_contains' "$fixtures_json")"

  materialize_case "$case_id" "$case_dir"
  if [[ "$case_id" == "missing_artifact" ]]; then
    run_drill_expect 42 "$case_dir" "$output_dir" missing
  else
    run_drill_expect 42 "$case_dir" "$output_dir"
  fi
  jq -e --arg reason "$expected_reason" '
    .decision == "fail_closed"
    and any(.failures[]; (.reasons | join(" ") | contains($reason)))
  ' "${output_dir}/aggregate_report.json" >/dev/null \
    || record_failure "negative case ${case_id} mismatch"
}

run_selftest() {
  run_check
  run_negative_case "stale_proof"
  run_negative_case "synthetic_proof"
  run_negative_case "missing_artifact"
  run_negative_case "overclaiming_readme_text"
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
    printf 'Usage: %s [check|selftest]\n' "${BASH_SOURCE[0]}"
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
