#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/idea_wizard_xiii_claim_promotion_gate.sh"
contract_json="${root_dir}/docs/idea_wizard_xiii_claim_promotion_gate_v1.json"
docs_path="${root_dir}/docs/IDEA_WIZARD_XIII_CLAIM_PROMOTION_GATE.md"
fixtures_json="${root_dir}/scripts/testdata/idea_wizard_xiii_claim_promotion_gate/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-xiii-claim-promotion-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-xiii-claim-promotion-gate %s\n' "$1" >&2
  exit 1
}

run_gate_expect() {
  local expected_exit="$1"
  local transparency="$2"
  local quarantine="$3"
  local capability="$4"
  local readme="$5"
  local output_dir="$6"
  local status

  set +e
  "$gate" \
    --contract-json "$contract_json" \
    --transparency-report "$transparency" \
    --quarantine-report "$quarantine" \
    --capability-report "$capability" \
    --readme "$readme" \
    --source-revision "smoke-claim-promotion-gate" \
    --output-dir "$output_dir" >/dev/null 2>"${output_dir}.stderr"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${output_dir}.stderr" >&2
    record_failure "gate exit ${status}, expected ${expected_exit}"
  fi
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"

  mkdir -p "$case_dir"
  jq -e --arg id "$case_id" '.cases[] | select(.case_id == $id)' "$fixtures_json" >/dev/null \
    || record_failure "missing fixture case ${case_id}"
  jq --arg id "$case_id" '.cases[] | select(.case_id == $id) | .reports.transparency' "$fixtures_json" >"${case_dir}/transparency_report.json"
  jq --arg id "$case_id" '.cases[] | select(.case_id == $id) | .reports.quarantine' "$fixtures_json" >"${case_dir}/quarantine_report.json"
  jq --arg id "$case_id" '.cases[] | select(.case_id == $id) | .reports.capability' "$fixtures_json" >"${case_dir}/capability_report.json"
  jq -r --arg id "$case_id" '.cases[] | select(.case_id == $id) | .readme_text' "$fixtures_json" >"${case_dir}/README.md"
}

run_check() {
  local tmpdir case_dir output_dir
  tmpdir="$(mktemp -d)"
  case_dir="${tmpdir}/live_case"
  output_dir="${tmpdir}/live_output"

  bash -n "$gate" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate" "${BASH_SOURCE[0]}"
  fi
  jq empty "$contract_json" "$fixtures_json"
  grep -Fq "FE-CLAIM-004" "$docs_path"
  grep -Fq "FE-CLAIM-005" "$docs_path"
  grep -Fq "FE-CLAIM-006" "$docs_path"

  materialize_case "live_proof" "$case_dir"
  run_gate_expect \
    0 \
    "${case_dir}/transparency_report.json" \
    "${case_dir}/quarantine_report.json" \
    "${case_dir}/capability_report.json" \
    "${case_dir}/README.md" \
    "$output_dir"

  jq -e '
    .decision == "pass"
    and .summary.green == 1
    and .summary.degraded == 2
    and .summary.fail_closed == 0
    and any(.claim_statuses[]; .claim_id == "FE-CLAIM-004" and .status == "degraded" and .proven_subset_status == "green")
    and any(.claim_statuses[]; .claim_id == "FE-CLAIM-005" and .status == "green")
    and any(.claim_statuses[]; .claim_id == "FE-CLAIM-006" and .status == "degraded" and (.downgrade_text | contains("TypeScript-to-IR")))
  ' "${output_dir}/operator_status.json" >/dev/null \
    || record_failure "operator status mismatch"
  jq -s 'length == 3 and all(.[]; .event == "claim_operator_status")' "${output_dir}/events.jsonl" >/dev/null \
    || record_failure "event log mismatch"

  git -C "$root_dir" diff --check -- \
    "$docs_path" \
    "$contract_json" \
    "$gate" \
    "${BASH_SOURCE[0]}" \
    "$fixtures_json"
  record_pass "check"
}

run_negative_case() {
  local case_id="$1"
  local expected_reason="$2"
  local tmpdir case_dir output_dir capability_path
  tmpdir="$(mktemp -d)"
  case_dir="${tmpdir}/${case_id}"
  output_dir="${tmpdir}/${case_id}_output"

  materialize_case "$case_id" "$case_dir"
  capability_path="${case_dir}/capability_report.json"
  if [[ "$case_id" == "missing_artifact" ]]; then
    capability_path="${case_dir}/missing_capability_report.json"
  fi

  run_gate_expect \
    42 \
    "${case_dir}/transparency_report.json" \
    "${case_dir}/quarantine_report.json" \
    "$capability_path" \
    "${case_dir}/README.md" \
    "$output_dir"
  jq -e --arg reason "$expected_reason" '
    .decision == "fail_closed"
    and .summary.fail_closed >= 1
    and any(.failures[]; (.reasons | join(" ") | contains($reason)))
  ' "${output_dir}/claim_promotion_gate_report.json" >/dev/null \
    || record_failure "negative case ${case_id} mismatch"
}

run_selftest() {
  run_check
  run_negative_case "stale_proof" "stale"
  run_negative_case "synthetic_proof" "synthetic"
  run_negative_case "missing_artifact" "missing"
  run_negative_case "overclaiming_readme_text" "overclaims"
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
