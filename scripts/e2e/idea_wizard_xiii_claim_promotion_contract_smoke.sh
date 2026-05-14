#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/idea_wizard_xiii_claim_promotion_contract_gate.sh"
contract_json="${root_dir}/docs/idea_wizard_xiii_claim_promotion_contract_v1.json"
matrix_json="${root_dir}/docs/claim_to_proof_matrix_v1.json"
docs_path="${root_dir}/docs/IDEA_WIZARD_XIII_CLAIM_PROMOTION_CONTRACT.md"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-xiii-claim-promotion-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-xiii-claim-promotion-contract %s\n' "$1" >&2
  exit 1
}

run_gate_expect() {
  local expected_exit="$1"
  local contract="$2"
  local matrix="$3"
  local output_dir="$4"
  local status

  set +e
  "$gate" \
    --contract-json "$contract" \
    --matrix-json "$matrix" \
    --source-revision "smoke-claim-promotion" \
    --output-dir "$output_dir" >/dev/null 2>"${output_dir}.stderr"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${output_dir}.stderr" >&2
    record_failure "gate exit ${status}, expected ${expected_exit}"
  fi
}

run_check() {
  local tmpdir output_dir
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/pass"

  bash -n "$gate" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate" "${BASH_SOURCE[0]}"
  fi
  jq empty "$contract_json" "$matrix_json"
  grep -Fq "FE-CLAIM-004" "$docs_path"
  grep -Fq "FE-CLAIM-005" "$docs_path"
  grep -Fq "FE-CLAIM-006" "$docs_path"

  run_gate_expect 0 "$contract_json" "$matrix_json" "$output_dir"
  jq -e '
    .decision == "pass"
    and (.claim_results | length) == 3
    and all(.claim_results[]; .status == "pass")
    and .mutation_policy.promotes_claims == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "${output_dir}/claim_promotion_contract_report.json" >/dev/null \
    || record_failure "live contract report mismatch"
  jq -s 'length >= 3 and all(.[]; .event == "claim_promotion_contract_checked")' "${output_dir}/events.jsonl" >/dev/null \
    || record_failure "event log mismatch"

  git -C "$root_dir" diff --check -- \
    "$docs_path" \
    "$contract_json" \
    "$gate" \
    "${BASH_SOURCE[0]}"
  record_pass "check"
}

run_selftest() {
  local tmpdir bad_contract output_dir
  tmpdir="$(mktemp -d)"
  bad_contract="${tmpdir}/bad_contract.json"
  output_dir="${tmpdir}/fail"

  jq '(.claims[] | select(.claim_id == "FE-CLAIM-006") | .required_artifacts) = ["capability_typed_onboarding_report_json"]' "$contract_json" >"$bad_contract"
  run_gate_expect 42 "$bad_contract" "$matrix_json" "$output_dir"
  jq -e '
    .decision == "fail_closed"
    and any(.failures[]; .claim_id == "FE-CLAIM-006" and (.reason | contains("required artifacts")))
  ' "${output_dir}/claim_promotion_contract_report.json" >/dev/null \
    || record_failure "negative contract failure mismatch"
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
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
