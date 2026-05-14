#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
proof_script="${root_dir}/scripts/idea_wizard_xiii_transparency_log_decision_receipt_proof.sh"
contract_json="${root_dir}/docs/idea_wizard_xiii_transparency_log_decision_receipt_proof_v1.json"
docs_path="${root_dir}/docs/IDEA_WIZARD_XIII_TRANSPARENCY_LOG_DECISION_RECEIPT_PROOF.md"
sample_receipt="${root_dir}/examples/02_signed_decision_receipt/sample_receipt.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-xiii-transparency-log-decision-receipt-proof %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-xiii-transparency-log-decision-receipt-proof %s\n' "$1" >&2
  exit 1
}

run_proof_expect() {
  local expected_exit="$1"
  local receipt="$2"
  local output_dir="$3"
  local status

  set +e
  "$proof_script" \
    --receipt-json "$receipt" \
    --skip-live-receipt-refresh \
    --source-revision "smoke-transparency-log-proof" \
    --output-dir "$output_dir" >/dev/null 2>"${output_dir}.stderr"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${output_dir}.stderr" >&2
    record_failure "proof script exit ${status}, expected ${expected_exit}"
  fi
}

run_check() {
  local tmpdir output_dir
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/pass"

  bash -n "$proof_script" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$proof_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$contract_json" "$sample_receipt"
  grep -Fq "FE-CLAIM-004" "$docs_path"
  grep -Fq "not_promoted" "$contract_json"

  run_proof_expect 0 "$sample_receipt" "$output_dir"
  jq -e '
    .decision == "pass"
    and .claim_id == "FE-CLAIM-004"
    and .promotion_subset == "decision_receipts_plus_transparency_log_only"
    and .tee_attestation_state == "not_promoted"
    and .inclusion_proof_count == 1
    and .consistency_proof_count == 1
    and all(.checks[]; .passed == true)
  ' "${output_dir}/independent_verifier_report.json" >/dev/null \
    || record_failure "proof report mismatch"
  jq -e 'all(.fixtures[]; .decision == "fail_closed")' "${output_dir}/negative_fixtures.json" >/dev/null \
    || record_failure "negative fixtures did not fail closed"
  jq -s 'length >= 5 and all(.[]; has("event") and has("status"))' "${output_dir}/events.jsonl" >/dev/null \
    || record_failure "events log mismatch"

  git -C "$root_dir" diff --check -- \
    "$docs_path" \
    "$contract_json" \
    "$proof_script" \
    "${BASH_SOURCE[0]}"
  record_pass "check"
}

run_selftest() {
  local tmpdir bad_receipt output_dir
  tmpdir="$(mktemp -d)"
  bad_receipt="${tmpdir}/missing_signature_receipt.json"
  output_dir="${tmpdir}/fail"

  jq 'del(.signature_hex)' "$sample_receipt" >"$bad_receipt"
  run_proof_expect 42 "$bad_receipt" "$output_dir"
  jq -e '
    .decision == "fail_closed"
    and any(.failures[]; .check == "receipt_schema")
  ' "${output_dir}/independent_verifier_report.json" >/dev/null \
    || record_failure "missing-signature selftest did not fail closed"
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
