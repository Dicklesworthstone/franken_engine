#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
proof_script="${root_dir}/scripts/idea_wizard_xiii_quarantine_mesh_convergence_proof.sh"
contract_json="${root_dir}/docs/idea_wizard_xiii_quarantine_mesh_convergence_proof_v1.json"
docs_path="${root_dir}/docs/IDEA_WIZARD_XIII_QUARANTINE_MESH_CONVERGENCE_PROOF.md"
sample_log="${root_dir}/examples/07_quarantine_mesh/sample_propagation_log.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-xiii-quarantine-mesh-convergence-proof %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-xiii-quarantine-mesh-convergence-proof %s\n' "$1" >&2
  exit 1
}

run_proof_expect() {
  local expected_exit="$1"
  local propagation_log="$2"
  local output_dir="$3"
  local status

  set +e
  "$proof_script" \
    --propagation-log-json "$propagation_log" \
    --skip-live-refresh \
    --source-revision "smoke-quarantine-mesh-proof" \
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
  jq empty "$contract_json" "$sample_log"
  grep -Fq "FE-CLAIM-005" "$docs_path"
  grep -Fq "de_escalation_supported" "$contract_json"

  run_proof_expect 0 "$sample_log" "$output_dir"
  jq -e '
    .decision == "pass"
    and .claim_id == "FE-CLAIM-005"
    and .promotion_subset == "live_quarantine_mesh_bounded_convergence_only"
    and .peer_count == 3
    and (.attempted_targets | length) == 3
    and (.failed_targets | length) == 0
    and .permanent_ratchet == true
    and .de_escalation_supported == false
    and all(.checks[]; .passed == true)
  ' "${output_dir}/live_quarantine_mesh_convergence_report.json" >/dev/null \
    || record_failure "proof report mismatch"
  jq -e '
    .decision == "pass"
    and .replay_verifier_verdict == "pass"
    and all(.checks[]; .passed == true)
  ' "${output_dir}/replay_verifier_report.json" >/dev/null \
    || record_failure "replay verifier mismatch"
  jq -e '.decision == "degraded" and .green == false and (.failed_targets | length) == 1' "${output_dir}/partial_failure_degraded_fixture.json" >/dev/null \
    || record_failure "partial failure fixture did not remain degraded"
  jq -e '.decision == "degraded" and .green == false and (.failed_targets | length) == (.attempted_targets | length)' "${output_dir}/total_failure_degraded_fixture.json" >/dev/null \
    || record_failure "total failure fixture did not remain degraded"
  jq -s 'length >= 6 and all(.[]; has("event") and has("status"))' "${output_dir}/events.jsonl" >/dev/null \
    || record_failure "events log mismatch"
  grep -Fq "permanent ratchet" "${output_dir}/report.md" \
    || record_failure "human report lacks permanent ratchet text"

  git -C "$root_dir" diff --check -- \
    "$docs_path" \
    "$contract_json" \
    "$proof_script" \
    "${BASH_SOURCE[0]}"
  record_pass "check"
}

run_selftest() {
  local tmpdir bad_log output_dir
  tmpdir="$(mktemp -d)"
  bad_log="${tmpdir}/bad_quarantine_mesh_log.json"
  output_dir="${tmpdir}/fail"

  jq '.instances[1].resolved_action = "allow" | .instances[1].target_revoked = false' "$sample_log" >"$bad_log"
  run_proof_expect 42 "$bad_log" "$output_dir"
  jq -e '
    .decision == "fail_closed"
    and any(.failures[]; .check == "failed_targets")
  ' "${output_dir}/live_quarantine_mesh_convergence_report.json" >/dev/null \
    || record_failure "tampered live log did not fail closed"
  jq -e '
    .decision == "fail_closed"
    and any(.failures[]; .check == "main_live_quarantine_mesh_report")
  ' "${output_dir}/replay_verifier_report.json" >/dev/null \
    || record_failure "replay verifier did not fail closed"
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
