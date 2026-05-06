#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_LIFECYCLE_DRILL.md"
contract_path="${root_dir}/docs/swarm_execution_queue_policy_adoption_lifecycle_drill_contract_v1.json"
drill_path="${root_dir}/scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-policy-adoption-lifecycle-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-policy-adoption-lifecycle-truth-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_runbook_truth_gate.sh [check]

Validates that the SWARM-CTRL-XV lifecycle runbook and contract name the real
producer scripts and keep advisory-only/non-mutation boundaries truthful.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatically adopts|automatic adoption is allowed|automatically promotes|automatic promotion is allowed|automatically expires|automatically supersedes|applies retuning automatically|changes active queue automatically|retirement has executed|supersession has executed|local fallback proof is acceptable|does not reject local fallback proof' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe lifecycle automation or local-fallback wording"
  fi
}

run_check() {
  [[ -f "$docs_path" ]] || record_failure "missing docs"
  [[ -f "$contract_path" ]] || record_failure "missing contract"
  [[ -f "$drill_path" ]] || record_failure "missing drill script"
  jq empty "$contract_path" >/dev/null
  bash -n "$drill_path"

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-policy-adoption-lifecycle-drill-contract.v1"
    and .bead_id == "bd-k6ng4"
    and .parent_bead_id == "bd-6qnx9"
    and (.depends_on | index("bd-adgrb") != null)
    and (.depends_on | index("bd-mj81s") != null)
    and (.depends_on | index("bd-48ooe") != null)
    and (.depends_on | index("bd-jtw90") != null)
    and (.real_producers_required | index("scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh") != null)
    and (.real_producers_required | index("scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh") != null)
    and (.real_producers_required | index("scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh") != null)
    and (.real_producers_required | index("scripts/swarm_operator_status_report.sh") != null)
    and .mutation_policy.no_mock_e2e_only == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.retirement_executed == false
    and .mutation_policy.supersession_executed == false
    and (.truth_gate_rules | index("reject local fallback proof evidence") != null)
  ' "$contract_path" >/dev/null || record_failure "contract shape mismatch"

  grep -Fq "scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh" "$docs_path" || record_failure "docs missing adoption writer"
  grep -Fq "scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh" "$docs_path" || record_failure "docs missing sustained scorer"
  grep -Fq "scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh" "$docs_path" || record_failure "docs missing expiry planner"
  grep -Fq "scripts/swarm_operator_status_report.sh" "$docs_path" || record_failure "docs missing operator status report"
  grep -Fq "never changes active queue settings" "$docs_path" || record_failure "docs missing active queue non-mutation wording"
  grep -Fq "never applies live retuning" "$docs_path" || record_failure "docs missing live retuning non-mutation wording"
  grep -Fq "reject local fallback proof evidence" "$docs_path" || record_failure "docs missing local fallback rejection wording"
  grep -Fq "without mocks or replacement harnesses" "$docs_path" || record_failure "docs missing no-mock wording"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "runbook truth validates"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
