#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_CONTRACT_PATH:-${root_dir}/docs/swarm_agent_mail_identity_reconciliation_contract_v1.json}"
truth_doc="${SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_TRUTH_DOC:-}"
producer="${root_dir}/scripts/swarm_agent_mail_identity_reconciler.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
drill="${root_dir}/scripts/e2e/swarm_agent_mail_identity_reconciliation_no_mock_drill.sh"

record_pass() {
  printf 'PASS agent-mail-identity-reconciliation-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL agent-mail-identity-reconciliation-truth %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_mail_identity_reconciliation_truth_gate.sh [check|selftest]

Validates the identity-reconciliation contract, composed drill wiring, and
proof-only mutation policy. If SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_TRUTH_DOC
is set, that document is also scanned for forbidden live-mutation claims.
EOF
}

assert_no_forbidden_live_claims() {
  local doc_path="$1"
  local forbidden_lines

  forbidden_lines="$(grep -Ein \
    'queries live Agent Mail|changes br state|mutates br state|acknowledges messages|sends Agent Mail|approves contacts|releases reservations|force releases reservations|reassigns beads|closes beads|mutates workers|runs cargo|runs Cargo|runs rch|runs RCH|repairs automatically|automatic acknowledgement|automatic contact approval|automatic reservation release|automatic bead reassignment|live Agent Mail querying|Cargo/RCH execution|worker mutation' \
    "$doc_path" \
    | grep -Eiv 'does not|never|no live|must not|not claim|reject|forbidden|false|proof-only|advisory-only|text only|manual repair recipe|Manual recipe only' || true)"
  if [[ -n "$forbidden_lines" ]]; then
    printf '%s\n' "$forbidden_lines" >&2
    record_failure "forbidden live mutation or automatic remediation claim"
    return 1
  fi
}

assert_no_executable_live_mutations() {
  local path="$1"
  local forbidden_lines

  forbidden_lines="$(grep -En \
    'mcp__mcp_agent_mail|br update|br close|cargo (test|check|clippy|bench|build)|rch exec|release_file_reservations|force_release_file_reservation|acknowledge_message|respond_contact|send_message' \
    "$path" \
    | grep -Ev 'grep -En|allowed_command_names_as_text|Manual recipe only|does not|never|must not|forbidden|proof-only|advisory-only|printf|Usage:' || true)"
  if [[ -n "$forbidden_lines" ]]; then
    printf '%s\n' "$forbidden_lines" >&2
    record_failure "script appears to execute forbidden live mutation"
    return 1
  fi
}

run_check() {
  test -f "$contract_path"
  test -f "$producer"
  test -f "$operator_status"
  test -f "$drill"

  bash -n "${BASH_SOURCE[0]}" "$producer" "$operator_status" "$drill"
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-agent-mail-identity-reconciliation-contract.v1"
    and .normalizer.planned_script == "scripts/swarm_agent_mail_identity_reconciler.sh"
    and .normalizer.planned_smoke_script == "scripts/e2e/swarm_agent_mail_identity_reconciler_smoke.sh"
    and .no_mock_drill.planned_script == "scripts/e2e/swarm_agent_mail_identity_reconciliation_no_mock_drill.sh"
    and (.no_mock_drill.composes | index("scripts/swarm_agent_mail_identity_reconciler.sh") != null)
    and (.no_mock_drill.composes | index("scripts/swarm_operator_status_report.sh") != null)
    and (.no_mock_drill.composes | index("scripts/e2e/swarm_agent_mail_identity_reconciliation_truth_gate.sh") != null)
    and (.no_mock_drill.required_cases | index("message_recipient_row_drift") != null)
    and (.no_mock_drill.required_cases | index("stale_contact_link") != null)
    and (.no_mock_drill.required_cases | index("missing_active_profile") != null)
    and (.no_mock_drill.required_cases | index("blocked_contact_policy") != null)
    and (.no_mock_drill.required_cases | index("contradictory_active_reservation") != null)
    and (.no_mock_drill.required_cases | index("healthy_no_drift") != null)
    and .truth_gate.planned_script == "scripts/e2e/swarm_agent_mail_identity_reconciliation_truth_gate.sh"
    and (.truth_gate.forbidden_live_claim_patterns | index("queries live Agent Mail") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("acknowledges messages") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("approves contacts") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("releases reservations") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("reassigns beads") != null)
    and (.mutation_policy.fixture_fed_only == true)
    and (.mutation_policy.proof_only == true)
    and (.mutation_policy.advisory_only == true)
    and (.mutation_policy.queries_live_agent_mail == false)
    and (.mutation_policy.acknowledges_messages == false)
    and (.mutation_policy.approves_contacts == false)
    and (.mutation_policy.releases_reservations == false)
    and (.mutation_policy.reassigns_beads == false)
    and (.mutation_policy.runs_cargo == false)
    and (.mutation_policy.runs_rch == false)
    and (.mutation_policy.mutates_remote_workers == false)
  ' "$contract_path" >/dev/null

  grep -Fq 'scripts/swarm_agent_mail_identity_reconciler.sh' "$drill"
  grep -Fq 'scripts/swarm_operator_status_report.sh' "$drill"
  grep -Fq 'scripts/e2e/swarm_agent_mail_identity_reconciliation_truth_gate.sh' "$drill"

  assert_no_executable_live_mutations "$producer"
  assert_no_executable_live_mutations "$drill"
  if [[ -n "$truth_doc" ]]; then
    test -f "$truth_doc"
    assert_no_forbidden_live_claims "$truth_doc"
  fi
  record_pass "contract drill and mutation policy"
}

run_selftest() {
  local tmp_root bad_live_doc bad_mutation_doc bad_contract

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/franken-engine-agent-mail-identity-truth.XXXXXX")"

  bad_live_doc="${tmp_root}/bad-live.md"
  printf 'The drill queries live Agent Mail and changes br state during replay.\n' >"$bad_live_doc"
  if SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_TRUTH_DOC="$bad_live_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "live Agent Mail and br mutation wording should fail"
    return 1
  fi
  record_pass "live Agent Mail and br mutation rejection"

  bad_mutation_doc="${tmp_root}/bad-mutation.md"
  printf 'The drill acknowledges messages, approves contacts, releases reservations, reassigns beads, runs Cargo, runs RCH, mutates workers, and repairs automatically.\n' >"$bad_mutation_doc"
  if SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_TRUTH_DOC="$bad_mutation_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "automatic remediation wording should fail"
    return 1
  fi
  record_pass "automatic remediation rejection"

  bad_contract="${tmp_root}/bad-contract.json"
  jq '.mutation_policy.acknowledges_messages = true' "$contract_path" >"$bad_contract"
  if SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "unsafe mutation policy should fail"
    return 1
  fi
  record_pass "unsafe mutation policy rejection"

  printf 'agent_mail_identity_reconciliation_truth_gate_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
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
