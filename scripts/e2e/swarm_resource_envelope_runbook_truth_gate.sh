#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_RESOURCE_ENVELOPE_RUNBOOK_PATH:-${root_dir}/docs/SWARM_RESOURCE_ENVELOPE.md}"
contract_path="${SWARM_RESOURCE_ENVELOPE_CONTRACT_PATH:-${root_dir}/docs/swarm_resource_envelope_contract_v1.json}"
drill_path="${SWARM_RESOURCE_ENVELOPE_DRILL_PATH:-${root_dir}/scripts/e2e/swarm_resource_envelope_no_mock_drill.sh}"

producer_scripts=(
  "scripts/swarm_resource_envelope_normalizer.sh"
  "scripts/swarm_fair_share_batch_planner.sh"
  "scripts/swarm_operator_status_report.sh"
  "scripts/e2e/swarm_resource_envelope_no_mock_drill.sh"
  "scripts/e2e/swarm_resource_envelope_runbook_truth_gate.sh"
)

required_artifacts=(
  "swarm_resource_envelope_receipt.json"
  "swarm_resource_envelope.json"
  "swarm_fair_share_batch_plan.json"
  "status.json"
  "commands.txt"
  "events.jsonl"
  "report.md"
)

# shellcheck disable=SC2016
required_truth_claims=(
  'fixture-fed, proof-only, and advisory-only'
  'Operator remediation remains manual or agent-executed outside this artifact'
  'does not query live services'
  'does not update, reopen, close, or reassign beads'
  'does not release file reservations'
  'does not send Agent Mail'
  'does not query live Agent Mail'
  'does not start RCH or Cargo commands'
  'does not change live queue policy'
  'does not mutate workers'
  'does not repair stalled builds automatically'
)

record_pass() {
  printf 'PASS swarm-resource-envelope-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-resource-envelope-runbook-truth %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_resource_envelope_runbook_truth_gate.sh [check|selftest]
EOF
}

assert_no_forbidden_live_claims() {
  local doc_path="$1"
  local forbidden_lines

  forbidden_lines="$(grep -Ein \
    'queries live services|queries live Agent Mail|changes br state|mutates br state|reassigns beads|releases reservations|sends Agent Mail|mutates workers|runs cargo|runs rch|starts cargo|starts rch|deletes target directories|repairs stalled builds|automatic remediation|automatic bead repair|automatic reservation release|live RCH execution|live Cargo execution|live queue policy|queue policy mutation|mutates live worker state' \
    "$doc_path" \
    | grep -Eiv 'does not|never|no live|must not|not claim|reject|forbidden|false|proof-only|advisory-only|outside this artifact|manual or agent-executed' || true)"
  if [[ -n "$forbidden_lines" ]]; then
    printf '%s\n' "$forbidden_lines" >&2
    record_failure "forbidden live mutation or automatic remediation claim"
    return 1
  fi
}

assert_runbook_truth() {
  local doc_path="$1"
  local producer artifact claim

  test -f "$doc_path"
  test -f "$contract_path"
  test -f "$drill_path"
  jq empty "$contract_path" >/dev/null

  for producer in "${producer_scripts[@]}"; do
    test -e "${root_dir}/${producer}"
    grep -Fq "$producer" "$doc_path"
    grep -Fq "$producer" "$contract_path"
  done

  for artifact in "${required_artifacts[@]}"; do
    grep -Fq "$artifact" "$doc_path"
    grep -Fq "$artifact" "$contract_path"
  done

  for claim in "${required_truth_claims[@]}"; do
    grep -Fq "$claim" "$doc_path"
  done

  grep -Fq 'scripts/swarm_resource_envelope_normalizer.sh' "$drill_path"
  grep -Fq 'scripts/swarm_fair_share_batch_planner.sh' "$drill_path"
  grep -Fq 'scripts/swarm_operator_status_report.sh' "$drill_path"

  jq -e '
    .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.queries_live_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.repairs_stalled_builds == false
    and .no_mock_drill.script == "scripts/e2e/swarm_resource_envelope_no_mock_drill.sh"
    and .no_mock_drill.truth_gate_script == "scripts/e2e/swarm_resource_envelope_runbook_truth_gate.sh"
  ' "$contract_path" >/dev/null

  assert_no_forbidden_live_claims "$doc_path"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}" "$drill_path"
  jq empty "$contract_path"
  assert_runbook_truth "$runbook_path"
  record_pass "syntax contract and runbook truth"
}

run_selftest() {
  local tmp_root bad_live_doc bad_cargo_doc missing_producer_doc missing_advisory_doc bad_auto_doc

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/franken-engine-resource-envelope-truth.XXXXXX")"

  bad_live_doc="${tmp_root}/bad-live.md"
  cp "$runbook_path" "$bad_live_doc"
  printf '\nThe drill queries live services, mutates br state, reassigns beads, releases reservations, sends Agent Mail, mutates workers, and changes live queue policy.\n' >>"$bad_live_doc"
  if SWARM_RESOURCE_ENVELOPE_RUNBOOK_PATH="$bad_live_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "live resource mutation wording should fail"
    return 1
  fi
  record_pass "live resource mutation rejection"

  bad_cargo_doc="${tmp_root}/bad-cargo.md"
  cp "$runbook_path" "$bad_cargo_doc"
  # rch-policy-waive: bare_cargo reason=Negative fixture must contain forbidden bare Cargo wording for truth-gate selftest
  printf '\nThe drill runs cargo test directly and starts rch execution while composing the receipt.\n' >>"$bad_cargo_doc"
  if SWARM_RESOURCE_ENVELOPE_RUNBOOK_PATH="$bad_cargo_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "bare Cargo or RCH wording should fail"
    return 1
  fi
  record_pass "bare Cargo and RCH wording rejection"

  bad_auto_doc="${tmp_root}/bad-auto.md"
  cp "$runbook_path" "$bad_auto_doc"
  printf '\nThe generated report performs automatic remediation and repairs stalled builds automatically.\n' >>"$bad_auto_doc"
  if SWARM_RESOURCE_ENVELOPE_RUNBOOK_PATH="$bad_auto_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "automatic remediation wording should fail"
    return 1
  fi
  record_pass "automatic remediation rejection"

  missing_producer_doc="${tmp_root}/missing-producer.md"
  grep -Fv 'scripts/swarm_fair_share_batch_planner.sh' "$runbook_path" >"$missing_producer_doc"
  if SWARM_RESOURCE_ENVELOPE_RUNBOOK_PATH="$missing_producer_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing producer reference should fail"
    return 1
  fi
  record_pass "missing producer reference rejection"

  missing_advisory_doc="${tmp_root}/missing-advisory.md"
  grep -Fv 'fixture-fed, proof-only, and advisory-only' "$runbook_path" >"$missing_advisory_doc"
  if SWARM_RESOURCE_ENVELOPE_RUNBOOK_PATH="$missing_advisory_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing advisory wording should fail"
    return 1
  fi
  record_pass "missing advisory wording rejection"

  printf 'swarm_resource_envelope_runbook_truth_gate_artifacts=%s\n' "$tmp_root"
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
