#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_AGENT_CAUSAL_TRACE_RUNBOOK_PATH:-${root_dir}/docs/SWARM_AGENT_CAUSAL_TRACE_SPINE.md}"
contract_path="${SWARM_AGENT_CAUSAL_TRACE_CONTRACT_PATH:-${root_dir}/docs/swarm_agent_causal_trace_spine_contract_v1.json}"
drill_path="${SWARM_AGENT_CAUSAL_TRACE_DRILL_PATH:-${root_dir}/scripts/e2e/swarm_agent_causal_trace_no_mock_drill.sh}"

producer_scripts=(
  "scripts/swarm_agent_causal_trace_normalizer.sh"
  "scripts/swarm_agent_causal_trace_graph.sh"
  "scripts/swarm_operator_status_report.sh"
  "scripts/e2e/swarm_agent_causal_trace_no_mock_drill.sh"
  "scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh"
)

required_artifacts=(
  "swarm_agent_causal_trace_receipt.json"
  "swarm_agent_causal_trace_graph.json"
  "swarm_agent_causal_trace_anomalies.json"
  "status.json"
  "commands.txt"
  "events.jsonl"
  "report.md"
)

# shellcheck disable=SC2016
required_truth_claims=(
  'fixture-fed, proof-only, and advisory-only'
  'human or agent operators perform actual remediation outside this artifact'
  'does not query live Agent Mail'
  'does not mutate `br` state'
  'does not release reservations'
  'does not send Agent Mail'
  'does not run Cargo or RCH'
  'does not mutate workers'
  'does not repair beads automatically'
)

record_pass() {
  printf 'PASS swarm-agent-causal-trace-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-agent-causal-trace-runbook-truth %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh [check|selftest]
EOF
}

assert_no_forbidden_live_claims() {
  local doc_path="$1"
  local forbidden_lines

  forbidden_lines="$(grep -Ein \
    'queries live Agent Mail|changes br state|mutates br state|releases reservations|sends Agent Mail|mutates workers|runs cargo|runs rch|repairs bead automatically|repairs beads automatically|automatic bead repair|automatic reservation release|live Agent Mail sends|live RCH execution|queue policy mutation|mutates live worker state' \
    "$doc_path" \
    | grep -Eiv 'does not|never|no live|must not|not claim|reject|forbidden|false|proof-only|advisory-only' || true)"
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

  grep -Fq 'scripts/swarm_agent_causal_trace_normalizer.sh' "$drill_path"
  grep -Fq 'scripts/swarm_agent_causal_trace_graph.sh' "$drill_path"
  grep -Fq 'scripts/swarm_operator_status_report.sh' "$drill_path"

  jq -e '
    .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.queries_live_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .no_mock_drill.script == "scripts/e2e/swarm_agent_causal_trace_no_mock_drill.sh"
    and .truth_gate.script == "scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh"
  ' "$contract_path" >/dev/null

  assert_no_forbidden_live_claims "$doc_path"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  jq empty "$contract_path"
  assert_runbook_truth "$runbook_path"
  record_pass "syntax contract and runbook truth"
}

run_selftest() {
  local tmp_root bad_live_doc bad_mutation_doc missing_producer_doc missing_advisory_doc

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/franken-engine-causal-trace-truth.XXXXXX")"

  bad_live_doc="${tmp_root}/bad-live.md"
  cp "$runbook_path" "$bad_live_doc"
  printf '\nThe drill queries live Agent Mail and changes br state during replay.\n' >>"$bad_live_doc"
  if SWARM_AGENT_CAUSAL_TRACE_RUNBOOK_PATH="$bad_live_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "live Agent Mail or br mutation wording should fail"
    return 1
  fi
  record_pass "live Agent Mail and br mutation rejection"

  bad_mutation_doc="${tmp_root}/bad-mutation.md"
  cp "$runbook_path" "$bad_mutation_doc"
  printf '\nThe drill releases reservations, sends Agent Mail, mutates workers, runs cargo, runs rch, and repairs beads automatically.\n' >>"$bad_mutation_doc"
  if SWARM_AGENT_CAUSAL_TRACE_RUNBOOK_PATH="$bad_mutation_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "automatic remediation wording should fail"
    return 1
  fi
  record_pass "automatic remediation rejection"

  missing_producer_doc="${tmp_root}/missing-producer.md"
  grep -Fv 'scripts/swarm_agent_causal_trace_graph.sh' "$runbook_path" >"$missing_producer_doc"
  if SWARM_AGENT_CAUSAL_TRACE_RUNBOOK_PATH="$missing_producer_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing producer reference should fail"
    return 1
  fi
  record_pass "missing producer reference rejection"

  missing_advisory_doc="${tmp_root}/missing-advisory.md"
  grep -Fv 'fixture-fed, proof-only, and advisory-only' "$runbook_path" >"$missing_advisory_doc"
  if SWARM_AGENT_CAUSAL_TRACE_RUNBOOK_PATH="$missing_advisory_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing advisory wording should fail"
    return 1
  fi
  record_pass "missing advisory wording rejection"

  printf 'swarm_agent_causal_trace_runbook_truth_gate_artifacts=%s\n' "$tmp_root"
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
