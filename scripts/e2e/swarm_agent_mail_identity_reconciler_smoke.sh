#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
producer="${root_dir}/scripts/swarm_agent_mail_identity_reconciler.sh"
contract="${root_dir}/docs/swarm_agent_mail_identity_reconciliation_contract_v1.json"
mode="${1:-check}"
artifact_root="${SWARM_AGENT_MAIL_IDENTITY_RECONCILER_SMOKE_ROOT:-${TMPDIR:-/tmp}/franken-engine-agent-mail-identity-reconciler-smoke}"
run_id="${SWARM_AGENT_MAIL_IDENTITY_RECONCILER_SMOKE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_MAIL_IDENTITY_RECONCILER_SMOKE_RUN_DIR:-${artifact_root}/${run_id}}"
failures=0

cases=(
  healthy_no_drift
  message_recipient_row_drift
  stale_contact_link
  missing_active_profile
  blocked_contact_policy
  contradictory_active_reservation
  unparsable_error
)

record_pass() {
  printf 'PASS agent-mail-identity-reconciler %s\n' "$1"
}

record_failure() {
  printf 'FAIL agent-mail-identity-reconciler %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_mail_identity_reconciler_smoke.sh [check]

Runs shell/JQ smoke fixtures for the fixture-fed Agent Mail identity reconciler.
The smoke writes temporary fixtures and artifacts but does not remove files,
query live Agent Mail, mutate br, acknowledge messages, approve contacts,
release reservations, run cargo/rch, or mutate workers.
EOF
}

write_common_fixtures() {
  local dir="$1"
  mkdir -p "$dir"
  jq -n '{agents:[{name:"EmeraldPine",last_active_ts:"2026-06-18T00:00:00Z"},{name:"MistyFox",last_active_ts:"2026-06-18T00:00:00Z"}]}' >"${dir}/profiles.json"
  jq -n '{contacts:[{from_agent:"EmeraldPine",to_agent:"MistyFox",status:"accepted"}]}' >"${dir}/contacts.json"
  jq -n '{messages:[{id:17897,thread_id:"bd-test",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true,ack_ts:"2026-06-18T00:01:00Z"}],ack_attempts:[]}' >"${dir}/messages.json"
  jq -n '{reservations:[{id:1,path_pattern:"docs/TRACE.md",agent_name:"EmeraldPine",bead_id:"bd-test",exclusive:true}]}' >"${dir}/reservations.json"
  jq -n '{id:"bd-test",status:"in_progress",assignee:"EmeraldPine"}' >"${dir}/br_issue.json"
  jq -n '{diagnostics:[]}' >"${dir}/sla.json"
  jq -n '{anomalies:[]}' >"${dir}/causal.json"
}

rewrite_case() {
  local case_id="$1"
  local dir="$2"
  case "$case_id" in
    healthy_no_drift)
      ;;
    message_recipient_row_drift)
      jq -n '{messages:[{id:17897,thread_id:"bd-test",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:17897,thread_id:"bd-test",agent_name:"EmeraldPine",success:false,error:"MessageRecipient not found: 739:17897"}]}' >"${dir}/messages.json"
      ;;
    stale_contact_link)
      jq -n '{contacts:[]}' >"${dir}/contacts.json"
      jq -n '{messages:[{id:2,thread_id:"bd-test",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:2,thread_id:"bd-test",agent_name:"EmeraldPine",success:false,error:"AgentLink not found: EmeraldPine:MistyFox"}]}' >"${dir}/messages.json"
      ;;
    missing_active_profile)
      jq -n '{agents:[]}' >"${dir}/profiles.json"
      jq -n '{messages:[{id:3,thread_id:"bd-test",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:3,thread_id:"bd-test",agent_name:"UnknownAgent",success:false,error:"MessageRecipient not found: 740:3"}]}' >"${dir}/messages.json"
      ;;
    blocked_contact_policy)
      jq -n '{messages:[{id:4,thread_id:"bd-test",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:4,thread_id:"bd-test",agent_name:"EmeraldPine",success:false,error:"contact policy blocked recipient"}]}' >"${dir}/messages.json"
      ;;
    contradictory_active_reservation)
      jq -n '{reservations:[{id:991,path_pattern:".beads/issues.jsonl",agent_name:"MistyFox",bead_id:"bd-test",exclusive:true}]}' >"${dir}/reservations.json"
      ;;
    unparsable_error)
      jq -n '{messages:[{id:5,thread_id:"bd-test",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:5,thread_id:"bd-test",agent_name:"EmeraldPine",success:false,error:"database said no"}]}' >"${dir}/messages.json"
      ;;
    *)
      record_failure "unknown case ${case_id}"
      return 1
      ;;
  esac
}

expected_exit() {
  case "$1" in
    healthy_no_drift) printf '0' ;;
    message_recipient_row_drift|stale_contact_link|missing_active_profile|blocked_contact_policy|contradictory_active_reservation) printf '75' ;;
    unparsable_error) printf '42' ;;
    *) printf '1' ;;
  esac
}

expected_decision() {
  case "$1" in
    healthy_no_drift) printf 'pass' ;;
    message_recipient_row_drift|stale_contact_link|missing_active_profile|blocked_contact_policy|contradictory_active_reservation) printf 'blocked' ;;
    unparsable_error) printf 'fail_closed' ;;
    *) printf 'unknown' ;;
  esac
}

expected_anomaly() {
  case "$1" in
    message_recipient_row_drift) printf 'stale_message_recipient_row' ;;
    stale_contact_link) printf 'stale_contact_link' ;;
    missing_active_profile) printf 'missing_agent_profile' ;;
    blocked_contact_policy) printf 'blocked_contact_policy' ;;
    contradictory_active_reservation) printf 'contradictory_active_reservation' ;;
    unparsable_error) printf 'unparsable_ack_error' ;;
    *) printf '' ;;
  esac
}

assert_no_forbidden_live_claims() {
  jq -e '
    (.truth_gate.forbidden_live_claim_patterns | index("queries live Agent Mail") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("acknowledges messages") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("releases reservations") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("runs cargo") != null)
    and (.truth_gate.forbidden_live_claim_patterns | index("runs rch") != null)
    and (.mutation_policy.queries_live_agent_mail == false)
    and (.mutation_policy.acknowledges_messages == false)
    and (.mutation_policy.releases_reservations == false)
    and (.mutation_policy.runs_cargo == false)
    and (.mutation_policy.runs_rch == false)
  ' "$contract" >/dev/null
  if grep -Eiq 'mcp__mcp_agent_mail|br update|br close|cargo test|cargo check|cargo clippy|rch exec' "$producer"; then
    record_failure "producer must not execute live Agent Mail, br, cargo, or rch mutations"
    return 1
  fi
}

run_case() {
  local case_id="$1"
  local fixture_dir="${run_dir}/fixtures/${case_id}"
  local out_dir="${run_dir}/out/${case_id}"
  local expected_code expected_status expected_class receipt exit_code

  write_common_fixtures "$fixture_dir"
  rewrite_case "$case_id" "$fixture_dir"
  mkdir -p "$out_dir"
  expected_code="$(expected_exit "$case_id")"
  expected_status="$(expected_decision "$case_id")"
  expected_class="$(expected_anomaly "$case_id")"

  set +e
  "$producer" \
    --agent-name EmeraldPine \
    --bead-id bd-test \
    --agent-mail-profiles-json "${fixture_dir}/profiles.json" \
    --agent-mail-contacts-json "${fixture_dir}/contacts.json" \
    --agent-mail-messages-json "${fixture_dir}/messages.json" \
    --file-reservations-json "${fixture_dir}/reservations.json" \
    --br-issue-json "${fixture_dir}/br_issue.json" \
    --agent-mail-sla-panel-json "${fixture_dir}/sla.json" \
    --causal-trace-anomalies-json "${fixture_dir}/causal.json" \
    --output-dir "$out_dir" >/dev/null
  exit_code=$?
  set -e

  if [[ "$exit_code" != "$expected_code" ]]; then
    record_failure "${case_id} exit ${exit_code}, expected ${expected_code}"
    return 1
  fi
  receipt="${out_dir}/swarm_agent_mail_identity_reconciliation_receipt.json"
  jq -e --arg decision "$expected_status" '.decision == $decision' "$receipt" >/dev/null
  if [[ -n "$expected_class" ]]; then
    jq -e --arg class "$expected_class" '.anomaly_classes | index($class) != null' "$receipt" >/dev/null
  fi
  jq -e '.mutation_policy.fixture_fed_only == true and .mutation_policy.queries_live_agent_mail == false and .mutation_policy.acknowledges_messages == false and .mutation_policy.releases_reservations == false' "$receipt" >/dev/null
  record_pass "$case_id"
}

run_check() {
  bash -n "$producer" "${BASH_SOURCE[0]}"
  jq empty "$contract"
  jq -e '.schema_version == "franken-engine.swarm-agent-mail-identity-reconciliation-contract.v1"
    and (.planned_fixture_cases | map(.fixture_id) | index("message_recipient_row_drift") != null)
    and (.mutation_policy.fixture_fed_only == true)
    and (.mutation_policy.queries_live_agent_mail == false)' "$contract" >/dev/null
  assert_no_forbidden_live_claims
  mkdir -p "$run_dir"
  for case_id in "${cases[@]}"; do
    run_case "$case_id"
  done
  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'agent_mail_identity_reconciler_smoke_artifacts=%s\n' "$run_dir"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help)
    usage
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    usage
    exit 64
    ;;
esac
