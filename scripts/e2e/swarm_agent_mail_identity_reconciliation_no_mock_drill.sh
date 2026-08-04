#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-agent-mail-identity-no-mock-drill}"
run_id="${SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

producer="${root_dir}/scripts/swarm_agent_mail_identity_reconciler.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_agent_mail_identity_reconciliation_truth_gate.sh"
contract_path="${root_dir}/docs/swarm_agent_mail_identity_reconciliation_contract_v1.json"
events_path=""
commands_path=""
report_md=""
receipt_json=""
case_rows_jsonl=""
failures=0

cases=(
  healthy_no_drift
  message_recipient_row_drift
  stale_contact_link
  missing_active_profile
  blocked_contact_policy
  contradictory_active_reservation
  unparsable_ack_error
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_mail_identity_reconciliation_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Composes the real identity reconciler, operator-status identity-drift surface,
and identity truth gate against deterministic fixtures. The drill is fixture-fed,
proof-only, and advisory-only: it does not query live Agent Mail, mutate br
state, acknowledge messages, approve contacts, send Agent Mail, release
reservations, run Cargo/RCH, mutate workers, or repair beads automatically.

Options:
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

record_pass() {
  printf 'PASS agent-mail-identity-reconciliation-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL agent-mail-identity-reconciliation-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_md="${run_dir}/report.md"
  receipt_json="${run_dir}/swarm_agent_mail_identity_reconciliation_no_mock_drill_receipt.json"
  case_rows_jsonl="${run_dir}/case_rows.jsonl"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
  : >"$case_rows_jsonl"
}

exit_code_is_expected() {
  local actual="$1"
  local expected_csv="$2"
  local expected

  IFS=',' read -r -a expected_list <<<"$expected_csv"
  for expected in "${expected_list[@]}"; do
    if [[ "$actual" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-agent-mail-identity-reconciliation-no-mock-drill.event.v1" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{schema_version:$schema_version,event_name:"swarm_agent_mail_identity_reconciliation_no_mock_drill.step",step_id:$step_id,decision:$decision,exit_code:$exit_code,artifact_paths:{stdout_log:$stdout_path,stderr_log:$stderr_path}}' >>"$events_path"
}

run_step() {
  local step="$1"
  local expected_codes="$2"
  shift 2
  local step_dir="${run_dir}/steps/${step}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code decision

  mkdir -p "$step_dir"
  printf '%q' "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"

  set +e
  (cd "$root_dir" && "$@") >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e

  if exit_code_is_expected "$exit_code" "$expected_codes"; then
    decision="pass"
  else
    decision="fail"
  fi
  write_event "$step" "$decision" "$exit_code" "$stdout_path" "$stderr_path"
  if [[ "$decision" != "pass" ]]; then
    printf 'step %s exited %s, expected %s\nstdout=%s\nstderr=%s\n' "$step" "$exit_code" "$expected_codes" "$stdout_path" "$stderr_path" >&2
    return 1
  fi
}

write_common_fixtures() {
  local dir="$1"

  mkdir -p "$dir"
  jq -n '{agents:[{name:"EmeraldPine",last_active_ts:"2026-06-18T00:00:00Z"},{name:"MistyFox",last_active_ts:"2026-06-18T00:00:00Z"}]}' >"${dir}/profiles.json"
  jq -n '{contacts:[{from_agent:"EmeraldPine",to_agent:"MistyFox",status:"accepted"}]}' >"${dir}/contacts.json"
  jq -n '{messages:[{id:17897,thread_id:"bd-lh0re.5",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true,ack_ts:"2026-06-18T00:01:00Z"}],ack_attempts:[]}' >"${dir}/messages.json"
  jq -n '{reservations:[{id:1,path_pattern:"scripts/e2e/swarm_agent_mail_identity_reconciliation_no_mock_drill.sh",agent_name:"EmeraldPine",bead_id:"bd-lh0re.5",exclusive:true}]}' >"${dir}/reservations.json"
  jq -n '{id:"bd-lh0re.5",status:"in_progress",assignee:"EmeraldPine"}' >"${dir}/br_issue.json"
  jq -n '{diagnostics:[]}' >"${dir}/sla.json"
  jq -n '{anomalies:[]}' >"${dir}/causal.json"
}

rewrite_case_fixtures() {
  local case_id="$1"
  local fixture_dir="$2"

  case "$case_id" in
    healthy_no_drift)
      ;;
    message_recipient_row_drift)
      jq -n '{messages:[{id:17897,thread_id:"bd-lh0re.5",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:17897,thread_id:"bd-lh0re.5",agent_name:"EmeraldPine",success:false,error:"MessageRecipient not found: 739:17897"}]}' >"${fixture_dir}/messages.json"
      ;;
    stale_contact_link)
      jq -n '{contacts:[]}' >"${fixture_dir}/contacts.json"
      jq -n '{messages:[{id:17898,thread_id:"bd-lh0re.5",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:17898,thread_id:"bd-lh0re.5",agent_name:"EmeraldPine",success:false,error:"AgentLink not found: EmeraldPine:MistyFox"}]}' >"${fixture_dir}/messages.json"
      ;;
    missing_active_profile)
      jq -n '{agents:[]}' >"${fixture_dir}/profiles.json"
      jq -n '{messages:[{id:17899,thread_id:"bd-lh0re.5",from:"MistyFox",to_agent:"UnknownAgent",ack_required:true}],ack_attempts:[{message_id:17899,thread_id:"bd-lh0re.5",agent_name:"UnknownAgent",success:false,error:"MessageRecipient not found: 740:17899"}]}' >"${fixture_dir}/messages.json"
      ;;
    blocked_contact_policy)
      jq -n '{messages:[{id:17900,thread_id:"bd-lh0re.5",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:17900,thread_id:"bd-lh0re.5",agent_name:"EmeraldPine",success:false,error:"contact policy blocked recipient"}]}' >"${fixture_dir}/messages.json"
      ;;
    contradictory_active_reservation)
      jq -n '{reservations:[{id:991,path_pattern:".beads/issues.jsonl",agent_name:"MistyFox",bead_id:"bd-lh0re.5",exclusive:true}]}' >"${fixture_dir}/reservations.json"
      ;;
    unparsable_ack_error)
      jq -n '{messages:[{id:17901,thread_id:"bd-lh0re.5",from:"MistyFox",to_agent:"EmeraldPine",ack_required:true}],ack_attempts:[{message_id:17901,thread_id:"bd-lh0re.5",agent_name:"EmeraldPine",success:false,error:"database said no"}]}' >"${fixture_dir}/messages.json"
      ;;
    *)
      record_failure "unknown fixture case ${case_id}"
      return 1
      ;;
  esac
}

expected_exit() {
  case "$1" in
    healthy_no_drift) printf '0' ;;
    message_recipient_row_drift|stale_contact_link|missing_active_profile|blocked_contact_policy|contradictory_active_reservation) printf '75' ;;
    unparsable_ack_error) printf '42' ;;
    *) printf '1' ;;
  esac
}

expected_decision() {
  case "$1" in
    healthy_no_drift) printf 'pass' ;;
    unparsable_ack_error) printf 'fail_closed' ;;
    *) printf 'blocked' ;;
  esac
}

expected_readiness() {
  case "$1" in
    healthy_no_drift) printf 'healthy' ;;
    unparsable_ack_error) printf 'fail_closed' ;;
    *) printf 'blocked' ;;
  esac
}

expected_anomaly() {
  case "$1" in
    message_recipient_row_drift) printf 'stale_message_recipient_row' ;;
    stale_contact_link) printf 'stale_contact_link' ;;
    missing_active_profile) printf 'missing_agent_profile' ;;
    blocked_contact_policy) printf 'blocked_contact_policy' ;;
    contradictory_active_reservation) printf 'contradictory_active_reservation' ;;
    unparsable_ack_error) printf 'unparsable_ack_error' ;;
    *) printf '' ;;
  esac
}

run_reconciler_case() {
  local case_id="$1"
  local fixture_dir="$2"
  local output_dir="$3"

  run_step "reconciler-${case_id}" "$(expected_exit "$case_id")" \
    bash "$producer" \
      --agent-name EmeraldPine \
      --bead-id bd-lh0re.5 \
      --source-revision "fixture-${case_id}" \
      --agent-mail-profiles-json "${fixture_dir}/profiles.json" \
      --agent-mail-contacts-json "${fixture_dir}/contacts.json" \
      --agent-mail-messages-json "${fixture_dir}/messages.json" \
      --file-reservations-json "${fixture_dir}/reservations.json" \
      --br-issue-json "${fixture_dir}/br_issue.json" \
      --agent-mail-sla-panel-json "${fixture_dir}/sla.json" \
      --causal-trace-anomalies-json "${fixture_dir}/causal.json" \
      --output-dir "$output_dir"
}

run_operator_status_case() {
  local case_id="$1"
  local reconciler_dir="$2"
  local output_dir="$3"

  run_step "operator-status-${case_id}" "0" \
    bash "$operator_status" \
      --bead-id bd-lh0re.5 \
      --source-revision "fixture-${case_id}" \
      --output-dir "$output_dir" \
      --agent-mail-status ok \
      --rch-status ok \
      --proof-index-status ok \
      --identity-reconciliation-receipt-json "${reconciler_dir}/swarm_agent_mail_identity_reconciliation_receipt.json"
}

assert_case_outputs() {
  local case_id="$1"
  local reconciler_dir="$2"
  local operator_dir="$3"
  local expected expected_ready expected_class actual_ready

  expected="$(expected_decision "$case_id")"
  expected_ready="$(expected_readiness "$case_id")"
  expected_class="$(expected_anomaly "$case_id")"

  jq -e --arg expected "$expected" '.decision == $expected' "${reconciler_dir}/swarm_agent_mail_identity_reconciliation_receipt.json" >/dev/null
  jq -e --arg expected "$expected" '.predictive_dashboard.agent_mail_identity_drift.decision == $expected' "${operator_dir}/status.json" >/dev/null
  actual_ready="$(jq -r '.predictive_dashboard.agent_mail_identity_drift.readiness' "${operator_dir}/status.json")"
  if [[ "$actual_ready" != "$expected_ready" ]]; then
    record_failure "${case_id} readiness ${actual_ready} did not match ${expected_ready}"
    return 1
  fi

  if [[ -n "$expected_class" ]]; then
    jq -e --arg class "$expected_class" '.anomaly_classes | index($class) != null' "${reconciler_dir}/swarm_agent_mail_identity_reconciliation_receipt.json" >/dev/null
    jq -e --arg class "$expected_class" '.predictive_dashboard.agent_mail_identity_drift.anomaly_classes | index($class) != null' "${operator_dir}/status.json" >/dev/null
  fi

  jq -e '
    .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.queries_live_agent_mail == false
    and .mutation_policy.acknowledges_messages == false
    and .mutation_policy.approves_contacts == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "${reconciler_dir}/swarm_agent_mail_identity_reconciliation_receipt.json" >/dev/null
  jq -e '
    .predictive_dashboard.agent_mail_identity_drift.mutation_policy.fixture_fed_only == true
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.proof_only == true
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.advisory_only == true
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.queries_live_agent_mail == false
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.acknowledges_messages == false
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.approves_contacts == false
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.releases_reservations == false
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.runs_cargo == false
    and .predictive_dashboard.agent_mail_identity_drift.mutation_policy.runs_rch == false
  ' "${operator_dir}/status.json" >/dev/null

  jq -nc \
    --arg case_id "$case_id" \
    --arg expected_decision "$expected" \
    --arg readiness "$actual_ready" \
    --arg receipt_json "${reconciler_dir}/swarm_agent_mail_identity_reconciliation_receipt.json" \
    --arg status_json "${operator_dir}/status.json" \
    --arg status_report_md "${operator_dir}/report.md" \
    '{case_id:$case_id,expected_decision:$expected_decision,operator_readiness:$readiness,artifact_paths:{identity_receipt_json:$receipt_json,operator_status_json:$status_json,operator_report_md:$status_report_md}}' >>"$case_rows_jsonl"
}

run_case() {
  local case_id="$1"
  local case_dir="${run_dir}/cases/${case_id}"
  local fixture_dir="${case_dir}/fixtures"
  local reconciler_dir="${case_dir}/reconciler"
  local operator_dir="${case_dir}/operator-status"

  write_common_fixtures "$fixture_dir"
  rewrite_case_fixtures "$case_id" "$fixture_dir"
  run_reconciler_case "$case_id" "$fixture_dir" "$reconciler_dir"
  run_operator_status_case "$case_id" "$reconciler_dir" "$operator_dir"
  assert_case_outputs "$case_id" "$reconciler_dir" "$operator_dir"
}

write_receipt() {
  # shellcheck disable=SC2094
  jq -s \
    --arg schema_version "franken-engine.swarm-agent-mail-identity-reconciliation-no-mock-drill-receipt.v1" \
    --arg receipt_json "$receipt_json" \
    --arg events_jsonl "$events_path" \
    --arg commands_txt "$commands_path" \
    --arg report_md "$report_md" \
    '{
      schema_version:$schema_version,
      decision:(if length == 7 and all(.[]; .expected_decision == "pass" or .expected_decision == "blocked" or .expected_decision == "fail_closed") then "pass" else "fail_closed" end),
      drill_id:"swarm_agent_mail_identity_reconciliation_no_mock_drill",
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        queries_live_agent_mail:false,
        mutates_agent_mail:false,
        acknowledges_messages:false,
        sends_agent_mail:false,
        approves_contacts:false,
        mutates_br:false,
        reassigns_beads:false,
        closes_beads:false,
        releases_reservations:false,
        force_releases_reservations:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        repairs_automatically:false
      },
      case_count:length,
      cases:.,
      artifact_paths:{
        drill_receipt_json:$receipt_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        report_md:$report_md
      }
    }' "$case_rows_jsonl" >"$receipt_json"
}

write_report() {
  {
    printf '# Agent Mail Identity Reconciliation No-Mock Drill\n\n'
    printf 'This drill is fixture-fed, proof-only, and advisory-only. It emits manual repair recipe evidence only; human or agent operators perform actual remediation outside this artifact.\n\n'
    # shellcheck disable=SC2016
    printf 'It does not query live Agent Mail, does not mutate `br` state, does not acknowledge messages, does not approve contacts, does not send Agent Mail, does not release reservations, does not run Cargo or RCH, does not mutate workers, and does not repair beads automatically.\n\n'
    printf -- "- Receipt: \`%s\`\n" "$receipt_json"
    printf -- "- Events: \`%s\`\n" "$events_path"
    printf -- "- Commands: \`%s\`\n" "$commands_path"
    printf -- "- Cases: \`%s\`\n\n" "$(jq '.case_count' "$receipt_json")"
    jq -r '.cases[] | "- `" + .case_id + "`: decision=`" + .expected_decision + "` readiness=`" + .operator_readiness + "`"' "$receipt_json"
  } >"$report_md"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}" "$producer" "$operator_status" "$truth_gate"
  jq empty "$contract_path" >/dev/null
  jq -e '
    .no_mock_drill.planned_script == "scripts/e2e/swarm_agent_mail_identity_reconciliation_no_mock_drill.sh"
    and (.no_mock_drill.composes | index("scripts/swarm_agent_mail_identity_reconciler.sh") != null)
    and (.no_mock_drill.composes | index("scripts/swarm_operator_status_report.sh") != null)
    and (.no_mock_drill.composes | index("scripts/e2e/swarm_agent_mail_identity_reconciliation_truth_gate.sh") != null)
    and (.no_mock_drill.required_cases | index("contradictory_active_reservation") != null)
    and (.truth_gate.planned_script == "scripts/e2e/swarm_agent_mail_identity_reconciliation_truth_gate.sh")
  ' "$contract_path" >/dev/null
  grep -Fq 'scripts/swarm_agent_mail_identity_reconciler.sh' "$truth_gate"
  grep -Fq 'scripts/swarm_operator_status_report.sh' "$truth_gate"
  record_pass "syntax and contract"
}

run_drill() {
  ensure_run_dir
  run_step "truth-gate-preflight" "0" bash "$truth_gate" check
  for case_id in "${cases[@]}"; do
    run_case "$case_id"
  done
  write_receipt
  write_report
  run_step "truth-gate-report" "0" env SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_TRUTH_DOC="$report_md" bash "$truth_gate" check
  jq -e '.decision == "pass" and .case_count == 7' "$receipt_json" >/dev/null
  record_pass "composed identity reconciliation surfaces"
  printf 'agent_mail_identity_reconciliation_no_mock_drill_receipt=%s\n' "$receipt_json"
}

run_selftest() {
  local tmp_root

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/franken-engine-agent-mail-identity-drill.XXXXXX")"
  SWARM_AGENT_MAIL_IDENTITY_RECONCILIATION_NO_MOCK_DRILL_RUN_DIR="${tmp_root}/selftest-run" bash "${BASH_SOURCE[0]}" run >/dev/null
  jq -e '.case_count == 7 and .decision == "pass"' "${tmp_root}/selftest-run/swarm_agent_mail_identity_reconciliation_no_mock_drill_receipt.json" >/dev/null
  jq -e 'any(.cases[]; .case_id == "missing_active_profile" and .expected_decision == "blocked")' "${tmp_root}/selftest-run/swarm_agent_mail_identity_reconciliation_no_mock_drill_receipt.json" >/dev/null
  jq -e 'any(.cases[]; .case_id == "contradictory_active_reservation" and .expected_decision == "blocked")' "${tmp_root}/selftest-run/swarm_agent_mail_identity_reconciliation_no_mock_drill_receipt.json" >/dev/null
  record_pass "selftest composed drill"
  printf 'agent_mail_identity_reconciliation_no_mock_drill_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_drill
    ;;
  selftest)
    run_selftest
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
