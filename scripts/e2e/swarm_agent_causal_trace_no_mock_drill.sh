#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_AGENT_CAUSAL_TRACE_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-agent-causal-trace-no-mock-drill}"
run_id="${SWARM_AGENT_CAUSAL_TRACE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_CAUSAL_TRACE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_agent_causal_trace_normalizer.sh"
graph="${root_dir}/scripts/swarm_agent_causal_trace_graph.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh"
docs_path="${root_dir}/docs/SWARM_AGENT_CAUSAL_TRACE_SPINE.md"
contract_path="${root_dir}/docs/swarm_agent_causal_trace_spine_contract_v1.json"
events_path=""
commands_path=""
report_md=""
receipt_json=""
case_rows_jsonl=""
failures=0

cases=(
  healthy_closeout
  missing_agent_mail_snapshot
  local_rch_fallback
  ownership_conflict
  closed_without_commit
  closed_without_validation
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_causal_trace_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Composes the real SWARM-CTRL-XVI causal trace producers into one deterministic
no-mock drill. The drill writes fixture snapshots and then invokes the real
normalizer, graph producer, and operator-status report. It does not query live
Agent Mail, mutate br state, release reservations, send messages, run cargo,
run rch, mutate workers, or repair beads.

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
  printf 'PASS swarm-agent-causal-trace-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-agent-causal-trace-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_md="${run_dir}/report.md"
  receipt_json="${run_dir}/swarm_agent_causal_trace_receipt.json"
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
    --arg schema_version "franken-engine.swarm-agent-causal-trace-no-mock-drill.event.v1" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{schema_version:$schema_version,event_name:"swarm_agent_causal_trace_no_mock_drill.step",step_id:$step_id,decision:$decision,exit_code:$exit_code,artifact_paths:{stdout_log:$stdout_path,stderr_log:$stderr_path}}' >>"$events_path"
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
  local status="${2:-closed}"

  mkdir -p "$dir"
  jq -n --arg status "$status" '[
    {
      id:"bd-trace",
      title:"Causal trace no-mock drill fixture",
      status:$status,
      priority:1,
      assignee:"AgentAlpha",
      updated_at:"2026-05-06T00:00:00Z",
      close_reason:"validation transcript, closeout mail, commit, and RCH proof linked"
    }
  ]' >"${dir}/br_issue.json"
  jq -n '[{id:"bd-next", title:"Next bead", status:"open", priority:1}]' >"${dir}/br_ready.json"
  jq -n '{dirty_count:0, db_newer:false, jsonl_newer:false}' >"${dir}/br_sync_status.json"
  jq -n '{plan:{tracks:[{track_id:"track-causal-trace",items:[{id:"bd-trace",status:"closed",priority:1}]}]}}' >"${dir}/bv_plan.json"
  jq -n '{agents:[{name:"AgentAlpha", last_active_ts:"2026-05-06T00:01:00Z", task_description:"causal trace closeout"}]}' >"${dir}/profiles.json"
  jq -n '{
    messages:[
      {id:1, thread_id:"bd-trace", from:"AgentAlpha", ack_required:true, ack_ts:"2026-05-06T00:02:00Z", subject:"Claimed bd-trace causal trace drill"},
      {id:2, thread_id:"bd-trace", from:"AgentAlpha", ack_required:false, subject:"Closeout bd-trace", body_md:"Closed bd-trace with validation transcript, RCH proof, commit abc1234, and br close reason."}
    ]
  }' >"${dir}/messages.json"
  jq -n '{reservations:[{id:1, path_pattern:"docs/TRACE.md", agent_name:"AgentAlpha", bead_id:"bd-trace", exclusive:true}]}' >"${dir}/reservations.json"
  jq -n '{paths:["docs/TRACE.md"]}' >"${dir}/write_set.json"
  jq -n '{paths:[]}' >"${dir}/git_status.json"
  jq -n '{commits:[{commit:"abc1234", message:"feat(swarm): close bd-trace causal trace drill", bead_id:"bd-trace"}]}' >"${dir}/commits.json"
  jq -n '{artifacts:[{artifact_path:"rch_policy_compliance_receipt.json", local_fallback_detected:false, content_hash:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}' >"${dir}/rch.json"
  jq -n '{commands:[{display:"bash scripts/e2e/swarm_agent_causal_trace_no_mock_drill.sh check", exit_code:0},{display:"bash scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh check", exit_code:0}]}' >"${dir}/validation.json"
  jq -n '{schema_version:"franken-engine.swarm-predictive-dashboard.v1", status:"ok", summary:{causal_trace_readiness:"complete"}}' >"${dir}/operator_status_input.json"
}

rewrite_case_fixtures() {
  local case_id="$1"
  local fixture_dir="$2"
  local tmp_path

  case "$case_id" in
    healthy_closeout)
      ;;
    missing_agent_mail_snapshot)
      ;;
    local_rch_fallback)
      tmp_path="${fixture_dir}/rch.tmp"
      jq '.artifacts[0].local_fallback_detected = true
        | .artifacts[0].stderr = "[RCH] local fallback detected while remote proof was claimed"' \
        "${fixture_dir}/rch.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/rch.json"
      ;;
    ownership_conflict)
      jq '{paths:["docs/OTHER.md"]}' >"${fixture_dir}/write_set.json"
      jq -n '{paths:["docs/UNRESERVED.md"]}' >"${fixture_dir}/git_status.json"
      ;;
    closed_without_commit)
      jq '{commits:[]}' >"${fixture_dir}/commits.json"
      ;;
    closed_without_validation)
      jq '{commands:[]}' >"${fixture_dir}/validation.json"
      ;;
    *)
      record_failure "unknown fixture case ${case_id}"
      return 1
      ;;
  esac
}

expected_decision() {
  case "$1" in
    healthy_closeout) printf 'pass' ;;
    missing_agent_mail_snapshot) printf 'degraded' ;;
    *) printf 'fail_closed' ;;
  esac
}

expected_readiness() {
  case "$1" in
    healthy_closeout) printf 'complete' ;;
    missing_agent_mail_snapshot) printf 'degraded' ;;
    *) printf 'contaminated' ;;
  esac
}

run_normalizer_case() {
  local case_id="$1"
  local fixture_dir="$2"
  local output_dir="$3"
  local args=(
    bash "$normalizer"
    --bead-id bd-trace
    --agent-name AgentAlpha
    --source-revision "fixture-${case_id}"
    --br-issue-json "${fixture_dir}/br_issue.json"
    --br-ready-json "${fixture_dir}/br_ready.json"
    --br-sync-status-json "${fixture_dir}/br_sync_status.json"
    --bv-actionable-plan-json "${fixture_dir}/bv_plan.json"
    --file-reservations-json "${fixture_dir}/reservations.json"
    --declared-write-set-json "${fixture_dir}/write_set.json"
    --git-status-json "${fixture_dir}/git_status.json"
    --git-closeout-commits-json "${fixture_dir}/commits.json"
    --rch-validation-artifacts-json "${fixture_dir}/rch.json"
    --validation-commands-json "${fixture_dir}/validation.json"
    --operator-status-json "${fixture_dir}/operator_status_input.json"
    --output-dir "$output_dir"
  )

  if [[ "$case_id" != "missing_agent_mail_snapshot" ]]; then
    args+=(
      --agent-mail-profiles-json "${fixture_dir}/profiles.json"
      --agent-mail-messages-json "${fixture_dir}/messages.json"
    )
  fi

  case "$(expected_decision "$case_id")" in
    fail_closed)
      run_step "normalizer-${case_id}" "42" "${args[@]}"
      ;;
    *)
      run_step "normalizer-${case_id}" "0" "${args[@]}"
      ;;
  esac
}

run_graph_case() {
  local case_id="$1"
  local normalizer_dir="$2"
  local output_dir="$3"

  case "$(expected_decision "$case_id")" in
    fail_closed)
      run_step "graph-${case_id}" "42" \
        bash "$graph" \
          --normalized-events-json "${normalizer_dir}/swarm_agent_causal_trace_events.json" \
          --output-dir "$output_dir"
      ;;
    *)
      run_step "graph-${case_id}" "0" \
        bash "$graph" \
          --normalized-events-json "${normalizer_dir}/swarm_agent_causal_trace_events.json" \
          --output-dir "$output_dir"
      ;;
  esac
}

run_operator_status_case() {
  local case_id="$1"
  local graph_dir="$2"
  local output_dir="$3"

  run_step "operator-status-${case_id}" "0" \
    bash "$operator_status" \
      --output-dir "$output_dir" \
      --bead-id bd-trace \
      --source-revision "fixture-${case_id}" \
      --agent-mail-status ok \
      --rch-status ok \
      --proof-index-status ok \
      --swarm-agent-causal-trace-graph-json "${graph_dir}/swarm_agent_causal_trace_graph.json" \
      --swarm-agent-causal-trace-anomaly-report-json "${graph_dir}/swarm_agent_causal_trace_anomalies.json"
}

assert_case_outputs() {
  local case_id="$1"
  local normalizer_dir="$2"
  local graph_dir="$3"
  local operator_dir="$4"
  local expected actual_readiness

  expected="$(expected_decision "$case_id")"
  jq -e --arg expected "$expected" '.decision == $expected' "${normalizer_dir}/swarm_agent_causal_trace_events.json" >/dev/null
  jq -e --arg expected "$expected" '.decision == $expected' "${graph_dir}/swarm_agent_causal_trace_anomalies.json" >/dev/null
  actual_readiness="$(jq -r '.predictive_dashboard.swarm_agent_causal_trace.readiness' "${operator_dir}/status.json")"
  if [[ "$actual_readiness" != "$(expected_readiness "$case_id")" ]]; then
    record_failure "${case_id} readiness ${actual_readiness} did not match $(expected_readiness "$case_id")"
    return 1
  fi

  case "$case_id" in
    healthy_closeout)
      jq -e '
        any(.edges[]; .edge_type == "bead_claimed")
        and any(.edges[]; .edge_type == "reservation_covers_path")
        and any(.edges[]; .edge_type == "validation_proves_closeout")
        and any(.edges[]; .edge_type == "commit_closes_bead")
      ' "${graph_dir}/swarm_agent_causal_trace_graph.json" >/dev/null
      ;;
    missing_agent_mail_snapshot)
      jq -e 'any(.anomalies[]; .anomaly_class == "missing_claim_message" and .severity == "degraded")' "${graph_dir}/swarm_agent_causal_trace_anomalies.json" >/dev/null
      ;;
    local_rch_fallback)
      jq -e 'any(.anomalies[]; .anomaly_class == "local_rch_fallback_contaminates_remote_proof")' "${graph_dir}/swarm_agent_causal_trace_anomalies.json" >/dev/null
      ;;
    ownership_conflict)
      jq -e 'any(.anomalies[]; .anomaly_class == "reservation_without_matching_bead_scope" or .anomaly_class == "missing_reservation_for_dirty_path")' "${graph_dir}/swarm_agent_causal_trace_anomalies.json" >/dev/null
      ;;
    closed_without_commit)
      jq -e 'any(.anomalies[]; .anomaly_class == "closed_bead_missing_commit")' "${graph_dir}/swarm_agent_causal_trace_anomalies.json" >/dev/null
      ;;
    closed_without_validation)
      jq -e 'any(.anomalies[]; .anomaly_class == "closed_bead_missing_validation_evidence")' "${graph_dir}/swarm_agent_causal_trace_anomalies.json" >/dev/null
      ;;
  esac

  jq -nc \
    --arg case_id "$case_id" \
    --arg expected_decision "$expected" \
    --arg readiness "$actual_readiness" \
    --arg normalizer_summary "${normalizer_dir}/swarm_agent_causal_trace_normalizer_summary.json" \
    --arg normalized_events "${normalizer_dir}/swarm_agent_causal_trace_events.json" \
    --arg graph_json "${graph_dir}/swarm_agent_causal_trace_graph.json" \
    --arg anomaly_report_json "${graph_dir}/swarm_agent_causal_trace_anomalies.json" \
    --arg operator_status_json "${operator_dir}/status.json" \
    --arg operator_report_md "${operator_dir}/report.md" \
    '{case_id:$case_id,expected_decision:$expected_decision,operator_readiness:$readiness,artifact_paths:{normalizer_summary_json:$normalizer_summary,normalized_events_json:$normalized_events,causal_graph_json:$graph_json,anomaly_report_json:$anomaly_report_json,operator_status_json:$operator_status_json,operator_report_md:$operator_report_md}}' >>"$case_rows_jsonl"
}

run_case() {
  local case_id="$1"
  local case_dir="${run_dir}/cases/${case_id}"
  local fixture_dir="${case_dir}/fixtures"
  local normalizer_dir="${case_dir}/normalizer"
  local graph_dir="${case_dir}/graph"
  local operator_dir="${case_dir}/operator-status"

  write_common_fixtures "$fixture_dir" "closed"
  rewrite_case_fixtures "$case_id" "$fixture_dir"
  run_normalizer_case "$case_id" "$fixture_dir" "$normalizer_dir"
  run_graph_case "$case_id" "$normalizer_dir" "$graph_dir"
  run_operator_status_case "$case_id" "$graph_dir" "$operator_dir"
  assert_case_outputs "$case_id" "$normalizer_dir" "$graph_dir" "$operator_dir"
}

write_receipt() {
  # shellcheck disable=SC2094
  jq -s \
    --arg schema_version "franken-engine.swarm-agent-causal-trace-receipt.v1" \
    --arg receipt_json "$receipt_json" \
    --arg events_jsonl "$events_path" \
    --arg commands_txt "$commands_path" \
    --arg report_md "$report_md" \
    '{
      schema_version:$schema_version,
      decision:(if all(.[]; .expected_decision == "pass" or .expected_decision == "degraded" or .expected_decision == "fail_closed") then "pass" else "fail_closed" end),
      drill_id:"swarm_agent_causal_trace_no_mock_drill",
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        queries_live_agent_mail:false,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        repairs_beads:false
      },
      case_count:length,
      cases:.,
      artifact_paths:{
        trace_receipt_json:$receipt_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        report_md:$report_md
      }
    }' "$case_rows_jsonl" >"$receipt_json"
}

write_report() {
  {
    printf '# Swarm Agent Causal Trace No-Mock Drill\n\n'
    printf -- "- Receipt: \`%s\`\n" "$receipt_json"
    printf -- "- Events: \`%s\`\n" "$events_path"
    printf -- "- Commands: \`%s\`\n" "$commands_path"
    printf -- "- Cases: \`%s\`\n\n" "$(jq '.case_count' "$receipt_json")"
    jq -r '.cases[] | "- `" + .case_id + "`: decision=`" + .expected_decision + "` readiness=`" + .operator_readiness + "`"' "$receipt_json"
  } >"$report_md"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$normalizer" "$graph" "$operator_status" "$truth_gate"
  jq empty "$contract_path"
  jq -e '
    (.planned_surfaces | index("scripts/e2e/swarm_agent_causal_trace_no_mock_drill.sh") != null)
    and (.planned_surfaces | index("scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh") != null)
    and (.no_mock_drill.required_cases | index("closed_without_validation") != null)
    and (.truth_gate.script == "scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh")
  ' "$contract_path" >/dev/null
  grep -Fq 'scripts/swarm_agent_causal_trace_normalizer.sh' "$docs_path"
  grep -Fq 'scripts/swarm_agent_causal_trace_graph.sh' "$docs_path"
  grep -Fq 'scripts/swarm_operator_status_report.sh' "$docs_path"
  grep -Fq 'swarm_agent_causal_trace_receipt.json' "$docs_path"
  grep -Fq 'proof-only, and advisory-only' "$docs_path"
  record_pass "syntax docs and contract"
}

run_drill() {
  ensure_run_dir
  for case_id in "${cases[@]}"; do
    run_case "$case_id"
  done
  write_receipt
  write_report
  jq -e '.decision == "pass" and .case_count == 6' "$receipt_json" >/dev/null
  record_pass "composed producers"
  printf 'swarm_agent_causal_trace_receipt=%s\n' "$receipt_json"
}

run_selftest() {
  local tmp_root bad_rch_case bad_commit_case

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/franken-engine-causal-trace-drill.XXXXXX")"
  SWARM_AGENT_CAUSAL_TRACE_NO_MOCK_DRILL_RUN_DIR="${tmp_root}/selftest-run" bash "${BASH_SOURCE[0]}" run >/dev/null
  jq -e '.case_count == 6 and .decision == "pass"' "${tmp_root}/selftest-run/swarm_agent_causal_trace_receipt.json" >/dev/null

  bad_rch_case="${tmp_root}/selftest-run/cases/local_rch_fallback/graph/swarm_agent_causal_trace_anomalies.json"
  jq -e 'any(.anomalies[]; .anomaly_class == "local_rch_fallback_contaminates_remote_proof")' "$bad_rch_case" >/dev/null

  bad_commit_case="${tmp_root}/selftest-run/cases/closed_without_commit/graph/swarm_agent_causal_trace_anomalies.json"
  jq -e 'any(.anomalies[]; .anomaly_class == "closed_bead_missing_commit")' "$bad_commit_case" >/dev/null

  record_pass "selftest composed drill"
  printf 'swarm_agent_causal_trace_no_mock_drill_artifacts=%s\n' "$tmp_root"
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
