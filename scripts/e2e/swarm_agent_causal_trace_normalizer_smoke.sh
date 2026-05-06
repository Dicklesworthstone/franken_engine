#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_agent_causal_trace_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_AGENT_CAUSAL_TRACE_SPINE.md"
contract_path="${root_dir}/docs/swarm_agent_causal_trace_spine_contract_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-agent-causal-trace-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-agent-causal-trace-normalizer %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_causal_trace_normalizer_smoke.sh [check|selftest]
EOF
}

write_common_fixtures() {
  local dir="$1"
  local status="${2:-closed}"

  mkdir -p "$dir"
  jq -n --arg status "$status" '[
    {
      id:"bd-trace",
      title:"Trace fixture",
      status:$status,
      priority:1,
      assignee:"AgentAlpha",
      updated_at:"2026-05-06T00:00:00Z"
    }
  ]' >"${dir}/br_issue.json"
  jq -n '[{id:"bd-next", title:"Next bead", status:"open", priority:1}]' >"${dir}/br_ready.json"
  jq -n '{dirty_count:0, db_newer:false, jsonl_newer:false}' >"${dir}/br_sync_status.json"
  jq -n '{plan:{tracks:[{track_id:"track-A",items:[{id:"bd-trace",status:"closed"}]}]}}' >"${dir}/bv_plan.json"
  jq -n '{agents:[{name:"AgentAlpha", last_active_ts:"2026-05-06T00:01:00Z"}]}' >"${dir}/profiles.json"
  jq -n '{messages:[{id:1, thread_id:"bd-trace", from:"AgentAlpha", ack_required:true, ack_ts:"2026-05-06T00:02:00Z", subject:"Claimed bd-trace"}]}' >"${dir}/messages.json"
  jq -n '{reservations:[{id:1, path_pattern:"docs/TRACE.md", agent_name:"AgentAlpha", bead_id:"bd-trace", exclusive:true}]}' >"${dir}/reservations.json"
  jq -n '{paths:["docs/TRACE.md"]}' >"${dir}/write_set.json"
  jq -n '{paths:[]}' >"${dir}/git_status.json"
  jq -n '{commits:[{commit:"abc1234", message:"close trace fixture", bead_id:"bd-trace"}]}' >"${dir}/commits.json"
  jq -n '{artifacts:[{artifact_path:"run_manifest.json", local_fallback_detected:false, content_hash:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}' >"${dir}/rch.json"
  jq -n '{commands:[{display:"jq empty docs/trace.json", exit_code:0}]}' >"${dir}/validation.json"
  jq -n '{schema_version:"franken-engine.swarm-predictive-dashboard.v1", status:"ok"}' >"${dir}/operator_status.json"
}

run_normalizer() {
  local fixture_dir="$1"
  local output_dir="$2"
  "$normalizer" \
    --bead-id bd-trace \
    --agent-name AgentAlpha \
    --source-revision fixture-rev \
    --br-issue-json "${fixture_dir}/br_issue.json" \
    --br-ready-json "${fixture_dir}/br_ready.json" \
    --br-sync-status-json "${fixture_dir}/br_sync_status.json" \
    --bv-actionable-plan-json "${fixture_dir}/bv_plan.json" \
    --agent-mail-profiles-json "${fixture_dir}/profiles.json" \
    --agent-mail-messages-json "${fixture_dir}/messages.json" \
    --file-reservations-json "${fixture_dir}/reservations.json" \
    --declared-write-set-json "${fixture_dir}/write_set.json" \
    --git-status-json "${fixture_dir}/git_status.json" \
    --git-closeout-commits-json "${fixture_dir}/commits.json" \
    --rch-validation-artifacts-json "${fixture_dir}/rch.json" \
    --validation-commands-json "${fixture_dir}/validation.json" \
    --operator-status-json "${fixture_dir}/operator_status.json" \
    --output-dir "$output_dir" >/dev/null
}

expect_fail_closed() {
  local fixture_dir="$1"
  local output_dir="$2"
  set +e
  run_normalizer "$fixture_dir" "$output_dir"
  local status=$?
  set -e
  if [[ "$status" -ne 42 ]]; then
    record_failure "expected fail-closed exit 42 for ${fixture_dir}"
    return 1
  fi
  jq -e '.decision == "fail_closed"' "${output_dir}/swarm_agent_causal_trace_events.json" >/dev/null
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  jq -e '
    .planned_surfaces | index("scripts/swarm_agent_causal_trace_normalizer.sh") != null
  ' "$contract_path" >/dev/null
  grep -q 'swarm_agent_causal_trace_events.json' "$docs_path"
  grep -q 'fixture-fed' "$docs_path"
  record_pass "syntax docs and contract"
}

run_selftest() {
  local tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-agent-causal-trace-normalizer-smoke"
  local healthy="${tmp_root}/healthy"
  local degraded="${tmp_root}/degraded"
  local local_fallback="${tmp_root}/local_fallback"
  local ownership_conflict="${tmp_root}/ownership_conflict"
  local missing_commit="${tmp_root}/missing_commit"
  local unacked="${tmp_root}/unacked"

  rm -rf "$tmp_root"
  mkdir -p "$tmp_root"

  write_common_fixtures "$healthy" "closed"
  run_normalizer "$healthy" "${healthy}/out"
  jq -e '
    .decision == "pass"
    and (.events | length >= 6)
  ' "${healthy}/out/swarm_agent_causal_trace_events.json" >/dev/null

  write_common_fixtures "$degraded" "in_progress"
  rm "${degraded}/messages.json"
  "$normalizer" \
    --bead-id bd-trace \
    --agent-name AgentAlpha \
    --source-revision fixture-rev \
    --br-issue-json "${degraded}/br_issue.json" \
    --file-reservations-json "${degraded}/reservations.json" \
    --declared-write-set-json "${degraded}/write_set.json" \
    --output-dir "${degraded}/out" >/dev/null
  jq -e '.decision == "degraded"' "${degraded}/out/swarm_agent_causal_trace_events.json" >/dev/null

  write_common_fixtures "$local_fallback" "closed"
  jq '.artifacts[0].local_fallback_detected = true' "${local_fallback}/rch.json" >"${local_fallback}/rch.tmp"
  mv "${local_fallback}/rch.tmp" "${local_fallback}/rch.json"
  expect_fail_closed "$local_fallback" "${local_fallback}/out"
  jq -e 'any(.fail_closed_reasons[]; .code == "local_rch_fallback_contaminates_remote_proof")' "${local_fallback}/out/swarm_agent_causal_trace_events.json" >/dev/null

  write_common_fixtures "$ownership_conflict" "closed"
  jq '{paths:["docs/OTHER.md"]}' >"${ownership_conflict}/write_set.json"
  expect_fail_closed "$ownership_conflict" "${ownership_conflict}/out"
  jq -e 'any(.fail_closed_reasons[]; .code == "reservation_without_matching_bead_scope")' "${ownership_conflict}/out/swarm_agent_causal_trace_events.json" >/dev/null

  write_common_fixtures "$missing_commit" "closed"
  jq '{commits:[]}' >"${missing_commit}/commits.json"
  expect_fail_closed "$missing_commit" "${missing_commit}/out"
  jq -e 'any(.fail_closed_reasons[]; .code == "closed_bead_missing_commit")' "${missing_commit}/out/swarm_agent_causal_trace_events.json" >/dev/null

  write_common_fixtures "$unacked" "closed"
  jq '.messages[0] |= del(.ack_ts)' "${unacked}/messages.json" >"${unacked}/messages.tmp"
  mv "${unacked}/messages.tmp" "${unacked}/messages.json"
  expect_fail_closed "$unacked" "${unacked}/out"
  jq -e 'any(.fail_closed_reasons[]; .code == "ack_required_message_unacknowledged")' "${unacked}/out/swarm_agent_causal_trace_events.json" >/dev/null

  record_pass "selftest fixtures"
  printf 'swarm_agent_causal_trace_normalizer_smoke_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
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
