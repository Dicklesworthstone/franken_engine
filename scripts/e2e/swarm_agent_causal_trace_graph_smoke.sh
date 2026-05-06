#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_agent_causal_trace_normalizer.sh"
graph="${root_dir}/scripts/swarm_agent_causal_trace_graph.sh"
docs_path="${root_dir}/docs/SWARM_AGENT_CAUSAL_TRACE_SPINE.md"
contract_path="${root_dir}/docs/swarm_agent_causal_trace_spine_contract_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-agent-causal-trace-graph %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-agent-causal-trace-graph %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_causal_trace_graph_smoke.sh [check|selftest]
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

run_normalizer_case() {
  local fixture_dir="$1"
  local output_dir="$2"
  set +e
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
  local status=$?
  set -e
  if [[ "$status" -ne 0 && "$status" -ne 42 ]]; then
    record_failure "normalizer exited ${status} for ${fixture_dir}"
    return 1
  fi
}

run_graph_case() {
  local normalizer_out="$1"
  local output_dir="$2"
  set +e
  "$graph" \
    --normalized-events-json "${normalizer_out}/swarm_agent_causal_trace_events.json" \
    --output-dir "$output_dir" >/dev/null
  local status=$?
  set -e
  if [[ "$status" -ne 0 && "$status" -ne 42 ]]; then
    record_failure "graph exited ${status} for ${normalizer_out}"
    return 1
  fi
  return "$status"
}

expect_graph_fail_closed() {
  local normalizer_out="$1"
  local output_dir="$2"
  local status=0
  if run_graph_case "$normalizer_out" "$output_dir"; then
    status=0
  else
    status=$?
  fi
  if [[ "$status" -ne 42 ]]; then
    record_failure "expected graph fail-closed exit 42 for ${normalizer_out}"
    return 1
  fi
  jq -e '.anomaly_summary.decision == "fail_closed"' "${output_dir}/swarm_agent_causal_trace_graph.json" >/dev/null
  jq -e '.decision == "fail_closed"' "${output_dir}/swarm_agent_causal_trace_anomalies.json" >/dev/null
}

run_check() {
  bash -n "$graph"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  jq -e '
    .graph.script == "scripts/swarm_agent_causal_trace_graph.sh"
    and .graph.smoke_script == "scripts/e2e/swarm_agent_causal_trace_graph_smoke.sh"
    and (.required_graph_fields | index("nodes") != null)
    and (.required_graph_fields | index("edges") != null)
  ' "$contract_path" >/dev/null
  grep -q 'swarm_agent_causal_trace_graph.json' "$docs_path"
  grep -q 'swarm_agent_causal_trace_anomalies.json' "$docs_path"
  record_pass "syntax docs and contract"
}

run_selftest() {
  local tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-agent-causal-trace-graph-smoke"
  local healthy="${tmp_root}/healthy"
  local local_fallback="${tmp_root}/local_fallback"
  local missing_commit="${tmp_root}/missing_commit"
  local ownership_conflict="${tmp_root}/ownership_conflict"

  rm -rf "$tmp_root"
  mkdir -p "$tmp_root"

  write_common_fixtures "$healthy" "closed"
  run_normalizer_case "$healthy" "${healthy}/normalizer"
  run_graph_case "${healthy}/normalizer" "${healthy}/graph"
  jq -e '
    .anomaly_summary.decision == "pass"
    and (.nodes | length >= 6)
    and any(.edges[]; .edge_type == "bead_claimed")
    and any(.edges[]; .edge_type == "commit_closes_bead")
    and all(.nodes[]; (.node_hash // "") | startswith("sha256:"))
    and all(.edges[]; (.edge_hash // "") | startswith("sha256:"))
  ' "${healthy}/graph/swarm_agent_causal_trace_graph.json" >/dev/null
  jq -e '.anomaly_count == 0' "${healthy}/graph/swarm_agent_causal_trace_anomalies.json" >/dev/null

  write_common_fixtures "$local_fallback" "closed"
  jq '.artifacts[0].local_fallback_detected = true' "${local_fallback}/rch.json" >"${local_fallback}/rch.tmp"
  mv "${local_fallback}/rch.tmp" "${local_fallback}/rch.json"
  run_normalizer_case "$local_fallback" "${local_fallback}/normalizer"
  expect_graph_fail_closed "${local_fallback}/normalizer" "${local_fallback}/graph"
  jq -e 'any(.anomalies[]; .anomaly_class == "local_rch_fallback_contaminates_remote_proof")' "${local_fallback}/graph/swarm_agent_causal_trace_anomalies.json" >/dev/null

  write_common_fixtures "$missing_commit" "closed"
  jq '{commits:[]}' >"${missing_commit}/commits.json"
  run_normalizer_case "$missing_commit" "${missing_commit}/normalizer"
  expect_graph_fail_closed "${missing_commit}/normalizer" "${missing_commit}/graph"
  jq -e 'any(.anomalies[]; .anomaly_class == "closed_bead_missing_commit")' "${missing_commit}/graph/swarm_agent_causal_trace_anomalies.json" >/dev/null

  write_common_fixtures "$ownership_conflict" "closed"
  jq '{paths:["docs/OTHER.md"]}' >"${ownership_conflict}/write_set.json"
  run_normalizer_case "$ownership_conflict" "${ownership_conflict}/normalizer"
  expect_graph_fail_closed "${ownership_conflict}/normalizer" "${ownership_conflict}/graph"
  jq -e 'any(.anomalies[]; .anomaly_class == "reservation_without_matching_bead_scope")' "${ownership_conflict}/graph/swarm_agent_causal_trace_anomalies.json" >/dev/null

  record_pass "selftest fixtures"
  printf 'swarm_agent_causal_trace_graph_smoke_artifacts=%s\n' "$tmp_root"
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
