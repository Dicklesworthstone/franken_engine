#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
index_script="${root_dir}/scripts/agent_run_evidence_index.sh"
docs_path="${root_dir}/docs/AGENT_RUN_EVIDENCE_INDEX.md"
contract_path="${root_dir}/docs/agent_run_evidence_index_contract_v1.json"
fixtures_path="${AGENT_RUN_EVIDENCE_INDEX_FIXTURES:-${root_dir}/scripts/testdata/agent_run_evidence_index/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS agent-run-evidence-index %s\n' "$1"
}

record_failure() {
  printf 'FAIL agent-run-evidence-index %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/agent_run_evidence_index_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatically mutates|automatically closes|automatically claims|queries live Agent Mail automatically|runs Cargo automatically|runs rch automatically|repairs beads automatically|changes live queue policy' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.agent-run-evidence-index-contract.v1"
    and .bead_id == "bd-es4nn"
    and .implementation_script == "scripts/agent_run_evidence_index.sh"
    and .smoke_script == "scripts/e2e/agent_run_evidence_index_smoke.sh"
    and (.reused_surfaces | index("scripts/swarm_agent_causal_trace_normalizer.sh") != null)
    and (.reused_surfaces | index("scripts/swarm_agent_causal_trace_graph.sh") != null)
    and ([.required_edge_types[]] | sort) == (["agent_mail_thread","bead","causal_trace_graph","closeout_commit","rch_artifact_manifest","validation_command_transcript"] | sort)
    and ([.required_fixture_cases[]] | sort) == (["complete_run","mail_outage","missing_bead","missing_command_transcript","missing_commit","missing_rch_manifest"] | sort)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.queries_live_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.agent-run-evidence-index-fixtures.v1"
    and ([.cases[].case_id] | sort) == (["complete_run","mail_outage","missing_bead","missing_command_transcript","missing_commit","missing_rch_manifest"] | sort)
    and any(.cases[]; .case_id == "complete_run" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "mail_outage" and .expected.reason_code == "agent_mail_snapshot_missing")
    and any(.cases[]; .expected.reason_code == "complete_run_missing_bead")
    and any(.cases[]; .expected.reason_code == "complete_run_missing_commit")
    and any(.cases[]; .expected.reason_code == "complete_run_missing_command_transcript")
    and any(.cases[]; .expected.reason_code == "complete_run_missing_artifact_manifest")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "swarm_agent_causal_trace_normalizer.sh" "$docs_path" \
    && grep -Fq "swarm_agent_causal_trace_graph.sh" "$docs_path" \
    && grep -Fq "Missing Agent Mail snapshots become degraded edges" "$docs_path" \
    && grep -Fq "agent_run_evidence_index.json" "$docs_path"
}

write_snapshot() {
  local case_json="$1"
  local output_path="$2"

  jq -n --argjson case "$case_json" '
    def maybe($cond; $value): if $cond then $value else null end;
    def bool($name): ($case[$name] // false);
    def rch_artifacts:
      if ($case.rch_artifact_mode // "") == "manifest" then
        {artifacts:[{artifact_path:"run_manifest.json", content_hash:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", local_fallback_detected:false}]}
      elif ($case.rch_artifact_mode // "") == "log_only" then
        {artifacts:[{artifact_path:"remote.log", content_hash:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", local_fallback_detected:false}]}
      else
        {artifacts:[]}
      end;
    {
      schema_version:"franken-engine.agent-run-evidence-index.snapshot.v1",
      case_id:$case.case_id,
      bead_id:"bd-run",
      agent_name:"AgentAlpha",
      source_revision:"fixture-rev",
      complete_run_expected:($case.complete_run_expected // false),
      sources:{
        br_issue_json:[{id:($case.br_issue_id // "bd-run"), title:"Run fixture", status:"closed", priority:2, assignee:"AgentAlpha", updated_at:"2026-05-12T00:00:00Z"}],
        br_ready_json:{issues:[]},
        br_sync_status_json:{dirty_count:0, db_newer:false, jsonl_newer:false},
        bv_actionable_plan_json:{plan:{tracks:[{track_id:"track-A",items:[{id:"bd-run",status:"closed"}]}]}},
        agent_mail_profiles_json:maybe(bool("include_agent_mail"); {agents:[{name:"AgentAlpha", last_active_ts:"2026-05-12T00:01:00Z"}]}),
        agent_mail_messages_json:maybe(bool("include_agent_mail"); {messages:[{id:1, thread_id:"bd-run", from:"AgentAlpha", ack_required:true, ack_ts:"2026-05-12T00:02:00Z", subject:"Claimed bd-run"}]}),
        file_reservations_json:{reservations:[{id:1, path_pattern:"docs/RUN.md", agent_name:"AgentAlpha", bead_id:"bd-run", exclusive:true}]},
        declared_write_set_json:{paths:["docs/RUN.md"]},
        git_status_json:{paths:[]},
        git_closeout_commits_json:(if bool("include_commit") then {commits:[{commit:"abc1234", message:"close bd-run", bead_id:"bd-run"}]} else {commits:[]} end),
        rch_validation_artifacts_json:rch_artifacts,
        validation_commands_json:(if bool("include_validation_command") then {commands:[{display:"jq empty docs/run.json", exit_code:0}]} else {commands:[]} end),
        operator_status_json:{schema_version:"franken-engine.swarm-predictive-dashboard.v1", status:"ok"}
      }
    }
  ' >"$output_path"
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir expected_exit expected_decision expected_edge expected_status reason_code actual_exit output
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/agent-run-evidence.XXXXXX")"
  output_dir="${tmpdir}/out"
  write_snapshot "$case_json" "${tmpdir}/run_snapshot.json"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_edge="$(jq -r '.expected.edge_type' <<<"$case_json")"
  expected_status="$(jq -r '.expected.edge_status' <<<"$case_json")"
  reason_code="$(jq -r '.expected.reason_code // ""' <<<"$case_json")"

  set +e
  output="$("$index_script" --run-snapshot-json "${tmpdir}/run_snapshot.json" --source-revision "smoke-${case_id}" --output-dir "$output_dir" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return
  fi

  for artifact in agent_run_evidence_index.json index_edges.jsonl causal_trace_normalizer/swarm_agent_causal_trace_events.json causal_trace_graph/swarm_agent_causal_trace_graph.json events.jsonl commands.txt report.md; do
    [[ -f "${output_dir}/${artifact}" ]] || record_failure "${case_id} missing ${artifact}"
  done

  local index="${output_dir}/agent_run_evidence_index.json"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$index" >/dev/null \
    || record_failure "${case_id} decision mismatch"
  jq -e --arg edge_type "$expected_edge" --arg status "$expected_status" 'any(.index_edges[]?; .edge_type == $edge_type and .status == $status)' "$index" >/dev/null \
    || record_failure "${case_id} edge status mismatch"
  if [[ -n "$reason_code" ]]; then
    jq -e --arg code "$reason_code" 'any((.fail_closed_reasons + .degraded_reasons)[]?; .code == $code)' "$index" >/dev/null \
      || record_failure "${case_id} missing reason ${reason_code}"
  fi
  jq -e '.mutation_policy.advisory_only == true and .mutation_policy.queries_live_agent_mail == false and .mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false and .mutation_policy.mutates_br == false' "$index" >/dev/null \
    || record_failure "${case_id} unsafe mutation policy"
  grep -Fq "./scripts/swarm_agent_causal_trace_normalizer.sh" "${output_dir}/commands.txt" \
    || record_failure "${case_id} commands missing normalizer"
  grep -Fq "./scripts/swarm_agent_causal_trace_graph.sh" "${output_dir}/commands.txt" \
    || record_failure "${case_id} commands missing graph"

  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$index_script" "${BASH_SOURCE[0]}"
  contract_shape_ok || record_failure "contract shape"
  fixtures_shape_ok || record_failure "fixture shape"
  docs_shape_ok || record_failure "docs shape"
  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$index_script"

  local case_id
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  for code in agent_mail_snapshot_missing complete_run_missing_artifact_manifest complete_run_missing_bead complete_run_missing_commit complete_run_missing_command_transcript; do
    jq -e --arg code "$code" 'any(.cases[]; .expected.reason_code == $code)' "$fixtures_path" >/dev/null \
      || { record_failure "selftest missing ${code}"; exit 1; }
  done
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
