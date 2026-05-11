#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${DEGRADED_COORDINATION_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-degraded-coordination-drill}"
run_id="${DEGRADED_COORDINATION_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${DEGRADED_COORDINATION_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-fixture}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

fixtures_json="${root_dir}/scripts/testdata/degraded_coordination_no_mock_drill/cases.json"
contract_path="${root_dir}/docs/degraded_coordination_no_mock_drill_contract_v1.json"
docs_path="${root_dir}/docs/DEGRADED_COORDINATION_NO_MOCK_DRILL.md"
bridge_script="${root_dir}/scripts/swarm_agent_mail_outage_continuity_bridge.sh"
handoff_script="${root_dir}/scripts/swarm_handoff_capsule_generator.sh"
dashboard_script="${root_dir}/scripts/high_core_validation_pressure_dashboard.sh"
completion_script="${root_dir}/scripts/objective_artifact_completion_audit_gate.sh"
scenario_filter=""
replay_run_dir=""
latest_from=""
source_revision="${DEGRADED_COORDINATION_DRILL_SOURCE_REVISION:-}"

run_manifest_path=""
events_path=""
commands_path=""
drill_report_path=""
case_results_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/degraded_coordination_no_mock_drill.sh [fixture|replay|check|selftest] [OPTIONS]

Options:
  --fixtures-json FILE
  --scenario-id ID
  --replay-run-dir DIR
  --latest-from DIR
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      shift 2
      ;;
    --scenario-id)
      scenario_filter="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      shift 2
      ;;
    --latest-from)
      latest_from="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for degraded coordination drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  run_manifest_path="${run_dir}/run_manifest.json"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  drill_report_path="${run_dir}/drill_report.json"
  case_results_path="${run_dir}/case_results.jsonl"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  refresh_paths
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

record_pass() {
  printf 'PASS degraded-coordination-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL degraded-coordination-no-mock-drill %s\n' "$1" >&2
}

render_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

log_command() {
  render_command "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.degraded-coordination-no-mock-drill.event.v1" \
    --arg scenario_id "$1" \
    --arg component "$2" \
    --arg event_name "$3" \
    --arg outcome "$4" \
    --arg artifact_path "$5" \
    '{schema_version:$schema_version,scenario_id:$scenario_id,component:$component,event_name:$event_name,outcome:$outcome,artifact_path:$artifact_path}' \
    >>"$events_path"
}

write_json_field() {
  local case_json="$1"
  local jq_expr="$2"
  local path="$3"
  jq "$jq_expr" <<<"$case_json" >"$path"
}

run_step() {
  local scenario_id="$1"
  local component="$2"
  local expected_codes="$3"
  shift 3
  local step_dir="${run_dir}/scenarios/${scenario_id}/steps/${component}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code expected
  mkdir -p "$step_dir"
  log_command "$@"
  write_event "$scenario_id" "$component" "started" "running" "$step_dir"
  set +e
  "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  IFS=',' read -r -a expected_list <<<"$expected_codes"
  for expected in "${expected_list[@]}"; do
    if [[ "$exit_code" == "$expected" ]]; then
      write_event "$scenario_id" "$component" "finished" "pass" "$step_dir"
      return 0
    fi
  done
  write_event "$scenario_id" "$component" "finished" "fail" "$stderr_path"
  printf 'scenario %s component %s expected exit %s, got %s\n' "$scenario_id" "$component" "$expected_codes" "$exit_code" >&2
  cat "$stderr_path" >&2
  return 1
}

write_component_inputs() {
  local case_json="$1"
  local scenario_dir="$2"
  local inputs_dir="${scenario_dir}/inputs"
  mkdir -p "$inputs_dir"/{bridge,handoff,dashboard}

  write_json_field "$case_json" '.sources.bridge.mail_health_json' "${inputs_dir}/bridge/mail_health.json"
  write_json_field "$case_json" '.sources.bridge.mail_bootstrap_json' "${inputs_dir}/bridge/mail_bootstrap.json"
  write_json_field "$case_json" '.sources.bridge.agent_profiles_json' "${inputs_dir}/bridge/agent_profiles.json"
  write_json_field "$case_json" '.sources.bridge.br_in_progress_json' "${inputs_dir}/bridge/br_in_progress.json"
  write_json_field "$case_json" '.sources.bridge.git_status_json' "${inputs_dir}/bridge/git_status.json"
  write_json_field "$case_json" '.sources.bridge.file_reservations_json' "${inputs_dir}/bridge/file_reservations.json"

  write_json_field "$case_json" '.sources.handoff.git_status_json' "${inputs_dir}/handoff/git_status.json"
  write_json_field "$case_json" '.sources.handoff.br_state_json' "${inputs_dir}/handoff/br_state.json"
  write_json_field "$case_json" '.sources.handoff.owned_paths_json' "${inputs_dir}/handoff/owned_paths.json"
  write_json_field "$case_json" '.sources.handoff.recent_commits_json' "${inputs_dir}/handoff/recent_commits.json"
  write_json_field "$case_json" '.sources.handoff.rch_jobs_json' "${inputs_dir}/handoff/rch_jobs.json"
  write_json_field "$case_json" '.sources.handoff.validation_receipts_json' "${inputs_dir}/handoff/validation_receipts.json"
  write_json_field "$case_json" '.sources.handoff.mail_health_json' "${inputs_dir}/handoff/mail_health.json"
  write_json_field "$case_json" '.sources.handoff.operator_notes_json' "${inputs_dir}/handoff/operator_notes.json"

  write_json_field "$case_json" '.sources.dashboard.resource_envelope_json' "${inputs_dir}/dashboard/resource_envelope.json"
  write_json_field "$case_json" '.sources.dashboard.rch_jobs_json' "${inputs_dir}/dashboard/rch_jobs.json"
  write_json_field "$case_json" '.sources.dashboard.process_counts_json' "${inputs_dir}/dashboard/process_counts.json"
  write_json_field "$case_json" '.sources.dashboard.proof_shard_plan_json' "${inputs_dir}/dashboard/proof_shard_plan.json"
  write_json_field "$case_json" '.sources.dashboard.br_readiness_json' "${inputs_dir}/dashboard/br_readiness.json"
  write_json_field "$case_json" '.sources.dashboard.mail_health_json' "${inputs_dir}/dashboard/mail_health.json"
}

write_completion_inputs() {
  local scenario_id="$1"
  local scenario_dir="$2"
  local bridge_dir="${scenario_dir}/steps/bridge/out"
  local handoff_dir="${scenario_dir}/steps/handoff/out"
  local dashboard_dir="${scenario_dir}/steps/dashboard/out"
  local completion_input_dir="${scenario_dir}/inputs/completion"
  mkdir -p "$completion_input_dir"

  jq -n \
    --arg objective_id "degraded-coordination-${scenario_id}" \
    --arg bridge_report "${bridge_dir}/mail_outage_continuity_bridge.json" \
    --arg bridge_locks "${bridge_dir}/soft_lock_receipts.jsonl" \
    --arg handoff_capsule "${handoff_dir}/swarm_handoff_capsule.json" \
    --arg dashboard_report "${dashboard_dir}/high_core_validation_pressure_dashboard.json" \
    '{
      objective_id:$objective_id,
      deliverables:[
        {
          deliverable_id:"agent_mail_bridge",
          title:"Agent Mail outage bridge emitted br soft-lock continuity evidence",
          required_artifacts:[$bridge_report,$bridge_locks],
          required_commands:["bridge-step"],
          required_beads:["bd-dl3q2"],
          required_proofs:["bridge-report"]
        },
        {
          deliverable_id:"handoff_capsule",
          title:"Handoff capsule preserved dirty worktree and active RCH context",
          required_artifacts:[$handoff_capsule],
          required_commands:["handoff-step"],
          required_beads:["bd-d5kxj"],
          required_proofs:["handoff-report"]
        },
        {
          deliverable_id:"validation_pressure_dashboard",
          title:"Validation pressure dashboard emitted safe degraded recommendation",
          required_artifacts:[$dashboard_report],
          required_commands:["dashboard-step"],
          required_beads:["bd-f7zfw"],
          required_proofs:["dashboard-report"]
        }
      ]
    }' >"${completion_input_dir}/objective.json"

  jq -n \
    --arg bridge_report "${bridge_dir}/mail_outage_continuity_bridge.json" \
    --arg bridge_locks "${bridge_dir}/soft_lock_receipts.jsonl" \
    --arg handoff_capsule "${handoff_dir}/swarm_handoff_capsule.json" \
    --arg dashboard_report "${dashboard_dir}/high_core_validation_pressure_dashboard.json" \
    '{
      artifacts:[
        {path:$bridge_report,status:"present"},
        {path:$bridge_locks,status:"present"},
        {path:$handoff_capsule,status:"present"},
        {path:$dashboard_report,status:"present"}
      ],
      commands:[
        {id:"bridge-step",exit_code:0},
        {id:"handoff-step",exit_code:0},
        {id:"dashboard-step",exit_code:0}
      ],
      beads:[
        {id:"bd-dl3q2",status:"closed"},
        {id:"bd-d5kxj",status:"closed"},
        {id:"bd-f7zfw",status:"closed"}
      ],
      proof_receipts:[
        {id:"bridge-report",status:"passed",reuse_eligible:true},
        {id:"handoff-report",status:"passed",reuse_eligible:true},
        {id:"dashboard-report",status:"passed",reuse_eligible:true}
      ]
    }' >"${completion_input_dir}/evidence.json"
}

assert_report_matches_expected() {
  local case_json="$1"
  local scenario_report="$2"
  local scenario_id
  scenario_id="$(jq -r '.scenario_id' <<<"$case_json")"
  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" '
      . as $report
      | $report.overall_decision == $expected.overall_decision
      and $report.components.bridge.decision == $expected.bridge_decision
      and $report.components.bridge.summary.soft_lock_count == $expected.bridge_soft_lock_count
      and all($expected.bridge_reason_codes[]; . as $code | any($report.components.bridge.reason_codes[]?; . == $code))
      and $report.components.handoff.decision == $expected.handoff_decision
      and $report.components.handoff.ready_count == $expected.handoff_ready_count
      and $report.components.handoff.active_rch_count == $expected.handoff_active_rch_count
      and all($expected.handoff_reason_codes[]; . as $code | any($report.components.handoff.reason_codes[]?; . == $code))
      and $report.components.dashboard.recommendation == $expected.dashboard_recommendation
      and $report.components.dashboard.pressure_level == $expected.dashboard_pressure_level
      and all($expected.dashboard_reason_codes[]; . as $code | any($report.components.dashboard.reason_codes[]?; . == $code))
      and $report.components.completion.decision == $expected.completion_decision
      and $report.mutation_policy.runs_cargo == false
      and $report.mutation_policy.runs_rch == false
      and $report.mutation_policy.sends_agent_mail == false
      and $report.mutation_policy.repairs_agent_mail_db == false
      and $report.mutation_policy.mutates_live_workers == false
    ' "$scenario_report" >/dev/null || {
      record_failure "report mismatch ${scenario_id}"
      jq . "$scenario_report" >&2
      return 1
    }
}

write_scenario_report() {
  local case_json="$1"
  local scenario_dir="$2"
  local scenario_id="$3"
  local scenario_report="${scenario_dir}/drill_report.json"
  local bridge_report="${scenario_dir}/steps/bridge/out/mail_outage_continuity_bridge.json"
  local handoff_report="${scenario_dir}/steps/handoff/out/swarm_handoff_capsule.json"
  local dashboard_report="${scenario_dir}/steps/dashboard/out/high_core_validation_pressure_dashboard.json"
  local completion_report="${scenario_dir}/steps/completion/out/completion_audit_report.json"

  jq -n \
    --arg schema_version "franken-engine.degraded-coordination-no-mock-drill.report.v1" \
    --arg scenario_id "$scenario_id" \
    --arg source_revision "$source_revision" \
    --slurpfile bridge "$bridge_report" \
    --slurpfile handoff "$handoff_report" \
    --slurpfile dashboard "$dashboard_report" \
    --slurpfile completion "$completion_report" \
    --arg bridge_report "$bridge_report" \
    --arg handoff_report "$handoff_report" \
    --arg dashboard_report "$dashboard_report" \
    --arg completion_report "$completion_report" \
    '
      ($bridge[0]) as $bridge_doc
      | ($handoff[0]) as $handoff_doc
      | ($dashboard[0]) as $dashboard_doc
      | ($completion[0]) as $completion_doc
      | {
          schema_version:$schema_version,
          scenario_id:$scenario_id,
          source_revision:$source_revision,
          overall_decision:(if $completion_doc.decision == "complete"
            and $bridge_doc.decision == "degraded"
            and $handoff_doc.decision == "degraded"
            and $dashboard_doc.recommendation == "split_file_blocker_bead"
            then "degraded_continue_source_only"
            else "blocked" end),
          components:{
            bridge:{
              decision:$bridge_doc.decision,
              mail_health_state:$bridge_doc.mail_health_state,
              summary:$bridge_doc.summary,
              reason_codes:([($bridge_doc.degraded_reasons[]?.code),($bridge_doc.blocked_reasons[]?.code)] | unique),
              artifact:$bridge_report
            },
            handoff:{
              decision:$handoff_doc.decision,
              ready_count:$handoff_doc.bead_state.ready_count,
              active_rch_count:$handoff_doc.rch_jobs.active_count,
              reason_codes:([($handoff_doc.degraded_reasons[]?.code),($handoff_doc.blocked_reasons[]?.code)] | unique),
              artifact:$handoff_report
            },
            dashboard:{
              recommendation:$dashboard_doc.recommendation,
              pressure_level:$dashboard_doc.pressure_level,
              reason_codes:([$dashboard_doc.pressure_reasons[]?.code] | unique),
              recommended_commands:$dashboard_doc.recommended_commands,
              artifact:$dashboard_report
            },
            completion:{
              decision:$completion_doc.decision,
              summary:$completion_doc.summary,
              artifact:$completion_report
            }
          },
          recommendations:[
            "Use br status and assignee as the coordination anchor while Agent Mail is red.",
            "Do not start heavy local Cargo or new RCH proof work from this drill.",
            "Keep work source-only until ready beads and coordination health are refreshed."
          ],
          mutation_policy:{
            advisory_only:true,
            proof_only:true,
            mutates_br:false,
            sends_agent_mail:false,
            repairs_agent_mail_db:false,
            queries_live_workers:false,
            mutates_live_workers:false,
            runs_cargo:false,
            runs_rch:false,
            reruns_component_commands_during_replay:false
          }
        }
    ' >"$scenario_report"

  assert_report_matches_expected "$case_json" "$scenario_report"
  jq -c . "$scenario_report" >>"$case_results_path"
}

verify_command_transcript_safe() {
  local transcript="$1"
  local pattern
  while IFS= read -r pattern; do
    if [[ -z "$pattern" ]]; then
      continue
    fi
    if grep -E "$pattern" "$transcript" >/dev/null 2>&1; then
      printf 'forbidden command pattern matched in %s: %s\n' "$transcript" "$pattern" >&2
      return 1
    fi
  done < <(jq -r '.forbidden_executed_command_patterns[]' "$contract_path")
}

run_case() {
  local case_json="$1"
  local scenario_id scenario_dir inputs_dir bridge_out handoff_out dashboard_out completion_out
  scenario_id="$(jq -r '.scenario_id' <<<"$case_json")"
  scenario_dir="${run_dir}/scenarios/${scenario_id}"
  inputs_dir="${scenario_dir}/inputs"
  bridge_out="${scenario_dir}/steps/bridge/out"
  handoff_out="${scenario_dir}/steps/handoff/out"
  dashboard_out="${scenario_dir}/steps/dashboard/out"
  completion_out="${scenario_dir}/steps/completion/out"
  mkdir -p "$bridge_out" "$handoff_out" "$dashboard_out" "$completion_out"

  write_component_inputs "$case_json" "$scenario_dir"

  run_step "$scenario_id" "bridge" "0" \
    "$bridge_script" \
    --mail-health-json "${inputs_dir}/bridge/mail_health.json" \
    --mail-bootstrap-json "${inputs_dir}/bridge/mail_bootstrap.json" \
    --agent-profiles-json "${inputs_dir}/bridge/agent_profiles.json" \
    --br-in-progress-json "${inputs_dir}/bridge/br_in_progress.json" \
    --git-status-json "${inputs_dir}/bridge/git_status.json" \
    --file-reservations-json "${inputs_dir}/bridge/file_reservations.json" \
    --source-revision "$source_revision" \
    --generated-epoch-seconds 1778418000 \
    --output-dir "$bridge_out"

  run_step "$scenario_id" "handoff" "0" \
    "$handoff_script" \
    --git-status-json "${inputs_dir}/handoff/git_status.json" \
    --br-state-json "${inputs_dir}/handoff/br_state.json" \
    --owned-paths-json "${inputs_dir}/handoff/owned_paths.json" \
    --recent-commits-json "${inputs_dir}/handoff/recent_commits.json" \
    --rch-jobs-json "${inputs_dir}/handoff/rch_jobs.json" \
    --validation-receipts-json "${inputs_dir}/handoff/validation_receipts.json" \
    --mail-health-json "${inputs_dir}/handoff/mail_health.json" \
    --operator-notes-json "${inputs_dir}/handoff/operator_notes.json" \
    --case-id "$scenario_id" \
    --source-revision "$source_revision" \
    --generated-epoch-seconds 1778418000 \
    --output-dir "$handoff_out"

  run_step "$scenario_id" "dashboard" "0" \
    "$dashboard_script" \
    --resource-envelope-json "${inputs_dir}/dashboard/resource_envelope.json" \
    --rch-jobs-json "${inputs_dir}/dashboard/rch_jobs.json" \
    --process-counts-json "${inputs_dir}/dashboard/process_counts.json" \
    --proof-shard-plan-json "${inputs_dir}/dashboard/proof_shard_plan.json" \
    --br-readiness-json "${inputs_dir}/dashboard/br_readiness.json" \
    --mail-health-json "${inputs_dir}/dashboard/mail_health.json" \
    --case-id "$scenario_id" \
    --source-revision "$source_revision" \
    --output-dir "$dashboard_out"

  write_completion_inputs "$scenario_id" "$scenario_dir"
  run_step "$scenario_id" "completion" "0" \
    "$completion_script" \
    --objective-json "${inputs_dir}/completion/objective.json" \
    --evidence-json "${inputs_dir}/completion/evidence.json" \
    --case-id "$scenario_id" \
    --source-revision "$source_revision" \
    --output-dir "$completion_out"

  write_scenario_report "$case_json" "$scenario_dir" "$scenario_id"
  write_event "$scenario_id" "drill" "scenario_complete" "pass" "${scenario_dir}/drill_report.json"
  record_pass "$scenario_id"
}

write_run_reports() {
  jq -s \
    --arg schema_version "franken-engine.degraded-coordination-no-mock-drill.aggregate-report.v1" \
    --arg source_revision "$source_revision" \
    '{
      schema_version:$schema_version,
      source_revision:$source_revision,
      scenario_count:length,
      overall_decision:(if all(.[]; .overall_decision == "degraded_continue_source_only") then "degraded_continue_source_only" else "blocked" end),
      scenarios:.
    }' "$case_results_path" >"$drill_report_path"

  jq -n \
    --arg schema_version "franken-engine.degraded-coordination-no-mock-drill.run-manifest.v1" \
    --arg source_revision "$source_revision" \
    --arg run_dir "$run_dir" \
    --arg events "$events_path" \
    --arg commands "$commands_path" \
    --arg report "$drill_report_path" \
    --arg cases "$case_results_path" \
    --arg fixtures "$fixtures_json" \
    '{
      schema_version:$schema_version,
      source_revision:$source_revision,
      run_dir:$run_dir,
      artifacts:{
        events_jsonl:$events,
        commands_txt:$commands,
        drill_report_json:$report,
        case_results_jsonl:$cases
      },
      fixture_bundle:$fixtures,
      component_invocation_count:4,
      replay_verification_only:false,
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        mutates_agent_mail:false,
        repairs_agent_mail_db:false,
        mutates_br:false,
        queries_live_workers:false,
        mutates_live_workers:false,
        runs_cargo:false,
        runs_rch:false
      }
    }' >"$run_manifest_path"
}

run_fixture() {
  local filter_expr
  ensure_run_dir
  jq empty "$fixtures_json"
  filter_expr='.cases[]'
  if [[ -n "$scenario_filter" ]]; then
    filter_expr=".cases[] | select(.scenario_id == \"${scenario_filter}\")"
  fi
  while IFS= read -r case_json; do
    run_case "$case_json"
  done < <(jq -c "$filter_expr" "$fixtures_json")
  if [[ ! -s "$case_results_path" ]]; then
    printf 'no degraded coordination drill scenarios matched\n' >&2
    exit 64
  fi
  verify_command_transcript_safe "$commands_path"
  write_run_reports
  record_pass "fixture"
}

latest_bundle_dir() {
  local parent="$1"
  find "$parent" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
    | sort -n \
    | awk 'END {print $2}'
}

run_replay() {
  if [[ -n "$latest_from" ]]; then
    replay_run_dir="$(latest_bundle_dir "$latest_from")"
  fi
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay requires --replay-run-dir or --latest-from\n' >&2
    exit 64
  fi
  run_dir="$replay_run_dir"
  refresh_paths
  for required in "$run_manifest_path" "$events_path" "$commands_path" "$drill_report_path"; do
    if [[ ! -f "$required" ]]; then
      printf 'replay bundle missing required artifact: %s\n' "$required" >&2
      exit 1
    fi
  done
  jq empty "$run_manifest_path" "$drill_report_path"
  if ! jq empty "$events_path" >/dev/null 2>&1; then
    printf 'events.jsonl is not valid JSONL: %s\n' "$events_path" >&2
    exit 1
  fi
  verify_command_transcript_safe "$commands_path"
  jq -e '
    .schema_version == "franken-engine.degraded-coordination-no-mock-drill.run-manifest.v1"
    and .component_invocation_count == 4
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_agent_mail == false
    and .mutation_policy.mutates_live_workers == false
  ' "$run_manifest_path" >/dev/null
  jq -e '
    .schema_version == "franken-engine.degraded-coordination-no-mock-drill.aggregate-report.v1"
    and .overall_decision == "degraded_continue_source_only"
    and .scenario_count >= 1
    and all(.scenarios[]; .overall_decision == "degraded_continue_source_only")
    and all(.scenarios[]; .mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false and .mutation_policy.sends_agent_mail == false)
  ' "$drill_report_path" >/dev/null
  record_pass "replay"
}

run_check() {
  jq empty "$contract_path" "$fixtures_json"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "${BASH_SOURCE[0]}"
  fi
  jq -e '
    .schema_version == "franken-engine.degraded-coordination-no-mock-drill-contract.v1"
    and .bead_id == "bd-y59d4"
    and (.required_outputs | sort) == ([
      "commands.txt",
      "drill_report.json",
      "events.jsonl",
      "run_manifest.json"
    ] | sort)
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_agent_mail == false
    and .mutation_policy.mutates_live_workers == false
    and (.composed_scripts | length) == 4
  ' "$contract_path" >/dev/null
  jq -e '
    .schema_version == "franken-engine.degraded-coordination-no-mock-drill-fixtures.v1"
    and ([.cases[].scenario_id] | index("agent_mail_red_zero_ready_dirty_active_rch") != null)
    and any(.cases[]; .expected.overall_decision == "degraded_continue_source_only")
  ' "$fixtures_json" >/dev/null
  grep -Fq "degraded_continue_source_only" "$docs_path"
  grep -Fq "run_manifest.json" "$docs_path"
  grep -Fq "does not repair Agent Mail" "$docs_path"
  record_pass "check"
}

run_selftest() {
  run_check
  run_fixture
  replay_run_dir="$run_dir"
  run_replay
  record_pass "selftest"
}

case "$mode" in
  fixture)
    run_fixture
    ;;
  replay)
    run_replay
    ;;
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
    printf 'unknown mode: %s\n' "$mode" >&2
    usage
    exit 64
    ;;
esac
