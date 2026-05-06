#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="${SWARM_ADMISSION_DRILL_FIXTURE_DIR:-${root_dir}/scripts/testdata/swarm_admission_drill}"
artifact_root="${SWARM_ADMISSION_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-admission-drill}"
run_id="${SWARM_ADMISSION_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_ADMISSION_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_admission_drill.sh [check|run|selftest|replay] [OPTIONS]

Runs a no-mock SWARM-CTRL-III admission drill using checked-in fixtures and the
real shell gates from the sibling beads. The drill does not execute heavy proof
commands; it only verifies admission planning and replay artifacts.

Modes:
  check       Syntax, fixture, and rch-policy checks.
  run         Run the child gates and emit a combined drill report.
  selftest    Run check, run, then replay the generated bundle.
  replay      Revalidate an existing artifact bundle without rerunning gates.

Options:
  --output-dir DIR
  --fixture-dir DIR
  --artifact-dir DIR    Required for replay unless replaying --output-dir.
EOF
}

replay_dir=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --fixture-dir)
      fixture_dir="${2:-}"
      shift 2
      ;;
    --artifact-dir)
      replay_dir="${2:-}"
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

report_json="${run_dir}/swarm_admission_drill_report.json"
report_tmp="${report_json}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"

record_pass() {
  printf 'PASS swarm-admission-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-admission-drill %s\n' "$1" >&2
}

require_fixture() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf 'missing fixture: %s\n' "$path" >&2
    exit 64
  fi
  jq empty "$path" >/dev/null
}

write_command_log() {
  printf './scripts/e2e/swarm_admission_drill.sh %q' "$mode" >"$commands_path"
  printf ' --fixture-dir %q --output-dir %q\n' "$fixture_dir" "$run_dir" >>"$commands_path"
}

check_mode() {
  local scope_file

  bash -n "${BASH_SOURCE[0]}"
  test -f "${root_dir}/docs/SWARM_ADMISSION_DRILL.md"
  require_fixture "${fixture_dir}/agents.json"
  require_fixture "${fixture_dir}/workers.json"
  require_fixture "${fixture_dir}/reservations.json"
  require_fixture "${fixture_dir}/br_in_progress.json"
  require_fixture "${fixture_dir}/dirty_files.json"
  require_fixture "${fixture_dir}/proof_index.json"
  require_fixture "${fixture_dir}/freshness_hit.json"
  require_fixture "${fixture_dir}/freshness_stale.json"
  require_fixture "${fixture_dir}/qos_pending_requests.json"
  require_fixture "${fixture_dir}/qos_resource_leases.json"
  require_fixture "${fixture_dir}/qos_cost_history.json"
  require_fixture "${fixture_dir}/stale_agents.json"
  require_fixture "${fixture_dir}/stale_threads.json"
  require_fixture "${fixture_dir}/stale_reservations.json"
  require_fixture "${fixture_dir}/stale_git_activity.json"
  require_fixture "${fixture_dir}/staged_contaminated.json"
  jq -e '(.agents | length) >= 20' "${fixture_dir}/agents.json" >/dev/null

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-admission-drill-rch-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/swarm_admission_drill.sh" \
    "docs/SWARM_ADMISSION_DRILL.md" \
    "scripts/testdata/swarm_admission_drill/agents.json" \
    "scripts/testdata/swarm_admission_drill/qos_pending_requests.json" \
    "scripts/testdata/swarm_admission_drill/qos_resource_leases.json" \
    "scripts/testdata/swarm_admission_drill/proof_index.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-admission-drill-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax fixtures and rch policy"
}

run_mode() {
  local resource_dir proof_dir qos_dir stale_dir contaminated_dir
  local contamination_exit contamination_output

  mkdir -p "$run_dir"
  : >"$events_path"
  write_command_log

  resource_dir="${run_dir}/resource-lease"
  proof_dir="${run_dir}/proof-reuse"
  qos_dir="${run_dir}/qos-batch"
  stale_dir="${run_dir}/stale-lock"
  contaminated_dir="${run_dir}/staged-contamination"

  "${root_dir}/scripts/swarm_resource_lease_planner.sh" \
    --agent-id AgentAlpha \
    --bead-id bd-p1-proof-alpha \
    --requested-command "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_admission_alpha cargo test -p frankenengine-engine --test semantic_dark_matter_pipeline -- --nocapture" \
    --estimated-cpu-slots 4 \
    --estimated-memory-class large \
    --target-dir /tmp/rch_target_franken_engine_admission_alpha \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --br-snapshot-json "${fixture_dir}/br_in_progress.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --dirty-files-json "${fixture_dir}/dirty_files.json" \
    --output-dir "$resource_dir" >/dev/null

  "${root_dir}/scripts/proof_reuse_cache_planner.sh" \
    --proof-index-json "${fixture_dir}/proof_index.json" \
    --expected-source-revision current-rev \
    --freshness-report "${fixture_dir}/freshness_hit.json" \
    --freshness-report "${fixture_dir}/freshness_stale.json" \
    --output-dir "$proof_dir" >/dev/null

  "${root_dir}/scripts/build_storm_qos_batch_planner.sh" \
    --pending-requests-json "${fixture_dir}/qos_pending_requests.json" \
    --resource-lease-plans-json "${fixture_dir}/qos_resource_leases.json" \
    --proof-cost-history-json "${fixture_dir}/qos_cost_history.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --max-parallel-heavy 3 \
    --max-per-agent-heavy 1 \
    --output-dir "$qos_dir" >/dev/null

  "${root_dir}/scripts/stale_lock_stalled_bead_recommender.sh" \
    --in-progress-json "${fixture_dir}/br_in_progress.json" \
    --agent-profiles-json "${fixture_dir}/stale_agents.json" \
    --thread-timestamps-json "${fixture_dir}/stale_threads.json" \
    --file-reservations-json "${fixture_dir}/stale_reservations.json" \
    --git-activity-json "${fixture_dir}/stale_git_activity.json" \
    --now-epoch-seconds 100000 \
    --stale-owner-seconds 1000 \
    --output-dir "$stale_dir" >/dev/null

  set +e
  contamination_output="$(
    "${root_dir}/scripts/staged_ownership_contamination_guard.sh" \
      --agent-id AgentAlpha \
      --bead-id bd-p1-proof-alpha \
      --allowed-path scripts/e2e/swarm_admission_drill.sh \
      --reservation-snapshot-json "${fixture_dir}/reservations.json" \
      --staged-name-status-json "${fixture_dir}/staged_contaminated.json" \
      --output-dir "$contaminated_dir" 2>&1
  )"
  contamination_exit=$?
  set -e
  if [[ "$contamination_exit" -ne 42 ]]; then
    record_failure "expected staged contamination rejection, got exit ${contamination_exit}"
    printf '%s\n' "$contamination_output" >&2
    return 1
  fi

  jq -n \
    --arg schema_version "franken-engine.swarm-admission-drill-report.v1" \
    --arg resource_plan "${resource_dir}/resource_lease_plan.json" \
    --arg proof_plan "${proof_dir}/proof_cache_plan.json" \
    --arg qos_plan "${qos_dir}/build_storm_batch_plan.json" \
    --arg stale_report "${stale_dir}/stale_lock_recommendations.json" \
    --arg contamination_report "${contaminated_dir}/staged_ownership_report.json" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    --arg report_json "$report_json" \
    --slurpfile resource "${resource_dir}/resource_lease_plan.json" \
    --slurpfile proof "${proof_dir}/proof_cache_plan.json" \
    --slurpfile qos "${qos_dir}/build_storm_batch_plan.json" \
    --slurpfile stale "${stale_dir}/stale_lock_recommendations.json" \
    --slurpfile contamination "${contaminated_dir}/staged_ownership_report.json" \
    '{
      schema_version: $schema_version,
      drill_decision: "pass",
      child_artifacts: {
        resource_lease_plan_json: $resource_plan,
        proof_cache_plan_json: $proof_plan,
        build_storm_batch_plan_json: $qos_plan,
        stale_lock_recommendations_json: $stale_report,
        staged_ownership_report_json: $contamination_report
      },
      drill_observations: {
        admitted_heavy_proof: ($resource[0].lease_decision == "admit"),
        proof_cache_hit: (($proof[0].cache_hit_artifacts | length) >= 1),
        stale_proof_refresh: (($proof[0].required_refreshes | length) >= 1),
        deferred_noisy_agent: (any($qos[0].deferred_commands[]?; .fairness_reason | contains("agent fairness throttle"))),
        stale_lock_contact_first: (($stale[0].contact_first | length) >= 1),
        staged_contamination_rejection: ($contamination[0].decision == "fail_closed")
      },
      summary: {
        admitted_commands: ($qos[0].admitted_commands | length),
        deferred_commands: ($qos[0].deferred_commands | length),
        cache_hits: ($proof[0].cache_hit_artifacts | length),
        refreshes: ($proof[0].required_refreshes | length),
        stale_contact_first: ($stale[0].contact_first | length),
        contamination_offenders: ($contamination[0].offending_paths | length)
      },
      artifact_paths: {
        swarm_admission_drill_report_json: $report_json,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      }
    }' \
    >"$report_tmp"
  mv "$report_tmp" "$report_json"

  jq -e '
    [.drill_observations[]] | all
  ' "$report_json" >/dev/null

  jq -nc \
    --arg schema_version "franken-engine.swarm-admission-drill-event.v1" \
    --arg event_name "swarm_admission_drill.completed" \
    --arg report_json "$report_json" \
    '{schema_version:$schema_version,event_name:$event_name,report_json:$report_json,decision:"pass"}' \
    >>"$events_path"

  {
    printf '# Swarm Admission Drill\n\n'
    printf "%s\n" "- Decision: \`pass\`"
    printf "%s\n" "- Admitted commands: \`$(jq '.summary.admitted_commands' "$report_json")\`"
    printf "%s\n" "- Deferred commands: \`$(jq '.summary.deferred_commands' "$report_json")\`"
    printf "%s\n" "- Cache hits: \`$(jq '.summary.cache_hits' "$report_json")\`"
    printf "%s\n" "- Refreshes: \`$(jq '.summary.refreshes' "$report_json")\`"
    printf "%s\n" "- Contamination offenders: \`$(jq '.summary.contamination_offenders' "$report_json")\`"
  } >"$report_md"

  record_pass "run artifacts ${run_dir}"
}

replay_mode() {
  local artifact_dir="${replay_dir:-$run_dir}"
  local replay_report="${artifact_dir}/swarm_admission_drill_report.json"

  if [[ ! -f "$replay_report" ]]; then
    printf 'missing replay report: %s\n' "$replay_report" >&2
    exit 64
  fi
  jq -e '
    .schema_version == "franken-engine.swarm-admission-drill-report.v1"
    and .drill_decision == "pass"
    and ([.drill_observations[]] | all)
    and (.child_artifacts.resource_lease_plan_json | length > 0)
    and (.child_artifacts.proof_cache_plan_json | length > 0)
    and (.child_artifacts.build_storm_batch_plan_json | length > 0)
    and (.child_artifacts.stale_lock_recommendations_json | length > 0)
    and (.child_artifacts.staged_ownership_report_json | length > 0)
  ' "$replay_report" >/dev/null
  while IFS= read -r child_path; do
    test -f "$child_path"
    jq empty "$child_path" >/dev/null
  done < <(jq -r '.child_artifacts[]' "$replay_report")
  record_pass "replay ${artifact_dir}"
}

case "$mode" in
  check)
    check_mode
    ;;
  run)
    check_mode
    run_mode
    ;;
  selftest)
    check_mode
    run_mode
    replay_dir="$run_dir"
    replay_mode
    ;;
  replay)
    replay_mode
    ;;
  *)
    usage
    exit 64
    ;;
esac
