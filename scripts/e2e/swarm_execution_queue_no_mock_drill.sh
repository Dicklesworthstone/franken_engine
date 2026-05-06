#!/usr/bin/env bash
# shellcheck disable=SC2094
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-no-mock-drill}"
run_id="${SWARM_EXECUTION_QUEUE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_execution_queue_input_normalizer.sh"
conformance_gate="${root_dir}/scripts/e2e/swarm_execution_queue_conformance_gate.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_execution_queue_runbook_truth_gate.sh"
runner_bin="${FRANKEN_SWARM_EXECUTION_QUEUE_BIN:-}"

events_path=""
commands_path=""
manifest_path=""
report_md=""
failures=0

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the SWARM-CTRL-XII execution queue surfaces into one deterministic
no-mock drill. The drill creates fixture snapshots, runs the real input
normalizer, real Rust queue runner, real conformance gate, and real operator
status report, then emits a combined artifact bundle. It does not mutate br,
Agent Mail, file reservations, remote workers, or Cargo targets.

Modes:
  check       Syntax, truth-gate, fixture, and runner-availability checks.
  run         Run the composed drill and emit artifacts.
  selftest    Run check, run, and validate degraded-case assertions.

Options:
  --output-dir DIR
  --runner-bin FILE
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --runner-bin)
      runner_bin="${2:-}"
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
  printf 'PASS swarm-execution-queue-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_output_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  manifest_path="${run_dir}/drill_manifest.json"
  report_md="${run_dir}/report.md"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
}

resolve_runner() {
  if [[ -n "$runner_bin" ]]; then
    return
  fi
  if command -v franken_swarm_execution_queue >/dev/null 2>&1; then
    runner_bin="$(command -v franken_swarm_execution_queue)"
    return
  fi
  if [[ -n "${CARGO_TARGET_DIR:-}" && -x "${CARGO_TARGET_DIR%/}/debug/franken_swarm_execution_queue" ]]; then
    runner_bin="${CARGO_TARGET_DIR%/}/debug/franken_swarm_execution_queue"
  fi
}

require_runner() {
  resolve_runner
  if [[ -z "$runner_bin" || ! -x "$runner_bin" ]]; then
    printf 'FRANKEN_SWARM_EXECUTION_QUEUE_BIN must point to an executable franken_swarm_execution_queue binary\n' >&2
    exit 64
  fi
}

quote_command() {
  printf '%q ' "$@"
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-no-mock-drill.event.v1" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version: $schema_version,
      event_name: "swarm_execution_queue_no_mock_drill.step",
      step_id: $step_id,
      decision: $decision,
      exit_code: $exit_code,
      artifact_paths: {
        stdout_log: $stdout_path,
        stderr_log: $stderr_path
      }
    }' >>"$events_path"
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

run_step() {
  local step="$1"
  local expected_codes="$2"
  shift 2

  local step_dir="${run_dir}/${step}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code decision

  mkdir -p "$step_dir"
  {
    printf '%s: ' "$step"
    quote_command "$@"
    printf '\n'
  } >>"$commands_path"

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
    return "$exit_code"
  fi
}

write_operator_status_base_fixtures() {
  local fixture_dir="$1"

  mkdir -p "$fixture_dir"
  jq -n '[{id:"bd-ready-a", title:"Focused proof runner", priority:1, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"queue-lane", items:[{id:"bd-ready-a", title:"Focused proof runner", priority:1, status:"open"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"admit", findings:[]}' >"${fixture_dir}/resource_decision.json"
  jq -n '{
    decision:"admit",
    collision_risk:"none",
    risk_flags:[],
    conflicting_agents:[],
    safe_alternatives:["scripts/e2e/swarm_execution_queue_no_mock_drill.sh"],
    commands:[{
      command_id:"script-check",
      display:"bash -n scripts/e2e/swarm_execution_queue_no_mock_drill.sh",
      command_kind:"shell_syntax",
      predicted_cost:{
        schema_version:"franken-engine.swarm-validation-predicted-cost.v1",
        state:"static",
        cost_class:"low",
        sample_count:0,
        elapsed_ms_p50:0,
        elapsed_ms_max:0,
        compiled_target_count_max:0,
        linked_target_count_max:0
      },
      risk_flags:[],
      cost_evidence:{status:"not_required", matched_rows:0, fresh_rows:0, stale_rows:0}
    }],
    omitted_commands:[],
    proof_cost_budgets:[]
  }' >"${fixture_dir}/validation_plan.json"
  jq -n '{queries:[]}' >"${fixture_dir}/proof_index.json"
  jq -n '[{bead_id:"bd-ready-a", artifact_id:"queue-proof", status:"pass"}]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[]' >"${fixture_dir}/dirty_files.json"
  jq -n '{collision_risk:"none", conflicting_agents:[], safe_alternatives:["scripts/e2e/swarm_execution_queue_no_mock_drill.sh"], reservation_recommendations:[], conflicts:{reservations:[], dirty:[], in_progress:[]}}' >"${fixture_dir}/collision_receipt.json"
  jq -n '{schema_version:"franken-engine.proof-freshness-decay-report.v1", proof_artifact_id:"queue-proof-current", freshness_state:"fresh", reusable:true, reason:"queue drill proof is current", recommended_next_action:"Reuse the queue drill artifact.", covered_paths:["scripts/e2e/swarm_execution_queue_no_mock_drill.sh"], changed_paths:[]}' >"${fixture_dir}/proof_freshness.json"
  jq -n '{status:"not_provided", failure_kind:"none", retry_safety:"not_required", recommended_next_action:"No rch incident packet was provided."}' >"${fixture_dir}/rch_incident_packet.json"
  jq -n '{
    schema_version:"franken-engine.swarm-resource-lease-plan.v1",
    agent_id:"BrownCreek",
    bead_id:"bd-w9sxz",
    requested_command:"bash -n scripts/e2e/swarm_execution_queue_no_mock_drill.sh",
    target_dir:"/tmp/rch_target_franken_engine_queue_drill",
    lease_decision:"admit",
    lease_ttl_seconds:1800,
    reason:"script-only validation admitted",
    safe_alternatives:[],
    assigned_worker:"worker-fixture",
    findings:[{severity:"info", code:"lease_admitted", message:"script-only validation admitted"}]
  }' >"${fixture_dir}/resource_lease_plan.json"
  jq -n '{
    schema_version:"franken-engine.proof-reuse-cache-plan.v1",
    expected_source_revision:"drill-rev",
    proof_cache_decision:"cache_hit",
    reason:"queue drill artifacts are explicitly generated",
    cache_hit_artifacts:[],
    required_refreshes:[],
    invalid_artifacts:[],
    invalidated_paths:[],
    refresh_commands:[],
    summary:{cache_hit_count:0, refresh_count:0, invalid_count:0}
  }' >"${fixture_dir}/proof_cache_plan.json"
  jq -n '{
    schema_version:"franken-engine.build-storm-batch-plan.v1",
    batch_id:"queue-drill",
    batch_decision:"planned",
    fairness_reason:"script-only drill fits outside heavy capacity",
    max_parallel_heavy:1,
    retry_after_seconds:0,
    admitted_commands:[{request_id:"queue-drill-check", agent_id:"BrownCreek", bead_id:"bd-w9sxz", command:"bash -n scripts/e2e/swarm_execution_queue_no_mock_drill.sh", heavy:false, batch_decision:"admit", fairness_reason:"light validation"}],
    deferred_commands:[]
  }' >"${fixture_dir}/qos_batch_plan.json"
  jq -n '{schema_version:"franken-engine.stale-lock-recommendations.v1", stale_lock_recommendations:[], safe_to_reopen:[], contact_first:[]}' >"${fixture_dir}/stale_lock_recommendations.json"
  jq -n '{
    schema_version:"franken-engine.staged-ownership-report.v1",
    agent_id:"BrownCreek",
    bead_id:"bd-w9sxz",
    decision:"pass",
    staged_path_count:4,
    offender_count:0,
    scoped_beads_issue_ids:["bd-w9sxz"],
    offending_paths:[],
    findings:[]
  }' >"${fixture_dir}/staged_ownership_report.json"
  jq -n --arg artifact_path "${fixture_dir}/capacity_forecast.json" '{
    schema_version:"franken-engine.swarm-capacity-forecast.v1",
    decision:"admit",
    confidence_band:"high",
    summary:{overall_state:"nominal", blocked_categories:[], degraded_categories:[]},
    telemetry_summary:{snapshot_decision:"current_and_complete"},
    inputs:[],
    failures:[],
    forecasts:{compile_pressure:{state:"nominal", recommended_action:"No compile-pressure mitigation is required."}},
    artifact_paths:{swarm_capacity_forecast_json:$artifact_path}
  }' >"${fixture_dir}/capacity_forecast.json"
  jq -n --arg artifact_path "${fixture_dir}/admission_budget_plan.json" '{
    schema_version:"franken-engine.swarm-admission-budget-plan.v1",
    decision:"admit",
    budget_profile:"balanced",
    summary:{admitted_count:1, deferred_count:0},
    recommendations:[],
    artifact_paths:{swarm_admission_budget_plan_json:$artifact_path}
  }' >"${fixture_dir}/admission_budget_plan.json"
  jq -n --arg artifact_path "${fixture_dir}/lease_exchange_salvage_simulation.json" '{
    schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
    decision:"retain_current_assignments",
    summary:{manual_review_count:0, lease_exchange_candidate_count:0, salvage_promotion_candidate_count:0},
    upstream_summary:{archive_pressure_advisory:"retain", salvage_workflow_state:"clean_finished"},
    recommendations:[],
    artifact_paths:{lease_exchange_cancellation_salvage_simulation_json:$artifact_path}
  }' >"${fixture_dir}/lease_exchange_salvage_simulation.json"
  jq -n --arg artifact_path "${fixture_dir}/warm_target_prefetch_roi_advisory.json" '{
    schema_version:"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
    advisory:"prefetch_recommended",
    recommended_action:"Reuse the bounded queue drill target only after explicit proof.",
    reason:"fixture-only advisory",
    exit_code:0,
    budget_summary:{budget_profile:"balanced"},
    warm_target_summary:{target_dir:"/tmp/rch_target_franken_engine_queue_drill"},
    proof_cache_summary:{proof_cache_decision:"cache_hit"},
    archive_pressure_summary:{advisory:"retain"},
    validation_cost_summary:{estimated_cpu_slots_total:1},
    roi_summary:{expected_reuse_score:800000, realized_reuse_score:810000, reuse_delta:10000},
    artifact_paths:{warm_target_prefetch_roi_advisory_json:$artifact_path}
  }' >"${fixture_dir}/warm_target_prefetch_roi_advisory.json"
  jq -n --arg artifact_path "${fixture_dir}/starvation_rescue_plan.json" '{
    schema_version:"franken-engine.swarm-starvation-rescue-plan.v1",
    decision:"advisory",
    scenario_class:"nominal",
    summary:{recommendation_count:0, top_recommendation_action:null, readiness:"ready", brownout_finding_count:0, starvation_finding_count:0, safe_to_reopen_count:0, contact_first_count:0, lease_exchange_candidate_count:0, manual_review_count:0, ownership_fail_closed_count:0},
    policy_basis:{matched_case_ids:[], matched_case_count:0, required_scenario_classes:[]},
    recommendations:[],
    fail_closed_reasons:[],
    artifact_paths:{swarm_starvation_rescue_plan_json:$artifact_path}
  }' >"${fixture_dir}/starvation_rescue_plan.json"
  jq -n --arg artifact_path "${fixture_dir}/starvation_rescue_conformance_report.json" '{
    schema_version:"franken-engine.swarm-starvation-rescue-conformance-report.v1",
    decision:"pass",
    summary:{plan_decision:"advisory", escalation_band:"ready", top_recommendation_action:null, gate_failure_count:0},
    gate_failures:[],
    artifact_paths:{swarm_starvation_rescue_conformance_report_json:$artifact_path}
  }' >"${fixture_dir}/starvation_rescue_conformance_report.json"
}

write_checkpoint_restore_fixtures() {
  local fixture_dir="$1"
  local checkpoint_mode="$2"
  local capture_decision="captured"
  local restore_hint="ready"
  local plan_decision="resume"
  local drift_class="clean"
  local top_restore_action="resume_from_checkpoint"
  local checkpoint_age_seconds=600
  local fail_closed_reasons='[]'
  local drift_findings='[]'
  local conformance_decision="pass"
  local gate_failures='[]'

  case "$checkpoint_mode" in
    ready)
      ;;
    manual_review)
      capture_decision="captured_degraded"
      restore_hint="manual_review"
      plan_decision="advisory_manual_review"
      drift_class="soft"
      top_restore_action="review_salvage_pressure_before_resume"
      checkpoint_age_seconds=1950
      drift_findings='[{"kind":"salvage_manual_review","severity":"advisory","detail":"current salvage truth requires manual review before restore"}]'
      ;;
    blocked)
      capture_decision="captured_degraded"
      restore_hint="blocked"
      plan_decision="fail_closed"
      drift_class="blocked"
      top_restore_action="capture_fresh_checkpoint_bundle"
      checkpoint_age_seconds=7200
      fail_closed_reasons='[{"kind":"checkpoint_stale","detail":"checkpoint evidence exceeded freshness window"}]'
      conformance_decision="fail_closed"
      gate_failures='[{"code":"checkpoint_stale","detail":"checkpoint evidence exceeded freshness window"}]'
      ;;
    *)
      printf 'unknown checkpoint fixture mode: %s\n' "$checkpoint_mode" >&2
      exit 64
      ;;
  esac

  : >"${fixture_dir}/checkpoint_bundle.events.jsonl"
  : >"${fixture_dir}/checkpoint_restore_plan.events.jsonl"
  : >"${fixture_dir}/checkpoint_restore_conformance.events.jsonl"
  printf './scripts/swarm_checkpoint_bundle_packer.sh --fixture\n' >"${fixture_dir}/checkpoint_bundle.commands.txt"
  printf './scripts/swarm_checkpoint_restore_planner.sh --fixture\n' >"${fixture_dir}/checkpoint_restore_plan.commands.txt"
  printf './scripts/e2e/swarm_checkpoint_restore_conformance_gate_smoke.sh --fixture\n' >"${fixture_dir}/checkpoint_restore_conformance.commands.txt"
  printf 'checkpoint bundle fixture\n' >"${fixture_dir}/checkpoint_bundle.summary.md"
  printf 'checkpoint restore plan fixture\n' >"${fixture_dir}/checkpoint_restore_plan.report.md"
  printf 'checkpoint restore conformance fixture\n' >"${fixture_dir}/checkpoint_restore_conformance.report.md"

  jq -n \
    --arg artifact_path "${fixture_dir}/checkpoint_bundle.json" \
    --arg fixture_dir "$fixture_dir" \
    --arg capture_decision "$capture_decision" \
    --arg restore_hint "$restore_hint" \
    '{
      schema_version:"franken-engine.swarm-checkpoint-bundle.v1",
      checkpoint_id:"checkpoint-execution-queue-drill",
      capture_decision:$capture_decision,
      restore_readiness_hint:$restore_hint,
      captured_epoch_seconds:1700000000,
      stale_after_seconds:1800,
      upstream_evidence:{required_count:4, optional_count:0, optional_present_count:0},
      artifact_ledger:{},
      blockers:[],
      artifact_paths:{
        checkpoint_bundle_json:$artifact_path,
        events_jsonl:($fixture_dir + "/checkpoint_bundle.events.jsonl"),
        commands_txt:($fixture_dir + "/checkpoint_bundle.commands.txt"),
        summary_md:($fixture_dir + "/checkpoint_bundle.summary.md")
      }
    }' >"${fixture_dir}/checkpoint_bundle.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/checkpoint_restore_plan.json" \
    --arg fixture_dir "$fixture_dir" \
    --arg plan_decision "$plan_decision" \
    --arg drift_class "$drift_class" \
    --arg top_restore_action "$top_restore_action" \
    --argjson checkpoint_age_seconds "$checkpoint_age_seconds" \
    --argjson fail_closed_reasons "$fail_closed_reasons" \
    --argjson drift_findings "$drift_findings" \
    '{
      schema_version:"franken-engine.swarm-checkpoint-restore-plan.v1",
      checkpoint_id:"checkpoint-execution-queue-drill",
      decision:$plan_decision,
      exit_code:0,
      drift_class:$drift_class,
      summary:{
        top_restore_action:$top_restore_action,
        provided_current_comparison_count:4,
        missing_current_comparison_count:0,
        drift_count:($drift_findings | length),
        fail_closed_reason_count:($fail_closed_reasons | length)
      },
      drift_receipt:{
        checkpoint_age_seconds:$checkpoint_age_seconds,
        fail_closed_reasons:$fail_closed_reasons,
        findings:$drift_findings
      },
      resolved_inputs:[{input:"checkpoint_bundle_json", status:"provided", path:($fixture_dir + "/checkpoint_bundle.json"), schema_version:"franken-engine.swarm-checkpoint-bundle.v1"}],
      artifact_paths:{
        swarm_checkpoint_restore_plan_json:$artifact_path,
        events_jsonl:($fixture_dir + "/checkpoint_restore_plan.events.jsonl"),
        commands_txt:($fixture_dir + "/checkpoint_restore_plan.commands.txt"),
        report_md:($fixture_dir + "/checkpoint_restore_plan.report.md")
      }
    }' >"${fixture_dir}/checkpoint_restore_plan.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/checkpoint_restore_conformance_report.json" \
    --arg fixture_dir "$fixture_dir" \
    --arg conformance_decision "$conformance_decision" \
    --arg plan_decision "$plan_decision" \
    --arg capture_decision "$capture_decision" \
    --arg top_restore_action "$top_restore_action" \
    --argjson gate_failures "$gate_failures" \
    '{
      schema_version:"franken-engine.swarm-checkpoint-restore-conformance-report.v1",
      decision:$conformance_decision,
      summary:{
        restore_decision:$plan_decision,
        checkpoint_capture_decision:$capture_decision,
        top_restore_action:$top_restore_action,
        gate_failure_count:($gate_failures | length),
        checked_artifact_path_count:4
      },
      gate_failures:$gate_failures,
      resolved_sources:{
        checkpoint_bundle_json:{path:($fixture_dir + "/checkpoint_bundle.json"), schema_version:"franken-engine.swarm-checkpoint-bundle.v1"},
        checkpoint_restore_plan_json:{path:($fixture_dir + "/checkpoint_restore_plan.json"), schema_version:"franken-engine.swarm-checkpoint-restore-plan.v1"}
      },
      artifact_paths:{
        swarm_checkpoint_restore_conformance_report_json:$artifact_path,
        events_jsonl:($fixture_dir + "/checkpoint_restore_conformance.events.jsonl"),
        commands_txt:($fixture_dir + "/checkpoint_restore_conformance.commands.txt"),
        report_md:($fixture_dir + "/checkpoint_restore_conformance.report.md")
      }
    }' >"${fixture_dir}/checkpoint_restore_conformance_report.json"
}

write_normalizer_snapshots() {
  local fixture_dir="$1"
  local case_name="$2"

  mkdir -p "$fixture_dir"
  case "$case_name" in
    healthy|checkpoint_restore_manual_review)
      jq -n '[{id:"bd-ready-a", title:"Implement focused proof runner", status:"open", priority:1, assignee:null, dependencies:[], dependents:["bd-parent"]}]' >"${fixture_dir}/br_ready.json"
      jq -n '{issues:[{id:"bd-ready-a", title:"Implement focused proof runner", status:"open", priority:1, assignee:null, dependencies:[], dependents:["bd-parent"]},{id:"bd-parent", title:"Parent closeout", status:"open", priority:2, assignee:null, dependencies:["bd-ready-a"], dependents:[]}]}' >"${fixture_dir}/br_list.json"
      jq -n '{plan:{tracks:[{track_id:"queue", items:[{id:"bd-ready-a", title:"Implement focused proof runner", status:"open", priority:1, unblocks:["bd-parent"]}]}]}}' >"${fixture_dir}/bv_plan.json"
      jq -n '{agents:[], messages:[]}' >"${fixture_dir}/agent_mail.json"
      jq -n '{reservations:[]}' >"${fixture_dir}/reservations.json"
      jq -n '{schema_version:"franken-engine.stale-lock-recommendations.v1", stale_lock_recommendations:[], safe_to_reopen:[], contact_first:[]}' >"${fixture_dir}/stale.json"
      jq -n '{schema_version:"franken-engine.proof-transport-health.v1", state:"remote_only_ok", local_fallback_detected:false, risk_budget:{remaining_millionths:900000, consumed_millionths:100000, conservative_threshold_millionths:200000}}' >"${fixture_dir}/proof.json"
      ;;
    stale_owner_recent_reservation)
      jq -n '[{id:"bd-stale-owner", title:"Resume stalled queue lane", status:"in_progress", priority:1, assignee:"DormantAgent", dependencies:[], dependents:[]}]' >"${fixture_dir}/br_ready.json"
      jq -n '{issues:[{id:"bd-stale-owner", title:"Resume stalled queue lane", status:"in_progress", priority:1, assignee:"DormantAgent", dependencies:[], dependents:[]}]}' >"${fixture_dir}/br_list.json"
      jq -n '{plan:{tracks:[{track_id:"queue", items:[{id:"bd-stale-owner", title:"Resume stalled queue lane", status:"in_progress", priority:1}]}]}}' >"${fixture_dir}/bv_plan.json"
      jq -n '{agents:[{name:"DormantAgent", last_active_age_seconds:90000},{name:"RecentHolder", last_active_age_seconds:120}], messages:[]}' >"${fixture_dir}/agent_mail.json"
      jq -n '{reservations:[{id:7001, path_pattern:"scripts/e2e/swarm_execution_queue_no_mock_drill.sh", agent_name:"RecentHolder", reason:"bd-stale-owner", exclusive:true}]}' >"${fixture_dir}/reservations.json"
      jq -n '{schema_version:"franken-engine.stale-lock-recommendations.v1", stale_lock_recommendations:[{bead_id:"bd-stale-owner", safe_to_reopen:true, recommendation:"safe_to_reopen_after_contact", reason:"owner stale but recent reservation is present"}], safe_to_reopen:["bd-stale-owner"], contact_first:[]}' >"${fixture_dir}/stale.json"
      jq -n '{schema_version:"franken-engine.proof-transport-health.v1", state:"remote_only_ok", local_fallback_detected:false, risk_budget:{remaining_millionths:720000, consumed_millionths:280000, conservative_threshold_millionths:200000}}' >"${fixture_dir}/proof.json"
      ;;
    proof_transport_brownout)
      jq -n '[{id:"bd-brownout-ready", title:"Broad proof lane during brownout", status:"open", priority:2, assignee:null, dependencies:[], dependents:[]}]' >"${fixture_dir}/br_ready.json"
      jq -n '{issues:[{id:"bd-brownout-ready", title:"Broad proof lane during brownout", status:"open", priority:2, assignee:null, dependencies:[], dependents:[]}]}' >"${fixture_dir}/br_list.json"
      jq -n '{plan:{tracks:[{track_id:"queue", items:[{id:"bd-brownout-ready", title:"Broad proof lane during brownout", status:"open", priority:2}]}]}}' >"${fixture_dir}/bv_plan.json"
      jq -n '{agents:[], messages:[]}' >"${fixture_dir}/agent_mail.json"
      jq -n '{reservations:[]}' >"${fixture_dir}/reservations.json"
      jq -n '{schema_version:"franken-engine.stale-lock-recommendations.v1", stale_lock_recommendations:[], safe_to_reopen:[], contact_first:[]}' >"${fixture_dir}/stale.json"
      jq -n '{schema_version:"franken-engine.proof-transport-health.v1", state:"brownout", local_fallback_detected:false, risk_budget:{remaining_millionths:180000, consumed_millionths:820000, conservative_threshold_millionths:200000}}' >"${fixture_dir}/proof.json"
      ;;
    malformed_graph)
      jq -n '{"issues":{}}' >"${fixture_dir}/br_ready.json"
      jq -n '{"issues":{}}' >"${fixture_dir}/br_list.json"
      jq -n '{plan:{tracks:[]}}' >"${fixture_dir}/bv_plan.json"
      jq -n '{agents:[], messages:[]}' >"${fixture_dir}/agent_mail.json"
      jq -n '{reservations:[]}' >"${fixture_dir}/reservations.json"
      jq -n '{schema_version:"franken-engine.stale-lock-recommendations.v1", stale_lock_recommendations:[], safe_to_reopen:[], contact_first:[]}' >"${fixture_dir}/stale.json"
      jq -n '{schema_version:"franken-engine.proof-transport-health.v1", state:"remote_only_ok", local_fallback_detected:false}' >"${fixture_dir}/proof.json"
      ;;
    *)
      printf 'unknown normalizer fixture case: %s\n' "$case_name" >&2
      exit 64
      ;;
  esac
}

run_normalizer_case() {
  local case_name="$1"
  local expected_codes="$2"
  local case_dir="${run_dir}/${case_name}"
  local fixtures="${case_dir}/input-fixtures"
  local input_dir="${case_dir}/normalized"

  write_normalizer_snapshots "$fixtures" "$case_name"
  run_step "${case_name}-normalize" "$expected_codes" \
    bash "$normalizer" \
    --br-ready-json "${fixtures}/br_ready.json" \
    --br-list-json "${fixtures}/br_list.json" \
    --bv-actionable-plan-json "${fixtures}/bv_plan.json" \
    --agent-mail-activity-json "${fixtures}/agent_mail.json" \
    --file-reservations-json "${fixtures}/reservations.json" \
    --stale-lock-recommendations-json "${fixtures}/stale.json" \
    --proof-transport-health-json "${fixtures}/proof.json" \
    --source-revision "drill-${case_name}" \
    --generated-epoch-seconds 1800000000 \
    --stale-after-seconds 3600 \
    --output-dir "$input_dir"
}

run_runner_case() {
  local case_name="$1"
  local expected_codes="$2"
  local input_path="${run_dir}/${case_name}/normalized/normalized_input.json"
  local output_dir="${run_dir}/${case_name}/runner"

  mkdir -p "$output_dir"
  run_step "${case_name}-runner" "$expected_codes" \
    "$runner_bin" \
    --normalized-input-json "$input_path" \
    --output-dir "$output_dir" \
    --queue-depth 8 \
    --epoch 7 \
    --timestamp-ns 777
}

run_operator_case() {
  local case_name="$1"
  local checkpoint_mode="$2"
  local case_dir="${run_dir}/${case_name}"
  local fixture_dir="${case_dir}/operator-fixtures"
  local status_dir="${case_dir}/status"

  write_operator_status_base_fixtures "$fixture_dir"
  write_checkpoint_restore_fixtures "$fixture_dir" "$checkpoint_mode"
  run_step "${case_name}-operator-status" "0" \
    bash "$operator_status" \
    --bead-id bd-w9sxz \
    --source-revision "drill-${case_name}" \
    --output-dir "$status_dir" \
    --agent-mail-status ok \
    --rch-status ok \
    --proof-index-status ok \
    --ready-json "${fixture_dir}/ready.json" \
    --in-progress-json "${fixture_dir}/in_progress.json" \
    --bv-plan-json "${fixture_dir}/bv_plan.json" \
    --reservations-json "${fixture_dir}/reservations.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --validation-plan-json "${fixture_dir}/validation_plan.json" \
    --proof-index-json "${fixture_dir}/proof_index.json" \
    --proof-outcomes-json "${fixture_dir}/proof_outcomes.json" \
    --stale-evidence-json "${fixture_dir}/stale_evidence.json" \
    --dirty-files-json "${fixture_dir}/dirty_files.json" \
    --collision-receipt-json "${fixture_dir}/collision_receipt.json" \
    --proof-freshness-json "${fixture_dir}/proof_freshness.json" \
    --rch-incident-packet-json "${fixture_dir}/rch_incident_packet.json" \
    --resource-lease-plan-json "${fixture_dir}/resource_lease_plan.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache_plan.json" \
    --qos-batch-plan-json "${fixture_dir}/qos_batch_plan.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --staged-ownership-report-json "${fixture_dir}/staged_ownership_report.json" \
    --capacity-forecast-json "${fixture_dir}/capacity_forecast.json" \
    --admission-budget-plan-json "${fixture_dir}/admission_budget_plan.json" \
    --lease-exchange-salvage-simulation-json "${fixture_dir}/lease_exchange_salvage_simulation.json" \
    --warm-target-prefetch-roi-advisory-json "${fixture_dir}/warm_target_prefetch_roi_advisory.json" \
    --starvation-rescue-plan-json "${fixture_dir}/starvation_rescue_plan.json" \
    --starvation-rescue-conformance-report-json "${fixture_dir}/starvation_rescue_conformance_report.json" \
    --checkpoint-bundle-json "${fixture_dir}/checkpoint_bundle.json" \
    --checkpoint-restore-plan-json "${fixture_dir}/checkpoint_restore_plan.json" \
    --checkpoint-restore-conformance-report-json "${fixture_dir}/checkpoint_restore_conformance_report.json" \
    --execution-queue-artifact-json "${case_dir}/runner/execution_queue_artifact.json" \
    --execution-queue-risk-budget-json "${case_dir}/runner/risk_budget_receipt.json" \
    --execution-queue-bottleneck-report-json "${case_dir}/runner/bottleneck_report.json" \
    --execution-queue-run-manifest-json "${case_dir}/runner/run_manifest.json"
}

assert_case_json() {
  local case_name="$1"
  local description="$2"
  local jq_filter="$3"
  local status_path="${run_dir}/${case_name}/status/status.json"

  if jq -e "$jq_filter" "$status_path" >/dev/null; then
    record_pass "${case_name} ${description}"
  else
    record_failure "${case_name} ${description}"
  fi
}

write_manifest() {
  local source_revision
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"

  jq -n \
    --arg schema_version "franken-engine.swarm-execution-queue-no-mock-drill.v1" \
    --arg bead_id "bd-w9sxz" \
    --arg source_revision "$source_revision" \
    --arg runner_bin "$runner_bin" \
    --arg run_dir "$run_dir" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      parent_bead_id: "bd-g347f",
      source_revision: $source_revision,
      runner_binary: $runner_bin,
      covered_cases: [
        "healthy",
        "stale_owner_recent_reservation",
        "proof_transport_brownout",
        "checkpoint_restore_manual_review",
        "cycle_rejection",
        "malformed_graph_rejection"
      ],
      real_chain: [
        "scripts/swarm_execution_queue_input_normalizer.sh",
        "franken_swarm_execution_queue",
        "scripts/e2e/swarm_execution_queue_conformance_gate.sh",
        "scripts/swarm_operator_status_report.sh"
      ],
      artifact_paths: {
        run_dir: $run_dir,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md,
        healthy_normalized_input_json: ($run_dir + "/healthy/normalized/normalized_input.json"),
        healthy_execution_queue_artifact_json: ($run_dir + "/healthy/runner/execution_queue_artifact.json"),
        healthy_status_json: ($run_dir + "/healthy/status/status.json"),
        stale_owner_status_json: ($run_dir + "/stale_owner_recent_reservation/status/status.json"),
        proof_brownout_status_json: ($run_dir + "/proof_transport_brownout/status/status.json"),
        checkpoint_manual_review_status_json: ($run_dir + "/checkpoint_restore_manual_review/status/status.json"),
        cycle_rejection_stderr_log: ($run_dir + "/cycle_rejection-runner/stderr.log"),
        malformed_graph_normalized_input_json: ($run_dir + "/malformed_graph/normalized/normalized_input.json")
      },
      mutation_policy: {
        mutates_br: false,
        reassigns_beads: false,
        releases_reservations: false,
        sends_agent_mail: false,
        mutates_remote_workers: false
      }
    }' >"$manifest_path"
}

write_report() {
  {
    printf '# Swarm Execution Queue No-Mock Drill\n\n'
    printf -- "- Run dir: \`%s\`\n" "$run_dir"
    printf -- "- Runner: \`%s\`\n" "$runner_bin"
    printf -- "- Manifest: \`%s\`\n" "$manifest_path"
    printf -- "- Events: \`%s\`\n" "$events_path"
    printf -- "- Commands: \`%s\`\n\n" "$commands_path"
    printf '## Case Artifacts\n'
    jq -r '.artifact_paths | to_entries[] | select(.key != "run_dir") | "- `" + .key + "`: `" + (.value | tostring) + "`"' "$manifest_path"
  } >"$report_md"
}

run_check() {
  refresh_output_paths
  ensure_run_dir
  require_runner

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$normalizer"
  bash -n "$conformance_gate"
  bash -n "$operator_status"
  bash -n "$truth_gate"
  jq empty "${root_dir}/docs/swarm_execution_queue_runbook_truth_contract_v1.json" >/dev/null
  bash "$truth_gate" check >/dev/null
  record_pass "syntax truth gate and runner availability"
}

run_mode() {
  refresh_output_paths
  ensure_run_dir
  require_runner

  printf './scripts/e2e/swarm_execution_queue_no_mock_drill.sh %q --output-dir %q --runner-bin %q\n' "$mode" "$run_dir" "$runner_bin" >"$commands_path"

  run_step "conformance-gate" "0" bash "$conformance_gate" check

  run_normalizer_case "healthy" "0"
  run_runner_case "healthy" "0"
  run_operator_case "healthy" "ready"

  run_normalizer_case "stale_owner_recent_reservation" "0"
  run_runner_case "stale_owner_recent_reservation" "0"
  run_operator_case "stale_owner_recent_reservation" "ready"

  run_normalizer_case "proof_transport_brownout" "0"
  run_runner_case "proof_transport_brownout" "0"
  run_operator_case "proof_transport_brownout" "ready"

  run_normalizer_case "checkpoint_restore_manual_review" "0"
  run_runner_case "checkpoint_restore_manual_review" "0"
  run_operator_case "checkpoint_restore_manual_review" "manual_review"

  run_step "cycle_rejection-runner" "42" \
    "$runner_bin" \
    --normalized-input-json "${root_dir}/scripts/testdata/swarm_execution_queue/cyclic_input.json" \
    --output-dir "${run_dir}/cycle_rejection/runner" \
    --queue-depth 8 \
    --epoch 7 \
    --timestamp-ns 777

  run_normalizer_case "malformed_graph" "42"

  write_manifest
  write_report
  record_pass "drill artifacts ${run_dir}"
}

run_selftest() {
  run_check
  run_mode

  assert_case_json "healthy" "clear ready queue" '
    .predictive_dashboard.execution_queue_advisory.decision == "pass"
    and .predictive_dashboard.execution_queue_advisory.conservative_mode == false
    and .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "clear"
    and (.predictive_dashboard.execution_queue_advisory.top_recommended_starts | map(.task_id) | index("bd-ready-a"))
  '
  assert_case_json "stale_owner_recent_reservation" "contact/reopen evidence" '
    .predictive_dashboard.execution_queue_advisory.decision == "degraded"
    and (.predictive_dashboard.execution_queue_advisory.deferred_items | map(select(.task_id == "bd-stale-owner" and .fallback_trigger == "contact_or_reopen_required")) | length) == 1
  '
  assert_case_json "proof_transport_brownout" "conservative mode" '
    .predictive_dashboard.execution_queue_advisory.decision == "degraded"
    and .predictive_dashboard.execution_queue_advisory.conservative_mode == true
    and .predictive_dashboard.execution_queue_advisory.risk_budget.remaining_millionths == 180000
  '
  assert_case_json "checkpoint_restore_manual_review" "restore manual review blocker" '
    .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "restore_manual_review"
    and (.predictive_dashboard.execution_queue_advisory.restore_dependency_detail | test("manual review"))
    and (.recommendations | any(.action == "review_checkpoint_restore_handoff" or .action == "review_restore_before_queue"))
  '

  if grep -Fq "cycle detected" "${run_dir}/cycle_rejection-runner/stderr.log"; then
    record_pass "cycle rejection stderr"
  else
    record_failure "cycle rejection stderr"
  fi

  if jq -e '.decision == "fail_closed" and (.fail_closed_reasons | any(.kind == "malformed_required_shape"))' "${run_dir}/malformed_graph/normalized/normalized_input.json" >/dev/null; then
    record_pass "malformed graph rejection"
  else
    record_failure "malformed graph rejection"
  fi

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-no-mock-drill.v1"
    and .bead_id == "bd-w9sxz"
    and (.covered_cases | index("checkpoint_restore_manual_review"))
    and .mutation_policy.mutates_br == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$manifest_path" >/dev/null || record_failure "manifest shape"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'swarm_execution_queue_no_mock_drill_artifacts=%s\n' "$run_dir"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_mode
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
