#!/usr/bin/env bash
# shellcheck disable=SC2094
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
reporter="${root_dir}/scripts/swarm_operator_status_report.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"
contract_doc="${root_dir}/docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"
contract_json="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"

record_pass() {
  printf 'PASS swarm-operator-status %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-operator-status %s\n' "$1" >&2
}

canonicalize_status() {
  local status_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
    | del(.artifact_paths)
  ' "$status_path"
}

compare_case_golden() {
  local case_name="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_name}"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_name}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches ${case_name}"
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"

  sed "s#${tmp_root}#[SMOKE_ROOT]#g" "$report_path"
}

write_predictive_extension_fixtures() {
  local fixture_dir="$1"

  jq -n --arg artifact_path "${fixture_dir}/capacity_forecast.json" '{
    schema_version:"franken-engine.swarm-capacity-forecast.v1",
    decision:"admit",
    confidence_band:"high",
    summary:{overall_state:"nominal", blocked_categories:[], degraded_categories:[]},
    telemetry_summary:{snapshot_decision:"current_and_complete"},
    inputs:[
      {input:"telemetry_snapshot_json", status:"provided", schema_version:"franken-engine.swarm-capacity-snapshot.v1"},
      {input:"validation_plan_json", status:"provided", schema_version:"franken-engine.swarm-validation-plan.v1"},
      {input:"build_storm_batch_plan_json", status:"provided", schema_version:"franken-engine.build-storm-batch-plan.v1"}
    ],
    failures:[],
    notes:["deterministic advisory-only forecast fixture"],
    forecasts:{
      compile_pressure:{state:"nominal", recommended_action:"No compile-pressure mitigation is required."},
      disk_memory_pressure:{state:"nominal", recommended_action:"No disk or memory mitigation is required."},
      rch_degradation:{state:"nominal", recommended_action:"rch is healthy enough for advisory use."},
      target_dir_heat:{state:"nominal", recommended_action:"Warm target reuse remains bounded."},
      proof_availability:{state:"nominal", recommended_action:"Proof availability is healthy enough for advisory reuse."},
      coordination_pressure:{state:"nominal", recommended_action:"Coordination pressure is nominal."}
    },
    artifact_paths:{swarm_capacity_forecast_json:$artifact_path}
  }' >"${fixture_dir}/capacity_forecast.json"

  jq -n --arg artifact_path "${fixture_dir}/admission_budget_plan.json" '{
    schema_version:"franken-engine.swarm-admission-budget-plan.v1",
    decision:"admit",
    budget_profile:"balanced",
    summary:{admitted_count:1, deferred_count:0},
    recommendations:[{
      request_id:"status-shell",
      bead_id:"bd-h95kz",
      agent_id:"CyanOak",
      decision:"admit",
      budget_class:"protected",
      proof_obligation:true
    }],
    artifact_paths:{swarm_admission_budget_plan_json:$artifact_path}
  }' >"${fixture_dir}/admission_budget_plan.json"

  jq -n --arg artifact_path "${fixture_dir}/lease_exchange_salvage_simulation.json" '{
    schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
    decision:"retain_current_assignments",
    summary:{
      manual_review_count:0,
      lease_exchange_candidate_count:0,
      salvage_promotion_candidate_count:0
    },
    upstream_summary:{
      archive_pressure_advisory:"retain",
      salvage_workflow_state:"clean_finished"
    },
    recommendations:[],
    artifact_paths:{lease_exchange_cancellation_salvage_simulation_json:$artifact_path}
  }' >"${fixture_dir}/lease_exchange_salvage_simulation.json"

  jq -n --arg artifact_path "${fixture_dir}/warm_target_prefetch_roi_advisory.json" '{
    schema_version:"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
    advisory:"prefetch_recommended",
    recommended_action:"Warm the preserved target before the next protected proof.",
    reason:"bounded replay cost and positive reuse delta justify a dry-run prefetch recommendation",
    exit_code:0,
    budget_summary:{budget_profile:"balanced"},
    warm_target_summary:{target_dir:"/tmp/rch_target_franken_engine_operator_status"},
    proof_cache_summary:{proof_cache_decision:"cache_hit"},
    archive_pressure_summary:{advisory:"retain"},
    validation_cost_summary:{estimated_cpu_slots_total:4},
    roi_summary:{expected_reuse_score:800000, realized_reuse_score:910000, reuse_delta:110000},
    artifact_paths:{swarm_warm_target_prefetch_roi_advisory_json:$artifact_path}
  }' >"${fixture_dir}/warm_target_prefetch_roi_advisory.json"

  write_starvation_rescue_fixtures "$fixture_dir" "advisory"
  write_checkpoint_restore_fixtures "$fixture_dir" "healthy"
  write_execution_queue_advisory_fixtures "$fixture_dir" "healthy"
}

write_starvation_rescue_fixtures() {
  local fixture_dir="$1"
  local mode="$2"

  case "$mode" in
    advisory)
      jq -n \
        --arg artifact_path "${fixture_dir}/starvation_rescue_plan.json" \
        '{
          schema_version:"franken-engine.swarm-starvation-rescue-plan.v1",
          decision:"advisory",
          scenario_class:"healthy",
          summary:{
            recommendation_count:2,
            top_recommendation_action:"reopen_stale_claim_then_rebalance",
            readiness:"ready",
            brownout_finding_count:0,
            starvation_finding_count:0,
            safe_to_reopen_count:2,
            contact_first_count:0,
            lease_exchange_candidate_count:1,
            manual_review_count:0,
            ownership_fail_closed_count:0
          },
          policy_basis:{
            matched_case_ids:["healthy_advisory_ready"],
            matched_case_count:1,
            required_scenario_classes:["healthy","brownout","ownership_contradiction","salvage_pinned","stale_telemetry","local_fallback"]
          },
          recommendations:[
            {
              rank:1,
              action:"reopen_stale_claim_then_rebalance",
              fairness_reason:"Safe stale reopen is available and no ownership drift is active.",
              required_next_actions:["Reopen only evidence-supported stale claims.","Rebalance deferred work after the reopen lands."]
            },
            {
              rank:2,
              action:"monitor_queue_and_keep_fair_share",
              fairness_reason:"No brownout or manual-review pressure is active, so queue hygiene remains sufficient.",
              required_next_actions:["Keep the next proof batch narrow and fairness-bounded."]
            }
          ],
          fail_closed_reasons:[],
          artifact_paths:{swarm_starvation_rescue_plan_json:$artifact_path}
        }' >"${fixture_dir}/starvation_rescue_plan.json"
      jq -n \
        --arg artifact_path "${fixture_dir}/starvation_rescue_conformance_report.json" \
        '{
          schema_version:"franken-engine.swarm-starvation-rescue-conformance-report.v1",
          decision:"pass",
          summary:{
            plan_decision:"advisory",
            scenario_class:"healthy",
            gate_failure_count:0
          },
          verified_invariants:[
            {name:"artifact_lineage_is_real", outcome:"pass"},
            {name:"fresh_rescue_input_evidence", outcome:"pass"}
          ],
          gate_failures:[],
          artifact_paths:{swarm_starvation_rescue_conformance_report_json:$artifact_path}
        }' >"${fixture_dir}/starvation_rescue_conformance_report.json"
      ;;
    manual)
      jq -n \
        --arg artifact_path "${fixture_dir}/starvation_rescue_plan.json" \
        '{
          schema_version:"franken-engine.swarm-starvation-rescue-plan.v1",
          decision:"manual_review_required",
          scenario_class:"salvage_pinned",
          summary:{
            recommendation_count:2,
            top_recommendation_action:"preserve_pinned_evidence",
            readiness:"degraded",
            brownout_finding_count:1,
            starvation_finding_count:1,
            safe_to_reopen_count:0,
            contact_first_count:1,
            lease_exchange_candidate_count:0,
            manual_review_count:1,
            ownership_fail_closed_count:0
          },
          policy_basis:{
            matched_case_ids:["salvage_pinned_manual_review"],
            matched_case_count:1,
            required_scenario_classes:["healthy","brownout","ownership_contradiction","salvage_pinned","stale_telemetry","local_fallback"]
          },
          recommendations:[
            {
              rank:1,
              action:"preserve_pinned_evidence",
              fairness_reason:"Pinned evidence and manual review outrank any automated rescue throughput.",
              required_next_actions:["Keep proof artifacts pinned until manual review clears.","Contact the owner before attempting lease exchange or reopen."]
            },
            {
              rank:2,
              action:"contact_owner_before_exchange",
              fairness_reason:"Fairness cannot override explicit owner-contact requirements.",
              required_next_actions:["Contact the current owner before attempting lease exchange or reopen."]
            }
          ],
          fail_closed_reasons:[],
          artifact_paths:{swarm_starvation_rescue_plan_json:$artifact_path}
        }' >"${fixture_dir}/starvation_rescue_plan.json"
      jq -n \
        --arg artifact_path "${fixture_dir}/starvation_rescue_conformance_report.json" \
        '{
          schema_version:"franken-engine.swarm-starvation-rescue-conformance-report.v1",
          decision:"pass",
          summary:{
            plan_decision:"manual_review_required",
            scenario_class:"salvage_pinned",
            gate_failure_count:0
          },
          verified_invariants:[
            {name:"contact_first_blocks_advisory", outcome:"pass"},
            {name:"salvage_pinned_blocks_advisory", outcome:"pass"}
          ],
          gate_failures:[],
          artifact_paths:{swarm_starvation_rescue_conformance_report_json:$artifact_path}
        }' >"${fixture_dir}/starvation_rescue_conformance_report.json"
      ;;
    *)
      record_failure "unknown starvation rescue fixture mode ${mode}"
      ;;
  esac
}

write_checkpoint_restore_fixtures() {
  local fixture_dir="$1"
  local mode="$2"
  local capture_decision="captured"
  local restore_hint="candidate"
  local plan_decision="resume"
  local drift_class="none"
  local top_restore_action="resume_from_checkpoint"
  local checkpoint_age_seconds=300
  local provided_current_comparison_count=6
  local missing_current_comparison_count=0
  local fail_closed_reasons='[]'
  local drift_findings='[]'

  case "$mode" in
    healthy)
      ;;
    stale)
      plan_decision="fail_closed"
      drift_class="blocked"
      top_restore_action="capture_fresh_checkpoint_bundle"
      checkpoint_age_seconds=7200
      fail_closed_reasons='[
        {
          "kind": "checkpoint_stale",
          "detail": "checkpoint age exceeded the restore freshness window"
        }
      ]'
      ;;
    owner_drift)
      plan_decision="fail_closed"
      drift_class="blocked"
      top_restore_action="manual_ownership_review"
      fail_closed_reasons='[
        {
          "kind": "ownership_drift",
          "detail": "current stale-lock reopen/contact truth drifted from the captured checkpoint evidence"
        }
      ]'
      ;;
    manual_review)
      capture_decision="captured_degraded"
      restore_hint="manual_review"
      plan_decision="advisory_manual_review"
      drift_class="soft"
      top_restore_action="review_salvage_pressure_before_resume"
      drift_findings='[
        {
          "kind": "salvage_manual_review",
          "severity": "advisory",
          "captured_value": "retain_current_assignments",
          "current_value": "manual_confirmation_required",
          "detail": "current salvage truth requires manual review before restore"
        }
      ]'
      ;;
    *)
      record_failure "unknown checkpoint restore fixture mode ${mode}"
      return 1
      ;;
  esac

  : >"${fixture_dir}/checkpoint_bundle.events.jsonl"
  printf 'checkpoint bundle fixture\n' >"${fixture_dir}/checkpoint_bundle.summary.md"
  printf './scripts/swarm_checkpoint_bundle_packer.sh --smoke-fixture\n' >"${fixture_dir}/checkpoint_bundle.commands.txt"
  : >"${fixture_dir}/checkpoint_restore_plan.events.jsonl"
  printf 'checkpoint restore plan fixture\n' >"${fixture_dir}/checkpoint_restore_plan.report.md"
  printf './scripts/swarm_checkpoint_restore_planner.sh --smoke-fixture\n' >"${fixture_dir}/checkpoint_restore_plan.commands.txt"
  : >"${fixture_dir}/checkpoint_restore_conformance.events.jsonl"
  printf 'checkpoint restore conformance fixture\n' >"${fixture_dir}/checkpoint_restore_conformance.report.md"
  printf './scripts/swarm_checkpoint_restore_conformance_gate.sh --smoke-fixture\n' >"${fixture_dir}/checkpoint_restore_conformance.commands.txt"

  jq -n \
    --arg artifact_path "${fixture_dir}/checkpoint_bundle.json" \
    --arg fixture_dir "$fixture_dir" \
    --arg capture_decision "$capture_decision" \
    --arg restore_hint "$restore_hint" \
    '{
      schema_version:"franken-engine.swarm-checkpoint-bundle.v1",
      checkpoint_id:"checkpoint-operator-status-smoke",
      capture_decision:$capture_decision,
      restore_readiness_hint:$restore_hint,
      captured_epoch_seconds:1700000000,
      stale_after_seconds:1800,
      upstream_evidence:{required_count:8, optional_count:0, optional_present_count:0},
      artifact_ledger:{
        swarm_capacity_snapshot:{schema_version:"franken-engine.swarm-capacity-snapshot.v1", path:($fixture_dir + "/capacity_snapshot.json"), trust_state:"primary", freshness_state:"fresh", required:true},
        swarm_capacity_forecast:{schema_version:"franken-engine.swarm-capacity-forecast.v1", path:($fixture_dir + "/capacity_forecast.json"), trust_state:"primary", freshness_state:"fresh", required:true},
        swarm_admission_budget_plan:{schema_version:"franken-engine.swarm-admission-budget-plan.v1", path:($fixture_dir + "/admission_budget_plan.json"), trust_state:"primary", freshness_state:"fresh", required:true},
        remote_proof_archive_pressure_scoreboard:{schema_version:"franken-engine.remote-proof-archive-pressure-scoreboard.v1", path:($fixture_dir + "/archive_pressure_scoreboard.json"), trust_state:"primary", freshness_state:"fresh", required:true},
        stale_lock_recommendations:{schema_version:"franken-engine.stale-lock-recommendations.v1", path:($fixture_dir + "/stale_lock_recommendations.json"), trust_state:"primary", freshness_state:"fresh", required:true},
        swarm_lease_exchange_cancellation_salvage_simulation:{schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1", path:($fixture_dir + "/lease_exchange_salvage_simulation.json"), trust_state:"primary", freshness_state:"fresh", required:true},
        swarm_starvation_rescue_plan:{schema_version:"franken-engine.swarm-starvation-rescue-plan.v1", path:($fixture_dir + "/starvation_rescue_plan.json"), trust_state:"primary", freshness_state:"fresh", required:true},
        swarm_operator_status_report:{schema_version:"franken-engine.swarm-operator-status-report.v1", path:($fixture_dir + "/operator_status_report.json"), trust_state:"primary", freshness_state:"fresh", required:true}
      },
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
    --argjson provided_current_comparison_count "$provided_current_comparison_count" \
    --argjson missing_current_comparison_count "$missing_current_comparison_count" \
    --argjson fail_closed_reasons "$fail_closed_reasons" \
    --argjson drift_findings "$drift_findings" \
    '{
      schema_version:"franken-engine.swarm-checkpoint-restore-plan.v1",
      checkpoint_id:"checkpoint-operator-status-smoke",
      decision:$plan_decision,
      exit_code:0,
      drift_class:$drift_class,
      summary:{
        top_restore_action:$top_restore_action,
        provided_current_comparison_count:$provided_current_comparison_count,
        missing_current_comparison_count:$missing_current_comparison_count,
        drift_count:($drift_findings | length),
        fail_closed_reason_count:($fail_closed_reasons | length)
      },
      drift_receipt:{
        checkpoint_age_seconds:$checkpoint_age_seconds,
        fail_closed_reasons:$fail_closed_reasons,
        findings:$drift_findings
      },
      resolved_inputs:[
        {input:"checkpoint_bundle_json", status:"provided", path:($fixture_dir + "/checkpoint_bundle.json"), schema_version:"franken-engine.swarm-checkpoint-bundle.v1"},
        {input:"current_swarm_capacity_snapshot_json", status:"provided", path:($fixture_dir + "/capacity_snapshot.json"), schema_version:"franken-engine.swarm-capacity-snapshot.v1"},
        {input:"current_swarm_capacity_forecast_json", status:"provided", path:($fixture_dir + "/capacity_forecast.json"), schema_version:"franken-engine.swarm-capacity-forecast.v1"},
        {input:"current_remote_proof_archive_pressure_scoreboard_json", status:"provided", path:($fixture_dir + "/archive_pressure_scoreboard.json"), schema_version:"franken-engine.remote-proof-archive-pressure-scoreboard.v1"},
        {input:"current_stale_lock_recommendations_json", status:"provided", path:($fixture_dir + "/stale_lock_recommendations.json"), schema_version:"franken-engine.stale-lock-recommendations.v1"},
        {input:"current_swarm_lease_exchange_cancellation_salvage_simulation_json", status:"provided", path:($fixture_dir + "/lease_exchange_salvage_simulation.json"), schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1"},
        {input:"current_swarm_operator_status_report_json", status:"provided", path:($fixture_dir + "/operator_status_report.json"), schema_version:"franken-engine.swarm-operator-status-report.v1"}
      ],
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
    --arg plan_decision "$plan_decision" \
    --arg capture_decision "$capture_decision" \
    --arg top_restore_action "$top_restore_action" \
    '{
      schema_version:"franken-engine.swarm-checkpoint-restore-conformance-report.v1",
      decision:"pass",
      summary:{
        restore_decision:$plan_decision,
        checkpoint_capture_decision:$capture_decision,
        top_restore_action:$top_restore_action,
        gate_failure_count:0,
        checked_artifact_path_count:8
      },
      verified_invariants:[
        {name:"checkpoint_id_alignment", outcome:"pass"},
        {name:"resume_requires_clean_comparison_set", outcome:"pass"}
      ],
      gate_failures:[],
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

write_execution_queue_advisory_fixtures() {
  local fixture_dir="$1"
  local mode="$2"
  local golden_path

  case "$mode" in
    healthy)
      golden_path="${root_dir}/scripts/testdata/swarm_execution_queue/goldens/healthy_runner_golden.json"
      ;;
    conservative)
      golden_path="${root_dir}/scripts/testdata/swarm_execution_queue/goldens/proof_brownout_runner_golden.json"
      ;;
    blocked_parent)
      golden_path="${root_dir}/scripts/testdata/swarm_execution_queue/goldens/blocked_parent_runner_golden.json"
      ;;
    *)
      record_failure "unknown execution queue fixture mode ${mode}"
      return 1
      ;;
  esac

  jq -n \
    --slurpfile golden "$golden_path" \
    '($golden[0]) as $g | {
      schema_version:$g.runner.artifact_schema_version,
      runner_schema_version:"franken-engine.swarm-execution-queue-runner.v1",
      source_revision:"smoke-rev",
      normalized_input_hash_hex:$g.runner.normalized_input_hash_hex,
      artifact_hash_hex:$g.runner.artifact_hash_hex,
      queue_artifact:{
        queue:$g.runner.queue,
        bottlenecks:($g.runner.bottleneck_ids | map({task_id:., severity:"low", downstream_count:1, unassigned:true})),
        risk_budget:$g.runner.risk_budget
      }
    }' >"${fixture_dir}/execution_queue_artifact.json"

  jq -n \
    --slurpfile golden "$golden_path" \
    '($golden[0]) as $g | {
      schema_version:$g.runner.risk_budget_schema_version,
      runner_schema_version:"franken-engine.swarm-execution-queue-runner.v1",
      source_revision:"smoke-rev",
      normalized_input_hash_hex:$g.runner.normalized_input_hash_hex,
      decision:$g.expected_decision,
      risk_budget:$g.runner.risk_budget,
      conservative_mode:$g.runner.conservative_mode,
      queue_depth:$g.runner.queue_depth
    }' >"${fixture_dir}/execution_queue_risk_budget_receipt.json"

  jq -n \
    --slurpfile golden "$golden_path" \
    '($golden[0]) as $g | {
      schema_version:$g.runner.bottleneck_schema_version,
      runner_schema_version:"franken-engine.swarm-execution-queue-runner.v1",
      source_revision:"smoke-rev",
      normalized_input_hash_hex:$g.runner.normalized_input_hash_hex,
      bottleneck_count:$g.runner.bottleneck_count,
      critical_bottleneck_count:$g.runner.critical_bottleneck_count,
      bottlenecks:($g.runner.bottleneck_ids | map({task_id:., severity:"low", downstream_count:1, unassigned:true}))
    }' >"${fixture_dir}/execution_queue_bottleneck_report.json"

  jq -n \
    --slurpfile golden "$golden_path" \
    --arg fixture_dir "$fixture_dir" \
    '($golden[0]) as $g | {
      schema_version:"franken-engine.swarm-execution-queue-runner.v1",
      source_revision:"smoke-rev",
      normalized_input_path:$g.normalized_input_path,
      normalized_input_hash_hex:$g.runner.normalized_input_hash_hex,
      decision:$g.expected_decision,
      task_count:($g.runner.queue | length),
      queue_depth:$g.runner.queue_depth,
      artifact_hash_hex:$g.runner.artifact_hash_hex,
      artifact_paths:{
        run_manifest_json:($fixture_dir + "/execution_queue_run_manifest.json"),
        events_jsonl:($fixture_dir + "/execution_queue.events.jsonl"),
        commands_txt:($fixture_dir + "/execution_queue.commands.txt"),
        execution_queue_artifact_json:($fixture_dir + "/execution_queue_artifact.json"),
        risk_budget_receipt_json:($fixture_dir + "/execution_queue_risk_budget_receipt.json"),
        bottleneck_report_json:($fixture_dir + "/execution_queue_bottleneck_report.json"),
        operator_summary_md:($fixture_dir + "/execution_queue.summary.md")
      }
    }' >"${fixture_dir}/execution_queue_run_manifest.json"

  : >"${fixture_dir}/execution_queue.events.jsonl"
  printf './franken_swarm_execution_queue --smoke-fixture\n' >"${fixture_dir}/execution_queue.commands.txt"
  printf 'execution queue advisory fixture\n' >"${fixture_dir}/execution_queue.summary.md"
}

write_healthy_fixtures() {
  local fixture_dir="$1"

  jq -n '[{id:"bd-p03vs", title:"Typed proof-evidence index", priority:1, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[{id:"bd-0ub12", title:"Semantic dark matter scoring", priority:1, status:"in_progress", assignee:"CyanOak"}]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"track-B", items:[{id:"bd-p03vs", title:"Typed proof-evidence index", priority:1, status:"open"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[{path:"scripts/swarm_operator_status_report.sh", holder:"SandyThrush", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"admit", findings:[]}' >"${fixture_dir}/resource_decision.json"
  jq -n '{
    decision:"admit",
    collision_risk:"none",
    risk_flags:[],
    conflicting_agents:[],
    safe_alternatives:["scripts/swarm_operator_status_report.sh"],
    commands:[{
      command_id:"script-check",
      display:"bash -n scripts/swarm_operator_status_report.sh",
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
  jq -n '{queries:[{name:"recent_failed_gates", row_count:0},{name:"proof_by_bead", row_count:2}]}' >"${fixture_dir}/proof_index.json"
  jq -n '[{bead_id:"bd-1onpa", artifact_id:"plan", status:"pass"}]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[]' >"${fixture_dir}/dirty_files.json"
  jq -n '{collision_risk:"none", conflicting_agents:[], safe_alternatives:["scripts/swarm_operator_status_report.sh"], reservation_recommendations:[], conflicts:{reservations:[], dirty:[], in_progress:[]}}' >"${fixture_dir}/collision_receipt.json"
  jq -n '{schema_version:"franken-engine.proof-freshness-decay-report.v1", proof_artifact_id:"proof-current", freshness_state:"fresh", reusable:true, reason:"proof artifact is reusable", recommended_next_action:"Reuse the proof artifact.", covered_paths:["scripts/swarm_operator_status_report.sh"], changed_paths:[]}' >"${fixture_dir}/proof_freshness.json"
  jq -n '{status:"not_provided", failure_kind:"none", retry_safety:"not_required", recommended_next_action:"No rch incident packet was provided."}' >"${fixture_dir}/rch_incident_packet.json"
  jq -n '{
    schema_version:"franken-engine.swarm-resource-lease-plan.v1",
    agent_id:"ScarletOwl",
    bead_id:"bd-h3hrc",
    requested_command:"bash -n scripts/swarm_operator_status_report.sh",
    target_dir:"/tmp/rch_target_franken_engine_operator_status",
    lease_decision:"admit",
    lease_ttl_seconds:1800,
    reason:"lease admitted",
    safe_alternatives:[],
    assigned_worker:"worker-alpha",
    findings:[{severity:"info", code:"lease_admitted", message:"lease admitted"}]
  }' >"${fixture_dir}/resource_lease_plan.json"
  jq -n '{
    schema_version:"franken-engine.proof-reuse-cache-plan.v1",
    expected_source_revision:"smoke-rev",
    proof_cache_decision:"cache_hit",
    reason:"all requested proof artifacts are safely reusable",
    cache_hit_artifacts:[{bead_id:"bd-h3hrc", artifact_id:"operator-status-golden", artifact_path:"scripts/testdata/goldens/swarm_operator_status_report_healthy.golden"}],
    required_refreshes:[],
    invalid_artifacts:[],
    invalidated_paths:[],
    refresh_commands:[],
    summary:{cache_hit_count:1, refresh_count:0, invalid_count:0}
  }' >"${fixture_dir}/proof_cache_plan.json"
  jq -n '{
    schema_version:"franken-engine.build-storm-batch-plan.v1",
    batch_id:"batch-healthy",
    batch_decision:"planned",
    fairness_reason:"all pending requests fit within fairness and worker capacity",
    max_parallel_heavy:2,
    retry_after_seconds:0,
    admitted_commands:[{request_id:"status-shell", agent_id:"ScarletOwl", bead_id:"bd-h3hrc", command:"bash -n scripts/swarm_operator_status_report.sh", heavy:false, batch_decision:"admit", fairness_reason:"admitted as light validation outside heavy capacity"}],
    deferred_commands:[]
  }' >"${fixture_dir}/qos_batch_plan.json"
  jq -n '{
    schema_version:"franken-engine.stale-lock-recommendations.v1",
    stale_lock_recommendations:[],
    safe_to_reopen:[],
    contact_first:[]
  }' >"${fixture_dir}/stale_lock_recommendations.json"
  jq -n '{
    schema_version:"franken-engine.staged-ownership-report.v1",
    agent_id:"ScarletOwl",
    bead_id:"bd-h3hrc",
    decision:"pass",
    staged_path_count:4,
    offender_count:0,
    scoped_beads_issue_ids:["bd-h3hrc"],
    offending_paths:[],
    findings:[]
  }' >"${fixture_dir}/staged_ownership_report.json"
  write_predictive_extension_fixtures "$fixture_dir"
}

write_degraded_fixtures() {
  local fixture_dir="$1"

  jq -n '[{id:"bd-4kwo8", title:"Dark matter board receipts", priority:1, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[{id:"bd-0ub12", title:"Semantic dark matter scoring", priority:1, status:"in_progress", assignee:"CyanOak"}]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"track-A", items:[{id:"bd-blocked", title:"Blocked dependent bead", priority:1, status:"blocked"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[{path:"crates/franken-engine/src/semantic_dark_matter_engine.rs", holder:"CyanOak", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"defer", findings:[{signal:"active_compile_count", decision:"defer"}]}' >"${fixture_dir}/resource_decision.json"
  jq -n '{decision:"fail_closed", collision_risk:"none", risk_flags:[], commands:[], omitted_commands:[{kind:"unknown_path_mapping", path:"unknown/path.rs"}], proof_cost_budgets:[]}' >"${fixture_dir}/validation_plan.json"
  jq -n '{queries:[]}' >"${fixture_dir}/proof_index.json"
  jq -n '[{bead_id:"bd-0ub12", artifact_id:"semantic-proof", status:"blocked"}]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[{artifact_id:"old-proof", stale:true, age_hours:72}]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[{path:"crates/franken-engine/src/semantic_dark_matter_engine.rs", reserved:true, overlaps_ready:true}]' >"${fixture_dir}/dirty_files.json"
  jq -n '{collision_risk:"none", conflicting_agents:[], safe_alternatives:[], reservation_recommendations:[], conflicts:{reservations:[], dirty:[], in_progress:[]}}' >"${fixture_dir}/collision_receipt.json"
  jq -n '{schema_version:"franken-engine.proof-freshness-decay-report.v1", proof_artifact_id:"proof-current", freshness_state:"fresh", reusable:true, reason:"proof artifact is reusable", recommended_next_action:"Reuse the proof artifact.", covered_paths:["crates/franken-engine/src/semantic_dark_matter_engine.rs"], changed_paths:[]}' >"${fixture_dir}/proof_freshness.json"
  jq -n '{schema_version:"franken-engine.rch-incident-packet.v1", incident_id:"rch-incident-smoke", status:"fail", failure_kind:"worker_timeout", retry_safety:"safe_after_narrowing_or_timeout_adjustment", classification_confidence:"high", worker_id:"worker-smoke", command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_smoke cargo test -p frankenengine-engine --test smoke", target_dir:"/tmp/rch_target_smoke", recommended_next_action:"Retry only after narrowing the command."}' >"${fixture_dir}/rch_incident_packet.json"
}

write_stale_proof_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  write_checkpoint_restore_fixtures "$fixture_dir" "stale"
  jq -n '{schema_version:"franken-engine.proof-freshness-decay-report.v1", proof_artifact_id:"proof-stale", artifact_path:"artifacts/proof/current/manifest.json", freshness_state:"stale_by_time", reusable:false, reason:"current time exceeds the artifact freshness deadline", recommended_next_action:"Refresh the proof artifact before publishing or relying on the claim.", covered_paths:["scripts/swarm_operator_status_report.sh"], changed_paths:[]}' >"${fixture_dir}/proof_freshness.json"
}

write_high_cost_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  jq -n '{
    decision:"admit",
    collision_risk:"none",
    risk_flags:["high_cost_history"],
    conflicting_agents:[],
    safe_alternatives:["crates/franken-engine/tests/proof_manifest_golden_artifacts.rs"],
    commands:[{
      command_id:"cargo-test-proof_manifest_golden_artifacts",
      display:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_high_cost cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts",
      command_kind:"rch_cargo_test",
      predicted_cost:{
        schema_version:"franken-engine.swarm-validation-predicted-cost.v1",
        state:"matched",
        cost_class:"high",
        sample_count:3,
        elapsed_ms_p50:450000,
        elapsed_ms_max:900000,
        compiled_target_count_max:12,
        linked_target_count_max:2
      },
      risk_flags:["high_cost_history"],
      cost_evidence:{status:"matched", matched_rows:3, fresh_rows:3, stale_rows:0, source_revisions:["smoke-rev"]}
    }],
    omitted_commands:[],
    proof_cost_budgets:[{
      schema_version:"franken-engine.focused-proof-cost-budget.v1",
      suite:"proof_manifest_golden_artifacts",
      package:"frankenengine-engine",
      max_total_compiled_targets:2,
      max_total_linked_targets:1
    }]
  }' >"${fixture_dir}/validation_plan.json"
}

write_collision_risk_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  write_checkpoint_restore_fixtures "$fixture_dir" "owner_drift"
  jq -n '[{path:"scripts/swarm_operator_status_report.sh", holder:"CyanOak", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{
    decision:"admit_narrow",
    collision_risk:"reserved_overlap",
    risk_flags:[],
    conflicting_agents:["CyanOak"],
    safe_alternatives:["docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"],
    reservation_recommendations:[{action:"coordinate_reservation_holder", scope:"planned_write_set", reason:"planned write paths overlap active exclusive reservations"}],
    commands:[{
      command_id:"bash-n-dashboard-contract",
      display:"bash -n scripts/swarm_operator_status_report.sh",
      command_kind:"shell_syntax",
      predicted_cost:{schema_version:"franken-engine.swarm-validation-predicted-cost.v1", state:"static", cost_class:"low", sample_count:0, elapsed_ms_p50:0, elapsed_ms_max:0, compiled_target_count_max:0, linked_target_count_max:0},
      risk_flags:[],
      cost_evidence:{status:"not_required", matched_rows:0}
    }],
    omitted_commands:[],
    proof_cost_budgets:[]
  }' >"${fixture_dir}/validation_plan.json"
  jq -n '{
    collision_risk:"reserved_overlap",
    conflicting_agents:["CyanOak"],
    safe_alternatives:["docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"],
    reservation_recommendations:[{action:"coordinate_reservation_holder", scope:"planned_write_set", reason:"planned write paths overlap active exclusive reservations"}],
    conflicts:{reservations:[{planned_path:"scripts/swarm_operator_status_report.sh", path_pattern:"scripts/swarm_operator_status_report.sh", agent:"CyanOak", bead_id:"bd-gc1ml", source:"reservation"}], dirty:[], in_progress:[]}
  }' >"${fixture_dir}/collision_receipt.json"
}

write_forecast_low_confidence_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  jq -n --arg artifact_path "${fixture_dir}/capacity_forecast.json" '{
    schema_version:"franken-engine.swarm-capacity-forecast.v1",
    decision:"fail_closed",
    confidence_band:"low",
    summary:{overall_state:"blocked", blocked_categories:["compile_pressure","proof_availability"], degraded_categories:["coordination_pressure"]},
    telemetry_summary:{snapshot_decision:"stale_required_telemetry"},
    inputs:[
      {input:"telemetry_snapshot_json", status:"provided", schema_version:"franken-engine.swarm-capacity-snapshot.v1"},
      {input:"predictive_wrapper_report_json", status:"missing", schema_version:null},
      {input:"archive_lifecycle_report_json", status:"missing", schema_version:null}
    ],
    failures:[{kind:"low_confidence", label:"confidence_band", detail:"required telemetry missing or incomplete for forecast category"}],
    notes:["missing predictive wrapper and archive lifecycle reports force a fail-closed forecast"],
    forecasts:{
      compile_pressure:{state:"blocked", recommended_action:"Refresh missing predictive wrapper inputs before relying on compile-pressure advice."},
      disk_memory_pressure:{state:"degraded", recommended_action:"Treat disk and memory pressure as degraded until lease evidence is refreshed."},
      rch_degradation:{state:"degraded", recommended_action:"Treat rch posture as degraded until incident inputs are complete."},
      target_dir_heat:{state:"degraded", recommended_action:"Do not trust warm target reuse claims until forecast inputs are complete."},
      proof_availability:{state:"blocked", recommended_action:"Refresh proof availability evidence before relying on archived proofs."},
      coordination_pressure:{state:"degraded", recommended_action:"Use direct coordination before acting on auto-reopen suggestions."}
    },
    artifact_paths:{swarm_capacity_forecast_json:$artifact_path}
  }' >"${fixture_dir}/capacity_forecast.json"
}

write_overloaded_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  jq -n '{
    schema_version:"franken-engine.swarm-resource-lease-plan.v1",
    agent_id:"ScarletOwl",
    bead_id:"bd-h3hrc",
    requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_overloaded cargo test -p frankenengine-engine --test overloaded_swarm",
    target_dir:"/tmp/rch_target_franken_engine_overloaded",
    lease_decision:"defer",
    lease_ttl_seconds:1800,
    reason:"no rch worker has the requested CPU and memory lease available",
    safe_alternatives:["Run shell/docs gates now and retry the heavy proof when a worker is idle."],
    assigned_worker:"none",
    findings:[{severity:"warning", code:"all_workers_busy", message:"no rch worker has the requested CPU and memory lease available"}]
  }' >"${fixture_dir}/resource_lease_plan.json"
  jq -n '{
    schema_version:"franken-engine.proof-reuse-cache-plan.v1",
    expected_source_revision:"smoke-rev",
    proof_cache_decision:"refresh_required",
    reason:"all matching proof artifacts require refresh before reuse",
    cache_hit_artifacts:[],
    required_refreshes:[{bead_id:"bd-h3hrc", artifact_id:"operator-status-golden", refresh_reason:"source paths changed"}],
    invalid_artifacts:[],
    invalidated_paths:["scripts/swarm_operator_status_report.sh"],
    refresh_commands:["rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_operator_status cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e"],
    summary:{cache_hit_count:0, refresh_count:1, invalid_count:0}
  }' >"${fixture_dir}/proof_cache_plan.json"
  jq -n '{
    schema_version:"franken-engine.build-storm-batch-plan.v1",
    batch_id:"batch-overloaded",
    batch_decision:"all_deferred",
    fairness_reason:"all requests deferred by worker capacity, resource leases, or fairness gates",
    max_parallel_heavy:0,
    retry_after_seconds:300,
    admitted_commands:[],
    deferred_commands:[
      {request_id:"heavy-proof-a", agent_id:"ScarletOwl", bead_id:"bd-h3hrc", command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_heavy_a cargo test -p frankenengine-engine --test heavy_a", heavy:true, batch_decision:"defer", fairness_reason:"all rch workers busy; no heavy validation slots available", retry_after_seconds:300},
      {request_id:"heavy-proof-b", agent_id:"CyanOak", bead_id:"bd-vnkan", command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_heavy_b cargo test -p frankenengine-engine --test heavy_b", heavy:true, batch_decision:"defer", fairness_reason:"all rch workers busy; no heavy validation slots available", retry_after_seconds:300}
    ]
  }' >"${fixture_dir}/qos_batch_plan.json"
  jq -n '{
    schema_version:"franken-engine.stale-lock-recommendations.v1",
    stale_lock_recommendations:[{
      bead_id:"bd-high-priority-stalled",
      title:"High priority stalled bead",
      priority:1,
      assignee:"AgentTau",
      safe_to_reopen:false,
      contact_first:true,
      recommendation:"contact_first_high_priority",
      suggested_br_commands:[],
      contact_commands:["fetch inbox and thread messages for bd-high-priority-stalled", "send Agent Mail contact-first message to AgentTau"]
    }],
    safe_to_reopen:[],
    contact_first:["bd-high-priority-stalled"]
  }' >"${fixture_dir}/stale_lock_recommendations.json"
  jq -n --arg artifact_path "${fixture_dir}/capacity_forecast.json" '{
    schema_version:"franken-engine.swarm-capacity-forecast.v1",
    decision:"defer",
    confidence_band:"medium",
    summary:{overall_state:"brownout", blocked_categories:["compile_pressure"], degraded_categories:["disk_memory_pressure","coordination_pressure"]},
    telemetry_summary:{snapshot_decision:"current_and_complete"},
    inputs:[
      {input:"telemetry_snapshot_json", status:"provided", schema_version:"franken-engine.swarm-capacity-snapshot.v1"},
      {input:"admission_drill_report_json", status:"provided", schema_version:"franken-engine.swarm-admission-drill.v1"},
      {input:"proof_economy_drill_report_json", status:"provided", schema_version:"franken-engine.proof-economy-replay-trace.v1"}
    ],
    failures:[],
    notes:["bounded brownout forecast fixture"],
    forecasts:{
      compile_pressure:{state:"blocked", recommended_action:"Defer heavy proof work until the brownout clears."},
      disk_memory_pressure:{state:"degraded", recommended_action:"Reuse existing target dirs and avoid broad rebuilds."},
      rch_degradation:{state:"degraded", recommended_action:"Narrow remote proofs and preserve incident receipts."},
      target_dir_heat:{state:"degraded", recommended_action:"Avoid new target-dir fan-out while workers are saturated."},
      proof_availability:{state:"degraded", recommended_action:"Refresh proof artifacts before reusing them."},
      coordination_pressure:{state:"degraded", recommended_action:"Use contact-first reopen flows while the queue is saturated."}
    },
    artifact_paths:{swarm_capacity_forecast_json:$artifact_path}
  }' >"${fixture_dir}/capacity_forecast.json"
  jq -n --arg artifact_path "${fixture_dir}/admission_budget_plan.json" '{
    schema_version:"franken-engine.swarm-admission-budget-plan.v1",
    decision:"defer",
    budget_profile:"brownout",
    summary:{admitted_count:0, deferred_count:2},
    recommendations:[
      {request_id:"heavy-proof-a", bead_id:"bd-h3hrc", agent_id:"ScarletOwl", decision:"defer", budget_class:"protected", proof_obligation:true},
      {request_id:"heavy-proof-b", bead_id:"bd-vnkan", agent_id:"CyanOak", decision:"defer", budget_class:"best_effort", proof_obligation:false}
    ],
    artifact_paths:{swarm_admission_budget_plan_json:$artifact_path}
  }' >"${fixture_dir}/admission_budget_plan.json"
  jq -n --arg artifact_path "${fixture_dir}/lease_exchange_salvage_simulation.json" '{
    schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
    decision:"manual_confirmation_required",
    summary:{
      manual_review_count:1,
      lease_exchange_candidate_count:1,
      salvage_promotion_candidate_count:0
    },
    upstream_summary:{
      archive_pressure_advisory:"compaction_first",
      salvage_workflow_state:"salvage_pinned"
    },
    recommendations:[{
      bead_id:"bd-high-priority-stalled",
      simulated_action:"manual_confirmation_required",
      lease_exchange_candidate:true,
      salvage_promotion_candidate:false
    }],
    artifact_paths:{lease_exchange_cancellation_salvage_simulation_json:$artifact_path}
  }' >"${fixture_dir}/lease_exchange_salvage_simulation.json"
  jq -n --arg artifact_path "${fixture_dir}/warm_target_prefetch_roi_advisory.json" '{
    schema_version:"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
    advisory:"manual_review_required",
    recommended_action:"Do not warm a fresh target until brownout pressure and cache refresh obligations clear.",
    reason:"brownout pressure, refresh-required proof cache, and compaction-first archive posture block safe prefetch",
    exit_code:75,
    budget_summary:{budget_profile:"brownout"},
    warm_target_summary:{target_dir:"/tmp/rch_target_franken_engine_overloaded"},
    proof_cache_summary:{proof_cache_decision:"refresh_required"},
    archive_pressure_summary:{advisory:"compaction_first"},
    validation_cost_summary:{estimated_cpu_slots_total:8},
    roi_summary:{expected_reuse_score:900000, realized_reuse_score:300000, reuse_delta:-600000},
    artifact_paths:{swarm_warm_target_prefetch_roi_advisory_json:$artifact_path}
  }' >"${fixture_dir}/warm_target_prefetch_roi_advisory.json"
  write_starvation_rescue_fixtures "$fixture_dir" "manual"
  write_checkpoint_restore_fixtures "$fixture_dir" "manual_review"
}

run_case() {
  local case_name="$1"
  local expected_status="$2"
  local agent_mail_status="$3"
  local rch_status="$4"
  local proof_index_status="$5"
  local tmp_root="$6"
  local fixture_dir="${tmp_root}/${case_name}-fixtures"
  local output_dir="${tmp_root}/${case_name}-out"
  local actual_path="${tmp_root}/${case_name}.actual.golden"
  local golden_path="${golden_dir}/swarm_operator_status_report_${case_name}.golden"
  local report_actual_path="${tmp_root}/${case_name}.report.actual.golden"
  local report_golden_path="${golden_dir}/swarm_operator_status_report_${case_name}.report.golden"

  mkdir -p "$fixture_dir"
  case "$case_name" in
    healthy)
      write_healthy_fixtures "$fixture_dir"
      ;;
    degraded)
      write_degraded_fixtures "$fixture_dir"
      ;;
    stale_proof)
      write_stale_proof_fixtures "$fixture_dir"
      ;;
    high_cost)
      write_high_cost_fixtures "$fixture_dir"
      ;;
    collision_risk)
      write_collision_risk_fixtures "$fixture_dir"
      ;;
    overloaded)
      write_overloaded_fixtures "$fixture_dir"
      ;;
    forecast_low_confidence)
      write_forecast_low_confidence_fixtures "$fixture_dir"
      ;;
    execution_queue_conservative)
      write_healthy_fixtures "$fixture_dir"
      write_execution_queue_advisory_fixtures "$fixture_dir" "conservative"
      ;;
    execution_queue_restore_blocked)
      write_healthy_fixtures "$fixture_dir"
      write_checkpoint_restore_fixtures "$fixture_dir" "stale"
      write_execution_queue_advisory_fixtures "$fixture_dir" "blocked_parent"
      ;;
    *)
      record_failure "unknown case: ${case_name}"
      exit 64
      ;;
  esac

  local extra_args=()
  [[ -f "${fixture_dir}/resource_lease_plan.json" ]] && extra_args+=(--resource-lease-plan-json "${fixture_dir}/resource_lease_plan.json")
  [[ -f "${fixture_dir}/proof_cache_plan.json" ]] && extra_args+=(--proof-cache-plan-json "${fixture_dir}/proof_cache_plan.json")
  [[ -f "${fixture_dir}/qos_batch_plan.json" ]] && extra_args+=(--qos-batch-plan-json "${fixture_dir}/qos_batch_plan.json")
  [[ -f "${fixture_dir}/stale_lock_recommendations.json" ]] && extra_args+=(--stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json")
  [[ -f "${fixture_dir}/staged_ownership_report.json" ]] && extra_args+=(--staged-ownership-report-json "${fixture_dir}/staged_ownership_report.json")
  [[ -f "${fixture_dir}/capacity_forecast.json" ]] && extra_args+=(--capacity-forecast-json "${fixture_dir}/capacity_forecast.json")
  [[ -f "${fixture_dir}/admission_budget_plan.json" ]] && extra_args+=(--admission-budget-plan-json "${fixture_dir}/admission_budget_plan.json")
  [[ -f "${fixture_dir}/lease_exchange_salvage_simulation.json" ]] && extra_args+=(--lease-exchange-salvage-simulation-json "${fixture_dir}/lease_exchange_salvage_simulation.json")
  [[ -f "${fixture_dir}/warm_target_prefetch_roi_advisory.json" ]] && extra_args+=(--warm-target-prefetch-roi-advisory-json "${fixture_dir}/warm_target_prefetch_roi_advisory.json")
  [[ -f "${fixture_dir}/starvation_rescue_plan.json" ]] && extra_args+=(--starvation-rescue-plan-json "${fixture_dir}/starvation_rescue_plan.json")
  [[ -f "${fixture_dir}/starvation_rescue_conformance_report.json" ]] && extra_args+=(--starvation-rescue-conformance-report-json "${fixture_dir}/starvation_rescue_conformance_report.json")
  [[ -f "${fixture_dir}/checkpoint_bundle.json" ]] && extra_args+=(--checkpoint-bundle-json "${fixture_dir}/checkpoint_bundle.json")
  [[ -f "${fixture_dir}/checkpoint_restore_plan.json" ]] && extra_args+=(--checkpoint-restore-plan-json "${fixture_dir}/checkpoint_restore_plan.json")
  [[ -f "${fixture_dir}/checkpoint_restore_conformance_report.json" ]] && extra_args+=(--checkpoint-restore-conformance-report-json "${fixture_dir}/checkpoint_restore_conformance_report.json")
  [[ -f "${fixture_dir}/execution_queue_artifact.json" ]] && extra_args+=(--execution-queue-artifact-json "${fixture_dir}/execution_queue_artifact.json")
  [[ -f "${fixture_dir}/execution_queue_risk_budget_receipt.json" ]] && extra_args+=(--execution-queue-risk-budget-json "${fixture_dir}/execution_queue_risk_budget_receipt.json")
  [[ -f "${fixture_dir}/execution_queue_bottleneck_report.json" ]] && extra_args+=(--execution-queue-bottleneck-report-json "${fixture_dir}/execution_queue_bottleneck_report.json")
  [[ -f "${fixture_dir}/execution_queue_run_manifest.json" ]] && extra_args+=(--execution-queue-run-manifest-json "${fixture_dir}/execution_queue_run_manifest.json")

  "$reporter" \
    --bead-id bd-jw854 \
    --source-revision smoke-rev \
    --output-dir "$output_dir" \
    --agent-mail-status "$agent_mail_status" \
    --rch-status "$rch_status" \
    --proof-index-status "$proof_index_status" \
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
    "${extra_args[@]}" >/dev/null

  jq -e --arg expected_status "$expected_status" '
    .schema_version == "franken-engine.swarm-operator-status-report.v1"
    and .status == $expected_status
    and .tui_ready == true
    and .dashboard_contract.schema_version == "franken-engine.swarm-predictive-dashboard.v1"
    and .dashboard_contract.renderer.provider == "/dp/frankentui"
    and .dashboard_contract.renderer.shipped_in_franken_engine == false
    and .dashboard_contract.renderer.local_renderer == false
    and .predictive_dashboard.schema_version == "franken-engine.swarm-predictive-dashboard.v1"
    and .predictive_dashboard.renderer_contract.provider == "/dp/frankentui"
    and .predictive_dashboard.fixture_contract.local_tui_renderer == false
    and (.predictive_dashboard.predictive_cost.commands | type == "array")
    and (.predictive_dashboard.collision_risk.risk | type == "string")
    and (.predictive_dashboard.proof_freshness.state | type == "string")
    and (.predictive_dashboard.rch_incidents.incidents | type == "array")
    and (.predictive_dashboard.resource_leases.lease_decision | type == "string")
    and (.predictive_dashboard.proof_cache.proof_cache_decision | type == "string")
    and (.predictive_dashboard.qos_batches.batch_decision | type == "string")
    and (.predictive_dashboard.stale_lock_recommendations.recommendation_count | type == "number")
    and (.predictive_dashboard.telemetry_quality.confidence_band | type == "string")
    and (.predictive_dashboard.telemetry_quality.missing_input_count | type == "number")
    and (.predictive_dashboard.capacity_forecast.overall_state | type == "string")
    and (.predictive_dashboard.admission_budgets.budget_profile | type == "string")
    and (.predictive_dashboard.lease_exchange_salvage.decision | type == "string")
    and (.predictive_dashboard.prefetch_roi.advisory | type == "string")
    and (.predictive_dashboard.starvation_rescue.plan_decision | type == "string")
    and (.predictive_dashboard.starvation_rescue.escalation_band | type == "string")
    and (.predictive_dashboard.starvation_rescue.recommended_ordering | type == "array")
    and (.predictive_dashboard.starvation_rescue.unresolved_risks | type == "array")
    and (.predictive_dashboard.checkpoint_restore.plan_decision | type == "string")
    and (.predictive_dashboard.checkpoint_restore.escalation_band | type == "string")
    and (.predictive_dashboard.checkpoint_restore.unresolved_risks | type == "array")
    and (.predictive_dashboard.execution_queue_advisory.decision | type == "string")
    and (.predictive_dashboard.execution_queue_advisory.top_recommended_starts | type == "array")
    and (.predictive_dashboard.execution_queue_advisory.deferred_items | type == "array")
    and (.predictive_dashboard.execution_queue_advisory.bottlenecks | type == "array")
    and (.predictive_dashboard.execution_queue_advisory.restore_dependency_state | type == "string")
    and (.predictive_dashboard.staged_contamination.decision | type == "string")
    and ((.artifact_paths.capacity_forecast_json == null) or (.artifact_paths.capacity_forecast_json | type == "string"))
    and ((.artifact_paths.admission_budget_plan_json == null) or (.artifact_paths.admission_budget_plan_json | type == "string"))
    and ((.artifact_paths.lease_exchange_salvage_simulation_json == null) or (.artifact_paths.lease_exchange_salvage_simulation_json | type == "string"))
    and ((.artifact_paths.warm_target_prefetch_roi_advisory_json == null) or (.artifact_paths.warm_target_prefetch_roi_advisory_json | type == "string"))
    and ((.artifact_paths.starvation_rescue_plan_json == null) or (.artifact_paths.starvation_rescue_plan_json | type == "string"))
    and ((.artifact_paths.starvation_rescue_conformance_report_json == null) or (.artifact_paths.starvation_rescue_conformance_report_json | type == "string"))
    and ((.artifact_paths.checkpoint_bundle_json == null) or (.artifact_paths.checkpoint_bundle_json | type == "string"))
    and ((.artifact_paths.checkpoint_restore_plan_json == null) or (.artifact_paths.checkpoint_restore_plan_json | type == "string"))
    and ((.artifact_paths.checkpoint_restore_conformance_report_json == null) or (.artifact_paths.checkpoint_restore_conformance_report_json | type == "string"))
    and ((.artifact_paths.execution_queue_artifact_json == null) or (.artifact_paths.execution_queue_artifact_json | type == "string"))
    and ((.artifact_paths.execution_queue_risk_budget_json == null) or (.artifact_paths.execution_queue_risk_budget_json | type == "string"))
    and ((.artifact_paths.execution_queue_bottleneck_report_json == null) or (.artifact_paths.execution_queue_bottleneck_report_json | type == "string"))
    and ((.artifact_paths.execution_queue_run_manifest_json == null) or (.artifact_paths.execution_queue_run_manifest_json | type == "string"))
    and (.recommendations | length) >= 1
  ' "${output_dir}/status.json" >/dev/null
  record_pass "${case_name} report validates"

  case "$case_name" in
    healthy)
      jq -e '
        .summary.high_cost_command_count == 0
        and .predictive_dashboard.collision_risk.risk == "none"
        and .predictive_dashboard.proof_freshness.state == "fresh"
        and .predictive_dashboard.rch_incidents.status == "none"
        and .predictive_dashboard.resource_leases.lease_decision == "admit"
        and .predictive_dashboard.proof_cache.proof_cache_decision == "cache_hit"
        and .predictive_dashboard.qos_batches.deferred_count == 0
        and .predictive_dashboard.stale_lock_recommendations.contact_first_count == 0
        and .predictive_dashboard.telemetry_quality.confidence_band == "high"
        and .predictive_dashboard.capacity_forecast.overall_state == "nominal"
        and .predictive_dashboard.admission_budgets.deferred_count == 0
        and .predictive_dashboard.lease_exchange_salvage.decision == "retain_current_assignments"
        and .predictive_dashboard.prefetch_roi.advisory == "prefetch_recommended"
        and .predictive_dashboard.starvation_rescue.plan_decision == "advisory"
        and .predictive_dashboard.starvation_rescue.escalation_band == "ready"
        and (.predictive_dashboard.starvation_rescue.unresolved_risks | length) == 0
        and .predictive_dashboard.checkpoint_restore.plan_decision == "resume"
        and .predictive_dashboard.checkpoint_restore.escalation_band == "ready"
        and (.predictive_dashboard.checkpoint_restore.unresolved_risks | length) == 0
        and .predictive_dashboard.execution_queue_advisory.decision == "pass"
        and .predictive_dashboard.execution_queue_advisory.conservative_mode == false
        and .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "clear"
        and (.predictive_dashboard.execution_queue_advisory.top_recommended_starts | length) == 1
        and (.predictive_dashboard.execution_queue_advisory.bottlenecks | length) == 1
        and .predictive_dashboard.staged_contamination.decision == "pass"
      ' "${output_dir}/status.json" >/dev/null
      ;;
    degraded)
      jq -e '
        .predictive_dashboard.rch_incidents.status == "degraded"
        and any(.degraded[]; .component == "rch_incident_packet")
        and .predictive_dashboard.resource_leases.artifact_status == "missing"
        and .predictive_dashboard.proof_cache.artifact_status == "missing"
        and .predictive_dashboard.qos_batches.artifact_status == "missing"
        and .predictive_dashboard.stale_lock_recommendations.artifact_status == "missing"
        and .predictive_dashboard.capacity_forecast.artifact_status == "missing"
        and .predictive_dashboard.admission_budgets.artifact_status == "missing"
        and .predictive_dashboard.lease_exchange_salvage.artifact_status == "missing"
        and .predictive_dashboard.prefetch_roi.artifact_status == "missing"
        and .predictive_dashboard.starvation_rescue.artifact_status == "missing"
        and .predictive_dashboard.checkpoint_restore.artifact_status == "missing"
        and .predictive_dashboard.execution_queue_advisory.artifact_status == "missing"
        and .predictive_dashboard.staged_contamination.artifact_status == "missing"
      ' "${output_dir}/status.json" >/dev/null
      ;;
    stale_proof)
      jq -e '
        .predictive_dashboard.proof_freshness.state == "stale_by_time"
        and .predictive_dashboard.proof_freshness.reusable == false
        and .predictive_dashboard.checkpoint_restore.plan_decision == "fail_closed"
        and .predictive_dashboard.checkpoint_restore.escalation_band == "fail_closed"
        and .predictive_dashboard.checkpoint_restore.top_restore_action == "capture_fresh_checkpoint_bundle"
        and (.predictive_dashboard.checkpoint_restore.unresolved_risks | map(.kind) | index("checkpoint_stale"))
        and .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "restore_blocked"
        and any(.degraded[]; .component == "proof_freshness")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    high_cost)
      jq -e '
        .summary.high_cost_command_count == 1
        and .predictive_dashboard.predictive_cost.status == "elevated"
        and any(.degraded[]; .component == "predictive_cost")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    collision_risk)
      jq -e '
        .predictive_dashboard.collision_risk.risk == "reserved_overlap"
        and (.predictive_dashboard.collision_risk.conflicting_agents | index("CyanOak"))
        and .predictive_dashboard.checkpoint_restore.plan_decision == "fail_closed"
        and .predictive_dashboard.checkpoint_restore.top_restore_action == "manual_ownership_review"
        and (.predictive_dashboard.checkpoint_restore.unresolved_risks | map(.kind) | index("ownership_drift"))
        and .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "restore_blocked"
        and any(.degraded[]; .component == "collision_risk")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    overloaded)
      jq -e '
        .predictive_dashboard.resource_leases.lease_decision == "defer"
        and .predictive_dashboard.proof_cache.proof_cache_decision == "refresh_required"
        and .predictive_dashboard.qos_batches.batch_decision == "all_deferred"
        and .predictive_dashboard.qos_batches.deferred_count == 2
        and .predictive_dashboard.stale_lock_recommendations.contact_first_count == 1
        and .predictive_dashboard.admission_budgets.budget_profile == "brownout"
        and .predictive_dashboard.lease_exchange_salvage.decision == "manual_confirmation_required"
        and .predictive_dashboard.prefetch_roi.advisory == "manual_review_required"
        and .predictive_dashboard.starvation_rescue.plan_decision == "manual_review_required"
        and .predictive_dashboard.starvation_rescue.escalation_band == "manual_review"
        and (.predictive_dashboard.starvation_rescue.unresolved_risks | map(.code) | index("contact_first_uncertainty"))
        and .predictive_dashboard.checkpoint_restore.plan_decision == "advisory_manual_review"
        and .predictive_dashboard.checkpoint_restore.escalation_band == "manual_review"
        and .predictive_dashboard.checkpoint_restore.top_restore_action == "review_salvage_pressure_before_resume"
        and (.predictive_dashboard.checkpoint_restore.unresolved_risks | map(.kind) | index("salvage_manual_review"))
        and .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "restore_manual_review"
        and .predictive_dashboard.staged_contamination.decision == "pass"
        and any(.degraded[]; .component == "qos_batches")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    forecast_low_confidence)
      jq -e '
        .predictive_dashboard.telemetry_quality.confidence_band == "low"
        and .predictive_dashboard.telemetry_quality.missing_input_count == 2
        and .predictive_dashboard.capacity_forecast.overall_state == "blocked"
        and (.predictive_dashboard.capacity_forecast.blocked_categories | index("compile_pressure"))
        and any(.degraded[]; .component == "capacity_forecast")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    execution_queue_conservative)
      jq -e '
        .predictive_dashboard.execution_queue_advisory.decision == "degraded"
        and .predictive_dashboard.execution_queue_advisory.conservative_mode == true
        and .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "clear"
        and .predictive_dashboard.execution_queue_advisory.risk_budget.remaining_millionths == 126000
        and (.predictive_dashboard.execution_queue_advisory.deferred_items | map(.task_id) | index("bd-brownout-ready"))
        and any(.degraded[]; .component == "execution_queue_advisory")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    execution_queue_restore_blocked)
      jq -e '
        .predictive_dashboard.execution_queue_advisory.decision == "pass"
        and .predictive_dashboard.execution_queue_advisory.restore_dependency_state == "restore_blocked"
        and (.predictive_dashboard.execution_queue_advisory.restore_dependency_detail | test("fail-closed|blocked"))
        and (.predictive_dashboard.execution_queue_advisory.top_recommended_starts | map(.task_id) | index("bd-child-contract"))
        and (.predictive_dashboard.execution_queue_advisory.deferred_items | map(.task_id) | index("bd-parent"))
        and any(.degraded[]; .component == "execution_queue_advisory")
      ' "${output_dir}/status.json" >/dev/null
      ;;
  esac
  record_pass "${case_name} dashboard fields validate"

  canonicalize_status "${output_dir}/status.json" "$tmp_root" >"$actual_path"
  compare_case_golden "$case_name" "$actual_path" "$golden_path"
  canonicalize_report "${output_dir}/report.md" "$tmp_root" >"$report_actual_path"
  compare_case_golden "${case_name}.report" "$report_actual_path" "$report_golden_path"
}

assert_dashboard_contract_truth() {
  if [[ ! -f "$contract_doc" ]]; then
    record_failure "missing dashboard contract doc"
    return 1
  fi
  if [[ ! -f "$contract_json" ]]; then
    record_failure "missing dashboard contract json"
    return 1
  fi

  jq -e '
    .schema_version == "franken-engine.swarm-predictive-dashboard-contract.v1"
    and .renderer.repo_path == "/dp/frankentui"
    and .renderer.shipped_in_franken_engine == false
    and .renderer.local_renderer == false
    and (.golden_fixture_cases | index("healthy"))
    and (.golden_fixture_cases | index("degraded"))
    and (.golden_fixture_cases | index("stale_proof"))
    and (.golden_fixture_cases | index("high_cost"))
    and (.golden_fixture_cases | index("collision_risk"))
    and (.golden_fixture_cases | index("overloaded"))
    and (.golden_fixture_cases | index("forecast_low_confidence"))
    and (.golden_fixture_cases | index("execution_queue_conservative"))
    and (.golden_fixture_cases | index("execution_queue_restore_blocked"))
    and (.required_dashboard_fields | index("predictive_dashboard.telemetry_quality.decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.capacity_forecast.overall_state"))
    and (.required_dashboard_fields | index("predictive_dashboard.admission_budgets.budget_profile"))
    and (.required_dashboard_fields | index("predictive_dashboard.lease_exchange_salvage.decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.prefetch_roi.advisory"))
    and (.required_dashboard_fields | index("predictive_dashboard.starvation_rescue.plan_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.starvation_rescue.escalation_band"))
    and (.required_dashboard_fields | index("predictive_dashboard.starvation_rescue.unresolved_risks"))
    and (.required_dashboard_fields | index("predictive_dashboard.checkpoint_restore.plan_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.checkpoint_restore.restore_readiness_hint"))
    and (.required_dashboard_fields | index("predictive_dashboard.checkpoint_restore.top_restore_action"))
    and (.required_dashboard_fields | index("predictive_dashboard.checkpoint_restore.unresolved_risks"))
    and (.required_dashboard_fields | index("predictive_dashboard.execution_queue_advisory.top_recommended_starts"))
    and (.required_dashboard_fields | index("predictive_dashboard.execution_queue_advisory.deferred_items"))
    and (.required_dashboard_fields | index("predictive_dashboard.execution_queue_advisory.restore_dependency_state"))
  ' "$contract_json" >/dev/null

  grep -Fq '/dp/frankentui' "$contract_doc"
  grep -Fq 'FrankenEngine does not ship a local TUI renderer for this contract.' "$contract_doc"
  grep -Fq "It remains the only predictive dashboard producer in \`franken_engine\`." "$contract_doc"
  grep -Fq 'scripts/swarm_capacity_forecaster.sh' "$contract_doc"
  grep -Fq 'docs/swarm_capacity_forecaster_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_admission_budget_planner.sh' "$contract_doc"
  grep -Fq 'docs/swarm_admission_budget_planner_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh' "$contract_doc"
  grep -Fq 'docs/swarm_lease_exchange_cancellation_salvage_simulator_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_warm_target_prefetch_roi_advisory.sh' "$contract_doc"
  grep -Fq 'docs/swarm_warm_target_prefetch_roi_advisory_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_starvation_rescue_planner.sh' "$contract_doc"
  grep -Fq 'docs/swarm_starvation_rescue_planner_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_starvation_rescue_conformance_gate.sh' "$contract_doc"
  grep -Fq 'docs/swarm_starvation_rescue_conformance_gate_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/SWARM_CHECKPOINT_BUNDLE_CONTRACT.md' "$contract_doc"
  grep -Fq 'docs/swarm_checkpoint_bundle_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_checkpoint_restore_planner.sh' "$contract_doc"
  grep -Fq 'docs/swarm_checkpoint_restore_planner_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_checkpoint_restore_conformance_gate.sh' "$contract_doc"
  grep -Fq 'docs/swarm_checkpoint_restore_conformance_gate_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_runner_contract_v1.json' "$contract_doc"
  grep -Fq 'execution_queue_advisory' "$contract_doc"
  grep -Fq 'deterministic source artifact path' "$contract_doc"

  if grep -Eiq 'franken_engine ships[[:space:]].*TUI|FrankenEngine ships[[:space:]].*TUI|ships a local TUI|local_renderer[[:space:]]*:[[:space:]]*true|shipped_in_franken_engine[[:space:]]*:[[:space:]]*true' "$contract_doc" "$contract_json"; then
    record_failure "dashboard docs claim a shipped local TUI"
    return 1
  fi

  record_pass "dashboard contract truth validates"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${SWARM_OPERATOR_STATUS_REPORT_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-operator-status.XXXXXX")"

  assert_dashboard_contract_truth
  run_case "healthy" "healthy" "ok" "ok" "ok" "$tmp_root"
  run_case "degraded" "degraded" "missing" "missing" "missing" "$tmp_root"
  run_case "stale_proof" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "high_cost" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "collision_risk" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "overloaded" "degraded" "ok" "degraded" "ok" "$tmp_root"
  run_case "forecast_low_confidence" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "execution_queue_conservative" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "execution_queue_restore_blocked" "degraded" "ok" "ok" "ok" "$tmp_root"

  printf 'swarm_operator_status_report_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check|selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
