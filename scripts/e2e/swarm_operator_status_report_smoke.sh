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

write_resource_envelope_fixtures() {
  local fixture_dir="$1"
  local mode="${2:-healthy}"
  local envelope_decision="pass"
  local envelope_readiness="ready"
  local plan_decision="admit"
  local admitted_count=3
  local deferred_count=0
  local heavy_admitted_count=2
  local build_lane_limit=6
  local remote_rch_slot_limit=12
  local rch_slots_used=2
  local degraded_reasons='[]'
  local blocked_reasons='[]'
  local fail_closed_reasons='[]'
  local fair_fail_closed_reasons='[]'

  case "$mode" in
    healthy)
      ;;
    degraded)
      envelope_decision="degraded"
      envelope_readiness="ready_degraded"
      plan_decision="admit_narrow"
      admitted_count=2
      deferred_count=1
      heavy_admitted_count=1
      degraded_reasons='[{"code":"optional_snapshot_missing","message":"proof cache hints were missing"}]'
      ;;
    blocked)
      envelope_decision="blocked"
      envelope_readiness="defer"
      plan_decision="defer"
      admitted_count=0
      deferred_count=3
      heavy_admitted_count=0
      rch_slots_used=0
      blocked_reasons='[{"code":"rch_slots_saturated","message":"remote RCH slots are saturated"}]'
      ;;
    contaminated)
      envelope_decision="fail_closed"
      envelope_readiness="not_ready"
      plan_decision="fail_closed"
      admitted_count=0
      deferred_count=3
      heavy_admitted_count=0
      build_lane_limit=0
      remote_rch_slot_limit=0
      rch_slots_used=0
      fail_closed_reasons='[{"code":"rch_local_fallback_contaminates_capacity","message":"RCH snapshots contain a local fallback marker"}]'
      fair_fail_closed_reasons='[{"code":"contaminated_resource_envelope","detail":"resource envelope contains fail-closed or contaminated evidence"}]'
      ;;
    *)
      record_failure "unknown resource envelope mode: ${mode}"
      exit 64
      ;;
  esac

  jq -n \
    --arg envelope_path "${fixture_dir}/swarm_resource_envelope.json" \
    --arg decision "$envelope_decision" \
    --arg readiness "$envelope_readiness" \
    --argjson build_lane_limit "$build_lane_limit" \
    --argjson remote_rch_slot_limit "$remote_rch_slot_limit" \
    --argjson degraded_reasons "$degraded_reasons" \
    --argjson blocked_reasons "$blocked_reasons" \
    --argjson fail_closed_reasons "$fail_closed_reasons" \
    '{
      schema_version:"franken-engine.swarm-resource-envelope.v1",
      envelope_id:"swarm-resource-envelope-smoke",
      source_revision:"smoke-rev",
      observed_at:"2026-05-06T20:00:00Z",
      decision:$decision,
      readiness:$readiness,
      host_identity:{host_id:"host-64c-256g", hostname:"swarm-host-a"},
      cpu_topology:{logical_cores:96, physical_cores:48, numa_nodes:2},
      memory_pressure:{total_bytes:274877906944, available_bytes:206158430208},
      target_dir_pressure:{min_available_bytes:322122547200, below_safe_budget:false},
      rch_slots:{available:$remote_rch_slot_limit, total:16, active:4},
      proof_cache:{decision:"cache_hit"},
      capacity_budget:{
        script_lane_limit:12,
        proof_lane_limit:$remote_rch_slot_limit,
        build_lane_limit:$build_lane_limit,
        remote_rch_slot_limit:$remote_rch_slot_limit,
        memory_bytes_budget:171798691840,
        target_dir_bytes_budget:311385128960,
        defer_reasons:($blocked_reasons | map(.code))
      },
      degraded_reasons:$degraded_reasons,
      blocked_reasons:$blocked_reasons,
      fail_closed_reasons:$fail_closed_reasons,
      artifact_paths:{envelope_json:$envelope_path},
      mutation_policy:{fixture_fed_only:true, runs_cargo:false, runs_rch:false, mutates_remote_workers:false, changes_live_queue_policy:false}
    }' >"${fixture_dir}/swarm_resource_envelope.json"

  jq -n \
    --arg plan_path "${fixture_dir}/swarm_fair_share_batch_plan.json" \
    --arg decision "$plan_decision" \
    --argjson admitted_count "$admitted_count" \
    --argjson deferred_count "$deferred_count" \
    --argjson heavy_admitted_count "$heavy_admitted_count" \
    --argjson build_lane_limit "$build_lane_limit" \
    --argjson remote_rch_slot_limit "$remote_rch_slot_limit" \
    --argjson rch_slots_used "$rch_slots_used" \
    --argjson fail_closed_reasons "$fair_fail_closed_reasons" \
    '{
      schema_version:"franken-engine.swarm-fair-share-batch-plan.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      summary:{
        requested_count:3,
        admitted_count:$admitted_count,
        deferred_count:$deferred_count,
        heavy_admitted_count:$heavy_admitted_count,
        heavy_lane_limit:$build_lane_limit,
        remote_rch_slot_limit:$remote_rch_slot_limit,
        rch_slots_used:$rch_slots_used,
        contaminated_input:(($fail_closed_reasons | length) > 0)
      },
      admitted_lanes:(if $admitted_count == 0 then [] else [{bead_id:"bd-heavy-a", decision:"admit_narrow", heavy_lane:true}] end),
      deferred_lanes:(if $deferred_count == 0 then [] else [{bead_id:"bd-heavy-b", decision:"defer", reasons:["resource_envelope_blocked"]}] end),
      fairness_rationale:["fixture fair-share rationale"],
      fail_closed_reasons:$fail_closed_reasons,
      artifact_paths:{swarm_fair_share_batch_plan_json:$plan_path},
      mutation_policy:{fixture_fed_only:true, runs_cargo:false, runs_rch:false, mutates_remote_workers:false, changes_live_queue_policy:false}
    }' >"${fixture_dir}/swarm_fair_share_batch_plan.json"
}

write_topology_placement_fixtures() {
  local fixture_dir="$1"
  local mode="${2:-healthy}"
  local plan_decision="pass"
  local placement_readiness="ready"
  local topology_class="numa_hot_cache_preferred"
  local adoption_decision="pass"
  local adoption_status="adopted"
  local plan_blocked_reasons='[]'
  local receipt_degraded_reasons='[]'
  local receipt_blocked_reasons='[]'
  local reason_codes='["adopted_recommended_target","cache_reuse_confirmed"]'
  local observed_worker="rch-a"
  local cache_reuse_observed="true"
  local observed_at="2026-05-06T20:40:00Z"
  local observed_epoch_seconds=1778100000

  case "$mode" in
    healthy)
      ;;
    drifted)
      adoption_decision="degraded"
      adoption_status="drifted"
      receipt_degraded_reasons='[{"code":"worker_drift","source_id":"adoption_observation_json","detail":"observed worker was not one of the recommended placement targets"},{"code":"cache_reuse_missing","source_id":"adoption_observation_json","detail":"plan recommended hot-cache reuse but observation did not confirm it"}]'
      reason_codes='["cache_reuse_missing","worker_drift"]'
      observed_worker="rch-z"
      cache_reuse_observed="false"
      ;;
    expired)
      adoption_decision="degraded"
      adoption_status="expired"
      receipt_degraded_reasons='[{"code":"receipt_expired","source_id":"validity_window","detail":"adoption observation arrived after receipt expiry"}]'
      reason_codes='["receipt_expired"]'
      observed_at="2026-05-06T21:20:01Z"
      observed_epoch_seconds=1778102401
      ;;
    blocked)
      plan_decision="blocked"
      placement_readiness="blocked"
      topology_class="blocked_contradictory_locality"
      adoption_decision="blocked"
      adoption_status="not_applicable"
      plan_blocked_reasons='[{"code":"contradictory_locality_evidence","source_id":"required_topology","detail":"required topology snapshots disagree on host identity"}]'
      receipt_blocked_reasons='[{"code":"blocked_plan_not_adoptable","source_id":"placement_plan_json","detail":"blocked placement plan cannot be adopted as a receipt target"}]'
      reason_codes='["blocked_plan_not_adoptable","contradictory_locality_evidence"]'
      ;;
    *)
      record_failure "unknown topology placement mode: ${mode}"
      exit 64
      ;;
  esac

  jq -n \
    --arg plan_path "${fixture_dir}/swarm_topology_placement_plan.json" \
    --arg decision "$plan_decision" \
    --arg readiness "$placement_readiness" \
    --arg topology_class "$topology_class" \
    --argjson blocked_reasons "$plan_blocked_reasons" \
    '{
      schema_version:"franken-engine.swarm-topology-placement-plan.v1",
      source_revision:"smoke-rev",
      bead_id:"bd-peqvp",
      plan_id:"plan-smoke-topology-placement",
      decision:$decision,
      placement_readiness:$readiness,
      recommended_topology_class:$topology_class,
      recommended_worker_targets:(if $decision == "blocked" then [] else [
        {rank:1,lane_class:"heavy",worker_id:"rch-a",numa_node:0,shard_hint:"heavy-numa-0-shard-0",cache_reuse:true,target_dir:"/mnt/rch/target-a",certainty:"confirmed",reason_codes:["numa_preferred","hot_cache_reuse"]},
        {rank:2,lane_class:"latency_sensitive",worker_id:"rch-a",numa_node:0,shard_hint:"latency_sensitive-numa-0-shard-1",cache_reuse:true,target_dir:"/mnt/rch/target-a",certainty:"confirmed",reason_codes:["numa_preferred","hot_cache_reuse"]}
      ] end),
      warm_cache_residency_state:"hot",
      warm_cache_opportunities:(if $decision == "blocked" then [] else [{
        opportunity_id:"reuse_hot_cache",
        action:"prefer_hot_cache_worker_before_cold_recompute",
        certainty:"confirmed",
        worker_ids:["rch-a"],
        target_dirs:[{path:"/mnt/rch/target-a",warm:true,cache_key:"franken-engine-main"}],
        reason_codes:["hot_cache_reuse","reuse_warm_target_dir"]
      }] end),
      degraded_reasons:[],
      blocked_reasons:$blocked_reasons,
      fail_closed_reasons:[],
      locality_assumptions:["Preferred NUMA nodes and workers are inherited from the normalized placement input.","Warm-cache reuse is advisory and must not pin workers automatically."],
      context:{host_identity:{host_id:"host-scale-a"},numa_summary:{preferred_numa_nodes:[0]},worker_inventory:{ready_worker_count:2}},
      summary:{
        target_count:(if $decision == "blocked" then 0 else 2 end),
        warm_cache_opportunity_count:(if $decision == "blocked" then 0 else 1 end),
        heavy_target_count:(if $decision == "blocked" then 0 else 1 end),
        latency_sensitive_target_count:(if $decision == "blocked" then 0 else 1 end)
      },
      artifact_paths:{swarm_topology_placement_plan_json:$plan_path},
      mutation_policy:{fixture_fed_only:true,proof_only:true,advisory_only:true,mutates_br:false,reassigns_beads:false,releases_reservations:false,sends_agent_mail:false,queries_live_agent_mail:false,runs_cargo:false,runs_rch:false,mutates_remote_workers:false,changes_live_queue_policy:false,pins_workers_automatically:false,rebinds_hosts_automatically:false,repairs_target_dirs_automatically:false}
    }' >"${fixture_dir}/swarm_topology_placement_plan.json"

  jq -n \
    --slurpfile plan "${fixture_dir}/swarm_topology_placement_plan.json" \
    --arg receipt_path "${fixture_dir}/swarm_topology_placement_receipt.json" \
    --arg ledger_path "${fixture_dir}/swarm_topology_placement_evidence_ledger.json" \
    --arg decision "$adoption_decision" \
    --arg adoption_status "$adoption_status" \
    --arg observed_worker "$observed_worker" \
    --arg observed_at "$observed_at" \
    --argjson cache_reuse_observed "$cache_reuse_observed" \
    --argjson observed_epoch_seconds "$observed_epoch_seconds" \
    --argjson degraded_reasons "$receipt_degraded_reasons" \
    --argjson blocked_reasons "$receipt_blocked_reasons" \
    --argjson reason_codes "$reason_codes" \
    '($plan[0]) as $p | {
      schema_version:"franken-engine.swarm-topology-placement-receipt.v1",
      source_revision:"smoke-rev",
      bead_id:"bd-peqvp",
      receipt_id:"receipt-smoke-topology-placement",
      source_plan:{path:$p.artifact_paths.swarm_topology_placement_plan_json,schema_version:$p.schema_version,plan_id:$p.plan_id,decision:$p.decision},
      decision:$decision,
      adoption_status:$adoption_status,
      recommended_placement_targets:$p.recommended_worker_targets,
      recommended_worker_ids:($p.recommended_worker_targets | map(.worker_id) | unique | sort),
      topology_locality_assumptions:$p.locality_assumptions,
      cache_warmth_assumptions:{state:$p.warm_cache_residency_state,opportunities:$p.warm_cache_opportunities},
      validity_window:{reference_time:"2026-05-06T20:30:00Z",reference_epoch_seconds:1778099400,ttl_seconds:1800,expires_at:"2026-05-06T21:00:00Z",expires_epoch_seconds:1778101200,expired_at_observation:($adoption_status == "expired")},
      adoption_observation:(if $adoption_status == "not_applicable" then null else {path:"adoption_observation.json",observed_at:$observed_at,observed_epoch_seconds:$observed_epoch_seconds,host_id:"host-scale-a",worker_ids:[$observed_worker],cache_reuse_observed:$cache_reuse_observed} end),
      expected_host_id:"host-scale-a",
      degraded_reasons:$degraded_reasons,
      blocked_reasons:$blocked_reasons,
      fail_closed_reasons:[],
      adoption_drift_reason_codes:$reason_codes,
      adoption_drift_reasons:(
        (if $adoption_status == "adopted" then [{code:"adopted_recommended_target",source_id:"adoption_observation_json",detail:"observation matched recommended worker and host assumptions"},{code:"cache_reuse_confirmed",source_id:"adoption_observation_json",detail:"observation confirmed hot-cache reuse"}] else [] end)
        + $degraded_reasons
        + $blocked_reasons
      ),
      artifact_paths:{placement_plan_json:$p.artifact_paths.swarm_topology_placement_plan_json,adoption_observation_json:(if $adoption_status == "not_applicable" then null else "adoption_observation.json" end),swarm_topology_placement_receipt_json:$receipt_path,swarm_topology_placement_evidence_ledger_json:$ledger_path},
      mutation_policy:{fixture_fed_only:true,proof_only:true,advisory_only:true,mutates_br:false,reassigns_beads:false,releases_reservations:false,sends_agent_mail:false,queries_live_agent_mail:false,runs_cargo:false,runs_rch:false,mutates_remote_workers:false,changes_live_queue_policy:false,pins_workers_automatically:false,rebinds_hosts_automatically:false,enforces_placement_automatically:false}
    }' >"${fixture_dir}/swarm_topology_placement_receipt.json"

  jq -n \
    --slurpfile receipt "${fixture_dir}/swarm_topology_placement_receipt.json" \
    --arg ledger_path "${fixture_dir}/swarm_topology_placement_evidence_ledger.json" \
    '($receipt[0]) as $r | {
      schema_version:"franken-engine.swarm-topology-placement-evidence-ledger.v1",
      source_revision:"smoke-rev",
      bead_id:"bd-peqvp",
      ledger_id:"ledger-smoke-topology-placement",
      decision:$r.decision,
      receipts:[$r],
      adoption_history:[{receipt_id:$r.receipt_id,plan_id:$r.source_plan.plan_id,adoption_status:$r.adoption_status,expected_host_id:$r.expected_host_id,expected_worker_ids:$r.recommended_worker_ids,observed:$r.adoption_observation,drift_reason_codes:$r.adoption_drift_reason_codes,validity_window:$r.validity_window}],
      summary:{receipt_count:1,adopted_count:(if $r.adoption_status == "adopted" then 1 else 0 end),drifted_count:(if $r.adoption_status == "drifted" then 1 else 0 end),expired_count:(if $r.adoption_status == "expired" then 1 else 0 end),blocked_count:(if $r.decision == "blocked" then 1 else 0 end),fail_closed_count:(if $r.decision == "fail_closed" then 1 else 0 end)},
      artifact_paths:{swarm_topology_placement_evidence_ledger_json:$ledger_path,swarm_topology_placement_receipt_json:$r.artifact_paths.swarm_topology_placement_receipt_json},
      mutation_policy:$r.mutation_policy
    }' >"${fixture_dir}/swarm_topology_placement_evidence_ledger.json"
}

write_capability_affinity_fixtures() {
  local fixture_dir="$1"
  local mode="${2:-healthy}"
  local advisory_decision="pass"
  local advisory_truth_state="confirmed"
  local outcome_decision="pass"
  local outcome_truth_state="confirmed"
  local routing_mode="capability_affinity_confirmed"
  local topology_class="numa_hot_cache_preferred"
  local advisory_degraded_reasons='[]'
  local advisory_blocked_reasons='[]'
  local ledger_degraded_reasons='[]'
  local ledger_blocked_reasons='[]'
  local reason_codes='["capability_coverage_confirmed","toolchain_parity_confirmed","preferred_cohort_confirmed","route_match_confirmed"]'
  local matched_task_ids='["task-cap-aff-1","task-cap-aff-2"]'
  local mismatched_task_ids='[]'
  local capability_gap_task_ids='[]'
  local toolchain_drift_task_ids='[]'
  local contamination_task_ids='[]'
  local preferred_worker_ids='["rch-a","rch-b"]'
  local advised_worker_ids='["rch-a"]'
  local required_capabilities='["cargo-check","clippy","rustfmt"]'
  local required_toolchain_fingerprints='["nightly-2026-05-06-x86_64-unknown-linux-gnu"]'
  local coverage_confirmed_task_ids='["task-cap-aff-1","task-cap-aff-2"]'
  local missing_required_capability_task_ids='[]'
  local toolchain_mismatch_task_ids='[]'
  local broader_fallback_task_ids='[]'
  local preferred_worker_count=2
  local advised_worker_count=1
  local preferred_total_score=93
  local advisory_total_score=90
  local confidence_score=91
  local outcome_rows='[
    {
      "task_id":"task-cap-aff-1",
      "recommended_worker_ids":["rch-a"],
      "observed_worker_ids":["rch-a"],
      "outcome_classification":"match",
      "observed_outcome":"match"
    },
    {
      "task_id":"task-cap-aff-2",
      "recommended_worker_ids":["rch-b"],
      "observed_worker_ids":["rch-b"],
      "outcome_classification":"match",
      "observed_outcome":"match"
    }
  ]'

  case "$mode" in
    healthy)
      ;;
    degraded)
      advisory_decision="degraded"
      advisory_truth_state="degraded"
      outcome_decision="degraded"
      outcome_truth_state="degraded"
      routing_mode="broader_cohort_fallback"
      topology_class="mixed_capability_degraded"
      advisory_degraded_reasons='[{"code":"broader_cohort_fallback","source_id":"routing_mode","detail":"preferred cohort lacked enough clean evidence so a broader advisory cohort remained visible"},{"code":"watch_workers_present","source_id":"worker_affinity_summary","detail":"watch-state workers reduced routing confidence"}]'
      ledger_degraded_reasons='[{"code":"route_mismatch_observed","source_id":"routing_outcome_samples_json","detail":"one observed task landed outside the preferred advised worker set"}]'
      reason_codes='["broader_cohort_fallback","watch_workers_present","route_mismatch_observed"]'
      matched_task_ids='["task-cap-aff-1"]'
      mismatched_task_ids='["task-cap-aff-3"]'
      preferred_worker_ids='["rch-a"]'
      advised_worker_ids='["rch-a","rch-c"]'
      broader_fallback_task_ids='["task-cap-aff-3"]'
      preferred_worker_count=1
      advised_worker_count=2
      preferred_total_score=78
      advisory_total_score=82
      confidence_score=71
      outcome_rows='[
        {
          "task_id":"task-cap-aff-1",
          "recommended_worker_ids":["rch-a"],
          "observed_worker_ids":["rch-a"],
          "outcome_classification":"match",
          "observed_outcome":"match"
        },
        {
          "task_id":"task-cap-aff-3",
          "recommended_worker_ids":["rch-a"],
          "observed_worker_ids":["rch-c"],
          "outcome_classification":"mismatch",
          "observed_outcome":"broader_match"
        }
      ]'
      ;;
    blocked)
      advisory_decision="blocked"
      advisory_truth_state="blocked"
      outcome_decision="blocked"
      outcome_truth_state="blocked"
      topology_class="blocked_toolchain_parity"
      advisory_blocked_reasons='[{"code":"required_toolchain_fingerprint_mismatch","source_id":"toolchain_parity_summary","detail":"required remote toolchain fingerprint is not present across the preferred cohort"}]'
      ledger_blocked_reasons='[{"code":"observed_capability_gap","source_id":"routing_outcome_samples_json","detail":"observed routing recorded a missing required capability"},{"code":"observed_toolchain_drift","source_id":"routing_outcome_samples_json","detail":"observed routing recorded a toolchain drift receipt"}]'
      reason_codes='["required_toolchain_fingerprint_mismatch","observed_capability_gap","observed_toolchain_drift"]'
      matched_task_ids='[]'
      capability_gap_task_ids='["task-cap-aff-5"]'
      toolchain_drift_task_ids='["task-cap-aff-4"]'
      toolchain_mismatch_task_ids='["task-cap-aff-4"]'
      coverage_confirmed_task_ids='["task-cap-aff-6"]'
      missing_required_capability_task_ids='["task-cap-aff-5"]'
      preferred_worker_ids='["rch-a"]'
      advised_worker_ids='["rch-a"]'
      preferred_worker_count=1
      advised_worker_count=1
      preferred_total_score=34
      advisory_total_score=34
      confidence_score=22
      outcome_rows='[
        {
          "task_id":"task-cap-aff-4",
          "recommended_worker_ids":["rch-a"],
          "observed_worker_ids":["rch-b"],
          "outcome_classification":"toolchain_drift",
          "observed_outcome":"toolchain_drift"
        },
        {
          "task_id":"task-cap-aff-5",
          "recommended_worker_ids":["rch-a"],
          "observed_worker_ids":["rch-a"],
          "outcome_classification":"capability_gap",
          "observed_outcome":"capability_gap"
        }
      ]'
      ;;
    *)
      record_failure "unknown capability affinity mode: ${mode}"
      exit 64
      ;;
  esac

  jq -n \
    --arg advisory_path "${fixture_dir}/swarm_capability_affinity_routing_advisory.json" \
    --arg decision "$advisory_decision" \
    --arg truth_state "$advisory_truth_state" \
    --arg routing_mode "$routing_mode" \
    --arg topology_class "$topology_class" \
    --argjson reason_codes "$reason_codes" \
    --argjson preferred_worker_ids "$preferred_worker_ids" \
    --argjson advised_worker_ids "$advised_worker_ids" \
    --argjson required_capabilities "$required_capabilities" \
    --argjson required_toolchain_fingerprints "$required_toolchain_fingerprints" \
    --argjson coverage_confirmed_task_ids "$coverage_confirmed_task_ids" \
    --argjson missing_required_capability_task_ids "$missing_required_capability_task_ids" \
    --argjson toolchain_mismatch_task_ids "$toolchain_mismatch_task_ids" \
    --argjson broader_fallback_task_ids "$broader_fallback_task_ids" \
    --argjson advisory_degraded_reasons "$advisory_degraded_reasons" \
    --argjson advisory_blocked_reasons "$advisory_blocked_reasons" \
    --argjson preferred_worker_count "$preferred_worker_count" \
    --argjson advised_worker_count "$advised_worker_count" \
    --argjson preferred_total_score "$preferred_total_score" \
    --argjson advisory_total_score "$advisory_total_score" \
    --argjson confidence_score "$confidence_score" \
    '{
      schema_version:"franken-engine.capability-affinity-queue-routing-advisory.v1",
      source_schema_version:"franken-engine.capability-affinity-queue-routing-sources.v1",
      routing_advisory_id:"car-smoke-capability-affinity",
      source_revision:"smoke-rev",
      truth_state:$truth_state,
      decision:$decision,
      reason_codes:$reason_codes,
      worker_affinity_summary:{
        task_count:3,
        routing_mode:$routing_mode,
        recommended_topology_class:$topology_class,
        preferred_worker_ids:$preferred_worker_ids,
        advised_worker_ids:$advised_worker_ids,
        excluded_worker_ids:(if $routing_mode == "broader_cohort_fallback" then ["rch-d"] else [] end),
        watch_worker_ids:(if $routing_mode == "broader_cohort_fallback" then ["rch-c"] else [] end),
        rehab_candidate_worker_ids:[],
        broader_fallback_task_ids:$broader_fallback_task_ids,
        preferred_cohort_score:{
          capability_coverage_score:(if ($missing_required_capability_task_ids | length) == 0 then 100 else 0 end),
          toolchain_parity_score:(if ($toolchain_mismatch_task_ids | length) == 0 then 100 else 0 end),
          locality_compatibility_score:(if $decision == "blocked" then 40 else 90 end),
          rehabilitation_exclusion_score:85,
          total_score:$preferred_total_score
        },
        advisory_cohort_score:{
          capability_coverage_score:(if ($missing_required_capability_task_ids | length) == 0 then 100 else 0 end),
          toolchain_parity_score:(if ($toolchain_mismatch_task_ids | length) == 0 then 100 else 0 end),
          locality_compatibility_score:(if $routing_mode == "broader_cohort_fallback" then 88 else 90 end),
          rehabilitation_exclusion_score:88,
          total_score:$advisory_total_score
        },
        confidence_score:$confidence_score
      },
      capability_coverage_summary:{
        required_capabilities:$required_capabilities,
        coverage_confirmed_task_ids:$coverage_confirmed_task_ids,
        missing_required_capability_task_ids:$missing_required_capability_task_ids,
        score:(if ($missing_required_capability_task_ids | length) == 0 then 100 else 0 end)
      },
      toolchain_parity_summary:{
        required_toolchain_fingerprints:$required_toolchain_fingerprints,
        toolchain_mismatch_task_ids:$toolchain_mismatch_task_ids,
        score:(if ($toolchain_mismatch_task_ids | length) == 0 then 100 else 0 end)
      },
      supporting_evidence_summary:{
        routing_outcome_samples_present:true,
        routing_outcome_sample_count:2
      },
      degraded_reasons:$advisory_degraded_reasons,
      blocked_reasons:$advisory_blocked_reasons,
      fail_closed_reasons:[],
      source_artifacts:[],
      artifact_paths:{
        advisory_json:$advisory_path,
        sources_json:"capability_affinity_sources.json",
        events_jsonl:"capability_affinity_events.jsonl",
        commands_txt:"capability_affinity_commands.txt",
        summary_md:"capability_affinity_summary.md"
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        reroutes_tasks_automatically:false
      }
    }' >"${fixture_dir}/swarm_capability_affinity_routing_advisory.json"

  jq -n \
    --arg ledger_path "${fixture_dir}/swarm_capability_affinity_routing_outcome_ledger.json" \
    --arg decision "$outcome_decision" \
    --arg truth_state "$outcome_truth_state" \
    --arg routing_mode "$routing_mode" \
    --argjson reason_codes "$reason_codes" \
    --argjson advised_worker_ids "$advised_worker_ids" \
    --argjson matched_task_ids "$matched_task_ids" \
    --argjson mismatched_task_ids "$mismatched_task_ids" \
    --argjson capability_gap_task_ids "$capability_gap_task_ids" \
    --argjson toolchain_drift_task_ids "$toolchain_drift_task_ids" \
    --argjson contamination_task_ids "$contamination_task_ids" \
    --argjson ledger_degraded_reasons "$ledger_degraded_reasons" \
    --argjson ledger_blocked_reasons "$ledger_blocked_reasons" \
    --argjson missing_required_capability_task_ids "$missing_required_capability_task_ids" \
    --argjson toolchain_mismatch_task_ids "$toolchain_mismatch_task_ids" \
    --argjson outcome_rows "$outcome_rows" \
    '{
      schema_version:"franken-engine.swarm-capability-affinity-routing-outcome-ledger.v1",
      source_schema_version:"franken-engine.swarm-capability-affinity-routing-outcome-sources.v1",
      outcome_ledger_id:"cal-smoke-capability-affinity",
      source_revision:"smoke-rev",
      truth_state:$truth_state,
      decision:$decision,
      routing_mode:$routing_mode,
      reason_codes:$reason_codes,
      planned_advised_worker_ids:$advised_worker_ids,
      upstream_missing_required_capability_task_ids:$missing_required_capability_task_ids,
      upstream_toolchain_mismatch_task_ids:$toolchain_mismatch_task_ids,
      matched_task_ids:$matched_task_ids,
      mismatched_task_ids:$mismatched_task_ids,
      capability_gap_task_ids:$capability_gap_task_ids,
      toolchain_drift_task_ids:$toolchain_drift_task_ids,
      contamination_task_ids:$contamination_task_ids,
      degraded_reasons:$ledger_degraded_reasons,
      blocked_reasons:$ledger_blocked_reasons,
      fail_closed_reasons:[],
      task_outcomes:$outcome_rows,
      source_artifacts:[],
      artifact_paths:{
        outcome_ledger_json:$ledger_path,
        sources_json:"capability_affinity_outcome_sources.json",
        events_jsonl:"capability_affinity_outcome_events.jsonl",
        commands_txt:"capability_affinity_outcome_commands.txt",
        summary_md:"capability_affinity_outcome_summary.md"
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        reroutes_tasks_automatically:false
      }
    }' >"${fixture_dir}/swarm_capability_affinity_routing_outcome_ledger.json"
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

write_queue_fidelity_fixtures() {
  local fixture_dir="$1"
  local mode="$2"
  local decision="pass"
  local overall_fidelity_millionths=1000000
  local confidence_band="high"
  local mismatch_class="exact_match"
  local drift_class="none"
  local row_score_millionths=1000000
  local remediation="keep current queue weights for this evidence shape"
  local task_id="bd-ready-a"
  local tuning_decision="pass"
  local plan_class="no_improvement"
  local recommended_candidate_json="null"
  local frontier_json='[{"candidate_id":"baseline_current","expected_fidelity_delta_millionths":0,"confidence_band":"low","safety_status":"no_change","manual_review_required":false}]'
  local operator_notes_json='["current weights remain best for this fixture set"]'

  case "$mode" in
    healthy)
      ;;
    high_drift)
      decision="degraded"
      overall_fidelity_millionths=420000
      confidence_band="low"
      mismatch_class="proof_brownout_miss"
      drift_class="proof_drift"
      row_score_millionths=300000
      remediation="raise proof-health penalties before trusting queue starts during brownout evidence"
      tuning_decision="degraded"
      plan_class="conflicting_improvements"
      recommended_candidate_json='{"candidate_id":"raise_proof_health_penalty","description":"Replay with stronger proof-brownout and proof-health penalties","impact_weight_delta":-30000,"reuse_weight_delta":0,"friction_weight_delta":30000,"risk_weight_delta":140000,"expected_fidelity_delta_millionths":240000,"improves_scenarios":["proof_brownout_miss"],"worsens_scenarios":[],"manual_review_required":false,"confidence_band":"high","safety_status":"safe_to_replay"}'
      frontier_json='[{"candidate_id":"raise_proof_health_penalty","expected_fidelity_delta_millionths":240000,"confidence_band":"high","safety_status":"safe_to_replay","manual_review_required":false},{"candidate_id":"raise_owner_friction_penalty","expected_fidelity_delta_millionths":200000,"confidence_band":"high","safety_status":"safe_to_replay","manual_review_required":false},{"candidate_id":"baseline_current","expected_fidelity_delta_millionths":0,"confidence_band":"low","safety_status":"no_change","manual_review_required":false}]'
      operator_notes_json='["multiple candidates improve different scenarios; keep manual review"]'
      ;;
    insufficient_evidence)
      decision="degraded"
      overall_fidelity_millionths=250000
      confidence_band="low"
      mismatch_class="missing_outcome"
      drift_class="missing_outcome"
      row_score_millionths=100000
      remediation="capture aftermath evidence before interpreting queue fidelity"
      tuning_decision="degraded"
      plan_class="insufficient_evidence"
      recommended_candidate_json='{"candidate_id":"require_aftermath_evidence","description":"Require stronger aftermath capture before tuning low-evidence rows","impact_weight_delta":0,"reuse_weight_delta":0,"friction_weight_delta":60000,"risk_weight_delta":90000,"expected_fidelity_delta_millionths":120000,"improves_scenarios":["missing_outcome"],"worsens_scenarios":[],"manual_review_required":true,"confidence_band":"insufficient_evidence","safety_status":"manual_review"}'
      frontier_json='[{"candidate_id":"require_aftermath_evidence","expected_fidelity_delta_millionths":120000,"confidence_band":"insufficient_evidence","safety_status":"manual_review","manual_review_required":true},{"candidate_id":"baseline_current","expected_fidelity_delta_millionths":0,"confidence_band":"low","safety_status":"no_change","manual_review_required":false}]'
      operator_notes_json='["insufficient aftermath evidence blocks automatic tuning interpretation"]'
      ;;
    *)
      record_failure "unknown queue fidelity fixture mode ${mode}"
      return 1
      ;;
  esac

  jq -n \
    --arg artifact_path "${fixture_dir}/fidelity_score_receipt.json" \
    --arg drift_ledger_path "${fixture_dir}/drift_ledger.json" \
    --arg decision "$decision" \
    --arg confidence_band "$confidence_band" \
    --argjson overall_fidelity_millionths "$overall_fidelity_millionths" \
    --argjson row_score_millionths "$row_score_millionths" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-fidelity-score-receipt.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      overall_fidelity_millionths:$overall_fidelity_millionths,
      confidence_band:$confidence_band,
      component_scores:{
        start_order_agreement_millionths:$overall_fidelity_millionths,
        defer_correctness_millionths:$overall_fidelity_millionths,
        proof_health_prediction_millionths:$row_score_millionths,
        owner_friction_prediction_millionths:$overall_fidelity_millionths,
        conservative_mode_appropriateness_millionths:$overall_fidelity_millionths
      },
      summary:{
        row_count:1,
        exact_match_count:(if $decision == "pass" then 1 else 0 end),
        conservative_but_correct_count:0,
        over_conservative_count:0,
        stale_owner_miss_count:0,
        proof_brownout_miss_count:(if $decision == "degraded" then 1 else 0 end),
        counterfactual_candidate_count:5,
        fail_closed_reason_count:0,
        degraded_input_count:(if $decision == "pass" then 0 else 1 end)
      },
      artifact_paths:{
        fidelity_score_receipt_json:$artifact_path,
        drift_ledger_json:$drift_ledger_path,
        events_jsonl:null,
        commands_txt:null,
        report_md:null
      }
    }' >"${fixture_dir}/fidelity_score_receipt.json"

  jq -n \
    --arg decision "$decision" \
    --arg task_id "$task_id" \
    --arg mismatch_class "$mismatch_class" \
    --arg drift_class "$drift_class" \
    --arg remediation "$remediation" \
    --argjson row_score_millionths "$row_score_millionths" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-drift-ledger.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      rows:[{
        task_id:$task_id,
        recommended_rank:1,
        actual_outcome:(if $mismatch_class == "missing_outcome" then "unknown" else "closed" end),
        fidelity_class:(if $mismatch_class == "exact_match" then "matched" else "drifted" end),
        drift_class:$drift_class,
        mismatch_class:$mismatch_class,
        row_score_millionths:$row_score_millionths,
        confidence_band:(if $row_score_millionths >= 800000 then "high" elif $row_score_millionths >= 650000 then "medium" else "low" end),
        remediation:$remediation,
        source_row:{task_id:$task_id, proof_outcome:(if $mismatch_class == "proof_brownout_miss" then "brownout" else "pass" end)}
      }],
      fail_closed_reasons:[],
      degraded_inputs:(if $decision == "pass" then [] else [{kind:$mismatch_class, source:"drift_ledger", label:$task_id, detail:$remediation}] end)
    }' >"${fixture_dir}/drift_ledger.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/counterfactual_backtest_report.json" \
    --arg tuning_plan_path "${fixture_dir}/tuning_plan.json" \
    --arg frontier_path "${fixture_dir}/frontier.json" \
    --arg decision "$tuning_decision" \
    --argjson overall_fidelity_millionths "$overall_fidelity_millionths" \
    --argjson recommended_candidate "$recommended_candidate_json" \
    --argjson frontier "$frontier_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-counterfactual-backtest-report.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      baseline_overall_fidelity_millionths:$overall_fidelity_millionths,
      evaluated_candidate_count:5,
      exact_match_count:(if $decision == "pass" then 1 else 0 end),
      positive_candidate_count:($frontier | map(select(.expected_fidelity_delta_millionths > 0)) | length),
      fail_closed_reasons:[],
      candidates:($frontier | map(. + {description:(.candidate_id // "candidate")})),
      artifact_paths:{
        counterfactual_backtest_report_json:$artifact_path,
        tuning_plan_json:$tuning_plan_path,
        frontier_json:$frontier_path,
        events_jsonl:null,
        commands_txt:null,
        report_md:null
      }
    }' >"${fixture_dir}/counterfactual_backtest_report.json"

  jq -n \
    --arg decision "$tuning_decision" \
    --arg plan_class "$plan_class" \
    --argjson recommended_candidate "$recommended_candidate_json" \
    --argjson frontier "$frontier_json" \
    --argjson operator_notes "$operator_notes_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-plan.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      plan_class:$plan_class,
      recommended_candidate:$recommended_candidate,
      ranked_candidates:$frontier,
      operator_notes:$operator_notes,
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false,
        advisory_only:true
      },
      plan_id:"swarm-execution-queue-counterfactual-smoke"
    }' >"${fixture_dir}/tuning_plan.json"

  jq -n --argjson frontier "$frontier_json" '{
    schema_version:"franken-engine.swarm-execution-queue-counterfactual-frontier.v1",
    source_revision:"smoke-rev",
    frontier:$frontier
  }' >"${fixture_dir}/frontier.json"
}

write_queue_tuning_promotion_fixtures() {
  local fixture_dir="$1"
  local mode="$2"
  local bundle_decision="ready"
  local guard_decision="eligible_canary"
  local rollout_decision="ready_for_manual_approval"
  local rollback_verdict="better_than_current"
  local canary_verdict="canary_running"
  local canary_action="continue_canary"
  local candidate_id="raise_proof_health_penalty"
  local candidate_delta_millionths=240000
  local reject_reasons_json='[]'
  local blockers_json='[]'
  local rollback_triggers_json='[]'
  local stop_conditions_json='[{"metric":"fidelity_delta_millionths","operator":"lt","threshold_millionths":0,"recommended_action":"rollback_required"}]'
  local evidence_links_json='[{"kind":"fidelity_score_receipt","path":"fidelity_score_receipt.json"},{"kind":"counterfactual_backtest_report","path":"counterfactual_backtest_report.json"},{"kind":"rollback_comparator_receipt","path":"rollback_comparator_receipt.json"}]'

  case "$mode" in
    healthy)
      ;;
    blocked)
      guard_decision="reject"
      rollout_decision="blocked"
      canary_verdict="not_started"
      canary_action="hold_canary"
      reject_reasons_json='["manual_approval_missing","bundle_not_reviewed"]'
      blockers_json='[{"code":"manual_approval_missing","detail":"operator approval is required before canary promotion"},{"code":"bundle_not_reviewed","detail":"policy bundle has not been reviewed"}]'
      ;;
    stale_evidence)
      guard_decision="reject"
      rollout_decision="blocked"
      canary_verdict="not_started"
      canary_action="hold_canary"
      reject_reasons_json='["stale_evidence"]'
      blockers_json='[{"code":"stale_evidence","detail":"bundle evidence is older than the freshness window"}]'
      ;;
    rollback_required)
      rollback_verdict="worse_than_current"
      canary_verdict="regressed"
      canary_action="rollback_required"
      rollback_triggers_json='[{"metric":"queue_fidelity_delta_millionths","observed_millionths":-64000,"threshold_millionths":0,"recommended_action":"rollback_required"}]'
      ;;
    *)
      record_failure "unknown queue tuning promotion fixture mode ${mode}"
      return 1
      ;;
  esac

  jq -n \
    --arg artifact_path "${fixture_dir}/tuning_policy_bundle.json" \
    --arg decision "$bundle_decision" \
    --arg candidate_id "$candidate_id" \
    --argjson candidate_delta_millionths "$candidate_delta_millionths" \
    --argjson evidence_links "$evidence_links_json" \
    --argjson blockers "$blockers_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      bundle_id:"queue-tuning-policy-bundle-smoke",
      promoted_candidate:{
        candidate_id:$candidate_id,
        expected_fidelity_delta_millionths:$candidate_delta_millionths,
        confidence_band:"high",
        safety_status:"safe_to_replay"
      },
      evidence_links:$evidence_links,
      manual_approval:{required:true, blockers:$blockers},
      rollback_references:{
        rollback_comparator_receipt_json:"rollback_comparator_receipt.json",
        canary_verdict_ledger_json:"canary_verdict_ledger.json"
      },
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false,
        advisory_only:true
      },
      artifact_paths:{tuning_policy_bundle_json:$artifact_path}
    }' >"${fixture_dir}/tuning_policy_bundle.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/promotion_guard_receipt.json" \
    --arg decision "$guard_decision" \
    --arg candidate_id "$candidate_id" \
    --argjson candidate_delta_millionths "$candidate_delta_millionths" \
    --argjson reject_reasons "$reject_reasons_json" \
    --argjson blockers "$blockers_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-promotion-guard-receipt.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      candidate_id:$candidate_id,
      expected_fidelity_delta_millionths:$candidate_delta_millionths,
      reject_reasons:$reject_reasons,
      manual_approval_blockers:$blockers,
      preconditions:{
        bundle_reviewed:(($reject_reasons | index("bundle_not_reviewed")) == null),
        evidence_fresh:(($reject_reasons | index("stale_evidence")) == null),
        manual_approval_present:(($reject_reasons | index("manual_approval_missing")) == null)
      },
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false,
        advisory_only:true
      },
      artifact_paths:{promotion_guard_receipt_json:$artifact_path}
    }' >"${fixture_dir}/promotion_guard_receipt.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/manual_approval_rollout_plan.json" \
    --arg decision "$rollout_decision" \
    --argjson blockers "$blockers_json" \
    --argjson reject_reasons "$reject_reasons_json" \
    --argjson stop_conditions "$stop_conditions_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-manual-approval-rollout-plan.v1",
      source_revision:"smoke-rev",
      decision:$decision,
      manual_approval:{
        required:true,
        approver_role:"operator",
        blockers:$blockers
      },
      rejection_reasons:$reject_reasons,
      stop_conditions:$stop_conditions,
      canary:{recommended_action:"continue_canary", initial_fraction_millionths:100000},
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false,
        advisory_only:true
      },
      artifact_paths:{manual_approval_rollout_plan_json:$artifact_path}
    }' >"${fixture_dir}/manual_approval_rollout_plan.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/rollback_comparator_receipt.json" \
    --arg verdict "$rollback_verdict" \
    --arg candidate_id "$candidate_id" \
    --argjson candidate_delta_millionths "$candidate_delta_millionths" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-tuning-rollback-comparator-receipt.v1",
      source_revision:"smoke-rev",
      verdict:$verdict,
      current_policy_id:"current-queue-policy",
      candidate_policy_id:$candidate_id,
      fidelity_delta_millionths:(if $verdict == "worse_than_current" then -64000 else $candidate_delta_millionths end),
      fail_closed_reasons:[],
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false,
        advisory_only:true
      },
      artifact_paths:{rollback_comparator_receipt_json:$artifact_path}
    }' >"${fixture_dir}/rollback_comparator_receipt.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/canary_verdict_ledger.json" \
    --arg verdict "$canary_verdict" \
    --arg recommended_action "$canary_action" \
    --argjson rollback_triggers "$rollback_triggers_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-canary-verdict-ledger.v1",
      source_revision:"smoke-rev",
      verdict:$verdict,
      recommended_action:$recommended_action,
      rollback_triggers:$rollback_triggers,
      fail_closed_reasons:[],
      mutation_policy:{
        changes_active_queue:false,
        applies_live_retuning:false,
        advisory_only:true
      },
      artifact_paths:{canary_verdict_ledger_json:$artifact_path}
  }' >"${fixture_dir}/canary_verdict_ledger.json"
}

write_queue_policy_adoption_fixtures() {
  local fixture_dir="$1"
  local mode="$2"
  local sustained_verdict="sustained_gain"
  local expiry_decision="retain_adopted_policy"
  local expiry_required=false
  local supersession_required=false
  local newer_bundle_id="queue-tuning-policy-bundle-smoke"
  local newer_candidate_id="raise_proof_health_penalty"
  local decision_reasons_json='[{"kind":"sustained_gain_retained","detail":"sustained-gain evidence supports retention"}]'
  local ledger_effect="retention_support"

  case "$mode" in
    healthy)
      ;;
    expiry_required)
      sustained_verdict="regression_detected"
      expiry_decision="expire_adopted_policy"
      expiry_required=true
      decision_reasons_json='[{"kind":"sustained_gain_regression","detail":"sustained-gain receipt reports regression"},{"kind":"rollback_relevant_drift","detail":"post-adoption drift ledger contains rollback-relevant rows"}]'
      ledger_effect="expiry_pressure"
      ;;
    supersession_required)
      expiry_decision="supersede_adopted_policy"
      expiry_required=true
      supersession_required=true
      newer_bundle_id="queue-tuning-policy-bundle-next"
      newer_candidate_id="raise_owner_friction_penalty"
      decision_reasons_json='[{"kind":"newer_candidate_available","detail":"newer candidate bundle improves expected fidelity delta"}]'
      ledger_effect="supersession_pressure"
      ;;
    *)
      record_failure "unknown queue policy adoption fixture mode ${mode}"
      return 1
      ;;
  esac

  jq -n \
    --arg artifact_path "${fixture_dir}/adoption_receipt.json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-adoption-receipt.v1",
      adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
      adopted_policy_bundle_id:"queue-tuning-policy-bundle-smoke",
      source_revision:"smoke-rev",
      generated_at:"2026-05-06T00:00:00Z",
      decision:"admitted",
      operator_decision:{decision:"adopt",approved_by:"human_operator",approved_at:"2026-05-06T00:00:00Z",approval_artifact_path:"approvals/queue-policy-adoption.json",decision_reason:"eligible evidence",adoption_state:"recorded_active_policy"},
      adopted_candidate:{candidate_id:"raise_proof_health_penalty",expected_fidelity_delta_millionths:240000,source_policy_bundle_id:"queue-tuning-policy-bundle-smoke",source_promotion_guard_receipt_json:"promotion_guard_receipt.json",source_canary_verdict_ledger_json:"canary_verdict_ledger.json"},
      observation_window:{starts_at:"2026-05-06T00:00:00Z",duration_seconds:3600,minimum_sample_count:3,monitored_metrics:["queue_fidelity_millionths","proof_drift_count","rollback_trigger_count"],stop_on_missing_evidence:true},
      supersession:{supersedes_adoption_receipt_id:null,supersedes_policy_bundle_id:"current-queue-policy",supersession_reason:"smoke",previous_policy_retention:"retain_for_rollback",expiry_policy:"score after window"},
      mutation_policy:{receipt_artifact_only:true,records_operator_decision:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
      artifact_paths:{adoption_receipt_json:$artifact_path}
    }' >"${fixture_dir}/adoption_receipt.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/adoption_snapshot_bundle.json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-adoption-snapshot-bundle.v1",
      snapshot_id:"queue-policy-adoption-snapshot-smoke",
      adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
      adopted_policy_bundle_id:"queue-tuning-policy-bundle-smoke",
      candidate_id:"raise_proof_health_penalty",
      source_revision:"smoke-rev",
      generated_at:"2026-05-06T00:00:00Z",
      decision:"admitted",
      normalized_inputs:{rollback_comparator_receipt:{current_fidelity_millionths:760000,candidate_expected_fidelity_millionths:1000000,candidate_delta_millionths:240000}},
      mutation_policy:{receipt_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
      artifact_paths:{adoption_snapshot_bundle_json:$artifact_path}
    }' >"${fixture_dir}/adoption_snapshot_bundle.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/sustained_gain_receipt.json" \
    --arg sustained_verdict "$sustained_verdict" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-sustained-gain-receipt.v1",
      sustained_gain_receipt_id:"queue-policy-sustained-gain-smoke",
      source_revision:"smoke-rev",
      generated_at:"2026-05-06T01:00:00Z",
      verdict:$sustained_verdict,
      adopted_policy_bundle_id:"queue-tuning-policy-bundle-smoke",
      adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
      candidate_id:"raise_proof_health_penalty",
      baseline_fidelity_millionths:760000,
      promised_delta_millionths:240000,
      sustained_floor_millionths:880000,
      observed_fidelity_millionths:(if $sustained_verdict == "regression_detected" then 700000 else 900000 end),
      rollback_drift_count:(if $sustained_verdict == "regression_detected" then 1 else 0 end),
      fail_closed_reasons:[],
      mutation_policy:{scoring_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false},
      artifact_paths:{sustained_gain_receipt_json:$artifact_path}
    }' >"${fixture_dir}/sustained_gain_receipt.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/expiry_supersession_plan.json" \
    --arg expiry_decision "$expiry_decision" \
    --arg newer_bundle_id "$newer_bundle_id" \
    --arg newer_candidate_id "$newer_candidate_id" \
    --argjson expiry_required "$expiry_required" \
    --argjson supersession_required "$supersession_required" \
    --argjson decision_reasons "$decision_reasons_json" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-expiry-supersession-plan.v1",
      plan_id:"queue-policy-expiry-supersession-smoke",
      source_revision:"smoke-rev",
      generated_at:"2026-05-06T02:00:00Z",
      decision:$expiry_decision,
      adopted_policy_bundle_id:"queue-tuning-policy-bundle-smoke",
      adoption_receipt_id:"queue-policy-adoption-receipt-smoke",
      adopted_candidate_id:"raise_proof_health_penalty",
      adopted_expected_delta_millionths:240000,
      sustained_gain_receipt_id:"queue-policy-sustained-gain-smoke",
      sustained_gain_verdict:(if $expiry_decision == "expire_adopted_policy" then "regression_detected" else "sustained_gain" end),
      rollback_relevant_drift_count:(if $expiry_decision == "expire_adopted_policy" then 1 else 0 end),
      newer_candidate_bundle_id:$newer_bundle_id,
      newer_candidate_id:$newer_candidate_id,
      expiry_required:$expiry_required,
      supersession_required:$supersession_required,
      advisory_status:{planning_artifact_only:true,execution_state:"advisory_not_executed",retirement_executed:false,supersession_executed:false,execution_evidence:"not supplied"},
      decision_reasons:$decision_reasons,
      fail_closed_reasons:[],
      mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false,retirement_executed:false,supersession_executed:false},
      artifact_paths:{expiry_supersession_plan_json:$artifact_path,expiry_supersession_ledger_json:"expiry_supersession_ledger.json"}
    }' >"${fixture_dir}/expiry_supersession_plan.json"

  jq -n \
    --arg artifact_path "${fixture_dir}/expiry_supersession_ledger.json" \
    --arg expiry_decision "$expiry_decision" \
    --arg ledger_effect "$ledger_effect" \
    '{
      schema_version:"franken-engine.swarm-execution-queue-policy-expiry-supersession-ledger.v1",
      source_revision:"smoke-rev",
      generated_at:"2026-05-06T02:00:00Z",
      decision:$expiry_decision,
      ledger_rows:[
        {check:"sustained_gain_verdict",observed_value:(if $expiry_decision == "expire_adopted_policy" then "regression_detected" else "sustained_gain" end),effect:$ledger_effect},
        {check:"newer_candidate_delta",observed_value:(if $expiry_decision == "supersede_adopted_policy" then "320000" else "240000" end),adopted_value:"240000",effect:$ledger_effect},
        {check:"rollback_relevant_drift_count",observed_value:(if $expiry_decision == "expire_adopted_policy" then "1" else "0" end),effect:$ledger_effect}
      ],
      ownership_rows:[],
      fail_closed_reasons:[],
      mutation_policy:{planning_artifact_only:true,changes_active_queue:false,applies_live_retuning:false,mutates_br:false,sends_agent_mail:false,mutates_remote_workers:false,rewrites_historical_outcomes:false,retirement_executed:false,supersession_executed:false},
      artifact_paths:{expiry_supersession_ledger_json:$artifact_path}
  }' >"${fixture_dir}/expiry_supersession_ledger.json"
}

write_causal_trace_fixtures() {
  local fixture_dir="$1"
  local mode="$2"
  local decision="pass"
  local bead_status="closed"
  local anomaly_class=""
  local anomaly_severity=""
  local anomaly_message=""

  case "$mode" in
    complete)
      ;;
    degraded)
      decision="degraded"
      bead_status="in_progress"
      anomaly_class="missing_claim_message"
      anomaly_severity="degraded"
      anomaly_message="claim message evidence is absent from supplied coordination snapshots"
      ;;
    contaminated)
      decision="fail_closed"
      bead_status="in_progress"
      anomaly_class="local_rch_fallback_contaminates_remote_proof"
      anomaly_severity="fail_closed"
      anomaly_message="local fallback marker contradicts claimed remote validation proof"
      ;;
    *)
      record_failure "unknown causal trace fixture mode: ${mode}"
      exit 64
      ;;
  esac

  jq -n \
    --arg mode "$mode" \
    --arg decision "$decision" \
    --arg bead_status "$bead_status" \
    --arg anomaly_class "$anomaly_class" \
    --arg anomaly_severity "$anomaly_severity" \
    --arg anomaly_message "$anomaly_message" \
    --arg graph_path "${fixture_dir}/causal_trace_graph.json" \
    --arg anomaly_path "${fixture_dir}/causal_trace_anomalies.json" \
    '{
      schema_version:"franken-engine.swarm-agent-causal-trace-graph.v1",
      trace_id:("trace-" + $mode),
      bead_id:"bd-jw854",
      source_revision:"smoke-rev",
      nodes:[
        {node_id:"agent:ScarletOwl",node_type:"agent_profile",payload:{agent_name:"ScarletOwl"}},
        {node_id:"bead:bd-jw854",node_type:"bead_state",payload:{id:"bd-jw854",status:$bead_status,assignee:"ScarletOwl"}},
        {node_id:"reservation:scripts/swarm_operator_status_report.sh",node_type:"file_reservation",payload:{path:"scripts/swarm_operator_status_report.sh",holder:"ScarletOwl"}},
        {node_id:"validation:operator-status-smoke",node_type:"validation_command",payload:{command:"bash -n scripts/swarm_operator_status_report.sh",decision:"pass"}},
        {node_id:"commit:operator-status-smoke",node_type:"git_commit",payload:{commit:"smoke-commit",message:"feat(swarm): add causal trace operator status"}}
      ],
      edges:(
        [
          {edge_id:"edge-reservation",edge_type:"reservation_covers_path",from:"reservation:scripts/swarm_operator_status_report.sh",to:"bead:bd-jw854",decision:"pass"},
          {edge_id:"edge-validation",edge_type:"validation_proves_closeout",from:"validation:operator-status-smoke",to:"bead:bd-jw854",decision:"pass"},
          {edge_id:"edge-commit",edge_type:"commit_closes_bead",from:"commit:operator-status-smoke",to:"bead:bd-jw854",decision:"pass"}
        ]
        + (if $mode == "degraded" then [] else [{edge_id:"edge-claim",edge_type:"bead_claimed",from:"agent:ScarletOwl",to:"bead:bd-jw854",decision:"pass"}] end)
      ),
      anomaly_summary:{
        decision:$decision,
        anomaly_count:(if $mode == "complete" then 0 else 1 end),
        fail_closed_count:(if $mode == "contaminated" then 1 else 0 end),
        degraded_count:(if $mode == "degraded" then 1 else 0 end),
        anomaly_classes:(if $mode == "complete" then [] else [$anomaly_class] end)
      },
      mutation_policy:{
        fixture_fed_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        queries_live_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        rewrites_historical_outcomes:false,
        operator_wording_required:"advisory-only"
      },
      artifact_paths:{
        causal_graph_json:$graph_path,
        anomaly_report_json:$anomaly_path
      }
    }' >"${fixture_dir}/causal_trace_graph.json"

  jq -n \
    --arg mode "$mode" \
    --arg decision "$decision" \
    --arg anomaly_class "$anomaly_class" \
    --arg anomaly_severity "$anomaly_severity" \
    --arg anomaly_message "$anomaly_message" \
    --arg anomaly_path "${fixture_dir}/causal_trace_anomalies.json" \
    '{
      schema_version:"franken-engine.swarm-agent-causal-trace-anomaly-report.v1",
      trace_id:("trace-" + $mode),
      bead_id:"bd-jw854",
      source_revision:"smoke-rev",
      decision:$decision,
      anomaly_count:(if $mode == "complete" then 0 else 1 end),
      fail_closed_count:(if $mode == "contaminated" then 1 else 0 end),
      degraded_count:(if $mode == "degraded" then 1 else 0 end),
      anomaly_classes:(if $mode == "complete" then [] else [$anomaly_class] end),
      anomalies:(
        if $mode == "complete" then []
        else [{anomaly_id:("anomaly-" + $mode),anomaly_class:$anomaly_class,severity:$anomaly_severity,message:$anomaly_message,bead_id:"bd-jw854"}]
        end
      ),
      artifact_paths:{anomaly_report_json:$anomaly_path}
    }' >"${fixture_dir}/causal_trace_anomalies.json"
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
  write_queue_fidelity_fixtures "$fixture_dir" "healthy"
  write_queue_tuning_promotion_fixtures "$fixture_dir" "healthy"
  write_queue_policy_adoption_fixtures "$fixture_dir" "healthy"
  write_causal_trace_fixtures "$fixture_dir" "complete"
  write_resource_envelope_fixtures "$fixture_dir" "healthy"
  write_topology_placement_fixtures "$fixture_dir" "healthy"
  write_capability_affinity_fixtures "$fixture_dir" "healthy"
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
    queue_fidelity_high_drift)
      write_healthy_fixtures "$fixture_dir"
      write_queue_fidelity_fixtures "$fixture_dir" "high_drift"
      ;;
    queue_fidelity_insufficient_evidence)
      write_healthy_fixtures "$fixture_dir"
      write_queue_fidelity_fixtures "$fixture_dir" "insufficient_evidence"
      ;;
    queue_tuning_promotion_blocked)
      write_healthy_fixtures "$fixture_dir"
      write_queue_tuning_promotion_fixtures "$fixture_dir" "blocked"
      ;;
    queue_tuning_promotion_stale_evidence)
      write_healthy_fixtures "$fixture_dir"
      write_queue_tuning_promotion_fixtures "$fixture_dir" "stale_evidence"
      ;;
    queue_tuning_promotion_rollback_required)
      write_healthy_fixtures "$fixture_dir"
      write_queue_tuning_promotion_fixtures "$fixture_dir" "rollback_required"
      ;;
    queue_policy_adoption_expiry_required)
      write_healthy_fixtures "$fixture_dir"
      write_queue_policy_adoption_fixtures "$fixture_dir" "expiry_required"
      ;;
    queue_policy_adoption_supersession_required)
      write_healthy_fixtures "$fixture_dir"
      write_queue_policy_adoption_fixtures "$fixture_dir" "supersession_required"
      ;;
    causal_trace_degraded)
      write_healthy_fixtures "$fixture_dir"
      write_causal_trace_fixtures "$fixture_dir" "degraded"
      ;;
    causal_trace_contaminated)
      write_healthy_fixtures "$fixture_dir"
      write_causal_trace_fixtures "$fixture_dir" "contaminated"
      ;;
    resource_envelope_healthy)
      write_healthy_fixtures "$fixture_dir"
      write_resource_envelope_fixtures "$fixture_dir" "healthy"
      ;;
    resource_envelope_degraded)
      write_healthy_fixtures "$fixture_dir"
      write_resource_envelope_fixtures "$fixture_dir" "degraded"
      ;;
    resource_envelope_blocked)
      write_healthy_fixtures "$fixture_dir"
      write_resource_envelope_fixtures "$fixture_dir" "blocked"
      ;;
    resource_envelope_contaminated)
      write_healthy_fixtures "$fixture_dir"
      write_resource_envelope_fixtures "$fixture_dir" "contaminated"
      ;;
    topology_placement_healthy)
      write_healthy_fixtures "$fixture_dir"
      write_topology_placement_fixtures "$fixture_dir" "healthy"
      ;;
    topology_placement_drifted)
      write_healthy_fixtures "$fixture_dir"
      write_topology_placement_fixtures "$fixture_dir" "drifted"
      ;;
    topology_placement_expired)
      write_healthy_fixtures "$fixture_dir"
      write_topology_placement_fixtures "$fixture_dir" "expired"
      ;;
    topology_placement_blocked)
      write_healthy_fixtures "$fixture_dir"
      write_topology_placement_fixtures "$fixture_dir" "blocked"
      ;;
    capability_affinity_healthy)
      write_healthy_fixtures "$fixture_dir"
      write_capability_affinity_fixtures "$fixture_dir" "healthy"
      ;;
    capability_affinity_degraded)
      write_healthy_fixtures "$fixture_dir"
      write_capability_affinity_fixtures "$fixture_dir" "degraded"
      ;;
    capability_affinity_blocked)
      write_healthy_fixtures "$fixture_dir"
      write_capability_affinity_fixtures "$fixture_dir" "blocked"
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
  [[ -f "${fixture_dir}/fidelity_score_receipt.json" ]] && extra_args+=(--queue-fidelity-score-receipt-json "${fixture_dir}/fidelity_score_receipt.json")
  [[ -f "${fixture_dir}/drift_ledger.json" ]] && extra_args+=(--queue-drift-ledger-json "${fixture_dir}/drift_ledger.json")
  [[ -f "${fixture_dir}/counterfactual_backtest_report.json" ]] && extra_args+=(--queue-counterfactual-backtest-report-json "${fixture_dir}/counterfactual_backtest_report.json")
  [[ -f "${fixture_dir}/tuning_plan.json" ]] && extra_args+=(--queue-tuning-plan-json "${fixture_dir}/tuning_plan.json")
  [[ -f "${fixture_dir}/frontier.json" ]] && extra_args+=(--queue-tuning-frontier-json "${fixture_dir}/frontier.json")
  [[ -f "${fixture_dir}/tuning_policy_bundle.json" ]] && extra_args+=(--queue-tuning-bundle-json "${fixture_dir}/tuning_policy_bundle.json")
  [[ -f "${fixture_dir}/promotion_guard_receipt.json" ]] && extra_args+=(--queue-tuning-promotion-guard-receipt-json "${fixture_dir}/promotion_guard_receipt.json")
  [[ -f "${fixture_dir}/manual_approval_rollout_plan.json" ]] && extra_args+=(--queue-tuning-rollout-plan-json "${fixture_dir}/manual_approval_rollout_plan.json")
  [[ -f "${fixture_dir}/rollback_comparator_receipt.json" ]] && extra_args+=(--queue-tuning-rollback-comparator-receipt-json "${fixture_dir}/rollback_comparator_receipt.json")
  [[ -f "${fixture_dir}/canary_verdict_ledger.json" ]] && extra_args+=(--queue-tuning-canary-verdict-ledger-json "${fixture_dir}/canary_verdict_ledger.json")
  [[ -f "${fixture_dir}/adoption_receipt.json" ]] && extra_args+=(--queue-policy-adoption-receipt-json "${fixture_dir}/adoption_receipt.json")
  [[ -f "${fixture_dir}/adoption_snapshot_bundle.json" ]] && extra_args+=(--queue-policy-adoption-snapshot-bundle-json "${fixture_dir}/adoption_snapshot_bundle.json")
  [[ -f "${fixture_dir}/sustained_gain_receipt.json" ]] && extra_args+=(--queue-policy-sustained-gain-receipt-json "${fixture_dir}/sustained_gain_receipt.json")
  [[ -f "${fixture_dir}/expiry_supersession_plan.json" ]] && extra_args+=(--queue-policy-expiry-supersession-plan-json "${fixture_dir}/expiry_supersession_plan.json")
  [[ -f "${fixture_dir}/expiry_supersession_ledger.json" ]] && extra_args+=(--queue-policy-expiry-supersession-ledger-json "${fixture_dir}/expiry_supersession_ledger.json")
  [[ -f "${fixture_dir}/causal_trace_graph.json" ]] && extra_args+=(--swarm-agent-causal-trace-graph-json "${fixture_dir}/causal_trace_graph.json")
  [[ -f "${fixture_dir}/causal_trace_anomalies.json" ]] && extra_args+=(--swarm-agent-causal-trace-anomaly-report-json "${fixture_dir}/causal_trace_anomalies.json")
  [[ -f "${fixture_dir}/swarm_resource_envelope.json" ]] && extra_args+=(--swarm-resource-envelope-json "${fixture_dir}/swarm_resource_envelope.json")
  [[ -f "${fixture_dir}/swarm_fair_share_batch_plan.json" ]] && extra_args+=(--swarm-fair-share-batch-plan-json "${fixture_dir}/swarm_fair_share_batch_plan.json")
  [[ -f "${fixture_dir}/swarm_topology_placement_plan.json" ]] && extra_args+=(--swarm-topology-placement-plan-json "${fixture_dir}/swarm_topology_placement_plan.json")
  [[ -f "${fixture_dir}/swarm_topology_placement_receipt.json" ]] && extra_args+=(--swarm-topology-placement-receipt-json "${fixture_dir}/swarm_topology_placement_receipt.json")
  [[ -f "${fixture_dir}/swarm_topology_placement_evidence_ledger.json" ]] && extra_args+=(--swarm-topology-placement-evidence-ledger-json "${fixture_dir}/swarm_topology_placement_evidence_ledger.json")
  [[ -f "${fixture_dir}/swarm_capability_affinity_routing_advisory.json" ]] && extra_args+=(--swarm-capability-affinity-routing-advisory-json "${fixture_dir}/swarm_capability_affinity_routing_advisory.json")
  [[ -f "${fixture_dir}/swarm_capability_affinity_routing_outcome_ledger.json" ]] && extra_args+=(--swarm-capability-affinity-routing-outcome-ledger-json "${fixture_dir}/swarm_capability_affinity_routing_outcome_ledger.json")

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
    and (.predictive_dashboard.queue_fidelity.trust_level | type == "string")
    and (.predictive_dashboard.queue_fidelity.drift_class | type == "string")
    and ((.predictive_dashboard.queue_fidelity.highest_severity_mismatch == null) or (.predictive_dashboard.queue_fidelity.highest_severity_mismatch | type == "object"))
    and ((.predictive_dashboard.queue_fidelity.top_tuning_recommendation == null) or (.predictive_dashboard.queue_fidelity.top_tuning_recommendation | type == "object"))
    and (.predictive_dashboard.queue_fidelity.frontier | type == "array")
    and (.predictive_dashboard.queue_fidelity.mutation_policy.advisory_only == true)
    and (.predictive_dashboard.queue_fidelity.mutation_policy.changes_active_queue == false)
    and (.predictive_dashboard.queue_fidelity.mutation_policy.applies_live_retuning == false)
    and (.predictive_dashboard.queue_tuning_promotion.readiness | type == "string")
    and (.predictive_dashboard.queue_tuning_promotion.promotion_decision | type == "string")
    and (.predictive_dashboard.queue_tuning_promotion.rollback_verdict | type == "string")
    and (.predictive_dashboard.queue_tuning_promotion.canary_recommended_action | type == "string")
    and (.predictive_dashboard.queue_tuning_promotion.manual_approval_blocker_count | type == "number")
    and (.predictive_dashboard.queue_tuning_promotion.evidence_link_count | type == "number")
    and (.predictive_dashboard.queue_tuning_promotion.mutation_policy.advisory_only == true)
    and (.predictive_dashboard.queue_tuning_promotion.mutation_policy.changes_active_queue == false)
    and (.predictive_dashboard.queue_tuning_promotion.mutation_policy.applies_live_retuning == false)
    and (.predictive_dashboard.queue_policy_adoption.readiness | type == "string")
    and (.predictive_dashboard.queue_policy_adoption.adoption_state | type == "string")
    and (.predictive_dashboard.queue_policy_adoption.sustained_gain_verdict | type == "string")
    and (.predictive_dashboard.queue_policy_adoption.expiry_decision | type == "string")
    and (.predictive_dashboard.queue_policy_adoption.expiry_required | type == "boolean")
    and (.predictive_dashboard.queue_policy_adoption.supersession_required | type == "boolean")
    and (.predictive_dashboard.queue_policy_adoption.execution_state | type == "string")
    and (.predictive_dashboard.queue_policy_adoption.mutation_policy.advisory_only == true)
    and (.predictive_dashboard.queue_policy_adoption.mutation_policy.changes_active_queue == false)
    and (.predictive_dashboard.queue_policy_adoption.mutation_policy.applies_live_retuning == false)
    and (.predictive_dashboard.queue_policy_adoption.mutation_policy.retirement_executed == false)
    and (.predictive_dashboard.queue_policy_adoption.mutation_policy.supersession_executed == false)
    and (.predictive_dashboard.swarm_agent_causal_trace.readiness | type == "string")
    and (.predictive_dashboard.swarm_agent_causal_trace.decision | type == "string")
    and (.predictive_dashboard.swarm_agent_causal_trace.missing_required_edges | type == "array")
    and (.predictive_dashboard.swarm_agent_causal_trace.anomaly_classes | type == "array")
    and (.predictive_dashboard.swarm_agent_causal_trace.mutation_policy.fixture_fed_only == true)
    and (.predictive_dashboard.swarm_agent_causal_trace.mutation_policy.mutates_br == false)
    and (.predictive_dashboard.swarm_agent_causal_trace.mutation_policy.sends_agent_mail == false)
    and (.predictive_dashboard.swarm_agent_causal_trace.mutation_policy.runs_rch == false)
    and (.predictive_dashboard.swarm_resource_envelope.readiness | type == "string")
    and (.predictive_dashboard.swarm_resource_envelope.decision | type == "string")
    and (.predictive_dashboard.swarm_resource_envelope.fair_share_decision | type == "string")
    and (.predictive_dashboard.swarm_resource_envelope.capacity.build_lane_limit | type == "number")
    and (.predictive_dashboard.swarm_resource_envelope.capacity.remote_rch_slot_limit | type == "number")
    and (.predictive_dashboard.swarm_resource_envelope.fair_share.admitted_count | type == "number")
    and (.predictive_dashboard.swarm_resource_envelope.fair_share.deferred_count | type == "number")
    and (.predictive_dashboard.swarm_resource_envelope.contaminating_classes | type == "array")
    and (.predictive_dashboard.swarm_topology_placement.readiness | type == "string")
    and (.predictive_dashboard.swarm_topology_placement.plan_decision | type == "string")
    and (.predictive_dashboard.swarm_topology_placement.receipt_decision | type == "string")
    and (.predictive_dashboard.swarm_topology_placement.recommended_topology_class | type == "string")
    and (.predictive_dashboard.swarm_topology_placement.recommended_worker_target_count | type == "number")
    and (.predictive_dashboard.swarm_topology_placement.heavy_target_count | type == "number")
    and (.predictive_dashboard.swarm_topology_placement.latency_sensitive_target_count | type == "number")
    and (.predictive_dashboard.swarm_topology_placement.warm_cache_residency_state | type == "string")
    and (.predictive_dashboard.swarm_topology_placement.warm_cache_opportunity_count | type == "number")
    and (.predictive_dashboard.swarm_topology_placement.shard_hints | type == "array")
    and (.predictive_dashboard.swarm_topology_placement.adoption_status | type == "string")
    and (.predictive_dashboard.swarm_topology_placement.adoption_drift_reason_codes | type == "array")
    and (.predictive_dashboard.swarm_topology_placement.expiry | type == "object")
    and (.predictive_dashboard.swarm_topology_placement.warnings | type == "array")
    and (.predictive_dashboard.swarm_topology_placement.artifact_paths | type == "object")
    and (.predictive_dashboard.swarm_topology_placement.mutation_policy.advisory_only == true)
    and (.predictive_dashboard.swarm_topology_placement.mutation_policy.mutates_br == false)
    and (.predictive_dashboard.swarm_topology_placement.mutation_policy.mutates_remote_workers == false)
    and (.predictive_dashboard.swarm_topology_placement.mutation_policy.changes_live_queue_policy == false)
    and (.predictive_dashboard.swarm_capability_affinity_routing.readiness | type == "string")
    and (.predictive_dashboard.swarm_capability_affinity_routing.advisory_decision | type == "string")
    and (.predictive_dashboard.swarm_capability_affinity_routing.outcome_ledger_decision | type == "string")
    and (.predictive_dashboard.swarm_capability_affinity_routing.routing_mode | type == "string")
    and (.predictive_dashboard.swarm_capability_affinity_routing.recommended_topology_class | type == "string")
    and (.predictive_dashboard.swarm_capability_affinity_routing.preferred_worker_ids | type == "array")
    and (.predictive_dashboard.swarm_capability_affinity_routing.advised_worker_ids | type == "array")
    and (.predictive_dashboard.swarm_capability_affinity_routing.required_capabilities | type == "array")
    and (.predictive_dashboard.swarm_capability_affinity_routing.required_toolchain_fingerprints | type == "array")
    and (.predictive_dashboard.swarm_capability_affinity_routing.reason_codes | type == "array")
    and (.predictive_dashboard.swarm_capability_affinity_routing.artifact_paths | type == "object")
    and (.predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.advisory_only == true)
    and (.predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.mutates_br == false)
    and (.predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.mutates_remote_workers == false)
    and (.predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.changes_live_queue_policy == false)
    and (.predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.reroutes_tasks_automatically == false)
    and (.predictive_dashboard.swarm_topology_placement.mutation_policy.pins_workers_automatically == false)
    and (.predictive_dashboard.swarm_topology_placement.mutation_policy.enforces_placement_automatically == false)
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
    and ((.artifact_paths.queue_fidelity_score_receipt_json == null) or (.artifact_paths.queue_fidelity_score_receipt_json | type == "string"))
    and ((.artifact_paths.queue_drift_ledger_json == null) or (.artifact_paths.queue_drift_ledger_json | type == "string"))
    and ((.artifact_paths.queue_counterfactual_backtest_report_json == null) or (.artifact_paths.queue_counterfactual_backtest_report_json | type == "string"))
    and ((.artifact_paths.queue_tuning_plan_json == null) or (.artifact_paths.queue_tuning_plan_json | type == "string"))
    and ((.artifact_paths.queue_tuning_frontier_json == null) or (.artifact_paths.queue_tuning_frontier_json | type == "string"))
    and ((.artifact_paths.queue_tuning_bundle_json == null) or (.artifact_paths.queue_tuning_bundle_json | type == "string"))
    and ((.artifact_paths.queue_tuning_promotion_guard_receipt_json == null) or (.artifact_paths.queue_tuning_promotion_guard_receipt_json | type == "string"))
    and ((.artifact_paths.queue_tuning_rollout_plan_json == null) or (.artifact_paths.queue_tuning_rollout_plan_json | type == "string"))
    and ((.artifact_paths.queue_tuning_rollback_comparator_receipt_json == null) or (.artifact_paths.queue_tuning_rollback_comparator_receipt_json | type == "string"))
    and ((.artifact_paths.queue_tuning_canary_verdict_ledger_json == null) or (.artifact_paths.queue_tuning_canary_verdict_ledger_json | type == "string"))
    and ((.artifact_paths.queue_policy_adoption_receipt_json == null) or (.artifact_paths.queue_policy_adoption_receipt_json | type == "string"))
    and ((.artifact_paths.queue_policy_adoption_snapshot_bundle_json == null) or (.artifact_paths.queue_policy_adoption_snapshot_bundle_json | type == "string"))
    and ((.artifact_paths.queue_policy_sustained_gain_receipt_json == null) or (.artifact_paths.queue_policy_sustained_gain_receipt_json | type == "string"))
    and ((.artifact_paths.queue_policy_expiry_supersession_plan_json == null) or (.artifact_paths.queue_policy_expiry_supersession_plan_json | type == "string"))
    and ((.artifact_paths.queue_policy_expiry_supersession_ledger_json == null) or (.artifact_paths.queue_policy_expiry_supersession_ledger_json | type == "string"))
    and ((.artifact_paths.swarm_agent_causal_trace_graph_json == null) or (.artifact_paths.swarm_agent_causal_trace_graph_json | type == "string"))
    and ((.artifact_paths.swarm_agent_causal_trace_anomaly_report_json == null) or (.artifact_paths.swarm_agent_causal_trace_anomaly_report_json | type == "string"))
    and ((.artifact_paths.swarm_resource_envelope_json == null) or (.artifact_paths.swarm_resource_envelope_json | type == "string"))
    and ((.artifact_paths.swarm_fair_share_batch_plan_json == null) or (.artifact_paths.swarm_fair_share_batch_plan_json | type == "string"))
    and ((.artifact_paths.swarm_topology_placement_plan_json == null) or (.artifact_paths.swarm_topology_placement_plan_json | type == "string"))
    and ((.artifact_paths.swarm_topology_placement_receipt_json == null) or (.artifact_paths.swarm_topology_placement_receipt_json | type == "string"))
    and ((.artifact_paths.swarm_topology_placement_evidence_ledger_json == null) or (.artifact_paths.swarm_topology_placement_evidence_ledger_json | type == "string"))
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
        and .predictive_dashboard.queue_fidelity.trust_level == "trustworthy"
        and .predictive_dashboard.queue_fidelity.drift_class == "none"
        and .predictive_dashboard.queue_fidelity.highest_severity_mismatch == null
        and .predictive_dashboard.queue_fidelity.top_tuning_recommendation == null
        and .predictive_dashboard.queue_tuning_promotion.readiness == "ready"
        and .predictive_dashboard.queue_tuning_promotion.promotion_decision == "eligible_canary"
        and .predictive_dashboard.queue_tuning_promotion.rollback_verdict == "better_than_current"
        and .predictive_dashboard.queue_tuning_promotion.canary_recommended_action == "continue_canary"
        and .predictive_dashboard.queue_tuning_promotion.manual_approval_blocker_count == 0
        and .predictive_dashboard.queue_policy_adoption.readiness == "retained"
        and .predictive_dashboard.queue_policy_adoption.adoption_state == "recorded_active_policy"
        and .predictive_dashboard.queue_policy_adoption.sustained_gain_verdict == "sustained_gain"
        and .predictive_dashboard.queue_policy_adoption.expiry_decision == "retain_adopted_policy"
        and .predictive_dashboard.queue_policy_adoption.expiry_required == false
        and .predictive_dashboard.queue_policy_adoption.supersession_required == false
        and .predictive_dashboard.swarm_agent_causal_trace.readiness == "complete"
        and .predictive_dashboard.swarm_agent_causal_trace.decision == "pass"
        and .predictive_dashboard.swarm_agent_causal_trace.anomaly_count == 0
        and (.predictive_dashboard.swarm_agent_causal_trace.missing_required_edges | length) == 0
        and .predictive_dashboard.swarm_resource_envelope.readiness == "ready"
        and .predictive_dashboard.swarm_resource_envelope.decision == "pass"
        and .predictive_dashboard.swarm_resource_envelope.fair_share_decision == "admit"
        and .predictive_dashboard.swarm_resource_envelope.fair_share.admitted_count == 3
        and .predictive_dashboard.swarm_resource_envelope.fair_share.deferred_count == 0
        and .predictive_dashboard.swarm_topology_placement.readiness == "ready"
        and .predictive_dashboard.swarm_topology_placement.plan_decision == "pass"
        and .predictive_dashboard.swarm_topology_placement.receipt_decision == "pass"
        and .predictive_dashboard.swarm_topology_placement.recommended_topology_class == "numa_hot_cache_preferred"
        and .predictive_dashboard.swarm_topology_placement.warm_cache_residency_state == "hot"
        and .predictive_dashboard.swarm_topology_placement.adoption_status == "adopted"
        and .predictive_dashboard.swarm_topology_placement.recommended_worker_target_count == 2
        and .predictive_dashboard.swarm_topology_placement.warm_cache_opportunity_count == 1
        and (.predictive_dashboard.swarm_topology_placement.shard_hints | index("heavy-numa-0-shard-0"))
        and .summary.causal_trace_readiness == "complete"
        and .summary.resource_envelope_readiness == "ready"
        and .summary.topology_placement_readiness == "ready"
        and .summary.fair_share_admitted_count == 3
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
        and .predictive_dashboard.queue_fidelity.artifact_status == "missing"
        and .predictive_dashboard.queue_tuning_promotion.artifact_statuses.bundle == "missing"
        and .predictive_dashboard.queue_policy_adoption.artifact_statuses.adoption_receipt == "missing"
        and .predictive_dashboard.swarm_agent_causal_trace.artifact_statuses.graph == "missing"
        and .predictive_dashboard.swarm_agent_causal_trace.artifact_statuses.anomaly_report == "missing"
        and .predictive_dashboard.swarm_agent_causal_trace.readiness == "degraded"
        and .predictive_dashboard.swarm_resource_envelope.artifact_statuses.resource_envelope == "missing"
        and .predictive_dashboard.swarm_resource_envelope.readiness == "degraded"
        and .predictive_dashboard.swarm_topology_placement.artifact_statuses.placement_plan == "missing"
        and .predictive_dashboard.swarm_topology_placement.readiness == "degraded"
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
    queue_fidelity_high_drift)
      jq -e '
        .predictive_dashboard.queue_fidelity.trust_level == "degraded"
        and .predictive_dashboard.queue_fidelity.drift_class == "proof_brownout_miss"
        and .predictive_dashboard.queue_fidelity.highest_severity_mismatch.mismatch_class == "proof_brownout_miss"
        and .predictive_dashboard.queue_fidelity.highest_severity_mismatch.task_id == "bd-ready-a"
        and .predictive_dashboard.queue_fidelity.tuning_plan_class == "conflicting_improvements"
        and .predictive_dashboard.queue_fidelity.top_tuning_recommendation.candidate_id == "raise_proof_health_penalty"
        and .summary.queue_tuning_top_recommendation == "raise_proof_health_penalty"
        and any(.degraded[]; .component == "queue_fidelity")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    queue_fidelity_insufficient_evidence)
      jq -e '
        .predictive_dashboard.queue_fidelity.trust_level == "degraded"
        and .predictive_dashboard.queue_fidelity.drift_class == "missing_outcome"
        and .predictive_dashboard.queue_fidelity.highest_severity_mismatch.mismatch_class == "missing_outcome"
        and .predictive_dashboard.queue_fidelity.tuning_plan_class == "insufficient_evidence"
        and .predictive_dashboard.queue_fidelity.top_tuning_recommendation.candidate_id == "require_aftermath_evidence"
        and .predictive_dashboard.queue_fidelity.top_tuning_recommendation.manual_review_required == true
        and any(.degraded[]; .component == "queue_fidelity")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    queue_tuning_promotion_blocked)
      jq -e '
        .predictive_dashboard.queue_tuning_promotion.readiness == "fail_closed"
        and .predictive_dashboard.queue_tuning_promotion.promotion_decision == "reject"
        and .predictive_dashboard.queue_tuning_promotion.manual_approval_blocker_count > 0
        and (.predictive_dashboard.queue_tuning_promotion.reject_reasons | index("manual_approval_missing"))
        and .summary.queue_tuning_promotion_readiness == "fail_closed"
        and .recommendations[0].action == "respect_queue_tuning_promotion_fail_closed"
        and any(.degraded[]; .component == "queue_tuning_promotion")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    queue_tuning_promotion_stale_evidence)
      jq -e '
        .predictive_dashboard.queue_tuning_promotion.readiness == "fail_closed"
        and .predictive_dashboard.queue_tuning_promotion.promotion_decision == "reject"
        and (.predictive_dashboard.queue_tuning_promotion.reject_reasons | index("stale_evidence"))
        and .summary.queue_tuning_promotion_decision == "reject"
        and .recommendations[0].action == "respect_queue_tuning_promotion_fail_closed"
        and any(.degraded[]; .component == "queue_tuning_promotion")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    queue_tuning_promotion_rollback_required)
      jq -e '
        .predictive_dashboard.queue_tuning_promotion.readiness == "rollback_required"
        and .predictive_dashboard.queue_tuning_promotion.rollback_verdict == "worse_than_current"
        and .predictive_dashboard.queue_tuning_promotion.canary_recommended_action == "rollback_required"
        and .predictive_dashboard.queue_tuning_promotion.rollback_trigger_count == 1
        and .summary.queue_tuning_rollback_verdict == "worse_than_current"
        and .recommendations[0].action == "respect_queue_tuning_promotion_fail_closed"
        and any(.degraded[]; .component == "queue_tuning_promotion")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    queue_policy_adoption_expiry_required)
      jq -e '
        .predictive_dashboard.queue_policy_adoption.readiness == "expiry_required"
        and .predictive_dashboard.queue_policy_adoption.sustained_gain_verdict == "regression_detected"
        and .predictive_dashboard.queue_policy_adoption.expiry_decision == "expire_adopted_policy"
        and .predictive_dashboard.queue_policy_adoption.expiry_required == true
        and .predictive_dashboard.queue_policy_adoption.supersession_required == false
        and .summary.queue_policy_expiry_required == true
        and .recommendations[0].action == "review_queue_policy_adoption_lifecycle"
        and any(.degraded[]; .component == "queue_policy_adoption")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    queue_policy_adoption_supersession_required)
      jq -e '
        .predictive_dashboard.queue_policy_adoption.readiness == "supersession_required"
        and .predictive_dashboard.queue_policy_adoption.sustained_gain_verdict == "sustained_gain"
        and .predictive_dashboard.queue_policy_adoption.expiry_decision == "supersede_adopted_policy"
        and .predictive_dashboard.queue_policy_adoption.expiry_required == true
        and .predictive_dashboard.queue_policy_adoption.supersession_required == true
        and .predictive_dashboard.queue_policy_adoption.newer_candidate_id == "raise_owner_friction_penalty"
        and .summary.queue_policy_supersession_required == true
        and .recommendations[0].action == "review_queue_policy_adoption_lifecycle"
        and any(.degraded[]; .component == "queue_policy_adoption")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    causal_trace_degraded)
      jq -e '
        .predictive_dashboard.swarm_agent_causal_trace.readiness == "degraded"
        and .predictive_dashboard.swarm_agent_causal_trace.decision == "degraded"
        and .predictive_dashboard.swarm_agent_causal_trace.anomaly_count == 1
        and (.predictive_dashboard.swarm_agent_causal_trace.anomaly_classes | index("missing_claim_message"))
        and (.predictive_dashboard.swarm_agent_causal_trace.missing_required_edges | index("bead_claimed"))
        and .summary.causal_trace_readiness == "degraded"
        and .recommendations[0].action == "review_causal_trace_handoff"
        and any(.degraded[]; .component == "swarm_agent_causal_trace")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    causal_trace_contaminated)
      jq -e '
        .predictive_dashboard.swarm_agent_causal_trace.readiness == "contaminated"
        and .predictive_dashboard.swarm_agent_causal_trace.decision == "fail_closed"
        and .predictive_dashboard.swarm_agent_causal_trace.fail_closed_count == 1
        and (.predictive_dashboard.swarm_agent_causal_trace.anomaly_classes | index("local_rch_fallback_contaminates_remote_proof"))
        and (.predictive_dashboard.swarm_agent_causal_trace.contaminating_anomaly_classes | index("local_rch_fallback_contaminates_remote_proof"))
        and .summary.causal_trace_readiness == "contaminated"
        and .recommendations[0].action == "respect_causal_trace_contamination"
        and any(.degraded[]; .component == "swarm_agent_causal_trace")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    resource_envelope_healthy)
      jq -e '
        .predictive_dashboard.swarm_resource_envelope.artifact_statuses.resource_envelope == "provided"
        and .predictive_dashboard.swarm_resource_envelope.artifact_statuses.fair_share_batch_plan == "provided"
        and .predictive_dashboard.swarm_resource_envelope.readiness == "ready"
        and .predictive_dashboard.swarm_resource_envelope.severity == "ok"
        and .predictive_dashboard.swarm_resource_envelope.decision == "pass"
        and .predictive_dashboard.swarm_resource_envelope.fair_share_decision == "admit"
        and .predictive_dashboard.swarm_resource_envelope.capacity.build_lane_limit == 6
        and .predictive_dashboard.swarm_resource_envelope.capacity.remote_rch_slot_limit == 12
        and .predictive_dashboard.swarm_resource_envelope.fair_share.admitted_count == 3
        and .predictive_dashboard.swarm_resource_envelope.fair_share.deferred_count == 0
        and .predictive_dashboard.swarm_resource_envelope.fair_share.heavy_admitted_count == 2
        and (.predictive_dashboard.swarm_resource_envelope.contaminating_classes | length) == 0
        and .summary.resource_envelope_readiness == "ready"
        and .summary.resource_envelope_decision == "pass"
        and .summary.fair_share_decision == "admit"
        and .summary.fair_share_admitted_count == 3
        and .summary.fair_share_deferred_count == 0
      ' "${output_dir}/status.json" >/dev/null
      ;;
    resource_envelope_degraded)
      jq -e '
        .predictive_dashboard.swarm_resource_envelope.artifact_statuses.resource_envelope == "provided"
        and .predictive_dashboard.swarm_resource_envelope.artifact_statuses.fair_share_batch_plan == "provided"
        and .predictive_dashboard.swarm_resource_envelope.readiness == "degraded"
        and .predictive_dashboard.swarm_resource_envelope.severity == "warning"
        and .predictive_dashboard.swarm_resource_envelope.decision == "degraded"
        and .predictive_dashboard.swarm_resource_envelope.fair_share_decision == "admit_narrow"
        and .predictive_dashboard.swarm_resource_envelope.fair_share.admitted_count == 2
        and .predictive_dashboard.swarm_resource_envelope.fair_share.deferred_count == 1
        and .predictive_dashboard.swarm_resource_envelope.fair_share.heavy_admitted_count == 1
        and .predictive_dashboard.swarm_resource_envelope.degraded_reason_count == 1
        and .summary.resource_envelope_readiness == "degraded"
        and .summary.resource_envelope_decision == "degraded"
        and .summary.fair_share_decision == "admit_narrow"
        and .summary.fair_share_admitted_count == 2
        and .summary.fair_share_deferred_count == 1
        and .recommendations[0].action == "refresh_resource_envelope"
        and any(.degraded[]; .component == "swarm_resource_envelope")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    resource_envelope_blocked)
      jq -e '
        .predictive_dashboard.swarm_resource_envelope.readiness == "blocked"
        and .predictive_dashboard.swarm_resource_envelope.severity == "warning"
        and .predictive_dashboard.swarm_resource_envelope.decision == "blocked"
        and .predictive_dashboard.swarm_resource_envelope.fair_share_decision == "defer"
        and .predictive_dashboard.swarm_resource_envelope.capacity.build_lane_limit == 6
        and .predictive_dashboard.swarm_resource_envelope.capacity.remote_rch_slot_limit == 12
        and .predictive_dashboard.swarm_resource_envelope.fair_share.admitted_count == 0
        and .predictive_dashboard.swarm_resource_envelope.fair_share.deferred_count == 3
        and .predictive_dashboard.swarm_resource_envelope.blocked_reason_count == 1
        and .summary.resource_envelope_readiness == "blocked"
        and .summary.fair_share_decision == "defer"
        and .recommendations[0].action == "respect_resource_envelope_block"
        and any(.degraded[]; .component == "swarm_resource_envelope")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    resource_envelope_contaminated)
      jq -e '
        .predictive_dashboard.swarm_resource_envelope.readiness == "contaminated"
        and .predictive_dashboard.swarm_resource_envelope.severity == "critical"
        and .predictive_dashboard.swarm_resource_envelope.decision == "fail_closed"
        and .predictive_dashboard.swarm_resource_envelope.fair_share_decision == "fail_closed"
        and .predictive_dashboard.swarm_resource_envelope.capacity.build_lane_limit == 0
        and .predictive_dashboard.swarm_resource_envelope.capacity.remote_rch_slot_limit == 0
        and .predictive_dashboard.swarm_resource_envelope.fair_share.admitted_count == 0
        and .predictive_dashboard.swarm_resource_envelope.fair_share.deferred_count == 3
        and .predictive_dashboard.swarm_resource_envelope.fail_closed_reason_count == 1
        and (.predictive_dashboard.swarm_resource_envelope.contaminating_classes | index("rch_local_fallback_contaminates_capacity"))
        and (.predictive_dashboard.swarm_resource_envelope.contaminating_classes | index("contaminated_resource_envelope"))
        and .summary.resource_envelope_readiness == "contaminated"
        and .summary.resource_envelope_decision == "fail_closed"
        and .summary.fair_share_decision == "fail_closed"
        and .recommendations[0].action == "respect_resource_envelope_contamination"
        and any(.degraded[]; .component == "swarm_resource_envelope")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    topology_placement_healthy)
      jq -e '
        .predictive_dashboard.swarm_topology_placement.artifact_statuses.placement_plan == "provided"
        and .predictive_dashboard.swarm_topology_placement.artifact_statuses.placement_receipt == "provided"
        and .predictive_dashboard.swarm_topology_placement.artifact_statuses.evidence_ledger == "provided"
        and .predictive_dashboard.swarm_topology_placement.readiness == "ready"
        and .predictive_dashboard.swarm_topology_placement.severity == "ok"
        and .predictive_dashboard.swarm_topology_placement.plan_decision == "pass"
        and .predictive_dashboard.swarm_topology_placement.receipt_decision == "pass"
        and .predictive_dashboard.swarm_topology_placement.ledger_decision == "pass"
        and .predictive_dashboard.swarm_topology_placement.recommended_topology_class == "numa_hot_cache_preferred"
        and .predictive_dashboard.swarm_topology_placement.recommended_worker_target_count == 2
        and .predictive_dashboard.swarm_topology_placement.heavy_target_count == 1
        and .predictive_dashboard.swarm_topology_placement.latency_sensitive_target_count == 1
        and .predictive_dashboard.swarm_topology_placement.warm_cache_residency_state == "hot"
        and .predictive_dashboard.swarm_topology_placement.warm_cache_opportunity_count == 1
        and .predictive_dashboard.swarm_topology_placement.adoption_status == "adopted"
        and (.predictive_dashboard.swarm_topology_placement.adoption_drift_reason_codes | index("cache_reuse_confirmed"))
        and .summary.topology_placement_readiness == "ready"
        and .summary.topology_placement_adoption_status == "adopted"
      ' "${output_dir}/status.json" >/dev/null
      ;;
    topology_placement_drifted)
      jq -e '
        .predictive_dashboard.swarm_topology_placement.readiness == "degraded"
        and .predictive_dashboard.swarm_topology_placement.severity == "warning"
        and .predictive_dashboard.swarm_topology_placement.plan_decision == "pass"
        and .predictive_dashboard.swarm_topology_placement.receipt_decision == "degraded"
        and .predictive_dashboard.swarm_topology_placement.adoption_status == "drifted"
        and (.predictive_dashboard.swarm_topology_placement.adoption_drift_reason_codes | index("worker_drift"))
        and (.predictive_dashboard.swarm_topology_placement.adoption_drift_reason_codes | index("cache_reuse_missing"))
        and .summary.topology_placement_readiness == "degraded"
        and .summary.topology_placement_drift_reason_count == 2
        and .recommendations[0].action == "review_topology_placement_advisory"
        and any(.degraded[]; .component == "swarm_topology_placement")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    topology_placement_expired)
      jq -e '
        .predictive_dashboard.swarm_topology_placement.readiness == "degraded"
        and .predictive_dashboard.swarm_topology_placement.receipt_decision == "degraded"
        and .predictive_dashboard.swarm_topology_placement.adoption_status == "expired"
        and .predictive_dashboard.swarm_topology_placement.expiry.expired_at_observation == true
        and (.predictive_dashboard.swarm_topology_placement.adoption_drift_reason_codes | index("receipt_expired"))
        and .summary.topology_placement_adoption_status == "expired"
        and .recommendations[0].action == "review_topology_placement_advisory"
        and any(.degraded[]; .component == "swarm_topology_placement")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    topology_placement_blocked)
      jq -e '
        .predictive_dashboard.swarm_topology_placement.readiness == "blocked"
        and .predictive_dashboard.swarm_topology_placement.severity == "warning"
        and .predictive_dashboard.swarm_topology_placement.plan_decision == "blocked"
        and .predictive_dashboard.swarm_topology_placement.receipt_decision == "blocked"
        and .predictive_dashboard.swarm_topology_placement.adoption_status == "not_applicable"
        and .predictive_dashboard.swarm_topology_placement.recommended_topology_class == "blocked_contradictory_locality"
        and .predictive_dashboard.swarm_topology_placement.recommended_worker_target_count == 0
        and (.predictive_dashboard.swarm_topology_placement.adoption_drift_reason_codes | index("blocked_plan_not_adoptable"))
        and .summary.topology_placement_readiness == "blocked"
        and .recommendations[0].action == "respect_topology_placement_block"
        and any(.degraded[]; .component == "swarm_topology_placement")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    capability_affinity_healthy)
      jq -e '
        .predictive_dashboard.swarm_capability_affinity_routing.artifact_statuses.routing_advisory == "provided"
        and .predictive_dashboard.swarm_capability_affinity_routing.artifact_statuses.outcome_ledger == "provided"
        and .predictive_dashboard.swarm_capability_affinity_routing.readiness == "ready"
        and .predictive_dashboard.swarm_capability_affinity_routing.severity == "ok"
        and .predictive_dashboard.swarm_capability_affinity_routing.advisory_decision == "pass"
        and .predictive_dashboard.swarm_capability_affinity_routing.outcome_ledger_decision == "pass"
        and .predictive_dashboard.swarm_capability_affinity_routing.routing_mode == "capability_affinity_confirmed"
        and .predictive_dashboard.swarm_capability_affinity_routing.recommended_topology_class == "numa_hot_cache_preferred"
        and .predictive_dashboard.swarm_capability_affinity_routing.preferred_worker_count == 2
        and .predictive_dashboard.swarm_capability_affinity_routing.mismatch_task_count == 0
        and .predictive_dashboard.swarm_capability_affinity_routing.capability_gap_task_count == 0
        and .predictive_dashboard.swarm_capability_affinity_routing.toolchain_drift_task_count == 0
        and (.predictive_dashboard.swarm_capability_affinity_routing.reason_codes | index("preferred_cohort_confirmed"))
        and .summary.capability_affinity_readiness == "ready"
        and .summary.capability_affinity_preferred_worker_count == 2
      ' "${output_dir}/status.json" >/dev/null
      ;;
    capability_affinity_degraded)
      jq -e '
        .predictive_dashboard.swarm_capability_affinity_routing.readiness == "degraded"
        and .predictive_dashboard.swarm_capability_affinity_routing.severity == "warning"
        and .predictive_dashboard.swarm_capability_affinity_routing.advisory_decision == "degraded"
        and .predictive_dashboard.swarm_capability_affinity_routing.outcome_ledger_decision == "degraded"
        and .predictive_dashboard.swarm_capability_affinity_routing.routing_mode == "broader_cohort_fallback"
        and .predictive_dashboard.swarm_capability_affinity_routing.recommended_topology_class == "mixed_capability_degraded"
        and .predictive_dashboard.swarm_capability_affinity_routing.mismatch_task_count == 1
        and .predictive_dashboard.swarm_capability_affinity_routing.capability_gap_task_count == 0
        and .predictive_dashboard.swarm_capability_affinity_routing.toolchain_drift_task_count == 0
        and (.predictive_dashboard.swarm_capability_affinity_routing.reason_codes | index("broader_cohort_fallback"))
        and (.predictive_dashboard.swarm_capability_affinity_routing.reason_codes | index("route_mismatch_observed"))
        and .summary.capability_affinity_readiness == "degraded"
        and .summary.capability_affinity_mismatch_count == 1
        and .recommendations[0].action == "review_capability_affinity_advisory"
        and any(.degraded[]; .component == "swarm_capability_affinity_routing")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    capability_affinity_blocked)
      jq -e '
        .predictive_dashboard.swarm_capability_affinity_routing.readiness == "blocked"
        and .predictive_dashboard.swarm_capability_affinity_routing.severity == "warning"
        and .predictive_dashboard.swarm_capability_affinity_routing.advisory_decision == "blocked"
        and .predictive_dashboard.swarm_capability_affinity_routing.outcome_ledger_decision == "blocked"
        and .predictive_dashboard.swarm_capability_affinity_routing.recommended_topology_class == "blocked_toolchain_parity"
        and .predictive_dashboard.swarm_capability_affinity_routing.mismatch_task_count == 0
        and .predictive_dashboard.swarm_capability_affinity_routing.capability_gap_task_count == 1
        and .predictive_dashboard.swarm_capability_affinity_routing.toolchain_drift_task_count == 1
        and (.predictive_dashboard.swarm_capability_affinity_routing.reason_codes | index("required_toolchain_fingerprint_mismatch"))
        and (.predictive_dashboard.swarm_capability_affinity_routing.reason_codes | index("observed_capability_gap"))
        and .summary.capability_affinity_readiness == "blocked"
        and .summary.capability_affinity_capability_gap_count == 1
        and .summary.capability_affinity_toolchain_drift_count == 1
        and .recommendations[0].action == "respect_capability_affinity_block"
        and any(.degraded[]; .component == "swarm_capability_affinity_routing")
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
    and (.golden_fixture_cases | index("queue_fidelity_high_drift"))
    and (.golden_fixture_cases | index("queue_fidelity_insufficient_evidence"))
    and (.golden_fixture_cases | index("queue_tuning_promotion_blocked"))
    and (.golden_fixture_cases | index("queue_tuning_promotion_stale_evidence"))
    and (.golden_fixture_cases | index("queue_tuning_promotion_rollback_required"))
    and (.golden_fixture_cases | index("queue_policy_adoption_expiry_required"))
    and (.golden_fixture_cases | index("queue_policy_adoption_supersession_required"))
    and (.golden_fixture_cases | index("causal_trace_degraded"))
    and (.golden_fixture_cases | index("causal_trace_contaminated"))
    and (.golden_fixture_cases | index("resource_envelope_healthy"))
    and (.golden_fixture_cases | index("resource_envelope_degraded"))
    and (.golden_fixture_cases | index("resource_envelope_blocked"))
    and (.golden_fixture_cases | index("resource_envelope_contaminated"))
    and (.golden_fixture_cases | index("topology_placement_healthy"))
    and (.golden_fixture_cases | index("topology_placement_drifted"))
    and (.golden_fixture_cases | index("topology_placement_expired"))
    and (.golden_fixture_cases | index("topology_placement_blocked"))
    and (.golden_fixture_cases | index("capability_affinity_healthy"))
    and (.golden_fixture_cases | index("capability_affinity_degraded"))
    and (.golden_fixture_cases | index("capability_affinity_blocked"))
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
    and (.required_dashboard_fields | index("predictive_dashboard.queue_fidelity.trust_level"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_fidelity.drift_class"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_fidelity.highest_severity_mismatch"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_fidelity.top_tuning_recommendation"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_tuning_promotion.readiness"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_tuning_promotion.promotion_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_tuning_promotion.rollback_verdict"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_tuning_promotion.canary_recommended_action"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_tuning_promotion.manual_approval_blocker_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_tuning_promotion.evidence_link_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_tuning_promotion.mutation_policy"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_policy_adoption.readiness"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_policy_adoption.adoption_state"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_policy_adoption.sustained_gain_verdict"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_policy_adoption.expiry_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_policy_adoption.expiry_required"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_policy_adoption.supersession_required"))
    and (.required_dashboard_fields | index("predictive_dashboard.queue_policy_adoption.mutation_policy"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_agent_causal_trace.readiness"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_agent_causal_trace.decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_agent_causal_trace.missing_required_edges"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_agent_causal_trace.anomaly_classes"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_agent_causal_trace.mutation_policy"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_resource_envelope.readiness"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_resource_envelope.decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_resource_envelope.fair_share_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_resource_envelope.capacity.build_lane_limit"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_resource_envelope.fair_share.admitted_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_resource_envelope.contaminating_classes"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.readiness"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.plan_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.receipt_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.recommended_topology_class"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.recommended_worker_target_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.warm_cache_residency_state"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.warm_cache_opportunity_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.adoption_status"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.adoption_drift_reason_codes"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.expiry"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_topology_placement.mutation_policy"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.readiness"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.advisory_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.outcome_ledger_decision"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.routing_mode"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.recommended_topology_class"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.preferred_worker_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.mismatch_task_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.capability_gap_task_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.toolchain_drift_task_count"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.reason_codes"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.artifact_paths"))
    and (.required_dashboard_fields | index("predictive_dashboard.swarm_capability_affinity_routing.mutation_policy"))
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
  grep -Fq 'docs/swarm_execution_queue_fidelity_scorer_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_counterfactual_planner_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_tuning_policy_bundle_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_tuning_promotion_guard_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_tuning_rollback_comparator_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_policy_adoption_receipt_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_policy_sustained_gain_scorer_contract_v1.json' "$contract_doc"
  grep -Fq 'docs/swarm_execution_queue_policy_expiry_supersession_planner_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_agent_causal_trace_graph.sh' "$contract_doc"
  grep -Fq 'docs/swarm_agent_causal_trace_spine_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_resource_envelope_normalizer.sh' "$contract_doc"
  grep -Fq 'scripts/swarm_fair_share_batch_planner.sh' "$contract_doc"
  grep -Fq 'docs/swarm_resource_envelope_contract_v1.json' "$contract_doc"
  grep -Fq 'scripts/swarm_topology_placement_planner.sh' "$contract_doc"
  grep -Fq 'scripts/swarm_topology_placement_receipt_ledger.sh' "$contract_doc"
  grep -Fq 'scripts/swarm_capability_affinity_queue_routing_planner.sh' "$contract_doc"
  grep -Fq 'scripts/swarm_capability_affinity_routing_outcome_ledger.sh' "$contract_doc"
  grep -Fq 'execution_queue_advisory' "$contract_doc"
  grep -Fq 'queue_fidelity' "$contract_doc"
  grep -Fq 'queue_tuning_promotion' "$contract_doc"
  grep -Fq 'queue_policy_adoption' "$contract_doc"
  grep -Fq 'swarm_agent_causal_trace' "$contract_doc"
  grep -Fq 'swarm_resource_envelope' "$contract_doc"
  grep -Fq 'swarm_topology_placement' "$contract_doc"
  grep -Fq 'swarm_capability_affinity_routing' "$contract_doc"
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
  run_case "queue_fidelity_high_drift" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "queue_fidelity_insufficient_evidence" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "queue_tuning_promotion_blocked" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "queue_tuning_promotion_stale_evidence" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "queue_tuning_promotion_rollback_required" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "queue_policy_adoption_expiry_required" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "queue_policy_adoption_supersession_required" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "causal_trace_degraded" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "causal_trace_contaminated" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "resource_envelope_healthy" "healthy" "ok" "ok" "ok" "$tmp_root"
  run_case "resource_envelope_degraded" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "resource_envelope_blocked" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "resource_envelope_contaminated" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "topology_placement_healthy" "healthy" "ok" "ok" "ok" "$tmp_root"
  run_case "topology_placement_drifted" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "topology_placement_expired" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "topology_placement_blocked" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "capability_affinity_healthy" "healthy" "ok" "ok" "ok" "$tmp_root"
  run_case "capability_affinity_degraded" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "capability_affinity_blocked" "degraded" "ok" "ok" "ok" "$tmp_root"

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
