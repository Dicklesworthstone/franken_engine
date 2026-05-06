#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
forecaster="${root_dir}/scripts/swarm_capacity_forecaster.sh"
normalizer="${root_dir}/scripts/swarm_telemetry_snapshot_normalizer.sh"
dashboard_contract="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"
forecast_contract="${root_dir}/docs/swarm_capacity_forecaster_contract_v1.json"

record_pass() {
  printf 'PASS swarm-capacity-forecaster %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-capacity-forecaster %s\n' "$1" >&2
}

write_common_fixtures() {
  local fixture_dir="$1"
  local scenario="$2"
  local resource_decision="admit"
  local resource_findings='[]'
  local collision_risk="none"
  local reservations='{"schema_version":"franken-engine.agent-mail-reservations.v1","snapshot_epoch_seconds":1900,"reservations":[{"path_pattern":"scripts/swarm_capacity_forecaster.sh","bead_id":"bd-r6ch9","agent_name":"CyanOak","exclusive":true}]}'
  local stale_lock='{"schema_version":"franken-engine.stale-lock-recommendations.v1","snapshot_epoch_seconds":1900,"stale_lock_recommendations":[],"safe_to_reopen":[],"contact_first":[]}'
  local proof_freshness='{"schema_version":"franken-engine.proof-freshness-decay-report.v1","generated_timestamp_ms":1900000,"freshness_state":"fresh","reusable":true,"reason":"proof artifact is reusable","recommended_next_action":"Reuse the proof artifact."}'
  local incident='{"schema_version":"franken-engine.rch-incident-packet.v1","status":"pass","failure_kind":"none","retry_safety":"not_required","classification_confidence":"high","recommended_next_action":"Remote execution signals are healthy."}'
  local resource_lease='{"schema_version":"franken-engine.swarm-resource-lease-plan.v1","generated_timestamp_ms":1900000,"lease_decision":"admit","target_dir":"/tmp/rch_target_franken_engine_bd_r6ch9","findings":[]}'
  local proof_cache='{"schema_version":"franken-engine.proof-reuse-cache-plan.v1","generated_timestamp_ms":1900000,"proof_cache_decision":"cache_hit","refresh_commands":[],"invalidated_paths":[]}'
  local qos_batch='{"schema_version":"franken-engine.build-storm-batch-plan.v1","generated_timestamp_ms":1900000,"batch_decision":"planned","admitted_commands":[{"request_id":"syntax"}],"deferred_commands":[]}'
  local brownout_state="nominal"
  local validation_plan

  mkdir -p "$fixture_dir"

  case "$scenario" in
    normal)
      ;;
    degraded)
      resource_decision="defer"
      resource_findings='[{"signal":"memory_available_bytes","message":"memory pressure"},{"signal":"active_compile_count","message":"worker capacity busy"}]'
      incident='{"schema_version":"franken-engine.rch-incident-packet.v1","status":"fail","failure_kind":"worker_timeout","retry_safety":"safe_after_narrowing_or_timeout_adjustment","classification_confidence":"high","recommended_next_action":"Narrow the command before retrying."}'
      resource_lease='{"schema_version":"franken-engine.swarm-resource-lease-plan.v1","generated_timestamp_ms":1900000,"lease_decision":"busy","target_dir":"/tmp/rch_target_franken_engine_bd_r6ch9_hot","findings":[{"signal":"target_dir_heat","message":"hot target dir"},{"signal":"memory_available_bytes","message":"memory pressure"}]}'
      proof_cache='{"schema_version":"franken-engine.proof-reuse-cache-plan.v1","generated_timestamp_ms":1900000,"proof_cache_decision":"refresh_required","refresh_commands":["rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_hot cargo test -p frankenengine-engine --test swarm_capacity_forecaster"],"invalidated_paths":["/tmp/rch_target_hot"]}'
      qos_batch='{"schema_version":"franken-engine.build-storm-batch-plan.v1","generated_timestamp_ms":1900000,"batch_decision":"planned","admitted_commands":[{"request_id":"syntax"}],"deferred_commands":[{"request_id":"heavy-proof","fairness_reason":"worker capacity throttle"}]}'
      ;;
    brownout)
      brownout_state="brownout"
      qos_batch='{"schema_version":"franken-engine.build-storm-batch-plan.v1","generated_timestamp_ms":1900000,"batch_decision":"planned","admitted_commands":[{"request_id":"syntax"}],"deferred_commands":[{"request_id":"heavy-proof","fairness_reason":"brownout throttle"}]}'
      ;;
    contradictory)
      reservations='{"schema_version":"franken-engine.agent-mail-reservations.v1","snapshot_epoch_seconds":1900,"reservations":[{"path_pattern":"scripts/swarm_capacity_forecaster.sh","bead_id":"bd-r6ch9","agent_name":"ScarletOwl","exclusive":true}]}'
      ;;
    manual)
      stale_lock='{"schema_version":"franken-engine.stale-lock-recommendations.v1","snapshot_epoch_seconds":1900,"stale_lock_recommendations":[{"bead_id":"bd-r6ch9","contact_first":true,"reason":"manual_confirmation_required"}],"safe_to_reopen":[],"contact_first":["bd-r6ch9"]}'
      ;;
    stale)
      ;;
    *)
      record_failure "unknown fixture scenario ${scenario}"
      return 1
      ;;
  esac

  jq -n '[{id:"bd-next",title:"Follow-on bead",priority:2,status:"open",assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n --arg assignee "CyanOak" '{"issues":[{id:"bd-r6ch9",title:"Predictive capacity forecaster",priority:2,status:"in_progress",assignee:$assignee}]}' >"${fixture_dir}/in_progress.json"

  validation_plan="$(jq -nc --arg collision_risk "$collision_risk" '
    {
      schema_version:"franken-engine.swarm-validation-plan.v1",
      decision:"admit",
      collision_risk:$collision_risk,
      conflicting_agents:[],
      safe_alternatives:["docs/SWARM_CAPACITY_FORECASTER.md"],
      reservation_recommendations:[],
      commands:[
        {
          command_id:"bash-n-forecaster",
          display:"bash -n scripts/swarm_capacity_forecaster.sh",
          predicted_cost:{
            schema_version:"franken-engine.swarm-validation-predicted-cost.v1",
            state:"static",
            cost_class:(if $collision_risk == "none" then "low" else "high" end)
          },
          risk_flags:(if $collision_risk == "none" then [] else ["reserved_overlap"] end)
        }
      ]
    }
  ')"
  if [[ "$scenario" == "degraded" || "$scenario" == "brownout" ]]; then
    validation_plan="$(jq '.commands[0].predicted_cost.cost_class = "high" | .commands[0].risk_flags = ["high_cost_history"]' <<<"$validation_plan")"
  fi
  printf '%s\n' "$validation_plan" >"${fixture_dir}/validation_plan.json"

  jq -n --arg decision "$resource_decision" --argjson findings "$resource_findings" '
    {
      schema_version:"franken-engine.swarm-resource-decision.v1",
      decision:$decision,
      findings:$findings
    }
  ' >"${fixture_dir}/resource_decision.json"
  printf '%s\n' "$reservations" | jq . >"${fixture_dir}/agent_mail_reservations.json"
  printf '%s\n' "$stale_lock" | jq . >"${fixture_dir}/stale_lock_recommendations.json"
  printf '%s\n' "$proof_freshness" | jq . >"${fixture_dir}/proof_freshness.json"
  printf '%s\n' "$incident" | jq . >"${fixture_dir}/rch_incident_packet.json"
  printf '%s\n' "$resource_lease" | jq . >"${fixture_dir}/resource_lease_plan.json"
  printf '%s\n' "$proof_cache" | jq . >"${fixture_dir}/proof_cache_plan.json"
  printf '%s\n' "$qos_batch" | jq . >"${fixture_dir}/build_storm_batch_plan.json"

  jq -n \
    --arg brownout_state "$brownout_state" \
    '{
      schema_version:"franken-engine.proof-economy-scheduler-replay-drill-report.v1",
      captured_epoch_seconds:1900,
      summary:{
        agent_count:20,
        command_count:4,
        brownout_state:$brownout_state,
        recommended_operator_action:(if $brownout_state == "brownout" then "shed heavy proofs" else "proceed" end)
      },
      dashboard_fields:{
        brownout_state:$brownout_state,
        fair_share_score_millionths:(if $brownout_state == "brownout" then 350000 else 900000 end)
      },
      artifact_paths:{
        scheduler_replay_drill_report_json:"../fixtures/proof_economy_scheduler_replay_drill_report.json"
      }
    }' >"${fixture_dir}/proof_economy_drill_report.json"
  cp "${fixture_dir}/proof_economy_drill_report.json" \
    "${fixture_dir}/proof_economy_scheduler_replay_drill_report.json"

  jq -n '
    {
      schema_version:"franken-engine.remote-proof-archive-lifecycle-no-mock-drill.v1",
      captured_epoch_seconds:1900,
      drill_decision:"pass",
      scenarios:{
        resident_bundle_export_restore:{
          status:"pass",
          archive_summary:{restore_verdict:"verified"},
          gc_guard_summary:{guard_decision:"deny_gc"},
          pressure_summary:{advisory:"retain",recommended_action:"preserve_active_evidence"}
        },
        duplicate_compaction_before_export:{
          status:"pass",
          compaction_summary:{compacted_group_count:0},
          pressure_summary:{advisory:"retain",recommended_action:"retain_hot_bundle"}
        },
        salvage_pinned_gc_block:{
          status:"pass",
          gc_guard_summary:{guard_decision:"deny_gc"},
          pressure_summary:{advisory:"retain",recommended_action:"preserve_pinned_evidence"}
        }
      },
      artifact_paths:{
        remote_proof_archive_lifecycle_no_mock_drill_report_json:"../fixtures/remote_proof_archive_lifecycle_no_mock_drill_report.json"
      }
    }' >"${fixture_dir}/archive_lifecycle_report.json"
  cp "${fixture_dir}/archive_lifecycle_report.json" \
    "${fixture_dir}/remote_proof_archive_lifecycle_no_mock_drill_report.json"

  jq -n '
    {
      schema_version:"franken-engine.swarm-operator-status-report.v1",
      status:"ok",
      predictive_dashboard:{
        rch_incidents:{status:"healthy",incidents:[]},
        resource_leases:{lease_decision:"admit",severity:"info"},
        proof_cache:{proof_cache_decision:"cache_hit",refresh_commands:[]},
        qos_batches:{batch_decision:"planned",deferred_commands:[]},
        stale_lock_recommendations:{contact_first:[],actionable_commands:[]}
      }
    }' >"${fixture_dir}/operator_status.json"

  if [[ "$scenario" == "degraded" ]]; then
    jq '.predictive_dashboard.rch_incidents = {status:"degraded",incidents:[{status:"fail",failure_kind:"worker_timeout",retry_safety:"safe_after_narrowing_or_timeout_adjustment",classification_confidence:"high",recommended_next_action:"Narrow the command before retrying."}]}
      | .predictive_dashboard.proof_cache = {proof_cache_decision:"refresh_required",refresh_commands:["rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_hot cargo test -p frankenengine-engine --test swarm_capacity_forecaster"]}
      | .predictive_dashboard.qos_batches = {batch_decision:"planned",deferred_commands:[{"request_id":"heavy-proof"}]}
      | .predictive_dashboard.resource_leases = {lease_decision:"busy",severity:"warn"}' \
      "${fixture_dir}/operator_status.json" >"${fixture_dir}/operator_status.tmp"
    mv "${fixture_dir}/operator_status.tmp" "${fixture_dir}/operator_status.json"
  fi
  if [[ "$scenario" == "brownout" ]]; then
    jq '.predictive_dashboard.qos_batches = {batch_decision:"planned",deferred_commands:[{"request_id":"heavy-proof"}]}' \
      "${fixture_dir}/operator_status.json" >"${fixture_dir}/operator_status.tmp"
    mv "${fixture_dir}/operator_status.tmp" "${fixture_dir}/operator_status.json"
  fi

  jq -n '
    {
      schema_version:"franken-engine.swarm-admission-drill-report.v1",
      captured_epoch_seconds:1900,
      drill_decision:"pass",
      child_artifacts:{
        resource_lease_plan_json:"../fixtures/resource_lease_plan.json",
        proof_cache_plan_json:"../fixtures/proof_cache_plan.json",
        build_storm_batch_plan_json:"../fixtures/build_storm_batch_plan.json",
        stale_lock_recommendations_json:"../fixtures/stale_lock_recommendations.json"
      }
    }' >"${fixture_dir}/swarm_admission_drill_report.json"

  jq -n '
    {
      schema_version:"franken-engine.swarm-predictive-orchestration-e2e-wrapper.v1",
      captured_epoch_seconds:1900,
      status:"pass",
      artifact_paths:{
        operator_status_json:"../fixtures/operator_status.json",
        rch_incident_packet_json:"../fixtures/rch_incident_packet.json"
      }
    }' >"${fixture_dir}/predictive_wrapper_report.json"
  if [[ "$scenario" == "stale" ]]; then
    jq '.captured_epoch_seconds = 100' "${fixture_dir}/predictive_wrapper_report.json" >"${fixture_dir}/predictive_wrapper_report.tmp"
    mv "${fixture_dir}/predictive_wrapper_report.tmp" "${fixture_dir}/predictive_wrapper_report.json"
  fi
}

build_snapshot() {
  local fixture_dir="$1"
  local output_dir="$2"
  local now_epoch="${3:-2000}"
  local stale_after="${4:-600}"

  "${normalizer}" \
    --ready-json "${fixture_dir}/ready.json" \
    --in-progress-json "${fixture_dir}/in_progress.json" \
    --validation-plan-json "${fixture_dir}/validation_plan.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --agent-mail-reservations-json "${fixture_dir}/agent_mail_reservations.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --proof-freshness-json "${fixture_dir}/proof_freshness.json" \
    --admission-drill-report-json "${fixture_dir}/swarm_admission_drill_report.json" \
    --predictive-wrapper-report-json "${fixture_dir}/predictive_wrapper_report.json" \
    --archive-lifecycle-report-json "${fixture_dir}/archive_lifecycle_report.json" \
    --proof-economy-drill-report-json "${fixture_dir}/proof_economy_drill_report.json" \
    --now-epoch-seconds "${now_epoch}" \
    --stale-after-seconds "${stale_after}" \
    --output-dir "${output_dir}"
}

run_check() {
  local scope_file

  bash -n "$forecaster"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$forecaster" "${BASH_SOURCE[0]}"
  jq empty "$forecast_contract" "$dashboard_contract" >/dev/null
  jq -e '.capacity_forecaster.forecast_schema_version == "franken-engine.swarm-capacity-forecast.v1"' "$dashboard_contract" >/dev/null
  jq -e '(.fixture_cases | index("contradictory_telemetry") != null) and (.fixture_cases | index("active_owner_manual_confirmation") != null)' "$forecast_contract" >/dev/null

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-capacity-forecaster-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/swarm_capacity_forecaster.sh" \
    "scripts/e2e/swarm_capacity_forecaster_smoke.sh" \
    "docs/SWARM_CAPACITY_FORECASTER.md" \
    "docs/swarm_capacity_forecaster_contract_v1.json" \
    "docs/swarm_predictive_dashboard_contract_v1.json" \
    "docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-capacity-forecaster-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax, shellcheck, contracts, and rch policy"
}

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local expected_jq="$3"
  local tmp_root fixture_dir snapshot_dir forecast_dir exit_code
  local snapshot_path

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-capacity-forecaster-${case_name}.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  snapshot_dir="${tmp_root}/snapshot"
  forecast_dir="${tmp_root}/forecast"

  write_common_fixtures "$fixture_dir" "$case_name"

  set +e
  build_snapshot "$fixture_dir" "$snapshot_dir" 2000 600 >/dev/null
  exit_code=$?
  set -e
  if [[ "$case_name" == "contradictory" || "$case_name" == "stale" ]]; then
    if [[ "$exit_code" -ne 42 ]]; then
      record_failure "${case_name} expected telemetry snapshot exit 42, got ${exit_code}"
      return 1
    fi
  elif [[ "$exit_code" -ne 0 ]]; then
    record_failure "${case_name} expected telemetry snapshot exit 0, got ${exit_code}"
    return 1
  fi

  snapshot_path="${snapshot_dir}/swarm_capacity_snapshot.json"
  set +e
  "${forecaster}" \
    --telemetry-snapshot-json "$snapshot_path" \
    --now-epoch-seconds 2000 \
    --stale-after-seconds 600 \
    --output-dir "$forecast_dir" >/dev/null
  exit_code=$?
  set -e
  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${case_name} expected forecaster exit ${expected_exit}, got ${exit_code}"
    return 1
  fi
  jq -e "$expected_jq" "${forecast_dir}/swarm_capacity_forecast.json" >/dev/null
  record_pass "${case_name}"
}

run_selftest() {
  run_check
  run_case "normal" 0 '
    .decision == "pass"
    and .summary.overall_state == "normal"
    and .forecasts.compile_pressure.state == "normal"
    and .forecasts.proof_availability.state == "normal"
    and all(.forecasts[]; .confidence_band != "low")
  '
  run_case "degraded" 0 '
    .decision == "pass"
    and .summary.overall_state == "degraded"
    and .forecasts.compile_pressure.state == "degraded"
    and .forecasts.disk_memory_pressure.state == "degraded"
    and .forecasts.rch_degradation.state == "degraded"
    and .forecasts.target_dir_heat.state == "degraded"
    and .forecasts.proof_availability.state == "degraded"
  '
  run_case "brownout" 0 '
    .decision == "pass"
    and .summary.overall_state == "brownout"
    and .summary.brownout_state == "brownout"
    and .forecasts.compile_pressure.state == "brownout"
  '
  run_case "contradictory" 42 '
    .decision == "fail_closed"
    and .inherited_snapshot_failures.snapshot_decision == "fail_closed"
    and (.inherited_snapshot_failures.contradictory_inputs | length) >= 1
    and .forecasts.coordination_pressure.state == "blocked"
  '
  run_case "manual" 0 '
    .decision == "pass"
    and .forecasts.coordination_pressure.state == "blocked"
    and .forecasts.coordination_pressure.auto_reopen_allowed == false
    and .forecasts.coordination_pressure.lease_exchange_allowed == false
  '
  run_case "stale" 42 '
    .decision == "fail_closed"
    and (
      (.fail_closed_reasons | map(select(.kind == "stale_required_telemetry")) | length) >= 1
      or (.inherited_snapshot_failures.stale_inputs | length) >= 1
    )
  '
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
