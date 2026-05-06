#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_telemetry_snapshot_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_TELEMETRY_SNAPSHOT_NORMALIZER.md"
contract_path="${root_dir}/docs/swarm_telemetry_snapshot_contract_v1.json"
dashboard_contract_path="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"
dashboard_docs_path="${root_dir}/docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"

record_pass() {
  printf 'PASS swarm-telemetry-snapshot %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-telemetry-snapshot %s\n' "$1" >&2
}

write_fixtures() {
  local dir="$1"
  local artifact_dir="${dir}/artifacts"
  local now_epoch=1778200200

  mkdir -p "$artifact_dir"
  printf '{}\n' >"${artifact_dir}/resource_lease_plan.json"
  printf '{}\n' >"${artifact_dir}/proof_cache_plan.json"
  printf '{}\n' >"${artifact_dir}/build_storm_batch_plan.json"
  printf '{}\n' >"${artifact_dir}/stale_lock_recommendations.json"
  printf '{}\n' >"${artifact_dir}/staged_ownership_report.json"
  printf '{}\n' >"${artifact_dir}/proof_freshness_report.json"
  printf '{}\n' >"${artifact_dir}/collision_receipt.json"
  printf '{}\n' >"${artifact_dir}/operator_status.json"
  printf '{}\n' >"${artifact_dir}/archive_pack.json"
  printf '{}\n' >"${artifact_dir}/restore_verification_report.json"
  printf '{}\n' >"${artifact_dir}/scheduler_replay_report.json"

  jq -n '[
    {id:"bd-p1-alpha", title:"P1 focused proof", priority:1, status:"open", assignee:null},
    {id:"bd-p2-beta", title:"P2 telemetry schema", priority:2, status:"open", assignee:null}
  ]' >"${dir}/ready.json"

  jq -n '{
    issues: [
      {id:"bd-active-gamma", title:"Active predictive lane", priority:2, status:"in_progress", assignee:"AgentGamma"}
    ]
  }' >"${dir}/in_progress.json"

  jq -n --argjson now_epoch "$now_epoch" '{
    schema_version:"franken-engine.swarm-validation-plan.v1",
    decision:"planned",
    collision_risk:"reserved_overlap",
    conflicting_agents:["AgentGamma"],
    safe_alternatives:["docs/swarm_predictive_dashboard_contract_v1.json"],
    reservation_recommendations:[{action:"coordinate_reservation_holder", scope:"planned_write_set", reason:"planned write paths overlap active exclusive reservations"}],
    commands:[
      {
        command_id:"cargo-test-swarm-validation",
        display:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_snapshot cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e -- --nocapture",
        predicted_cost:{cost_class:"high", state:"fresh", sample_count:2},
        risk_flags:["high_cost_history"]
      },
      {
        command_id:"bash-n-snapshot-normalizer",
        display:"bash -n scripts/swarm_telemetry_snapshot_normalizer.sh",
        predicted_cost:{cost_class:"low", state:"static", sample_count:0},
        risk_flags:[]
      }
    ],
    proof_cost_budgets:[{command_id:"cargo-test-swarm-validation", max_elapsed_ms:900000}],
    snapshot_epoch_seconds:$now_epoch
  }' >"${dir}/validation_plan.json"

  jq -n --argjson now_epoch "$now_epoch" '{
    schema_version:"franken-engine.swarm-resource-governor-decision.v1",
    decision:"admit_narrow",
    findings:[
      {decision:"admit_narrow", signal:"memory_available_bytes", reason:"missing_optional_memory_signal", remediation:"Keep validation narrow."}
    ],
    snapshot_epoch_seconds:$now_epoch
  }' >"${dir}/resource_decision.json"

  jq -n --argjson now_epoch "$now_epoch" '{
    snapshot_epoch_seconds:$now_epoch,
    reservations:[
      {path_pattern:"scripts/e2e/swarm_predictive_orchestration_e2e.sh", agent_name:"AgentGamma", bead_id:"bd-active-gamma", exclusive:true}
    ]
  }' >"${dir}/reservations.json"

  jq -n '{
    schema_version:"franken-engine.stale-lock-recommendations.v1",
    stale_lock_recommendations:[{bead_id:"bd-old-1", suggested_br_commands:["br update bd-old-1 --status open"], contact_commands:["agent-mail reply bd-old-1"]}],
    safe_to_reopen:["bd-old-1"],
    contact_first:["bd-active-gamma"]
  }' >"${dir}/stale_lock_recommendations.json"

  jq -n '{
    schema_version:"franken-engine.proof-freshness-decay-report.v1",
    freshness_state:"fresh",
    reusable:true,
    recommended_next_action:"reuse proof",
    changed_paths:["scripts/swarm_telemetry_snapshot_normalizer.sh"]
  }' >"${dir}/proof_freshness.json"

  jq -n --arg resource_plan "${artifact_dir}/resource_lease_plan.json" \
    --arg proof_cache "${artifact_dir}/proof_cache_plan.json" \
    --arg qos_plan "${artifact_dir}/build_storm_batch_plan.json" \
    --arg stale_report "${artifact_dir}/stale_lock_recommendations.json" \
    --arg contamination_report "${artifact_dir}/staged_ownership_report.json" \
    '{
      schema_version:"franken-engine.swarm-admission-drill-report.v1",
      drill_decision:"pass",
      child_artifacts:{
        resource_lease_plan_json:$resource_plan,
        proof_cache_plan_json:$proof_cache,
        build_storm_batch_plan_json:$qos_plan,
        stale_lock_recommendations_json:$stale_report,
        staged_ownership_report_json:$contamination_report
      }
    }' >"${dir}/admission_drill_report.json"

  jq -n --arg collision "${artifact_dir}/collision_receipt.json" \
    --arg proof_freshness "${artifact_dir}/proof_freshness_report.json" \
    --arg operator_status "${artifact_dir}/operator_status.json" \
    --argjson now_epoch "$now_epoch" '{
      schema_version:"franken-engine.swarm-predictive-orchestration-e2e-wrapper.v1",
      status:"pass",
      captured_epoch_seconds:$now_epoch,
      artifact_paths:{
        collision_receipt_json:$collision,
        proof_freshness_report_json:$proof_freshness,
        operator_status_json:$operator_status
      }
    }' >"${dir}/predictive_wrapper_report.json"

  jq -n --arg archive_pack "${artifact_dir}/archive_pack.json" \
    --arg restore "${artifact_dir}/restore_verification_report.json" \
    --argjson now_epoch "$now_epoch" '{
      schema_version:"franken-engine.remote-proof-archive-lifecycle-no-mock-drill-report.v1",
      drill_decision:"pass",
      captured_epoch_seconds:$now_epoch,
      artifact_paths:{
        archive_pack_json:$archive_pack,
        restore_verification_report_json:$restore
      }
    }' >"${dir}/archive_lifecycle_report.json"

  jq -n --arg report "${artifact_dir}/scheduler_replay_report.json" \
    --argjson now_epoch "$now_epoch" '{
      schema_version:"franken-engine.proof-economy-scheduler-replay-drill-report.v1",
      drill_decision:"pass",
      captured_epoch_seconds:$now_epoch,
      artifact_paths:{
        scheduler_replay_drill_report_json:$report
      }
    }' >"${dir}/proof_economy_drill_report.json"
}

run_normalizer() {
  local fixture_dir="$1"
  local output_dir="$2"

  "$normalizer" \
    --ready-json "${fixture_dir}/ready.json" \
    --in-progress-json "${fixture_dir}/in_progress.json" \
    --validation-plan-json "${fixture_dir}/validation_plan.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --agent-mail-reservations-json "${fixture_dir}/reservations.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --proof-freshness-json "${fixture_dir}/proof_freshness.json" \
    --admission-drill-report-json "${fixture_dir}/admission_drill_report.json" \
    --predictive-wrapper-report-json "${fixture_dir}/predictive_wrapper_report.json" \
    --archive-lifecycle-report-json "${fixture_dir}/archive_lifecycle_report.json" \
    --proof-economy-drill-report-json "${fixture_dir}/proof_economy_drill_report.json" \
    --source-revision fixture-rev \
    --now-epoch-seconds 1778200200 \
    --stale-after-seconds 600 \
    --output-dir "$output_dir" >/dev/null
}

run_check() {
  local scope_file

  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  jq -e '.telemetry_snapshot_normalizer.snapshot_schema_version == "franken-engine.swarm-capacity-snapshot.v1" and .telemetry_snapshot_normalizer.slo_input_snapshot_schema_version == "franken-engine.swarm-slo-input-snapshot.v1"' "$dashboard_contract_path" >/dev/null
  grep -q 'swarm-capacity-snapshot.v1' "$docs_path"
  grep -q 'swarm_slo_input_snapshot.json' "$docs_path"
  grep -q 'scripts/swarm_telemetry_snapshot_normalizer.sh' "$dashboard_docs_path"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-telemetry-snapshot-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/swarm_telemetry_snapshot_normalizer.sh" \
    "scripts/e2e/swarm_telemetry_snapshot_normalizer_smoke.sh" \
    "docs/SWARM_TELEMETRY_SNAPSHOT_NORMALIZER.md" \
    "docs/swarm_telemetry_snapshot_contract_v1.json" \
    "docs/swarm_predictive_dashboard_contract_v1.json" \
    "docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-telemetry-snapshot-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax docs contract and rch policy"
}

expect_fail_closed() {
  local fixture_dir="$1"
  local output_dir="$2"
  shift 2

  set +e
  "$normalizer" \
    --ready-json "${fixture_dir}/ready.json" \
    --in-progress-json "${fixture_dir}/in_progress.json" \
    --validation-plan-json "${fixture_dir}/validation_plan.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --agent-mail-reservations-json "${fixture_dir}/reservations.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --proof-freshness-json "${fixture_dir}/proof_freshness.json" \
    --admission-drill-report-json "${fixture_dir}/admission_drill_report.json" \
    --predictive-wrapper-report-json "${fixture_dir}/predictive_wrapper_report.json" \
    --archive-lifecycle-report-json "${fixture_dir}/archive_lifecycle_report.json" \
    --proof-economy-drill-report-json "${fixture_dir}/proof_economy_drill_report.json" \
    --source-revision fixture-rev \
    --now-epoch-seconds 1778200200 \
    --stale-after-seconds 600 \
    --output-dir "$output_dir" \
    "$@" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne 42 ]]; then
    record_failure "expected fail_closed exit 42, got ${code}"
    return 1
  fi
}

run_selftest() {
  local tmp_root fixture_dir run_a run_b stale_dir contradiction_dir replay_dir missing_dir

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-telemetry-snapshot.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"
  write_fixtures "$fixture_dir"

  run_a="${tmp_root}/run-a"
  run_normalizer "$fixture_dir" "$run_a"
  jq -e '
    .schema_version == "franken-engine.swarm-capacity-snapshot.v1"
    and .decision == "pass"
    and .summary.ready_count == 2
    and .summary.in_progress_count == 1
    and .summary.active_agent_count == 1
    and .summary.high_cost_command_count == 1
    and .swarm_capacity_snapshot.predictive_cost.collision_risk == "reserved_overlap"
    and .swarm_capacity_snapshot.proof_freshness.freshness_state == "fresh"
    and .reuse_audit.dashboard_contract_extension.provider == "/dp/frankentui"
    and .summary.high_core_requested == false
    and .swarm_capacity_snapshot.swarm_slo_inputs.decision == "not_requested"
    and (.accepted_inputs | length) >= 10
    and (.missing_inputs | length) == 0
    and (.non_replayable_artifact_refs | length) == 0
  ' "${run_a}/swarm_capacity_snapshot.json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.swarm-slo-input-snapshot.v1"
    and .decision == "not_requested"
    and .summary.requested == false
  ' "${run_a}/swarm_slo_input_snapshot.json" >/dev/null
  record_pass "healthy fixture normalizes into deterministic capacity snapshot"

  run_b="${tmp_root}/run-b"
  run_normalizer "$fixture_dir" "$run_b"
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${run_a}/swarm_capacity_snapshot.json") \
    <(jq -cS 'del(.artifact_paths)' "${run_b}/swarm_capacity_snapshot.json") >/dev/null
  record_pass "repeated fixture snapshot is deterministic"

  stale_dir="${tmp_root}/stale"
  jq '.snapshot_epoch_seconds = 1778199000' "${fixture_dir}/reservations.json" >"${tmp_root}/reservations.stale.json"
  expect_fail_closed "$fixture_dir" "$stale_dir" --agent-mail-reservations-json "${tmp_root}/reservations.stale.json"
  jq -e '
    .decision == "fail_closed"
    and any(.stale_inputs[]?; .source == "agent_mail_reservations_json")
  ' "${stale_dir}/swarm_capacity_snapshot.json" >/dev/null
  record_pass "stale reservation snapshot fails closed"

  contradiction_dir="${tmp_root}/contradiction"
  jq '.reservations[0].agent_name = "AgentDelta"' "${fixture_dir}/reservations.json" >"${tmp_root}/reservations.contradiction.json"
  expect_fail_closed "$fixture_dir" "$contradiction_dir" --agent-mail-reservations-json "${tmp_root}/reservations.contradiction.json"
  jq -e '
    .decision == "fail_closed"
    and any(.contradictory_inputs[]?; .source == "agent_mail_reservations_json")
  ' "${contradiction_dir}/swarm_capacity_snapshot.json" >/dev/null
  record_pass "contradictory active-agent ownership fails closed"

  replay_dir="${tmp_root}/replay"
  jq '.artifact_paths.archive_pack_json = "/does/not/exist/archive_pack.json"' "${fixture_dir}/archive_lifecycle_report.json" >"${tmp_root}/archive_lifecycle_report.missing.json"
  expect_fail_closed "$fixture_dir" "$replay_dir" --archive-lifecycle-report-json "${tmp_root}/archive_lifecycle_report.missing.json"
  jq -e '
    .decision == "fail_closed"
    and any(.non_replayable_artifact_refs[]?; .source == "archive_lifecycle_report_json")
  ' "${replay_dir}/swarm_capacity_snapshot.json" >/dev/null
  record_pass "non-replayable archive artifact references fail closed"

  missing_dir="${tmp_root}/missing"
  jq 'del(.commands)' "${fixture_dir}/validation_plan.json" >"${tmp_root}/validation_plan.missing.json"
  expect_fail_closed "$fixture_dir" "$missing_dir" --validation-plan-json "${tmp_root}/validation_plan.missing.json"
  jq -e '
    .decision == "fail_closed"
    and any(.missing_required_fields[]?; .source == "validation_plan_json")
  ' "${missing_dir}/swarm_capacity_snapshot.json" >/dev/null
  record_pass "missing required validation-plan fields fail closed"

  real_artifact_dir="${tmp_root}/real-high-core"
  real_now_epoch="$(date -u -d '2026-02-22T07:24:00Z' +%s)"
  expect_fail_closed "$fixture_dir" "$real_artifact_dir" \
    --stress-suite-manifest-json "${root_dir}/artifacts/stress_concurrency/20260222T072317Z/suite_run_manifest.json" \
    --tail-latency-report-json "${root_dir}/artifacts/rgc_tail_latency_control_plane/20260319T183341Z/latency_control_plane_report.json" \
    --chaos-verification-report-json "${root_dir}/artifacts/rgc_fault_injection_chaos_verification_pack/20260303T075226Z/chaos_verification_report.json" \
    --swarm-responsiveness-claim-map-json "${root_dir}/docs/rgc_swarm_responsiveness_claim_map_v1.json" \
    --now-epoch-seconds "${real_now_epoch}"
  jq -e '
    .decision == "fail_closed"
    and .swarm_capacity_snapshot.swarm_slo_inputs.requested == true
    and .swarm_capacity_snapshot.swarm_slo_inputs.stress_concurrency.traceability == "local_or_unknown"
    and .swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.traceability == "local_or_unknown"
    and .swarm_capacity_snapshot.swarm_slo_inputs.chaos_verification.traceability == "local_or_unknown"
    and .swarm_capacity_snapshot.swarm_slo_inputs.responsiveness_claim_map.traceability == "local_or_unknown"
    and any(.high_core_traceability_failures[]?; .source == "stress_suite_manifest_json")
    and any(.high_core_traceability_failures[]?; .source == "tail_latency_report_json")
    and any(.high_core_traceability_failures[]?; .source == "chaos_verification_report_json")
    and any(.high_core_traceability_failures[]?; .source == "swarm_responsiveness_claim_map_json")
  ' "${real_artifact_dir}/swarm_capacity_snapshot.json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.swarm-slo-input-snapshot.v1"
    and .request_state == "requested"
    and .decision == "fail_closed"
    and .evidence.responsiveness_claim_map.traceability == "local_or_unknown"
  ' "${real_artifact_dir}/swarm_slo_input_snapshot.json" >/dev/null
  record_pass "real checked-in stress/tail/chaos evidence replays and fail-closes on local cargo traceability"

  printf 'swarm_telemetry_snapshot_smoke_artifacts=%s\n' "$tmp_root"
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
