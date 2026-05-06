#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
run_id="${SWARM_PREDICTIVE_ORCHESTRATION_E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
artifact_root="${SWARM_PREDICTIVE_ORCHESTRATION_E2E_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-predictive-orchestration/${run_id}}"
wrapper_dir="${artifact_root}/wrapper"
commands_path="${wrapper_dir}/commands.txt"
events_path="${wrapper_dir}/events.jsonl"
report_path="${wrapper_dir}/report.json"

record_pass() {
  printf 'PASS swarm-predictive-orchestration-e2e %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-predictive-orchestration-e2e %s\n' "$1" >&2
}

ensure_wrapper_dir() {
  mkdir -p "$wrapper_dir"
  : >"$commands_path"
  : >"$events_path"
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
    --arg schema_version "franken-engine.swarm-predictive-orchestration-e2e-event.v1" \
    --arg event_name "swarm_predictive_orchestration_e2e.step" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      severity: (if $decision == "pass" then "info" else "error" end),
      step_id: $step_id,
      command_id: $step_id,
      decision: $decision,
      exit_code: $exit_code,
      duration_ms: 0,
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

  IFS=',' read -r -a expected_code_list <<<"$expected_csv"
  for expected in "${expected_code_list[@]}"; do
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
  local step_dir="${wrapper_dir}/${step}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code
  local decision

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
    record_failure "${step} exited ${exit_code}, expected ${expected_codes}"
    printf 'stdout=%s\nstderr=%s\n' "$stdout_path" "$stderr_path" >&2
    return "$exit_code"
  fi
}

write_proof_cost_history() {
  local output_path="$1"
  local source_revision="$2"

  jq -n \
    --arg schema_version "franken-engine.proof-cost-history.v1" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      bead_id: "bd-ad31e",
      source_revision: $source_revision,
      changed_paths: ["crates/franken-engine/tests/swarm_validation_control_plane_e2e.rs"],
      rows: [{
        command_id: "cargo-test-swarm_validation_control_plane_e2e",
        package: "frankenengine-engine",
        target: "swarm_validation_control_plane_e2e",
        source_revision: $source_revision,
        elapsed_ms: 900000,
        compiled_target_count: 12,
        linked_target_count: 2,
        rch_worker: "worker-predictive-smoke",
        rch_status: "pass",
        fallback_detected: false,
        artifact_paths: ["artifacts/swarm-predictive-orchestration/proof-cost-history.json"],
        content_hash: "sha-predictive-high-cost"
      }]
    }' >"$output_path"
}

write_planner_snapshots() {
  local reservation_path="$1"
  local in_progress_path="$2"

  jq -n '{
    reservations: [{
      path_pattern: "scripts/e2e/swarm_validation_control_plane_e2e.sh",
      agent_name: "CyanOak",
      bead_id: "bd-gc1ml",
      exclusive: true
    }]
  }' >"$reservation_path"

  jq -n '{beads: []}' >"$in_progress_path"
}

write_stale_proof_artifact() {
  local output_path="$1"

  jq -n '{
    schema_version: "franken-engine.proof-cost-manifest.v1",
    proof_artifact_id: "proof-cost-stale-bd-ad31e",
    source_revision: "old-source-revision",
    status: "pass",
    generated_timestamp_ms: 1777000000000,
    freshness_deadline_ms: 1778000000000,
    covered_paths: ["crates/franken-engine/tests/swarm_validation_control_plane_e2e.rs"]
  }' >"$output_path"
}

write_rch_logs() {
  local stdout_path="$1"
  local stderr_path="$2"

  printf '%s\n' "[RCH] remote worker-predictive-smoke started cargo test" >"$stdout_path"
  printf '%s\n' "stuck detector auto-cancelled job; exit_code 130 after timeout" >"$stderr_path"
}

write_operator_status_fixtures() {
  local fixture_dir="$1"
  local source_revision="$2"
  local validation_plan_path="$3"
  local proof_freshness_path="$4"
  local rch_incident_path="$5"

  mkdir -p "$fixture_dir"
  jq -n '[{id:"bd-1y2bu", title:"Predictive orchestration runbook", priority:2, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[{id:"bd-ad31e", title:"Predictive orchestration e2e", priority:1, status:"in_progress", assignee:"ScarletOwl"}]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"track-predictive", items:[{id:"bd-ad31e", title:"Predictive orchestration e2e", priority:1, status:"in_progress"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[{path:"scripts/e2e/swarm_validation_control_plane_e2e.sh", holder:"CyanOak", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"admit_narrow", findings:[{signal:"ownership_state", decision:"admit_narrow", reason:"predictive drill keeps heavy proof unexecuted"}]}' >"${fixture_dir}/resource_decision.json"
  jq -n \
    --arg source_revision "$source_revision" \
    --arg validation_plan "$validation_plan_path" \
    --arg proof_freshness "$proof_freshness_path" \
    --arg rch_incident "$rch_incident_path" \
    '[{
      bead_id: "bd-ad31e",
      artifact_id: "predictive-orchestration-drill",
      status: "stale",
      source_revision: $source_revision,
      validation_plan: $validation_plan,
      proof_freshness: $proof_freshness,
      rch_incident: $rch_incident
    }]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[{artifact_id:"proof-cost-stale-bd-ad31e", stale:true, freshness_state:"stale_by_source_revision"}]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[]' >"${fixture_dir}/dirty_files.json"
  jq -n '{queries:[{name:"predictive_orchestration_drill", row_count:3}]}' >"${fixture_dir}/proof_index.json"
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
    notes:["predictive orchestration drill keeps forecast fail-closed"],
    forecasts:{
      compile_pressure:{state:"blocked", recommended_action:"Refresh missing predictive wrapper inputs before trusting compile-pressure advice."},
      disk_memory_pressure:{state:"degraded", recommended_action:"Treat disk and memory pressure as degraded until lease evidence is refreshed."},
      rch_degradation:{state:"degraded", recommended_action:"Treat rch posture as degraded until incident inputs are complete."},
      target_dir_heat:{state:"degraded", recommended_action:"Do not trust warm target reuse claims until forecast inputs are complete."},
      proof_availability:{state:"blocked", recommended_action:"Refresh proof availability evidence before relying on archived proofs."},
      coordination_pressure:{state:"degraded", recommended_action:"Use direct coordination before acting on auto-reopen suggestions."}
    },
    artifact_paths:{swarm_capacity_forecast_json:$artifact_path}
  }' >"${fixture_dir}/capacity_forecast.json"
  jq -n --arg artifact_path "${fixture_dir}/admission_budget_plan.json" '{
    schema_version:"franken-engine.swarm-admission-budget-plan.v1",
    decision:"defer",
    budget_profile:"brownout",
    summary:{admitted_count:0, deferred_count:1},
    recommendations:[{
      request_id:"predictive-heavy-proof",
      bead_id:"bd-ad31e",
      agent_id:"ScarletOwl",
      decision:"defer",
      budget_class:"protected",
      proof_obligation:true
    }],
    artifact_paths:{swarm_admission_budget_plan_json:$artifact_path}
  }' >"${fixture_dir}/admission_budget_plan.json"
  jq -n --arg artifact_path "${fixture_dir}/lease_exchange_salvage_simulation.json" '{
    schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
    decision:"manual_confirmation_required",
    summary:{manual_review_count:1, lease_exchange_candidate_count:1, salvage_promotion_candidate_count:0},
    upstream_summary:{archive_pressure_advisory:"compaction_first", salvage_workflow_state:"salvage_pinned"},
    recommendations:[{bead_id:"bd-ad31e", simulated_action:"manual_confirmation_required", lease_exchange_candidate:true, salvage_promotion_candidate:false}],
    artifact_paths:{lease_exchange_cancellation_salvage_simulation_json:$artifact_path}
  }' >"${fixture_dir}/lease_exchange_salvage_simulation.json"
  jq -n --arg artifact_path "${fixture_dir}/warm_target_prefetch_roi_advisory.json" '{
    schema_version:"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
    advisory:"manual_review_required",
    recommended_action:"Do not warm a fresh target until brownout pressure and cache refresh obligations clear.",
    reason:"forecast and proof-cache posture make prefetch advisory-only and negative",
    exit_code:75,
    budget_summary:{budget_profile:"brownout"},
    warm_target_summary:{target_dir:"/tmp/rch_target_franken_engine_bd_ad31e"},
    proof_cache_summary:{proof_cache_decision:"refresh_required"},
    archive_pressure_summary:{advisory:"compaction_first"},
    validation_cost_summary:{estimated_cpu_slots_total:8},
    roi_summary:{expected_reuse_score:900000, realized_reuse_score:200000, reuse_delta:-700000},
    artifact_paths:{swarm_warm_target_prefetch_roi_advisory_json:$artifact_path}
  }' >"${fixture_dir}/warm_target_prefetch_roi_advisory.json"
}

run_check() {
  local scope_file

  ensure_wrapper_dir
  bash -n "${BASH_SOURCE[0]}"
  bash -n "${root_dir}/scripts/swarm_validation_planner.sh"
  bash -n "${root_dir}/scripts/proof_freshness_decay_gate.sh"
  bash -n "${root_dir}/scripts/rch_incident_packet_gate.sh"
  bash -n "${root_dir}/scripts/swarm_operator_status_report.sh"
  bash -n "${root_dir}/scripts/swarm_capacity_forecaster.sh"
  bash -n "${root_dir}/scripts/swarm_admission_budget_planner.sh"
  bash -n "${root_dir}/scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh"
  bash -n "${root_dir}/scripts/swarm_warm_target_prefetch_roi_advisory.sh"
  record_pass "bash syntax"

  jq empty "${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"
  record_pass "dashboard contract json parses"

  scope_file="${wrapper_dir}/rch-policy-scope.txt"
  printf '%s\n' \
    "scripts/e2e/swarm_predictive_orchestration_e2e.sh" \
    "scripts/swarm_validation_planner.sh" \
    "scripts/proof_freshness_decay_gate.sh" \
    "scripts/rch_incident_packet_gate.sh" \
    "scripts/swarm_operator_status_report.sh" \
    >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${wrapper_dir}/rch-policy-check" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local inputs_dir planner_dir freshness_dir incident_dir status_dir fixture_dir
  local proof_cost_history reservation_snapshot in_progress_snapshot proof_artifact
  local rch_stdout rch_stderr source_revision status_path

  run_check

  inputs_dir="${artifact_root}/inputs"
  planner_dir="${artifact_root}/validation-planner"
  freshness_dir="${artifact_root}/proof-freshness"
  incident_dir="${artifact_root}/rch-incident"
  status_dir="${artifact_root}/operator-status"
  fixture_dir="${artifact_root}/operator-status-fixtures"
  mkdir -p "$inputs_dir" "$planner_dir" "$freshness_dir" "$incident_dir" "$status_dir"

  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
  proof_cost_history="${inputs_dir}/proof_cost_history.json"
  reservation_snapshot="${inputs_dir}/reservation_snapshot.json"
  in_progress_snapshot="${inputs_dir}/in_progress.json"
  proof_artifact="${inputs_dir}/stale_proof_artifact.json"
  rch_stdout="${inputs_dir}/rch.stdout.log"
  rch_stderr="${inputs_dir}/rch.stderr.log"

  write_proof_cost_history "$proof_cost_history" "$source_revision"
  write_planner_snapshots "$reservation_snapshot" "$in_progress_snapshot"
  write_stale_proof_artifact "$proof_artifact"
  write_rch_logs "$rch_stdout" "$rch_stderr"

  run_step "validation-planner-conflict" "42" \
    scripts/swarm_validation_planner.sh \
    --bead-id bd-ad31e \
    --source-revision "$source_revision" \
    --output-dir "$planner_dir" \
    --proof-cost-history-json "$proof_cost_history" \
    --reservation-snapshot-json "$reservation_snapshot" \
    --in-progress-json "$in_progress_snapshot" \
    --package frankenengine-engine \
    --test-target swarm_validation_control_plane_e2e \
    --changed-path crates/franken-engine/tests/swarm_validation_control_plane_e2e.rs \
    --planned-write-path scripts/e2e/swarm_validation_control_plane_e2e.sh \
    --planned-write-path docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md

  jq -e '
    .decision == "fail_closed"
    and .collision_risk == "reserved_overlap"
    and (.conflicting_agents | index("CyanOak") != null)
    and any(.commands[]?; .predicted_cost.cost_class == "high")
  ' "${planner_dir}/plan.json" >/dev/null
  record_pass "planner propagated high cost and collision risk"

  run_step "proof-freshness-stale" "42" \
    scripts/proof_freshness_decay_gate.sh \
    --artifact "$proof_artifact" \
    --expected-source-revision "$source_revision" \
    --expected-schema-version franken-engine.proof-cost-manifest.v1 \
    --now-ms 1777500000000 \
    --output-dir "$freshness_dir"

  jq -e '
    .freshness_state == "stale_by_source_revision"
    and .reusable == false
  ' "${freshness_dir}/proof_freshness_report.json" >/dev/null
  record_pass "proof freshness gate rejected stale source revision"

  run_step "rch-incident-timeout" "42" \
    scripts/rch_incident_packet_gate.sh \
    --output-dir "$incident_dir" \
    --command "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_ad31e cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e" \
    --target-dir /tmp/rch_target_franken_engine_bd_ad31e \
    --worker worker-predictive-smoke \
    --source-revision "$source_revision" \
    --stdout-file "$rch_stdout" \
    --stderr-file "$rch_stderr" \
    --exit-code 130 \
    --completion-marker missing

  jq -e '
    .status == "fail"
    and .failure_kind == "worker_timeout"
    and (.retry_safety | length > 0)
  ' "${incident_dir}/incident_packet.json" >/dev/null
  record_pass "rch incident packet classified timeout"

  write_operator_status_fixtures \
    "$fixture_dir" \
    "$source_revision" \
    "${planner_dir}/plan.json" \
    "${freshness_dir}/proof_freshness_report.json" \
    "${incident_dir}/incident_packet.json"

  run_step "operator-status-composed" "0" \
    scripts/swarm_operator_status_report.sh \
    --bead-id bd-ad31e \
    --source-revision "$source_revision" \
    --output-dir "$status_dir" \
    --agent-mail-status ok \
    --rch-status ok \
    --proof-index-status ok \
    --ready-json "${fixture_dir}/ready.json" \
    --in-progress-json "${fixture_dir}/in_progress.json" \
    --bv-plan-json "${fixture_dir}/bv_plan.json" \
    --reservations-json "${fixture_dir}/reservations.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --validation-plan-json "${planner_dir}/plan.json" \
    --proof-index-json "${fixture_dir}/proof_index.json" \
    --proof-outcomes-json "${fixture_dir}/proof_outcomes.json" \
    --stale-evidence-json "${fixture_dir}/stale_evidence.json" \
    --dirty-files-json "${fixture_dir}/dirty_files.json" \
    --collision-receipt-json "${planner_dir}/collision_receipt.json" \
    --proof-freshness-json "${freshness_dir}/proof_freshness_report.json" \
    --rch-incident-packet-json "${incident_dir}/incident_packet.json" \
    --capacity-forecast-json "${fixture_dir}/capacity_forecast.json" \
    --admission-budget-plan-json "${fixture_dir}/admission_budget_plan.json" \
    --lease-exchange-salvage-simulation-json "${fixture_dir}/lease_exchange_salvage_simulation.json" \
    --warm-target-prefetch-roi-advisory-json "${fixture_dir}/warm_target_prefetch_roi_advisory.json"

  status_path="${status_dir}/status.json"
  jq -e '
    .status == "degraded"
    and .dashboard_contract.renderer.provider == "/dp/frankentui"
    and .summary.high_cost_command_count >= 1
    and .predictive_dashboard.collision_risk.risk == "reserved_overlap"
    and .predictive_dashboard.proof_freshness.state == "stale_by_source_revision"
    and .predictive_dashboard.proof_freshness.reusable == false
    and .predictive_dashboard.rch_incidents.status == "degraded"
    and .predictive_dashboard.telemetry_quality.confidence_band == "low"
    and .predictive_dashboard.capacity_forecast.overall_state == "blocked"
    and .predictive_dashboard.admission_budgets.budget_profile == "brownout"
    and .predictive_dashboard.lease_exchange_salvage.decision == "manual_confirmation_required"
    and .predictive_dashboard.prefetch_roi.advisory == "manual_review_required"
    and any(.degraded[]; .component == "collision_risk")
    and any(.degraded[]; .component == "proof_freshness")
    and any(.degraded[]; .component == "rch_incident_packet")
    and any(.degraded[]; .component == "capacity_forecast")
  ' "$status_path" >/dev/null
  record_pass "operator status propagated predictive degradations"

  jq -n \
    --arg schema_version "franken-engine.swarm-predictive-orchestration-e2e-wrapper.v1" \
    --arg status "pass" \
    --arg source_revision "$source_revision" \
    --arg artifact_root "$artifact_root" \
    --arg commands_path "$commands_path" \
    --arg events_path "$events_path" \
    --arg validation_plan "${planner_dir}/plan.json" \
    --arg collision_receipt "${planner_dir}/collision_receipt.json" \
    --arg proof_freshness "${freshness_dir}/proof_freshness_report.json" \
    --arg rch_incident "${incident_dir}/incident_packet.json" \
    --arg operator_status "$status_path" \
    '{
      schema_version: $schema_version,
      status: $status,
      bead_id: "bd-ad31e",
      source_revision: $source_revision,
      heavy_rust_required: false,
      heavy_rust_reason: "This drill composes shell/json gates and verifies the planned heavy command is emitted, classified, and rejected without executing Cargo.",
      artifact_root: $artifact_root,
      artifact_paths: {
        commands_txt: $commands_path,
        events_jsonl: $events_path,
        validation_plan_json: $validation_plan,
        collision_receipt_json: $collision_receipt,
        proof_freshness_report_json: $proof_freshness,
        rch_incident_packet_json: $rch_incident,
        operator_status_json: $operator_status
      },
      assertions: [
        "planner_high_cost",
        "planner_reserved_overlap",
        "proof_stale_by_source_revision",
        "rch_worker_timeout",
        "operator_status_predictive_degraded",
        "operator_status_forecast_low_confidence",
        "operator_status_prefetch_roi_warning"
      ]
    }' >"$report_path"

  record_pass "selftest"
  printf 'swarm_predictive_orchestration_e2e_artifacts=%s\n' "$artifact_root"
  printf 'swarm_predictive_orchestration_e2e_report=%s\n' "$report_path"
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
