#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
advisory_script="${root_dir}/scripts/swarm_operator_slo_tuning_advisory.sh"
contract_doc="${root_dir}/docs/SWARM_OPERATOR_SLO_TUNING_ADVISORY.md"
contract_json="${root_dir}/docs/swarm_operator_slo_tuning_advisory_contract_v1.json"
dashboard_doc="${root_dir}/docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"
dashboard_json="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"
golden_dir="${root_dir}/scripts/testdata/goldens"

record_pass() {
  printf 'PASS swarm-operator-slo-tuning-advisory %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-operator-slo-tuning-advisory %s\n' "$1" >&2
}

canonicalize_json() {
  local json_path="$1"
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
    scrub | del(.artifact_paths, .generated_epoch_seconds, .advisory_id, .hash_basis, (.evidence_links[]?.hash))
  ' "$json_path"
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"
  sed -E \
    -e "s#${tmp_root}#[SMOKE_ROOT]#g" \
    -e 's/swarm-operator-slo-tuning-[0-9a-f]{16}/swarm-operator-slo-tuning-[ADVISORY_ID]/g' \
    "$report_path"
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

write_threshold_fixture() {
  local output_path="$1"
  local mode="$2"
  local tmp="${output_path}.tmp"

  if [[ "$mode" == "healthy" ]]; then
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-slo-threshold-receipt.v1",
      decision:"pass",
      confidence_class:"high",
      summary:{accepted_threshold_count:6, downgraded_threshold_count:0, rejected_threshold_count:0},
      thresholds:{
        queue_wait_budget_band:{status:"accepted", confidence_class:"high", current_band:"healthy", reason:"queue p99 remains healthy"},
        validation_latency_band:{status:"accepted", confidence_class:"high", current_band:"healthy", reason:"latency remains healthy"},
        rch_fallback_rate_tolerance:{status:"accepted", confidence_class:"high", current_band:"rch_backed_only", reason:"all high-core evidence stayed rch-backed"},
        starvation_brownout_guardrails:{status:"accepted", confidence_class:"high", current_band:"healthy", reason:"guardrails stay healthy"},
        proof_cache_freshness_and_warm_target_roi:{status:"accepted", confidence_class:"high", current_band:"reuse_hot_cache", reason:"proof cache and ROI both support reuse"},
        archive_salvage_pressure_thresholds:{status:"accepted", confidence_class:"high", current_band:"retain", reason:"archive pressure remains low"}
      },
      artifact_paths:{swarm_slo_threshold_receipt_json:$artifact_path}
    }' >"$tmp"
  else
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-slo-threshold-receipt.v1",
      decision:"pass",
      confidence_class:"medium",
      summary:{accepted_threshold_count:4, downgraded_threshold_count:2, rejected_threshold_count:0},
      thresholds:{
        queue_wait_budget_band:{status:"downgraded", confidence_class:"medium", current_band:"near_limit", reason:"queue p99 is near the reviewed limit"},
        validation_latency_band:{status:"accepted", confidence_class:"medium", current_band:"near_limit", reason:"latency remains bounded but not green"},
        rch_fallback_rate_tolerance:{status:"accepted", confidence_class:"high", current_band:"rch_backed_only", reason:"reviewed evidence is still rch-backed"},
        starvation_brownout_guardrails:{status:"downgraded", confidence_class:"medium", current_band:"manual_confirmation", reason:"brownout guardrails require operator review"},
        proof_cache_freshness_and_warm_target_roi:{status:"accepted", confidence_class:"medium", current_band:"reuse_hot_cache", reason:"prefetch still helps but with bounded margin"},
        archive_salvage_pressure_thresholds:{status:"accepted", confidence_class:"medium", current_band:"cool_archive", reason:"archive pressure is elevated"}
      },
      artifact_paths:{swarm_slo_threshold_receipt_json:$artifact_path}
    }' >"$tmp"
  fi
  mv "$tmp" "$output_path"
}

write_forecast_fixture() {
  local output_path="$1"
  local mode="$2"
  local generated_epoch_seconds="$3"
  local tmp="${output_path}.tmp"

  if [[ "$mode" == "healthy" ]]; then
    jq -n --arg artifact_path "$output_path" --argjson generated_epoch_seconds "$generated_epoch_seconds" '{
      schema_version:"franken-engine.swarm-capacity-forecast.v1",
      decision:"pass",
      confidence_band:"high",
      generated_epoch_seconds:$generated_epoch_seconds,
      summary:{overall_state:"nominal", blocked_categories:[], degraded_categories:[]},
      artifact_paths:{swarm_capacity_forecast_json:$artifact_path}
    }' >"$tmp"
  else
    jq -n --arg artifact_path "$output_path" --argjson generated_epoch_seconds "$generated_epoch_seconds" '{
      schema_version:"franken-engine.swarm-capacity-forecast.v1",
      decision:"pass",
      confidence_band:"low",
      generated_epoch_seconds:$generated_epoch_seconds,
      summary:{overall_state:"brownout", blocked_categories:["compile_pressure"], degraded_categories:["coordination_pressure","proof_availability"]},
      artifact_paths:{swarm_capacity_forecast_json:$artifact_path}
    }' >"$tmp"
  fi
  mv "$tmp" "$output_path"
}

write_admission_fixture() {
  local output_path="$1"
  local mode="$2"
  local tmp="${output_path}.tmp"

  if [[ "$mode" == "healthy" ]]; then
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-admission-budget-plan.v1",
      decision:"admit",
      budget_profile:"balanced",
      summary:{admitted_count:2, deferred_count:0},
      recommendations:[
        {request_id:"proof-a", bead_id:"bd-hybk2", agent_id:"CyanOak", decision:"admit", budget_class:"protected", proof_obligation:true},
        {request_id:"proof-b", bead_id:"bd-hybk2", agent_id:"CyanOak", decision:"admit", budget_class:"standard", proof_obligation:false}
      ],
      artifact_paths:{swarm_admission_budget_plan_json:$artifact_path}
    }' >"$tmp"
  else
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-admission-budget-plan.v1",
      decision:"defer",
      budget_profile:"brownout",
      summary:{admitted_count:0, deferred_count:2},
      recommendations:[
        {request_id:"proof-a", bead_id:"bd-hybk2", agent_id:"CyanOak", decision:"defer", budget_class:"protected", proof_obligation:true},
        {request_id:"proof-b", bead_id:"bd-hybk2", agent_id:"CyanOak", decision:"admit_narrow", budget_class:"protected", proof_obligation:true}
      ],
      artifact_paths:{swarm_admission_budget_plan_json:$artifact_path}
    }' >"$tmp"
  fi
  mv "$tmp" "$output_path"
}

write_salvage_fixture() {
  local output_path="$1"
  local mode="$2"
  local tmp="${output_path}.tmp"

  if [[ "$mode" == "healthy" ]]; then
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
      decision:"retain_current_assignments",
      summary:{manual_review_count:0, lease_exchange_candidate_count:0, salvage_promotion_candidate_count:0},
      upstream_summary:{archive_pressure_advisory:"retain", lease_decision:"admit", lease_reason:"healthy"},
      artifact_paths:{swarm_lease_exchange_cancellation_salvage_simulation_json:$artifact_path}
    }' >"$tmp"
  else
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
      decision:"salvage_manual_review",
      summary:{manual_review_count:1, lease_exchange_candidate_count:1, salvage_promotion_candidate_count:2},
      upstream_summary:{archive_pressure_advisory:"cool_archive", lease_decision:"defer", lease_reason:"brownout"},
      artifact_paths:{swarm_lease_exchange_cancellation_salvage_simulation_json:$artifact_path}
    }' >"$tmp"
  fi
  mv "$tmp" "$output_path"
}

write_roi_fixture() {
  local output_path="$1"
  local mode="$2"
  local tmp="${output_path}.tmp"

  if [[ "$mode" == "healthy" ]]; then
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
      advisory:"prefetch_recommended",
      recommended_action:"Warm the preserved target before the next protected proof.",
      proof_cache_summary:{proof_cache_decision:"cache_hit"},
      archive_pressure_summary:{advisory:"retain"},
      warm_target_summary:{target_dir:"/tmp/rch_target_hybk2"},
      artifact_paths:{swarm_warm_target_prefetch_roi_advisory_json:$artifact_path}
    }' >"$tmp"
  else
    jq -n --arg artifact_path "$output_path" '{
      schema_version:"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
      advisory:"prefetch_not_recommended",
      recommended_action:"Keep the target cool until brownout pressure clears.",
      proof_cache_summary:{proof_cache_decision:"partial_refresh"},
      archive_pressure_summary:{advisory:"cool_archive"},
      warm_target_summary:{target_dir:"/tmp/rch_target_hybk2"},
      artifact_paths:{swarm_warm_target_prefetch_roi_advisory_json:$artifact_path}
    }' >"$tmp"
  fi
  mv "$tmp" "$output_path"
}

write_chaos_fixture() {
  local output_path="$1"
  local mode="$2"
  local claim_rows
  local tmp="${output_path}.tmp"

  if [[ "$mode" == "healthy" ]]; then
    claim_rows='[
      {"claim_id":"queue_wait_budget_band", "scenario_class":"healthy_64plus_admission", "verdict":"pass"},
      {"claim_id":"validation_latency_band", "scenario_class":"healthy_64plus_admission", "verdict":"pass"},
      {"claim_id":"rch_fallback_rate_tolerance", "scenario_class":"healthy_64plus_admission", "verdict":"pass"},
      {"claim_id":"starvation_brownout_guardrails", "scenario_class":"chaos_recovery_saturated_queue", "verdict":"pass"},
      {"claim_id":"proof_cache_freshness_and_warm_target_roi", "scenario_class":"proof_cache_hit", "verdict":"expected_fail"},
      {"claim_id":"archive_salvage_pressure_thresholds", "scenario_class":"proof_cache_hit", "verdict":"expected_fail"}
    ]'
    jq -n --arg artifact_path "$output_path" --argjson rows "$claim_rows" '{
      schema_version:"franken-engine.swarm-high-core-chaos-conformance-report.v1",
      decision:"pass",
      summary:{total_rows:42, pass_count:28, fail_count:0, expected_fail_count:14, must_count:24, should_count:4, may_count:14},
      rows:$rows,
      gate_failures:[],
      artifact_paths:{swarm_high_core_chaos_conformance_report_json:$artifact_path}
    }' >"$tmp"
  else
    claim_rows='[
      {"claim_id":"queue_wait_budget_band", "scenario_class":"degraded_worker_pool_local_fallback", "verdict":"expected_fail"},
      {"claim_id":"validation_latency_band", "scenario_class":"degraded_worker_pool_local_fallback", "verdict":"expected_fail"},
      {"claim_id":"rch_fallback_rate_tolerance", "scenario_class":"degraded_worker_pool_local_fallback", "verdict":"pass"},
      {"claim_id":"starvation_brownout_guardrails", "scenario_class":"manual_confirmation_lock_pressure", "verdict":"pass"},
      {"claim_id":"proof_cache_freshness_and_warm_target_roi", "scenario_class":"proof_cache_stale_miss", "verdict":"expected_fail"},
      {"claim_id":"archive_salvage_pressure_thresholds", "scenario_class":"proof_cache_stale_miss", "verdict":"expected_fail"}
    ]'
    jq -n --arg artifact_path "$output_path" --argjson rows "$claim_rows" '{
      schema_version:"franken-engine.swarm-high-core-chaos-conformance-report.v1",
      decision:"pass",
      summary:{total_rows:42, pass_count:26, fail_count:0, expected_fail_count:16, must_count:22, should_count:4, may_count:16},
      rows:$rows,
      gate_failures:[],
      artifact_paths:{swarm_high_core_chaos_conformance_report_json:$artifact_path}
    }' >"$tmp"
  fi
  mv "$tmp" "$output_path"
}

assert_contract_truth_paths() {
  local advisory_doc_path="$1"
  local advisory_json_path="$2"
  local dashboard_doc_path="$3"
  local dashboard_json_path="$4"

  jq -e '
    .schema_version == "franken-engine.swarm-operator-slo-tuning-advisory-contract.v1"
    and .report_schema_version == "franken-engine.swarm-operator-slo-tuning-advisory.v1"
    and .dashboard_section_path == "predictive_dashboard.slo_tuning_advisory"
    and (.supported_claim_ids | length == 6)
    and (.compatible_inputs | index("franken-engine.swarm-high-core-chaos-conformance-report.v1"))
  ' "$advisory_json_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-predictive-dashboard-contract.v1"
    and .renderer.repo_path == "/dp/frankentui"
    and .renderer.shipped_in_franken_engine == false
    and .renderer.local_renderer == false
    and .slo_tuning_advisory.script == "scripts/swarm_operator_slo_tuning_advisory.sh"
    and .slo_tuning_advisory.status == "fixture_only_extension"
    and .slo_tuning_advisory.producer_integration == false
    and (.slo_tuning_advisory_dashboard_fields | index("predictive_dashboard.slo_tuning_advisory.evidence_quality"))
    and (.slo_tuning_advisory_dashboard_fields | index("predictive_dashboard.slo_tuning_advisory.recommended_actions"))
  ' "$dashboard_json_path" >/dev/null

  grep -Fq '/dp/frankentui' "$advisory_doc_path"
  grep -Fq 'unsupported SLO claims' "$advisory_doc_path"
  grep -Fq 'duplicate UI-stack claims' "$advisory_doc_path"
  grep -Fq 'scripts/swarm_operator_slo_tuning_advisory.sh' "$dashboard_doc_path"
  grep -Fq 'docs/swarm_operator_slo_tuning_advisory_contract_v1.json' "$dashboard_doc_path"
  grep -Fq 'scripts/swarm_operator_status_report.sh remains the only predictive dashboard producer' "$dashboard_doc_path"

  if grep -Eiq 'ships a local TUI|local_renderer[[:space:]]*:[[:space:]]*true|shipped_in_franken_engine[[:space:]]*:[[:space:]]*true' "$dashboard_doc_path" "$dashboard_json_path" "$advisory_doc_path"; then
    record_failure "contract docs/json claim a shipped local renderer or duplicate dashboard producer"
    return 1
  fi

  record_pass "dashboard handoff truth validates"
}

run_case() {
  local case_name="$1"
  local tmp_root="$2"
  local fixture_dir output_dir actual_path report_actual_path golden_path report_golden_path now_epoch

  fixture_dir="${tmp_root}/${case_name}/fixtures"
  output_dir="${tmp_root}/${case_name}/output"
  actual_path="${tmp_root}/${case_name}.actual.json"
  report_actual_path="${tmp_root}/${case_name}.actual.report.md"
  golden_path="${golden_dir}/swarm_operator_slo_tuning_advisory.golden"
  report_golden_path="${golden_dir}/swarm_operator_slo_tuning_advisory.report.golden"
  mkdir -p "$fixture_dir" "$output_dir"
  now_epoch="$(date -u +%s)"

  write_threshold_fixture "${fixture_dir}/threshold.json" "$case_name"
  write_forecast_fixture "${fixture_dir}/forecast.json" "$case_name" "$now_epoch"
  write_admission_fixture "${fixture_dir}/admission.json" "$case_name"
  write_salvage_fixture "${fixture_dir}/salvage.json" "$case_name"
  write_roi_fixture "${fixture_dir}/roi.json" "$case_name"
  write_chaos_fixture "${fixture_dir}/chaos.json" "$case_name"

  "$advisory_script" \
    --threshold-receipt-json "${fixture_dir}/threshold.json" \
    --capacity-forecast-json "${fixture_dir}/forecast.json" \
    --admission-budget-plan-json "${fixture_dir}/admission.json" \
    --lease-exchange-salvage-simulation-json "${fixture_dir}/salvage.json" \
    --warm-target-prefetch-roi-advisory-json "${fixture_dir}/roi.json" \
    --chaos-conformance-report-json "${fixture_dir}/chaos.json" \
    --output-dir "$output_dir" >/dev/null

  if [[ "$case_name" == "healthy" ]]; then
    jq -e '
      .schema_version == "franken-engine.swarm-operator-slo-tuning-advisory.v1"
      and .decision == "pass"
      and .evidence_quality.decision == "reviewed"
      and .evidence_quality.confidence_band == "high"
      and (.recommended_actions | any(.action == "admit" and .state == "recommended"))
      and (.recommended_actions | any(.action == "prewarm" and .state == "recommended"))
      and (.recommended_actions | any(.action == "require_human_coordination" and .state == "hold"))
      and (.claim_support.supported_claims | length == 6)
      and (.claim_support.unsupported_claims | length == 0)
      and .dashboard_handoff.future_section_path == "predictive_dashboard.slo_tuning_advisory"
    ' "${output_dir}/swarm_operator_slo_tuning_advisory.json" >/dev/null

    canonicalize_json "${output_dir}/swarm_operator_slo_tuning_advisory.json" "$tmp_root" >"$actual_path"
    compare_case_golden "$case_name" "$actual_path" "$golden_path"
    canonicalize_report "${output_dir}/report.md" "$tmp_root" >"$report_actual_path"
    compare_case_golden "${case_name}.report" "$report_actual_path" "$report_golden_path"
  else
    jq -e '
      .decision == "pass"
      and .evidence_quality.decision == "degraded"
      and .evidence_quality.confidence_band == "low"
      and .forecast_summary.overall_state == "brownout"
      and (.recommended_actions | any(.action == "narrow" and .state == "recommended"))
      and (.recommended_actions | any(.action == "defer" and .state == "recommended"))
      and (.recommended_actions | any(.action == "archive" and .state == "recommended"))
      and (.recommended_actions | any(.action == "salvage" and .state == "recommended"))
      and (.recommended_actions | any(.action == "require_human_coordination" and .state == "recommended"))
    ' "${output_dir}/swarm_operator_slo_tuning_advisory.json" >/dev/null
    grep -Fq '## Evidence Links' "${output_dir}/report.md"
    record_pass "degraded advisory remains advisory-only and bounded"
  fi
}

run_check() {
  bash -n "$advisory_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_json"
  grep -q 'predictive_dashboard.slo_tuning_advisory' "$contract_doc"
  grep -q 'duplicate UI-stack claims' "$contract_doc"
  record_pass "syntax and contract inventory"
}

run_selftest() {
  local tmp_parent tmp_root rc

  run_check
  tmp_parent="${SWARM_OPERATOR_SLO_TUNING_ADVISORY_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-operator-slo-tuning-advisory.XXXXXX")"

  assert_contract_truth_paths "$contract_doc" "$contract_json" "$dashboard_doc" "$dashboard_json"
  run_case "healthy" "$tmp_root"
  run_case "degraded" "$tmp_root"

  cp "$dashboard_doc" "${tmp_root}/dashboard.bad.md"
  printf '\nFrankenEngine ships a local TUI for this advisory.\n' >> "${tmp_root}/dashboard.bad.md"
  set +e
  assert_contract_truth_paths "$contract_doc" "$contract_json" "${tmp_root}/dashboard.bad.md" "$dashboard_json" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    record_failure "truth gate did not reject duplicate UI-stack claims"
    exit 1
  fi
  record_pass "duplicate UI-stack claims fail truth gate"

  write_threshold_fixture "${tmp_root}/threshold.json" "healthy"
  write_forecast_fixture "${tmp_root}/forecast.json" "healthy" "$(( $(date -u +%s) - 7200 ))"
  write_admission_fixture "${tmp_root}/admission.json" "healthy"
  write_salvage_fixture "${tmp_root}/salvage.json" "healthy"
  write_roi_fixture "${tmp_root}/roi.json" "healthy"
  write_chaos_fixture "${tmp_root}/chaos.json" "healthy"
  set +e
  "$advisory_script" \
    --threshold-receipt-json "${tmp_root}/threshold.json" \
    --capacity-forecast-json "${tmp_root}/forecast.json" \
    --admission-budget-plan-json "${tmp_root}/admission.json" \
    --lease-exchange-salvage-simulation-json "${tmp_root}/salvage.json" \
    --warm-target-prefetch-roi-advisory-json "${tmp_root}/roi.json" \
    --chaos-conformance-report-json "${tmp_root}/chaos.json" \
    --output-dir "${tmp_root}/stale-forecast" >/dev/null
  rc=$?
  set -e
  if [[ "$rc" -ne 42 ]]; then
    record_failure "expected stale forecast fail-closed exit 42, got ${rc}"
    exit 1
  fi
  jq -e '.decision == "fail_closed" and (.gate_failures | any(.code == "stale_forecast_reference"))' "${tmp_root}/stale-forecast/swarm_operator_slo_tuning_advisory.json" >/dev/null
  record_pass "stale forecast fails closed"

  write_forecast_fixture "${tmp_root}/forecast.json" "healthy" "$(date -u +%s)"
  jq 'del(.artifact_paths.swarm_capacity_forecast_json)' "${tmp_root}/forecast.json" > "${tmp_root}/forecast.bad.json"
  set +e
  "$advisory_script" \
    --threshold-receipt-json "${tmp_root}/threshold.json" \
    --capacity-forecast-json "${tmp_root}/forecast.bad.json" \
    --admission-budget-plan-json "${tmp_root}/admission.json" \
    --lease-exchange-salvage-simulation-json "${tmp_root}/salvage.json" \
    --warm-target-prefetch-roi-advisory-json "${tmp_root}/roi.json" \
    --chaos-conformance-report-json "${tmp_root}/chaos.json" \
    --output-dir "${tmp_root}/missing-evidence" >/dev/null
  rc=$?
  set -e
  if [[ "$rc" -ne 42 ]]; then
    record_failure "expected missing evidence fail-closed exit 42, got ${rc}"
    exit 1
  fi
  jq -e '.decision == "fail_closed" and (.gate_failures | any(.code == "missing_evidence_link"))' "${tmp_root}/missing-evidence/swarm_operator_slo_tuning_advisory.json" >/dev/null
  record_pass "missing evidence links fail closed"

  jq '.thresholds.synthetic_scheduler_claim = {status:"accepted", confidence_class:"high", current_band:"synthetic", reason:"bad fixture"}' "${tmp_root}/threshold.json" > "${tmp_root}/threshold.bad.json"
  set +e
  "$advisory_script" \
    --threshold-receipt-json "${tmp_root}/threshold.bad.json" \
    --capacity-forecast-json "${tmp_root}/forecast.json" \
    --admission-budget-plan-json "${tmp_root}/admission.json" \
    --lease-exchange-salvage-simulation-json "${tmp_root}/salvage.json" \
    --warm-target-prefetch-roi-advisory-json "${tmp_root}/roi.json" \
    --chaos-conformance-report-json "${tmp_root}/chaos.json" \
    --output-dir "${tmp_root}/unsupported-claim" >/dev/null
  rc=$?
  set -e
  if [[ "$rc" -ne 42 ]]; then
    record_failure "expected unsupported claim fail-closed exit 42, got ${rc}"
    exit 1
  fi
  jq -e '.decision == "fail_closed" and (.gate_failures | any(.code == "unsupported_slo_claim"))' "${tmp_root}/unsupported-claim/swarm_operator_slo_tuning_advisory.json" >/dev/null
  record_pass "unsupported SLO claims fail closed"

  printf 'swarm_operator_slo_tuning_advisory_smoke_artifacts=%s\n' "$tmp_root"
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
