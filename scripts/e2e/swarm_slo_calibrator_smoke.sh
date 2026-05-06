#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
calibrator="${root_dir}/scripts/swarm_slo_calibrator.sh"
matrix_script="${root_dir}/scripts/swarm_high_core_slo_scenario_matrix.sh"
matrix_fixture="${root_dir}/scripts/testdata/swarm_high_core_slo/scenario_matrix.json"
contract_path="${root_dir}/docs/swarm_slo_threshold_receipt_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_SLO_CALIBRATOR.md"
dashboard_contract_path="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"
dashboard_docs_path="${root_dir}/docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"

record_pass() {
  printf 'PASS swarm-slo-calibrator %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-slo-calibrator %s\n' "$1" >&2
}

write_archive_fixture() {
  local output_path="$1"
  local pressure_level="$2"
  local advisory="$3"
  local recommended_action="$4"

  jq -n \
    --arg pressure_level "$pressure_level" \
    --arg advisory "$advisory" \
    --arg recommended_action "$recommended_action" \
    '{
      schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
      pressure_level: $pressure_level,
      advisory: $advisory,
      recommended_action: $recommended_action,
      reason: "fixture",
      policy_findings: [],
      hash_basis: {
        input_hash: "archive-fixture",
        scoreboard_hash: "archive-fixture-scoreboard"
      }
    }' >"$output_path"
}

write_roi_fixture() {
  local output_path="$1"
  local advisory="$2"
  local recommended_action="$3"
  local proof_cache_decision="$4"
  local expected_reuse_score="$5"
  local realized_reuse_score="$6"

  jq -n \
    --arg advisory "$advisory" \
    --arg recommended_action "$recommended_action" \
    --arg proof_cache_decision "$proof_cache_decision" \
    --argjson expected_reuse_score "$expected_reuse_score" \
    --argjson realized_reuse_score "$realized_reuse_score" \
    '{
      schema_version: "franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
      advisory: $advisory,
      recommended_action: $recommended_action,
      reason: "fixture",
      proof_cache_summary: {
        proof_cache_decision: $proof_cache_decision
      },
      warm_target_summary: {
        target_dir: "fixture-target",
        roi: {
          expected_reuse_score: $expected_reuse_score,
          realized_reuse_score: $realized_reuse_score
        }
      },
      archive_pressure_summary: {
        advisory: (
          if $advisory == "prefetch_archive" then "cool_archive"
          elif $advisory == "defer" then "compaction_first"
          else "retain"
          end
        ),
        recommended_action: "fixture"
      },
      validation_cost_summary: {
        estimated_cpu_slots_total: 6
      }
    }' >"$output_path"
}

run_check() {
  bash -n "$calibrator"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  jq -e '
    .slo_calibrator.receipt_schema_version == "franken-engine.swarm-slo-threshold-receipt.v1"
    and (.input_snapshot_contracts | index("franken-engine.swarm-slo-threshold-receipt.v1") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.slo_calibration.decision") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.slo_calibration.confidence_class") != null)
  ' "$dashboard_contract_path" >/dev/null
  grep -q 'scripts/swarm_slo_calibrator.sh' "$docs_path"
  grep -q 'swarm_slo_threshold_receipt' "$dashboard_docs_path"
  record_pass "syntax docs and contract inventory"
}

run_selftest() {
  local tmp_parent tmp_root matrix_output
  local healthy_snapshot chaos_snapshot degraded_snapshot matrix_report
  local healthy_archive healthy_roi downgraded_archive downgraded_roi
  local healthy_a healthy_b chaos_run fail_run rc

  run_check
  tmp_parent="${SWARM_SLO_CALIBRATOR_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-slo-calibrator.XXXXXX")"
  matrix_output="${tmp_root}/matrix"

  "$matrix_script" --matrix-json "$matrix_fixture" --output-dir "$matrix_output" >/dev/null

  matrix_report="${matrix_output}/swarm_high_core_scenario_matrix_report.json"
  healthy_snapshot="${matrix_output}/cases/healthy_64plus_admission/swarm_capacity_snapshot.json"
  chaos_snapshot="${matrix_output}/cases/chaos_recovery_saturated_queue/swarm_capacity_snapshot.json"
  degraded_snapshot="${matrix_output}/cases/degraded_worker_pool_local_fallback/swarm_capacity_snapshot.json"

  healthy_archive="${tmp_root}/healthy_archive.json"
  healthy_roi="${tmp_root}/healthy_roi.json"
  downgraded_archive="${tmp_root}/downgraded_archive.json"
  downgraded_roi="${tmp_root}/downgraded_roi.json"

  write_archive_fixture "$healthy_archive" "low" "retain" "retain_current_residency"
  write_roi_fixture "$healthy_roi" "reuse_hot_cache" "retain_target_and_reuse_cache" "reuse_hot_cache" 0.82 0.91

  write_archive_fixture "$downgraded_archive" "elevated" "compaction_first" "compact_before_eviction"
  write_roi_fixture "$downgraded_roi" "defer" "defer_prefetch_pressure" "refresh_required" 0.82 0.31

  healthy_a="${tmp_root}/healthy-a"
  "$calibrator" \
    --telemetry-snapshot-json "$healthy_snapshot" \
    --scenario-matrix-report-json "$matrix_report" \
    --archive-pressure-scoreboard-json "$healthy_archive" \
    --warm-target-prefetch-roi-advisory-json "$healthy_roi" \
    --output-dir "$healthy_a" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-slo-threshold-receipt.v1"
    and .decision == "pass"
    and .confidence_class == "high"
    and .summary.accepted_threshold_count == 6
    and .summary.downgraded_threshold_count == 0
    and .summary.rejected_threshold_count == 0
    and .thresholds.queue_wait_budget_band.status == "accepted"
    and .thresholds.validation_latency_band.status == "accepted"
    and .thresholds.rch_fallback_rate_tolerance.observed_local_or_unknown_high_core_surfaces == 0
    and .thresholds.proof_cache_freshness_and_warm_target_roi.current_band == "reuse_hot_cache"
    and .thresholds.archive_salvage_pressure_thresholds.current_band == "retain"
    and (.evidence_hashes | keys | length) == 4
  ' "${healthy_a}/swarm_slo_threshold_receipt.json" >/dev/null
  jq -s 'map(select(.status == "accepted")) | length == 6' "${healthy_a}/events.jsonl" >/dev/null
  record_pass "healthy receipt validates"

  healthy_b="${tmp_root}/healthy-b"
  "$calibrator" \
    --telemetry-snapshot-json "$healthy_snapshot" \
    --scenario-matrix-report-json "$matrix_report" \
    --archive-pressure-scoreboard-json "$healthy_archive" \
    --warm-target-prefetch-roi-advisory-json "$healthy_roi" \
    --output-dir "$healthy_b" >/dev/null

  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${healthy_a}/swarm_slo_threshold_receipt.json") \
    <(jq -cS 'del(.artifact_paths)' "${healthy_b}/swarm_slo_threshold_receipt.json") >/dev/null
  record_pass "repeated receipt is deterministic"

  chaos_run="${tmp_root}/chaos"
  "$calibrator" \
    --telemetry-snapshot-json "$chaos_snapshot" \
    --scenario-matrix-report-json "$matrix_report" \
    --archive-pressure-scoreboard-json "$downgraded_archive" \
    --warm-target-prefetch-roi-advisory-json "$downgraded_roi" \
    --output-dir "$chaos_run" >/dev/null

  jq -e '
    .decision == "pass"
    and .confidence_class == "medium"
    and .summary.downgraded_threshold_count >= 4
    and .summary.rejected_threshold_count == 0
    and .thresholds.queue_wait_budget_band.status == "downgraded"
    and .thresholds.starvation_brownout_guardrails.status == "downgraded"
    and .thresholds.proof_cache_freshness_and_warm_target_roi.status == "downgraded"
    and .thresholds.archive_salvage_pressure_thresholds.status == "downgraded"
  ' "${chaos_run}/swarm_slo_threshold_receipt.json" >/dev/null
  jq -s 'map(select(.status == "downgraded")) | length >= 4' "${chaos_run}/events.jsonl" >/dev/null
  record_pass "chaos pressure receipt downgrades thresholds"

  fail_run="${tmp_root}/fail"
  set +e
  "$calibrator" \
    --telemetry-snapshot-json "$degraded_snapshot" \
    --scenario-matrix-report-json "$matrix_report" \
    --archive-pressure-scoreboard-json "$healthy_archive" \
    --warm-target-prefetch-roi-advisory-json "$healthy_roi" \
    --output-dir "$fail_run" >/dev/null
  rc=$?
  set -e
  if [[ "$rc" -ne 42 ]]; then
    record_failure "expected fail-closed exit 42 for degraded worker evidence, got ${rc}"
    exit 1
  fi
  jq -e '
    .decision == "fail_closed"
    and .confidence_class == "low"
    and .summary.rejected_threshold_count >= 4
    and .thresholds.rch_fallback_rate_tolerance.status == "rejected"
    and .thresholds.queue_wait_budget_band.status == "rejected"
  ' "${fail_run}/swarm_slo_threshold_receipt.json" >/dev/null
  jq -s 'map(select(.status == "rejected")) | length >= 4' "${fail_run}/events.jsonl" >/dev/null
  record_pass "degraded worker evidence fails closed"

  printf 'swarm_slo_calibrator_smoke_artifacts=%s\n' "$tmp_root"
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
