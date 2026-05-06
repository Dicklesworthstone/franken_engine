#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/swarm_high_core_chaos_conformance_gate.sh"
matrix_script="${root_dir}/scripts/swarm_high_core_slo_scenario_matrix.sh"
matrix_fixture="${root_dir}/scripts/testdata/swarm_high_core_slo/scenario_matrix.json"
calibrator="${root_dir}/scripts/swarm_slo_calibrator.sh"
contract_path="${root_dir}/docs/swarm_high_core_chaos_conformance_gate_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_HIGH_CORE_CHAOS_CONFORMANCE_GATE.md"

record_pass() {
  printf 'PASS swarm-high-core-chaos-conformance %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-high-core-chaos-conformance %s\n' "$1" >&2
}

write_archive_fixture() {
  local output_path="$1"
  jq -n '{
    schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
    pressure_level: "low",
    advisory: "retain",
    recommended_action: "retain_current_residency",
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
  jq -n '{
    schema_version: "franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
    advisory: "reuse_hot_cache",
    recommended_action: "retain_target_and_reuse_cache",
    reason: "fixture",
    proof_cache_summary: {
      proof_cache_decision: "reuse_hot_cache"
    },
    warm_target_summary: {
      target_dir: "fixture-target",
      roi: {
        expected_reuse_score: 0.82,
        realized_reuse_score: 0.91
      }
    },
    archive_pressure_summary: {
      advisory: "retain",
      recommended_action: "retain_current_residency"
    },
    validation_cost_summary: {
      estimated_cpu_slots_total: 6
    }
  }' >"$output_path"
}

write_forecast_fixture() {
  local output_path="$1"
  local generated_epoch_seconds="$2"
  jq -n \
    --argjson generated_epoch_seconds "$generated_epoch_seconds" \
    '{
      schema_version: "franken-engine.swarm-capacity-forecast.v1",
      generated_epoch_seconds: $generated_epoch_seconds,
      decision: "pass",
      summary: {
        overall_state: "normal"
      }
    }' >"$output_path"
}

run_check() {
  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'swarm_high_core_chaos_conformance_report.json' "$docs_path"
  grep -q 'MUST/SHOULD/MAY' "$docs_path"
  record_pass "syntax and contract inventory"
}

run_selftest() {
  local tmp_parent tmp_root matrix_output matrix_report
  local healthy_snapshot archive_fixture roi_fixture forecast_fresh forecast_stale
  local threshold_receipt healthy_run healthy_copy bare_run local_run fail_run rc now_epoch

  run_check
  tmp_parent="${SWARM_HIGH_CORE_CHAOS_CONFORMANCE_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-high-core-chaos-conformance.XXXXXX")"
  matrix_output="${tmp_root}/matrix"
  now_epoch="$(date -u +%s)"

  "$matrix_script" --matrix-json "$matrix_fixture" --output-dir "$matrix_output" >/dev/null
  matrix_report="${matrix_output}/swarm_high_core_scenario_matrix_report.json"
  healthy_snapshot="${matrix_output}/cases/healthy_64plus_admission/swarm_capacity_snapshot.json"
  archive_fixture="${tmp_root}/archive.json"
  roi_fixture="${tmp_root}/roi.json"
  forecast_fresh="${tmp_root}/forecast-fresh.json"
  forecast_stale="${tmp_root}/forecast-stale.json"

  write_archive_fixture "$archive_fixture"
  write_roi_fixture "$roi_fixture"
  write_forecast_fixture "$forecast_fresh" "$now_epoch"
  write_forecast_fixture "$forecast_stale" "$((now_epoch - 7200))"

  threshold_receipt="${tmp_root}/threshold-receipt"
  "$calibrator" \
    --telemetry-snapshot-json "$healthy_snapshot" \
    --scenario-matrix-report-json "$matrix_report" \
    --archive-pressure-scoreboard-json "$archive_fixture" \
    --warm-target-prefetch-roi-advisory-json "$roi_fixture" \
    --output-dir "$threshold_receipt" >/dev/null

  healthy_run="${tmp_root}/healthy-run"
  "$gate" \
    --scenario-matrix-report-json "$matrix_report" \
    --threshold-receipt-json "${threshold_receipt}/swarm_slo_threshold_receipt.json" \
    --capacity-forecast-json "$forecast_fresh" \
    --output-dir "$healthy_run" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-high-core-chaos-conformance-report.v1"
    and .decision == "pass"
    and .summary.total_rows == 42
    and .summary.fail_count == 0
    and .summary.expected_fail_count == 14
    and .summary.must_count > 0
    and .summary.should_count > 0
    and .summary.may_count > 0
    and (.rows | any(.claim_id == "rch_fallback_rate_tolerance" and .scenario_class == "degraded_worker_pool_local_fallback" and .verdict == "pass"))
    and (.rows | any(.claim_id == "archive_salvage_pressure_thresholds" and .verdict == "expected_fail"))
    and (.rows | any(.claim_id == "starvation_brownout_guardrails" and .scenario_class == "chaos_recovery_saturated_queue" and .verdict == "pass"))
  ' "${healthy_run}/swarm_high_core_chaos_conformance_report.json" >/dev/null
  grep -q '| Claim | Scenario | Level | Verdict | Reason |' "${healthy_run}/report.md"
  record_pass "healthy conformance report validates"

  healthy_copy="${tmp_root}/healthy-copy"
  "$gate" \
    --scenario-matrix-report-json "$matrix_report" \
    --threshold-receipt-json "${threshold_receipt}/swarm_slo_threshold_receipt.json" \
    --capacity-forecast-json "$forecast_fresh" \
    --output-dir "$healthy_copy" >/dev/null
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${healthy_run}/swarm_high_core_chaos_conformance_report.json") \
    <(jq -cS 'del(.artifact_paths)' "${healthy_copy}/swarm_high_core_chaos_conformance_report.json") >/dev/null
  record_pass "repeated conformance report is deterministic"

  fail_run="${tmp_root}/stale-forecast"
  set +e
  "$gate" \
    --scenario-matrix-report-json "$matrix_report" \
    --threshold-receipt-json "${threshold_receipt}/swarm_slo_threshold_receipt.json" \
    --capacity-forecast-json "$forecast_stale" \
    --output-dir "$fail_run" >/dev/null
  rc=$?
  set -e
  if [[ "$rc" -ne 42 ]]; then
    record_failure "expected stale forecast fail-closed exit 42, got ${rc}"
    exit 1
  fi
  jq -e '
    .decision == "fail_closed"
    and (.gate_failures | any(.code == "stale_forecast_artifact"))
  ' "${fail_run}/swarm_high_core_chaos_conformance_report.json" >/dev/null
  record_pass "stale forecast fails closed"

  bare_run="${tmp_root}/bare-cargo"
  cp -R "$matrix_output" "${tmp_root}/matrix-bare"
  printf 'cargo test -p frankenengine-engine --test forbidden\n' >> "${tmp_root}/matrix-bare/cases/healthy_64plus_admission/high_core/stress/commands.txt"
  set +e
  "$gate" \
    --scenario-matrix-report-json "${tmp_root}/matrix-bare/swarm_high_core_scenario_matrix_report.json" \
    --threshold-receipt-json "${threshold_receipt}/swarm_slo_threshold_receipt.json" \
    --capacity-forecast-json "$forecast_fresh" \
    --output-dir "$bare_run" >/dev/null
  rc=$?
  set -e
  if [[ "$rc" -ne 42 ]]; then
    record_failure "expected bare cargo fail-closed exit 42, got ${rc}"
    exit 1
  fi
  jq -e '
    .decision == "fail_closed"
    and (.gate_failures | any(.code == "bare_cargo_command_detected"))
  ' "${bare_run}/swarm_high_core_chaos_conformance_report.json" >/dev/null
  record_pass "bare cargo evidence fails closed"

  local_run="${tmp_root}/local-fallback"
  cp -R "$matrix_output" "${tmp_root}/matrix-local"
  jq '
    .cases |= map(
      if .case_id == "healthy_64plus_admission" then
        .actual.traceability.stress = "local_or_unknown"
      else
        .
      end
    )
  ' "${tmp_root}/matrix-local/swarm_high_core_scenario_matrix_report.json" > "${tmp_root}/matrix-local/swarm_high_core_scenario_matrix_report.json.tmp"
  mv "${tmp_root}/matrix-local/swarm_high_core_scenario_matrix_report.json.tmp" "${tmp_root}/matrix-local/swarm_high_core_scenario_matrix_report.json"
  set +e
  "$gate" \
    --scenario-matrix-report-json "${tmp_root}/matrix-local/swarm_high_core_scenario_matrix_report.json" \
    --threshold-receipt-json "${threshold_receipt}/swarm_slo_threshold_receipt.json" \
    --capacity-forecast-json "$forecast_fresh" \
    --output-dir "$local_run" >/dev/null
  rc=$?
  set -e
  if [[ "$rc" -ne 42 ]]; then
    record_failure "expected unexpected local fallback fail-closed exit 42, got ${rc}"
    exit 1
  fi
  jq -e '
    .decision == "fail_closed"
    and (.gate_failures | any(.code == "unexpected_local_or_unknown_traceability"))
  ' "${local_run}/swarm_high_core_chaos_conformance_report.json" >/dev/null
  record_pass "unexpected local fallback fails closed"

  printf 'swarm_high_core_chaos_conformance_smoke_artifacts=%s\n' "$tmp_root"
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
