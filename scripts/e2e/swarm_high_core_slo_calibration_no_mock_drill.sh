#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_HIGH_CORE_SLO_CALIBRATION_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-high-core-slo-calibration-no-mock-drill}"
run_id="${SWARM_HIGH_CORE_SLO_CALIBRATION_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_HIGH_CORE_SLO_CALIBRATION_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
fixture_dir="${SWARM_HIGH_CORE_SLO_CALIBRATION_FIXTURE_DIR:-${root_dir}/scripts/testdata/swarm_high_core_slo_calibration_drill}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_telemetry_snapshot_normalizer.sh"
scenario_matrix="${root_dir}/scripts/swarm_high_core_slo_scenario_matrix.sh"
calibrator="${root_dir}/scripts/swarm_slo_calibrator.sh"
chaos_gate="${root_dir}/scripts/swarm_high_core_chaos_conformance_gate.sh"
operator_advisory="${root_dir}/scripts/swarm_operator_slo_tuning_advisory.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_ctrl_ix_runbook_truth_gate.sh"

scenario_fixture="${root_dir}/scripts/testdata/swarm_high_core_slo/scenario_matrix.json"
scenario_golden="${root_dir}/scripts/testdata/goldens/swarm_high_core_slo_scenario_matrix.golden"

stress_suite_manifest="${root_dir}/artifacts/stress_concurrency/20260222T072317Z/suite_run_manifest.json"
tail_latency_report="${root_dir}/artifacts/rgc_tail_latency_control_plane/20260319T183341Z/latency_control_plane_report.json"
chaos_verification_report="${root_dir}/artifacts/rgc_fault_injection_chaos_verification_pack/20260303T075226Z/chaos_verification_report.json"
swarm_responsiveness_claim_map="${root_dir}/docs/rgc_swarm_responsiveness_claim_map_v1.json"

fixed_now_epoch="1778200200"
fixed_stale_after_seconds="600"

replay_dir=""
report_json=""
report_tmp=""
events_path=""
commands_path=""
report_md=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_high_core_slo_calibration_no_mock_drill.sh [check|run|selftest|replay] [OPTIONS]

Compose SWARM-CTRL-IX into one deterministic, no-mock drill over checked-in
fixtures and replay artifacts. The drill reuses the shipped IX child scripts,
compares the scenario matrix output to the checked-in golden, and proves that
the real checked-in high-core evidence path still fail-closes when traceability
is not fully rch-backed. It does not execute heavy Cargo or mutate worker
state.

Modes:
  check       Syntax, fixture, and truth-gate checks.
  run         Run the composed drill and emit a deterministic artifact bundle.
  selftest    Run check, run, then replay the bundle.
  replay      Revalidate an existing bundle without rerunning child surfaces.

Options:
  --fixture-dir DIR
  --output-dir DIR
  --artifact-dir DIR    Required for replay unless replaying --output-dir.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixture-dir)
      fixture_dir="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
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

record_pass() {
  printf 'PASS swarm-high-core-slo-calibration-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-high-core-slo-calibration-no-mock-drill %s\n' "$1" >&2
}

refresh_output_paths() {
  report_json="${run_dir}/swarm_high_core_slo_calibration_no_mock_drill_report.json"
  report_tmp="${report_json}.tmp"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_md="${run_dir}/report.md"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  : >"$commands_path"
  : >"$events_path"
}

quote_command() {
  printf '%q ' "$@"
}

write_command_log() {
  printf './scripts/e2e/swarm_high_core_slo_calibration_no_mock_drill.sh %q' "$mode" >"$commands_path"
  printf ' --fixture-dir %q --output-dir %q' "$fixture_dir" "$run_dir" >>"$commands_path"
  if [[ -n "$replay_dir" ]]; then
    printf ' --artifact-dir %q' "$replay_dir" >>"$commands_path"
  fi
  printf '\n' >>"$commands_path"
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-high-core-slo-calibration-no-mock-drill.event.v1" \
    --arg event_name "swarm_high_core_slo_calibration_no_mock_drill.step" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
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
    record_failure "${step} exited ${exit_code}, expected ${expected_codes}"
    printf 'stdout=%s\nstderr=%s\n' "$stdout_path" "$stderr_path" >&2
    return "$exit_code"
  fi
}

require_json() {
  local path="$1"

  if [[ ! -f "$path" ]]; then
    printf 'missing JSON artifact: %s\n' "$path" >&2
    exit 64
  fi
  jq empty "$path" >/dev/null
}

require_path() {
  local path="$1"

  if [[ ! -e "$path" ]]; then
    printf 'missing required path: %s\n' "$path" >&2
    exit 64
  fi
}

compare_scenario_golden() {
  local report_path="$1"
  local diff_path="${run_dir}/scenario_matrix_golden.diff"

  if ! diff -u "$scenario_golden" "$report_path" >"$diff_path"; then
    record_failure "scenario matrix golden drift"
    printf 'diff=%s\n' "$diff_path" >&2
    return 1
  fi
}

run_check() {
  refresh_output_paths
  ensure_run_dir

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$normalizer"
  bash -n "$scenario_matrix"
  bash -n "$calibrator"
  bash -n "$chaos_gate"
  bash -n "$operator_advisory"
  bash -n "$truth_gate"
  jq empty "${root_dir}/docs/swarm_ctrl_ix_runbook_truth_contract_v1.json"

  require_path "$fixture_dir/ready.json"
  require_path "$fixture_dir/in_progress.json"
  require_path "$fixture_dir/validation_plan.json"
  require_path "$fixture_dir/resource_decision.json"
  require_path "$fixture_dir/reservations.json"
  require_path "$fixture_dir/proof_freshness.json"
  require_path "$fixture_dir/archive_pressure_scoreboard.json"
  require_path "$fixture_dir/capacity_forecast.json"
  require_path "$fixture_dir/admission_budget_plan.json"
  require_path "$fixture_dir/lease_exchange_salvage_simulation.json"
  require_path "$fixture_dir/warm_target_prefetch_roi_advisory.json"
  require_path "$scenario_fixture"
  require_path "$scenario_golden"
  require_path "$stress_suite_manifest"
  require_path "$tail_latency_report"
  require_path "$chaos_verification_report"
  require_path "$swarm_responsiveness_claim_map"

  bash "$truth_gate" check >/dev/null
  record_pass "syntax fixtures and truth gate"
}

run_mode() {
  local source_revision
  local telemetry_dir scenario_dir threshold_dir chaos_dir advisory_dir high_core_dir
  local telemetry_snapshot scenario_report threshold_receipt chaos_report advisory_json high_core_snapshot
  local scenario_diff budget_json high_core_failure_count high_core_traceability_count

  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
  refresh_output_paths
  ensure_run_dir
  write_command_log

  telemetry_dir="${run_dir}/telemetry"
  scenario_dir="${run_dir}/scenario-matrix"
  threshold_dir="${run_dir}/threshold-receipt"
  chaos_dir="${run_dir}/chaos-conformance"
  advisory_dir="${run_dir}/operator-advisory"
  high_core_dir="${run_dir}/high-core-traceability"

  run_step telemetry_snapshot 0 \
    bash "$normalizer" \
      --ready-json "$fixture_dir/ready.json" \
      --in-progress-json "$fixture_dir/in_progress.json" \
      --validation-plan-json "$fixture_dir/validation_plan.json" \
      --resource-decision-json "$fixture_dir/resource_decision.json" \
      --agent-mail-reservations-json "$fixture_dir/reservations.json" \
      --proof-freshness-json "$fixture_dir/proof_freshness.json" \
      --stress-suite-manifest-json "$fixture_dir/stress/stress_suite_manifest.json" \
      --tail-latency-report-json "$fixture_dir/tail_latency/latency_control_plane_report.json" \
      --chaos-verification-report-json "$fixture_dir/chaos/chaos_verification_report.json" \
      --swarm-responsiveness-claim-map-json "$fixture_dir/swarm_responsiveness_claim_map.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch" \
      --stale-after-seconds "$fixed_stale_after_seconds" \
      --output-dir "$telemetry_dir"

  telemetry_snapshot="${telemetry_dir}/swarm_capacity_snapshot.json"
  require_json "$telemetry_snapshot"
  require_json "${telemetry_dir}/swarm_slo_input_snapshot.json"

  run_step scenario_matrix 0 \
    bash "$scenario_matrix" \
      --matrix-json "$scenario_fixture" \
      --output-dir "$scenario_dir"

  scenario_report="${scenario_dir}/swarm_high_core_scenario_matrix_report.json"
  require_json "$scenario_report"
  compare_scenario_golden "$scenario_report"
  scenario_diff="${run_dir}/scenario_matrix_golden.diff"

  run_step threshold_receipt 0 \
    bash "$calibrator" \
      --telemetry-snapshot-json "$telemetry_snapshot" \
      --scenario-matrix-report-json "$scenario_report" \
      --archive-pressure-scoreboard-json "$fixture_dir/archive_pressure_scoreboard.json" \
      --warm-target-prefetch-roi-advisory-json "$fixture_dir/warm_target_prefetch_roi_advisory.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch" \
      --stale-after-seconds "$fixed_stale_after_seconds" \
      --output-dir "$threshold_dir"

  threshold_receipt="${threshold_dir}/swarm_slo_threshold_receipt.json"
  require_json "$threshold_receipt"

  run_step chaos_conformance 0 \
    bash "$chaos_gate" \
      --scenario-matrix-report-json "$scenario_report" \
      --threshold-receipt-json "$threshold_receipt" \
      --capacity-forecast-json "$fixture_dir/capacity_forecast.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch" \
      --stale-after-seconds "$fixed_stale_after_seconds" \
      --output-dir "$chaos_dir"

  chaos_report="${chaos_dir}/swarm_high_core_chaos_conformance_report.json"
  require_json "$chaos_report"

  budget_json="$fixture_dir/admission_budget_plan.json"
  require_json "$budget_json"

  run_step operator_advisory 0 \
    bash "$operator_advisory" \
      --threshold-receipt-json "$threshold_receipt" \
      --capacity-forecast-json "$fixture_dir/capacity_forecast.json" \
      --admission-budget-plan-json "$budget_json" \
      --lease-exchange-salvage-simulation-json "$fixture_dir/lease_exchange_salvage_simulation.json" \
      --warm-target-prefetch-roi-advisory-json "$fixture_dir/warm_target_prefetch_roi_advisory.json" \
      --chaos-conformance-report-json "$chaos_report" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch" \
      --stale-after-seconds "$fixed_stale_after_seconds" \
      --output-dir "$advisory_dir"

  advisory_json="${advisory_dir}/swarm_operator_slo_tuning_advisory.json"
  require_json "$advisory_json"

  run_step high_core_traceability_fail_closed 42 \
    bash "$normalizer" \
      --ready-json "$fixture_dir/ready.json" \
      --in-progress-json "$fixture_dir/in_progress.json" \
      --validation-plan-json "$fixture_dir/validation_plan.json" \
      --resource-decision-json "$fixture_dir/resource_decision.json" \
      --agent-mail-reservations-json "$fixture_dir/reservations.json" \
      --proof-freshness-json "$fixture_dir/proof_freshness.json" \
      --stress-suite-manifest-json "$stress_suite_manifest" \
      --tail-latency-report-json "$tail_latency_report" \
      --chaos-verification-report-json "$chaos_verification_report" \
      --swarm-responsiveness-claim-map-json "$swarm_responsiveness_claim_map" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch" \
      --stale-after-seconds "$fixed_stale_after_seconds" \
      --output-dir "$high_core_dir"

  high_core_snapshot="${high_core_dir}/swarm_capacity_snapshot.json"
  require_json "$high_core_snapshot"
  require_json "${high_core_dir}/swarm_slo_input_snapshot.json"

  high_core_failure_count="$(jq '(.failure_reasons // []) | length' "$high_core_snapshot")"
  high_core_traceability_count="$(jq '(.high_core_traceability_failures // []) | length' "$high_core_snapshot")"
  if [[ "$high_core_traceability_count" -lt 1 ]]; then
    record_failure "expected checked-in high-core traceability failures"
    return 1
  fi

  jq -n \
    --arg schema_version "franken-engine.swarm-high-core-slo-calibration-no-mock-drill-report.v1" \
    --arg drill_decision "pass" \
    --arg source_revision "$source_revision" \
    --arg fixture_dir_rel "scripts/testdata/swarm_high_core_slo_calibration_drill" \
    --arg scenario_fixture_rel "scripts/testdata/swarm_high_core_slo/scenario_matrix.json" \
    --arg scenario_golden_rel "scripts/testdata/goldens/swarm_high_core_slo_scenario_matrix.golden" \
    --arg stress_suite_manifest "$stress_suite_manifest" \
    --arg tail_latency_report "$tail_latency_report" \
    --arg chaos_verification_report "$chaos_verification_report" \
    --arg claim_map "$swarm_responsiveness_claim_map" \
    --arg telemetry_snapshot "$telemetry_snapshot" \
    --arg telemetry_slo_snapshot "${telemetry_dir}/swarm_slo_input_snapshot.json" \
    --arg scenario_report "$scenario_report" \
    --arg threshold_receipt "$threshold_receipt" \
    --arg chaos_report "$chaos_report" \
    --arg advisory_json "$advisory_json" \
    --arg high_core_snapshot "$high_core_snapshot" \
    --arg high_core_slo_snapshot "${high_core_dir}/swarm_slo_input_snapshot.json" \
    --arg report_json "$report_json" \
    --arg report_md "$report_md" \
    --arg commands_path "$commands_path" \
    --arg events_path "$events_path" \
    --arg scenario_diff "$scenario_diff" \
    --arg budget_json "$budget_json" \
    --arg capacity_forecast "$fixture_dir/capacity_forecast.json" \
    --arg salvage_json "$fixture_dir/lease_exchange_salvage_simulation.json" \
    --arg roi_json "$fixture_dir/warm_target_prefetch_roi_advisory.json" \
    --arg archive_pressure_json "$fixture_dir/archive_pressure_scoreboard.json" \
    --argjson fixed_now_epoch "$fixed_now_epoch" \
    --argjson high_core_failure_count "$high_core_failure_count" \
    --argjson high_core_traceability_count "$high_core_traceability_count" \
    --slurpfile telemetry "$telemetry_snapshot" \
    --slurpfile threshold "$threshold_receipt" \
    --slurpfile chaos "$chaos_report" \
    --slurpfile advisory "$advisory_json" \
    '{
      schema_version: $schema_version,
      drill_decision: $drill_decision,
      source_revision: $source_revision,
      generated_epoch_seconds: $fixed_now_epoch,
      child_artifacts: {
        swarm_capacity_snapshot_json: $telemetry_snapshot,
        swarm_slo_input_snapshot_json: $telemetry_slo_snapshot,
        swarm_high_core_scenario_matrix_report_json: $scenario_report,
        scenario_matrix_golden_diff: $scenario_diff,
        swarm_slo_threshold_receipt_json: $threshold_receipt,
        swarm_high_core_chaos_conformance_report_json: $chaos_report,
        swarm_operator_slo_tuning_advisory_json: $advisory_json,
        high_core_traceability_fail_closed_snapshot_json: $high_core_snapshot,
        high_core_traceability_fail_closed_slo_snapshot_json: $high_core_slo_snapshot
      },
      no_mock_evidence: {
        checked_in_fixture_dir: $fixture_dir_rel,
        checked_in_matrix_fixture: $scenario_fixture_rel,
        checked_in_matrix_golden: $scenario_golden_rel,
        checked_in_budget_fixture: $budget_json,
        checked_in_capacity_forecast_fixture: $capacity_forecast,
        checked_in_salvage_fixture: $salvage_json,
        checked_in_roi_fixture: $roi_json,
        checked_in_archive_pressure_fixture: $archive_pressure_json,
        checked_in_high_core_artifacts: {
          stress_suite_manifest_json: $stress_suite_manifest,
          tail_latency_report_json: $tail_latency_report,
          chaos_verification_report_json: $chaos_verification_report,
          swarm_responsiveness_claim_map_json: $claim_map
        }
      },
      assertions: {
        checked_in_fixture_inputs: true,
        scenario_golden_matches: true,
        baseline_normalizer_passed: (($telemetry[0].decision // "") == "pass"),
        threshold_receipt_passed: (($threshold[0].decision // "") == "pass"),
        chaos_conformance_passed: (($chaos[0].decision // "") == "pass"),
        operator_advisory_passed: (($advisory[0].decision // "") == "pass"),
        high_core_traceability_fail_closed: ($high_core_traceability_count > 0),
        no_live_worker_mutation_claims: true,
        replay_supported: true
      },
      summary: {
        baseline_capacity_decision: ($telemetry[0].decision // "unknown"),
        threshold_decision: ($threshold[0].decision // "unknown"),
        chaos_decision: ($chaos[0].decision // "unknown"),
        advisory_decision: ($advisory[0].decision // "unknown"),
        advisory_confidence_band: ($advisory[0].evidence_quality.confidence_band // "unknown"),
        high_core_failure_reason_count: $high_core_failure_count,
        high_core_traceability_failure_count: $high_core_traceability_count
      },
      artifact_paths: {
        swarm_high_core_slo_calibration_no_mock_drill_report_json: $report_json,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      }
    }' >"$report_tmp"
  mv "$report_tmp" "$report_json"

  cat >"$report_md" <<EOF
# SWARM-CTRL-IX No-Mock Drill

- Decision: pass
- Baseline telemetry snapshot: \`$telemetry_snapshot\`
- Scenario matrix report: \`$scenario_report\`
- Threshold receipt: \`$threshold_receipt\`
- Chaos conformance report: \`$chaos_report\`
- Operator advisory: \`$advisory_json\`
- High-core fail-closed snapshot: \`$high_core_snapshot\`

## Evidence Assertions

- Checked-in fixture inputs were used from \`scripts/testdata/swarm_high_core_slo_calibration_drill\`.
- Scenario matrix output matched \`scripts/testdata/goldens/swarm_high_core_slo_scenario_matrix.golden\`.
- The checked-in high-core evidence path fail-closed with \`$high_core_traceability_count\` traceability finding(s).
- The composed drill did not mutate live worker state, leases, queue entries, or archive bundles.
EOF
}

replay_mode() {
  if [[ -z "$replay_dir" ]]; then
    replay_dir="$run_dir"
  fi
  run_dir="$replay_dir"
  refresh_output_paths

  require_json "$report_json"
  require_path "$commands_path"
  require_path "$events_path"
  require_path "$report_md"

  while IFS= read -r child_path; do
    require_json "$child_path"
  done < <(jq -r '.child_artifacts[]' "$report_json")

  if ! jq -e '
    .schema_version == "franken-engine.swarm-high-core-slo-calibration-no-mock-drill-report.v1"
    and .drill_decision == "pass"
    and .assertions.checked_in_fixture_inputs == true
    and .assertions.scenario_golden_matches == true
    and .assertions.high_core_traceability_fail_closed == true
    and .assertions.no_live_worker_mutation_claims == true
    and .assertions.replay_supported == true
    and (.summary.high_core_traceability_failure_count | tonumber) >= 1
  ' "$report_json" >/dev/null; then
    record_failure "report assertions mismatch"
    return 1
  fi

  if ! diff -u "$scenario_golden" "$(jq -r '.child_artifacts.swarm_high_core_scenario_matrix_report_json' "$report_json")" >/dev/null; then
    record_failure "scenario golden drift during replay"
    return 1
  fi
}

run_selftest() {
  local tmp_root run_output

  run_check
  tmp_root="${SWARM_HIGH_CORE_SLO_CALIBRATION_NO_MOCK_DRILL_SELFTEST_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_root"
  run_output="$(mktemp -d "${tmp_root%/}/swarm-high-core-slo-calibration-no-mock-drill.XXXXXX")"
  run_dir="$run_output"
  mode="run"
  run_mode
  mode="replay"
  replay_dir="$run_output"
  replay_mode
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
  replay)
    replay_mode
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    usage
    exit 64
    ;;
esac
