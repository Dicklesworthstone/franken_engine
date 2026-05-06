#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2016

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_CHECKPOINT_LIFECYCLE_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-checkpoint-lifecycle-no-mock-drill}"
run_id="${SWARM_CHECKPOINT_LIFECYCLE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CHECKPOINT_LIFECYCLE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
fixture_dir="${SWARM_CHECKPOINT_LIFECYCLE_DRILL_FIXTURE_DIR:-${root_dir}/scripts/testdata/swarm_checkpoint_lifecycle_drill/healthy}"
bead_id="${SWARM_CHECKPOINT_LIFECYCLE_NO_MOCK_DRILL_BEAD_ID:-bd-sm48h}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

bundle_packer="${root_dir}/scripts/swarm_checkpoint_bundle_packer.sh"
restore_planner="${root_dir}/scripts/swarm_checkpoint_restore_planner.sh"
conformance_gate="${root_dir}/scripts/swarm_checkpoint_restore_conformance_gate.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"

replay_dir=""
report_json=""
report_tmp=""
events_path=""
commands_path=""
report_md=""

fixture_files=(
  "swarm_capacity_snapshot.json"
  "swarm_capacity_forecast.json"
  "swarm_admission_budget_plan.json"
  "remote_proof_archive_pressure_scoreboard.json"
  "stale_lock_recommendations.json"
  "swarm_lease_exchange_cancellation_salvage_simulation.json"
  "swarm_starvation_rescue_plan.json"
  "swarm_starvation_rescue_conformance_report.json"
  "swarm_operator_status_report.json"
  "swarm_warm_target_prefetch_roi_advisory.json"
  "swarm_high_core_scenario_matrix_report.json"
  "swarm_operator_slo_tuning_advisory.json"
  "proof_economy_replay_trace.json"
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh [check|run|selftest|replay] [OPTIONS]

Compose the shipped SWARM-CTRL-XI checkpoint bundle packer, restore planner,
conformance gate, and operator status handoff into one deterministic no-mock
checkpoint lifecycle drill over checked-in fixtures.

Modes:
  check       Syntax and fixture availability checks.
  run         Build the composed checkpoint lifecycle artifact bundle.
  selftest    Run check, run, then replay the emitted bundle.
  replay      Revalidate an existing bundle without rerunning child scripts.

Options:
  --fixture-dir DIR
  --output-dir DIR
  --artifact-dir DIR    Required for replay unless replaying --output-dir.
  --bead-id ID
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
    --bead-id)
      bead_id="${2:-}"
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
  printf 'PASS swarm-checkpoint-lifecycle-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-checkpoint-lifecycle-no-mock-drill %s\n' "$1" >&2
}

refresh_output_paths() {
  report_json="${run_dir}/swarm_checkpoint_lifecycle_no_mock_drill_report.json"
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
  printf './scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh %q' "$mode" >"$commands_path"
  printf ' --fixture-dir %q --output-dir %q --bead-id %q' "$fixture_dir" "$run_dir" "$bead_id" >>"$commands_path"
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
    --arg schema_version "franken-engine.swarm-checkpoint-lifecycle-no-mock-drill.event.v1" \
    --arg event_name "swarm_checkpoint_lifecycle_no_mock_drill.step" \
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
  local step_dir="${run_dir}/${step}"
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

require_json() {
  local path="$1"

  if [[ ! -f "$path" ]]; then
    printf 'missing JSON artifact: %s\n' "$path" >&2
    exit 64
  fi
  jq empty "$path" >/dev/null
}

simulate_disconnect_restart() {
  local capture_dir="$1"
  local simulated_dir="${run_dir}/simulated-disconnect-restart"
  local step_dir="${run_dir}/simulate-disconnect-restart"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"

  mkdir -p "$simulated_dir" "$step_dir"
  cp "${capture_dir}/checkpoint_bundle.json" "${simulated_dir}/checkpoint_bundle.json"
  cp "${capture_dir}/run_manifest.json" "${simulated_dir}/run_manifest.json"
  cp "${capture_dir}/events.jsonl" "${simulated_dir}/events.jsonl"
  cp "${capture_dir}/commands.txt" "${simulated_dir}/commands.txt"
  cp "${capture_dir}/summary.md" "${simulated_dir}/summary.md"

  {
    printf 'simulated_disconnect_restart=true\n'
    printf 'source_bundle=%s\n' "${capture_dir}/checkpoint_bundle.json"
    printf 'restored_bundle=%s\n' "${simulated_dir}/checkpoint_bundle.json"
    printf 'source_run_manifest=%s\n' "${capture_dir}/run_manifest.json"
    printf 'restored_run_manifest=%s\n' "${simulated_dir}/run_manifest.json"
  } >"$stdout_path"
  : >"$stderr_path"

  printf 'simulate_disconnect_restart: copy %q -> %q\n' \
    "${capture_dir}/checkpoint_bundle.json" \
    "${simulated_dir}/checkpoint_bundle.json" >>"$commands_path"
  write_event "simulate-disconnect-restart" "pass" 0 "$stdout_path" "$stderr_path"
}

run_check() {
  local fixture

  refresh_output_paths
  ensure_run_dir

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$bundle_packer"
  bash -n "$restore_planner"
  bash -n "$conformance_gate"
  bash -n "$operator_status"

  for fixture in "${fixture_files[@]}"; do
    test -f "${fixture_dir}/${fixture}"
    jq empty "${fixture_dir}/${fixture}" >/dev/null
  done
  record_pass "bash syntax and fixture json"
}

run_mode() {
  local capture_dir restore_dir conformance_dir status_dir simulated_dir
  local capture_bundle capture_manifest restored_bundle restored_manifest
  local restore_plan_json conformance_json status_json status_report_md
  local prefetch_json rescue_plan_json rescue_conformance_json
  local source_revision

  refresh_output_paths
  ensure_run_dir
  write_command_log

  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
  capture_dir="${run_dir}/capture"
  restore_dir="${run_dir}/restore-plan"
  conformance_dir="${run_dir}/conformance"
  status_dir="${run_dir}/operator-status"

  mkdir -p "$capture_dir" "$restore_dir" "$conformance_dir" "$status_dir"

  run_step "checkpoint-bundle" "0" \
    "$bundle_packer" \
    --output-dir "$capture_dir" \
    --swarm-capacity-snapshot-json "${fixture_dir}/swarm_capacity_snapshot.json" \
    --swarm-capacity-forecast-json "${fixture_dir}/swarm_capacity_forecast.json" \
    --swarm-admission-budget-plan-json "${fixture_dir}/swarm_admission_budget_plan.json" \
    --remote-proof-archive-pressure-scoreboard-json "${fixture_dir}/remote_proof_archive_pressure_scoreboard.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --swarm-lease-exchange-cancellation-salvage-simulation-json "${fixture_dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --swarm-starvation-rescue-plan-json "${fixture_dir}/swarm_starvation_rescue_plan.json" \
    --swarm-operator-status-report-json "${fixture_dir}/swarm_operator_status_report.json" \
    --swarm-high-core-scenario-matrix-report-json "${fixture_dir}/swarm_high_core_scenario_matrix_report.json" \
    --swarm-operator-slo-tuning-advisory-json "${fixture_dir}/swarm_operator_slo_tuning_advisory.json" \
    --proof-economy-replay-trace-json "${fixture_dir}/proof_economy_replay_trace.json" \
    --now-epoch-seconds 2000 \
    --stale-after-seconds 1800 \
    --source-revision "$source_revision"

  require_json "${capture_dir}/checkpoint_bundle.json"
  require_json "${capture_dir}/run_manifest.json"

  simulate_disconnect_restart "$capture_dir"
  simulated_dir="${run_dir}/simulated-disconnect-restart"

  run_step "checkpoint-restore-plan" "0" \
    "$restore_planner" \
    --output-dir "$restore_dir" \
    --checkpoint-bundle-json "${simulated_dir}/checkpoint_bundle.json" \
    --current-swarm-capacity-snapshot-json "${fixture_dir}/swarm_capacity_snapshot.json" \
    --current-swarm-capacity-forecast-json "${fixture_dir}/swarm_capacity_forecast.json" \
    --current-remote-proof-archive-pressure-scoreboard-json "${fixture_dir}/remote_proof_archive_pressure_scoreboard.json" \
    --current-stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json "${fixture_dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --current-swarm-operator-status-report-json "${fixture_dir}/swarm_operator_status_report.json" \
    --now-epoch-seconds 2000 \
    --source-revision "$source_revision"

  run_step "checkpoint-restore-conformance" "0" \
    "$conformance_gate" \
    --output-dir "$conformance_dir" \
    --checkpoint-bundle-json "${simulated_dir}/checkpoint_bundle.json" \
    --checkpoint-restore-plan-json "${restore_dir}/swarm_checkpoint_restore_plan.json" \
    --source-revision "$source_revision"

  run_step "operator-status" "0" \
    "$operator_status" \
    --output-dir "$status_dir" \
    --bead-id "$bead_id" \
    --agent-mail-status ok \
    --rch-status ok \
    --proof-index-status ok \
    --stale-lock-recommendations-json "${fixture_dir}/stale_lock_recommendations.json" \
    --capacity-forecast-json "${fixture_dir}/swarm_capacity_forecast.json" \
    --admission-budget-plan-json "${fixture_dir}/swarm_admission_budget_plan.json" \
    --lease-exchange-salvage-simulation-json "${fixture_dir}/swarm_lease_exchange_cancellation_salvage_simulation.json" \
    --warm-target-prefetch-roi-advisory-json "${fixture_dir}/swarm_warm_target_prefetch_roi_advisory.json" \
    --starvation-rescue-plan-json "${fixture_dir}/swarm_starvation_rescue_plan.json" \
    --starvation-rescue-conformance-report-json "${fixture_dir}/swarm_starvation_rescue_conformance_report.json" \
    --checkpoint-bundle-json "${simulated_dir}/checkpoint_bundle.json" \
    --checkpoint-restore-plan-json "${restore_dir}/swarm_checkpoint_restore_plan.json" \
    --checkpoint-restore-conformance-report-json "${conformance_dir}/swarm_checkpoint_restore_conformance_report.json" \
    --source-revision "$source_revision"

  capture_bundle="${capture_dir}/checkpoint_bundle.json"
  capture_manifest="${capture_dir}/run_manifest.json"
  restored_bundle="${simulated_dir}/checkpoint_bundle.json"
  restored_manifest="${simulated_dir}/run_manifest.json"
  restore_plan_json="${restore_dir}/swarm_checkpoint_restore_plan.json"
  conformance_json="${conformance_dir}/swarm_checkpoint_restore_conformance_report.json"
  status_json="${status_dir}/status.json"
  status_report_md="${status_dir}/report.md"
  prefetch_json="${fixture_dir}/swarm_warm_target_prefetch_roi_advisory.json"
  rescue_plan_json="${fixture_dir}/swarm_starvation_rescue_plan.json"
  rescue_conformance_json="${fixture_dir}/swarm_starvation_rescue_conformance_report.json"

  require_json "$capture_bundle"
  require_json "$capture_manifest"
  require_json "$restored_bundle"
  require_json "$restored_manifest"
  require_json "$restore_plan_json"
  require_json "$conformance_json"
  require_json "$status_json"
  require_json "$prefetch_json"
  require_json "$rescue_plan_json"
  require_json "$rescue_conformance_json"
  test -f "${capture_dir}/summary.md"
  test -f "${restore_dir}/report.md"
  test -f "${conformance_dir}/report.md"
  test -f "$status_report_md"

  jq -n \
    --arg schema_version "franken-engine.swarm-checkpoint-lifecycle-no-mock-drill-report.v1" \
    --arg source_revision "$source_revision" \
    --arg bead_id "$bead_id" \
    --arg fixture_dir "$fixture_dir" \
    --arg report_json "$report_json" \
    --arg report_md "$report_md" \
    --arg commands_path "$commands_path" \
    --arg events_path "$events_path" \
    --arg capture_bundle "$capture_bundle" \
    --arg capture_manifest "$capture_manifest" \
    --arg capture_summary "${capture_dir}/summary.md" \
    --arg restored_bundle "$restored_bundle" \
    --arg restored_manifest "$restored_manifest" \
    --arg restore_plan_json "$restore_plan_json" \
    --arg restore_plan_report "${restore_dir}/report.md" \
    --arg conformance_json "$conformance_json" \
    --arg conformance_report "${conformance_dir}/report.md" \
    --arg status_json "$status_json" \
    --arg status_report_md "$status_report_md" \
    --arg prefetch_json "$prefetch_json" \
    --arg rescue_plan_json "$rescue_plan_json" \
    --arg rescue_conformance_json "$rescue_conformance_json" \
    --arg simulate_stdout "${run_dir}/simulate-disconnect-restart/stdout.log" \
    --slurpfile bundle "$restored_bundle" \
    --slurpfile plan "$restore_plan_json" \
    --slurpfile conformance "$conformance_json" \
    --slurpfile status "$status_json" \
    '
    ($bundle[0]) as $bundle
    | ($plan[0]) as $plan
    | ($conformance[0]) as $conformance
    | ($status[0]) as $status
    | {
        schema_version: $schema_version,
        bead_id: $bead_id,
        source_revision: $source_revision,
        fixture_dir: $fixture_dir,
        summary: {
          checkpoint_id: $bundle.checkpoint_id,
          capture_decision: $bundle.capture_decision,
          restore_readiness_hint: $bundle.restore_readiness_hint,
          restore_plan_decision: $plan.decision,
          restore_drift_class: ($plan.drift_class // "unknown"),
          restore_top_action: ($plan.summary.top_restore_action // null),
          conformance_decision: $conformance.decision,
          conformance_restore_decision: ($conformance.summary.restore_decision // null),
          operator_status: ($status.status // "unknown"),
          operator_checkpoint_restore_plan_decision: ($status.summary.checkpoint_restore_plan_decision // "unknown"),
          operator_checkpoint_restore_escalation_band: ($status.summary.checkpoint_restore_escalation_band // "unknown"),
          operator_checkpoint_restore_top_action: ($status.summary.checkpoint_restore_top_action // null),
          operator_checkpoint_restore_unresolved_risk_count: ($status.summary.checkpoint_restore_unresolved_risk_count // 0),
          operator_degraded_count: ($status.summary.degraded_count // 0)
        },
        assertions: {
          bundle_copy_reused_for_restore: ($restored_bundle | endswith("/simulated-disconnect-restart/checkpoint_bundle.json")),
          checkpoint_ids_match: (
            ($bundle.checkpoint_id == $plan.checkpoint_id)
            and ($plan.checkpoint_id == $conformance.checkpoint_id)
          ),
          conformance_tracks_plan: (($conformance.summary.restore_decision // null) == $plan.decision),
          operator_status_integrates_checkpoint_restore: (
            ($status.summary.checkpoint_restore_plan_decision // null) == $plan.decision
            and ($status.artifact_paths.checkpoint_bundle_json // null) == ($bundle.artifact_paths.checkpoint_bundle_json // null)
            and ($status.artifact_paths.checkpoint_restore_plan_json // null) == ($plan.artifact_paths.swarm_checkpoint_restore_plan_json // null)
            and ($status.artifact_paths.checkpoint_restore_conformance_report_json // null) == ($conformance.artifact_paths.swarm_checkpoint_restore_conformance_report_json // null)
          ),
          report_paths_exist: true,
          simulated_disconnect_restart_logged: true
        },
        components: {
          checkpoint_bundle: {
            checkpoint_id: $bundle.checkpoint_id,
            capture_decision: $bundle.capture_decision,
            restore_readiness_hint: $bundle.restore_readiness_hint,
            blocker_count: ($bundle.upstream_evidence.blocker_count // 0),
            optional_present_count: ($bundle.upstream_evidence.optional_present_count // 0),
            run_manifest_path: $capture_manifest
          },
          restore_plan: {
            decision: $plan.decision,
            drift_class: ($plan.drift_class // "unknown"),
            top_restore_action: ($plan.summary.top_restore_action // null),
            missing_current_comparison_count: ($plan.summary.missing_current_comparison_count // 0),
            fail_closed_reason_count: (($plan.drift_receipt.fail_closed_reasons // []) | length),
            finding_count: (($plan.drift_receipt.findings // []) | length)
          },
          conformance: {
            decision: $conformance.decision,
            restore_decision: ($conformance.summary.restore_decision // null),
            gate_failure_count: ($conformance.summary.gate_failure_count // 0),
            checked_artifact_path_count: ($conformance.summary.checked_artifact_path_count // 0)
          },
          operator_status_checkpoint_restore: {
            plan_decision: ($status.predictive_dashboard.checkpoint_restore.plan_decision // "unknown"),
            conformance_decision: ($status.predictive_dashboard.checkpoint_restore.conformance_decision // "unknown"),
            escalation_band: ($status.predictive_dashboard.checkpoint_restore.escalation_band // "unknown"),
            top_restore_action: ($status.predictive_dashboard.checkpoint_restore.top_restore_action // null),
            checked_artifact_path_count: ($status.predictive_dashboard.checkpoint_restore.checked_artifact_path_count // 0),
            unresolved_risk_count: (($status.predictive_dashboard.checkpoint_restore.unresolved_risks // []) | length)
          }
        },
        reuse_audit: {
          source_surfaces: [
            "scripts/swarm_checkpoint_bundle_packer.sh",
            "scripts/swarm_checkpoint_restore_planner.sh",
            "scripts/swarm_checkpoint_restore_conformance_gate.sh",
            "scripts/swarm_operator_status_report.sh",
            "scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh"
          ],
          checked_in_fixture_dir: $fixture_dir,
          simulated_steps: [
            "capture_checkpoint_bundle",
            "simulate_disconnect_restart",
            "checkpoint_restore_plan",
            "checkpoint_restore_conformance",
            "operator_status_handoff"
          ]
        },
        child_artifacts: {
          capture_checkpoint_bundle_json: $capture_bundle,
          capture_run_manifest_json: $capture_manifest,
          capture_summary_md: $capture_summary,
          restored_checkpoint_bundle_json: $restored_bundle,
          restored_run_manifest_json: $restored_manifest,
          swarm_checkpoint_restore_plan_json: $restore_plan_json,
          swarm_checkpoint_restore_report_md: $restore_plan_report,
          swarm_checkpoint_restore_conformance_report_json: $conformance_json,
          swarm_checkpoint_restore_conformance_report_md: $conformance_report,
          operator_status_json: $status_json,
          operator_report_md: $status_report_md,
          swarm_warm_target_prefetch_roi_advisory_json: $prefetch_json,
          swarm_starvation_rescue_plan_json: $rescue_plan_json,
          swarm_starvation_rescue_conformance_report_json: $rescue_conformance_json,
          simulated_disconnect_restart_stdout_log: $simulate_stdout
        },
        artifact_paths: {
          report_json: $report_json,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_md
        }
      }
    ' >"$report_tmp"
  mv "$report_tmp" "$report_json"

  jq -e '[.assertions[]] | all' "$report_json" >/dev/null

  {
    printf '# SWARM Checkpoint Lifecycle No-Mock Drill\n\n'
    printf -- "- Bead: \`%s\`\n" "$bead_id"
    printf -- "- Fixture dir: \`%s\`\n" "$fixture_dir"
    printf -- "- Checkpoint id: \`%s\`\n" "$(jq -r '.summary.checkpoint_id' "$report_json")"
    printf -- "- Capture decision: \`%s\`\n" "$(jq -r '.summary.capture_decision' "$report_json")"
    printf -- "- Restore plan: \`%s\` via \`%s\`\n" \
      "$(jq -r '.summary.restore_plan_decision' "$report_json")" \
      "$(jq -r '.summary.restore_top_action' "$report_json")"
    printf -- "- Conformance decision: \`%s\`\n" "$(jq -r '.summary.conformance_decision' "$report_json")"
    printf -- "- Operator checkpoint escalation: \`%s\` via \`%s\`\n" \
      "$(jq -r '.summary.operator_checkpoint_restore_escalation_band' "$report_json")" \
      "$(jq -r '.summary.operator_checkpoint_restore_top_action' "$report_json")"
    printf -- "- Operator overall status: \`%s\` with degraded_count=%s\n" \
      "$(jq -r '.summary.operator_status' "$report_json")" \
      "$(jq -r '.summary.operator_degraded_count' "$report_json")"
    printf '\n## Notes\n\n'
    printf -- "- The simulated disconnect/restart step replays the saved checkpoint bundle copy under \`simulated-disconnect-restart/checkpoint_bundle.json\`.\n"
    printf -- "- \`operator-status/status.json\` may remain degraded because the no-mock drill intentionally omits unrelated resource-lease, proof-cache, QoS batch, and staged-contamination artifacts; checkpoint restore truth lives in \`summary.checkpoint_restore_*\` and \`predictive_dashboard.checkpoint_restore.*\`.\n"
    printf '\n## Child Artifacts\n\n'
    jq -r '.child_artifacts | to_entries[] | "- `" + .key + "`: `" + .value + "`"' "$report_json"
  } >"$report_md"

  printf 'swarm_checkpoint_lifecycle_no_mock_drill_artifacts=%s\n' "$run_dir"
}

replay_mode() {
  local artifact_dir="${replay_dir:-$run_dir}"
  local replay_report="${artifact_dir}/swarm_checkpoint_lifecycle_no_mock_drill_report.json"
  local capture_bundle restored_bundle restore_plan_json conformance_json status_json status_report_md

  if [[ ! -f "$replay_report" ]]; then
    printf 'missing replay report: %s\n' "$replay_report" >&2
    exit 64
  fi
  require_json "$replay_report"

  jq -e '
    .schema_version == "franken-engine.swarm-checkpoint-lifecycle-no-mock-drill-report.v1"
    and ([.assertions[]] | all)
    and (.reuse_audit.source_surfaces | length >= 5)
  ' "$replay_report" >/dev/null

  capture_bundle="$(jq -r '.child_artifacts.capture_checkpoint_bundle_json' "$replay_report")"
  restored_bundle="$(jq -r '.child_artifacts.restored_checkpoint_bundle_json' "$replay_report")"
  restore_plan_json="$(jq -r '.child_artifacts.swarm_checkpoint_restore_plan_json' "$replay_report")"
  conformance_json="$(jq -r '.child_artifacts.swarm_checkpoint_restore_conformance_report_json' "$replay_report")"
  status_json="$(jq -r '.child_artifacts.operator_status_json' "$replay_report")"
  status_report_md="$(jq -r '.child_artifacts.operator_report_md' "$replay_report")"

  require_json "$capture_bundle"
  require_json "$restored_bundle"
  require_json "$restore_plan_json"
  require_json "$conformance_json"
  require_json "$status_json"
  test -f "$status_report_md"
  test -f "$(jq -r '.artifact_paths.report_md' "$replay_report")"
  test -f "$(jq -r '.artifact_paths.commands_txt' "$replay_report")"
  test -f "$(jq -r '.artifact_paths.events_jsonl' "$replay_report")"

  jq -e '
    .summary.restore_plan_decision == .summary.operator_checkpoint_restore_plan_decision
    and .assertions.operator_status_integrates_checkpoint_restore
  ' "$replay_report" >/dev/null

  record_pass "replay bundle ${artifact_dir}"
}

run_selftest() {
  run_check
  run_mode
  replay_dir="$run_dir"
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
    record_failure "unknown mode: $mode"
    exit 64
    ;;
esac
