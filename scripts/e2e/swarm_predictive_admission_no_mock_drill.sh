#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_PREDICTIVE_ADMISSION_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-predictive-admission-no-mock-drill}"
run_id="${SWARM_PREDICTIVE_ADMISSION_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PREDICTIVE_ADMISSION_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
fixture_dir="${SWARM_ADMISSION_DRILL_FIXTURE_DIR:-${root_dir}/scripts/testdata/swarm_admission_drill}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

admission_drill="${root_dir}/scripts/e2e/swarm_admission_drill.sh"
predictive_e2e="${root_dir}/scripts/e2e/swarm_predictive_orchestration_e2e.sh"
archive_drill="${root_dir}/scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh"

replay_dir=""
report_json=""
report_tmp=""
events_path=""
commands_path=""
report_md=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh [check|run|selftest|replay] [OPTIONS]

Compose the shipped SWARM-CTRL-VIII predictive-admission surfaces into one
deterministic no-mock drill. The drill reuses the existing admission drill,
predictive orchestration e2e, and archive lifecycle drill directly. It does not
run heavy Cargo or mutate live worker state.

Modes:
  check       Syntax and child-surface existence checks.
  run         Run the composed drill with deterministic output paths.
  selftest    Run check, run, then replay the combined bundle.
  replay      Revalidate an existing combined bundle without rerunning children.

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
  printf 'PASS swarm-predictive-admission-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-predictive-admission-no-mock-drill %s\n' "$1" >&2
}

refresh_output_paths() {
  report_json="${run_dir}/swarm_predictive_admission_no_mock_drill_report.json"
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
  printf './scripts/e2e/swarm_predictive_admission_no_mock_drill.sh %q' "$mode" >"$commands_path"
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
    --arg schema_version "franken-engine.swarm-predictive-admission-no-mock-drill.event.v1" \
    --arg event_name "swarm_predictive_admission_no_mock_drill.step" \
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

run_check() {
  refresh_output_paths
  ensure_run_dir

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$admission_drill"
  bash -n "$predictive_e2e"
  bash -n "$archive_drill"
  record_pass "bash syntax"

  bash "$admission_drill" check --fixture-dir "$fixture_dir" --output-dir "${run_dir}/admission-check" >/dev/null
  SWARM_PREDICTIVE_ORCHESTRATION_E2E_ARTIFACT_ROOT="${run_dir}/predictive-check" \
    bash "$predictive_e2e" check >/dev/null
  bash "$archive_drill" check --output-dir "${run_dir}/archive-check" >/dev/null
  record_pass "child surfaces check"
}

run_mode() {
  local admission_dir predictive_dir archive_dir
  local admission_report predictive_report archive_report
  local status_json status_report_md
  local capacity_forecast_json admission_budget_json salvage_json prefetch_json
  local archive_stdout archive_root
  local source_revision

  refresh_output_paths
  ensure_run_dir
  write_command_log

  admission_dir="${run_dir}/admission"
  predictive_dir="${run_dir}/predictive"
  archive_dir="${run_dir}/archive"
  mkdir -p "$admission_dir" "$predictive_dir" "$archive_dir"

  run_step "admission-selftest" "0" \
    bash "$admission_drill" selftest --fixture-dir "$fixture_dir" --output-dir "$admission_dir"

  run_step "predictive-selftest" "0" \
    env SWARM_PREDICTIVE_ORCHESTRATION_E2E_ARTIFACT_ROOT="$predictive_dir" \
    bash "$predictive_e2e" selftest

  run_step "archive-selftest" "0" \
    bash "$archive_drill" selftest --output-dir "$archive_dir"

  admission_report="${admission_dir}/swarm_admission_drill_report.json"
  predictive_report="${predictive_dir}/wrapper/report.json"
  archive_stdout="${run_dir}/archive-selftest/stdout.log"
  archive_root="$(sed -n 's/^remote_proof_archive_lifecycle_no_mock_drill_artifacts=//p' "$archive_stdout" | tail -n 1)"
  if [[ -z "$archive_root" ]]; then
    printf 'archive lifecycle selftest did not report an artifact root\n' >&2
    exit 64
  fi
  archive_report="${archive_root}/run/remote_proof_archive_lifecycle_no_mock_drill_report.json"
  require_json "$admission_report"
  require_json "$predictive_report"
  require_json "$archive_report"

  status_json="$(jq -r '.artifact_paths.operator_status_json // empty' "$predictive_report")"
  if [[ -z "$status_json" ]]; then
    printf 'predictive wrapper missing operator status artifact path\n' >&2
    exit 64
  fi
  require_json "$status_json"

  status_report_md="$(jq -r '.artifact_paths.report_md // empty' "$status_json")"
  if [[ -z "$status_report_md" || ! -f "$status_report_md" ]]; then
    printf 'operator status markdown report missing: %s\n' "$status_report_md" >&2
    exit 64
  fi

  capacity_forecast_json="$(jq -r '.artifact_paths.capacity_forecast_json // empty' "$status_json")"
  admission_budget_json="$(jq -r '.artifact_paths.admission_budget_plan_json // empty' "$status_json")"
  salvage_json="$(jq -r '.artifact_paths.lease_exchange_salvage_simulation_json // empty' "$status_json")"
  prefetch_json="$(jq -r '.artifact_paths.warm_target_prefetch_roi_advisory_json // empty' "$status_json")"
  require_json "$capacity_forecast_json"
  require_json "$admission_budget_json"
  require_json "$salvage_json"
  require_json "$prefetch_json"

  jq -e '
    .schema_version == "franken-engine.swarm-admission-drill-report.v1"
    and .drill_decision == "pass"
    and .drill_observations.stale_lock_contact_first == true
    and .drill_observations.staged_contamination_rejection == true
    and .drill_observations.protected_priority_budget == true
  ' "$admission_report" >/dev/null
  record_pass "admission drill reused with contact-first and protected budget findings"

  jq -e '
    .schema_version == "franken-engine.swarm-predictive-orchestration-e2e-wrapper.v1"
    and .status == "pass"
    and (.assertions | index("planner_reserved_overlap") != null)
    and (.assertions | index("operator_status_forecast_low_confidence") != null)
    and (.assertions | index("operator_status_prefetch_roi_warning") != null)
  ' "$predictive_report" >/dev/null
  record_pass "predictive orchestration wrapper reused with degraded predictive assertions"

  jq -e '
    .status == "degraded"
    and .predictive_dashboard.telemetry_quality.confidence_band == "low"
    and .predictive_dashboard.capacity_forecast.overall_state == "blocked"
    and .predictive_dashboard.admission_budgets.budget_profile == "brownout"
    and .predictive_dashboard.lease_exchange_salvage.decision == "manual_confirmation_required"
    and .predictive_dashboard.prefetch_roi.advisory == "manual_review_required"
  ' "$status_json" >/dev/null
  record_pass "operator status report linked predictive degradations"

  jq -e '
    .decision == "fail_closed"
    and .confidence_band == "low"
    and .summary.overall_state == "blocked"
  ' "$capacity_forecast_json" >/dev/null

  jq -e '
    .decision == "defer"
    and .budget_profile == "brownout"
    and .summary.deferred_count >= 1
  ' "$admission_budget_json" >/dev/null

  jq -e '
    .decision == "manual_confirmation_required"
    and .summary.manual_review_count >= 1
  ' "$salvage_json" >/dev/null

  jq -e '
    .advisory == "manual_review_required"
    and .archive_pressure_summary.advisory == "compaction_first"
  ' "$prefetch_json" >/dev/null
  record_pass "forecast, budget, salvage, and prefetch advisory stayed fail-closed"

  jq -e '
    .drill_decision == "pass"
    and .scenarios.duplicate_compaction_before_export.pressure_summary.advisory == "compaction_first"
    and .scenarios.salvage_pinned_gc_block.gc_guard_summary.guard_decision == "deny_gc"
    and .scenarios.salvage_pinned_gc_block.pressure_summary.advisory == "fail_closed"
  ' "$archive_report" >/dev/null
  record_pass "archive lifecycle drill preserved compaction-first and salvage-pinned pressure"

  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
  jq -n \
    --arg schema_version "franken-engine.swarm-predictive-admission-no-mock-drill-report.v1" \
    --arg source_revision "$source_revision" \
    --arg admission_report "$admission_report" \
    --arg predictive_report "$predictive_report" \
    --arg operator_status "$status_json" \
    --arg operator_report_md "$status_report_md" \
    --arg capacity_forecast "$capacity_forecast_json" \
    --arg admission_budget "$admission_budget_json" \
    --arg salvage "$salvage_json" \
    --arg prefetch "$prefetch_json" \
    --arg archive_report "$archive_report" \
    --arg commands_path "$commands_path" \
    --arg events_path "$events_path" \
    --arg report_md "$report_md" \
    --arg report_json "$report_json" \
    --slurpfile admission "$admission_report" \
    --slurpfile predictive "$predictive_report" \
    --slurpfile status "$status_json" \
    --slurpfile forecast "$capacity_forecast_json" \
    --slurpfile budget "$admission_budget_json" \
    --slurpfile salvage_file "$salvage_json" \
    --slurpfile prefetch_file "$prefetch_json" \
    --slurpfile archive "$archive_report" '
    {
      schema_version: $schema_version,
      drill_decision: "pass",
      source_revision: $source_revision,
      proof_only: true,
      summary: {
        stale_lock_contact_first: $admission[0].drill_observations.stale_lock_contact_first,
        forecast_decision: $forecast[0].decision,
        forecast_confidence_band: $forecast[0].confidence_band,
        admission_budget_profile: $budget[0].budget_profile,
        lease_exchange_decision: $salvage_file[0].decision,
        prefetch_advisory: $prefetch_file[0].advisory,
        archive_pressure_advisory: $archive[0].scenarios.duplicate_compaction_before_export.pressure_summary.advisory,
        archive_salvage_guard_decision: $archive[0].scenarios.salvage_pinned_gc_block.gc_guard_summary.guard_decision
      },
      assertions: {
        reuse_existing_admission_drill: true,
        reuse_existing_predictive_orchestration_e2e: true,
        reuse_existing_archive_lifecycle_drill: true,
        stale_lock_contact_first: $admission[0].drill_observations.stale_lock_contact_first,
        degraded_rch_fail_closed: ($status[0].predictive_dashboard.rch_incidents.status == "degraded"),
        low_confidence_forecast_fail_closed: ($forecast[0].decision == "fail_closed"),
        manual_confirmation_preserved: ($salvage_file[0].decision == "manual_confirmation_required"),
        archive_pressure_blocks_prefetch_promotion: ($prefetch_file[0].archive_pressure_summary.advisory == "compaction_first")
      },
      reuse_audit: {
        source_surfaces: [
          "scripts/e2e/swarm_admission_drill.sh",
          "scripts/e2e/swarm_predictive_orchestration_e2e.sh",
          "scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh",
          "scripts/swarm_operator_status_report.sh"
        ],
        direct_consumption: {
          admission_drill_report_json: $admission_report,
          predictive_orchestration_report_json: $predictive_report,
          predictive_operator_status_json: $operator_status,
          predictive_operator_report_md: $operator_report_md,
          archive_lifecycle_report_json: $archive_report
        },
        notes: [
          "The composed drill reuses the published admission drill report directly.",
          "The predictive orchestration wrapper is consumed without rewriting its child artifact layout.",
          "Archive pressure evidence comes from the shipped SWARM-CTRL-VI archive lifecycle drill, not a synthetic duplicate."
        ]
      },
      child_artifacts: {
        admission_drill_report_json: $admission_report,
        predictive_orchestration_report_json: $predictive_report,
        operator_status_json: $operator_status,
        operator_report_md: $operator_report_md,
        swarm_capacity_forecast_json: $capacity_forecast,
        swarm_admission_budget_plan_json: $admission_budget,
        lease_exchange_cancellation_salvage_simulation_json: $salvage,
        swarm_warm_target_prefetch_roi_advisory_json: $prefetch,
        remote_proof_archive_lifecycle_no_mock_drill_report_json: $archive_report
      },
      artifact_paths: {
        swarm_predictive_admission_no_mock_drill_report_json: $report_json,
        commands_txt: $commands_path,
        events_jsonl: $events_path,
        report_md: $report_md
      }
    }' >"$report_tmp"
  mv "$report_tmp" "$report_json"

  jq -nc \
    --arg schema_version "franken-engine.swarm-predictive-admission-no-mock-drill.event.v1" \
    --arg event_name "swarm_predictive_admission_no_mock_drill.completed" \
    --arg report_json "$report_json" \
    '{schema_version:$schema_version,event_name:$event_name,report_json:$report_json,decision:"pass"}' \
    >>"$events_path"

  {
    printf '# SWARM-CTRL-VIII Predictive Admission No-Mock Drill\n\n'
    printf '%s\n' "- Decision: \`pass\`"
    printf '%s\n' "- Source revision: \`${source_revision}\`"
    printf '%s\n' "- Forecast confidence: \`$(jq -r '.summary.forecast_confidence_band' "$report_json")\`"
    printf '%s\n' "- Admission budget profile: \`$(jq -r '.summary.admission_budget_profile' "$report_json")\`"
    printf '%s\n' "- Lease exchange decision: \`$(jq -r '.summary.lease_exchange_decision' "$report_json")\`"
    printf '%s\n' "- Prefetch advisory: \`$(jq -r '.summary.prefetch_advisory' "$report_json")\`"
    printf '%s\n\n' "- Archive pressure advisory: \`$(jq -r '.summary.archive_pressure_advisory' "$report_json")\`"
    printf '## Reuse Audit\n'
    jq -r '.reuse_audit.source_surfaces[] | "- `" + . + "`"' "$report_json"
    printf '\n## Linked Artifacts\n'
    jq -r '
      .child_artifacts
      | to_entries[]
      | "- `" + .key + "` -> `" + .value + "`"
    ' "$report_json"
  } >"$report_md"

  record_pass "run artifacts ${run_dir}"
}

replay_mode() {
  local artifact_dir="${replay_dir:-$run_dir}"
  local replay_report="${artifact_dir}/swarm_predictive_admission_no_mock_drill_report.json"
  local admission_report predictive_report status_json status_report_md
  local capacity_forecast_json admission_budget_json salvage_json prefetch_json archive_report

  if [[ ! -f "$replay_report" ]]; then
    printf 'missing replay report: %s\n' "$replay_report" >&2
    exit 64
  fi
  require_json "$replay_report"

  jq -e '
    .schema_version == "franken-engine.swarm-predictive-admission-no-mock-drill-report.v1"
    and .drill_decision == "pass"
    and .proof_only == true
    and ([.assertions[]] | all)
    and (.reuse_audit.source_surfaces | length >= 4)
  ' "$replay_report" >/dev/null

  admission_report="$(jq -r '.child_artifacts.admission_drill_report_json' "$replay_report")"
  predictive_report="$(jq -r '.child_artifacts.predictive_orchestration_report_json' "$replay_report")"
  status_json="$(jq -r '.child_artifacts.operator_status_json' "$replay_report")"
  status_report_md="$(jq -r '.child_artifacts.operator_report_md' "$replay_report")"
  capacity_forecast_json="$(jq -r '.child_artifacts.swarm_capacity_forecast_json' "$replay_report")"
  admission_budget_json="$(jq -r '.child_artifacts.swarm_admission_budget_plan_json' "$replay_report")"
  salvage_json="$(jq -r '.child_artifacts.lease_exchange_cancellation_salvage_simulation_json' "$replay_report")"
  prefetch_json="$(jq -r '.child_artifacts.swarm_warm_target_prefetch_roi_advisory_json' "$replay_report")"
  archive_report="$(jq -r '.child_artifacts.remote_proof_archive_lifecycle_no_mock_drill_report_json' "$replay_report")"

  require_json "$admission_report"
  require_json "$predictive_report"
  require_json "$status_json"
  require_json "$capacity_forecast_json"
  require_json "$admission_budget_json"
  require_json "$salvage_json"
  require_json "$prefetch_json"
  require_json "$archive_report"
  test -f "$status_report_md"
  test -f "$(jq -r '.artifact_paths.report_md' "$replay_report")"
  test -f "$(jq -r '.artifact_paths.commands_txt' "$replay_report")"
  test -f "$(jq -r '.artifact_paths.events_jsonl' "$replay_report")"

  record_pass "replay bundle ${artifact_dir}"
}

run_selftest() {
  run_check
  run_mode
  replay_dir="$run_dir"
  replay_mode
  record_pass "selftest"
  printf 'swarm_predictive_admission_no_mock_drill_artifacts=%s\n' "$run_dir"
  printf 'swarm_predictive_admission_no_mock_drill_report=%s\n' "$report_json"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    run_mode
    ;;
  selftest)
    run_selftest
    ;;
  replay)
    replay_mode
    ;;
  *)
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
