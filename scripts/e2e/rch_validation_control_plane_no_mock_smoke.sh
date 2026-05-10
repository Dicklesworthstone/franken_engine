#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixtures_path="${root_dir}/scripts/testdata/rch_validation_control_plane_no_mock/fixtures.json"
telemetry_rs="${root_dir}/crates/franken-engine/src/rch_validation_telemetry.rs"
preflight_smoke="${root_dir}/scripts/e2e/swarm_proof_command_preflight_smoke.sh"
admission_smoke="${root_dir}/scripts/e2e/swarm_validation_admission_recommender_smoke.sh"
ledger_smoke="${root_dir}/scripts/e2e/rch_validation_evidence_ledger_smoke.sh"
admission_script="${root_dir}/scripts/swarm_validation_admission_recommender.sh"
ledger_verifier="${root_dir}/scripts/verify_rch_validation_evidence_ledger.sh"
sample_ledger="${root_dir}/docs/rch_validation_evidence_ledger_sample_v1.json"
mode="${1:-check}"
output_root="${2:-${RCH_VALIDATION_CONTROL_PLANE_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-rch-validation-control-plane-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS rch-validation-control-plane %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-validation-control-plane %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_validation_control_plane_no_mock_smoke.sh [check|selftest] [output_root]
EOF
}

write_event() {
  local path="$1"
  local event="$2"
  local outcome="$3"
  local detail="$4"
  jq -nc \
    --arg schema_version "franken-engine.rch-validation-control-plane-no-mock.event.v1" \
    --arg component "rch_validation_control_plane_no_mock_smoke" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    '{schema_version: $schema_version, component: $component, event: $event, outcome: $outcome, detail: $detail}' >>"$path"
}

check_static_contracts() {
  jq empty "$fixtures_path" "$sample_ledger" >/dev/null
  bash -n "${BASH_SOURCE[0]}"
  jq -e '
    .schema_version == "franken-engine.rch-validation-control-plane-no-mock-fixtures.v1"
    and (.transcript_fixtures | length) == 3
    and all(.transcript_fixtures[]; (.bead_id // "") != "" and (.command // "") != "" and (.expected_result.status // "") != "")
    and any(.transcript_fixtures[]; .expected_result.status == "infrastructure_timeout" and .expected_result.compiler_diagnostic_surfaced == false)
    and any(.transcript_fixtures[]; .expected_result.status == "compiler_diagnostic" and .expected_result.compiler_diagnostic_surfaced == true)
    and any(.transcript_fixtures[]; .expected_result.status == "worker_disk_full")
  ' "$fixtures_path" >/dev/null
  rg -q 'rch_e104_timeout_without_diagnostic_gets_retryable_action' "$telemetry_rs"
  rg -q 'compiler_diagnostic_takes_precedence_over_infrastructure_text' "$telemetry_rs"
  rg -q 'worker_disk_full_quarantines_worker' "$telemetry_rs"
}

run_check() {
  check_static_contracts || record_failure "static contracts"
  "$preflight_smoke" check >/dev/null || record_failure "preflight smoke"
  "$admission_smoke" check >/dev/null || record_failure "admission smoke"
  "$ledger_smoke" check >/dev/null || record_failure "ledger smoke"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local run_dir="$1"
  local events_path="${run_dir}/events.jsonl"
  local commands_path="${run_dir}/commands.txt"
  local report_path="${run_dir}/report.md"
  local ps_path="${run_dir}/ps.txt"
  local br_path="${run_dir}/br.json"
  local dirty_path="${run_dir}/dirty.json"
  local admission_dir="${run_dir}/admission"
  local generated_ledger="${run_dir}/control_plane_ledger.json"
  local smoke_report="${run_dir}/control_plane_smoke_report.json"
  local admission_exit admission_recommendation admission_reason

  mkdir -p "$run_dir"
  : >"$events_path"
  printf './scripts/e2e/rch_validation_control_plane_no_mock_smoke.sh selftest %q\n' "$run_dir" >"$commands_path"
  write_event "$events_path" "selftest.started" "ok" "$run_dir"

  jq -r '.active_process_snapshot' "$fixtures_path" >"$ps_path"
  jq -n '{issues: [{id: "bd-zy517", status: "in_progress", assignee: "RainyBadger"}]}' >"$br_path"
  jq -n '{files: []}' >"$dirty_path"

  set +e
  "$admission_script" \
    --bead-id bd-zy517 \
    --agent-id RainyBadger \
    --command-class package_all_targets \
    --ps-snapshot "$ps_path" \
    --br-snapshot-json "$br_path" \
    --dirty-files-json "$dirty_path" \
    --output-dir "$admission_dir" >/dev/null 2>&1
  admission_exit=$?
  set -e

  admission_recommendation="$(jq -r '.recommendation' "${admission_dir}/recommendation.json")"
  admission_reason="$(jq -r '.reason_code' "${admission_dir}/recommendation.json")"
  if [[ "$admission_exit" -ne 75 || "$admission_recommendation" != "wait_existing_all_targets" ]]; then
    record_failure "admission selected ${admission_recommendation}/${admission_reason} exit ${admission_exit}"
  fi

  jq --slurpfile fixtures "$fixtures_path" '
    .ledger_id = "rch-validation-control-plane-no-mock-smoke"
    | .entries += [
        $fixtures[0].transcript_fixtures[]
        | {
            entry_id: ("fixture-" + .fixture_id),
            bead_id,
            commit: "fixture",
            evidence_kind: (if .expected_result.status == "compiler_diagnostic" then "broad_gate_attempt" else "focused_rch_proof" end),
            command_class,
            command,
            result: {
              status: .expected_result.status,
              exit_code: null,
              compile_stage_reached: .expected_result.compile_stage_reached,
              compiler_diagnostic_surfaced: .expected_result.compiler_diagnostic_surfaced,
              rch_error_code: .expected_result.rch_error_code,
              reason_code: .fixture_id,
              recommended_next_action: "record_in_ledger"
            }
          }
      ]
  ' "$sample_ledger" >"$generated_ledger"

  "$ledger_verifier" "$generated_ledger" >/dev/null || record_failure "generated ledger verification"

  jq -n \
    --arg schema_version "franken-engine.rch-validation-control-plane-no-mock-smoke.v1" \
    --arg input_snapshot "$ps_path" \
    --arg selected_validation_action "$admission_recommendation" \
    --arg reason_code "$admission_reason" \
    --arg admission_artifact "${admission_dir}/recommendation.json" \
    --arg ledger_artifact "$generated_ledger" \
    --arg events_path "$events_path" \
    '{
      schema_version: $schema_version,
      input_snapshot: $input_snapshot,
      selected_validation_action: $selected_validation_action,
      reason_code: $reason_code,
      artifact_paths: {
        admission_recommendation_json: $admission_artifact,
        generated_ledger_json: $ledger_artifact,
        events_jsonl: $events_path
      }
    }' >"$smoke_report"

  write_event "$events_path" "selftest.completed" "$admission_recommendation" "$admission_reason"
  {
    printf '# RCH Validation Control Plane No-Mock Smoke\n\n'
    printf -- "- input_snapshot: \`%s\`\n" "$ps_path"
    printf -- "- selected_validation_action: \`%s\`\n" "$admission_recommendation"
    printf -- "- reason_code: \`%s\`\n" "$admission_reason"
    printf -- "- admission_artifact: \`%s\`\n" "${admission_dir}/recommendation.json"
    printf -- "- generated_ledger: \`%s\`\n" "$generated_ledger"
  } >"$report_path"

  test -s "$events_path"
  test -s "$commands_path"
  test -s "$report_path"
  test -s "$smoke_report"

  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest "$output_root"
    fi
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
