#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
receipt_script="${root_dir}/scripts/remote_proof_salvage_receipt.sh"

record_pass() {
  printf 'PASS remote-proof-salvage-receipt %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-salvage-receipt %s\n' "$1" >&2
}

write_json() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

assert_receipt() {
  local case_dir="$1"
  local expected_state="$2"
  local expected_recommendation="$3"
  local expected_exit="$4"
  local expected_recoverable="$5"

  jq -e \
    --arg expected_state "$expected_state" \
    --arg expected_recommendation "$expected_recommendation" \
    --argjson expected_exit "$expected_exit" \
    --argjson expected_recoverable "$expected_recoverable" '
      .schema_version == "franken-engine.remote-proof-salvage-receipt.v1"
      and (.salvage_id | length > 0)
      and .workflow_state == $expected_state
      and .recovery_recommendation == $expected_recommendation
      and .exit_code == $expected_exit
      and .observed_process_truth.recoverable_artifact_set == $expected_recoverable
      and (.artifact_paths.salvage_receipt_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
      and (.operator_actions | length > 0)
    ' "${case_dir}/salvage_receipt.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local expected_state="$3"
  local expected_recommendation="$4"
  local expected_exit="$5"
  local expected_recoverable="$6"
  local bundle_json="$7"
  local incident_json="$8"
  local worker_truth_json="$9"
  local case_dir="${tmp_root}/${case_name}"
  local bundle_path="${case_dir}.bundle.json"
  local incident_path="${case_dir}.incident.json"
  local worker_path="${case_dir}.worker.json"
  local actual_exit output

  write_json "$bundle_path" "$bundle_json"
  write_json "$incident_path" "$incident_json"
  write_json "$worker_path" "$worker_truth_json"

  set +e
  output="$(
    "$receipt_script" \
      --output-dir "$case_dir" \
      --bundle-report-json "$bundle_path" \
      --incident-packet-json "$incident_path" \
      --worker-truth-report-json "$worker_path" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  assert_receipt "$case_dir" "$expected_state" "$expected_recommendation" "$expected_exit" "$expected_recoverable"
  record_pass "${case_name} => ${expected_recommendation}"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${REMOTE_PROOF_SALVAGE_RECEIPT_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-salvage-receipt.XXXXXX")"

  run_case \
    "$tmp_root" \
    "timeout-live-compile-salvage" \
    "live_compile_salvageable" \
    "wait_then_salvage_artifacts" \
    42 \
    true \
    '{"schema_version":"franken-engine.resident-remote-proof-bundle.v1","bundle_id":"bundle-timeout","bundle_decision":"fail_closed","expected_worker_id":"vmi1156319","expected_target_dir":"/tmp/rch_target_franken_engine_bundle_timeout","source_revision":"smoke-rev","phase_results":[{"phase":"check","stdout_log":"/artifacts/check.stdout.log","stderr_log":"/artifacts/check.stderr.log"}],"artifact_paths":{"bundle_report_json":"/artifacts/bundle_report.json","run_manifest_json":"/artifacts/run_manifest.json","phase_logs_dir":"/artifacts/phase_logs"}}' \
    '{"schema_version":"franken-engine.rch-incident-packet.v1","status":"fail","failure_kind":"timed_out_transport_live_remote_compile","retry_safety":"safe_to_salvage_or_wait_before_rerun","recommended_next_action":"preserve evidence","worker_id":"vmi1156319","target_dir":"/tmp/rch_target_franken_engine_bundle_timeout","exit_code":124}' \
    '{"schema_version":"franken-engine.rch-worker-truth-parity-report.v1","decision":"fail_closed","drift_count":1,"ghost_job_detected":true,"findings":[{"code":"ghost_job_live_remote_compile","worker_id":"vmi1156319"}],"worker_rows":[{"worker_id":"vmi1156319","daemon_present":true,"daemon_drained":false,"probe_present":true,"probe_schedulable":true,"queue_present":true,"queue_schedulable":true}],"incident_evidence":{"failure_kind":"timed_out_transport_live_remote_compile"}}'

  run_case \
    "$tmp_root" \
    "canceled-orphaned-rustc" \
    "orphan_reconciliation_required" \
    "clear_orphan_before_retry" \
    42 \
    true \
    '{"schema_version":"franken-engine.resident-remote-proof-bundle.v1","bundle_id":"bundle-orphan","bundle_decision":"fail_closed","expected_worker_id":"ts2","expected_target_dir":"/tmp/rch_target_franken_engine_bundle_orphan","source_revision":"smoke-rev","phase_results":[{"phase":"test","stdout_log":"/artifacts/test.stdout.log","stderr_log":"/artifacts/test.stderr.log"}],"artifact_paths":{"bundle_report_json":"/artifacts/bundle_report.json","run_manifest_json":"/artifacts/run_manifest.json","phase_logs_dir":"/artifacts/phase_logs"}}' \
    '{"schema_version":"franken-engine.rch-incident-packet.v1","status":"fail","failure_kind":"canceled_build_live_orphaned_rustc","retry_safety":"unsafe_until_orphaned_processes_are_cleared","recommended_next_action":"clear orphan","worker_id":"ts2","target_dir":"/tmp/rch_target_franken_engine_bundle_orphan","exit_code":130}' \
    '{"schema_version":"franken-engine.rch-worker-truth-parity-report.v1","decision":"fail_closed","drift_count":1,"ghost_job_detected":true,"findings":[{"code":"ghost_job_live_remote_compile","worker_id":"ts2"}],"worker_rows":[{"worker_id":"ts2","daemon_present":true,"daemon_drained":false,"probe_present":true,"probe_schedulable":true,"queue_present":true,"queue_schedulable":true}],"incident_evidence":{"failure_kind":"canceled_build_live_orphaned_rustc"}}'

  run_case \
    "$tmp_root" \
    "clean-finished" \
    "clean_finished" \
    "no_salvage_needed" \
    0 \
    true \
    '{"schema_version":"franken-engine.resident-remote-proof-bundle.v1","bundle_id":"bundle-clean","bundle_decision":"pass","expected_worker_id":"vmi1293453","expected_target_dir":"/tmp/rch_target_franken_engine_bundle_clean","source_revision":"smoke-rev","phase_results":[{"phase":"check","stdout_log":"/artifacts/check.stdout.log","stderr_log":"/artifacts/check.stderr.log"},{"phase":"test","stdout_log":"/artifacts/test.stdout.log","stderr_log":"/artifacts/test.stderr.log"}],"artifact_paths":{"bundle_report_json":"/artifacts/bundle_report.json","run_manifest_json":"/artifacts/run_manifest.json","phase_logs_dir":"/artifacts/phase_logs"}}' \
    '{"schema_version":"franken-engine.rch-incident-packet.v1","status":"pass","failure_kind":"clean_remote_success","retry_safety":"no_retry_needed","recommended_next_action":"record success","worker_id":"vmi1293453","target_dir":"/tmp/rch_target_franken_engine_bundle_clean","exit_code":0}' \
    '{"schema_version":"franken-engine.rch-worker-truth-parity-report.v1","decision":"pass","drift_count":0,"ghost_job_detected":false,"findings":[],"worker_rows":[{"worker_id":"vmi1293453","daemon_present":true,"daemon_drained":false,"probe_present":true,"probe_schedulable":true,"queue_present":true,"queue_schedulable":true}],"incident_evidence":{"failure_kind":"clean_remote_success"}}'

  run_case \
    "$tmp_root" \
    "worker-unreachable-degraded" \
    "worker_unreachable_degraded" \
    "quarantine_worker_and_reroute" \
    42 \
    true \
    '{"schema_version":"franken-engine.resident-remote-proof-bundle.v1","bundle_id":"bundle-unreachable","bundle_decision":"fail_closed","expected_worker_id":"vmi1264463","expected_target_dir":"/tmp/rch_target_franken_engine_bundle_unreachable","source_revision":"smoke-rev","phase_results":[{"phase":"clippy","stdout_log":"/artifacts/clippy.stdout.log","stderr_log":"/artifacts/clippy.stderr.log"}],"artifact_paths":{"bundle_report_json":"/artifacts/bundle_report.json","run_manifest_json":"/artifacts/run_manifest.json","phase_logs_dir":"/artifacts/phase_logs"}}' \
    '{"schema_version":"franken-engine.rch-incident-packet.v1","status":"fail","failure_kind":"worker_unreachable_degraded","retry_safety":"safe_after_worker_recovery_or_reroute","recommended_next_action":"reroute worker","worker_id":"vmi1264463","target_dir":"/tmp/rch_target_franken_engine_bundle_unreachable","exit_code":255}' \
    '{"schema_version":"franken-engine.rch-worker-truth-parity-report.v1","decision":"fail_closed","drift_count":1,"ghost_job_detected":false,"findings":[{"code":"healthy_daemon_absent_or_unschedulable_in_probe","worker_id":"vmi1264463"}],"worker_rows":[{"worker_id":"vmi1264463","daemon_present":true,"daemon_drained":false,"probe_present":false,"probe_schedulable":false,"queue_present":false,"queue_schedulable":false}],"incident_evidence":{"failure_kind":"worker_unreachable_degraded"}}'

  printf 'remote_proof_salvage_receipt_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$receipt_script"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$receipt_script" "${BASH_SOURCE[0]}"
  jq empty "${root_dir}/docs/remote_proof_salvage_receipt_contract_v1.json" >/dev/null
  record_pass "shell syntax, shellcheck, and contract JSON"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
