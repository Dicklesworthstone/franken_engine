#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger="${root_dir}/scripts/rch_worker_truth_parity_ledger.sh"

record_pass() {
  printf 'PASS rch-worker-truth-parity %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-worker-truth-parity %s\n' "$1" >&2
}

write_json() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

assert_report() {
  local case_dir="$1"
  local expected_decision="$2"
  local required_code="${3:-}"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg required_code "$required_code" '
      .schema_version == "franken-engine.rch-worker-truth-parity-report.v1"
      and .decision == $expected_decision
      and (.artifact_paths.worker_truth_report_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
      and (
        if $required_code == "" then true
        else any(.findings[]?; .code == $required_code)
        end
      )
    ' "${case_dir}/worker_truth_report.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local expected_decision="$3"
  local expected_exit="$4"
  local required_code="$5"
  local daemon_json="$6"
  local probe_json="$7"
  local queue_json="$8"
  local incident_json="$9"
  local case_dir="${tmp_root}/${case_name}"
  local daemon_path="${case_dir}.daemon.json"
  local probe_path="${case_dir}.probe.json"
  local queue_path="${case_dir}.queue.json"
  local incident_path="${case_dir}.incident.json"
  local actual_exit output
  local -a cmd

  write_json "$daemon_path" "$daemon_json"
  write_json "$probe_path" "$probe_json"
  write_json "$queue_path" "$queue_json"
  write_json "$incident_path" "$incident_json"

  cmd=(
    "$ledger"
    --output-dir "$case_dir"
    --daemon-workers-json "$daemon_path"
    --probe-workers-json "$probe_path"
    --queue-diagnostics-json "$queue_path"
    --incident-packet-json "$incident_path"
  )

  set +e
  output="$("${cmd[@]}" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  assert_report "$case_dir" "$expected_decision" "$required_code"
  record_pass "${case_name} => ${expected_decision}"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${RCH_WORKER_TRUTH_PARITY_LEDGER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/rch-worker-truth-parity.XXXXXX")"

  run_case \
    "$tmp_root" \
    "healthy-parity" \
    "pass" \
    0 \
    "" \
    '{"workers":[{"worker_id":"vmi1293453","status":"idle","cpu_slots_available":4}]}' \
    '{"workers":[{"worker_id":"vmi1293453","status":"idle","projects_root_ok":true,"nightly_available":true}]}' \
    '{"decision":"admit","reason":"worker is available","workers":[{"worker_id":"vmi1293453","schedulable":true,"selection_reason":"idle worker"}],"drained_workers":[]}' \
    '{"status":"pass","failure_kind":"clean_remote_success","remote_worker_id":"vmi1293453","live_remote_compile":false}'

  run_case \
    "$tmp_root" \
    "snapshot-parity-drift" \
    "fail_closed" \
    42 \
    "healthy_probe_absent_or_unschedulable_in_daemon" \
    '{"workers":[]}' \
    '{"workers":[{"worker_id":"vmi1156319","status":"idle","projects_root_ok":true,"nightly_available":true}]}' \
    '{"decision":"defer","reason":"all_workers_busy","workers":[],"drained_workers":[]}' \
    '{"status":"missing","failure_kind":"missing","remote_worker_id":"","live_remote_compile":false}'

  run_case \
    "$tmp_root" \
    "drained-worker-disappearance" \
    "fail_closed" \
    42 \
    "drained_worker_missing_from_daemon" \
    '{"workers":[{"worker_id":"vmi1293453","status":"idle","cpu_slots_available":2}]}' \
    '{"workers":[{"worker_id":"vmi1293453","status":"idle","projects_root_ok":true,"nightly_available":true}]}' \
    '{"decision":"defer","reason":"drain in progress","workers":[{"worker_id":"vmi1293453","schedulable":true,"selection_reason":"safe fallback"}],"drained_workers":["vmi1149989"]}' \
    '{"status":"missing","failure_kind":"missing","remote_worker_id":"","live_remote_compile":false}'

  run_case \
    "$tmp_root" \
    "ghost-job" \
    "fail_closed" \
    42 \
    "ghost_job_live_remote_compile" \
    '{"workers":[{"worker_id":"ts2","status":"idle","cpu_slots_available":6}]}' \
    '{"workers":[{"worker_id":"ts2","status":"idle","projects_root_ok":true,"nightly_available":true}]}' \
    '{"decision":"admit","reason":"worker is available","workers":[{"worker_id":"ts2","schedulable":true,"selection_reason":"warm worker"}],"drained_workers":[]}' \
    '{"status":"fail","failure_kind":"canceled_build_live_orphaned_rustc","remote_worker_id":"ts2","live_remote_compile":true}'

  printf 'rch_worker_truth_parity_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$ledger"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$ledger" "${BASH_SOURCE[0]}"
  record_pass "shell syntax and shellcheck"
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
