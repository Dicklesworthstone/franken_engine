#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/rch_incident_packet_gate.sh"

record_pass() {
  printf 'PASS rch-incident-packet %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-incident-packet %s\n' "$1" >&2
}

write_fixture() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

assert_packet() {
  local case_dir="$1"
  local expected_kind="$2"
  local expected_status="$3"

  jq -e \
    --arg expected_kind "$expected_kind" \
    --arg expected_status "$expected_status" \
    '.schema_version == "franken-engine.rch-incident-packet.v1"
      and .failure_kind == $expected_kind
      and .status == $expected_status
      and (.artifact_paths.incident_packet_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
      and (.recommended_next_action | length > 0)
      and (.retry_safety | length > 0)' \
    "${case_dir}/incident_packet.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local expected_kind="$3"
  local expected_status="$4"
  local expected_exit="$5"
  local stdout_text="$6"
  local stderr_text="$7"
  local exit_code="$8"
  local completion_marker="$9"
  local case_dir="${tmp_root}/${case_name}"
  local stdout_path="${case_dir}.stdout"
  local stderr_path="${case_dir}.stderr"
  local command_text="rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_wlux9 cargo test -p frankenengine-engine --test rch_incident_packet_gate_smoke"
  local actual_exit output

  write_fixture "$stdout_path" "$stdout_text"
  write_fixture "$stderr_path" "$stderr_text"

  set +e
  output="$(
    "$gate" \
      --output-dir "$case_dir" \
      --command "$command_text" \
      --target-dir /tmp/rch_target_franken_engine_bd_wlux9 \
      --source-revision smoke-rev \
      --stdout-file "$stdout_path" \
      --stderr-file "$stderr_path" \
      --exit-code "$exit_code" \
      --completion-marker "$completion_marker" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  assert_packet "$case_dir" "$expected_kind" "$expected_status"
  record_pass "${case_name} classified as ${expected_kind}"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${RCH_INCIDENT_PACKET_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/rch-incident-packet.XXXXXX")"

  run_case \
    "$tmp_root" \
    "fallback-marker" \
    "local_fallback" \
    "fail" \
    42 \
    "[RCH] local (Dependency preflight blocked remote execution)" \
    "refusing unsafe local cargo execution" \
    0 \
    "missing"

  run_case \
    "$tmp_root" \
    "timed-out-transport-live-remote-compile" \
    "timed_out_transport_live_remote_compile" \
    "fail" \
    42 \
    "[RCH] remote vmi1264463 started; fresh heartbeats with stale progress; hot rustc compiling frankenengine_engine" \
    "[RCH-E104] SSH command timed out after 1800s" \
    124 \
    "missing"

  run_case \
    "$tmp_root" \
    "canceled-build-live-orphaned-rustc" \
    "canceled_build_live_orphaned_rustc" \
    "fail" \
    42 \
    "[RCH] remote worker=ts2; cancel requested; live orphaned rustc still alive after cancel" \
    "build canceled cleanly; exit_code 130" \
    130 \
    "missing"

  run_case \
    "$tmp_root" \
    "worker-unreachable-degraded" \
    "worker_unreachable_degraded" \
    "fail" \
    42 \
    "" \
    "ssh: connect to host vmi1293453 port 22: No route to host" \
    255 \
    "unknown"

  run_case \
    "$tmp_root" \
    "worker-timeout" \
    "worker_timeout" \
    "fail" \
    42 \
    "[RCH] remote vmi1264463 started" \
    "stuck detector auto-cancelled job; exit_code 130 after timeout" \
    130 \
    "missing"

  run_case \
    "$tmp_root" \
    "remote-sigkill" \
    "remote_sigkill" \
    "fail" \
    42 \
    "[RCH] remote worker=ts2" \
    "process terminated by SIGKILL; exit status 137" \
    137 \
    "missing"

  run_case \
    "$tmp_root" \
    "artifact-retrieval" \
    "artifact_retrieval_failure" \
    "fail" \
    42 \
    "[RCH] remote vmi1293453 completed build" \
    "artifact retrieval failed: rsync code 23" \
    23 \
    "missing"

  run_case \
    "$tmp_root" \
    "missing-completion-marker" \
    "missing_completion_marker" \
    "fail" \
    42 \
    "[RCH] remote vmi1293453 finished stdout tail" \
    "wrapper ended without completion marker" \
    0 \
    "missing"

  run_case \
    "$tmp_root" \
    "clean-remote-success" \
    "clean_remote_success" \
    "pass" \
    0 \
    "[RCH] remote vmi1293453 completed cleanly" \
    "remote proof completed" \
    0 \
    "present"

  run_case \
    "$tmp_root" \
    "unknown-failure" \
    "unknown_failure_text" \
    "fail" \
    42 \
    "[RCH] remote vmi1293453 emitted unusual diagnostics" \
    "opaque transport state without known classifier" \
    9 \
    "unknown"

  printf 'rch_incident_packet_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  local scope_file

  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  record_pass "bash syntax"

  scope_file="${RCH_INCIDENT_PACKET_SMOKE_SCOPE_FILE:-/tmp/franken-engine-rch-incident-packet-scope.txt}"
  printf '%s\n' \
    "scripts/rch_incident_packet_gate.sh" \
    "scripts/e2e/rch_incident_packet_gate_smoke.sh" \
    "docs/swarm_validation_control_plane_contract_v1.json" \
    >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${RCH_INCIDENT_PACKET_SMOKE_POLICY_DIR:-/tmp/franken-engine-rch-incident-packet-policy}" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
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
