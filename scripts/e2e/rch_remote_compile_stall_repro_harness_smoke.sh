#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
harness="${root_dir}/scripts/e2e/rch_remote_compile_stall_repro_harness.sh"
fixture_root="${root_dir}/scripts/testdata/rch_remote_compile_stall_repro"

record_pass() {
  printf 'PASS rch-remote-compile-stall-repro %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-remote-compile-stall-repro %s\n' "$1" >&2
}

assert_report() {
  local output_dir="$1"
  local expected_path="$2"

  jq -e --slurpfile expected "$expected_path" '
    ($expected[0]) as $expected_doc
    | .schema_version == "franken-engine.rch-remote-compile-stall-repro-report.v1"
    and .final_verdict == $expected_doc.final_verdict
    and .reason_code == $expected_doc.reason_code
    and .source_evidence == $expected_doc.source_evidence
    and .harness_exit_code == $expected_doc.expected_exit_code
    and .selected_worker == $expected_doc.selected_worker
    and .stall_observation.capture_decision == $expected_doc.capture_decision
    and .stall_observation.truth_state == $expected_doc.truth_state
    and (.artifact_paths.repro_report_json | length > 0)
    and (.artifact_paths.stall_bundle_json | length > 0)
    and (.artifact_paths.harness_log_txt | length > 0)
    and (.artifact_paths.events_jsonl | length > 0)
    and (.artifact_paths.commands_txt | length > 0)
    and (.artifact_paths.summary_md | length > 0)
  ' "${output_dir}/repro_report.json" >/dev/null

  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/summary.md"
  test -s "${output_dir}/remote_command.log"
  test -s "${output_dir}/stall_bundle/stall_bundle.json"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local case_dir="${fixture_root}/${case_name}"
  local output_dir="${tmp_root}/${case_name}"
  local expected_path="${case_dir}/expected.json"
  local bead_id case_id actual_exit
  local -a cmd

  bead_id="$(jq -r '.[0].id' "${case_dir}/bead_metadata.json")"
  case_id="$(jq -r '.case_id' "$expected_path")"

  cmd=(
    "$harness"
    --output-dir "$output_dir"
    --case-id "$case_id"
    --bead-id "$bead_id"
    --bead-metadata-json "${case_dir}/bead_metadata.json"
    --queue-json "${case_dir}/queue.json"
    --status-json "${case_dir}/status.json"
    --command-log "${case_dir}/command_excerpt.txt"
  )
  [[ -f "${case_dir}/worker_inventory.json" ]] && cmd+=(--worker-inventory-json "${case_dir}/worker_inventory.json")
  [[ -f "${case_dir}/operator_note.md" ]] && cmd+=(--operator-note "${case_dir}/operator_note.md")

  set +e
  "${cmd[@]}" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$(jq -r '.expected_exit_code' "$expected_path")" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected $(jq -r '.expected_exit_code' "$expected_path")"
    return 1
  fi

  assert_report "$output_dir" "$expected_path" || {
    record_failure "${case_name} report assertion failed"
    return 1
  }

  record_pass "$case_name"
}

run_numeric_timestamp_case() {
  local tmp_root="$1"
  local source_case="fresh_heartbeat_frozen_progress_test"
  local source_dir="${fixture_root}/${source_case}"
  local case_dir="${tmp_root}/numeric-top-level-timestamps"
  local output_dir="${tmp_root}/numeric-top-level-timestamps-output"
  local expected_path="${source_dir}/expected.json"
  local bead_id case_id actual_exit
  local -a cmd

  mkdir -p "$case_dir"
  cp "${source_dir}/bead_metadata.json" "$case_dir/bead_metadata.json"
  cp "${source_dir}/command_excerpt.txt" "$case_dir/command_excerpt.txt"
  cp "${source_dir}/worker_inventory.json" "$case_dir/worker_inventory.json"

  jq '
    .timestamp |= (
      if type == "string" then fromdateiso8601
      else .
      end
    )
  ' "${source_dir}/queue.json" >"$case_dir/queue.json"

  jq '
    .timestamp |= (
      if type == "string" then fromdateiso8601
      else .
      end
    )
  ' "${source_dir}/status.json" >"$case_dir/status.json"

  bead_id="$(jq -r '.[0].id' "$case_dir/bead_metadata.json")"
  case_id="$(jq -r '.case_id' "$expected_path")"

  cmd=(
    "$harness"
    --output-dir "$output_dir"
    --case-id "$case_id"
    --bead-id "$bead_id"
    --bead-metadata-json "$case_dir/bead_metadata.json"
    --queue-json "$case_dir/queue.json"
    --status-json "$case_dir/status.json"
    --command-log "$case_dir/command_excerpt.txt"
    --worker-inventory-json "$case_dir/worker_inventory.json"
  )

  set +e
  "${cmd[@]}" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$(jq -r '.expected_exit_code' "$expected_path")" ]]; then
    record_failure "numeric_top_level_timestamps exit ${actual_exit}, expected $(jq -r '.expected_exit_code' "$expected_path")"
    return 1
  fi

  assert_report "$output_dir" "$expected_path" || {
    record_failure "numeric_top_level_timestamps report assertion failed"
    return 1
  }

  record_pass "numeric_top_level_timestamps"
}

run_check() {
  bash -n "$harness"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$harness" "${BASH_SOURCE[0]}"
  find "$fixture_root" -type f -name '*.json' -print0 | xargs -0 -n1 jq empty >/dev/null
  record_pass "shell syntax, shellcheck, and fixture JSON"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/rch-remote-compile-stall-repro.XXXXXX")"

  run_case "$tmp_root" source_failure_check_lib
  run_case "$tmp_root" transport_timeout_check_lib
  run_case "$tmp_root" fresh_heartbeat_frozen_progress_test
  run_numeric_timestamp_case "$tmp_root"
  run_case "$tmp_root" contaminated_local_fallback_check_lib

  printf 'rch_remote_compile_stall_repro_smoke_artifacts=%s\n' "$tmp_root"
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
