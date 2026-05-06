#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
capture_script="${root_dir}/scripts/rch_remote_compile_stall_bundle_capture.sh"
fixture_root="${root_dir}/scripts/testdata/rch_remote_compile_stall_bundle"

record_pass() {
  printf 'PASS rch-remote-compile-stall-bundle-capture %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-remote-compile-stall-bundle-capture %s\n' "$1" >&2
}

fixture_arg_if_exists() {
  local flag="$1"
  local path="$2"
  if [[ -f "$path" ]]; then
    printf '%s\n%s\n' "$flag" "$path"
  fi
}

assert_bundle() {
  local case_dir="$1"
  local expected_path="$2"
  local output_dir="$3"

  jq -e --slurpfile expected "$expected_path" '
    ($expected[0]) as $expected_doc
    | .schema_version == "franken-engine.rch-remote-compile-stall-bundle.v1"
    and .truth_state == $expected_doc.truth_state
    and .capture_decision == $expected_doc.capture_decision
    and .local_fallback_observed == $expected_doc.local_fallback_observed
    and .snapshot_health.required_present_count == $expected_doc.required_present_count
    and .snapshot_health.optional_present_count == $expected_doc.optional_present_count
    and .snapshot_health.optional_missing_count == $expected_doc.optional_missing_count
    and .snapshot_health.contradictory_snapshot_count == $expected_doc.contradictory_snapshot_count
    and .stall_subject.build_id == $expected_doc.primary_build_id
    and .stall_subject.worker_id == $expected_doc.primary_worker_id
    and (.artifact_paths.stall_bundle_json | length > 0)
    and (.artifact_paths.events_jsonl | length > 0)
    and (.artifact_paths.commands_txt | length > 0)
    and (.artifact_paths.summary_md | length > 0)
    and (
      if (($expected_doc.required_blocker_code // "") | length) == 0 then true
      else any(.blockers[]?; .code == $expected_doc.required_blocker_code)
      end
    )
  ' "${output_dir}/stall_bundle.json" >/dev/null || return 1

  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/summary.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local case_dir="${fixture_root}/${case_name}"
  local output_dir="${tmp_root}/${case_name}"
  local expected_path="${case_dir}/expected.json"
  local bead_id actual_exit
  local -a cmd optional_args

  bead_id="$(jq -r '.[0].id' "${case_dir}/bead_metadata.json")"

  optional_args=()
  while IFS= read -r arg; do
    [[ -n "$arg" ]] && optional_args+=("$arg")
  done < <(fixture_arg_if_exists --command-log "${case_dir}/command_excerpt.txt")
  while IFS= read -r arg; do
    [[ -n "$arg" ]] && optional_args+=("$arg")
  done < <(fixture_arg_if_exists --worker-inventory-json "${case_dir}/worker_inventory.json")
  while IFS= read -r arg; do
    [[ -n "$arg" ]] && optional_args+=("$arg")
  done < <(fixture_arg_if_exists --operator-note "${case_dir}/operator_note.md")

  cmd=(
    "$capture_script"
    --output-dir "$output_dir"
    --bead-id "$bead_id"
    --bead-metadata-json "${case_dir}/bead_metadata.json"
    --queue-json "${case_dir}/queue.json"
    --status-json "${case_dir}/status.json"
    "${optional_args[@]}"
  )

  set +e
  "${cmd[@]}" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$(jq -r '.expected_exit_code' "$expected_path")" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected $(jq -r '.expected_exit_code' "$expected_path")"
    return 1
  fi

  if ! assert_bundle "$case_dir" "$expected_path" "$output_dir"; then
    record_failure "${case_name} bundle assertion failed"
    return 1
  fi

  record_pass "${case_name}"
}

run_check() {
  bash -n "$capture_script"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$capture_script" "${BASH_SOURCE[0]}"
  jq empty "${root_dir}/docs/rch_remote_compile_stall_bundle_contract_v1.json" >/dev/null

  while IFS= read -r json_path; do
    jq empty "$json_path" >/dev/null
  done < <(find "$fixture_root" -type f -name '*.json' | sort)

  test -f "${fixture_root}/confirmed/command_excerpt.txt"
  test -f "${fixture_root}/contaminated_local_fallback/command_excerpt.txt"

  record_pass "shell syntax, shellcheck, and fixture JSON"
}

run_selftest() {
  local tmp_root

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/rch-remote-compile-stall-bundle.XXXXXX")"

  run_case "$tmp_root" confirmed
  run_case "$tmp_root" degraded_missing_optional
  run_case "$tmp_root" blocked_contradictory_queue
  run_case "$tmp_root" contaminated_local_fallback

  printf 'rch_remote_compile_stall_bundle_smoke_artifacts=%s\n' "$tmp_root"
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
