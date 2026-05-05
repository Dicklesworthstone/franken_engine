#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
governor="${root_dir}/scripts/swarm_resource_governor.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"

record_pass() {
  printf 'PASS swarm-resource-governor %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-resource-governor %s\n' "$1" >&2
}

canonicalize_decision() {
  local decision_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
    | del(.artifact_paths)
  ' "$decision_path"
}

write_case_golden() {
  local tmp_root="$1"
  local output_dir="$2"
  local actual_path="$3"

  canonicalize_decision "${output_dir}/decision.json" "$tmp_root" >"$actual_path"
}

compare_case_golden() {
  local case_name="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_name}"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_name}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches ${case_name}"
}

assert_case_golden() {
  local case_name="$1"
  local tmp_root="$2"
  local output_dir="$3"
  local golden_path="$4"
  local actual_path="${tmp_root}/${case_name}.actual.golden"

  write_case_golden "$tmp_root" "$output_dir" "$actual_path"
  compare_case_golden "$case_name" "$actual_path" "$golden_path"
}

run_case() {
  local case_name="$1"
  local output_dir="$2"
  local expected_decision="$3"
  local expected_exit="$4"
  shift 4
  local output exit_code

  set +e
  output="$("$governor" --bead-id bd-zmuv5 --output-dir "$output_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exited ${exit_code}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.swarm-resource-governor-decision.v1"
    and .bead_id == "bd-zmuv5"
    and .decision == $expected_decision
  ' "${output_dir}/decision.json" >/dev/null
  record_pass "${case_name} decided ${expected_decision}"
}

base_args() {
  printf '%s\n' \
    --active-compile-count 1 \
    --disk-available-bytes 2147483648 \
    --target-dir /tmp/rch_target_franken_engine_swarm_resource_governor \
    --target-dir-writable true \
    --memory-available-bytes 2147483648 \
    --rch-present true \
    --rch-status ok \
    --rch-fallback-detected false \
    --command-exit-code 0 \
    --command-failure-kind none \
    --ownership-state none \
    --dirty-state clean
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${SWARM_RESOURCE_GOVERNOR_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-resource-governor.XXXXXX")"

  mapfile -t healthy_args < <(base_args)
  run_case "healthy" "${tmp_root}/healthy" "admit" 0 "${healthy_args[@]}"
  assert_case_golden \
    "healthy" \
    "$tmp_root" \
    "${tmp_root}/healthy" \
    "${golden_dir}/swarm_resource_governor_healthy.golden"

  mapfile -t high_compile_args < <(base_args)
  high_compile_args[1]=5
  run_case "high-compile-count" "${tmp_root}/high-compile-count" "defer" 75 "${high_compile_args[@]}"
  assert_case_golden \
    "high-compile-count" \
    "$tmp_root" \
    "${tmp_root}/high-compile-count" \
    "${golden_dir}/swarm_resource_governor_high_compile_count.golden"

  mapfile -t disk_pressure_args < <(base_args)
  disk_pressure_args[3]=64
  run_case "disk-pressure" "${tmp_root}/disk-pressure" "fail_closed" 42 "${disk_pressure_args[@]}"
  assert_case_golden \
    "disk-pressure" \
    "$tmp_root" \
    "${tmp_root}/disk-pressure" \
    "${golden_dir}/swarm_resource_governor_disk_pressure.golden"

  mapfile -t non_writable_args < <(base_args)
  non_writable_args[7]=false
  run_case "non-writable-target" "${tmp_root}/non-writable-target" "fail_closed" 42 "${non_writable_args[@]}"
  assert_case_golden \
    "non-writable-target" \
    "$tmp_root" \
    "${tmp_root}/non-writable-target" \
    "${golden_dir}/swarm_resource_governor_non_writable_target.golden"

  mapfile -t missing_rch_args < <(base_args)
  missing_rch_args[11]=false
  missing_rch_args[13]=missing
  run_case "missing-rch" "${tmp_root}/missing-rch" "fail_closed" 42 "${missing_rch_args[@]}"
  assert_case_golden \
    "missing-rch" \
    "$tmp_root" \
    "${tmp_root}/missing-rch" \
    "${golden_dir}/swarm_resource_governor_missing_rch.golden"

  mapfile -t local_fallback_args < <(base_args)
  local_fallback_args[15]=true
  run_case "fallback-detected" "${tmp_root}/fallback-detected" "fail_closed" 42 "${local_fallback_args[@]}"
  assert_case_golden \
    "fallback-detected" \
    "$tmp_root" \
    "${tmp_root}/fallback-detected" \
    "${golden_dir}/swarm_resource_governor_local_fallback.golden"

  mapfile -t unknown_ownership_args < <(base_args)
  unknown_ownership_args[21]=unknown
  run_case "unknown-ownership" "${tmp_root}/unknown-ownership" "fail_closed" 42 "${unknown_ownership_args[@]}"
  assert_case_golden \
    "unknown-ownership" \
    "$tmp_root" \
    "${tmp_root}/unknown-ownership" \
    "${golden_dir}/swarm_resource_governor_unknown_ownership.golden"

  mapfile -t override_args < <(base_args)
  override_args[1]=5
  override_args+=(--override-note "operator confirms script-only validation; no heavy cargo")
  run_case "override-note" "${tmp_root}/override-note" "admit_narrow" 0 "${override_args[@]}"
  assert_case_golden \
    "override-note" \
    "$tmp_root" \
    "${tmp_root}/override-note" \
    "${golden_dir}/swarm_resource_governor_override_note.golden"

  printf 'swarm_resource_governor_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check|selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
