#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_validation_planner.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"

record_pass() {
  printf 'PASS swarm-validation-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-validation-planner %s\n' "$1" >&2
}

canonicalize_plan() {
  local plan_path="$1"
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
    | del(.expected_artifacts)
  ' "$plan_path"
}

write_case_golden() {
  local tmp_root="$1"
  local output_dir="$2"
  local actual_path="$3"

  canonicalize_plan "${output_dir}/plan.json" "$tmp_root" >"$actual_path"
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

run_planner_expect_pass() {
  local output_dir="$1"
  shift

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE="${SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE:-}" \
    "$planner" --bead-id bd-1onpa --source-revision smoke-rev --output-dir "$output_dir" "$@" >/dev/null

  jq -e '.decision != "fail_closed" and (.commands | length) > 0' "${output_dir}/plan.json" >/dev/null
  if rg -q 'cargo check --all-targets' "${output_dir}/commands.txt"; then
    record_failure "planner emitted broad all-targets check"
    return 1
  fi
  record_pass "planner passed"
}

run_planner_expect_fail() {
  local output_dir="$1"
  shift
  local output exit_code

  set +e
  output="$(SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE="${SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE:-}" \
    "$planner" --bead-id bd-1onpa --source-revision smoke-rev --output-dir "$output_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    record_failure "planner unexpectedly passed"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e '.decision == "fail_closed" and (.omitted_commands | map(.kind) | index("unknown_path_mapping") != null)' "${output_dir}/plan.json" >/dev/null
  record_pass "planner failed closed"
}

assert_default_output_dir_outside_worktree() {
  local tmp_root="$1"
  local default_run_id="smoke-default-dir"
  local default_dir="${TMPDIR:-/tmp}/franken-engine-swarm-validation-planner/${default_run_id}"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE='' \
    SWARM_VALIDATION_PLANNER_RUN_ID="$default_run_id" \
    "$planner" --bead-id bd-1onpa --source-revision smoke-rev \
      --changed-path scripts/swarm_validation_planner.sh >/dev/null

  jq -e \
    --arg default_dir "$default_dir" \
    --arg root_dir "$root_dir" \
    '.artifact_paths.run_dir == $default_dir and (.artifact_paths.run_dir | startswith($root_dir) | not)' \
    "${default_dir}/plan.json" >/dev/null
  cp "${default_dir}/plan.json" "${tmp_root}/default-output-dir-plan.json"
  record_pass "default output directory stays outside worktree"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${SWARM_VALIDATION_PLANNER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-validation-planner.XXXXXX")"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=''
  run_planner_expect_pass \
    "${tmp_root}/exact-test" \
    --changed-path crates/franken-engine/tests/proof_manifest_golden_artifacts.rs
  assert_case_golden \
    "exact-test" \
    "$tmp_root" \
    "${tmp_root}/exact-test" \
    "${golden_dir}/swarm_validation_planner_exact_test.golden"

  run_planner_expect_pass \
    "${tmp_root}/script-only" \
    --changed-path scripts/rch_policy_compliance_gate.sh
  assert_case_golden \
    "script-only" \
    "$tmp_root" \
    "${tmp_root}/script-only" \
    "${golden_dir}/swarm_validation_planner_script_only.golden"

  run_planner_expect_pass \
    "${tmp_root}/docs-only" \
    --changed-path docs/swarm_validation_control_plane_contract_v1.json
  assert_case_golden \
    "docs-only" \
    "$tmp_root" \
    "${tmp_root}/docs-only" \
    "${golden_dir}/swarm_validation_planner_docs_only.golden"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=' M README.md'
  run_planner_expect_pass \
    "${tmp_root}/package-fallback" \
    --changed-path crates/franken-engine/src/proof_artifact.rs
  assert_case_golden \
    "package-fallback" \
    "$tmp_root" \
    "${tmp_root}/package-fallback" \
    "${golden_dir}/swarm_validation_planner_package_fallback.golden"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=''
  run_planner_expect_pass \
    "${tmp_root}/multi-crate" \
    --changed-path crates/franken-engine/src/proof_artifact.rs \
    --changed-path crates/franken-extension-host/src/lib.rs
  assert_case_golden \
    "multi-crate" \
    "$tmp_root" \
    "${tmp_root}/multi-crate" \
    "${golden_dir}/swarm_validation_planner_multi_crate.golden"

  run_planner_expect_fail \
    "${tmp_root}/unknown-path" \
    --changed-path unknown/path.rs
  assert_case_golden \
    "unknown-path" \
    "$tmp_root" \
    "${tmp_root}/unknown-path" \
    "${golden_dir}/swarm_validation_planner_unknown_path.golden"

  assert_default_output_dir_outside_worktree "$tmp_root"

  printf 'swarm_validation_planner_smoke_artifacts=%s\n' "$tmp_root"
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
