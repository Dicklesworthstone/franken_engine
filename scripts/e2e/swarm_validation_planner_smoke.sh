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

write_proof_cost_history() {
  local output_path="$1"
  local row_source_revision="$2"
  local command_id="$3"
  local package="$4"
  local target="$5"
  local elapsed_ms="$6"
  local compiled_count="$7"
  local linked_count="$8"
  local rch_status="$9"
  local fallback_detected="${10}"
  local content_hash="${11}"

  jq -n \
    --arg schema_version "franken-engine.proof-cost-history.v1" \
    --arg bead_id "bd-history" \
    --arg source_revision "$row_source_revision" \
    --arg command_id "$command_id" \
    --arg package "$package" \
    --arg target "$target" \
    --arg rch_status "$rch_status" \
    --arg content_hash "$content_hash" \
    --argjson elapsed_ms "$elapsed_ms" \
    --argjson compiled_count "$compiled_count" \
    --argjson linked_count "$linked_count" \
    --argjson fallback_detected "$fallback_detected" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      source_revision: $source_revision,
      changed_paths: ["crates/franken-engine/tests/proof_manifest_golden_artifacts.rs"],
      rows: [
        {
          command_id: $command_id,
          package: $package,
          target: $target,
          elapsed_ms: $elapsed_ms,
          compiled_target_count: $compiled_count,
          linked_target_count: $linked_count,
          rch_worker: "rch-smoke",
          rch_status: $rch_status,
          fallback_detected: $fallback_detected,
          artifact_paths: ["artifacts/proof-cost-history-smoke/report.json"],
          content_hash: $content_hash
        }
      ]
    }' >"$output_path"
}

write_contradictory_cost_history() {
  local output_path="$1"
  local command_id="cargo-test-proof_manifest_golden_artifacts"
  local package="frankenengine-engine"
  local target="proof_manifest_golden_artifacts"

  jq -n \
    --arg schema_version "franken-engine.proof-cost-history.v1" \
    --arg command_id "$command_id" \
    --arg package "$package" \
    --arg target "$target" \
    '{
      schema_version: $schema_version,
      bead_id: "bd-history",
      source_revision: "smoke-rev",
      changed_paths: ["crates/franken-engine/tests/proof_manifest_golden_artifacts.rs"],
      rows: [
        {
          command_id: $command_id,
          package: $package,
          target: $target,
          elapsed_ms: 900,
          compiled_target_count: 1,
          linked_target_count: 1,
          rch_worker: "rch-smoke-a",
          rch_status: "pass",
          fallback_detected: false,
          artifact_paths: ["artifacts/proof-cost-history-smoke/pass.json"],
          content_hash: "sha-contradict-pass"
        },
        {
          command_id: $command_id,
          package: $package,
          target: $target,
          elapsed_ms: 1000,
          compiled_target_count: 1,
          linked_target_count: 1,
          rch_worker: "local",
          rch_status: "fail",
          fallback_detected: true,
          artifact_paths: ["artifacts/proof-cost-history-smoke/fail.json"],
          content_hash: "sha-contradict-fail"
        }
      ]
    }' >"$output_path"
}

write_reservation_snapshot() {
  local output_path="$1"
  local path_pattern="$2"
  local agent="$3"
  local bead_id="$4"
  local exclusive="${5:-true}"

  jq -n \
    --arg path_pattern "$path_pattern" \
    --arg agent "$agent" \
    --arg bead_id "$bead_id" \
    --argjson exclusive "$exclusive" \
    '{
      reservations: [
        {
          path_pattern: $path_pattern,
          agent_name: $agent,
          bead_id: $bead_id,
          exclusive: $exclusive
        }
      ]
    }' >"$output_path"
}

write_in_progress_snapshot() {
  local output_path="$1"
  local bead_id="$2"
  local assignee="$3"
  shift 3

  jq -n \
    --arg bead_id "$bead_id" \
    --arg assignee "$assignee" \
    --argjson paths "$(printf '%s\n' "$@" | jq -R . | jq -s 'map(select(length > 0))')" \
    '{
      beads: [
        {
          id: $bead_id,
          assignee: $assignee,
          status: "in_progress",
          planned_write_paths: $paths
        }
      ]
    }' >"$output_path"
}

assert_no_stale_or_mismatch_low_cost_claim() {
  local plan_path="$1"

  jq -e '
    [
      .commands[]?
      | select((.cost_evidence.status == "stale" or .cost_evidence.status == "mismatched")
          and .predicted_cost.cost_class == "low")
    ]
    | length == 0
  ' "$plan_path" >/dev/null
  record_pass "stale/mismatched evidence cannot claim low cost"
}

assert_decision_and_collision() {
  local plan_path="$1"
  local expected_decision="$2"
  local expected_risk="$3"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_risk "$expected_risk" \
    '.decision == $expected_decision and .collision_risk == $expected_risk' \
    "$plan_path" >/dev/null
  record_pass "decision ${expected_decision} with collision risk ${expected_risk}"
}

assert_conflicting_agent() {
  local plan_path="$1"
  local expected_agent="$2"

  jq -e \
    --arg expected_agent "$expected_agent" \
    '.conflicting_agents | index($expected_agent) != null' \
    "$plan_path" >/dev/null
  record_pass "conflicting agent includes ${expected_agent}"
}

assert_safe_alternative() {
  local plan_path="$1"
  local expected_path="$2"

  jq -e \
    --arg expected_path "$expected_path" \
    '.safe_alternatives | index($expected_path) != null' \
    "$plan_path" >/dev/null
  record_pass "safe alternative includes ${expected_path}"
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

run_planner_expect_cost_fail() {
  local output_dir="$1"
  local expected_flag="$2"
  shift 2
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

  jq -e \
    --arg expected_flag "$expected_flag" \
    '.decision == "fail_closed" and (.risk_flags | index($expected_flag) != null)' \
    "${output_dir}/plan.json" >/dev/null
  assert_no_stale_or_mismatch_low_cost_claim "${output_dir}/plan.json"
  record_pass "planner failed closed for ${expected_flag}"
}

run_planner_expect_fail_closed() {
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

  jq -e '.decision == "fail_closed"' "${output_dir}/plan.json" >/dev/null
  record_pass "planner failed closed"
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
  local low_history high_history stale_history mismatched_history contradictory_history
  local no_conflict_reservations exact_conflict_reservations glob_conflict_reservations
  local clean_in_progress dirty_overlap_in_progress safe_alternative_in_progress

  tmp_parent="${SWARM_VALIDATION_PLANNER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-validation-planner.XXXXXX")"
  low_history="${tmp_root}/low-cost-history.json"
  high_history="${tmp_root}/high-cost-history.json"
  stale_history="${tmp_root}/stale-cost-history.json"
  mismatched_history="${tmp_root}/mismatched-cost-history.json"
  contradictory_history="${tmp_root}/contradictory-cost-history.json"
  no_conflict_reservations="${tmp_root}/no-conflict-reservations.json"
  exact_conflict_reservations="${tmp_root}/exact-conflict-reservations.json"
  glob_conflict_reservations="${tmp_root}/glob-conflict-reservations.json"
  clean_in_progress="${tmp_root}/clean-in-progress.json"
  dirty_overlap_in_progress="${tmp_root}/dirty-overlap-in-progress.json"
  safe_alternative_in_progress="${tmp_root}/safe-alternative-in-progress.json"
  write_proof_cost_history "$low_history" "smoke-rev" "cargo-test-proof_manifest_golden_artifacts" "frankenengine-engine" "proof_manifest_golden_artifacts" 1200 1 1 "pass" false "sha-low-cost"
  write_proof_cost_history "$high_history" "smoke-rev" "cargo-test-proof_manifest_golden_artifacts" "frankenengine-engine" "proof_manifest_golden_artifacts" 900000 12 2 "pass" false "sha-high-cost"
  write_proof_cost_history "$stale_history" "old-rev" "cargo-test-proof_manifest_golden_artifacts" "frankenengine-engine" "proof_manifest_golden_artifacts" 800 1 1 "pass" false "sha-stale-cost"
  write_proof_cost_history "$mismatched_history" "smoke-rev" "cargo-test-proof_manifest_golden_artifacts" "frankenengine-extension-host" "proof_manifest_golden_artifacts" 800 1 1 "pass" false "sha-mismatched-cost"
  write_contradictory_cost_history "$contradictory_history"
  write_reservation_snapshot "$no_conflict_reservations" "docs/other_runbook.md" "BlueStone" "bd-other" true
  write_reservation_snapshot "$exact_conflict_reservations" "docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md" "BlueStone" "bd-other" true
  write_reservation_snapshot "$glob_conflict_reservations" "scripts/testdata/goldens/swarm_validation_planner_*.golden" "BlueStone" "bd-other" true
  write_in_progress_snapshot "$clean_in_progress" "bd-clean" "GreenField" "docs/non_overlapping.md"
  write_in_progress_snapshot "$dirty_overlap_in_progress" "bd-overlap" "PurpleRiver" "docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md"
  write_in_progress_snapshot "$safe_alternative_in_progress" "bd-safe" "PurpleRiver" "docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=''
  run_planner_expect_pass \
    "${tmp_root}/exact-test" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --proof-cost-history-json "$low_history" \
    --changed-path crates/franken-engine/tests/proof_manifest_golden_artifacts.rs
  assert_case_golden \
    "exact-test" \
    "$tmp_root" \
    "${tmp_root}/exact-test" \
    "${golden_dir}/swarm_validation_planner_exact_test.golden"

  run_planner_expect_pass \
    "${tmp_root}/no-conflict" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path scripts/swarm_validation_planner.sh \
    --planned-write-path scripts/swarm_validation_planner.sh
  assert_decision_and_collision "${tmp_root}/no-conflict/plan.json" "admit" "none"
  assert_case_golden \
    "no-conflict" \
    "$tmp_root" \
    "${tmp_root}/no-conflict" \
    "${golden_dir}/swarm_validation_planner_no_conflict.golden"

  run_planner_expect_pass \
    "${tmp_root}/unknown-cost" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path crates/franken-engine/tests/swarm_validation_control_plane_e2e.rs
  assert_case_golden \
    "unknown-cost" \
    "$tmp_root" \
    "${tmp_root}/unknown-cost" \
    "${golden_dir}/swarm_validation_planner_unknown_cost.golden"

  run_planner_expect_pass \
    "${tmp_root}/script-only" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path scripts/rch_policy_compliance_gate.sh
  assert_case_golden \
    "script-only" \
    "$tmp_root" \
    "${tmp_root}/script-only" \
    "${golden_dir}/swarm_validation_planner_script_only.golden"

  run_planner_expect_pass \
    "${tmp_root}/docs-only" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path docs/swarm_validation_control_plane_contract_v1.json
  assert_case_golden \
    "docs-only" \
    "$tmp_root" \
    "${tmp_root}/docs-only" \
    "${golden_dir}/swarm_validation_planner_docs_only.golden"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=' M README.md'
  run_planner_expect_pass \
    "${tmp_root}/package-fallback" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path crates/franken-engine/src/proof_artifact.rs
  assert_case_golden \
    "package-fallback" \
    "$tmp_root" \
    "${tmp_root}/package-fallback" \
    "${golden_dir}/swarm_validation_planner_package_fallback.golden"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=''
  run_planner_expect_pass \
    "${tmp_root}/multi-crate" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path crates/franken-engine/src/proof_artifact.rs \
    --changed-path crates/franken-extension-host/src/lib.rs
  assert_case_golden \
    "multi-crate" \
    "$tmp_root" \
    "${tmp_root}/multi-crate" \
    "${golden_dir}/swarm_validation_planner_multi_crate.golden"

  run_planner_expect_pass \
    "${tmp_root}/high-cost" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --proof-cost-history-json "$high_history" \
    --changed-path crates/franken-engine/tests/proof_manifest_golden_artifacts.rs
  assert_case_golden \
    "high-cost" \
    "$tmp_root" \
    "${tmp_root}/high-cost" \
    "${golden_dir}/swarm_validation_planner_high_cost.golden"

  run_planner_expect_pass \
    "${tmp_root}/stale-cost" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --proof-cost-history-json "$stale_history" \
    --changed-path crates/franken-engine/tests/proof_manifest_golden_artifacts.rs
  assert_no_stale_or_mismatch_low_cost_claim "${tmp_root}/stale-cost/plan.json"
  assert_case_golden \
    "stale-cost" \
    "$tmp_root" \
    "${tmp_root}/stale-cost" \
    "${golden_dir}/swarm_validation_planner_stale_cost.golden"

  run_planner_expect_cost_fail \
    "${tmp_root}/mismatched-cost" \
    "mismatched_cost_evidence" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --proof-cost-history-json "$mismatched_history" \
    --changed-path crates/franken-engine/tests/proof_manifest_golden_artifacts.rs

  run_planner_expect_cost_fail \
    "${tmp_root}/contradictory-cost" \
    "contradictory_cost_evidence" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --proof-cost-history-json "$contradictory_history" \
    --changed-path crates/franken-engine/tests/proof_manifest_golden_artifacts.rs

  run_planner_expect_fail_closed \
    "${tmp_root}/exact-reservation-conflict" \
    --reservation-snapshot-json "$exact_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md \
    --planned-write-path docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md
  assert_decision_and_collision "${tmp_root}/exact-reservation-conflict/plan.json" "fail_closed" "reserved_overlap"
  assert_conflicting_agent "${tmp_root}/exact-reservation-conflict/plan.json" "BlueStone"
  assert_case_golden \
    "exact-reservation-conflict" \
    "$tmp_root" \
    "${tmp_root}/exact-reservation-conflict" \
    "${golden_dir}/swarm_validation_planner_exact_reservation_conflict.golden"

  run_planner_expect_fail_closed \
    "${tmp_root}/glob-reservation-conflict" \
    --reservation-snapshot-json "$glob_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
    --changed-path scripts/testdata/goldens/swarm_validation_planner_exact_test.golden \
    --planned-write-path scripts/testdata/goldens/swarm_validation_planner_exact_test.golden
  assert_decision_and_collision "${tmp_root}/glob-reservation-conflict/plan.json" "fail_closed" "reserved_overlap"
  assert_conflicting_agent "${tmp_root}/glob-reservation-conflict/plan.json" "BlueStone"
  assert_case_golden \
    "glob-reservation-conflict" \
    "$tmp_root" \
    "${tmp_root}/glob-reservation-conflict" \
    "${golden_dir}/swarm_validation_planner_glob_reservation_conflict.golden"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=' M docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md'
  run_planner_expect_pass \
    "${tmp_root}/dirty-overlap-conflict" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$dirty_overlap_in_progress" \
    --changed-path scripts/swarm_validation_planner.sh \
    --planned-write-path docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md
  assert_decision_and_collision "${tmp_root}/dirty-overlap-conflict/plan.json" "admit_narrow" "dirty_or_in_progress_overlap"
  assert_conflicting_agent "${tmp_root}/dirty-overlap-conflict/plan.json" "PurpleRiver"
  assert_case_golden \
    "dirty-overlap-conflict" \
    "$tmp_root" \
    "${tmp_root}/dirty-overlap-conflict" \
    "${golden_dir}/swarm_validation_planner_dirty_overlap_conflict.golden"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=''
  run_planner_expect_pass \
    "${tmp_root}/missing-agent-mail-degraded" \
    --changed-path scripts/swarm_validation_planner.sh \
    --planned-write-path scripts/swarm_validation_planner.sh
  assert_decision_and_collision "${tmp_root}/missing-agent-mail-degraded/plan.json" "admit_narrow" "agent_mail_snapshot_missing"
  assert_case_golden \
    "missing-agent-mail-degraded" \
    "$tmp_root" \
    "${tmp_root}/missing-agent-mail-degraded" \
    "${golden_dir}/swarm_validation_planner_missing_agent_mail_degraded.golden"

  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE=' M docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md'
  run_planner_expect_pass \
    "${tmp_root}/safe-alternative-path" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$safe_alternative_in_progress" \
    --changed-path scripts/swarm_validation_planner.sh \
    --planned-write-path docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md \
    --planned-write-path scripts/swarm_validation_planner.sh
  assert_decision_and_collision "${tmp_root}/safe-alternative-path/plan.json" "admit_narrow" "dirty_or_in_progress_overlap"
  assert_conflicting_agent "${tmp_root}/safe-alternative-path/plan.json" "PurpleRiver"
  assert_safe_alternative "${tmp_root}/safe-alternative-path/plan.json" "scripts/swarm_validation_planner.sh"
  assert_case_golden \
    "safe-alternative-path" \
    "$tmp_root" \
    "${tmp_root}/safe-alternative-path" \
    "${golden_dir}/swarm_validation_planner_safe_alternative_path.golden"

  run_planner_expect_fail \
    "${tmp_root}/unknown-path" \
    --reservation-snapshot-json "$no_conflict_reservations" \
    --in-progress-json "$clean_in_progress" \
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
