#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
guard="${root_dir}/scripts/staged_ownership_contamination_guard.sh"
docs_path="${root_dir}/docs/STAGED_OWNERSHIP_CONTAMINATION_GUARD.md"

record_pass() {
  printf 'PASS staged-ownership-contamination-guard %s\n' "$1"
}

record_failure() {
  printf 'FAIL staged-ownership-contamination-guard %s\n' "$1" >&2
}

write_common_fixtures() {
  local fixture_dir="$1"

  mkdir -p "$fixture_dir"
  jq -n '{reservations:[
    {path_pattern:"scripts/staged_ownership_contamination_guard.sh", agent_id:"ScarletOwl", bead_id:"bd-2wp35", exclusive:true},
    {path_pattern:"docs/STAGED_OWNERSHIP_CONTAMINATION_GUARD.md", agent_id:"ScarletOwl", bead_id:"bd-2wp35", exclusive:true},
    {path_pattern:"crates/franken-engine/src/other_lane.rs", agent_id:"CyanOak", bead_id:"bd-other", exclusive:true}
  ]}' >"${fixture_dir}/reservations.json"
  jq -n '{touched_bead_ids:["bd-2wp35"]}' >"${fixture_dir}/beads-scoped.json"
  jq -n '{touched_bead_ids:["bd-2wp35","bd-other"]}' >"${fixture_dir}/beads-unrelated.json"
}

run_case() {
  local case_name="$1"
  local expected_decision="$2"
  local expected_exit="$3"
  local output_dir="$4"
  shift 4
  local output
  local exit_code

  set +e
  output="$("$guard" --output-dir "$output_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${exit_code}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.staged-ownership-report.v1"
    and .agent_id == "ScarletOwl"
    and .bead_id == "bd-2wp35"
    and .decision == $expected_decision
    and (.staged_paths | type == "array")
    and (.path_decisions | type == "array")
    and (.offending_paths | type == "array")
    and (.artifact_paths.staged_ownership_report_json | length > 0)
    and (.artifact_paths.events_jsonl | length > 0)
    and (.artifact_paths.commands_txt | length > 0)
    and (.artifact_paths.report_md | length > 0)
  ' "${output_dir}/staged_ownership_report.json" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
  record_pass "${case_name} decided ${expected_decision}"
}

run_check() {
  local scope_file

  bash -n "$guard"
  bash -n "${BASH_SOURCE[0]}"
  test -f "$docs_path"
  record_pass "bash syntax and docs exist"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/staged-ownership-rch-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/staged_ownership_contamination_guard.sh" \
    "scripts/e2e/staged_ownership_contamination_guard_smoke.sh" \
    "docs/STAGED_OWNERSHIP_CONTAMINATION_GUARD.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/staged-ownership-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir

  run_check
  tmp_parent="${STAGED_OWNERSHIP_GUARD_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/staged-ownership-guard.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  write_common_fixtures "$fixture_dir"

  jq -n '[{status:"A", path:"scripts/staged_ownership_contamination_guard.sh"}]' >"${fixture_dir}/clean.json"
  run_case "clean-staged-set" "pass" 0 "${tmp_root}/clean-staged-set" \
    --agent-id ScarletOwl \
    --bead-id bd-2wp35 \
    --allowed-path scripts/staged_ownership_contamination_guard.sh \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --staged-name-status-json "${fixture_dir}/clean.json"

  jq -n '[{status:"M", path:"crates/franken-engine/src/other_lane.rs"}]' >"${fixture_dir}/extra-source.json"
  run_case "extra-unrelated-source" "fail_closed" 42 "${tmp_root}/extra-unrelated-source" \
    --agent-id ScarletOwl \
    --bead-id bd-2wp35 \
    --allowed-path scripts/staged_ownership_contamination_guard.sh \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --staged-name-status-json "${fixture_dir}/extra-source.json"

  jq -n '[{status:"M", path:".beads/issues.jsonl"}]' >"${fixture_dir}/beads-only.json"
  run_case "shared-beads-scoped" "pass" 0 "${tmp_root}/shared-beads-scoped" \
    --agent-id ScarletOwl \
    --bead-id bd-2wp35 \
    --allowed-path .beads/issues.jsonl \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --staged-name-status-json "${fixture_dir}/beads-only.json" \
    --beads-diff-json "${fixture_dir}/beads-scoped.json"

  run_case "shared-beads-unrelated" "fail_closed" 42 "${tmp_root}/shared-beads-unrelated" \
    --agent-id ScarletOwl \
    --bead-id bd-2wp35 \
    --allowed-path .beads/issues.jsonl \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --staged-name-status-json "${fixture_dir}/beads-only.json" \
    --beads-diff-json "${fixture_dir}/beads-unrelated.json"

  run_case "missing-reservation-degraded" "pass_degraded" 0 "${tmp_root}/missing-reservation-degraded" \
    --agent-id ScarletOwl \
    --bead-id bd-2wp35 \
    --allowed-path scripts/staged_ownership_contamination_guard.sh \
    --staged-name-status-json "${fixture_dir}/clean.json"

  printf 'staged_ownership_guard_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
