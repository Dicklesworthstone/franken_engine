#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill_script="${root_dir}/scripts/e2e/rch_first_error_conveyor_no_mock_drill.sh"
contract_path="${root_dir}/docs/rch_first_error_conveyor_no_mock_drill_contract_v1.json"
docs_path="${root_dir}/docs/RCH_FIRST_ERROR_CONVEYOR_NO_MOCK_DRILL.md"
fixtures_path="${root_dir}/scripts/testdata/rch_first_error_conveyor_no_mock_drill/cases.json"
mode="${1:-check}"
output_root="${2:-${RCH_FIRST_ERROR_CONVEYOR_DRILL_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-first-error-drill-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS rch-first-error-conveyor-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-first-error-conveyor-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_first_error_conveyor_no_mock_drill_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.rch-first-error-conveyor-no-mock-drill-contract.v1"
    and .bead_id == "bd-pkxky.6"
    and .drill_script == "scripts/e2e/rch_first_error_conveyor_no_mock_drill.sh"
    and .smoke_script == "scripts/e2e/rch_first_error_conveyor_no_mock_drill_smoke.sh"
    and (.modes | index("fixture") != null)
    and (.modes | index("replay") != null)
    and (.required_outputs | index("artifact_hashes.json") != null)
    and any(.drill_scenarios[]; .scenario_id == "first_error_chain")
    and any(.drill_scenarios[]; .scenario_id == "blocked_golden_lane")
    and any(.drill_scenarios[]; .scenario_id == "blocked_object_create_lane")
    and any(.drill_scenarios[]; .scenario_id == "fresh_active_owner")
    and any(.drill_scenarios[]; .scenario_id == "stale_owner")
    and any(.drill_scenarios[]; .scenario_id == "local_fallback_contamination")
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.creates_beads == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "fixture mode followed by replay mode" "$docs_path" \
    && grep -Fq "local fallback contamination fails closed" "$docs_path" \
    && grep -Fq "The drill does not run Cargo, invoke" "$docs_path" \
    && grep -Fq "artifact_hashes.json" "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.rch-first-error-conveyor-no-mock-drill-fixtures.v1"
    and .primary_scenario_id == "first_error_chain"
    and (.cases | length) == 6
    and any(.cases[]; .scenario_id == "first_error_chain" and .expected.decision == "block_current_bead")
    and any(.cases[]; .scenario_id == "blocked_golden_lane" and .expected.matched_bead_id == "bd-golden-lane")
    and any(.cases[]; .scenario_id == "blocked_object_create_lane" and .expected.matched_bead_id == "bd-object-create-lane")
    and any(.cases[]; .scenario_id == "fresh_active_owner" and .expected.matched_reservation_id == "res-shadow-active")
    and any(.cases[]; .scenario_id == "stale_owner" and .expected.reason_code == "stale_owner_manual_reopen_candidate")
    and any(.cases[]; .scenario_id == "local_fallback_contamination" and .expected.decision == "fail_closed")
    and all(.cases[]; has("transcript_lines") and has("metadata") and has("profile") and has("expected"))
  ' "$fixtures_path" >/dev/null
}

assert_lightweight_commands() {
  local path="$1"
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path} contains heavy Cargo command: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "${path} contains rch exec command: ${command}"
    fi
  done < <(jq -r '.verification_commands[]?' "$contract_path")
}

run_check() {
  bash -n "$drill_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixtures_path"
  contract_shape_ok || record_failure "contract shape mismatch"
  docs_shape_ok || record_failure "docs shape mismatch"
  fixtures_shape_ok || record_failure "fixture shape mismatch"
  assert_lightweight_commands "contract"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$drill_script" "${BASH_SOURCE[0]}"
  fi
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local fixture_dir replay_dir
  fixture_dir="${output_root}/fixture"
  replay_dir="${output_root}/replay"
  mkdir -p "$fixture_dir" "$replay_dir"

  bash "$drill_script" fixture --fixtures-json "$fixtures_path" --output-dir "$fixture_dir" >/dev/null
  jq -e '
    .decision == "pass"
    and .required_coverage.first_error_chain == true
    and .required_coverage.blocked_golden_lane == true
    and .required_coverage.blocked_object_create_lane == true
    and .required_coverage.fresh_active_owner == true
    and .required_coverage.stale_owner == true
    and .required_coverage.local_fallback_contamination == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.creates_beads == false
    and .mutation_policy.sends_agent_mail == false
  ' "${fixture_dir}/truth_gate_report.json" >/dev/null || record_failure "fixture truth gate mismatch"
  jq -e '
    .schema_version == "franken-engine.rch-first-error-conveyor-no-mock-drill-trace-ids.v1"
    and (.traces | length) == 6
  ' "${fixture_dir}/trace_ids.json" >/dev/null || record_failure "trace ids mismatch"
  jq -e '
    .schema_version == "franken-engine.rch-first-error-conveyor-no-mock-drill-artifact-hashes.v1"
    and (.hashes | length) > 20
  ' "${fixture_dir}/artifact_hashes.json" >/dev/null || record_failure "artifact hash mismatch"
  jq -e '
    all(.recommendations[]; (.evidence_paths | type) == "object" and ((.proposed_command // "") | length) > 0)
  ' "${fixture_dir}/first_error_conveyor_plan.json" >/dev/null || record_failure "primary conveyor plan evidence paths missing"

  bash "$drill_script" replay --replay-run-dir "$fixture_dir" --output-dir "$replay_dir" >/dev/null
  jq -e '.decision == "pass" and .replay_verified == true and .hashes_match == true' "${replay_dir}/truth_gate_report.json" >/dev/null \
    || record_failure "replay verification mismatch"

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
      run_selftest
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
