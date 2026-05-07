#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill_script="${root_dir}/scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill.sh"
truth_gate_script="${root_dir}/scripts/e2e/swarm_autopilot_forensic_diff_truth_gate.sh"
contract_path="${root_dir}/docs/swarm_autopilot_forensic_diff_no_mock_drill_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_FORENSIC_DIFF_NO_MOCK_DRILL.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_autopilot_forensic_diff_no_mock_drill/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_AUTOPILOT_FORENSIC_DIFF_DRILL_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-forensic-diff-drill-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-forensic-diff-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-forensic-diff-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-forensic-diff-no-mock-drill-contract.v1"
    and .bead_id == "bd-00ofm.6"
    and .drill_script == "scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill.sh"
    and .truth_gate_script == "scripts/e2e/swarm_autopilot_forensic_diff_truth_gate.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill_smoke.sh"
    and (.modes | index("fixture") != null)
    and (.modes | index("replay") != null)
    and (.modes | index("live") != null)
    and (.required_outputs | index("cohort_diff_receipts.json") != null)
    and (.required_outputs | index("truth_gate_report.json") != null)
    and any(.drill_scenarios[]; .scenario_id == "healthy_forensic_comparison")
    and any(.drill_scenarios[]; .scenario_id == "blocked_locality_contradiction_replay")
    and any(.drill_scenarios[]; .scenario_id == "contaminated_replay_refusal")
    and any(.drill_scenarios[]; .scenario_id == "low_evidence_degraded_hypothesis")
    and any(.drill_scenarios[]; .scenario_id == "stale_reference_fail_closed")
    and (.required_truth_gate_rejections | index("local_fallback_contamination_non_fail_closed_claim") != null)
    and (.required_truth_gate_rejections | index("heavy_cargo_or_rch_claim") != null)
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch_heavy_commands == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "Fixture mode runs the real shipped forensic producer scripts" "$docs_path" \
    && grep -Fq "Replay mode verifies a pinned complete forensic bundle without rerunning producers." "$docs_path" \
    && grep -Fq "The drill does not run Cargo or RCH work directly." "$docs_path" \
    && grep -Fq "contaminated replay refusal fail closed" "$docs_path" \
    && grep -Fq "forensic_hypothesis_summary.json" "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-forensic-diff-no-mock-drill-fixtures.v1"
    and .primary_scenario_id == "healthy_forensic_comparison"
    and (.cases | length) == 5
    and any(.cases[]; .scenario_id == "healthy_forensic_comparison" and .expected.decision == "pass")
    and any(.cases[]; .scenario_id == "blocked_locality_contradiction_replay" and .expected.required_pivot == "topology_drift")
    and any(.cases[]; .scenario_id == "contaminated_replay_refusal" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-CONTAMINATED-BASELINE")
    and any(.cases[]; .scenario_id == "low_evidence_degraded_hypothesis" and .expected.required_pivot == "insufficient_evidence")
    and any(.cases[]; .scenario_id == "stale_reference_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-COHORT-DIFF-STALE-REFERENCE")
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
  bash -n "$drill_script" "$truth_gate_script" "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixtures_path"
  contract_shape_ok || record_failure "contract shape mismatch"
  docs_shape_ok || record_failure "docs shape mismatch"
  fixtures_shape_ok || record_failure "fixture shape mismatch"
  assert_lightweight_commands "contract"
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
    and .required_coverage.healthy_forensic_comparison == true
    and .required_coverage.blocked_locality_contradiction_replay == true
    and .required_coverage.contaminated_replay_refusal == true
    and .required_coverage.low_evidence_degraded_hypothesis == true
    and .required_coverage.stale_reference_fail_closed == true
  ' "${fixture_dir}/truth_gate_report.json" >/dev/null || record_failure "fixture truth gate mismatch"

  bash "$drill_script" replay --replay-run-dir "$fixture_dir" --output-dir "$replay_dir" >/dev/null
  jq -e '.decision == "pass" and .replay_verified == true' "${replay_dir}/truth_gate_report.json" >/dev/null \
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
