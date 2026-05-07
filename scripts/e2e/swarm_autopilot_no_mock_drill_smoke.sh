#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill_script="${root_dir}/scripts/e2e/swarm_autopilot_no_mock_drill.sh"
contract_path="${root_dir}/docs/swarm_autopilot_no_mock_drill_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_NO_MOCK_DRILL.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_autopilot_no_mock_drill/cases.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-no-mock-drill-smoke %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-no-mock-drill-smoke %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_no_mock_drill_smoke.sh [check|selftest]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-no-mock-drill-contract.v1"
    and .bead_id == "bd-khg2d"
    and .drill_script == "scripts/e2e/swarm_autopilot_no_mock_drill.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_no_mock_drill_smoke.sh"
    and (.modes | index("live") != null)
    and (.modes | index("fixture") != null)
    and (.modes | index("replay") != null)
    and (.required_outputs | index("run_manifest.json") != null)
    and (.required_outputs | index("trace_ids.json") != null)
    and (.required_outputs | index("truth_gate_report.json") != null)
    and (.required_outputs | index("dashboard_projection.json") != null)
    and (.required_outputs | index("chaos_replay_index.json") != null)
    and any(.drill_scenarios[]; .scenario_id == "healthy_autopilot")
    and any(.drill_scenarios[]; .scenario_id == "forecast_brownout")
    and any(.drill_scenarios[]; .scenario_id == "policy_conflict")
    and any(.drill_scenarios[]; .scenario_id == "stale_rch_progress_not_upgraded")
    and any(.drill_scenarios[]; .scenario_id == "local_fallback_contamination")
    and any(.drill_scenarios[]; .scenario_id == "replay_verification")
    and (.required_truth_gate_rejections | index("heavy_cargo_or_rch_claim") != null)
    and (.required_truth_gate_rejections | index("stale_rch_progress_healthy_claim") != null)
    and (.required_truth_gate_rejections | index("local_fallback_non_fail_closed_claim") != null)
    and (.required_truth_gate_rejections | index("contradictory_queue_or_locality_healthy_claim") != null)
    and (.required_truth_gate_rejections | index("replay_reruns_live_capture_claim") != null)
    and .mutation_policy.live_capture_allowed == true
    and .mutation_policy.fixture_mode_deterministic == true
    and .mutation_policy.replay_verification_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch_heavy_commands == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "The drill supports live, fixture, and replay modes." "$docs_path" \
    && grep -Fq "Live mode runs the real SWARM-OPS capture and autopilot evidence warehouse path against the local repository state." "$docs_path" \
    && grep -Fq "Fixture mode composes the shipped producers against preserved upstream inputs and preserves raw and normalized stage inputs for every stage." "$docs_path" \
    && grep -Fq "Replay mode verifies a pinned bundle or the latest complete bundle without re-running live capture." "$docs_path" \
    && grep -Fq "The drill does not run Cargo or RCH work directly." "$docs_path" \
    && grep -Fq "Stale SWARM-OPS sync, stale RCH progress, local fallback contamination, contradictory queue or locality evidence, and bare Cargo contamination fail closed." "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-no-mock-drill-fixtures.v1"
    and .primary_scenario_id == "healthy_autopilot"
    and (.scenarios | length) == 5
    and any(.scenarios[]; .scenario_id == "healthy_autopilot" and .expected.dashboard_decision == "pass" and .expected.dashboard_top_action == "admit_lane")
    and any(.scenarios[]; .scenario_id == "forecast_brownout" and .expected.dashboard_decision == "pass" and .expected.dashboard_top_action == "preserve_urgent_rch_slack")
    and any(.scenarios[]; .scenario_id == "policy_conflict" and .expected.required_truth_gate_reason_code == "FE-SWARM-AUTOPILOT-POLICY-CONFLICT")
    and any(.scenarios[]; .scenario_id == "stale_rch_progress_not_upgraded" and .expected.required_truth_gate_reason_code == "FE-SWARM-OPS-RCH-STALL-NOT-UPGRADED")
    and any(.scenarios[]; .scenario_id == "local_fallback_contamination" and .expected.required_truth_gate_reason_code == "FE-SWARM-AUTOPILOT-LOCAL-FALLBACK")
    and .replay_expectation.scenario_id == "replay_verification"
    and .replay_expectation.source_scenario_id == "healthy_autopilot"
    and .replay_expectation.expected.replay_verified == true
  ' "$fixtures_path" >/dev/null
}

assert_required_paths() {
  local path
  while IFS= read -r path; do
    if [[ ! -e "${root_dir}/${path}" ]]; then
      record_failure "missing required path ${path}"
      return 1
    fi
  done < <(jq -r '.required_repo_paths[]' "$contract_path")
}

assert_truth_claims() {
  local claim
  while IFS= read -r claim; do
    case "$claim" in
      *"runs heavy Cargo or RCH work directly."*)
        record_failure "heavy Cargo or RCH positive claim present"
        return 1
        ;;
      *"mutates live queue policy"*|*"mutates remote workers"*|*"mutates br"*)
        record_failure "live queue or worker mutation claim present"
        return 1
        ;;
      *"releases reservations"*|*"sends Agent Mail"*|*"reassigns beads"*)
        record_failure "automatic reassignment or reservation release claim present"
        return 1
        ;;
      *"stale RCH progress can still be treated as healthy."*)
        record_failure "stale RCH progress healthy claim present"
        return 1
        ;;
      *"local fallback contamination is advisory only"*|*"does not fail closed"*)
        record_failure "local fallback non-fail-closed claim present"
        return 1
        ;;
      *"contradictory queue or locality evidence can still be healthy."*)
        record_failure "contradictory queue or locality healthy claim present"
        return 1
        ;;
      *"replay mode reruns live capture."*)
        record_failure "replay reruns live capture claim present"
        return 1
        ;;
    esac
  done < <(jq -r '.operator_truth_claims[]' "$contract_path")
}

assert_verification_commands_are_lightweight() {
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "truth contract must not advertise heavy Cargo in verification: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "truth contract must not advertise RCH in verification: ${command}"
    fi
  done < <(jq -r '.verification_commands[]?' "$contract_path")
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_script"
  jq empty "$contract_path" >/dev/null
  jq empty "$fixtures_path" >/dev/null

  contract_shape_ok || record_failure "contract JSON shape mismatch"
  docs_shape_ok || record_failure "docs truth text mismatch"
  fixtures_shape_ok || record_failure "fixtures shape mismatch"
  assert_required_paths
  assert_truth_claims
  assert_verification_commands_are_lightweight

  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local temp_dir fixture_dir replay_dir
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-autopilot-no-mock-drill.XXXXXX")"
  trap 'rm -rf "$temp_dir"' RETURN
  fixture_dir="${temp_dir}/fixture"
  replay_dir="${temp_dir}/replay"

  bash "$drill_script" fixture --fixtures-json "$fixtures_path" --output-dir "$fixture_dir" >/dev/null
  jq -e '
    .decision == "pass"
    and .required_coverage.healthy_autopilot == true
    and .required_coverage.forecast_brownout == true
    and .required_coverage.policy_conflict == true
    and .required_coverage.stale_rch_progress_not_upgraded == true
    and .required_coverage.local_fallback_contamination == true
  ' "${fixture_dir}/truth_gate_report.json" >/dev/null || record_failure "fixture suite truth gate mismatch"

  bash "$drill_script" replay --replay-run-dir "$fixture_dir" --output-dir "$replay_dir" >/dev/null
  jq -e '.decision == "pass" and .replay_verified == true' "${replay_dir}/truth_gate_report.json" >/dev/null \
    || record_failure "replay verification mismatch"

  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest"
  else
    exit 1
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
    else
      exit 1
    fi
    ;;
  -h|--help)
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
