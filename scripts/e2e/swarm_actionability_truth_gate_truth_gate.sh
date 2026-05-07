#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${SWARM_ACTIONABILITY_TRUTH_GATE_NO_MOCK_DRILL_CONTRACT_PATH:-${root_dir}/docs/swarm_actionability_truth_gate_no_mock_drill_contract_v1.json}"
drill_path="${root_dir}/scripts/e2e/swarm_actionability_truth_gate_no_mock_drill.sh"
fixtures_path="${root_dir}/scripts/testdata/swarm_actionability_truth_gate/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-actionability-truth-gate-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-actionability-truth-gate-truth-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_actionability_truth_gate_truth_gate.sh [check|selftest]
EOF
}

assert_contract_shape() {
  jq -e '
    .schema_version == "franken-engine.swarm-actionability-truth-gate-no-mock-drill-contract.v1"
    and .bead_id == "bd-fi6kq"
    and .parent_bead_id == "bd-l09xv"
    and .track_contract_path == "docs/swarm_actionability_truth_gate_contract_v1.json"
    and .drill_script == "scripts/e2e/swarm_actionability_truth_gate_no_mock_drill.sh"
    and .truth_gate_script == "scripts/e2e/swarm_actionability_truth_gate_truth_gate.sh"
    and .fixture_bundle == "scripts/testdata/swarm_actionability_truth_gate/cases.json"
    and (.depends_on | index("bd-l4mya") != null)
    and (.modes | sort == ["fixture", "live", "replay"])
    and (.composed_scripts | index("scripts/swarm_actionability_truth_gate.sh") != null)
    and (.required_repo_paths | index("docs/swarm_actionability_truth_gate_contract_v1.json") != null)
    and (.required_repo_paths | index("docs/SWARM_ACTIONABILITY_TRUTH_GATE_CONTRACT.md") != null)
    and (.required_repo_paths | index("docs/SWARM_ACTIONABILITY_TRUTH_GATE.md") != null)
    and (.required_repo_paths | index("scripts/swarm_actionability_truth_gate.sh") != null)
    and (.required_repo_paths | index("scripts/e2e/swarm_actionability_truth_gate_no_mock_drill.sh") != null)
    and (.required_repo_paths | index("scripts/e2e/swarm_actionability_truth_gate_truth_gate.sh") != null)
    and (.required_repo_paths | index("scripts/testdata/swarm_actionability_truth_gate/cases.json") != null)
    and any(.drill_scenarios[]; .scenario_id == "healthy_ready_safe_to_claim" and .expected.decision == "safe_to_claim" and .expected.candidate_id == "bd-ready1")
    and any(.drill_scenarios[]; .scenario_id == "bv_blocked_track_fail_closed" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE")
    and any(.drill_scenarios[]; .scenario_id == "in_progress_owned_defer" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE")
    and any(.drill_scenarios[]; .scenario_id == "stale_export_fail_closed" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE")
    and any(.drill_scenarios[]; .scenario_id == "dirty_overlap_defer" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP")
    and any(.drill_scenarios[]; .scenario_id == "missing_optional_mail_observe_only" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-MISSING-SOURCE")
    and any(.drill_scenarios[]; .scenario_id == "replay_verification" and .expected.replay_verified == true)
    and (.required_truth_gate_rejections | index("heavy_cargo_or_rch_claim") != null)
    and (.required_truth_gate_rejections | index("tracker_or_git_mutation_claim") != null)
    and (.required_truth_gate_rejections | index("reservation_release_or_agent_mail_claim") != null)
    and (.required_truth_gate_rejections | index("replay_reruns_live_capture_claim") != null)
    and (.required_truth_gate_rejections | index("blocked_or_stale_healthy_claim") != null)
    and .mutation_policy.live_capture_allowed == true
    and .mutation_policy.fixture_mode_deterministic == true
    and .mutation_policy.replay_verification_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.claims_beads == false
    and .mutation_policy.reopens_beads == false
    and .mutation_policy.closes_beads == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_git == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch_heavy_commands == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reruns_live_capture_during_replay == false
  ' "$contract_path" >/dev/null
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
      *"runs Cargo"*|*"runs RCH heavy commands."*)
        if [[ "$claim" != *"does not run Cargo or RCH heavy commands."* ]]; then
          record_failure "heavy Cargo or RCH positive claim present"
          return 1
        fi
        ;;
      *"mutates br"*|*"mutates git"*|*"claims beads"*|*"reopens beads"*|*"closes beads"*|*"reassigns beads"*)
        record_failure "tracker or git mutation positive claim present"
        return 1
        ;;
      *"releases reservations"*|*"sends Agent Mail"*)
        if [[ "$claim" != *"does not"* ]]; then
          record_failure "reservation release or Agent Mail positive claim present"
          return 1
        fi
        ;;
      *"Replay mode reruns live capture."*)
        record_failure "replay reruns live capture positive claim present"
        return 1
        ;;
      *"blocked bv actionability"*|*"stale exported state"*|*"dirty overlap ambiguity"*|*"missing optional ownership evidence"*)
        if { [[ "$claim" == *"safe claim"* ]] || [[ "$claim" == *"healthy"* ]] || [[ "$claim" == *"upgraded"* ]]; } \
          && [[ "$claim" != *"instead of"* ]] \
          && [[ "$claim" != *"must stay"* ]] \
          && [[ "$claim" != *"does not"* ]]; then
          record_failure "blocked or stale state healthy claim present"
          return 1
        fi
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

assert_drill_outputs() {
  local drill_output_dir="$1"

  jq -e '.decision == "pass" and .replay_verified == false' "${drill_output_dir}/truth_gate_report.json" >/dev/null
  jq -e '.schema_version == "franken-engine.swarm-actionability-no-mock-drill.manifest.v1" and .mode == "fixture" and .replay_verified == false' "${drill_output_dir}/run_manifest.json" >/dev/null
  jq -e '.schema_version == "franken-engine.swarm-actionability-truth-gate.v1"' "${drill_output_dir}/actionability_report.json" >/dev/null
  jq -e '.schema_version == "franken-engine.swarm-actionability-no-mock-drill.source-snapshots.v1"' "${drill_output_dir}/source_snapshots.json" >/dev/null
  jq -s -e 'length == 6 and all(.[]; .expected_match == true)' "${drill_output_dir}/case_results.jsonl" >/dev/null
}

run_check() {
  local drill_output_dir

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  jq empty "$contract_path" >/dev/null
  jq empty "$fixtures_path" >/dev/null

  if assert_contract_shape; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  assert_required_paths
  assert_truth_claims
  assert_verification_commands_are_lightweight

  if [[ "$failures" -eq 0 ]]; then
    drill_output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-actionability-truth-gate-truth-gate-check.XXXXXX")"
    bash "$drill_path" check --output-dir "$drill_output_dir" --fixtures-json "$fixtures_path" >/dev/null
    if assert_drill_outputs "$drill_output_dir"; then
      record_pass "drill outputs"
    else
      record_failure "drill outputs mismatch"
    fi
  fi
}

run_negative_case() {
  local bad_contract="$1"
  local label="$2"

  if SWARM_ACTIONABILITY_TRUTH_GATE_NO_MOCK_DRILL_CONTRACT_PATH="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "${label} should fail"
  else
    record_pass "${label} rejection"
  fi
}

run_selftest() {
  local tmp_root bad_contract

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-actionability-truth-gate-truth-gate.XXXXXX")"

  bad_contract="${tmp_root}/bad-heavy-cargo.json"
  jq '.operator_truth_claims += ["The drill runs Cargo and RCH heavy commands."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "heavy Cargo or RCH positive claim"

  bad_contract="${tmp_root}/bad-mutation.json"
  jq '.operator_truth_claims += ["The drill mutates br, mutates git, and claims beads automatically."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "tracker or git mutation"

  bad_contract="${tmp_root}/bad-agent-mail.json"
  jq '.operator_truth_claims += ["The drill releases reservations and sends Agent Mail."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "reservation release or Agent Mail"

  bad_contract="${tmp_root}/bad-replay.json"
  jq '.operator_truth_claims += ["Replay mode reruns live capture."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "replay reruns live capture"

  bad_contract="${tmp_root}/bad-healthy-claim.json"
  jq '.operator_truth_claims += ["Blocked bv actionability and stale exported state can be upgraded to safe claim guidance."]' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "blocked or stale healthy claim"

  bad_contract="${tmp_root}/bad-policy.json"
  jq '.mutation_policy.runs_rch_heavy_commands = true' "$contract_path" >"$bad_contract"
  run_negative_case "$bad_contract" "mutation policy runs_rch_heavy_commands=true"

  printf 'swarm_actionability_truth_gate_truth_gate_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
