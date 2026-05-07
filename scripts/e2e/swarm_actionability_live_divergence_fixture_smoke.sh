#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_path="${root_dir}/scripts/testdata/swarm_actionability_live_divergence/current_divergence.json"
docs_path="${root_dir}/docs/SWARM_ACTIONABILITY_LIVE_DIVERGENCE_FIXTURES.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-actionability-live-divergence-fixture %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-actionability-live-divergence-fixture %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_actionability_live_divergence_fixture_smoke.sh [check|selftest]
EOF
}

fixture_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-actionability-live-divergence-fixture.v1"
    and .bead_id == "bd-30x14"
    and .contract_bead_id == "bd-1tsvb"
    and .source_freshness_json.db_newer == false
    and .source_freshness_json.jsonl_newer == false
    and (.sources.br_ready_json | length) == 0
    and (.sources.br_in_progress_json | map(.id) | index("bd-l4mya") != null)
    and (.sources.br_in_progress_json | map(.id) | index("bd-30x14") != null)
    and (.sources.br_blocked_json | map(.id) | index("bd-5oef0") != null)
    and (.sources.br_blocked_json | map(.id) | index("bd-djejh.2") != null)
    and (.sources.bv_robot_plan_json.plan.tracks | length) == 4
    and any(.sources.bv_robot_plan_json.plan.tracks[].items[]; .id == "bd-l4mya" and .status == "in_progress")
    and any(.sources.bv_robot_plan_json.plan.tracks[].items[]; .id == "bd-30x14" and .status == "in_progress")
    and any(.sources.bv_robot_plan_json.plan.tracks[].items[]; .id == "bd-5oef0" and .status == "blocked")
    and any(.sources.bv_robot_plan_json.plan.tracks[].items[]; .id == "bd-djejh.2" and .status == "blocked")
    and .expected_report.decision == "fail_closed"
    and (.expected_report.reason_codes | index("FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE") != null)
    and (.expected_report.reason_codes | index("FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE") != null)
    and all(.expected_report.candidate_reports[]; (.evidence_paths | length) >= 2)
    and .expected_report.mutation_policy.advisory_only == true
    and .expected_report.mutation_policy.proof_only == true
    and .expected_report.mutation_policy.mutates_br == false
    and .expected_report.mutation_policy.claims_beads == false
    and .expected_report.mutation_policy.reopens_beads == false
    and .expected_report.mutation_policy.closes_beads == false
    and .expected_report.mutation_policy.releases_reservations == false
    and .expected_report.mutation_policy.sends_agent_mail == false
    and .expected_report.mutation_policy.mutates_git == false
    and .expected_report.mutation_policy.runs_cargo == false
    and .expected_report.mutation_policy.runs_rch == false
    and .expected_report.mutation_policy.mutates_remote_workers == false
    and .expected_report.mutation_policy.changes_live_queue_policy == false
  ' "$fixture_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "Replay evidence only." "$docs_path" \
    && grep -Fq "\`br ready\` returned an empty array." "$docs_path" \
    && grep -Fq "The expected aggregate decision is \`fail_closed\`." "$docs_path" \
    && grep -Fq "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE" "$docs_path"
}

assert_capture_commands_are_observe_only() {
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])br[[:space:]]+(update|close|reopen|assign|claim)([[:space:]]|$) ]]; then
      record_failure "capture command mutates br: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])git[[:space:]]+(add|commit|checkout|reset|clean|merge|rebase|push)([[:space:]]|$) ]]; then
      record_failure "capture command mutates git: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "capture command runs cargo: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "capture command runs rch: ${command}"
    fi
  done < <(jq -r '.capture_context.commands[]' "$fixture_path")
}

run_check() {
  jq empty "$fixture_path"
  bash -n "${BASH_SOURCE[0]}"
  fixture_shape_ok || record_failure "fixture shape mismatch"
  docs_shape_ok || record_failure "docs shape mismatch"
  assert_capture_commands_are_observe_only
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  run_check
  jq -e '
    ([.expected_report.candidate_reports[] | select(.source_status == "in_progress")] | length) == 2
    and ([.expected_report.candidate_reports[] | select(.source_status == "blocked")] | length) == 2
    and ([.expected_report.candidate_reports[].required_error_code] | unique | sort) == [
      "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE",
      "FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE"
    ]
  ' "$fixture_path" >/dev/null || record_failure "candidate coverage mismatch"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
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
