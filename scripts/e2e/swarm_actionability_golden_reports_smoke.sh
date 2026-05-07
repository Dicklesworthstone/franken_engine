#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
golden_path="${root_dir}/scripts/testdata/swarm_actionability_golden_reports/reports.json"
contract_cases_path="${root_dir}/scripts/testdata/swarm_actionability_truth_gate_contract/cases.json"
docs_path="${root_dir}/docs/SWARM_ACTIONABILITY_GOLDEN_REPORTS.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-actionability-golden-reports %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-actionability-golden-reports %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_actionability_golden_reports_smoke.sh [check|selftest]
EOF
}

golden_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-actionability-golden-reports.v1"
    and .bead_id == "bd-p02f6"
    and .contract_bead_id == "bd-1tsvb"
    and (.reports | length) == 6
    and all(.reports[]; .actionability_report.schema_version == "franken-engine.swarm-actionability-report.v1")
    and all(.reports[]; .actionability_report.source_revision.captured_at == "[SCRUBBED_TIMESTAMP]")
    and all(.reports[]; .actionability_report.source_revision.br_state_hash == "[SCRUBBED_HASH]")
    and all(.reports[]; .actionability_report.source_revision.bv_plan_hash == "[SCRUBBED_HASH]")
    and all(.reports[]; .actionability_report.source_revision.git_status_hash == "[SCRUBBED_HASH]")
    and all(.reports[]; .actionability_report.source_revision.agent_mail_hash == "[SCRUBBED_HASH]")
    and ([.reports[].actionability_report.decision] | unique | sort) == ["defer","fail_closed","observe_only","safe_to_claim"]
    and any(.reports[]; .case_id == "healthy_ready_safe_to_claim" and .actionability_report.decision == "safe_to_claim")
    and any(.reports[]; .case_id == "bv_blocked_track_fail_closed" and (.actionability_report.fail_closed_reasons | index("FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE") != null))
    and any(.reports[]; .case_id == "in_progress_owned_defer" and (.actionability_report.fail_closed_reasons | index("FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE") != null))
    and any(.reports[]; .case_id == "stale_export_fail_closed" and (.actionability_report.fail_closed_reasons | index("FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE") != null))
    and any(.reports[]; .case_id == "dirty_overlap_defer" and (.actionability_report.fail_closed_reasons | index("FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP") != null))
    and any(.reports[]; .case_id == "missing_optional_mail_observe_only" and (.actionability_report.fail_closed_reasons | index("FE-SWARM-ACTIONABILITY-MISSING-SOURCE") != null))
    and all(.reports[]; .actionability_report.mutation_policy.advisory_only == true)
    and all(.reports[]; .actionability_report.mutation_policy.proof_only == true)
    and all(.reports[]; .actionability_report.mutation_policy.mutates_br == false)
    and all(.reports[]; .actionability_report.mutation_policy.claims_beads == false)
    and all(.reports[]; .actionability_report.mutation_policy.reopens_beads == false)
    and all(.reports[]; .actionability_report.mutation_policy.closes_beads == false)
    and all(.reports[]; .actionability_report.mutation_policy.releases_reservations == false)
    and all(.reports[]; .actionability_report.mutation_policy.sends_agent_mail == false)
    and all(.reports[]; .actionability_report.mutation_policy.mutates_git == false)
    and all(.reports[]; .actionability_report.mutation_policy.runs_cargo == false)
    and all(.reports[]; .actionability_report.mutation_policy.runs_rch == false)
    and all(.reports[]; .actionability_report.mutation_policy.mutates_remote_workers == false)
    and all(.reports[]; .actionability_report.mutation_policy.changes_live_queue_policy == false)
  ' "$golden_path" >/dev/null
}

contract_case_coverage_ok() {
  jq -n --slurpfile goldens "$golden_path" --slurpfile cases "$contract_cases_path" '
    ($goldens[0].reports | map(.case_id) | sort) == ($cases[0].cases | map(.case_id) | sort)
  ' >/dev/null
}

docs_shape_ok() {
  grep -Fq "reviewed golden reports" "$docs_path" \
    && grep -Fq "healthy_ready_safe_to_claim" "$docs_path" \
    && grep -Fq "Dynamic source metadata is represented with" "$docs_path"
}

assert_no_live_dynamic_values() {
  if grep -Eq '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' "$golden_path"; then
    record_failure "golden contains live timestamp"
  fi
  if grep -Eq '/data/projects|/home/ubuntu|/tmp/' "$golden_path"; then
    record_failure "golden contains host path"
  fi
}

assert_advisory_commands() {
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])br[[:space:]]+(update|close|reopen|assign|claim)([[:space:]]|$) ]]; then
      record_failure "golden remediation mutates br: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])git[[:space:]]+(add|commit|checkout|reset|clean|merge|rebase|push)([[:space:]]|$) ]]; then
      record_failure "golden remediation mutates git: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "golden remediation runs cargo: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "golden remediation runs rch: ${command}"
    fi
  done < <(jq -r '.reports[].actionability_report.advisory_remediation_commands[]?' "$golden_path")
}

run_check() {
  jq empty "$golden_path" "$contract_cases_path"
  bash -n "${BASH_SOURCE[0]}"
  golden_shape_ok || record_failure "golden shape mismatch"
  contract_case_coverage_ok || record_failure "contract case coverage mismatch"
  docs_shape_ok || record_failure "docs shape mismatch"
  assert_no_live_dynamic_values
  assert_advisory_commands
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  run_check
  jq -e '
    all(.reports[]; (.actionability_report.candidate_summary.safe_to_claim_count
      + .actionability_report.candidate_summary.defer_count
      + .actionability_report.candidate_summary.fail_closed_count
      + .actionability_report.candidate_summary.observe_only_count) >= 1)
    and ([.reports[].actionability_report.fail_closed_reasons[]?] | unique | length) >= 5
    and all(.reports[]; (.actionability_report.candidate_reports[]?.evidence_paths // []) | length >= 0)
  ' "$golden_path" >/dev/null || record_failure "selftest coverage mismatch"
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
