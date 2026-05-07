#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix_path="${root_dir}/docs/swarm_actionability_conformance_matrix_v1.json"
docs_path="${root_dir}/docs/SWARM_ACTIONABILITY_CONFORMANCE_MATRIX.md"
contract_path="${root_dir}/docs/swarm_actionability_truth_gate_contract_v1.json"
cases_path="${root_dir}/scripts/testdata/swarm_actionability_truth_gate_contract/cases.json"
goldens_path="${root_dir}/scripts/testdata/swarm_actionability_golden_reports/reports.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-actionability-conformance-matrix %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-actionability-conformance-matrix %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_actionability_conformance_matrix_smoke.sh [check|selftest]
EOF
}

matrix_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-actionability-conformance-matrix.v1"
    and .bead_id == "bd-l28cd"
    and .contract_bead_id == "bd-1tsvb"
    and .golden_bead_id == "bd-p02f6"
    and (.requirements | length) == 6
    and all(.requirements[]; .level == "MUST" and .status == "covered")
    and .coverage_summary.must_total == 6
    and .coverage_summary.must_covered == 6
    and .coverage_summary.known_divergences == 0
    and .coverage_summary.score == 1
    and (.known_boundaries | map(.boundary_id) | index("expected-output-only") != null)
    and (.known_boundaries | map(.boundary_id) | index("no-active-drill-files") != null)
  ' "$matrix_path" >/dev/null
}

case_coverage_ok() {
  jq -n --slurpfile matrix "$matrix_path" --slurpfile cases "$cases_path" --slurpfile goldens "$goldens_path" '
    (($matrix[0].requirements[] | select(.id == "ACT-MUST-001") | .evidence.contract_cases) | sort)
      == ($cases[0].cases | map(.case_id) | sort)
    and (($matrix[0].requirements[] | select(.id == "ACT-MUST-001") | .evidence.golden_reports) | sort)
      == ($goldens[0].reports | map(.case_id) | sort)
  ' >/dev/null
}

decision_coverage_ok() {
  jq -n --slurpfile matrix "$matrix_path" --slurpfile contract "$contract_path" --slurpfile goldens "$goldens_path" '
    (($matrix[0].requirements[] | select(.id == "ACT-MUST-002") | .evidence.decisions) | sort)
      == ($contract[0].decisions | sort)
    and (($goldens[0].reports | map(.actionability_report.decision) | unique) | sort)
      == ($contract[0].decisions | sort)
  ' >/dev/null
}

reason_coverage_ok() {
  jq -n --slurpfile matrix "$matrix_path" --slurpfile goldens "$goldens_path" '
    (($matrix[0].requirements[] | select(.id == "ACT-MUST-003") | .evidence.reason_codes) | sort) as $required
    | ([$goldens[0].reports[].actionability_report.fail_closed_reasons[]?] | unique | sort) as $actual
    | all($required[]; . as $code | ($actual | index($code) != null))
  ' >/dev/null
}

scrubbed_revision_ok() {
  jq -e '
    all(.reports[];
      .actionability_report.source_revision.captured_at == "[SCRUBBED_TIMESTAMP]"
      and .actionability_report.source_revision.br_state_hash == "[SCRUBBED_HASH]"
      and .actionability_report.source_revision.bv_plan_hash == "[SCRUBBED_HASH]"
      and .actionability_report.source_revision.git_status_hash == "[SCRUBBED_HASH]"
      and .actionability_report.source_revision.agent_mail_hash == "[SCRUBBED_HASH]"
    )
  ' "$goldens_path" >/dev/null
}

mutation_policy_ok() {
  jq -e '
    all(.reports[];
      .actionability_report.mutation_policy.advisory_only == true
      and .actionability_report.mutation_policy.proof_only == true
      and .actionability_report.mutation_policy.mutates_br == false
      and .actionability_report.mutation_policy.claims_beads == false
      and .actionability_report.mutation_policy.reopens_beads == false
      and .actionability_report.mutation_policy.closes_beads == false
      and .actionability_report.mutation_policy.reassigns_beads == false
      and .actionability_report.mutation_policy.releases_reservations == false
      and .actionability_report.mutation_policy.sends_agent_mail == false
      and .actionability_report.mutation_policy.mutates_git == false
      and .actionability_report.mutation_policy.runs_cargo == false
      and .actionability_report.mutation_policy.runs_rch == false
      and .actionability_report.mutation_policy.mutates_remote_workers == false
      and .actionability_report.mutation_policy.changes_live_queue_policy == false
    )
  ' "$goldens_path" >/dev/null
}

required_report_fields_ok() {
  jq -e '
    all(.reports[];
      (.actionability_report | has("schema_version"))
      and (.actionability_report | has("source_revision"))
      and (.actionability_report | has("decision"))
      and (.actionability_report | has("candidate_summary"))
      and (.actionability_report | has("candidate_reports"))
      and (.actionability_report | has("fail_closed_reasons"))
      and (.actionability_report | has("advisory_remediation_commands"))
      and (.actionability_report | has("source_freshness_summary"))
      and (.actionability_report | has("mutation_policy"))
    )
  ' "$goldens_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "does not prove live guard execution" "$docs_path" \
    && grep -Fq "6 of 6 contract cases" "$docs_path" \
    && grep -Fq "Known boundary" "$docs_path"
}

assert_lightweight_commands() {
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "matrix validation contains heavy cargo command: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "matrix validation contains rch exec command: ${command}"
    fi
  done < <(jq -r '.validation_commands[]?' "$matrix_path")
}

run_check() {
  jq empty "$matrix_path" "$contract_path" "$cases_path" "$goldens_path"
  bash -n "${BASH_SOURCE[0]}"
  matrix_shape_ok || record_failure "matrix shape mismatch"
  case_coverage_ok || record_failure "case coverage mismatch"
  decision_coverage_ok || record_failure "decision coverage mismatch"
  reason_coverage_ok || record_failure "reason coverage mismatch"
  scrubbed_revision_ok || record_failure "scrubbed revision mismatch"
  mutation_policy_ok || record_failure "mutation policy mismatch"
  required_report_fields_ok || record_failure "required report fields mismatch"
  docs_shape_ok || record_failure "docs shape mismatch"
  assert_lightweight_commands
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  run_check
  jq -e '
    .coverage_summary.conformance_claim == "fixture-and-golden-report-conformant"
    and ([.requirements[].area] | unique | length) == 6
  ' "$matrix_path" >/dev/null || record_failure "selftest summary mismatch"
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
