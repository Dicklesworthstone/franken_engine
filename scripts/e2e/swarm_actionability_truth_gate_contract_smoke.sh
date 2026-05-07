#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${root_dir}/docs/swarm_actionability_truth_gate_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_ACTIONABILITY_TRUTH_GATE_CONTRACT.md"
guide_docs_path="${root_dir}/docs/SWARM_ACTIONABILITY_TRUTH_GATE.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_actionability_truth_gate_contract/cases.json"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-actionability-truth-gate-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-actionability-truth-gate-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_actionability_truth_gate_contract_smoke.sh [check|selftest]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-actionability-truth-gate-contract.v1"
    and .bead_id == "bd-1tsvb"
    and .parent_bead_id == "bd-l09xv"
    and (.required_sources | map(.source_id) | index("br_ready_json") != null)
    and (.required_sources | map(.source_id) | index("br_in_progress_json") != null)
    and (.required_sources | map(.source_id) | index("br_blocked_json") != null)
    and (.required_sources | map(.source_id) | index("bv_robot_plan_json") != null)
    and (.required_sources | map(.source_id) | index("agent_mail_snapshot_json") != null)
    and (.required_sources | map(.source_id) | index("git_status_snapshot_json") != null)
    and (.decisions | index("safe_to_claim") != null)
    and (.decisions | index("defer") != null)
    and (.decisions | index("fail_closed") != null)
    and (.decisions | index("observe_only") != null)
    and (.fail_closed_reason_codes | index("FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE") != null)
    and (.fail_closed_reason_codes | index("FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE") != null)
    and (.fail_closed_reason_codes | index("FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE") != null)
    and (.fail_closed_reason_codes | index("FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP") != null)
    and (.fail_closed_reason_codes | index("FE-SWARM-ACTIONABILITY-UNSUPPORTED-MUTATION") != null)
    and (.required_outputs | index("actionability_report.json") != null)
    and (.operator_pre_claim_workflow | length) == 5
    and (.operator_pre_claim_workflow[0] | contains("Run scripts/swarm_actionability_truth_gate.sh before any claim or reassignment driven by bv --recipe actionable --robot-plan."))
    and (.operator_pre_claim_workflow[1] | contains("Treat safe_to_claim as advisory only"))
    and (.operator_pre_claim_workflow[3] | contains("bd-5oef0"))
    and (.upstream_follow_up_beads | length) == 1
    and (.upstream_follow_up_beads[0].bead_id == "bd-5oef0")
    and (.mutation_policy_scanner.observe_only_script_paths | index("scripts/swarm_actionability_truth_gate.sh") != null)
    and (.mutation_policy_scanner.observe_only_script_paths | index("scripts/e2e/swarm_actionability_truth_gate_smoke.sh") != null)
    and (.mutation_policy_scanner.observe_only_script_paths | index("scripts/e2e/swarm_actionability_truth_gate_no_mock_drill.sh") != null)
    and (.mutation_policy_scanner.required_rejections | sort == [
      "agent_mail_mutation_api",
      "br_update_close_reopen_create_claim",
      "cargo_heavy",
      "git_mutation",
      "rch_exec"
    ])
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.claims_beads == false
    and .mutation_policy.reopens_beads == false
    and .mutation_policy.closes_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_git == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "The gate is advisory only and proof only." "$docs_path" \
    && grep -Fq "## Required Operator Workflow" "$docs_path" \
    && grep -Fq "## Required Mutation-Policy Scanner" "$docs_path" \
    && grep -Fq "Treat safe_to_claim as advisory only." "$docs_path" \
    && grep -Fq "bd-5oef0" "$docs_path" \
    && grep -Fq "safe_to_claim" "$docs_path" \
    && grep -Fq "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE" "$docs_path" \
    && grep -Fq "It must not claim, reopen, close, or reassign beads." "$docs_path"
}

guide_docs_shape_ok() {
  grep -Fq "## Adoption Workflow" "$guide_docs_path" \
    && grep -Fq "Run \`scripts/swarm_actionability_truth_gate.sh\` before any claim or reassignment driven by \`bv --recipe actionable --robot-plan\`." "$guide_docs_path" \
    && grep -Fq "A \`safe_to_claim\` result is advisory only." "$guide_docs_path" \
    && grep -Fq "bd-5oef0" "$guide_docs_path" \
    && grep -Fq "\`observe_only\` is diagnostics only and never authorizes a claim." "$guide_docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-actionability-truth-gate-contract-fixtures.v1"
    and (.cases | length) == 6
    and any(.cases[]; .case_id == "healthy_ready_safe_to_claim" and .expected.decision == "safe_to_claim")
    and any(.cases[]; .case_id == "bv_blocked_track_fail_closed" and .expected.required_error_code == "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE")
    and any(.cases[]; .case_id == "in_progress_owned_defer" and .expected.required_error_code == "FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE")
    and any(.cases[]; .case_id == "stale_export_fail_closed" and .expected.required_error_code == "FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE")
    and any(.cases[]; .case_id == "dirty_overlap_defer" and .expected.required_error_code == "FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP")
    and any(.cases[]; .case_id == "missing_optional_mail_observe_only" and .expected.decision == "observe_only")
    and all(.cases[]; (.sources.br_ready_json != null) and (.sources.bv_robot_plan_json != null) and (.sources.git_status_snapshot_json != null))
  ' "$fixtures_path" >/dev/null
}

assert_lightweight_commands() {
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "contract contains heavy Cargo command: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "contract contains rch exec command: ${command}"
    fi
  done < <(jq -r '.validation_commands[]?' "$contract_path")
}

scanner_pattern() {
  case "$1" in
    br_update_close_reopen_create_claim)
      printf '%s' '(^|[^[:alnum:]_])br[[:space:]]+(update|close|reopen|create|claim)([[:space:]]|$)'
      ;;
    agent_mail_mutation_api)
      printf '%s' '(send_message|reply_message|request_contact|respond_contact|release_file_reservations|renew_file_reservations|macro_start_session|register_agent)'
      ;;
    git_mutation)
      printf '%s' '(^|[^[:alnum:]_])git[[:space:]]+(-C[[:space:]]+[^[:space:]]+[[:space:]]+)?(add|commit|checkout|switch|reset|clean|merge|rebase|push|pull|tag|cherry-pick)([[:space:]]|$)'
      ;;
    cargo_heavy)
      printf '%s' '(^|[^[:alnum:]_])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)'
      ;;
    rch_exec)
      printf '%s' '(^|[^[:alnum:]_])rch[[:space:]]+exec([[:space:]]|$)'
      ;;
    *)
      return 1
      ;;
  esac
}

scan_file_for_rejection() {
  local path="$1"
  local rejection="$2"
  local pattern match

  pattern="$(scanner_pattern "$rejection")"
  match="$(grep -nE "$pattern" "$path" | head -n 1 || true)"
  if [[ -n "$match" ]]; then
    record_failure "${path} violates ${rejection}: ${match}"
  fi
}

assert_observe_only_scripts() {
  local relative_path absolute_path rejection

  while IFS= read -r relative_path; do
    absolute_path="${root_dir}/${relative_path}"
    if [[ ! -f "$absolute_path" ]]; then
      record_failure "missing observe-only script ${relative_path}"
      continue
    fi
    while IFS= read -r rejection; do
      scan_file_for_rejection "$absolute_path" "$rejection"
    done < <(jq -r '.mutation_policy_scanner.required_rejections[]' "$contract_path")
  done < <(jq -r '.mutation_policy_scanner.observe_only_script_paths[]' "$contract_path")
}

scanner_detects_rejection() {
  local path="$1"
  local rejection="$2"
  local pattern

  pattern="$(scanner_pattern "$rejection")"
  grep -qE "$pattern" "$path"
}

run_negative_scanner_case() {
  local rejection="$1"
  local content="$2"
  local tmp_path

  tmp_path="$(mktemp "${TMPDIR:-/tmp}/swarm-actionability-mutation-scan.XXXXXX")"
  printf '%s\n' "$content" >"$tmp_path"
  if scanner_detects_rejection "$tmp_path" "$rejection"; then
    record_pass "${rejection} rejection"
  else
    record_failure "${rejection} should reject"
  fi
  rm -f "$tmp_path"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "${BASH_SOURCE[0]}"
  contract_shape_ok || record_failure "contract shape mismatch"
  docs_shape_ok || record_failure "docs shape mismatch"
  guide_docs_shape_ok || record_failure "guide docs shape mismatch"
  fixtures_shape_ok || record_failure "fixture shape mismatch"
  assert_lightweight_commands
  assert_observe_only_scripts
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  run_check
  jq -e '
    (.cases | map(.expected.decision) | unique | sort) == ["defer","fail_closed","observe_only","safe_to_claim"]
    and ([.cases[].expected.required_error_code?] | map(select(. != null)) | length) >= 4
  ' "$fixtures_path" >/dev/null || record_failure "fixture decision coverage mismatch"
  run_negative_scanner_case "br_update_close_reopen_create_claim" 'br update bd-test --assignee ExampleAgent'
  run_negative_scanner_case "agent_mail_mutation_api" 'send_message --subject mutation'
  run_negative_scanner_case "git_mutation" 'git commit -m "mutation"'
  run_negative_scanner_case "cargo_heavy" 'cargo test'
  run_negative_scanner_case "rch_exec" 'rch exec -- cargo check'
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
