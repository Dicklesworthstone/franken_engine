#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_script="${root_dir}/scripts/swarm_actionability_truth_gate.sh"
docs_path="${root_dir}/docs/SWARM_ACTIONABILITY_TRUTH_GATE.md"
contract_docs_path="${root_dir}/docs/SWARM_ACTIONABILITY_TRUTH_GATE_CONTRACT.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_actionability_truth_gate/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-actionability-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-actionability-truth-gate %s\n' "$1" >&2
  exit 1
}

write_case_source() {
  local case_json="$1"
  local jq_expr="$2"
  local path="$3"
  jq "$jq_expr" <<<"$case_json" >"$path"
}

run_case() {
  local case_id="$1"
  local case_json
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  local tmpdir output_dir status expected_exit required_reason expected_decision expected_candidate
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"

  write_case_source "$case_json" '.sources.br_ready_json' "${tmpdir}/br_ready.json"
  write_case_source "$case_json" '.sources.br_open_json' "${tmpdir}/br_open.json"
  write_case_source "$case_json" '.sources.br_in_progress_json' "${tmpdir}/br_in_progress.json"
  write_case_source "$case_json" '.sources.br_blocked_json' "${tmpdir}/br_blocked.json"
  write_case_source "$case_json" '.sources.bv_robot_plan_json' "${tmpdir}/bv_plan.json"
  write_case_source "$case_json" '.sources.git_status_snapshot_json' "${tmpdir}/git_status.json"
  write_case_source "$case_json" '.sources.source_freshness_json' "${tmpdir}/source_freshness.json"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_candidate="$(jq -r '.expected.candidate_id // ""' <<<"$case_json")"
  required_reason="$(jq -r '.expected.required_reason_code // ""' <<<"$case_json")"
  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  cmd=(
    "$gate_script"
    --br-ready-json "${tmpdir}/br_ready.json"
    --br-open-json "${tmpdir}/br_open.json"
    --br-in-progress-json "${tmpdir}/br_in_progress.json"
    --br-blocked-json "${tmpdir}/br_blocked.json"
    --bv-robot-plan-json "${tmpdir}/bv_plan.json"
    --git-status-snapshot-json "${tmpdir}/git_status.json"
    --source-freshness-json "${tmpdir}/source_freshness.json"
    --source-revision "smoke-${case_id}"
    --generated-epoch-seconds 1800000000
    --output-dir "$output_dir"
  )

  if jq -e '.sources.agent_mail_snapshot_json != null' <<<"$case_json" >/dev/null; then
    write_case_source "$case_json" '.sources.agent_mail_snapshot_json' "${tmpdir}/agent_mail.json"
    cmd+=(--agent-mail-snapshot-json "${tmpdir}/agent_mail.json")
  fi

  set +e
  "${cmd[@]}" >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    printf 'expected exit %s for %s, got %s\n' "$expected_exit" "$case_id" "$status" >&2
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}"
  fi

  [[ -f "${output_dir}/actionability_report.json" ]] || record_failure "missing report for ${case_id}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events for ${case_id}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands for ${case_id}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing markdown for ${case_id}"

  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/actionability_report.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"

  if [[ -n "$expected_candidate" ]]; then
    jq -e --arg candidate "$expected_candidate" '.primary_candidate_id == $candidate' "${output_dir}/actionability_report.json" >/dev/null \
      || record_failure "candidate mismatch for ${case_id}"
  else
    jq -e '.primary_candidate_id == null' "${output_dir}/actionability_report.json" >/dev/null \
      || record_failure "expected null candidate for ${case_id}"
  fi

  if [[ -n "$required_reason" ]]; then
    jq -e --arg code "$required_reason" 'any(.fail_closed_reasons[]?; .code == $code)' "${output_dir}/actionability_report.json" >/dev/null \
      || record_failure "missing reason code ${required_reason} for ${case_id}"
  fi

  jq -e --arg decision "$expected_decision" --arg candidate "$expected_candidate" '
    if $candidate == "" then
      .decision == $decision
    else
      any(.candidate_reports[]?; .candidate_id == $candidate and .decision == $decision)
    end
  ' "${output_dir}/actionability_report.json" >/dev/null || record_failure "candidate report mismatch for ${case_id}"

  grep -Fq "decision:" "${output_dir}/report.md" || record_failure "report markdown missing decision for ${case_id}"
  grep -Fq "./scripts/swarm_actionability_truth_gate.sh" "${output_dir}/commands.txt" || record_failure "commands.txt missing invocation for ${case_id}"

  rm -rf "$tmpdir"
  record_pass "$case_id"
}

docs_shape_ok() {
  grep -Fq "The gate is advisory only and proof only." "$docs_path" \
    && grep -Fq "It must not claim, reopen, close, or reassign beads." "$docs_path" \
    && grep -Fq "It also supports \`--collect-live\`" "$docs_path" \
    && grep -Fq "FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE" "$docs_path" \
    && grep -Fq "docs/SWARM_ACTIONABILITY_TRUTH_GATE_CONTRACT.md" "$docs_path"
}

fixture_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-actionability-truth-gate-fixtures.v1"
    and (.cases | length) == 6
    and any(.cases[]; .case_id == "healthy_ready_safe_to_claim" and .expected.decision == "safe_to_claim")
    and any(.cases[]; .case_id == "bv_blocked_track_fail_closed" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE")
    and any(.cases[]; .case_id == "in_progress_owned_defer" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE")
    and any(.cases[]; .case_id == "stale_export_fail_closed" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE")
    and any(.cases[]; .case_id == "dirty_overlap_defer" and .expected.required_reason_code == "FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP")
    and any(.cases[]; .case_id == "missing_optional_mail_observe_only" and .expected.decision == "observe_only")
  ' "$fixtures_path" >/dev/null
}

run_check() {
  jq empty "$fixtures_path"
  bash -n "$gate_script" "${BASH_SOURCE[0]}"
  docs_shape_ok || record_failure "docs shape mismatch"
  [[ -f "$contract_docs_path" ]] || record_failure "missing contract doc"
  fixture_shape_ok || record_failure "fixture shape mismatch"

  local case_id
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  record_pass "check"
}

run_selftest() {
  run_check
  jq -e '
    ([.cases[].expected.decision] | unique | sort) == ["defer","fail_closed","observe_only","safe_to_claim"]
    and ([.cases[].expected.required_reason_code // empty] | unique | length) >= 4
  ' "$fixtures_path" >/dev/null || record_failure "fixture decision coverage mismatch"
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage='Usage: ./scripts/e2e/swarm_actionability_truth_gate_smoke.sh [check|selftest]'
    printf '%s\n' "$usage"
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
