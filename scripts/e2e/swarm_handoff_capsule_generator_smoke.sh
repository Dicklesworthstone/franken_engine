#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
generator_script="${root_dir}/scripts/swarm_handoff_capsule_generator.sh"
docs_path="${root_dir}/docs/SWARM_HANDOFF_CAPSULE_GENERATOR.md"
contract_path="${root_dir}/docs/swarm_handoff_capsule_generator_contract_v1.json"
fixtures_path="${SWARM_HANDOFF_CAPSULE_FIXTURES:-${root_dir}/scripts/testdata/swarm_handoff_capsule_generator/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-handoff-capsule-generator %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-handoff-capsule-generator %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-handoff-capsule-generator-contract.v1"
    and .bead_id == "bd-d5kxj"
    and .surface_id == "swarm_handoff_capsule_generator"
    and (.required_capsule_fields | index("dirty_worktree") != null)
    and (.emitted_artifacts | sort) == ([
      "events.jsonl",
      "handoff_commands.txt",
      "swarm_handoff_capsule.json",
      "swarm_handoff_capsule.md"
    ] | sort)
    and .privacy_policy.reads_file_contents == false
    and .privacy_policy.copies_operator_note_bodies == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .degraded_mail_policy.mail_outage_decision == "degraded"
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "file contents" "$docs_path" \
    && grep -Fq "swarm_handoff_capsule.json" "$docs_path" \
    && grep -Fq "rch exec -- env CARGO_TARGET_DIR=" "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-handoff-capsule-generator-fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "active_rch_process_fixture",
      "clean_repo_fixture",
      "corrupted_agent_mail_fixture",
      "dirty_multi_agent_fixture"
    ] | sort)
    and any(.cases[]; .case_id == "dirty_multi_agent_fixture" and .expected.unrelated_dirty_count == 1)
    and any(.cases[]; .case_id == "active_rch_process_fixture" and .expected.active_rch_count == 1)
    and any(.cases[]; .case_id == "corrupted_agent_mail_fixture" and .expected.mail_decision == "degraded")
  ' "$fixtures_path" >/dev/null
}

write_json_field() {
  local case_json="$1"
  local field="$2"
  local path="$3"
  jq ".${field}" <<<"$case_json" >"$path"
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir status expected_exit expected_decision expected_owned expected_unrelated
  local expected_rch expected_mail expected_bad expected_reason capsule

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"
  write_json_field "$case_json" "git_status_json" "${tmpdir}/git_status.json"
  write_json_field "$case_json" "br_state_json" "${tmpdir}/br_state.json"
  write_json_field "$case_json" "owned_paths_json" "${tmpdir}/owned_paths.json"
  write_json_field "$case_json" "recent_commits_json" "${tmpdir}/recent_commits.json"
  write_json_field "$case_json" "rch_jobs_json" "${tmpdir}/rch_jobs.json"
  write_json_field "$case_json" "validation_receipts_json" "${tmpdir}/validation_receipts.json"
  write_json_field "$case_json" "mail_health_json" "${tmpdir}/mail_health.json"
  write_json_field "$case_json" "operator_notes_json" "${tmpdir}/operator_notes.json"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_owned="$(jq -r '.expected.owned_dirty_count' <<<"$case_json")"
  expected_unrelated="$(jq -r '.expected.unrelated_dirty_count' <<<"$case_json")"
  expected_rch="$(jq -r '.expected.active_rch_count' <<<"$case_json")"
  expected_mail="$(jq -r '.expected.mail_decision' <<<"$case_json")"
  expected_bad="$(jq -r '.expected.bad_receipt_count' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.required_reason_code // ""' <<<"$case_json")"
  if [[ "$expected_decision" == "blocked" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  "$generator_script" \
    --git-status-json "${tmpdir}/git_status.json" \
    --br-state-json "${tmpdir}/br_state.json" \
    --owned-paths-json "${tmpdir}/owned_paths.json" \
    --recent-commits-json "${tmpdir}/recent_commits.json" \
    --rch-jobs-json "${tmpdir}/rch_jobs.json" \
    --validation-receipts-json "${tmpdir}/validation_receipts.json" \
    --mail-health-json "${tmpdir}/mail_health.json" \
    --operator-notes-json "${tmpdir}/operator_notes.json" \
    --case-id "$case_id" \
    --source-revision "fixture-${case_id}" \
    --generated-epoch-seconds 1778418000 \
    --output-dir "$output_dir" \
    >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    printf 'expected exit %s for %s, got %s\n' "$expected_exit" "$case_id" "$status" >&2
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit ${case_id}"
    return
  fi

  capsule="${output_dir}/swarm_handoff_capsule.json"
  [[ -f "$capsule" ]] || { record_failure "missing capsule ${case_id}"; return; }
  [[ -f "${output_dir}/swarm_handoff_capsule.md" ]] || { record_failure "missing markdown ${case_id}"; return; }
  [[ -f "${output_dir}/handoff_commands.txt" ]] || { record_failure "missing commands ${case_id}"; return; }
  [[ -f "${output_dir}/events.jsonl" ]] || { record_failure "missing events ${case_id}"; return; }

  jq -e \
    --arg decision "$expected_decision" \
    --argjson owned "$expected_owned" \
    --argjson unrelated "$expected_unrelated" \
    --argjson active_rch "$expected_rch" \
    --arg mail "$expected_mail" \
    --argjson bad "$expected_bad" '
      .schema_version == "franken-engine.swarm-handoff-capsule.v1"
      and .decision == $decision
      and .dirty_worktree.owned_dirty_count == $owned
      and .dirty_worktree.unrelated_dirty_count == $unrelated
      and .rch_jobs.active_count == $active_rch
      and .agent_mail.decision == $mail
      and .validation_receipts.bad_count == $bad
      and .mutation_policy.reads_file_contents == false
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
      and .operator_notes.body_copied == false
    ' "$capsule" >/dev/null || record_failure "capsule mismatch ${case_id}"

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" '
      any((.degraded_reasons + .blocked_reasons)[]?; .code == $code)
    ' "$capsule" >/dev/null || record_failure "missing reason ${expected_reason} ${case_id}"
  fi
  if [[ "$case_id" == "clean_repo_fixture" ]]; then
    jq -e '.operator_notes.notes[0] | has("body") | not' "$capsule" >/dev/null \
      || record_failure "note body leaked in clean fixture"
  fi
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$generator_script" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$generator_script" "${BASH_SOURCE[0]}"
  fi
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
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
    printf 'Usage: ./scripts/e2e/swarm_handoff_capsule_generator_smoke.sh [check|selftest]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
