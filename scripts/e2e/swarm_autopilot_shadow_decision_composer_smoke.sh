#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
composer_script="${root_dir}/scripts/swarm_autopilot_shadow_decision_composer.sh"
fixtures_path="${SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_shadow_decision_composer/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_shadow_decision_composer_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER.md"
mode="${1:-check}"
failures=0
fixed_now_epoch_seconds="1778123000"

record_pass() {
  printf 'PASS swarm-autopilot-shadow-decision-composer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-shadow-decision-composer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_shadow_decision_composer_smoke.sh [check|selftest]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-shadow-decision-composer-contract.v1"
    and .bead_id == "bd-djejh.4"
    and .script == "scripts/swarm_autopilot_shadow_decision_composer.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_shadow_decision_composer_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_shadow_decision_composer/cases.json"
    and .shadow_status_schema_version == "franken-engine.swarm-autopilot-shadow-status.v1"
    and .recommendation_bundle_schema_version == "franken-engine.swarm-autopilot-shadow-recommendations.v1"
    and ((["br_queue","bv_robot_plan","agent_mail","rch_status","git_state","artifact_bundles"] - .required_sources) | length) == 0
    and (([
      "recommendation_id",
      "rank",
      "action_class",
      "command_text",
      "executes_mutation",
      "remediation_only",
      "source_event_ids",
      "source_hashes",
      "source_collected_epoch_seconds",
      "degradation_state",
      "reason_codes",
      "evidence_paths"
    ] - .recommendation_required_fields) | length) == 0
    and (([
      "healthy_idle_queue",
      "active_owned_lane",
      "stalled_agent_lane",
      "stale_reservation",
      "contradictory_ownership",
      "agent_mail_degraded",
      "dirty_worktree",
      "rch_fallback_contamination",
      "missing_no_mock_proof",
      "bounded_recommendations"
    ] - .covered_operator_conditions) | length) == 0
    and (([
      "FE-SWARM-AUTOPILOT-SHADOW-MISSING-SOURCE",
      "FE-SWARM-AUTOPILOT-SHADOW-STALE-SOURCE",
      "FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP",
      "FE-SWARM-AUTOPILOT-SHADOW-UNSUPPORTED-MUTATION",
      "FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK",
      "FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE",
      "FE-SWARM-AUTOPILOT-SHADOW-DIRTY-WORKTREE",
      "FE-SWARM-AUTOPILOT-SHADOW-STALED-BEAD",
      "FE-SWARM-AUTOPILOT-SHADOW-STALE-RESERVATION",
      "FE-SWARM-AUTOPILOT-SHADOW-MISSING-NO-MOCK-PROOF"
    ] - .required_error_codes) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_git == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.writes_outside_output_dir == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-shadow-decision-composer-fixtures.v1"
    and (.base_journal_events | length) == 6
    and (.cases | length) == 10
    and ([.cases[].case_id] | unique | length) == 10
    and any(.cases[]; .case_id == "healthy_idle_queue" and .expected.required_action == "observe_idle_queue")
    and any(.cases[]; .case_id == "active_owned_lane" and .expected.required_action == "continue_owned_lane")
    and any(.cases[]; .case_id == "stalled_agent_lane" and .expected.required_action == "review_stalled_bead" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-STALED-BEAD")
    and any(.cases[]; .case_id == "stale_reservation" and .expected.required_action == "review_stale_reservation")
    and any(.cases[]; .case_id == "contradictory_ownership" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP")
    and any(.cases[]; .case_id == "agent_mail_degraded" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE")
    and any(.cases[]; .case_id == "dirty_worktree" and .expected.required_action == "inspect_dirty_worktree")
    and any(.cases[]; .case_id == "rch_fallback_contamination" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK")
    and any(.cases[]; .case_id == "missing_no_mock_proof" and .expected.required_action == "request_no_mock_proof")
    and any(.cases[]; .case_id == "bounded_recommendations" and .expected.max_recommendations == 3 and .expected.required_action == "observe_idle_queue")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The composer is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'never mutates beads, Agent Mail' "$docs_path" \
    && grep -Fq 'reservations, rch, git, workers, or live queue policy' "$docs_path" \
    && grep -Fq 'Every recommendation preserves source event ids, content hashes' "$docs_path" \
    && grep -Fq 'timestamps, degradation state, and a separate operator command' "$docs_path" \
    && grep -Fq 'rch local fallback contamination' "$docs_path" \
    && grep -Fq 'stalled in-progress beads' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | ($case.source_overrides // {}) as $overrides
    | $root.base_journal_events
    | map(. as $event | ($event * ($overrides[$event.source_key] // {})))
  ' "$fixtures_path" >"${case_dir}/journal_events.json"
  jq -c '.[]' "${case_dir}/journal_events.json" >"${case_dir}/journal_events.jsonl"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"${case_dir}/expected.json"
  jq '.base_existing_autopilot_output' "$fixtures_path" >"${case_dir}/existing_autopilot.json"
}

validate_required_artifacts() {
  local output_dir="$1"
  local artifact
  for artifact in shadow_status.json recommendations.json operator_notice.md events.jsonl commands.txt report.md; do
    if [[ ! -s "${output_dir}/${artifact}" ]]; then
      record_failure "${output_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local status_json="${output_dir}/shadow_status.json"
  local recommendations_json="${output_dir}/recommendations.json"
  local expected_decision expected_truth expected_cap required_action required_error

  expected_decision="$(jq -r '.decision' "$expected_json")"
  expected_truth="$(jq -r '.truth_state' "$expected_json")"
  expected_cap="$(jq -r '.max_recommendations // 16' "$expected_json")"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth "$expected_truth" \
    --argjson expected_cap "$expected_cap" \
    --slurpfile contract "$contract_path" '
      . as $status
      |
      .schema_version == $contract[0].shadow_status_schema_version
      and .truth_state == $expected_truth
      and .decision == $expected_decision
      and (.shadow_run_id | length > 0)
      and all($contract[0].required_sources[]; . as $source | ($status.source_snapshot_status[$source] != null))
      and (.source_snapshot_ids | length) >= 6
      and (.advisory_recommendations | length) > 0
      and (.advisory_recommendations | length) <= $expected_cap
      and all(.advisory_recommendations[]; . as $recommendation |
        all($contract[0].recommendation_required_fields[]; $recommendation[.] != null)
        and $recommendation.executes_mutation == false
        and $recommendation.remediation_only == true
        and ($recommendation.source_event_ids | length) > 0
        and ($recommendation.source_hashes | length) > 0
        and ($recommendation.source_collected_epoch_seconds | length) > 0
      )
      and .mutation_policy.advisory_only == true
      and .mutation_policy.proof_only == true
      and .mutation_policy.mutates_br == false
      and .mutation_policy.reassigns_beads == false
      and .mutation_policy.releases_reservations == false
      and .mutation_policy.sends_agent_mail == false
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
      and .mutation_policy.mutates_git == false
      and .mutation_policy.mutates_remote_workers == false
      and .mutation_policy.changes_live_queue_policy == false
      and .sibling_reuse.persistence == "/dp/frankensqlite"
      and .sibling_reuse.tui == "/dp/frankentui"
      and .sibling_reuse.service_api == "/dp/fastapi_rust"
      and (.existing_autopilot_outputs | length) == 1
    ' "$status_json" >/dev/null || record_failure "${case_id} status shape mismatch"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth "$expected_truth" \
    --argjson expected_cap "$expected_cap" '
      .schema_version == "franken-engine.swarm-autopilot-shadow-recommendations.v1"
      and .truth_state == $expected_truth
      and .decision == $expected_decision
      and (.recommendations | length) > 0
      and (.recommendations | length) <= $expected_cap
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
    ' "$recommendations_json" >/dev/null || record_failure "${case_id} recommendations shape mismatch"

  required_action="$(jq -r '.required_action // ""' "$expected_json")"
  if [[ -n "$required_action" ]]; then
    jq -e --arg required_action "$required_action" '.advisory_recommendations | any(.action_class == $required_action)' "$status_json" >/dev/null \
      || record_failure "${case_id} missing action ${required_action}"
  fi

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.error_codes | index($required_error) != null' "$status_json" >/dev/null \
      || record_failure "${case_id} missing error code ${required_error}"
  fi

  grep -Fq 'advisory_only: true' "${output_dir}/operator_notice.md" \
    || record_failure "${case_id} notice missing advisory wording"
  grep -Fq './scripts/swarm_autopilot_shadow_decision_composer.sh' "${output_dir}/commands.txt" \
    || record_failure "${case_id} commands missing composer invocation"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local output_dir="${case_dir}/output"
  local rc expected_rc max_recommendations

  mkdir -p "$case_dir" "$output_dir"
  materialize_case "$case_id" "$case_dir"
  max_recommendations="$(jq -r '.max_recommendations // 16' "${case_dir}/expected.json")"

  set +e
  bash "$composer_script" \
    --journal-events-jsonl "${case_dir}/journal_events.jsonl" \
    --existing-autopilot-json "${case_dir}/existing_autopilot.json" \
    --source-revision "fixture-${case_id}" \
    --now-epoch-seconds "$fixed_now_epoch_seconds" \
    --freshness-window-seconds 300 \
    --max-recommendations "$max_recommendations" \
    --output-dir "$output_dir"
  rc=$?
  set -e

  expected_rc="$(jq -r '.expected_exit_code' "${case_dir}/expected.json")"
  if [[ "$rc" -ne "$expected_rc" ]]; then
    record_failure "${case_id} exit code ${rc} != ${expected_rc}"
  fi
  validate_required_artifacts "$output_dir"
  validate_outputs "$output_dir" "$case_id" "${case_dir}/expected.json"
}

run_check() {
  bash -n "$composer_script" "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixtures_path"
  contract_shape_ok || record_failure "contract shape mismatch"
  fixtures_shape_ok || record_failure "fixture shape mismatch"
  docs_shape_ok || record_failure "docs shape mismatch"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local temp_dir
  temp_dir="${TMPDIR:-/tmp}/franken-engine-shadow-decision-composer-smoke-${fixed_now_epoch_seconds}-$$"
  mkdir -p "$temp_dir"

  while IFS= read -r case_id; do
    run_case "$case_id" "${temp_dir}/${case_id}"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

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
  selftest|run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
