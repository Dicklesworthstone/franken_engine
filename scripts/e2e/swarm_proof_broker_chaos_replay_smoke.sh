#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_broker_chaos_replay.sh"
contract_path="${root_dir}/docs/swarm_proof_broker_chaos_replay_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_BROKER_CHAOS_REPLAY.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_broker_chaos_replay/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_BROKER_CHAOS_REPLAY_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-broker-chaos-replay-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-broker-chaos-replay %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-broker-chaos-replay %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_broker_chaos_replay_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-chaos-replay-contract.v1"
    and .bead_id == "bd-ua5n2.7"
    and (.depends_on | sort) == ["bd-ua5n2.2", "bd-ua5n2.3", "bd-ua5n2.4", "bd-ua5n2.5", "bd-ua5n2.6"]
    and (.scenario_kinds | sort) == [
      "agent_mail_degraded_capture",
      "dirty_worktree_divergence",
      "duplicate_proof_storm",
      "missing_source_evidence",
      "rch_local_fallback_contamination",
      "stale_artifact_storm"
    ]
    and (.required_outputs | index("chaos_replay_bundle.json") != null)
    and (.required_outputs | index("replay_commands.sh") != null)
    and (.required_outputs | index("operator_status_input.json") != null)
    and (.required_invariant_surfaces | index("classifier_verdict") != null)
    and (.required_invariant_surfaces | index("operator_status_projection") != null)
    and (.fail_closed_reasons | sort) == ["insufficient_source_evidence"]
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq 'deterministic scenario hash' "$docs_path" \
    && grep -Fq 'exact replay commands' "$docs_path" \
    && grep -Fq 'Agent Mail' "$docs_path" \
    && grep -Fq 'fail closed' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-chaos-replay-fixtures.v1"
    and (.cases | length) == 6
    and ([.cases[].case_id] | sort) == [
      "agent_mail_degraded_capture",
      "dirty_worktree_divergence",
      "duplicate_proof_storm",
      "missing_source_evidence",
      "rch_local_fallback_contamination",
      "stale_artifact_storm"
    ]
    and all(.cases[]; has("scenario_kind") and has("expected"))
    and ([.cases[].expected.decision] | unique | sort) == ["fail_closed", "pass"]
    and ([.cases[].expected.reason_codes[]?] | unique | sort) == [
      "agent_mail_degraded_capture",
      "changed_dependency_root",
      "dirty_lane_mismatch",
      "duplicate_command_burst",
      "expired_ttl",
      "insufficient_source_evidence",
      "local_fallback_contamination"
    ]
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

expand_case() {
  local case_json="$1"
  jq -n \
    --slurpfile fixtures "$cases_path" \
    --argjson case "$case_json" '
      ($fixtures[0].base_input * ($case | del(.expected)))
      + {expected: $case.expected}
    '
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local bundle_path="${output_dir}/chaos_replay_bundle.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty \
    "$bundle_path" \
    "${output_dir}/classifier_input.json" \
    "${output_dir}/artifact_index_input.json" \
    "${output_dir}/batch_planner_input.json" \
    "${output_dir}/operator_status_input.json" >/dev/null
  test -s "${output_dir}/scenarios.jsonl"
  test -x "${output_dir}/replay_commands.sh"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-broker-chaos-replay.v1"
      and .case_id == $case_id
      and .decision == $expected.decision
      and .fail_closed_reasons == $expected.fail_closed_reasons
      and .scenario.replayable == $expected.replayable
      and .scenario.reason_codes == $expected.reason_codes
      and .scenario.invariant_agreement == $expected.invariant_agreement
      and .scenario.expected_invariants == $expected.expected_invariants
      and (.scenario.perturbed_requests | length) == $expected.perturbed_request_count
      and (.scenario.scenario_hash | test("^[0-9a-f]{64}$"))
      and (.scenario.replay_commands | length) == 4
      and all(.scenario.replay_commands[]; test("^./scripts/swarm_proof_.* --fixture-json .* --output-dir replay/"))
      and (.scenario.replay_commands | index("./scripts/swarm_proof_equivalence_classifier.sh --fixture-json classifier_input.json --output-dir replay/classifier") != null)
      and (.scenario.replay_commands | index("./scripts/swarm_proof_artifact_index.sh --fixture-json artifact_index_input.json --output-dir replay/artifact_index") != null)
      and (.scenario.replay_commands | index("./scripts/swarm_proof_batch_planner.sh --fixture-json batch_planner_input.json --output-dir replay/batch_planner") != null)
      and (.scenario.replay_commands | index("./scripts/swarm_proof_broker_operator_status.sh --fixture-json operator_status_input.json --output-dir replay/operator_status") != null)
      and .scenario.component_inputs.classifier != null
      and .scenario.component_inputs.artifact_index != null
      and .scenario.component_inputs.batch_planner != null
      and .scenario.component_inputs.operator_status != null
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_br == false
    ' "$bundle_path" >/dev/null || record_failure "${case_id} chaos bundle mismatch"

  jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
    .proofs[0].proof_fingerprint != null
    and (.proofs[0].local_fallback_observed == ($expected.reason_codes | index("local_fallback_contamination") != null))
  ' "${output_dir}/artifact_index_input.json" >/dev/null || record_failure "${case_id} artifact input mismatch"

  jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
    (.requests | length) == $expected.perturbed_request_count
    and (([.requests[].requested_at_offset_ms] | length) == $expected.perturbed_request_count)
  ' "${output_dir}/batch_planner_input.json" >/dev/null || record_failure "${case_id} batch input mismatch"

  jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
    .batch_recommendations[0].action == $expected.expected_invariants.batch_planner_action
    and .equivalence_receipts[0].verdict == $expected.expected_invariants.classifier_verdict
  ' "${output_dir}/operator_status_input.json" >/dev/null || record_failure "${case_id} operator input mismatch"
}

run_case_once() {
  local case_json="$1"
  local case_dir="$2"
  local fixture_path="${case_dir}/fixture.json"
  local expected_exit actual_exit

  mkdir -p "$case_dir"
  jq 'del(.expected)' <<<"$case_json" >"$fixture_path"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"

  set +e
  "$script_path" --fixture-json "$fixture_path" --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "$(jq -r '.case_id' <<<"$case_json") exit ${actual_exit}, expected ${expected_exit}"
    return 1
  fi
  assert_case_output "$case_json" "${case_dir}/out"
}

run_case() {
  local raw_case_json="$1"
  local tmp_root="$2"
  local case_json case_id first_hash second_hash

  case_json="$(expand_case "$raw_case_json")"
  case_id="$(jq -r '.case_id' <<<"$case_json")"

  run_case_once "$case_json" "${tmp_root}/${case_id}-a" || return
  run_case_once "$case_json" "${tmp_root}/${case_id}-b" || return

  first_hash="$(jq -r '.scenario.scenario_hash' "${tmp_root}/${case_id}-a/out/chaos_replay_bundle.json")"
  second_hash="$(jq -r '.scenario.scenario_hash' "${tmp_root}/${case_id}-b/out/chaos_replay_bundle.json")"
  if [[ "$first_hash" != "$second_hash" ]]; then
    record_failure "${case_id} nondeterministic scenario hash"
    return
  fi
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi
  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
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
