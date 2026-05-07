#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
generator="${root_dir}/scripts/swarm_autopilot_hindsight_chaos.sh"
fixtures_path="${SWARM_AUTOPILOT_HINDSIGHT_CHAOS_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_hindsight_chaos/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_hindsight_chaos_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_HINDSIGHT_CHAOS.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-hindsight-chaos %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-hindsight-chaos %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-fixtures.v1"
    and .base_source_bundle_json.schema_version == "franken-engine.swarm-autopilot-hindsight-source-bundle.v1"
    and (.cases | length) == 5
    and ([.cases[].case_id] | unique | length) == 5
    and any(.cases[]; .case_id == "minimal_perturbation_generation" and .expected.required_perturbation_type == "minimal_perturbation")
    and any(.cases[]; .case_id == "brownout_chaos" and .expected.required_perturbation_type == "brownout_chaos")
    and any(.cases[]; .case_id == "stale_ownership_chaos" and .expected.required_stress_target == "recommendation_bundle")
    and any(.cases[]; .case_id == "local_fallback_chaos" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-HINDSIGHT-CHAOS-LOCAL-FALLBACK")
    and any(.cases[]; .case_id == "under_specified_replay_rejection" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-HINDSIGHT-CHAOS-UNDER-SPECIFIED")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-contract.v1"
    and .bead_id == "bd-09g6k"
    and ((["bd-g7bk2","bd-knanr"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_hindsight_chaos.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_HINDSIGHT_CHAOS.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_hindsight_chaos/cases.json"
    and .source_bundle_schema_version == "franken-engine.swarm-autopilot-hindsight-source-bundle.v1"
    and .scenarios_schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-scenarios.v1"
    and .replay_index_schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-replay-index.v1"
    and ((["forecast","policy_compiler","lease_allocator","recommendation_bundle"] - .stress_targets) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.approves_replay_automatically == false
    and .mutation_policy.promotes_recommendations_automatically == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The hindsight chaos generator is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Minimal perturbations must preserve the original evidence link and record only the delta.' "$docs_path" \
    && grep -Fq 'Brownout chaos must stress RCH slot availability, target-dir pressure, and proof-cache pressure without changing live workers.' "$docs_path" \
    && grep -Fq 'Local fallback chaos is quarantine-only and cannot produce replayable remote-only scenarios.' "$docs_path" \
    && grep -Fq 'Under-specified replay commands or expected invariants fail closed.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_source_bundle_json * ($case.overrides.source_bundle_json // {})
  ' "$fixtures_path" >"${case_dir}/source_bundle.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"${case_dir}/expected.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in \
    swarm_autopilot_hindsight_chaos_scenarios.json \
    swarm_autopilot_hindsight_chaos_replay_index.json \
    events.jsonl \
    commands.txt \
    report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local scenarios_json="${output_case_dir}/swarm_autopilot_hindsight_chaos_scenarios.json"
  local replay_index_json="${output_case_dir}/swarm_autopilot_hindsight_chaos_replay_index.json"
  local required_error required_type required_target

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-scenarios.v1"
    and .decision == $expected[0].decision
    and (.scenario_summary.scenario_count == (.scenarios | length))
    and (.scenarios | length) > 0
    and all(.scenarios[]; (.scenario_hash | test("^[0-9a-f]{64}$")))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.approves_replay_automatically == false
    and .mutation_policy.promotes_recommendations_automatically == false
  ' "$scenarios_json" >/dev/null || record_failure "${case_id} scenarios bundle mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-replay-index.v1"
    and .decision == $expected[0].decision
    and (.entries | length) > 0
  ' "$replay_index_json" >/dev/null || record_failure "${case_id} replay index mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$scenarios_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
  fi

  required_type="$(jq -r '.required_perturbation_type // ""' "$expected_json")"
  if [[ -n "$required_type" ]]; then
    jq -e --arg required_type "$required_type" '.scenarios | any(.perturbation_type == $required_type)' "$scenarios_json" >/dev/null \
      || record_failure "${case_id} missing perturbation type ${required_type}"
  fi

  required_target="$(jq -r '.required_stress_target // ""' "$expected_json")"
  if [[ -n "$required_target" ]]; then
    jq -e --arg required_target "$required_target" '.scenarios | any((.stress_targets // []) | index($required_target) != null)' "$scenarios_json" >/dev/null \
      || record_failure "${case_id} missing stress target ${required_target}"
  fi

  grep -Fq './scripts/swarm_autopilot_hindsight_chaos.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing hindsight chaos command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local output_case_dir="${case_dir}/output"
  local expected_json="${case_dir}/expected.json"
  local rc

  mkdir -p "$case_dir" "$output_case_dir"
  materialize_case "$case_id" "$case_dir"

  set +e
  bash "$generator" \
    --source-bundle-json "${case_dir}/source_bundle.json" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_case_dir"
  rc=$?
  set -e

  if [[ "$rc" -ne "$(jq -r '.expected_exit_code' "$expected_json")" ]]; then
    record_failure "${case_id} exit code ${rc} != expected $(jq -r '.expected_exit_code' "$expected_json")"
  fi

  validate_required_artifacts "$output_case_dir"
  validate_outputs "$output_case_dir" "$case_id" "$expected_json"
}

run_check() {
  fixtures_shape_ok || record_failure "fixtures shape mismatch"
  contract_shape_ok || record_failure "contract JSON shape mismatch"
  docs_shape_ok || record_failure "docs truth text mismatch"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local temp_dir
  temp_dir="$(mktemp -d)"

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
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    else
      exit 1
    fi
    ;;
  *)
    usage
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
